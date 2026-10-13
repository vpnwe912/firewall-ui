package api

import (
	"errors"
	"firewall-ui/internal/auth"
	"firewall-ui/internal/firewall"
	"firewall-ui/internal/ipset"
	"firewall-ui/internal/storage"
	"firewall-ui/internal/system"
	webassets "firewall-ui/web"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
)

type Server struct {
	Auth   *auth.Service
	Store  *storage.Store
	Draft  *firewall.DraftService
	Draft6 *firewall.DraftService
	IPSet  *ipset.Service
	System system.Info
}
type ctxKey string

const principalKey ctxKey = "principal"

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/setup", s.setup)
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.Handle("/api/", s.requireAuth(http.HandlerFunc(s.api)))
	dist, _ := fs.Sub(webassets.Assets, "dist")
	files := http.FileServer(http.FS(dist))
	mux.Handle("/", spa(files, dist))
	return security(newRateLimiter(s).limit(mux))
}
func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(auth.Principal)
	path := r.URL.Path
	writeAllowed := p.Role == "admin" || p.Role == "operator"
	switch {
	case r.Method == "GET" && path == "/api/v1/auth/me":
		jsonOut(w, 200, p)
	case r.Method == "POST" && path == "/api/v1/auth/logout":
		s.Auth.Logout(w, p)
		s.Store.AddAudit(p.Username, r.RemoteAddr, "logout", "session", "success")
		jsonOut(w, 200, map[string]bool{"ok": true})
	case r.Method == "GET" && path == "/api/v1/auth/attempts":
		if p.Role != "admin" {
			apiError(w, errors.New("admin required"), 403)
			return
		}
		a, e := s.Store.LoginAttempts()
		if e != nil {
			apiError(w, e, 500)
		} else {
			jsonOut(w, 200, a)
		}
	case r.Method == "GET" && path == "/api/v1/auth/locks":
		if p.Role != "admin" {
			apiError(w, errors.New("admin required"), 403)
			return
		}
		jsonOut(w, 200, s.Auth.Locks())
	case r.Method == "GET" && path == "/api/v1/system":
		jsonOut(w, 200, s.System)
	case r.Method == "GET" && (path == "/api/v1/firewall" || path == "/api/v1/firewall/filter" || path == "/api/v1/firewall/nat"):
		d := s.Draft.Get()
		if d == nil {
			apiError(w, errors.New("firewall draft is not loaded"), 503)
			return
		}
		if path == "/api/v1/firewall" {
			jsonOut(w, 200, d)
			return
		}
		table := strings.TrimPrefix(path, "/api/v1/firewall/")
		var rules []firewall.Rule
		for _, rule := range d.Rules {
			if rule.Table == table {
				rules = append(rules, rule)
			}
		}
		jsonOut(w, 200, rules)
	case r.Method == "GET" && path == "/api/v1/draft":
		jsonOut(w, 200, s.Draft.Get())
	case r.Method == "POST" && path == "/api/v1/draft/refresh" && writeAllowed:
		s.handleRefresh(w)
	case r.Method == "PUT" && path == "/api/v1/draft" && writeAllowed:
		var d firewall.Ruleset
		if decode(w, r, &d) && s.requireCSRF(w, r, p) {
			err := s.Draft.Save(&d)
			s.Store.AddAudit(p.Username, r.RemoteAddr, "save", "draft", auditResult(err))
			respondErr(w, err)
		}
	case r.Method == "POST" && path == "/api/v1/draft/validate" && writeAllowed:
		if s.requireCSRF(w, r, p) {
			err := s.Draft.Validate()
			s.Store.AddAudit(p.Username, r.RemoteAddr, "validate", "draft", auditResult(err))
			respondErr(w, err)
		}
	case r.Method == "POST" && path == "/api/v1/draft/apply" && writeAllowed:
		if s.requireCSRF(w, r, p) {
			b, d, e := s.Draft.Apply()
			if e != nil {
				s.Store.AddAudit(p.Username, r.RemoteAddr, "apply", "firewall", "failed")
				apiError(w, e, 409)
			} else {
				details := ""
				if diff, err := s.Draft.Diff(); err == nil {
					details = fmt.Sprintf("%d changes", diff.Changed)
				}
				s.Store.AddAuditDetails(p.Username, r.RemoteAddr, "apply", "firewall", "success", details)
				if b != nil {
					_ = s.Store.SaveBackupMeta(storage.BackupMeta{ID: b.ID, Path: b.Path, Snapshot: b.Snapshot, CreatedAt: b.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"), Status: "created", Username: p.Username})
				}
				jsonOut(w, 200, map[string]any{"backup": b, "rollback_deadline": d})
			}
		}
	case r.Method == "POST" && path == "/api/v1/firewall/confirm" && writeAllowed:
		if s.requireCSRF(w, r, p) {
			s.Draft.Confirm()
			if id := s.Draft.LastBackupID(); id != "" {
				_ = s.Store.SetBackupStatus(id, "confirmed")
			}
			s.Store.AddAudit(p.Username, r.RemoteAddr, "confirm", "firewall", "success")
			jsonOut(w, 200, map[string]bool{"ok": true})
		}
	case r.Method == "POST" && path == "/api/v1/firewall/rollback" && writeAllowed:
		if s.requireCSRF(w, r, p) {
			err := s.Draft.Rollback()
			if id := s.Draft.LastBackupID(); id != "" && err == nil {
				_ = s.Store.SetBackupStatus(id, "rolled-back")
			}
			s.Store.AddAudit(p.Username, r.RemoteAddr, "rollback", "firewall", auditResult(err))
			respondErr(w, err)
		}
	case r.Method == "GET" && path == "/api/v1/firewall/rollback":
		active, deadline := s.Draft.RollbackStatus()
		jsonOut(w, 200, map[string]any{"active": active, "deadline": deadline})
	case r.Method == "GET" && path == "/api/v1/ipsets":
		sets, e := s.IPSet.List()
		if e != nil {
			apiError(w, e, 503)
		} else {
			if draft := s.Draft.Get(); draft != nil {
				for i := range sets {
					for _, rule := range draft.Rules {
						if (rule.Source.Type == "ipset" && rule.Source.Value == sets[i].Name) || (rule.Destination.Type == "ipset" && rule.Destination.Value == sets[i].Name) {
							sets[i].References++
						}
					}
				}
			}
			jsonOut(w, 200, sets)
		}
	case (r.Method == "POST" || r.Method == "DELETE") && strings.HasSuffix(path, "/members") && strings.HasPrefix(path, "/api/v1/ipsets/") && writeAllowed:
		if !s.requireCSRF(w, r, p) {
			return
		}
		name := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/ipsets/"), "/members")
		var v struct {
			Member  string `json:"member"`
			Comment string `json:"comment"`
		}
		if decode(w, r, &v) {
			var err error
			action := "add_member"
			if r.Method == "POST" {
				err = s.IPSet.Add(name, v.Member, v.Comment)
			} else {
				action = "remove_member"
				err = s.IPSet.Remove(name, v.Member)
			}
			s.Store.AddAudit(p.Username, r.RemoteAddr, action, "ipset:"+name, auditResult(err))
			respondErr(w, err)
		}
	case r.Method == "POST" && path == "/api/v1/ipsets" && writeAllowed:
		if !s.requireCSRF(w, r, p) {
			return
		}
		var v struct {
			Name    string `json:"name"`
			Type    string `json:"type"`
			Family  string `json:"family"`
			Comment bool   `json:"comment"`
		}
		if decode(w, r, &v) {
			err := s.IPSet.Create(v.Name, v.Type, v.Family, v.Comment)
			s.Store.AddAudit(p.Username, r.RemoteAddr, "create", "ipset:"+v.Name, auditResult(err))
			respondErr(w, err)
		}
	case r.Method == "DELETE" && strings.HasPrefix(path, "/api/v1/ipsets/") && writeAllowed:
		if s.requireCSRF(w, r, p) {
			name := strings.TrimPrefix(path, "/api/v1/ipsets/")
			if draft := s.Draft.Get(); draft != nil {
				refs := 0
				for _, rule := range draft.Rules {
					if (rule.Source.Type == "ipset" && rule.Source.Value == name) || (rule.Destination.Type == "ipset" && rule.Destination.Value == name) {
						refs++
					}
				}
				if refs > 0 {
					apiError(w, errors.New("IPSet "+name+" is used by firewall rules"), 409)
					return
				}
			}
			err := s.IPSet.Delete(name)
			s.Store.AddAudit(p.Username, r.RemoteAddr, "delete", "ipset:"+name, auditResult(err))
			respondErr(w, err)
		}
	case r.Method == "GET" && path == "/api/v1/audit":
		a, e := s.Store.Audits()
		if e != nil {
			apiError(w, e, 500)
		} else {
			jsonOut(w, 200, a)
		}
	default:
		apiError(w, errors.New("not found or insufficient permissions"), 404)
	}
}
func auditResult(err error) string {
	if err != nil {
		return "failed"
	}
	return "success"
}
func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if decode(w, r, &v) {
		if err := s.Auth.Bootstrap(v.Username, v.Password); err != nil {
			apiError(w, err, 409)
		} else {
			jsonOut(w, 201, map[string]bool{"ok": true})
		}
	}
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &v) {
		return
	}
	token, p, err := s.Auth.Login(v.Username, v.Password, r.RemoteAddr)
	if err != nil {
		apiError(w, err, 401)
		return
	}
	s.Auth.SetCookie(w, token)
	s.Store.AddAudit(p.Username, r.RemoteAddr, "login", "session", "success")
	jsonOut(w, 200, p)
}
func (s *Server) handleRefresh(w http.ResponseWriter) {
	d, e := s.Draft.Refresh()
	if e != nil {
		apiError(w, e, 503)
	} else {
		jsonOut(w, 200, d)
	}
}
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, e := s.Auth.Authenticate(r)
		if e != nil {
			apiError(w, e, 401)
			return
		}
		ctx := r.Context()
		ctx = withPrincipal(ctx, p)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
