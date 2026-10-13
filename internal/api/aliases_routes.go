package api

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"firewall-ui/internal/auth"
	"firewall-ui/internal/firewall"
	"firewall-ui/internal/storage"
)

var validAliasName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,31}$`)

func WithAliasRoutes(s *Server, next http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/aliases", s.requireAuth(http.HandlerFunc(s.aliasEndpoint)))
	mux.Handle("POST /api/v1/aliases", s.requireAuth(http.HandlerFunc(s.aliasEndpoint)))
	mux.Handle("PUT /api/v1/aliases/{id}", s.requireAuth(http.HandlerFunc(s.aliasEndpoint)))
	mux.Handle("DELETE /api/v1/aliases/{id}", s.requireAuth(http.HandlerFunc(s.aliasEndpoint)))
	mux.Handle("GET /api/v1/backups", s.requireAuth(http.HandlerFunc(s.managementEndpoint)))
	mux.Handle("GET /api/v1/backups/{id}", s.requireAuth(http.HandlerFunc(s.managementEndpoint)))
	mux.Handle("GET /api/v1/backups/{id}/download", s.requireAuth(http.HandlerFunc(s.managementEndpoint)))
	mux.Handle("DELETE /api/v1/backups/{id}", s.requireAuth(http.HandlerFunc(s.managementEndpoint)))
	mux.Handle("POST /api/v1/backups/{id}/restore", s.requireAuth(http.HandlerFunc(s.managementEndpoint)))
	mux.Handle("POST /api/v1/draft/discard", s.requireAuth(http.HandlerFunc(s.managementEndpoint)))
	mux.Handle("GET /api/v1/draft/diff", s.requireAuth(http.HandlerFunc(s.managementEndpoint)))
	mux.Handle("POST /api/v1/firewall/counters/reset", s.requireAuth(http.HandlerFunc(s.managementEndpoint)))
	mux.Handle("GET /api/v1/ipsets/{name}", s.requireAuth(http.HandlerFunc(s.managementEndpoint)))
	mux.Handle("POST /api/v1/ipsets/{name}/members/bulk", s.requireAuth(http.HandlerFunc(s.managementEndpoint)))
	mux.Handle("DELETE /api/v1/ipsets/{name}/members/bulk", s.requireAuth(http.HandlerFunc(s.managementEndpoint)))
	mux.Handle("GET /api/v1/users", s.requireAuth(http.HandlerFunc(s.usersEndpoint)))
	mux.Handle("POST /api/v1/users", s.requireAuth(http.HandlerFunc(s.usersEndpoint)))
	mux.Handle("PUT /api/v1/users/{id}", s.requireAuth(http.HandlerFunc(s.usersEndpoint)))
	mux.Handle("DELETE /api/v1/users/{id}", s.requireAuth(http.HandlerFunc(s.usersEndpoint)))
	mux.Handle("GET /api/v1/ip6/draft", s.requireAuth(http.HandlerFunc(s.v6Endpoint)))
	mux.Handle("PUT /api/v1/ip6/draft", s.requireAuth(http.HandlerFunc(s.v6Endpoint)))
	mux.Handle("POST /api/v1/ip6/draft/refresh", s.requireAuth(http.HandlerFunc(s.v6Endpoint)))
	mux.Handle("POST /api/v1/ip6/draft/validate", s.requireAuth(http.HandlerFunc(s.v6Endpoint)))
	mux.Handle("POST /api/v1/ip6/draft/apply", s.requireAuth(http.HandlerFunc(s.v6Endpoint)))
	mux.Handle("POST /api/v1/ip6/draft/discard", s.requireAuth(http.HandlerFunc(s.v6Endpoint)))
	mux.Handle("GET /api/v1/ip6/draft/diff", s.requireAuth(http.HandlerFunc(s.v6Endpoint)))
	mux.Handle("GET /api/v1/ip6/firewall/rollback", s.requireAuth(http.HandlerFunc(s.v6Endpoint)))
	mux.Handle("POST /api/v1/ip6/firewall/confirm", s.requireAuth(http.HandlerFunc(s.v6Endpoint)))
	mux.Handle("POST /api/v1/ip6/firewall/rollback", s.requireAuth(http.HandlerFunc(s.v6Endpoint)))
	mux.Handle("GET /api/v1/settings", s.requireAuth(http.HandlerFunc(s.settingsEndpoint)))
	mux.Handle("PUT /api/v1/settings", s.requireAuth(http.HandlerFunc(s.settingsEndpoint)))
	mux.Handle("GET /api/v1/tokens", s.requireAuth(http.HandlerFunc(s.tokensEndpoint)))
	mux.Handle("POST /api/v1/tokens", s.requireAuth(http.HandlerFunc(s.tokensEndpoint)))
	mux.Handle("DELETE /api/v1/tokens/{id}", s.requireAuth(http.HandlerFunc(s.tokensEndpoint)))
	mux.Handle("/", next)
	return mux
}

func (s *Server) audit(p auth.Principal, r *http.Request, action, object, result string) {
	s.Store.AddAudit(p.Username, r.RemoteAddr, action, object, result)
}
func (s *Server) auditChange(p auth.Principal, r *http.Request, action, object, result, before, after string) {
	s.Store.AddAuditFull(p.Username, r.RemoteAddr, action, object, result, before, after, "")
}

func (s *Server) managementEndpoint(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(auth.Principal)
	path := r.URL.Path
	writeAllowed := p.Role == "admin" || p.Role == "operator"
	switch {
	case r.Method == "GET" && path == "/api/v1/backups":
		backups, err := s.Draft.Backups()
		if err != nil {
			apiError(w, err, 500)
			return
		}
		if metas, err := s.Store.BackupMetas(); err == nil {
			for i := range backups {
				if m, ok := metas[backups[i].ID]; ok {
					backups[i].Username = m.Username
					backups[i].Comment = m.Comment
					backups[i].Status = m.Status
				}
			}
		}
		jsonOut(w, 200, backups)
	case r.Method == "GET" && strings.HasPrefix(path, "/api/v1/backups/") && strings.HasSuffix(path, "/download"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/backups/"), "/download")
		content, err := s.Draft.BackupContent(id)
		if err != nil {
			apiError(w, err, 404)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Disposition", "attachment; filename=\"iptables-"+id+".rules\"")
		_, _ = w.Write(content)
	case r.Method == "GET" && strings.HasPrefix(path, "/api/v1/backups/"):
		content, err := s.Draft.BackupContent(r.PathValue("id"))
		if err != nil {
			apiError(w, err, 404)
		} else {
			jsonOut(w, 200, map[string]string{"id": r.PathValue("id"), "content": string(content)})
		}
	case r.Method == "GET" && path == "/api/v1/draft/diff":
		diff, err := s.Draft.Diff()
		if err != nil {
			apiError(w, err, 503)
		} else {
			jsonOut(w, 200, diff)
		}
	case r.Method == "GET" && strings.HasPrefix(path, "/api/v1/ipsets/"):
		name := strings.TrimPrefix(path, "/api/v1/ipsets/")
		sets, err := s.IPSet.List()
		if err != nil {
			apiError(w, err, 503)
			return
		}
		for _, set := range sets {
			if set.Name == name {
				refs := s.IPSet.KernelReferences(name)
				if draft := s.Draft.Get(); draft != nil {
					for _, rule := range draft.Rules {
						if (rule.Source.Type == "ipset" && rule.Source.Value == name) || (rule.Destination.Type == "ipset" && rule.Destination.Value == name) {
							refs++
						}
					}
				}
				set.References = refs
				jsonOut(w, 200, set)
				return
			}
		}
		apiError(w, errors.New("ipset not found"), 404)
	case (r.Method == "POST" || r.Method == "DELETE") && strings.HasSuffix(path, "/members/bulk") && writeAllowed:
		if !s.requireCSRF(w, r, p) {
			return
		}
		name := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/ipsets/"), "/members/bulk")
		var v struct {
			Members []string `json:"members"`
		}
		if !decode(w, r, &v) {
			return
		}
		n, err := s.IPSet.Bulk(name, v.Members, r.Method == "DELETE")
		action := "bulk_add"
		if r.Method == "DELETE" {
			action = "bulk_remove"
		}
		s.audit(p, r, action, "ipset:"+name, resultOf(err))
		if err != nil {
			apiError(w, err, 400)
		} else {
			jsonOut(w, 200, map[string]int{"applied": n})
		}
	case r.Method == "POST" && path == "/api/v1/draft/discard" && writeAllowed:
		if !s.requireCSRF(w, r, p) {
			return
		}
		draft, err := s.Draft.Discard()
		if err != nil {
			s.audit(p, r, "discard", "draft", "failed")
			apiError(w, err, 500)
		} else {
			s.audit(p, r, "discard", "draft", "success")
			jsonOut(w, 200, draft)
		}
	case r.Method == "POST" && path == "/api/v1/firewall/counters/reset" && writeAllowed:
		if !s.requireCSRF(w, r, p) {
			return
		}
		err := s.Draft.ResetCounters()
		s.audit(p, r, "reset_counters", "firewall", resultOf(err))
		respondErr(w, err)
	case r.Method == "POST" && strings.HasPrefix(path, "/api/v1/backups/") && strings.HasSuffix(path, "/restore") && writeAllowed:
		if !s.requireCSRF(w, r, p) {
			return
		}
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/backups/"), "/restore")
		err := s.Draft.RestoreBackup(id)
		if err == nil {
			_ = s.Store.SetBackupStatus(id, "restored")
		}
		s.audit(p, r, "restore", "backup:"+id, resultOf(err))
		respondErr(w, err)
	case r.Method == "DELETE" && strings.HasPrefix(path, "/api/v1/backups/") && writeAllowed:
		if !s.requireCSRF(w, r, p) {
			return
		}
		if p.Role != "admin" {
			apiError(w, errors.New("insufficient permissions"), 403)
			return
		}
		id := r.PathValue("id")
		err := s.Draft.DeleteBackup(id)
		if err == nil {
			_ = s.Store.DeleteBackupMeta(id)
		}
		s.audit(p, r, "delete", "backup:"+id, resultOf(err))
		respondErr(w, err)
	default:
		apiError(w, errors.New("not found or insufficient permissions"), 404)
	}
}

func resultOf(err error) string {
	if err != nil {
		return "failed"
	}
	return "success"
}

func (s *Server) aliasEndpoint(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(auth.Principal)
	if r.Method == http.MethodGet {
		aliases, err := s.Store.Aliases()
		if err != nil {
			apiError(w, err, http.StatusInternalServerError)
			return
		}
		type aliasOut struct {
			storage.Alias
			References int `json:"references"`
		}
		out := make([]aliasOut, 0, len(aliases))
		draft := s.Draft.Get()
		for _, a := range aliases {
			ao := aliasOut{Alias: a}
			if draft != nil {
				for _, rule := range draft.Rules {
					if (rule.Source.Type == "alias" && rule.Source.Value == a.Name) || (rule.Destination.Type == "alias" && rule.Destination.Value == a.Name) {
						ao.References++
					}
				}
			}
			out = append(out, ao)
		}
		jsonOut(w, http.StatusOK, out)
		return
	}
	if p.Role != "admin" && p.Role != "operator" {
		apiError(w, errors.New("insufficient permissions"), http.StatusForbidden)
		return
	}
	if !s.requireCSRF(w, r, p) {
		return
	}
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		var input struct {
			Name    string `json:"name"`
			Address string `json:"address"`
		}
		if !decode(w, r, &input) {
			return
		}
		if !validAliasName.MatchString(input.Name) {
			apiError(w, errors.New("invalid alias name"), http.StatusBadRequest)
			return
		}
		if net.ParseIP(input.Address) == nil {
			if _, _, err := net.ParseCIDR(input.Address); err != nil {
				apiError(w, errors.New("invalid alias IP/CIDR"), http.StatusBadRequest)
				return
			}
		}
		var err error
		action := "create"
		after := storage.Alias{Name: input.Name, Address: input.Address}
		afterJSON, _ := json.Marshal(after)
		if r.Method == http.MethodPost {
			err = s.Store.CreateAlias(input.Name, input.Address)
		} else {
			action = "update"
			id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
			if e != nil {
				apiError(w, errors.New("invalid alias id"), http.StatusBadRequest)
				return
			}
			before := storage.Alias{Name: input.Name, Address: input.Address}
			if old, e := s.Store.Aliases(); e == nil {
				for _, a := range old {
					if a.ID == id {
						before = a
						break
					}
				}
			}
			beforeJSON, _ := json.Marshal(before)
			err = s.Store.UpdateAlias(id, input.Name, input.Address)
			s.auditChange(p, r, action, "alias:"+input.Name, resultOf(err), string(beforeJSON), string(afterJSON))
			respondErr(w, err)
			return
		}
		s.auditChange(p, r, action, "alias:"+input.Name, resultOf(err), "", string(afterJSON))
		respondErr(w, err)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		apiError(w, errors.New("invalid alias id"), http.StatusBadRequest)
		return
	}
	aliases, err := s.Store.Aliases()
	if err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	name := ""
	for _, alias := range aliases {
		if alias.ID == id {
			name = alias.Name
			break
		}
	}
	if draft := s.Draft.Get(); draft != nil {
		for _, rule := range draft.Rules {
			if (rule.Source.Type == "alias" && rule.Source.Value == name) || (rule.Destination.Type == "alias" && rule.Destination.Value == name) {
				apiError(w, errors.New("alias "+name+" is used by firewall rules"), http.StatusConflict)
				return
			}
		}
	}
	beforeJSON, _ := json.Marshal(storage.Alias{Name: name})
	err = s.Store.DeleteAlias(id)
	s.auditChange(p, r, "delete", "alias:"+name, resultOf(err), string(beforeJSON), "")
	respondErr(w, err)
}

func (s *Server) usersEndpoint(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(auth.Principal)
	if p.Role != "admin" {
		apiError(w, errors.New("insufficient permissions"), 403)
		return
	}
	if r.Method == "GET" {
		users, err := s.Store.Users()
		if err != nil {
			apiError(w, err, 500)
			return
		}
		type out struct {
			ID       int64  `json:"id"`
			Username string `json:"username"`
			Role     string `json:"role"`
		}
		res := make([]out, 0, len(users))
		for _, u := range users {
			res = append(res, out{u.ID, u.Username, u.Role})
		}
		jsonOut(w, 200, res)
		return
	}
	if !s.requireCSRF(w, r, p) {
		return
	}
	switch r.Method {
	case "POST":
		var v struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if !decode(w, r, &v) {
			return
		}
		if v.Role != "admin" && v.Role != "operator" && v.Role != "viewer" {
			apiError(w, errors.New("invalid role"), 400)
			return
		}
		err := s.Auth.CreateUser(v.Username, v.Password, v.Role)
		afterJSON, _ := json.Marshal(map[string]string{"username": v.Username, "role": v.Role})
		s.auditChange(p, r, "create", "user:"+v.Username, resultOf(err), "", string(afterJSON))
		respondErr(w, err)
	case "PUT":
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			apiError(w, errors.New("invalid user id"), 400)
			return
		}
		var v struct {
			Role     string `json:"role"`
			Password string `json:"password"`
		}
		if !decode(w, r, &v) {
			return
		}
		if v.Role != "admin" && v.Role != "operator" && v.Role != "viewer" {
			apiError(w, errors.New("invalid role"), 400)
			return
		}
		hash := ""
		if v.Password != "" {
			if hash, err = s.Auth.HashPassword(v.Password); err != nil {
				apiError(w, err, 400)
				return
			}
		}
		beforeJSON := ""
		if users, e := s.Store.Users(); e == nil {
			for _, u := range users {
				if u.ID == id {
					b, _ := json.Marshal(map[string]any{"id": u.ID, "username": u.Username, "role": u.Role})
					beforeJSON = string(b)
					break
				}
			}
		}
		err = s.Store.UpdateUser(id, v.Role, hash)
		if err == nil && hash != "" {
			_ = s.Store.DeleteUserSessions(id)
		}
		afterJSON, _ := json.Marshal(map[string]any{"id": id, "role": v.Role, "password_changed": hash != ""})
		s.auditChange(p, r, "update", "user:"+r.PathValue("id"), resultOf(err), beforeJSON, string(afterJSON))
		respondErr(w, err)
	case "DELETE":
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			apiError(w, errors.New("invalid user id"), 400)
			return
		}
		if id == p.ID {
			apiError(w, errors.New("cannot delete own account"), 409)
			return
		}
		beforeJSON := ""
		if users, e := s.Store.Users(); e == nil {
			for _, u := range users {
				if u.ID == id {
					b, _ := json.Marshal(map[string]any{"id": u.ID, "username": u.Username, "role": u.Role})
					beforeJSON = string(b)
					break
				}
			}
		}
		err = s.Store.DeleteUser(id)
		s.auditChange(p, r, "delete", "user:"+r.PathValue("id"), resultOf(err), beforeJSON, "")
		respondErr(w, err)
	}
}

func (s *Server) v6Endpoint(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(auth.Principal)
	ds := s.Draft6
	if ds == nil {
		apiError(w, errors.New("ipv6 backend is not configured"), 503)
		return
	}
	writeAllowed := p.Role == "admin" || p.Role == "operator"
	path := r.URL.Path
	switch {
	case r.Method == "GET" && path == "/api/v1/ip6/draft":
		jsonOut(w, 200, ds.Get())
	case r.Method == "GET" && path == "/api/v1/ip6/draft/diff":
		diff, err := ds.Diff()
		if err != nil {
			apiError(w, err, 503)
		} else {
			jsonOut(w, 200, diff)
		}
	case r.Method == "GET" && path == "/api/v1/ip6/firewall/rollback":
		active, deadline := ds.RollbackStatus()
		jsonOut(w, 200, map[string]any{"active": active, "deadline": deadline})
	case !writeAllowed:
		apiError(w, errors.New("insufficient permissions"), 403)
	case !s.requireCSRF(w, r, p):
	case r.Method == "POST" && path == "/api/v1/ip6/draft/refresh":
		d, err := ds.Refresh()
		if err != nil {
			apiError(w, err, 503)
		} else {
			jsonOut(w, 200, d)
		}
	case r.Method == "PUT" && path == "/api/v1/ip6/draft":
		var d firewall.Ruleset
		if !decode(w, r, &d) {
			return
		}
		err := ds.Save(&d)
		s.audit(p, r, "save", "draft6", resultOf(err))
		respondErr(w, err)
	case r.Method == "POST" && path == "/api/v1/ip6/draft/validate":
		err := ds.Validate()
		s.audit(p, r, "validate", "draft6", resultOf(err))
		respondErr(w, err)
	case r.Method == "POST" && path == "/api/v1/ip6/draft/apply":
		b, dl, err := ds.Apply()
		s.audit(p, r, "apply", "firewall6", resultOf(err))
		if err != nil {
			apiError(w, err, 409)
		} else {
			if b != nil {
				_ = s.Store.SaveBackupMeta(storage.BackupMeta{ID: b.ID, Path: b.Path, Snapshot: b.Snapshot, CreatedAt: b.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"), Status: "created", Username: p.Username})
			}
			jsonOut(w, 200, map[string]any{"backup": b, "rollback_deadline": dl})
		}
	case r.Method == "POST" && path == "/api/v1/ip6/draft/discard":
		d, err := ds.Discard()
		s.audit(p, r, "discard", "draft6", resultOf(err))
		if err != nil {
			apiError(w, err, 500)
		} else {
			jsonOut(w, 200, d)
		}
	case r.Method == "POST" && path == "/api/v1/ip6/firewall/confirm":
		ds.Confirm()
		if id := ds.LastBackupID(); id != "" {
			_ = s.Store.SetBackupStatus(id, "confirmed")
		}
		s.audit(p, r, "confirm", "firewall6", "success")
		jsonOut(w, 200, map[string]bool{"ok": true})
	case r.Method == "POST" && path == "/api/v1/ip6/firewall/rollback":
		err := ds.Rollback()
		if id := ds.LastBackupID(); id != "" && err == nil {
			_ = s.Store.SetBackupStatus(id, "rolled-back")
		}
		s.audit(p, r, "rollback", "firewall6", resultOf(err))
		respondErr(w, err)
	default:
		apiError(w, errors.New("not found or insufficient permissions"), 404)
	}
}

func (s *Server) settingsEndpoint(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(auth.Principal)
	if r.Method == "GET" {
		settings, err := s.Store.Settings()
		if err != nil {
			apiError(w, err, 500)
			return
		}
		rateEnabled := true
		if v, ok := settings["rate_limit_enabled"]; ok {
			rateEnabled = v == "true"
		}
		rateAuth := "10"
		if v, ok := settings["rate_limit_auth"]; ok {
			rateAuth = v
		}
		rateAPI := "200"
		if v, ok := settings["rate_limit_api"]; ok {
			rateAPI = v
		}
		rateWhitelist := ""
		if v, ok := settings["rate_limit_whitelist_ipset"]; ok {
			rateWhitelist = v
		}
		sessionTTL := "720"
		if v, ok := settings["session_ttl_minutes"]; ok {
			sessionTTL = v
		}
		jsonOut(w, 200, map[string]any{
			"safe_mode":                  settings["safe_mode"] == "true",
			"rollback_timeout":           settings["rollback_timeout"],
			"backup_retention":           settings["backup_retention"],
			"rate_limit_enabled":         rateEnabled,
			"rate_limit_auth":            rateAuth,
			"rate_limit_api":             rateAPI,
			"rate_limit_whitelist_ipset": rateWhitelist,
			"session_ttl_minutes":        sessionTTL,
		})
		return
	}
	if p.Role != "admin" {
		apiError(w, errors.New("insufficient permissions"), 403)
		return
	}
	if !s.requireCSRF(w, r, p) {
		return
	}
	var v struct {
		SafeMode                bool   `json:"safe_mode"`
		RollbackTimeout         int    `json:"rollback_timeout"`
		BackupRetention         int    `json:"backup_retention"`
		RateLimitEnabled        bool   `json:"rate_limit_enabled"`
		RateLimitAuth           int    `json:"rate_limit_auth"`
		RateLimitAPI            int    `json:"rate_limit_api"`
		RateLimitWhitelistIPSet string `json:"rate_limit_whitelist_ipset"`
		SessionTTLMinutes       int    `json:"session_ttl_minutes"`
	}
	if !decode(w, r, &v) {
		return
	}
	if v.RollbackTimeout < 10 || v.RollbackTimeout > 3600 {
		apiError(w, errors.New("rollback timeout must be 10-3600 seconds"), 400)
		return
	}
	if v.BackupRetention < 0 || v.BackupRetention > 1000 {
		apiError(w, errors.New("backup retention must be 0-1000"), 400)
		return
	}
	if v.RateLimitAuth < 1 || v.RateLimitAuth > 10000 || v.RateLimitAPI < 1 || v.RateLimitAPI > 10000 {
		apiError(w, errors.New("rate limits must be 1-10000"), 400)
		return
	}
	if v.SessionTTLMinutes < 1 || v.SessionTTLMinutes > 525600 {
		apiError(w, errors.New("session lifetime must be 1-525600 minutes"), 400)
		return
	}
	before, _ := s.Store.Settings()
	_ = s.Store.SetSetting("safe_mode", strconv.FormatBool(v.SafeMode))
	_ = s.Store.SetSetting("rollback_timeout", strconv.Itoa(v.RollbackTimeout))
	_ = s.Store.SetSetting("backup_retention", strconv.Itoa(v.BackupRetention))
	_ = s.Store.SetSetting("rate_limit_enabled", strconv.FormatBool(v.RateLimitEnabled))
	_ = s.Store.SetSetting("rate_limit_auth", strconv.Itoa(v.RateLimitAuth))
	_ = s.Store.SetSetting("rate_limit_api", strconv.Itoa(v.RateLimitAPI))
	_ = s.Store.SetSetting("rate_limit_whitelist_ipset", v.RateLimitWhitelistIPSet)
	_ = s.Store.SetSetting("session_ttl_minutes", strconv.Itoa(v.SessionTTLMinutes))
	after := map[string]string{
		"safe_mode":                  strconv.FormatBool(v.SafeMode),
		"rollback_timeout":           strconv.Itoa(v.RollbackTimeout),
		"backup_retention":           strconv.Itoa(v.BackupRetention),
		"rate_limit_enabled":         strconv.FormatBool(v.RateLimitEnabled),
		"rate_limit_auth":            strconv.Itoa(v.RateLimitAuth),
		"rate_limit_api":             strconv.Itoa(v.RateLimitAPI),
		"rate_limit_whitelist_ipset": v.RateLimitWhitelistIPSet,
		"session_ttl_minutes":        strconv.Itoa(v.SessionTTLMinutes),
	}
	s.Draft.SafeMode = v.SafeMode
	s.Draft.MaxBackups = v.BackupRetention
	s.Draft.SetTimeout(time.Duration(v.RollbackTimeout) * time.Second)
	if s.Draft6 != nil {
		s.Draft6.SafeMode = v.SafeMode
		s.Draft6.MaxBackups = v.BackupRetention
		s.Draft6.SetTimeout(time.Duration(v.RollbackTimeout) * time.Second)
	}
	b, _ := json.Marshal(before)
	a, _ := json.Marshal(after)
	s.auditChange(p, r, "update", "settings", "success", string(b), string(a))
	jsonOut(w, 200, map[string]bool{"ok": true})
}

var validTokenScopes = map[string]bool{"firewall:read": true, "firewall:write": true, "ipset:read": true, "ipset:write": true, "system:read": true, "admin": true}

func (s *Server) tokensEndpoint(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(auth.Principal)
	if p.Role != "admin" {
		apiError(w, errors.New("insufficient permissions"), 403)
		return
	}
	if r.Method == "GET" {
		tokens, err := s.Store.Tokens()
		if err != nil {
			apiError(w, err, 500)
		} else {
			jsonOut(w, 200, tokens)
		}
		return
	}
	if !s.requireCSRF(w, r, p) {
		return
	}
	if r.Method == "POST" {
		var v struct {
			Name   string   `json:"name"`
			Scopes []string `json:"scopes"`
		}
		if !decode(w, r, &v) {
			return
		}
		if len(v.Name) < 2 || len(v.Name) > 64 {
			apiError(w, errors.New("invalid token name"), 400)
			return
		}
		if len(v.Scopes) == 0 {
			apiError(w, errors.New("at least one scope is required"), 400)
			return
		}
		for _, sc := range v.Scopes {
			if !validTokenScopes[sc] {
				apiError(w, errors.New("invalid scope: "+sc), 400)
				return
			}
		}
		token, _, err := s.Auth.CreateToken(v.Name, strings.Join(v.Scopes, ","))
		afterJSON, _ := json.Marshal(map[string]any{"name": v.Name, "scopes": v.Scopes})
		s.auditChange(p, r, "create", "token:"+v.Name, resultOf(err), "", string(afterJSON))
		if err != nil {
			apiError(w, err, 400)
		} else {
			jsonOut(w, 201, map[string]string{"token": token})
		}
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		apiError(w, errors.New("invalid token id"), 400)
		return
	}
	beforeJSON := ""
	if tokens, e := s.Store.Tokens(); e == nil {
		for _, t := range tokens {
			if t.ID == id {
				b, _ := json.Marshal(map[string]any{"id": t.ID, "name": t.Name, "scopes": t.Scopes})
				beforeJSON = string(b)
				break
			}
		}
	}
	err = s.Store.DeleteToken(id)
	s.auditChange(p, r, "delete", "token:"+r.PathValue("id"), resultOf(err), beforeJSON, "")
	respondErr(w, err)
}
