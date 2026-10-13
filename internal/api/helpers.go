package api

import (
	"context"
	"encoding/json"
	"firewall-ui/internal/auth"
	"io"
	"io/fs"
	"net/http"
	"path"
)

func withPrincipal(ctx context.Context, p auth.Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}
func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func apiError(w http.ResponseWriter, err error, status int) {
	jsonOut(w, status, map[string]string{"error": err.Error()})
}
func respondErr(w http.ResponseWriter, err error) {
	if err != nil {
		apiError(w, err, 400)
	} else {
		jsonOut(w, 200, map[string]bool{"ok": true})
	}
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		apiError(w, err, 400)
		return false
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		apiError(w, io.ErrUnexpectedEOF, 400)
		return false
	}
	return true
}
func (s *Server) requireCSRF(w http.ResponseWriter, r *http.Request, p auth.Principal) bool {
	if r.Header.Get("Authorization") != "" {
		return true
	}
	if r.Header.Get("X-CSRF-Token") != p.CSRF {
		apiError(w, context.Canceled, 403)
		return false
	}
	return true
}
func security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}
func spa(files http.Handler, assets fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := path.Clean(stringsTrim(r.URL.Path))
		if name != "." {
			if _, err := fs.Stat(assets, name); err == nil {
				files.ServeHTTP(w, r)
				return
			}
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		files.ServeHTTP(w, r2)
	})
}
func stringsTrim(v string) string {
	for len(v) > 0 && v[0] == '/' {
		v = v[1:]
	}
	return v
}
