package api

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type rateLimitConfig struct {
	enabled      bool
	authMax      int
	apiMax       int
	whitelistSet string
}

type rateLimiter struct {
	server *Server
	mu     sync.Mutex
	cfg    rateLimitConfig
	loaded time.Time
	auth   map[string][]time.Time
	api    map[string][]time.Time
}

func newRateLimiter(s *Server) *rateLimiter {
	return &rateLimiter{
		server: s,
		auth:   map[string][]time.Time{},
		api:    map[string][]time.Time{},
	}
}

func (rl *rateLimiter) config() rateLimitConfig {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if !rl.loaded.IsZero() && time.Since(rl.loaded) < 5*time.Second {
		return rl.cfg
	}
	cfg := rateLimitConfig{enabled: true, authMax: 10, apiMax: 200}
	if v, err := rl.server.Store.Setting("rate_limit_enabled"); err == nil {
		cfg.enabled = v == "true"
	}
	if v, err := rl.server.Store.Setting("rate_limit_auth"); err == nil {
		if n, e := strconv.Atoi(v); e == nil && n > 0 {
			cfg.authMax = n
		}
	}
	if v, err := rl.server.Store.Setting("rate_limit_api"); err == nil {
		if n, e := strconv.Atoi(v); e == nil && n > 0 {
			cfg.apiMax = n
		}
	}
	if v, err := rl.server.Store.Setting("rate_limit_whitelist_ipset"); err == nil {
		cfg.whitelistSet = v
	}
	rl.cfg = cfg
	rl.loaded = time.Now()
	return cfg
}

func (rl *rateLimiter) limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		cfg := rl.config()
		if !cfg.enabled {
			next.ServeHTTP(w, r)
			return
		}
		ip := clientIP(r)
		if cfg.whitelistSet != "" {
			if ok, _ := rl.server.IPSet.Contains(cfg.whitelistSet, ip); ok {
				next.ServeHTTP(w, r)
				return
			}
		}
		isAuth := r.URL.Path == "/api/v1/auth/login" || r.URL.Path == "/api/v1/setup"
		var allowed bool
		if isAuth {
			allowed = rl.allow(rl.auth, ip, cfg.authMax, time.Minute)
		} else {
			allowed = rl.allow(rl.api, ip, cfg.apiMax, time.Minute)
		}
		if !allowed {
			w.Header().Set("Retry-After", "60")
			apiError(w, errTooManyRequests, 429)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (rl *rateLimiter) allow(m map[string][]time.Time, ip string, max int, window time.Duration) bool {
	now := time.Now()
	cutoff := now.Add(-window)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	hits := m[ip]
	n := 0
	for _, t := range hits {
		if t.After(cutoff) {
			hits[n] = t
			n++
		}
	}
	hits = hits[:n]
	if len(hits) >= max {
		return false
	}
	m[ip] = append(hits, now)
	return true
}

func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		if i := strings.Index(ip, ","); i != -1 {
			ip = strings.TrimSpace(ip[:i])
		}
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

var errTooManyRequests = &staticError{"too many requests"}

type staticError struct{ msg string }

func (e *staticError) Error() string { return e.msg }
