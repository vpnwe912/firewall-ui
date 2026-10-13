package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"firewall-ui/internal/storage"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Principal struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	CSRF      string `json:"csrf"`
	Scopes    string `json:"scopes,omitempty"`
	TokenHash string `json:"-"`
}
type Service struct {
	Store    *storage.Store
	Secure   bool
	mu       sync.Mutex
	fails    map[string]int
	locked   map[string]time.Time
	ipFails  map[string]int
	ipLocked map[string]time.Time
}

func (s *Service) Bootstrap(username, password string) error {
	n, err := s.Store.UserCount()
	if err != nil {
		return err
	}
	if n > 0 {
		return errors.New("administrator already exists")
	}
	return s.create(username, password, "admin")
}
func (s *Service) create(username, password, role string) error {
	if len(username) < 3 || len(username) > 64 || strings.TrimSpace(username) != username {
		return errors.New("invalid username")
	}
	if len(password) < 10 {
		return errors.New("password must contain at least 10 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return err
	}
	return s.Store.CreateUser(username, string(hash), role)
}
func (s *Service) Login(username, password, remoteAddr string) (string, Principal, error) {
	key := remoteAddr + "|" + username
	s.mu.Lock()
	if s.fails == nil {
		s.fails = map[string]int{}
		s.locked = map[string]time.Time{}
		s.ipFails = map[string]int{}
		s.ipLocked = map[string]time.Time{}
	}
	now := time.Now()
	if until, ok := s.locked[key]; ok && now.Before(until) {
		s.mu.Unlock()
		s.Store.AddLoginAttempt(remoteAddr, username, false, true, "rate limited (user)")
		return "", Principal{}, errors.New("too many failed attempts, try again later")
	}
	if until, ok := s.ipLocked[remoteAddr]; ok && now.Before(until) {
		s.mu.Unlock()
		s.Store.AddLoginAttempt(remoteAddr, username, false, true, "rate limited (ip)")
		return "", Principal{}, errors.New("too many failed attempts, try again later")
	}
	s.mu.Unlock()
	u, err := s.Store.UserByName(username)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		s.mu.Lock()
		s.fails[key]++
		s.ipFails[remoteAddr]++
		locked := false
		if s.fails[key] >= 5 {
			s.locked[key] = time.Now().Add(5 * time.Minute)
			s.fails[key] = 0
			locked = true
		}
		if s.ipFails[remoteAddr] >= 20 {
			s.ipLocked[remoteAddr] = time.Now().Add(15 * time.Minute)
			s.ipFails[remoteAddr] = 0
			locked = true
		}
		s.mu.Unlock()
		s.Store.AddLoginAttempt(remoteAddr, username, false, locked, "invalid credentials")
		return "", Principal{}, errors.New("invalid credentials")
	}
	s.mu.Lock()
	delete(s.fails, key)
	delete(s.locked, key)
	delete(s.ipFails, remoteAddr)
	delete(s.ipLocked, remoteAddr)
	s.mu.Unlock()
	s.Store.CleanupSessions()
	s.Store.AddLoginAttempt(remoteAddr, username, true, false, "success")
	token := random(32)
	csrf := random(24)
	hash := digest(token)
	if err = s.Store.SaveSession(hash, u.ID, csrf, time.Now().Add(s.sessionTTL())); err != nil {
		return "", Principal{}, err
	}
	return token, Principal{ID: u.ID, Username: u.Username, Role: u.Role, CSRF: csrf, TokenHash: hash}, nil
}
func (s *Service) sessionTTL() time.Duration {
	mins := 12 * 60
	if v, err := s.Store.Setting("session_ttl_minutes"); err == nil {
		if n, e := strconv.Atoi(v); e == nil && n > 0 {
			mins = n
		}
	}
	return time.Duration(mins) * time.Minute
}
func (s *Service) Authenticate(r *http.Request) (Principal, error) {
	token := ""
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		token = strings.TrimPrefix(h, "Bearer ")
		if strings.HasPrefix(token, "fw_") {
			return s.authenticateToken(token)
		}
	} else if c, err := r.Cookie("fwui_session"); err == nil {
		token = c.Value
	}
	if token == "" {
		return Principal{}, errors.New("authentication required")
	}
	u, csrf, err := s.Store.Session(digest(token))
	if err != nil {
		return Principal{}, errors.New("invalid session")
	}
	return Principal{ID: u.ID, Username: u.Username, Role: u.Role, CSRF: csrf, TokenHash: digest(token)}, nil
}
func (s *Service) authenticateToken(token string) (Principal, error) {
	t, err := s.Store.APIToken(digest(token))
	if err != nil {
		return Principal{}, errors.New("invalid api token")
	}
	s.Store.TouchToken(t.ID)
	role := "viewer"
	for _, sc := range strings.Split(t.Scopes, ",") {
		sc = strings.TrimSpace(sc)
		if sc == "admin" {
			role = "admin"
			break
		}
		if strings.HasSuffix(sc, ":write") {
			role = "operator"
		}
	}
	return Principal{ID: -t.ID, Username: "token:" + t.Name, Role: role, Scopes: t.Scopes}, nil
}
func (s *Service) CreateToken(name, scopes string) (string, int64, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", 0, err
	}
	token := "fw_" + base64.RawURLEncoding.EncodeToString(raw)
	id, err := s.Store.CreateToken(name, digest(token), scopes)
	if err != nil {
		return "", 0, err
	}
	return token, id, nil
}
func (s *Service) CreateUser(username, password, role string) error {
	return s.create(username, password, role)
}
func (s *Service) HashPassword(password string) (string, error) {
	if len(password) < 10 {
		return "", errors.New("password must contain at least 10 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(hash), err
}
func (s *Service) Locks() []map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]string
	now := time.Now()
	for k, until := range s.locked {
		if now.Before(until) {
			out = append(out, map[string]string{"key": k, "type": "user", "until": until.UTC().Format(time.RFC3339)})
		}
	}
	for k, until := range s.ipLocked {
		if now.Before(until) {
			out = append(out, map[string]string{"key": k, "type": "ip", "until": until.UTC().Format(time.RFC3339)})
		}
	}
	return out
}
func (s *Service) SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: "fwui_session", Value: token, Path: "/", HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
}
func (s *Service) Logout(w http.ResponseWriter, p Principal) {
	s.Store.DeleteSession(p.TokenHash)
	http.SetCookie(w, &http.Cookie{Name: "fwui_session", Path: "/", HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}
func random(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func digest(v string) string { sum := sha256.Sum256([]byte(v)); return hex.EncodeToString(sum[:]) }
