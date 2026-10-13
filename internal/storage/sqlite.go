package storage

import (
	"database/sql"
	_ "modernc.org/sqlite"
	"time"
)

type Store struct{ DB *sql.DB }
type User struct {
	ID                           int64
	Username, PasswordHash, Role string
}
type Audit struct {
	ID        int64  `json:"id"`
	CreatedAt string `json:"created_at"`
	Username  string `json:"username"`
	IP        string `json:"ip"`
	Action    string `json:"action"`
	Object    string `json:"object"`
	Result    string `json:"result"`
	Before    string `json:"before"`
	After     string `json:"after"`
	Details   string `json:"details"`
}
type Alias struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
}
type BackupMeta struct {
	ID        string `json:"id"`
	Path      string `json:"path"`
	Snapshot  string `json:"snapshot"`
	CreatedAt string `json:"created_at"`
	Status    string `json:"status"`
	Username  string `json:"username"`
	Comment   string `json:"comment"`
}
type APIToken struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Scopes    string `json:"scopes"`
	CreatedAt string `json:"created_at"`
	LastUsed  string `json:"last_used"`
}
type LoginAttempt struct {
	ID        int64  `json:"id"`
	CreatedAt string `json:"created_at"`
	IP        string `json:"ip"`
	Username  string `json:"username"`
	Success   bool   `json:"success"`
	Locked    bool   `json:"locked"`
	Message   string `json:"message"`
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{DB: db}
	if err = s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) migrate() error {
	_, err := s.DB.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('viewer','operator','admin')), created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, csrf_token TEXT NOT NULL, expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, username TEXT NOT NULL, ip TEXT NOT NULL, action TEXT NOT NULL, object TEXT NOT NULL, result TEXT NOT NULL, before TEXT NOT NULL DEFAULT '', after TEXT NOT NULL DEFAULT '', details TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS backup_metadata(id TEXT PRIMARY KEY, path TEXT NOT NULL, snapshot TEXT NOT NULL, created_at TEXT NOT NULL, status TEXT NOT NULL, username TEXT NOT NULL DEFAULT '', comment TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS aliases(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, address TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS api_tokens(id INTEGER PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, scopes TEXT NOT NULL, created_at TEXT NOT NULL, last_used TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS login_attempts(id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, ip TEXT NOT NULL, username TEXT NOT NULL, success INTEGER NOT NULL, locked INTEGER NOT NULL, message TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);`)
	if err != nil {
		return err
	}
	_, _ = s.DB.Exec(`ALTER TABLE backup_metadata ADD COLUMN username TEXT NOT NULL DEFAULT ''`)
	_, _ = s.DB.Exec(`ALTER TABLE backup_metadata ADD COLUMN comment TEXT NOT NULL DEFAULT ''`)
	_, _ = s.DB.Exec(`ALTER TABLE audit_log ADD COLUMN before TEXT NOT NULL DEFAULT ''`)
	_, _ = s.DB.Exec(`ALTER TABLE audit_log ADD COLUMN after TEXT NOT NULL DEFAULT ''`)
	_, _ = s.DB.Exec(`ALTER TABLE audit_log ADD COLUMN details TEXT NOT NULL DEFAULT ''`)
	return nil
}
func (s *Store) UserCount() (int, error) {
	var n int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}
func (s *Store) CreateUser(name, hash, role string) error {
	_, err := s.DB.Exec(`INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)`, name, hash, role, time.Now().UTC().Format(time.RFC3339))
	return err
}
func (s *Store) UserByName(name string) (User, error) {
	var u User
	err := s.DB.QueryRow(`SELECT id,username,password_hash,role FROM users WHERE username=?`, name).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role)
	return u, err
}
func (s *Store) SaveSession(hash string, uid int64, csrf string, expires time.Time) error {
	_, err := s.DB.Exec(`INSERT OR REPLACE INTO sessions VALUES(?,?,?,?)`, hash, uid, csrf, expires.UTC().Format(time.RFC3339))
	return err
}
func (s *Store) Session(hash string) (User, string, error) {
	var u User
	var csrf, expires string
	err := s.DB.QueryRow(`SELECT u.id,u.username,u.password_hash,u.role,s.csrf_token,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`, hash).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &csrf, &expires)
	if err == nil {
		t, _ := time.Parse(time.RFC3339, expires)
		if time.Now().After(t) {
			err = sql.ErrNoRows
		}
	}
	return u, csrf, err
}
func (s *Store) DeleteSession(hash string) {
	_, _ = s.DB.Exec(`DELETE FROM sessions WHERE token_hash=?`, hash)
}
func (s *Store) CleanupSessions() {
	_, _ = s.DB.Exec(`DELETE FROM sessions WHERE expires_at<?`, time.Now().UTC().Format(time.RFC3339))
}
func (s *Store) AddAudit(user, ip, action, object, result string) {
	s.addAudit(user, ip, action, object, result, "", "", "")
}
func (s *Store) AddAuditDetails(user, ip, action, object, result, details string) {
	s.addAudit(user, ip, action, object, result, "", "", details)
}
func (s *Store) AddAuditFull(user, ip, action, object, result, before, after, details string) {
	s.addAudit(user, ip, action, object, result, before, after, details)
}
func (s *Store) addAudit(user, ip, action, object, result, before, after, details string) {
	_, _ = s.DB.Exec(`INSERT INTO audit_log(created_at,username,ip,action,object,result,before,after,details) VALUES(?,?,?,?,?,?,?,?,?)`, time.Now().UTC().Format(time.RFC3339), user, ip, action, object, result, before, after, details)
}
func (s *Store) Audits() ([]Audit, error) {
	rows, err := s.DB.Query(`SELECT id,created_at,username,ip,action,object,result,COALESCE(before,''),COALESCE(after,''),COALESCE(details,'') FROM audit_log ORDER BY id DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Audit
	for rows.Next() {
		var a Audit
		if err = rows.Scan(&a.ID, &a.CreatedAt, &a.Username, &a.IP, &a.Action, &a.Object, &a.Result, &a.Before, &a.After, &a.Details); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (s *Store) Aliases() ([]Alias, error) {
	rows, err := s.DB.Query(`SELECT id,name,address FROM aliases ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alias
	for rows.Next() {
		var a Alias
		if err = rows.Scan(&a.ID, &a.Name, &a.Address); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (s *Store) CreateAlias(name, address string) error {
	_, err := s.DB.Exec(`INSERT INTO aliases(name,address,created_at) VALUES(?,?,?)`, name, address, time.Now().UTC().Format(time.RFC3339))
	return err
}
func (s *Store) DeleteAlias(id int64) error {
	_, err := s.DB.Exec(`DELETE FROM aliases WHERE id=?`, id)
	return err
}
func (s *Store) UpdateAlias(id int64, name, address string) error {
	_, err := s.DB.Exec(`UPDATE aliases SET name=?, address=? WHERE id=?`, name, address, id)
	return err
}
func (s *Store) SaveBackupMeta(m BackupMeta) error {
	_, err := s.DB.Exec(`INSERT OR REPLACE INTO backup_metadata(id,path,snapshot,created_at,status,username,comment) VALUES(?,?,?,?,?,?,?)`, m.ID, m.Path, m.Snapshot, m.CreatedAt, m.Status, m.Username, m.Comment)
	return err
}
func (s *Store) BackupMetas() (map[string]BackupMeta, error) {
	rows, err := s.DB.Query(`SELECT id,path,snapshot,created_at,status,username,comment FROM backup_metadata`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]BackupMeta{}
	for rows.Next() {
		var m BackupMeta
		if err = rows.Scan(&m.ID, &m.Path, &m.Snapshot, &m.CreatedAt, &m.Status, &m.Username, &m.Comment); err != nil {
			return nil, err
		}
		out[m.ID] = m
	}
	return out, rows.Err()
}
func (s *Store) SetBackupStatus(id, status string) error {
	_, err := s.DB.Exec(`UPDATE backup_metadata SET status=? WHERE id=?`, status, id)
	return err
}
func (s *Store) DeleteBackupMeta(id string) error {
	_, err := s.DB.Exec(`DELETE FROM backup_metadata WHERE id=?`, id)
	return err
}
func (s *Store) Users() ([]User, error) {
	rows, err := s.DB.Query(`SELECT id,username,role FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err = rows.Scan(&u.ID, &u.Username, &u.Role); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
func (s *Store) UpdateUser(id int64, role, passwordHash string) error {
	if passwordHash != "" {
		_, err := s.DB.Exec(`UPDATE users SET role=?, password_hash=? WHERE id=?`, role, passwordHash, id)
		return err
	}
	_, err := s.DB.Exec(`UPDATE users SET role=? WHERE id=?`, role, id)
	return err
}
func (s *Store) DeleteUser(id int64) error {
	_, err := s.DB.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}
func (s *Store) DeleteUserSessions(uid int64) error {
	_, err := s.DB.Exec(`DELETE FROM sessions WHERE user_id=?`, uid)
	return err
}
func (s *Store) CreateToken(name, hash, scopes string) (int64, error) {
	res, err := s.DB.Exec(`INSERT INTO api_tokens(name,token_hash,scopes,created_at) VALUES(?,?,?,?)`, name, hash, scopes, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}
func (s *Store) Tokens() ([]APIToken, error) {
	rows, err := s.DB.Query(`SELECT id,name,scopes,created_at,last_used FROM api_tokens ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		if err = rows.Scan(&t.ID, &t.Name, &t.Scopes, &t.CreatedAt, &t.LastUsed); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
func (s *Store) TouchToken(id int64) {
	_, _ = s.DB.Exec(`UPDATE api_tokens SET last_used=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339), id)
}
func (s *Store) DeleteToken(id int64) error {
	_, err := s.DB.Exec(`DELETE FROM api_tokens WHERE id=?`, id)
	return err
}
func (s *Store) APIToken(hash string) (APIToken, error) {
	var t APIToken
	err := s.DB.QueryRow(`SELECT id,name,scopes,created_at,last_used FROM api_tokens WHERE token_hash=?`, hash).Scan(&t.ID, &t.Name, &t.Scopes, &t.CreatedAt, &t.LastUsed)
	return t, err
}
func (s *Store) Setting(key string) (string, error) {
	var v string
	err := s.DB.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	return v, err
}
func (s *Store) SetSetting(key, value string) error {
	_, err := s.DB.Exec(`INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)`, key, value)
	return err
}
func (s *Store) Settings() (map[string]string, error) {
	rows, err := s.DB.Query(`SELECT key,value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err = rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}
func (s *Store) AddLoginAttempt(ip, username string, success, locked bool, message string) {
	var succ, lock int
	if success {
		succ = 1
	}
	if locked {
		lock = 1
	}
	_, _ = s.DB.Exec(`INSERT INTO login_attempts(created_at,ip,username,success,locked,message) VALUES(?,?,?,?,?,?)`, time.Now().UTC().Format(time.RFC3339), ip, username, succ, lock, message)
}
func (s *Store) LoginAttempts() ([]LoginAttempt, error) {
	rows, err := s.DB.Query(`SELECT id,created_at,ip,username,success,locked,message FROM login_attempts ORDER BY id DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LoginAttempt
	for rows.Next() {
		var a LoginAttempt
		var succ, lock int
		if err = rows.Scan(&a.ID, &a.CreatedAt, &a.IP, &a.Username, &succ, &lock, &a.Message); err != nil {
			return nil, err
		}
		a.Success = succ != 0
		a.Locked = lock != 0
		out = append(out, a)
	}
	return out, rows.Err()
}
