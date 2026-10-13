package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen          string
	Database        string
	Backups         string
	RollbackTimeout time.Duration
	SecureCookie    bool
	SafeMode        bool
	AuthEnabled     bool
	Backend         string
	TLSEnabled      bool
	TLSCert         string
	TLSKey          string
}

func Load(args []string) Config {
	cfg := Config{
		Listen:          "0.0.0.0:8921",
		Database:        "/var/lib/firewall-ui/firewall.db",
		Backups:         "/var/lib/firewall-ui/backups",
		RollbackTimeout: 120 * time.Second,
		AuthEnabled:     true,
		Backend:         "iptables",
	}
	configPath := "/etc/firewall-ui/config.yaml"
	for i, a := range args {
		if a == "--config" && i+1 < len(args) {
			configPath = args[i+1]
		}
	}
	applyFile(&cfg, configPath)
	cfg.Listen = env("FWUI_LISTEN", cfg.Listen)
	cfg.Database = env("FWUI_DATABASE", cfg.Database)
	cfg.Backups = env("FWUI_BACKUPS", cfg.Backups)
	if v := env("FWUI_ROLLBACK_TIMEOUT", ""); v != "" {
		if secs, err := strconv.Atoi(v); err == nil {
			cfg.RollbackTimeout = time.Duration(secs) * time.Second
		}
	}
	if v := env("FWUI_SECURE_COOKIE", ""); v != "" {
		cfg.SecureCookie = v == "true"
	}
	if v := env("FWUI_SAFE_MODE", ""); v != "" {
		cfg.SafeMode = v == "true"
	}
	fs := flag.NewFlagSet("firewall-ui", flag.ContinueOnError)
	fs.StringVar(&cfg.Listen, "listen", cfg.Listen, "HTTP listen address")
	fs.StringVar(&cfg.Database, "database", cfg.Database, "SQLite database path")
	fs.StringVar(&cfg.Backups, "backups", cfg.Backups, "backup directory")
	fs.DurationVar(&cfg.RollbackTimeout, "rollback-timeout", cfg.RollbackTimeout, "automatic rollback timeout")
	fs.BoolVar(&cfg.SecureCookie, "secure-cookie", cfg.SecureCookie, "mark cookies Secure")
	fs.BoolVar(&cfg.SafeMode, "safe-mode", cfg.SafeMode, "restrict edits to FWUI_* chains")
	fs.String("config", configPath, "config file path")
	_ = fs.Parse(args)
	return cfg
}

func applyFile(cfg *Config, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return
	}
	if s, ok := getMap(root, "server"); ok {
		if v, ok := getString(s, "listen"); ok {
			cfg.Listen = v
		}
	}
	if f, ok := getMap(root, "firewall"); ok {
		if v, ok := getString(f, "backend"); ok {
			cfg.Backend = v
		}
		if v, ok := getString(f, "mode"); ok {
			cfg.SafeMode = v == "safe"
		}
		if v, ok := getInt(f, "rollback_timeout"); ok {
			cfg.RollbackTimeout = time.Duration(v) * time.Second
		}
	}
	if s, ok := getMap(root, "storage"); ok {
		if v, ok := getString(s, "database"); ok {
			cfg.Database = v
		}
		if v, ok := getString(s, "backups"); ok {
			cfg.Backups = v
		}
	}
	if a, ok := getMap(root, "auth"); ok {
		if v, ok := getBool(a, "enabled"); ok {
			cfg.AuthEnabled = v
		}
	}
	if t, ok := getMap(root, "tls"); ok {
		if v, ok := getBool(t, "enabled"); ok {
			cfg.TLSEnabled = v
		}
		if v, ok := getString(t, "cert"); ok {
			cfg.TLSCert = v
		}
		if v, ok := getString(t, "key"); ok {
			cfg.TLSKey = v
		}
	}
}

func getMap(m map[string]any, key string) (map[string]any, bool) {
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	sub, ok := v.(map[string]any)
	return sub, ok
}

func getString(m map[string]any, key string) (string, bool) {
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func getInt(m map[string]any, key string) (int, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case string:
		if i, err := strconv.Atoi(n); err == nil {
			return i, true
		}
	}
	return 0, false
}

func getBool(m map[string]any, key string) (bool, bool) {
	v, ok := m[key]
	if !ok {
		return false, false
	}
	switch b := v.(type) {
	case bool:
		return b, true
	case string:
		return b == "true" || b == "yes" || b == "1", true
	}
	return false, false
}

func Prepare(cfg Config) error {
	for _, dir := range []string{filepath.Dir(cfg.Database), cfg.Backups} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	return nil
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func WriteDefault(path string) error {
	text := fmt.Sprintf(`server:
  listen: "%s"

firewall:
  backend: "%s"
  mode: "%s"
  rollback_timeout: %d

storage:
  database: "%s"
  backups: "%s"

auth:
  enabled: true

tls:
  enabled: false
  cert: ""
  key: ""
`, "0.0.0.0:8921", "iptables", "safe", 120, "/var/lib/firewall-ui/firewall.db", "/var/lib/firewall-ui/backups")
	return os.WriteFile(path, []byte(text), 0600)
}
