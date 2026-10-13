package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNestedYAMLConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `server:
  listen: "127.0.0.1:9999"
firewall:
  backend: "iptables"
  mode: "safe"
  rollback_timeout: 300
storage:
  database: "/tmp/test.db"
  backups: "/tmp/backups"
auth:
  enabled: false
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := Load([]string{"--config", path})
	if cfg.Listen != "127.0.0.1:9999" {
		t.Fatalf("listen=%s", cfg.Listen)
	}
	if cfg.Database != "/tmp/test.db" {
		t.Fatalf("database=%s", cfg.Database)
	}
	if cfg.Backups != "/tmp/backups" {
		t.Fatalf("backups=%s", cfg.Backups)
	}
	if cfg.RollbackTimeout != 300*time.Second {
		t.Fatalf("rollback=%s", cfg.RollbackTimeout)
	}
	if !cfg.SafeMode {
		t.Fatal("safe mode should be true")
	}
	if cfg.AuthEnabled {
		t.Fatal("auth should be disabled")
	}
}

func TestWriteDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := WriteDefault(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "server:") || !strings.Contains(string(data), "firewall:") {
		t.Fatalf("default config missing sections: %s", string(data))
	}
}
