package main

import (
	"context"
	"firewall-ui/internal/api"
	"firewall-ui/internal/auth"
	"firewall-ui/internal/config"
	"firewall-ui/internal/firewall"
	"firewall-ui/internal/ipset"
	"firewall-ui/internal/storage"
	"firewall-ui/internal/system"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Println("firewall-ui", version)
			return
		case "install":
			if err := install(version); err != nil {
				slog.Error("install", "error", err)
				os.Exit(1)
			}
			return
		case "uninstall":
			if err := uninstall(); err != nil {
				slog.Error("uninstall", "error", err)
				os.Exit(1)
			}
			return
		case "status":
			status()
			return
		case "rollback-file":
			if err := rollbackFileCmd(os.Args[2:]); err != nil {
				slog.Error("rollback-file", "error", err)
				os.Exit(1)
			}
			return
		}
	}
	cfg := config.Load(os.Args[1:])
	if err := config.Prepare(cfg); err != nil {
		slog.Error("prepare directories", "error", err)
		os.Exit(1)
	}
	store, err := storage.Open(cfg.Database)
	if err != nil {
		slog.Error("open database", "error", err)
		os.Exit(1)
	}
	defer store.DB.Close()
	backend := firewall.NewIPTables(cfg.Backups)
	backend6 := firewall.NewIP6Tables(cfg.Backups)
	draft := firewall.NewDraftService(backend, cfg.RollbackTimeout)
	draft6 := firewall.NewDraftService(backend6, cfg.RollbackTimeout)
	draft.SafeMode = cfg.SafeMode
	draft6.SafeMode = cfg.SafeMode
	if v, err := store.Setting("safe_mode"); err == nil {
		draft.SafeMode = v == "true"
		draft6.SafeMode = v == "true"
	}
	if v, err := store.Setting("rollback_timeout"); err == nil {
		if secs, err := time.ParseDuration(v + "s"); err == nil {
			draft.SetTimeout(secs)
			draft6.SetTimeout(secs)
		}
	}
	draft.AfterApply = func(b *firewall.Backup, deadline time.Time) {
		if os.Getenv("INVOCATION_ID") != "" || os.Getenv("FWUI_ROLLBACK_HELPER") == "true" {
			scheduleRollbackHelper(time.Until(deadline), b.Path)
		}
	}
	if v, err := store.Setting("backup_retention"); err == nil {
		if n, err := strconv.Atoi(v); err == nil {
			draft.MaxBackups = n
			draft6.MaxBackups = n
		}
	}
	if err := draft.EnablePersistentRollback(cfg.Backups); err != nil {
		slog.Error("recover rollback state", "error", err)
		os.Exit(1)
	}
	state6Dir := filepath.Join(cfg.Backups, "state6")
	_ = os.MkdirAll(state6Dir, 0700)
	if err := draft6.EnablePersistentRollback(state6Dir); err != nil {
		slog.Error("recover ipv6 rollback state", "error", err)
	}
	if _, err := draft.Refresh(); err != nil {
		slog.Warn("initial firewall load failed", "error", err)
	}
	if _, err := draft6.Refresh(); err != nil {
		slog.Warn("initial ipv6 firewall load failed", "error", err)
	}
	srv := &api.Server{Auth: &auth.Service{Store: store, Secure: cfg.SecureCookie}, Store: store, Draft: draft, Draft6: draft6, IPSet: ipset.New(), System: system.Detect(context.Background())}
	httpServer := &http.Server{Addr: cfg.Listen, Handler: api.WithAliasRoutes(srv, srv.Handler()), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		slog.Info("firewall-ui started", "listen", cfg.Listen, "version", version)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http server", "error", err)
			os.Exit(1)
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
}
