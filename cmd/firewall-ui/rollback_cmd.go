package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"firewall-ui/internal/firewall"
	rollbackstate "firewall-ui/internal/rollback"
)

// rollbackFileCmd is executed by the transient systemd unit scheduled after
// every Apply. It restores the given backup only when the persisted rollback
// state is still present — meaning the main process never confirmed the change.
func rollbackFileCmd(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: firewall-ui rollback-file <backup-path>")
	}
	backupPath := args[0]
	stateDir := filepath.Dir(backupPath)
	state, err := rollbackstate.Load(stateDir)
	if err != nil {
		return nil
	}
	backend := firewall.NewIPTables(stateDir)
	id := filepath.Base(backupPath)
	id = id[len("iptables-") : len(id)-len(".rules")]
	if err := backend.Restore(&firewall.Backup{ID: id, Path: backupPath}); err != nil {
		return err
	}
	_ = state
	rollbackstate.Clear(stateDir)
	return nil
}

// scheduleRollbackHelper registers a transient systemd unit that performs the
// rollback even if this process dies before the deadline.
func scheduleRollbackHelper(timeout time.Duration, backupPath string) {
	self, err := os.Executable()
	if err != nil {
		return
	}
	unit := fmt.Sprintf("fwui-rollback-%d", time.Now().Unix())
	delay := fmt.Sprintf("--on-active=%ds", int(timeout.Seconds()))
	_ = exec.Command("systemd-run", "--unit="+unit, delay, self, "rollback-file", backupPath).Run()
}
