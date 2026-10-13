package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	rollbackstate "firewall-ui/internal/rollback"
)

var ErrChangedExternally = errors.New("Firewall configuration has changed externally. Reload before applying.")

type Runner interface {
	Run(context.Context, string, []string, []byte) ([]byte, error)
}
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args []string, input []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

type IPTablesBackend struct {
	Runner     Runner
	BackupsDir string
	Timeout    time.Duration
	V6         bool
}

func NewIPTables(backups string) *IPTablesBackend {
	return &IPTablesBackend{Runner: ExecRunner{}, BackupsDir: backups, Timeout: 15 * time.Second}
}
func NewIP6Tables(backups string) *IPTablesBackend {
	return &IPTablesBackend{Runner: ExecRunner{}, BackupsDir: backups, Timeout: 15 * time.Second, V6: true}
}
func (b *IPTablesBackend) bin(name string) string {
	if b.V6 {
		return "ip6" + name[len("ip"):] // iptables-save -> ip6tables-save
	}
	return name
}
func (b *IPTablesBackend) prefix() string {
	if b.V6 {
		return "ip6tables-"
	}
	return "iptables-"
}
func (b *IPTablesBackend) prefixIPSet() string { return "ipset-" }
func (b *IPTablesBackend) command(name string, args []string, input []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), b.Timeout)
	defer cancel()
	return b.Runner.Run(ctx, name, args, input)
}
func (b *IPTablesBackend) Load() (*Ruleset, error) {
	out, err := b.command(b.bin("iptables-save"), []string{"-c"}, nil)
	if err != nil {
		return nil, err
	}
	return Parse(string(out)), nil
}
func (b *IPTablesBackend) Validate(rs *Ruleset) error {
	rendered, err := Render(rs)
	if err != nil {
		return err
	}
	_, err = b.command(b.bin("iptables-restore"), []string{"--test"}, []byte(rendered))
	return err
}
func (b *IPTablesBackend) Apply(rs *Ruleset) error {
	current, err := b.command(b.bin("iptables-save"), nil, nil)
	if err != nil {
		return err
	}
	if SnapshotID(current) != rs.SnapshotID {
		return ErrChangedExternally
	}
	rendered, err := Render(rs)
	if err != nil {
		return err
	}
	if _, err = b.command(b.bin("iptables-restore"), []string{"--test"}, []byte(rendered)); err != nil {
		return err
	}
	_, err = b.command(b.bin("iptables-restore"), nil, []byte(rendered))
	return err
}
func (b *IPTablesBackend) Backup() (*Backup, error) {
	raw, err := b.command(b.bin("iptables-save"), nil, nil)
	if err != nil {
		return nil, err
	}
	snapshot := SnapshotID(raw)
	id := time.Now().UTC().Format("20060102-150405.000000000")
	path := filepath.Join(b.BackupsDir, b.prefix()+id+".rules")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		return nil, err
	}
	if ipsets, err := b.command("ipset", []string{"save"}, nil); err == nil {
		_ = os.WriteFile(filepath.Join(b.BackupsDir, b.prefixIPSet()+id+".save"), ipsets, 0600)
	}
	return &Backup{ID: id, Path: path, Snapshot: snapshot, CreatedAt: time.Now().UTC(), Status: "ready"}, nil
}
func (b *IPTablesBackend) PruneBackups(keep int) {
	if keep <= 0 {
		return
	}
	backups, err := b.Backups()
	if err != nil || len(backups) <= keep {
		return
	}
	for _, bk := range backups[keep:] {
		_ = os.Remove(bk.Path)
		_ = os.Remove(filepath.Join(b.BackupsDir, b.prefixIPSet()+bk.ID+".save"))
	}
}
func (b *IPTablesBackend) Backups() ([]Backup, error) {
	entries, err := os.ReadDir(b.BackupsDir)
	if err != nil {
		return nil, err
	}
	var backups []Backup
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), b.prefix()) || !strings.HasSuffix(entry.Name(), ".rules") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		id := strings.TrimSuffix(strings.TrimPrefix(entry.Name(), b.prefix()), ".rules")
		backups = append(backups, Backup{ID: id, Path: filepath.Join(b.BackupsDir, entry.Name()), CreatedAt: info.ModTime().UTC(), Status: "ready"})
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].CreatedAt.After(backups[j].CreatedAt) })
	return backups, nil
}
func (b *IPTablesBackend) ResetCounters() error {
	_, err := b.command(b.bin("iptables"), []string{"-Z"}, nil)
	return err
}
func (b *IPTablesBackend) RestoreByID(id string) error {
	if strings.ContainsAny(id, "/\\\n\r") {
		return errors.New("invalid backup id")
	}
	return b.Restore(&Backup{ID: id, Path: filepath.Join(b.BackupsDir, b.prefix()+id+".rules")})
}
func (b *IPTablesBackend) BackupContent(id string) ([]byte, error) {
	if strings.ContainsAny(id, "/\\\n\r") {
		return nil, errors.New("invalid backup id")
	}
	return os.ReadFile(filepath.Join(b.BackupsDir, b.prefix()+id+".rules"))
}
func (b *IPTablesBackend) DeleteBackup(id string) error {
	if strings.ContainsAny(id, "/\\\n\r") {
		return errors.New("invalid backup id")
	}
	_ = os.Remove(filepath.Join(b.BackupsDir, b.prefixIPSet()+id+".save"))
	return os.Remove(filepath.Join(b.BackupsDir, b.prefix()+id+".rules"))
}
func (b *IPTablesBackend) Restore(backup *Backup) error {
	raw, err := os.ReadFile(backup.Path)
	if err != nil {
		return err
	}
	if _, err = b.command(b.bin("iptables-restore"), []string{"--test"}, raw); err != nil {
		return err
	}
	if _, err = b.command(b.bin("iptables-restore"), nil, raw); err != nil {
		return err
	}
	ipsetPath := filepath.Join(b.BackupsDir, b.prefixIPSet()+backup.ID+".save")
	if sets, err := os.ReadFile(ipsetPath); err == nil && len(sets) > 0 {
		_, _ = b.command("ipset", []string{"restore", "-exist"}, sets)
	}
	return nil
}

type DraftService struct {
	mu         sync.RWMutex
	backend    FirewallBackend
	draft      *Ruleset
	rollback   *Backup
	timer      *time.Timer
	deadline   time.Time
	timeout    time.Duration
	stateDir   string
	lastBackup string
	OnBackup   func(*Backup)
	AfterApply func(*Backup, time.Time)
	SafeMode   bool
	MaxBackups int
}

func NewDraftService(b FirewallBackend, timeout time.Duration) *DraftService {
	return &DraftService{backend: b, timeout: timeout}
}
func (s *DraftService) EnablePersistentRollback(dir string) error {
	s.stateDir = dir
	state, err := rollbackstate.Load(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	backup := &Backup{Path: state.BackupPath, Status: "rollback-pending"}
	if !state.Deadline.After(time.Now()) {
		defer rollbackstate.Clear(dir)
		return s.backend.Restore(backup)
	}
	s.mu.Lock()
	s.rollback = backup
	s.deadline = state.Deadline
	s.timer = time.AfterFunc(time.Until(state.Deadline), func() { _ = s.Rollback() })
	s.mu.Unlock()
	return nil
}
func (s *DraftService) Refresh() (*Ruleset, error) {
	r, e := s.backend.Load()
	if e == nil {
		s.mu.Lock()
		s.draft = r
		s.mu.Unlock()
	}
	return r, e
}
func (s *DraftService) Get() *Ruleset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.draft == nil {
		return nil
	}
	copy := *s.draft
	return &copy
}
func (s *DraftService) Save(r *Ruleset) error {
	if err := ValidateRuleset(r); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.draft != nil && r.SnapshotID != s.draft.SnapshotID {
		return errors.New("draft snapshot mismatch")
	}
	if s.SafeMode && s.draft != nil {
		if err := checkSafeMode(s.draft, r); err != nil {
			return err
		}
	}
	s.draft = r
	return nil
}
func (s *DraftService) SetTimeout(d time.Duration) {
	s.mu.Lock()
	s.timeout = d
	s.mu.Unlock()
}
func checkSafeMode(live, next *Ruleset) error {
	protectedChain := func(c string) bool {
		return !strings.HasPrefix(c, "FWUI_")
	}
	builtin := map[string]bool{"INPUT": true, "FORWARD": true, "OUTPUT": true, "PREROUTING": true, "POSTROUTING": true}
	for key, policy := range next.Policies {
		chain := key[strings.Index(key, "/")+1:]
		if builtin[chain] && live.Policies[key] != policy {
			return fmt.Errorf("safe mode: policy of built-in chain %s cannot be changed", chain)
		}
		if protectedChain(chain) && !builtin[chain] && live.Policies[key] != policy {
			return fmt.Errorf("safe mode: external chain %s cannot be modified", chain)
		}
	}
	group := func(rs *Ruleset) map[string][]Rule {
		m := map[string][]Rule{}
		for _, r := range rs.Rules {
			m[r.Table+"/"+r.Chain] = append(m[r.Table+"/"+r.Chain], r)
		}
		return m
	}
	lm, nm := group(live), group(next)
	keys := map[string]bool{}
	for k := range lm {
		keys[k] = true
	}
	for k := range nm {
		keys[k] = true
	}
	for key := range keys {
		chain := key[strings.Index(key, "/")+1:]
		if !protectedChain(chain) {
			continue
		}
		var lp, np []string
		for _, r := range lm[key] {
			if !strings.HasPrefix(r.Action, "FWUI_") {
				lp = append(lp, ruleSig(r))
			}
		}
		for _, r := range nm[key] {
			if !strings.HasPrefix(r.Action, "FWUI_") {
				np = append(np, ruleSig(r))
			}
		}
		if strings.Join(lp, "\n") != strings.Join(np, "\n") {
			return fmt.Errorf("safe mode: rules in %s are read-only; only jumps to FWUI_* chains may be added or removed", key)
		}
	}
	return nil
}
func (s *DraftService) Validate() error {
	s.mu.RLock()
	d := s.draft
	s.mu.RUnlock()
	if d == nil {
		return errors.New("draft is not loaded")
	}
	return s.backend.Validate(d)
}
func (s *DraftService) Apply() (*Backup, time.Time, error) {
	s.mu.RLock()
	d := s.draft
	s.mu.RUnlock()
	if d == nil {
		return nil, time.Time{}, errors.New("draft is not loaded")
	}
	backup, err := s.backend.Backup()
	if err != nil {
		return nil, time.Time{}, err
	}
	if s.OnBackup != nil {
		s.OnBackup(backup)
	}
	if s.MaxBackups > 0 {
		if p, ok := s.backend.(interface{ PruneBackups(int) }); ok {
			p.PruneBackups(s.MaxBackups)
		}
	}
	if err = s.backend.Apply(d); err != nil {
		return nil, time.Time{}, err
	}
	s.mu.Lock()
	s.rollback = backup
	s.deadline = time.Now().Add(s.timeout)
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(s.timeout, func() { _ = s.Rollback() })
	deadline := s.deadline
	stateDir := s.stateDir
	s.mu.Unlock()
	if stateDir != "" {
		if err := rollbackstate.Save(stateDir, rollbackstate.State{BackupPath: backup.Path, Deadline: deadline}); err != nil {
			_ = s.Rollback()
			return nil, time.Time{}, fmt.Errorf("persist rollback state: %w", err)
		}
	}
	if s.AfterApply != nil {
		s.AfterApply(backup, deadline)
	}
	s.mu.Lock()
	s.lastBackup = backup.ID
	s.mu.Unlock()
	return backup, deadline, nil
}
func (s *DraftService) LastBackupID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastBackup
}
func (s *DraftService) Confirm() {
	s.mu.Lock()
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = nil
	s.rollback = nil
	s.deadline = time.Time{}
	stateDir := s.stateDir
	s.mu.Unlock()
	if stateDir != "" {
		_ = rollbackstate.Clear(stateDir)
	}
}
func (s *DraftService) Rollback() error {
	s.mu.Lock()
	backup := s.rollback
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = nil
	s.rollback = nil
	s.deadline = time.Time{}
	stateDir := s.stateDir
	s.mu.Unlock()
	if stateDir != "" {
		defer rollbackstate.Clear(stateDir)
	}
	if backup == nil {
		return errors.New("no rollback snapshot available")
	}
	return s.backend.Restore(backup)
}
func (s *DraftService) RollbackStatus() (bool, time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rollback != nil, s.deadline
}
func (s *DraftService) Discard() (*Ruleset, error) { return s.Refresh() }
func (s *DraftService) Backups() ([]Backup, error) {
	backend, ok := s.backend.(interface{ Backups() ([]Backup, error) })
	if !ok {
		return nil, errors.New("backups are not supported by backend")
	}
	return backend.Backups()
}
func (s *DraftService) RestoreBackup(id string) error {
	backend, ok := s.backend.(interface{ RestoreByID(string) error })
	if !ok {
		return errors.New("backup restore is not supported by backend")
	}
	if err := backend.RestoreByID(id); err != nil {
		return err
	}
	_, err := s.Refresh()
	return err
}
func (s *DraftService) ResetCounters() error {
	backend, ok := s.backend.(interface{ ResetCounters() error })
	if !ok {
		return errors.New("counter reset is not supported by backend")
	}
	return backend.ResetCounters()
}
func (s *DraftService) BackupContent(id string) ([]byte, error) {
	backend, ok := s.backend.(interface{ BackupContent(string) ([]byte, error) })
	if !ok {
		return nil, errors.New("backups are not supported by backend")
	}
	return backend.BackupContent(id)
}
func (s *DraftService) DeleteBackup(id string) error {
	backend, ok := s.backend.(interface{ DeleteBackup(string) error })
	if !ok {
		return errors.New("backups are not supported by backend")
	}
	return backend.DeleteBackup(id)
}
func (s *DraftService) Diff() (*DiffResult, error) {
	s.mu.RLock()
	d := s.draft
	s.mu.RUnlock()
	if d == nil {
		return nil, errors.New("draft is not loaded")
	}
	live, err := s.backend.Load()
	if err != nil {
		return nil, err
	}
	return DiffRulesets(live, d), nil
}
