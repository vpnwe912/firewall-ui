package rollback

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type State struct {
	BackupPath string    `json:"backup_path"`
	Deadline   time.Time `json:"deadline"`
	Confirmed  bool      `json:"confirmed"`
}

func Save(dir string, s State) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "rollback-state.json.tmp")
	final := filepath.Join(dir, "rollback-state.json")
	if err = os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}
func Load(dir string) (State, error) {
	var s State
	data, err := os.ReadFile(filepath.Join(dir, "rollback-state.json"))
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(data, &s)
	return s, err
}
func Clear(dir string) error {
	err := os.Remove(filepath.Join(dir, "rollback-state.json"))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
