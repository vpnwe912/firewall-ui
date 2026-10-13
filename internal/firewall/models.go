package firewall

import "time"

type AddressMatch struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
type PortRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}
type Rule struct {
	ID           string       `json:"id"`
	Table        string       `json:"table"`
	Chain        string       `json:"chain"`
	Action       string       `json:"action"`
	Source       AddressMatch `json:"source"`
	Destination  AddressMatch `json:"destination"`
	Protocol     string       `json:"protocol"`
	SourcePorts  []PortRange  `json:"source_ports"`
	DestPorts    []PortRange  `json:"dest_ports"`
	InInterface  string       `json:"in_interface"`
	OutInterface string       `json:"out_interface"`
	ToAddress    string       `json:"to_address"`
	ToPort       int          `json:"to_port"`
	States       []string     `json:"states"`
	Comment      string       `json:"comment"`
	Enabled      bool         `json:"enabled"`
	Position     int          `json:"position"`
	Packets      uint64       `json:"packets"`
	Bytes        uint64       `json:"bytes"`
}
type RawRule struct {
	Table    string `json:"table"`
	Chain    string `json:"chain"`
	Line     string `json:"line"`
	Position int    `json:"position"`
	Reason   string `json:"reason"`
}
type Ruleset struct {
	SnapshotID  string            `json:"snapshot_id"`
	Raw         string            `json:"raw"`
	Policies    map[string]string `json:"policies"`
	Aliases     map[string]string `json:"aliases,omitempty"`
	Rules       []Rule            `json:"rules"`
	Unsupported []RawRule         `json:"unsupported"`
	LoadedAt    time.Time         `json:"loaded_at"`
}
type Backup struct {
	ID        string    `json:"id"`
	Path      string    `json:"path"`
	Snapshot  string    `json:"snapshot"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"`
	Username  string    `json:"username"`
	Comment   string    `json:"comment"`
}
type DiffEntry struct {
	Kind    string `json:"kind"`
	Object  string `json:"object"`
	Details string `json:"details"`
}
type DiffResult struct {
	Entries []DiffEntry `json:"entries"`
	Changed int         `json:"changed"`
}

type FirewallBackend interface {
	Load() (*Ruleset, error)
	Validate(*Ruleset) error
	Apply(*Ruleset) error
	Backup() (*Backup, error)
	Restore(*Backup) error
}
