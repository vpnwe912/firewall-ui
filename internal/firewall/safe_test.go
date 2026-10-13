package firewall

import (
	"strings"
	"testing"
)

func TestSafeModeBlocksBuiltInRuleChange(t *testing.T) {
	live := &Ruleset{
		Policies: map[string]string{
			"filter/INPUT":   "ACCEPT",
			"filter/FORWARD": "ACCEPT",
			"filter/OUTPUT":  "ACCEPT",
		},
		Rules: []Rule{
			{ID: "r1", Table: "filter", Chain: "INPUT", Action: "ACCEPT", Source: AddressMatch{Type: "any"}, Destination: AddressMatch{Type: "any"}, Enabled: true},
		},
	}
	// Adding a new ACCEPT rule in INPUT should fail.
	next := cloneRuleset(live)
	next.Rules = append(next.Rules, Rule{ID: "r2", Table: "filter", Chain: "INPUT", Action: "ACCEPT", Source: AddressMatch{Type: "any"}, Destination: AddressMatch{Type: "any"}, Enabled: true})
	if err := checkSafeMode(live, next); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("expected read-only error, got %v", err)
	}
	// Adding a jump to a FWUI_* chain in INPUT should succeed.
	next2 := cloneRuleset(live)
	next2.Rules = append(next2.Rules, Rule{ID: "r3", Table: "filter", Chain: "INPUT", Action: "FWUI_SSH", Source: AddressMatch{Type: "any"}, Destination: AddressMatch{Type: "any"}, Enabled: true})
	if err := checkSafeMode(live, next2); err != nil {
		t.Fatalf("expected jump to FWUI_* allowed, got %v", err)
	}
	// Changing built-in chain policy should fail.
	next3 := cloneRuleset(live)
	next3.Policies["filter/INPUT"] = "DROP"
	if err := checkSafeMode(live, next3); err == nil || !strings.Contains(err.Error(), "policy") {
		t.Fatalf("expected policy error, got %v", err)
	}
	// Modifying rule inside FWUI_* chain should succeed.
	next4 := cloneRuleset(live)
	next4.Rules = append(next4.Rules, Rule{ID: "r4", Table: "filter", Chain: "FWUI_TEST", Action: "DROP", Source: AddressMatch{Type: "any"}, Destination: AddressMatch{Type: "any"}, Enabled: true})
	if err := checkSafeMode(live, next4); err != nil {
		t.Fatalf("expected FWUI_* rule allowed, got %v", err)
	}
}

func cloneRuleset(r *Ruleset) *Ruleset {
	next := &Ruleset{
		Policies: map[string]string{},
		Rules:    make([]Rule, len(r.Rules)),
	}
	for k, v := range r.Policies {
		next.Policies[k] = v
	}
	copy(next.Rules, r.Rules)
	return next
}
