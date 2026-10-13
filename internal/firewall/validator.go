package firewall

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var safeName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:+-]{0,31}$`)
var allowedChains = map[string]bool{"INPUT": true, "OUTPUT": true, "FORWARD": true, "PREROUTING": true, "POSTROUTING": true}

func ValidateRuleset(r *Ruleset) error {
	for name, address := range r.Aliases {
		if !safeName.MatchString(name) {
			return fmt.Errorf("invalid alias name")
		}
		if net.ParseIP(address) == nil {
			if _, _, err := net.ParseCIDR(address); err != nil {
				return fmt.Errorf("invalid alias address")
			}
		}
	}
	for key, policy := range r.Policies {
		chain := key[strings.LastIndex(key, "/")+1:]
		if policy == "-" && !allowedChains[chain] {
			continue
		}
		if policy != "ACCEPT" && policy != "DROP" {
			return fmt.Errorf("invalid policy %q", policy)
		}
	}
	for i := range r.Rules {
		if r.Rules[i].Source.Type == "alias" && r.Aliases[r.Rules[i].Source.Value] == "" {
			return fmt.Errorf("rule %d: unknown source alias", i+1)
		}
		if r.Rules[i].Destination.Type == "alias" && r.Aliases[r.Rules[i].Destination.Value] == "" {
			return fmt.Errorf("rule %d: unknown destination alias", i+1)
		}
		if err := ValidateRule(r.Rules[i]); err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	jumps := map[string][]string{}
	for _, rule := range r.Rules {
		if strings.HasPrefix(rule.Action, "FWUI_") {
			jumps[rule.Chain] = append(jumps[rule.Chain], rule.Action)
		}
	}
	const visiting, done = 1, 2
	state := map[string]int{}
	var visit func(chain string) error
	visit = func(chain string) error {
		if state[chain] == visiting {
			return fmt.Errorf("cyclic jump detected involving chain %s", chain)
		}
		if state[chain] == done {
			return nil
		}
		state[chain] = visiting
		for _, next := range jumps[chain] {
			if err := visit(next); err != nil {
				return err
			}
		}
		state[chain] = done
		return nil
	}
	for chain := range jumps {
		if err := visit(chain); err != nil {
			return err
		}
	}
	return nil
}
func ValidateRule(r Rule) error {
	if !safeName.MatchString(r.Chain) {
		return fmt.Errorf("invalid chain")
	}
	if !allowedChains[r.Chain] && !strings.HasPrefix(r.Chain, "FWUI_") {
		return fmt.Errorf("safe mode only permits built-in and FWUI_ chains")
	}
	filterAction := r.Action == "ACCEPT" || r.Action == "DROP" || r.Action == "REJECT" || strings.HasPrefix(r.Action, "FWUI_")
	natAction := r.Table == "nat" && (r.Action == "DNAT" || r.Action == "SNAT" || r.Action == "MASQUERADE")
	if !filterAction && !natAction {
		return fmt.Errorf("invalid action")
	}
	if (r.Action == "DNAT" || r.Action == "SNAT") && net.ParseIP(r.ToAddress) == nil {
		return fmt.Errorf("%s requires a valid target address", r.Action)
	}
	if r.ToPort < 0 || r.ToPort > 65535 {
		return fmt.Errorf("invalid target port")
	}
	if r.Action == "DNAT" && r.Chain != "PREROUTING" && r.Chain != "OUTPUT" && !strings.HasPrefix(r.Chain, "FWUI_") {
		return fmt.Errorf("DNAT is only valid in PREROUTING, OUTPUT, or custom chains")
	}
	if (r.Action == "SNAT" || r.Action == "MASQUERADE") && r.Chain != "POSTROUTING" && !strings.HasPrefix(r.Chain, "FWUI_") {
		return fmt.Errorf("%s is only valid in POSTROUTING or custom chains", r.Action)
	}
	if r.Protocol != "" && r.Protocol != "all" && r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != "icmp" {
		return fmt.Errorf("invalid protocol")
	}
	for _, a := range []AddressMatch{r.Source, r.Destination} {
		if err := validateAddress(a); err != nil {
			return err
		}
	}
	for _, ports := range [][]PortRange{r.SourcePorts, r.DestPorts} {
		for _, p := range ports {
			if p.From < 1 || p.From > 65535 || p.To < p.From || p.To > 65535 {
				return fmt.Errorf("invalid port range")
			}
		}
	}
	for _, iface := range []string{r.InInterface, r.OutInterface} {
		if iface != "" && !safeName.MatchString(strings.TrimSuffix(iface, "+")) {
			return fmt.Errorf("invalid interface")
		}
	}
	return nil
}
func validateAddress(a AddressMatch) error {
	if a.Type == "" || a.Type == "any" {
		return nil
	}
	if a.Type == "ipset" || a.Type == "alias" {
		if !safeName.MatchString(a.Value) {
			return fmt.Errorf("invalid %s", a.Type)
		}
		return nil
	}
	if a.Type != "cidr" {
		return fmt.Errorf("unsupported address type")
	}
	if net.ParseIP(a.Value) != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(a.Value); err != nil {
		return fmt.Errorf("invalid IP/CIDR")
	}
	return nil
}
