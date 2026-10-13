package firewall

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func Render(rs *Ruleset) (string, error) {
	if err := ValidateRuleset(rs); err != nil {
		return "", err
	}
	tables := map[string]bool{"filter": true}
	for _, r := range rs.Rules {
		tables[r.Table] = true
	}
	for _, r := range rs.Unsupported {
		tables[r.Table] = true
	}
	order := []string{"raw", "mangle", "nat", "filter", "security"}
	var b strings.Builder
	for _, table := range order {
		if !tables[table] {
			continue
		}
		b.WriteString("*" + table + "\n")
		keys := make([]string, 0)
		for k := range rs.Policies {
			if strings.HasPrefix(k, table+"/") {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			chain := strings.TrimPrefix(k, table+"/")
			b.WriteString(fmt.Sprintf(":%s %s [0:0]\n", chain, rs.Policies[k]))
		}
		var entries []struct {
			pos  int
			line string
		}
		for _, r := range rs.Rules {
			if r.Table == table && r.Enabled {
				line, err := renderRule(r, rs.Aliases)
				if err != nil {
					return "", err
				}
				entries = append(entries, struct {
					pos  int
					line string
				}{r.Position, line})
			}
		}
		for _, r := range rs.Unsupported {
			if r.Table == table {
				entries = append(entries, struct {
					pos  int
					line string
				}{r.Position, r.Line})
			}
		}
		sort.SliceStable(entries, func(i, j int) bool { return entries[i].pos < entries[j].pos })
		for _, e := range entries {
			b.WriteString(e.line + "\n")
		}
		b.WriteString("COMMIT\n")
	}
	return b.String(), nil
}
func renderRule(r Rule, aliases map[string]string) (string, error) {
	args := []string{"-A", r.Chain}
	if r.Protocol != "" && r.Protocol != "all" {
		args = append(args, "-p", r.Protocol)
	}
	args = appendAddress(args, r.Source, aliases, "-s", "src")
	args = appendAddress(args, r.Destination, aliases, "-d", "dst")
	if r.InInterface != "" {
		args = append(args, "-i", r.InInterface)
	}
	if r.OutInterface != "" {
		args = append(args, "-o", r.OutInterface)
	}
	if len(r.SourcePorts) > 0 {
		args = append(args, "--sport", formatPort(r.SourcePorts[0]))
	}
	if len(r.DestPorts) > 0 {
		args = append(args, "--dport", formatPort(r.DestPorts[0]))
	}
	if len(r.States) > 0 {
		args = append(args, "-m", "conntrack", "--ctstate", strings.Join(r.States, ","))
	}
	if r.Comment != "" {
		args = append(args, "-m", "comment", "--comment", quote(r.Comment))
	}
	args = append(args, "-j", r.Action)
	if r.Action == "DNAT" || r.Action == "SNAT" {
		target := r.ToAddress
		if r.ToPort > 0 {
			target += ":" + strconv.Itoa(r.ToPort)
		}
		if r.Action == "DNAT" {
			args = append(args, "--to-destination", target)
		} else {
			args = append(args, "--to-source", target)
		}
	}
	return strings.Join(args, " "), nil
}
func appendAddress(a []string, m AddressMatch, aliases map[string]string, flag, dir string) []string {
	if m.Type == "alias" {
		return append(a, flag, aliases[m.Value])
	}
	if m.Type == "cidr" && m.Value != "" {
		return append(a, flag, m.Value)
	}
	if m.Type == "ipset" {
		return append(a, "-m", "set", "--match-set", m.Value, dir)
	}
	return a
}
func formatPort(p PortRange) string {
	if p.To == 0 || p.To == p.From {
		return strconv.Itoa(p.From)
	}
	return fmt.Sprintf("%d:%d", p.From, p.To)
}
func quote(v string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `"`, `\"`) + `"`
}
