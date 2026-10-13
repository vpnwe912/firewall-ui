package firewall

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func Parse(raw string) *Ruleset {
	rs := &Ruleset{SnapshotID: SnapshotID([]byte(raw)), Raw: raw, Policies: map[string]string{}, LoadedAt: time.Now().UTC()}
	table := ""
	positions := map[string]int{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "*") {
			table = strings.TrimPrefix(line, "*")
			continue
		}
		if strings.HasPrefix(line, ":") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				rs.Policies[table+"/"+strings.TrimPrefix(f[0], ":")] = f[1]
			}
			continue
		}
		var packets, bytes uint64
		if strings.HasPrefix(line, "[") {
			if end := strings.Index(line, "]"); end > 1 {
				counter := strings.SplitN(line[1:end], ":", 2)
				if len(counter) == 2 {
					packets, _ = strconv.ParseUint(counter[0], 10, 64)
					bytes, _ = strconv.ParseUint(counter[1], 10, 64)
					line = strings.TrimSpace(line[end+1:])
				}
			}
		}
		if !strings.HasPrefix(line, "-A ") {
			continue
		}
		f, ok := tokens(line)
		if !ok {
			rs.Unsupported = append(rs.Unsupported, RawRule{Table: table, Line: line, Reason: "invalid quoting"})
			continue
		}
		chain := f[1]
		positions[table+chain]++
		if !allowedChains[chain] && !strings.HasPrefix(chain, "FWUI_") {
			rs.Unsupported = append(rs.Unsupported, RawRule{Table: table, Chain: chain, Line: line, Position: positions[table+chain], Reason: "external chain is preserved read-only"})
			continue
		}
		rule, ok := parseRule(table, chain, positions[table+chain], f)
		if ok && !editableAction(rule.Action) {
			ok = false
		}
		if ok {
			rule.Packets = packets
			rule.Bytes = bytes
			rs.Rules = append(rs.Rules, rule)
		} else {
			rs.Unsupported = append(rs.Unsupported, RawRule{Table: table, Chain: chain, Line: line, Position: positions[table+chain], Reason: "unsupported structured rule"})
		}
	}
	return rs
}
func editableAction(action string) bool {
	switch action {
	case "ACCEPT", "DROP", "REJECT", "DNAT", "SNAT", "MASQUERADE":
		return true
	}
	return strings.HasPrefix(action, "FWUI_")
}
func parseRule(table, chain string, pos int, f []string) (Rule, bool) {
	r := Rule{ID: fmt.Sprintf("%s-%s-%d", table, chain, pos), Table: table, Chain: chain, Position: pos, Enabled: true, Protocol: "all", Source: AddressMatch{Type: "any"}, Destination: AddressMatch{Type: "any"}}
	for i := 2; i < len(f); i++ {
		next := func() (string, bool) {
			if i+1 >= len(f) {
				return "", false
			}
			i++
			return f[i], true
		}
		switch f[i] {
		case "-p":
			v, ok := next()
			if !ok {
				return r, false
			}
			r.Protocol = v
		case "-s":
			v, ok := next()
			if !ok {
				return r, false
			}
			r.Source = AddressMatch{Type: "cidr", Value: v}
		case "-d":
			v, ok := next()
			if !ok {
				return r, false
			}
			r.Destination = AddressMatch{Type: "cidr", Value: v}
		case "-i":
			v, ok := next()
			if !ok {
				return r, false
			}
			r.InInterface = v
		case "-o":
			v, ok := next()
			if !ok {
				return r, false
			}
			r.OutInterface = v
		case "--sport", "--source-port":
			v, ok := next()
			if !ok {
				return r, false
			}
			p, ok := parsePort(v)
			if !ok {
				return r, false
			}
			r.SourcePorts = []PortRange{p}
		case "--dport", "--destination-port":
			v, ok := next()
			if !ok {
				return r, false
			}
			p, ok := parsePort(v)
			if !ok {
				return r, false
			}
			r.DestPorts = []PortRange{p}
		case "--to-destination", "--to-source":
			v, ok := next()
			if !ok {
				return r, false
			}
			r.ToAddress, r.ToPort, ok = parseTarget(v)
			if !ok {
				return r, false
			}
		case "--ctstate":
			v, ok := next()
			if !ok {
				return r, false
			}
			r.States = strings.Split(v, ",")
		case "--comment":
			v, ok := next()
			if !ok {
				return r, false
			}
			r.Comment = v
		case "--match-set":
			name, ok := next()
			if !ok {
				return r, false
			}
			dir, ok := next()
			if !ok {
				return r, false
			}
			if dir == "src" {
				r.Source = AddressMatch{Type: "ipset", Value: name}
			} else if dir == "dst" {
				r.Destination = AddressMatch{Type: "ipset", Value: name}
			} else {
				return r, false
			}
		case "-j":
			v, ok := next()
			if !ok {
				return r, false
			}
			r.Action = v
		case "-m":
			v, ok := next()
			if !ok || !(v == "comment" || v == "conntrack" || v == "tcp" || v == "udp" || v == "set") {
				return r, false
			}
		case "-c":
			packets, ok := next()
			if !ok {
				return r, false
			}
			bytes, ok := next()
			if !ok {
				return r, false
			}
			r.Packets, _ = strconv.ParseUint(packets, 10, 64)
			r.Bytes, _ = strconv.ParseUint(bytes, 10, 64)
		default:
			return r, false
		}
	}
	return r, r.Action != ""
}
func parsePort(v string) (PortRange, bool) {
	p := strings.Split(v, ":")
	a, e := strconv.Atoi(p[0])
	if e != nil {
		return PortRange{}, false
	}
	b := a
	if len(p) == 2 {
		b, e = strconv.Atoi(p[1])
		if e != nil {
			return PortRange{}, false
		}
	}
	return PortRange{From: a, To: b}, true
}
func parseTarget(value string) (string, int, bool) {
	if net.ParseIP(value) != nil {
		return value, 0, true
	}
	index := strings.LastIndex(value, ":")
	if index < 1 || net.ParseIP(value[:index]) == nil {
		return "", 0, false
	}
	port, err := strconv.Atoi(value[index+1:])
	return value[:index], port, err == nil && port > 0 && port <= 65535
}

func tokens(line string) ([]string, bool) {
	var out []string
	var b strings.Builder
	quoted := false
	escaped := false
	for _, r := range line {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '"' {
			quoted = !quoted
			continue
		}
		if r == ' ' && !quoted {
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
		} else {
			b.WriteRune(r)
		}
	}
	if quoted {
		return nil, false
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out, true
}
