package ipset

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type Set struct {
	Name       string      `json:"name"`
	Type       string      `json:"type"`
	Family     string      `json:"family"`
	Members    []SetMember `json:"members"`
	References int         `json:"references"`
	Comment    bool        `json:"comment"`
}
type SetMember struct {
	Value   string `json:"value"`
	Comment string `json:"comment"`
}
type Service struct{ Timeout time.Duration }

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,30}$`)
var addRE = regexp.MustCompile(`^add\s+(\S+)\s+(\S+)(?:\s+comment\s+"(.*?)")?\s*$`)

func New() *Service { return &Service{Timeout: 10 * time.Second} }
func (s *Service) run(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ipset", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ipset: %w: %s", err, strings.TrimSpace(out.String()))
	}
	return out.Bytes(), nil
}
func (s *Service) List() ([]Set, error) {
	out, err := s.run("save")
	if err != nil {
		return nil, err
	}
	sets := map[string]*Set{}
	var order []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		if f[0] == "create" {
			family := "inet"
			for i := 3; i+1 < len(f); i++ {
				if f[i] == "family" && (f[i+1] == "inet" || f[i+1] == "inet6") {
					family = f[i+1]
					break
				}
			}
			sets[f[1]] = &Set{Name: f[1], Type: f[2], Family: family, Comment: strings.Contains(line, " comment ")}
			order = append(order, f[1])
		} else if f[0] == "add" {
			m := addRE.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			if set := sets[m[1]]; set != nil {
				set.Members = append(set.Members, SetMember{Value: m[2], Comment: m[3]})
			}
		}
	}
	result := make([]Set, 0, len(order))
	for _, n := range order {
		result = append(result, *sets[n])
	}
	return result, nil
}
func (s *Service) Create(name, kind, family string, comment bool) error {
	if !nameRE.MatchString(name) {
		return errors.New("invalid ipset name")
	}
	if kind != "hash:ip" && kind != "hash:net" {
		return errors.New("unsupported ipset type")
	}
	if family != "inet" && family != "inet6" {
		family = "inet"
	}
	args := []string{"create", name, kind, "family", family}
	if comment {
		args = append(args, "comment")
	}
	_, err := s.run(args...)
	return err
}
func (s *Service) Delete(name string) error {
	if !nameRE.MatchString(name) {
		return errors.New("invalid ipset name")
	}
	_, err := s.run("destroy", name)
	return err
}
func (s *Service) Add(name, member, comment string) error {
	family := s.familyOf(name)
	if !validMember(name, member, family) {
		return errors.New("invalid name or member for family " + family)
	}
	args := []string{"add", name, member}
	if strings.TrimSpace(comment) != "" {
		args = append(args, "comment", comment)
	}
	_, err := s.run(args...)
	return err
}
func (s *Service) Bulk(name string, members []string, del bool) (int, error) {
	if !nameRE.MatchString(name) || len(members) == 0 || len(members) > 10000 {
		return 0, errors.New("invalid name or member list")
	}
	family := s.familyOf(name)
	type item struct{ value, comment string }
	parsed := make([]item, 0, len(members))
	for _, raw := range members {
		parts := strings.SplitN(raw, " comment ", 2)
		value := strings.TrimSpace(parts[0])
		comment := ""
		if len(parts) == 2 {
			c := strings.TrimSpace(parts[1])
			if strings.HasPrefix(c, "\"") && strings.HasSuffix(c, "\"") {
				comment = c[1 : len(c)-1]
			} else {
				comment = c
			}
		}
		if !validMember(name, value, family) {
			return 0, fmt.Errorf("invalid member %q for family %s", raw, family)
		}
		parsed = append(parsed, item{value, comment})
	}
	var script strings.Builder
	op := "add"
	if del {
		op = "del"
	}
	for _, it := range parsed {
		script.WriteString(op + " " + name + " " + it.value)
		if op == "add" && it.comment != "" {
			script.WriteString(" comment \"" + it.comment + "\"")
		}
		script.WriteString("\n")
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ipset", "restore", "-exist")
	cmd.Stdin = strings.NewReader(script.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return 0, fmt.Errorf("ipset: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return len(members), nil
}
func (s *Service) Remove(name, member string) error {
	if !validMember(name, member, s.familyOf(name)) {
		return errors.New("invalid name or member")
	}
	_, err := s.run("del", name, member)
	return err
}
func (s *Service) Contains(name, member string) (bool, error) {
	if !nameRE.MatchString(name) {
		return false, errors.New("invalid ipset name")
	}
	_, err := s.run("test", name, member)
	if err == nil {
		return true, nil
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "is not in set") || strings.Contains(msg, "not in set") || strings.Contains(msg, "element is not") {
		return false, nil
	}
	return false, err
}
func (s *Service) KernelReferences(name string) int {
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "iptables-save").Output()
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "--match-set "+name+" ") || strings.HasSuffix(line, "--match-set "+name) {
			count++
		}
	}
	return count
}
func (s *Service) familyOf(name string) string {
	out, err := s.run("list", "-t", name)
	if err != nil {
		return "inet"
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Header:") {
			if strings.Contains(line, "family inet6") {
				return "inet6"
			}
			return "inet"
		}
	}
	return "inet"
}
func validMember(name, member, family string) bool {
	if !nameRE.MatchString(name) {
		return false
	}
	if ip := net.ParseIP(member); ip != nil {
		if family == "inet6" {
			return ip.To4() == nil
		}
		return ip.To4() != nil
	}
	_, ipnet, err := net.ParseCIDR(member)
	if err != nil {
		return false
	}
	is4 := ipnet.IP.To4() != nil
	if family == "inet6" {
		return !is4
	}
	return is4
}
func valid(name, member string) bool { return validMember(name, member, "inet") }
