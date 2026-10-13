package system

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type Command struct {
	Name, Path, Version string
	Available           bool
}
type Info struct {
	OS, Kernel, Hostname, IPTablesBackend string
	IPv4Forwarding, IPv6Forwarding        bool
	Systemd                               bool
	Commands                              []Command
	Warnings                              []string
}

func Detect(ctx context.Context) Info {
	info := Info{OS: readOS(), Kernel: runtime.GOOS + "/" + runtime.GOARCH}
	info.Hostname, _ = os.Hostname()
	for _, name := range []string{"iptables", "iptables-save", "iptables-restore", "ip6tables", "ip6tables-save", "ip6tables-restore", "ipset", "systemctl"} {
		cmd := Command{Name: name}
		cmd.Path, _ = exec.LookPath(name)
		cmd.Available = cmd.Path != ""
		if cmd.Available && (name == "iptables" || name == "ipset") {
			cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			out, _ := exec.CommandContext(cctx, cmd.Path, "--version").CombinedOutput()
			cancel()
			cmd.Version = strings.TrimSpace(string(out))
		}
		if !cmd.Available && name != "systemctl" {
			info.Warnings = append(info.Warnings, name+" is not available")
		}
		if name == "iptables" {
			if strings.Contains(cmd.Version, "nf_tables") {
				info.IPTablesBackend = "iptables-nft"
			} else if cmd.Available {
				info.IPTablesBackend = "iptables-legacy"
			}
		}
		if name == "systemctl" {
			info.Systemd = cmd.Available
		}
		info.Commands = append(info.Commands, cmd)
	}
	info.IPv4Forwarding = readBool("/proc/sys/net/ipv4/ip_forward")
	info.IPv6Forwarding = readBool("/proc/sys/net/ipv6/conf/all/forwarding")
	return info
}

func readBool(path string) bool {
	data, err := os.ReadFile(path)
	return err == nil && strings.TrimSpace(string(data)) == "1"
}
func readOS() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "Unknown Linux"
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if strings.HasPrefix(s.Text(), "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(s.Text(), "PRETTY_NAME="), "\"")
		}
	}
	return "Linux"
}
