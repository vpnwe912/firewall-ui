package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"firewall-ui/internal/config"
)

const unitFile = `[Unit]
Description=Firewall UI - iptables/ipset management
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/firewall-ui --config /etc/firewall-ui/config.yaml
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
`

func run(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
func distroFamily() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "ID=") {
			return strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		}
	}
	return ""
}
func installHint(missing []string) string {
	if len(missing) == 0 {
		return ""
	}
	id := distroFamily()
	var pkg string
	switch id {
	case "debian", "ubuntu":
		pkg = "iptables ipset"
	case "centos", "rhel", "rocky", "almalinux", "fedora", "ol":
		pkg = "iptables ipset"
	case "arch":
		pkg = "iptables ipset"
	default:
		pkg = "iptables ipset"
	}
	var cmd string
	switch id {
	case "debian", "ubuntu":
		cmd = fmt.Sprintf("apt update && apt install %s", pkg)
	case "centos", "rhel", "rocky", "almalinux", "ol":
		cmd = fmt.Sprintf("dnf install %s", pkg)
	case "fedora":
		cmd = fmt.Sprintf("dnf install %s", pkg)
	case "arch":
		cmd = fmt.Sprintf("pacman -S %s", pkg)
	default:
		cmd = fmt.Sprintf("(apt|dnf|pacman) install %s", pkg)
	}
	return fmt.Sprintf("missing commands: %s. Install: %s", strings.Join(missing, ", "), cmd)
}
func checkDependencies() error {
	required := []string{"iptables-save", "iptables-restore", "iptables", "ipset", "systemctl"}
	var missing []string
	for _, c := range required {
		if !commandExists(c) {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		return errors.New(installHint(missing))
	}
	optional := []string{"ip6tables-save", "ip6tables-restore", "ip6tables"}
	var optMissing []string
	for _, c := range optional {
		if !commandExists(c) {
			optMissing = append(optMissing, c)
		}
	}
	if len(optMissing) > 0 {
		fmt.Println("warning: IPv6 backend commands not found:", strings.Join(optMissing, ", "))
	}
	return nil
}
func install(ver string) error {
	if os.Geteuid() != 0 {
		return errors.New("install requires root")
	}
	if err := checkDependencies(); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if filepath.Clean(self) != "/usr/local/bin/firewall-ui" {
		src, err := os.Open(self)
		if err != nil {
			return err
		}
		defer src.Close()
		dst, err := os.OpenFile("/usr/local/bin/firewall-ui", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			return err
		}
		if _, err = io.Copy(dst, src); err != nil {
			dst.Close()
			return err
		}
		if err = dst.Close(); err != nil {
			return err
		}
	}
	for _, dir := range []string{"/etc/firewall-ui", "/var/lib/firewall-ui/backups", "/var/log/firewall-ui"} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	if _, err := os.Stat("/etc/firewall-ui/config.yaml"); os.IsNotExist(err) {
		if err := config.WriteDefault("/etc/firewall-ui/config.yaml"); err != nil {
			return err
		}
	}
	if err := os.WriteFile("/etc/systemd/system/firewall-ui.service", []byte(unitFile), 0644); err != nil {
		return err
	}
	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := run("systemctl", "enable", "--now", "firewall-ui"); err != nil {
		return err
	}
	fmt.Println("firewall-ui", ver, "installed and started")
	fmt.Println("Web UI: http://SERVER_IP:8921")
	return nil
}
func uninstall() error {
	if os.Geteuid() != 0 {
		return errors.New("uninstall requires root")
	}
	_ = run("systemctl", "disable", "--now", "firewall-ui")
	_ = os.Remove("/etc/systemd/system/firewall-ui.service")
	_ = run("systemctl", "daemon-reload")
	if err := os.Remove("/usr/local/bin/firewall-ui"); err != nil && !os.IsNotExist(err) {
		return err
	}
	fmt.Println("firewall-ui uninstalled (data kept in /var/lib/firewall-ui and /etc/firewall-ui)")
	return nil
}
func status() {
	fmt.Println("firewall-ui", version)
	for _, p := range []string{"/usr/local/bin/firewall-ui", "/etc/systemd/system/firewall-ui.service", "/etc/firewall-ui/config.yaml", "/var/lib/firewall-ui/firewall.db"} {
		state := "missing"
		if _, err := os.Stat(p); err == nil {
			state = "present"
		}
		fmt.Printf("%-55s %s\n", p, state)
	}
	out, _ := exec.Command("systemctl", "is-active", "firewall-ui").Output()
	fmt.Printf("%-55s %s\n", "systemd service", strings.TrimSpace(string(out)))
}
