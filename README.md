# firewall-ui

Standalone Web GUI for managing Linux firewall based on `iptables`/`ipset`.

One self-contained Go binary with an embedded React/Vite frontend. No PHP, Nginx, Apache or Node.js is required on the production host.

## Runtime dependencies

The application itself is a single static binary. It needs the following host tools to manage the firewall:

- `iptables`, `iptables-save`, `iptables-restore`
- `ipset`
- `systemctl` (only if you use the built-in `install` command)

For IPv6 support the matching `ip6tables*` tools are also recommended.

On Debian/Ubuntu:

```bash
apt update && apt install iptables ipset
```

On RHEL/CentOS/Rocky Linux/AlmaLinux/Fedora:

```bash
dnf install iptables ipset
```

On Arch Linux:

```bash
pacman -S iptables ipset
```

## Build dependencies

- Go 1.22+
- Node.js + npm (only for building the frontend)

## Build

```bash
make build
```

This builds the frontend first and then embeds it into the Go binary at `build/firewall-ui`.

## Run

```bash
./build/firewall-ui --listen 0.0.0.0:8921
```

Then open `http://SERVER_IP:8921`.

## Install as systemd service

```bash
./build/firewall-ui install
```

The installer checks for the required host commands, copies the binary to `/usr/local/bin/firewall-ui`, creates the data/config directories, writes a default config and enables a systemd service.

The installer **does not create or modify any firewall rules**. If your default `INPUT` policy is `DROP`, open port `8921` yourself or proxy the application through Nginx.

## Configuration

Default config path is `/etc/firewall-ui/config.yaml`:

```yaml
server:
  listen: "0.0.0.0:8921"

firewall:
  backend: "iptables"
  mode: "safe"
  rollback_timeout: 120

storage:
  database: "/var/lib/firewall-ui/firewall.db"
  backups: "/var/lib/firewall-ui/backups"

auth:
  enabled: true

tls:
  enabled: false
  cert: ""
  key: ""
```

You can override values with CLI flags or environment variables:

```bash
firewall-ui --listen 127.0.0.1:8921 --safe-mode
FWUI_LISTEN=127.0.0.1:8921 firewall-ui
```

## First login

On the first launch the UI asks to create an administrator account. After that use that account to sign in.

## Useful commands

```bash
firewall-ui install     # install systemd service
firewall-ui uninstall   # remove service and binary
firewall-ui status      # show installation state
firewall-ui version     # show version
```

## Production notes

- TLS is not implemented; use an Nginx reverse proxy with Let's Encrypt if you need HTTPS.
- Keep a separate way to access the server (out-of-band management / console) until you are confident in your firewall rules.
- The built-in rollback timer restores the previous ruleset automatically if you do not confirm changes.
# firewall-ui
