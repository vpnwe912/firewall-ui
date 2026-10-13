# firewall-ui REST API

The web interface uses the same JSON API described here.

- Base URL: `http://SERVER_IP:8921/api/v1`
- Request format: `application/json`
- API version: `v1`
- Maximum JSON request body: 1 MiB
- Unknown JSON fields are rejected

> Firewall changes are draft-based. Saving a draft does not alter the live firewall until `apply` is called. After applying, call `confirm` before the rollback deadline or the previous ruleset is restored automatically.

## Authentication

With the exception of initial setup and login, every endpoint requires authentication.

### API token (recommended for automation)

Create a token in **Settings → API Tokens**. Its plaintext value is returned only once.

```bash
export FWUI_URL="http://127.0.0.1:8921"
export FWUI_TOKEN="fw_REPLACE_ME"

curl -sS \
  -H "Authorization: Bearer $FWUI_TOKEN" \
  "$FWUI_URL/api/v1/system"
```

Bearer-token requests do not require a CSRF header.

Available token scopes:

| Scope | Effective access |
|---|---|
| `firewall:read` | Viewer |
| `ipset:read` | Viewer |
| `system:read` | Viewer |
| `firewall:write` | Operator |
| `ipset:write` | Operator |
| `admin` | Administrator |

Currently, scopes determine the token's effective role: any `*:write` scope grants operator access, while `admin` grants administrator access. Resource-specific scope enforcement is not currently performed, so grant tokens only the access appropriate for their intended use.

### Browser session and CSRF

Login stores an HttpOnly `fwui_session` cookie. State-changing cookie-authenticated requests must include the `csrf` value returned by login or `/auth/me`:

```bash
curl -sS -c cookies.txt \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"CHANGE_ME"}' \
  "$FWUI_URL/api/v1/auth/login"

curl -sS -b cookies.txt "$FWUI_URL/api/v1/auth/me"

curl -sS -b cookies.txt \
  -H "X-CSRF-Token: CSRF_VALUE" \
  -X POST "$FWUI_URL/api/v1/draft/validate"
```

### Roles

| Role | Permissions |
|---|---|
| `viewer` | Read-only endpoints |
| `operator` | Read and firewall/IPSet/alias/backup operations |
| `admin` | Full access, including settings, users, tokens and backup deletion |

Some forbidden operations return `403`; routes handled by the main API switch may return `404` with `not found or insufficient permissions`.

## Common responses

Successful mutation:

```json
{"ok": true}
```

Error:

```json
{"error": "error description"}
```

Common status codes:

| Status | Meaning |
|---:|---|
| `200` | Success |
| `201` | Resource created |
| `400` | Invalid JSON, validation failure or command failure |
| `401` | Missing/invalid authentication or failed login |
| `403` | Missing role or CSRF token |
| `404` | Resource/route not found or operation unavailable to the role |
| `409` | Conflict, apply failure or referenced resource |
| `429` | Rate limit exceeded; inspect `Retry-After` |
| `503` | Firewall/IPSet backend unavailable |

## Endpoint index

### Setup and authentication

| Method | Path | Access | Description |
|---|---|---|---|
| `POST` | `/setup` | Public, first run only | Create the first administrator |
| `POST` | `/auth/login` | Public | Create browser session |
| `GET` | `/auth/me` | Authenticated | Current principal and CSRF token |
| `POST` | `/auth/logout` | Authenticated | Delete current browser session |
| `GET` | `/auth/attempts` | Admin | Login attempt history |
| `GET` | `/auth/locks` | Admin | Active brute-force locks |

Setup/login body:

```json
{"username":"admin","password":"at-least-10-characters"}
```

Principal response:

```json
{"id":1,"username":"admin","role":"admin","csrf":"..."}
```

Brute-force protection locks a username/IP pair after 5 failures for 5 minutes and an IP after 20 failures for 15 minutes.

### System and audit

| Method | Path | Access | Description |
|---|---|---|---|
| `GET` | `/system` | Viewer+ | Detected OS, commands, forwarding and backend capabilities |
| `GET` | `/audit` | Viewer+ | Audit records, including details and before/after JSON when available |

### IPv4 firewall and draft

| Method | Path | Access | Description |
|---|---|---|---|
| `GET` | `/firewall` | Viewer+ | Complete current IPv4 draft |
| `GET` | `/firewall/filter` | Viewer+ | Structured filter rules |
| `GET` | `/firewall/nat` | Viewer+ | Structured NAT rules |
| `GET` | `/draft` | Viewer+ | Complete current IPv4 draft |
| `POST` | `/draft/refresh` | Operator+ | Reload draft from live firewall |
| `PUT` | `/draft` | Operator+ | Save complete draft in memory |
| `POST` | `/draft/validate` | Operator+ | Validate draft through `iptables-restore --test` |
| `GET` | `/draft/diff` | Viewer+ | Changes between live state and draft |
| `POST` | `/draft/discard` | Operator+ | Discard edits and reload live state |
| `POST` | `/draft/apply` | Operator+ | Backup and apply draft, start rollback timer |
| `GET` | `/firewall/rollback` | Viewer+ | Automatic rollback status/deadline |
| `POST` | `/firewall/confirm` | Operator+ | Confirm applied rules and stop timer |
| `POST` | `/firewall/rollback` | Operator+ | Restore pre-apply snapshot immediately |
| `POST` | `/firewall/counters/reset` | Operator+ | Reset live packet/byte counters |

### Ruleset model

`PUT /draft` and `PUT /ip6/draft` accept the full ruleset:

```json
{
  "snapshot_id": "snapshot-id",
  "raw": "",
  "policies": {"INPUT":"DROP","FORWARD":"DROP","OUTPUT":"ACCEPT"},
  "aliases": {},
  "rules": [
    {
      "id": "rule-id",
      "table": "filter",
      "chain": "FWUI_INPUT",
      "action": "ACCEPT",
      "source": {"type":"cidr","value":"192.0.2.0/24"},
      "destination": {"type":"any","value":""},
      "protocol": "tcp",
      "source_ports": [],
      "dest_ports": [{"from":22,"to":22}],
      "in_interface": "",
      "out_interface": "",
      "to_address": "",
      "to_port": 0,
      "states": ["NEW","ESTABLISHED"],
      "comment": "SSH from administrators",
      "enabled": true,
      "position": 0,
      "packets": 0,
      "bytes": 0
    }
  ],
  "unsupported": [],
  "loaded_at": "2026-10-13T10:00:00Z"
}
```

Address `type` values used by the UI are `any`, `ip`, `cidr`, `ipset`, and `alias`. Unsupported rules are returned in `unsupported` and must be preserved when submitting the complete draft.

Safe Mode permits changes only inside `FWUI_*` chains and jumps from built-in chains to `FWUI_*`. Do not remove or rewrite unsupported rules generated by Docker, Proxmox, libvirt, Kubernetes or other software.

### Safe apply example

```bash
# Save an edited ruleset prepared in draft.json
curl -sS -X PUT \
  -H "Authorization: Bearer $FWUI_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @draft.json \
  "$FWUI_URL/api/v1/draft"

curl -sS -X POST -H "Authorization: Bearer $FWUI_TOKEN" \
  "$FWUI_URL/api/v1/draft/validate"

curl -sS "$FWUI_URL/api/v1/draft/diff" \
  -H "Authorization: Bearer $FWUI_TOKEN"

curl -sS -X POST -H "Authorization: Bearer $FWUI_TOKEN" \
  "$FWUI_URL/api/v1/draft/apply"

# Confirm only after verifying connectivity
curl -sS -X POST -H "Authorization: Bearer $FWUI_TOKEN" \
  "$FWUI_URL/api/v1/firewall/confirm"
```

### IPv6 firewall

| Method | Path | Access | Description |
|---|---|---|---|
| `GET` | `/ip6/draft` | Viewer+ | Current IPv6 draft |
| `POST` | `/ip6/draft/refresh` | Operator+ | Reload from `ip6tables-save` |
| `PUT` | `/ip6/draft` | Operator+ | Save complete IPv6 draft |
| `POST` | `/ip6/draft/validate` | Operator+ | Validate IPv6 draft |
| `GET` | `/ip6/draft/diff` | Viewer+ | IPv6 draft diff |
| `POST` | `/ip6/draft/discard` | Operator+ | Discard IPv6 edits |
| `POST` | `/ip6/draft/apply` | Operator+ | Apply IPv6 draft with rollback timer |
| `GET` | `/ip6/firewall/rollback` | Viewer+ | IPv6 rollback status |
| `POST` | `/ip6/firewall/confirm` | Operator+ | Confirm IPv6 apply |
| `POST` | `/ip6/firewall/rollback` | Operator+ | Roll back IPv6 immediately |

The model and workflow are identical to IPv4. Endpoints return `503` when the IPv6 backend is unavailable.

### IP sets

| Method | Path | Access | Description |
|---|---|---|---|
| `GET` | `/ipsets` | Viewer+ | List sets and members |
| `POST` | `/ipsets` | Operator+ | Create a set |
| `GET` | `/ipsets/{name}` | Viewer+ | Read one set |
| `DELETE` | `/ipsets/{name}` | Operator+ | Delete an unreferenced set |
| `POST` | `/ipsets/{name}/members` | Operator+ | Add one member |
| `DELETE` | `/ipsets/{name}/members` | Operator+ | Remove one member |
| `POST` | `/ipsets/{name}/members/bulk` | Operator+ | Add multiple members |
| `DELETE` | `/ipsets/{name}/members/bulk` | Operator+ | Remove multiple members |

Create an IPv6 network set with comments:

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $FWUI_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"TrustedIPv6","type":"hash:net","family":"inet6","comment":true}' \
  "$FWUI_URL/api/v1/ipsets"
```

Add members:

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $FWUI_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"member":"2001:db8::/32","comment":"Documentation network"}' \
  "$FWUI_URL/api/v1/ipsets/TrustedIPv6/members"

curl -sS -X POST \
  -H "Authorization: Bearer $FWUI_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"members":["2001:db8:1::/48 comment \"Office\"","2001:db8:2::/48"]}' \
  "$FWUI_URL/api/v1/ipsets/TrustedIPv6/members/bulk"
```

Set responses include `name`, `type`, `family`, `members`, `references`, and whether comments are enabled.

### Aliases

| Method | Path | Access | Description |
|---|---|---|---|
| `GET` | `/aliases` | Viewer+ | List aliases and reference counts |
| `POST` | `/aliases` | Operator+ | Create alias |
| `PUT` | `/aliases/{id}` | Operator+ | Update alias |
| `DELETE` | `/aliases/{id}` | Operator+ | Delete unreferenced alias |

Create/update body:

```json
{"name":"admin_network","address":"192.0.2.0/24"}
```

Alias names must begin with a letter and contain at most 32 letters, digits, `_`, `.`, or `-` characters. Addresses must be valid IP addresses or CIDRs.

### Backups

| Method | Path | Access | Description |
|---|---|---|---|
| `GET` | `/backups` | Viewer+ | List IPv4 firewall backups and metadata |
| `GET` | `/backups/{id}` | Viewer+ | Read backup content as JSON |
| `GET` | `/backups/{id}/download` | Viewer+ | Download raw iptables rules |
| `POST` | `/backups/{id}/restore` | Operator+ | Restore backup |
| `DELETE` | `/backups/{id}` | Admin | Delete backup and metadata |

Backup statuses include `created`, `confirmed`, `rolled-back`, and `restored`.

### Users

All user-management endpoints require `admin`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/users` | List users without password hashes |
| `POST` | `/users` | Create user |
| `PUT` | `/users/{id}` | Change role and optionally password |
| `DELETE` | `/users/{id}` | Delete user; current account cannot delete itself |

Create:

```json
{"username":"operator1","password":"at-least-10-characters","role":"operator"}
```

Update (empty password preserves the current password):

```json
{"role":"viewer","password":""}
```

Roles are `admin`, `operator`, and `viewer`.

### API tokens

All token-management endpoints require `admin`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/tokens` | List token metadata; token secrets are never returned |
| `POST` | `/tokens` | Create token; plaintext secret is returned once |
| `DELETE` | `/tokens/{id}` | Revoke token |

```bash
curl -sS -X POST -b cookies.txt \
  -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: CSRF_VALUE" \
  -d '{"name":"automation","scopes":["firewall:read","firewall:write"]}' \
  "$FWUI_URL/api/v1/tokens"
```

Response:

```json
{"token":"fw_..."}
```

### Settings

| Method | Path | Access | Description |
|---|---|---|---|
| `GET` | `/settings` | Viewer+ | Read runtime settings |
| `PUT` | `/settings` | Admin | Update runtime settings |

The complete update body is required:

```json
{
  "safe_mode": true,
  "rollback_timeout": 120,
  "backup_retention": 20,
  "rate_limit_enabled": true,
  "rate_limit_auth": 10,
  "rate_limit_api": 200,
  "rate_limit_whitelist_ipset": "TrustedAdmins",
  "session_ttl_minutes": 720
}
```

Validation limits:

- `rollback_timeout`: 10–3600 seconds
- `backup_retention`: 0–1000
- `rate_limit_auth`, `rate_limit_api`: 1–10000 requests/minute
- `session_ttl_minutes`: 1–525600

The rate limiter reloads these settings periodically. A configured whitelist IPSet bypasses API limits for matching client addresses.

## Rate limiting and proxying

Default limits are 10 requests/minute for login/setup and 200 requests/minute for other API calls. A limited response uses status `429` and includes `Retry-After: 60`.

When publishing firewall-ui through Nginx, restrict direct access to port `8921` and configure the proxy securely. Validate the observed client address before relying on per-IP limiting or whitelist behavior.

## Security notes

- Use HTTPS at the reverse proxy before sending passwords or tokens over a network.
- Store API tokens as secrets; revoke and replace exposed tokens.
- Prefer a narrowly privileged operator token over `admin` for automation.
- Verify SSH or management connectivity before confirming an applied ruleset.
- Keep unsupported/raw rules in every submitted draft.
- API mutations are recorded in the audit log.
