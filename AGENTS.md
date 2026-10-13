# Project notes

- Build frontend with `cd web && npm run build` before building Go so `web/dist` can be embedded.
- Build backend with `go build -o firewall-ui ./cmd/firewall-ui`.
- Run tests with `go test ./...`.
- Makefile targets are available:
  - `make build` — builds frontend and places the Go binary in `build/firewall-ui`.
  - `make test` — builds frontend and runs `go test ./...`.
  - `make dev` — builds and starts the server on `0.0.0.0:8921`.
  - `make clean` — removes `build/` and `web/dist`.
  - `make install` — copies `build/firewall-ui` to `/usr/local/bin/firewall-ui`.
- Build output goes to `build/`; it is ignored by Git.
- This development host currently has Go and Node.js, but does not have `iptables` or `ipset`; runtime must report missing capabilities without crashing.
- Never invoke firewall commands through a shell; use `exec.CommandContext` with explicit arguments/stdin.
