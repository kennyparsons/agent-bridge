# agent-bridge

Static, zero-dependency Go binary (`v0.2.0`) for synchronous remote command execution, native OS service management, and multi-node security-state replication over private overlay and LAN networks using Mutual TLS 1.3, self-contained ECDSA P-256 PKI, hot-reloading Certificate Revocation Lists (CRLs), and transactional WebSockets (`wss://<endpoint>/ws/exec`).

- **Protocol & Security Specification**: [spec.md](spec.md)
- **Clustering Architecture Decision Record**: [docs/ADR-001-clustering.md](docs/ADR-001-clustering.md)
- **Live Infrastructure Bring-Up Runbook**: [docs/FIELD-VALIDATION-RUNBOOK.md](docs/FIELD-VALIDATION-RUNBOOK.md)

## What's New in `v0.2.0` (Binary-Native Architecture)

`v0.2.0` replaces external PowerShell, Bash, WinSW, NSSM, and Scheduled Task wrappers with pure Go binary-native subcommands:

- **Native OS Service Manager (`agent-bridge service`)**: Implements Win32 Service Control Manager (`golang.org/x/sys/windows/svc` + `svc/mgr` with `3s/5s/10s` failure recovery and automatic cleanup of legacy `\AgentBridge-Server` Scheduled Tasks), Linux `systemd`, and macOS `launchd` — eliminating Windows Error 1053 without third-party wrappers.
- **Native Filesystem & Key ACLs (`internal/acl`)**: Enforces Win32 SDDL DACLs (`D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` with `SE_DACL_PROTECTED`) and POSIX `0700`/`0600` ownership/mode lockdown automatically during `ca init`, `ca issue`, `cluster join/rejoin`, `service install`, and `client init`.
- **Universal Multi-Address Bind & Boot Readiness (`--bind`, `--cluster-bind`, `--wait-bind`)**: Accepts `0.0.0.0`, `::`, `all`, comma-separated IPs (`198.51.100.10,100.64.0.10`), and CIDR interface selectors (`198.51.100.0/24,100.64.0.0/10`), polling up to `--wait-bind` (default `60s` for OS services) for virtual overlay NICs at boot and automatically harvesting active NIC IPs into X.509 SANs.
- **Pre-Flight & Live Diagnostics (`agent-bridge doctor`)**: Cross-OS UDP route probing, Tailscale `--accept-routes` + IPv4 forwarding LAN hairpin detection, multi-seed TCP + Root-CA pin checks, bind socket availability, X.509 SAN completeness against live NICs, CRL freshness, and filesystem ACL audits.
- **Zero-Downtime Certificate & SAN Rotation (`cluster join`, `cluster rejoin`, `ca revoke --sync`)**: Tokenless mTLS renewal (`POST /cluster/v1/renew`) or token-authorized re-keying with optional `--revoke-old`, automatic OS service restart (`AGENT_BRIDGE_IN_EXEC=1` detached restart safe over `/ws/exec`), zero-flag server-local `cluster` discovery, and immediate cluster-wide CRL push on `ca revoke --cert <pem> --sync`.
- **Single-File Client Provisioning (`.abbundle`)**: `ca issue --bundle-out` / `ca bundle` emit self-contained JSON bundles (with optional PBKDF2-SHA256 + AES-256-GCM passphrase encryption via `--passphrase-env`), unpacked and verified in one step via `client init --bundle <file> --verify` and `client verify`.
- **Cryptographically Verified Self-Upgrades (`agent-bridge selfupgrade`)**: Verifies GitHub Release assets against an embedded Ed25519 public key (`SHA256SUMS.txt.sig`) + `SHA256SUMS.txt` with automatic direct-dial fallback on HTTP `502` proxy errors, atomic `.exe -> .exe.old` swap + startup sweep, and health-checked service rollback.

## Security & Execution Architecture

| Layer | Enforcement |
| :--- | :--- |
| **Network Binding** | Multi-listener `http.Server` and cluster mesh supporting explicit IPs, `0.0.0.0`/`::`/`all`, and CIDR interface selectors with `--wait-bind` boot readiness polling; fails fast before consuming single-use join tokens if sockets cannot bind. |
| **OS Service & ACLs** | Native Win32 SCM / `systemd` / `launchd` lifecycle; Win32 `SE_DACL_PROTECTED` SDDL (`SYSTEM` + `Administrators` or current owner) and POSIX `0700`/`0600` ACLs; rotating shared-handle daemon logs (`FILE_SHARE_READ\|WRITE\|DELETE`). |
| **Transport & Identity** | `tls.VersionTLS13` minimum, `tls.RequireAndVerifyClientCert` on `/ws/exec`, ECDSA P-256 (`secp256r1`) + SHA-256 signatures, positive 128-bit random serials, automatic active-NIC IP/DNS SAN harvesting, `5m` `NotBefore` clock-skew leeway. |
| **Revocation (`crl.pem`)** | RFC 5280 v2 CRL validated synchronously at startup (`CheckSignatureFrom` + `NextUpdate`), hot-reloaded lock-free via `fsnotify` + stat fallback, and pushed across clustered peers on reload or `ca revoke --sync`. |
| **Cluster Mesh (`8444/tcp`)** | Pure-Go TLS 1.3 TCP SWIM/anti-entropy mesh (`cluster/`, `1.5s` gossip tick, `4.5s` suspect, `9.0s` unreachable) with Root-CA-pinned single-use join tokens, tokenless mTLS `/cluster/v1/renew`, and ECDSA-signed `ExecutionPolicy` replication. |
| **Wire Protocol** | Single JSON `CommandRequest` text frame in, single compact JSON `CommandResponse` text frame (`omitempty` on empty streams) out, followed by WebSocket Close `1000`. |
| **Process Isolation** | Per-command timeout (`60s` default, `600s` ceiling), `10 MiB` (`10,485,760` B) per-stream cap, immediate process-tree termination on timeout or client disconnect (`JobObject` on Windows; `Setpgid` + `-pgid` `SIGKILL` on Linux/macOS). |

```text
[AI Agent / Operator CLI (workstation-01)]
   │  agent-bridge exec --host node-a "Get-Service AgentBridge | ConvertTo-Json -Compress"
   ▼
[Client Wrapper] ── mTLS 1.3 + wss://100.64.0.10:8443/ws/exec ──► [node-a Daemon (SCM / systemd / launchd)]
   │                                                                  ├─ Verify client chain against ca.crt
   │                                                                  ├─ Check leaf serial against live crl.pem
   │                                                                  ├─ Enforce signed cluster ExecutionPolicy (ACL / timeouts / shell)
   │                                                                  ├─ Spawn isolated shell (powershell / sh)
   ◄── {"exit_code":0,"stdout":"..."} + Close(1000) ──────────────────┘
                                                                      ▲
                                        TLS 1.3 TCP Gossip (:8444) ───┴───► Peer Nodes (node-b: CRL + Policy + Quorum)
```

## Build, Cross-Compilation & SemVer CI/CD Pipeline

Requires Go `1.26+`. All targets compile with `CGO_ENABLED=0` and `-trimpath` (symbol and DWARF sections are preserved to prevent heuristic AV ML false positives on unsigned binaries).

```bash
make build      # Host binary -> bin/agent-bridge
make build-all  # Static cross-compiled binaries + SHA256SUMS.txt -> dist/
make vet        # Static analysis
make test       # Full go test -race suite
```

| Target Artifact | `GOOS` | `GOARCH` |
| :--- | :--- | :--- |
| `dist/agent-bridge-windows-amd64.exe` | `windows` | `amd64` |
| `dist/agent-bridge-linux-amd64` | `linux` | `amd64` |
| `dist/agent-bridge-linux-arm64` | `linux` | `arm64` |
| `dist/agent-bridge-darwin-arm64` | `darwin` | `arm64` |

### Automated SemVer Release & Signing Workflow (`.github/workflows/ci-release.yml`)

1. **PR & Main Verification**: Runs structural OPSEC/secret checks, `gofmt`, cross-OS `go vet` (`linux`, `windows`, `darwin`), `go test -race -count=1 ./...` on both `ubuntu-latest` and `windows-latest`, and reproducible unstripped `-trimpath` binary metadata verification.
2. **SemVer Tagging & Ed25519 Signing**: On pushes to `main` (Conventional Commits `feat:` -> minor, `fix:|perf:|sec:|build:` -> patch, `!:` / `BREAKING CHANGE:` -> major/0.x minor, or `VERSION` override), GitHub Actions creates an annotated `vX.Y.Z` tag, builds all 4 release binaries, generates `SHA256SUMS.txt`, signs it with `cmd/agent-bridge-sign` (`RELEASE_ED25519_PRIVATE_KEY` -> `SHA256SUMS.txt.sig`), verifies the signature against the embedded public key, and publishes the GitHub Release consumed by `agent-bridge selfupgrade`.

## Quickstart: Zero-Script End-to-End Workflow

### 1. Initialize Root CA & Seed Node (`node-a`)

```bash
# Initialize Root CA + initial server.crt & peer.crt with automatic active-NIC SAN harvesting
sudo agent-bridge ca init \
  --out-dir /etc/agent-bridge \
  --san-dns node-a.example.internal \
  --san-ip 198.51.100.10,100.64.0.10

# Run pre-flight diagnostics before installing the OS service
sudo agent-bridge doctor --data-dir /etc/agent-bridge --bind 198.51.100.10,100.64.0.10

# Install and start native OS service (systemd / launchd / Windows SCM)
sudo agent-bridge service install \
  --data-dir /etc/agent-bridge \
  --node-id node-a \
  --bind 198.51.100.0/24,100.64.0.0/10 \
  --port 8443 \
  --cluster \
  --cluster-bind 198.51.100.10:8444,100.64.0.10:8444 \
  --cluster-advertise 100.64.0.10:8444 \
  --wait-bind 60s
```

### 2. Enroll Additional Cluster Node (`node-b`, Windows or Linux)

On `node-a`, mint a single-use join token with **zero flags** (auto-discovers local server config and credentials):

```bash
sudo agent-bridge cluster token-create --node-id node-b --ttl 30m -q
```

On `node-b` (e.g., elevated PowerShell on Windows Server or `sudo` on Linux), enroll and install the native service in a single command — `BootstrapJoin` runs in-process first so the single-use `join_token` is **never** written to `server.json`:

```powershell
agent-bridge.exe service install `
  --node-id node-b `
  --bind 198.51.100.20,100.64.0.20 `
  --cluster-bind 198.51.100.20:8444,100.64.0.20:8444 `
  --cluster-advertise 100.64.0.20:8444 `
  --join 100.64.0.10:8444,198.51.100.10:8444 `
  --join-token "<JOIN_TOKEN>" `
  --configure-firewall `
  --defender-exclusion
```

### 3. Single-File Client Provisioning (`workstation-01`)

On `node-a`, issue a single-file `.abbundle` containing the client keypair, Root CA, and host map (optionally encrypted with AES-256-GCM via `--passphrase-env`):

```bash
export AB_BUNDLE_PASS="replace-with-strong-passphrase"
sudo -E agent-bridge ca issue \
  --ca-dir /etc/agent-bridge \
  --type client \
  --name workstation-01 \
  --hosts node-a=100.64.0.10:8443,node-b=100.64.0.20:8443 \
  --default-host node-a \
  --cluster-endpoint 100.64.0.10:8444 \
  --passphrase-env AB_BUNDLE_PASS \
  --bundle-out ./workstation-01.abbundle
```

On `workstation-01`, unpack the bundle with native `0700`/`0600` (or Win32 SDDL) ACLs and verify live mTLS 1.3 connectivity across all hosts:

```bash
export AB_BUNDLE_PASS="replace-with-strong-passphrase"
agent-bridge client init --bundle ./workstation-01.abbundle --passphrase-env AB_BUNDLE_PASS --verify

agent-bridge exec --host node-a "hostname"
agent-bridge exec --host node-b "hostname"
```

## CLI Reference

### Version & Help

```bash
agent-bridge version [--json]   # Also accepts --version, -version, -v -> "agent-bridge v0.2.0"
agent-bridge --help             # Subcommand help: agent-bridge <cmd> [subcmd] --help
```

### 1. OS Service Management (`agent-bridge service`)

Manages the native OS daemon (`AgentBridge` Win32 SCM service on Windows, `agent-bridge.service` on Linux `systemd`, `io.agentbridge.server` LaunchDaemon on macOS) backed by `<data-dir>/server.json`.

| Subcommand | Key Flags | Behavior |
| :--- | :--- | :--- |
| `service install` | `--name`, `--data-dir`, `--bind` (repeatable/CSV), `--port`, `--wait-bind` (default `60s`), `--cluster`, `--node-id`, `--cluster-bind` (repeatable/CSV), `--cluster-advertise`, `--seed` (repeatable/CSV), `--join`, `--join-token`, `--join-token-stdin`, `--san-ip`, `--san-dns`, `--no-auto-sans`, `--shell`, `--policy`, `--log-file`, `--configure-firewall`, `--defender-exclusion`, `--no-start`, `--skip-preflight`, `--json` | Runs pre-flight `doctor` checks; executes `BootstrapJoin` in-process when `--join` + token are provided (recording discovered `seed_peers` in `server.json` without persisting `join_token`); locks down `<data-dir>` and `server.json` via `internal/acl`; configures optional Windows Firewall/Defender rules; installs and starts the native OS service (cleaning up legacy `\AgentBridge-Server` Scheduled Tasks on Windows). |
| `service uninstall` | `--name`, `--purge-config`, `--data-dir`, `--json` | Stops and removes the OS service definition (`--purge-config` also removes `server.json`). |
| `service start` | `--name`, `--json` | Starts the installed OS service. |
| `service stop` | `--name`, `--json` | Gracefully stops the running OS service. |
| `service restart` | `--name`, `--detach`, `--json` | Restarts the OS service. Automatically spawns a detached helper when `--detach` is set or `AGENT_BRIDGE_IN_EXEC=1` so remote restarts over `agent-bridge exec` complete cleanly without severing mid-stop. |
| `service status` | `--name`, `--data-dir`, `--json` | Reports OS service installation/running state, PID, `server.json` path, and log path. |
| `service logs` | `--data-dir`, `--log-file`, `--lines <N>` (default `100`), `--follow` / `-f` | Tails the shared-handle rotating daemon log (`agent-bridge-server.log`). |

### 2. Execution & Cluster Daemon (`agent-bridge server`)

Runs interactively or under an OS service manager (`--service-config <path>`; automatically invokes `service.RunManagedService` when launched by the Windows SCM). Explicit CLI flags always override values loaded from `server.json`.

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--service-config <path>` | Auto under SCM | Path to `server.json` providing base daemon defaults before CLI flag overrides. |
| `--bind <spec>` | Required (unless in `server.json`) | Repeatable or comma-separated bind spec: `0.0.0.0`, `::`, `all`, `*`, explicit IPs (`198.51.100.10,100.64.0.10`), or CIDRs (`198.51.100.0/24,100.64.0.0/10`). |
| `--port <int>` | `8443` | TCP port for `/ws/exec`. |
| `--wait-bind <dur>` | `0s` (`60s` with `--service-config`) | Max duration to poll for virtual/overlay NIC addresses to appear at boot. |
| `--data-dir <dir>` | Platform default / `./agent-bridge-data/<node-id>` | Server credential and state directory; auto-resolves `server.{crt,key}` or `peer.{crt,key}`, `ca.crt`, and `crl.pem`. |
| `--cert`, `--key`, `--ca`, `--crl` | Resolved from `--data-dir` | Explicit X.509 certificate, private key, Root CA, and CRL PEM paths. |
| `--cluster-bind <spec>` | `<bind>:8444` when joining | Repeatable or comma-separated cluster gossip/API bind spec (supports inline `:port` or CIDRs). |
| `--cluster-advertise <host:port>` | First concrete cluster bind | Routable `host:port` advertised to cluster peers. |
| `--seed <peer1:port,...>` | — | Repeatable or comma-separated seed peer addresses for cluster anti-entropy. |
| `--join <seed1:port,...>` | — | Multi-seed bootstrap addresses tried in order during enrollment. |
| `--join-token <tok>` / `--join-token-stdin` | Initial `--join` only | Single-use `abjt1.<ca_sha256>.<id>.<secret>` join token. |
| `--san-ip <csv>` / `--san-dns <csv>` | — | Additional IP / DNS SANs merged with active-NIC SANs during CSR bootstrap. |
| `--no-auto-sans` | `false` | Disable automatic active-NIC IP SAN harvesting during CSR bootstrap. |
| `--skip-preflight` | `false` | Skip pre-join `doctor` route-hairpin check. |
| `--shell <name>` | `powershell` (Win) / `sh` (POSIX) | Execution shell (`powershell`, `pwsh`, `cmd`, `sh`, `bash`). |
| `--policy <path>` | — | Initial JSON `ExecutionPolicy` file. |
| `--log-file <path>` | stderr | Rotating shared-handle log file (`daemonlog`). |

### 3. Pre-Flight & Live Diagnostics (`agent-bridge doctor`)

```bash
agent-bridge doctor [--data-dir <dir>] [--service-config <path>] [--join <seed1:8444,seed2:8444>] \
  [--bind <spec>] [--port 8443] [--cluster-bind <spec>] [--strict-sans] [--require-pki] \
  [--daemon-running] [--json]
```

Auto-loads defaults from `--service-config` or `<data-dir>/server.json` when present and evaluates:
- `route_hairpin`: Cross-OS UDP egress route probe + Tailscale `--accept-routes` / IPv4 forwarding LAN subnet-router hairpin detection.
- `seed_reachability`: Multi-seed TCP dial + TLS 1.3 Root-CA fingerprint verification across `--join` / `--seed` peers.
- `exec_bind` & `cluster_bind`: Socket bind availability (skipped cleanly when `--daemon-running` is set).
- `node_cert_sans`: Leaf validity window, Root CA chain, EKU, and active-NIC IP SAN coverage (`--strict-sans` promotes missing NIC SANs from `warn` to `fail`).
- `crl_freshness`: RFC 5280 CRL signature and `NextUpdate` freshness.
- `acl_permissions`: Verifies Win32 SDDL DACLs (`SE_DACL_PROTECTED`, no unprivileged SIDs) or POSIX `0700`/`0600` permissions via `acl.AuditPathACL`.

Exits non-zero if any check reports `fail`.

### 4. Cluster Lifecycle & Certificate Rotation (`agent-bridge cluster`)

On server nodes, `cluster status`, `cluster peers`, `cluster token-create`, and `cluster sync` work with **zero flags** by auto-discovering local `server.json` / `--data-dir` and `peer.{crt,key}` or `server.{crt,key}` credentials (`config.ResolveClusterConfig`).

| Subcommand | Key Flags | Behavior |
| :--- | :--- | :--- |
| `cluster join` | `--join`, `--join-token` / `--join-token-stdin`, `--data-dir`, `--node-id`, `--bind`, `--port`, `--cluster-bind`, `--cluster-advertise`, `--san-ip`, `--san-dns`, `--no-auto-sans`, `--skip-preflight`, `--json` | One-shot cryptographic node enrollment + `acl.LockdownServerDir` without starting the daemon. |
| `cluster rejoin` | `--data-dir`, `--service-config`, `--seed` / `--join`, `--join-token` / `--join-token-stdin`, `--node-id`, `--bind`, `--port`, `--cluster-bind`, `--cluster-advertise`, `--san-ip`, `--san-dns`, `--no-auto-sans`, `--revoke-old`, `--no-restart`, `--service-name`, `--json` | Live certificate & SAN rotation. Auto-discovers seeds from flags -> `server.json` -> `cluster-state.json`. Without `--join-token`, performs **tokenless mTLS renewal** (`POST /cluster/v1/renew`) using the node's current valid cert; with `--join-token`, performs full `BootstrapJoin` re-keying. Optionally revokes the old serial (`--revoke-old`), updates `server.json`, locks down ACLs, and restarts the local OS service (detached if `AGENT_BRIDGE_IN_EXEC=1`). |
| `cluster token-create` | `--ttl` (default `1h`), `--node-id`, `--data-dir`, `--quiet` / `-q`, `--json` | Mints a single-use join token on a quorum node. |
| `cluster status` | `--data-dir`, `--json` | Displays node ID, addresses, topology, `QuorumState`, leader, `HasCAKey`, `CRLNumber`, and signed `ExecutionPolicy`. |
| `cluster peers` | `--data-dir`, `--json` | Lists cluster peer health, roles, exec/cluster endpoints, CRL numbers, and policy versions. |
| `cluster sync` | `--crl-file`, `--default-timeout`, `--max-timeout`, `--default-shell`, `--enforce-client-acl`, `--disable-client-acl`, `--allow-client`, `--data-dir`, `--json` | Pushes a newer `crl.pem` and/or signs & broadcasts an updated `ExecutionPolicy` (`Version + 1`), or forces immediate anti-entropy sync when called with no mutation flags. |

#### Zero-Script SAN Rotation Example (`cluster rejoin`)

When a host gains a new VLAN or secondary IP (`198.51.100.25`), rotate its node certificate and restart the daemon in one command without touching `openssl` or generating a join token:

```bash
sudo agent-bridge cluster rejoin \
  --data-dir /etc/agent-bridge \
  --bind 198.51.100.20,198.51.100.25,100.64.0.20 \
  --san-ip 198.51.100.25 \
  --revoke-old
```

### 5. PKI & Client Provisioning (`agent-bridge ca`, `client`, `host`, `health`)

#### `agent-bridge ca <init|issue|bundle|revoke>`

| Subcommand | Key Flags | Behavior |
| :--- | :--- | :--- |
| `ca init` | `--out-dir`, `--common-name`, `--org`, `--years` (`10`), `--san-ip`, `--san-dns`, `--no-auto-sans`, `--ca-only`, `--json` | Generates `ca.crt`, `ca.key`, `crl.pem`, and (unless `--ca-only`) initial `server.{crt,key}` + `peer.{crt,key}` populated with active NIC IPs + `--san-ip`/`--san-dns`, locked down with `internal/acl`. |
| `ca issue` | `--ca-dir`, `--type <server\|client\|peer>`, `--name`, `--out-dir`, `--bundle-out`, `--passphrase-env`, `--hosts <alias=host:port,...>`, `--default-host`, `--cluster-endpoint`, `--ip`, `--dns`, `--auto-sans`, `--years`, `--json` | Issues ECDSA P-256 leaf cert/key (writing PEMs to `--out-dir` and/or a portable `.abbundle` to `--bundle-out`). |
| `ca bundle` | `--ca`, `--cert`, `--key`, `--out <path\|->`, `--name`, `--passphrase-env`, `--hosts`, `--default-host`, `--cluster-endpoint`, `--json` | Packages existing client PEM files into an encrypted or plaintext `.abbundle`. |
| `ca revoke` | `--ca-dir`, `--cert <pem>` or `--serial <hex>`, `--crl-out`, `--sync`, `--cluster-addr`, `--data-dir`, `--config`, `--json` | Revokes by certificate file or hex serial, increments `CRLNumber`, atomically writes `crl.pem`, and when `--sync` is set, broadcasts the updated CRL into the live cluster mesh immediately. |

#### `agent-bridge client <init|verify>`, `health`, and `host <list|add|remove|set-default>`

- `agent-bridge client init --bundle <file|-> [--config-dir <dir>] [--config <file>] [--passphrase-env <ENV>] [--overwrite] [--default-host <alias>] [--verify] [--timeout <dur>] [--json]`: Installs client credentials + `config.json`, enforces `acl.LockdownClientDir` / `acl.LockdownClientFile`, and optionally probes every configured host over mTLS 1.3 (`--verify`).
- `agent-bridge client verify [--host <alias|addr>] [--all] [--config <file>] [--ca ...] [--cert ...] [--key ...] [--server-name <sni>] [--timeout <dur>] [--json]`: Executes a non-destructive TLS 1.3 mutual-auth + live CRL + `ExecutionPolicy` WebSocket handshake probe without spawning a remote shell; returns non-zero if any probed host fails.
- `agent-bridge health [--host <alias>] [--endpoint <addr>] [--all] [--json]`: Alias/companion health probe over `/ws/exec`.
- `agent-bridge host <list|add|remove|set-default>`: Manages named host profiles in `config.json` without manual JSON editing.

### 6. Remote Command Execution (`agent-bridge exec`)

```bash
agent-bridge exec [--host <alias>] [--endpoint <host:port>] [--config <file>] [--timeout <dur>] "<COMMAND>"
```

Configuration resolves from highest to lowest precedence:
1. **CLI Flags**: `--endpoint`, `--host`, `--config`, `--cert`, `--key`, `--ca`, `--timeout`
2. **Environment Variables**: `AGENT_BRIDGE_HOST`, `AGENT_BRIDGE_ENDPOINT`, `AGENT_BRIDGE_CLUSTER_ADDR`, `AGENT_BRIDGE_CERT`, `AGENT_BRIDGE_KEY`, `AGENT_BRIDGE_CA`, `AGENT_BRIDGE_TIMEOUT`
3. **Working Directory `.env`** (`./.env`)
4. **Working Directory `agent-bridge.json`** (`./agent-bridge.json`)
5. **Global User Config**: `~/.config/agent-bridge/config.json` (`%APPDATA%\agent-bridge\config.json` on Windows)
6. **Built-in Defaults**: port `8443` (`exec`), `127.0.0.1:8444` (`cluster`), timeout `60s` (hard ceiling `600s`)

```json
{
  "default_host": "node-a",
  "client_cert": "client.crt",
  "client_key": "client.key",
  "ca_cert": "ca.crt",
  "timeout": "60s",
  "hosts": {
    "node-a": {
      "endpoint": "100.64.0.10:8443",
      "cluster_endpoint": "100.64.0.10:8444",
      "timeout": "45s"
    },
    "node-b": {
      "endpoint": "100.64.0.20:8443",
      "cluster_endpoint": "100.64.0.20:8444",
      "timeout": "60s"
    }
  }
}
```

### 7. Cryptographically Verified Self-Upgrades (`agent-bridge selfupgrade`)

```bash
# Check latest release against current binary version
agent-bridge selfupgrade --check [--channel stable|prerelease] [--json]

# Download, verify Ed25519 signature + SHA-256 checksum, atomically swap binary, and restart service
sudo agent-bridge selfupgrade --yes [--version latest|v0.2.0] [--no-proxy] [--no-restart] [--service-name <name>] [--json]
```

- **Cryptographic Verification**: Verifies `SHA256SUMS.txt.sig` using the embedded 32-byte Ed25519 release public key before verifying the platform binary's SHA-256 digest and running a `<staged-binary> version` smoke test.
- **Corporate Proxy Resilience**: Automatically retries via direct dial when `HTTP_PROXY` / `HTTPS_PROXY` returns HTTP `502 Bad Gateway` (or bypasses proxies explicitly with `--no-proxy`).
- **Windows In-Use Binary Swap & Remote Exec Safety**: Moves the running `.exe` to `.exe.old` (swept automatically on subsequent CLI startups), moves the verified binary into place, triggers a detached service restart when `AGENT_BRIDGE_IN_EXEC=1`, and rolls back if the upgraded service fails to report healthy.

## Exit Code Reference

| Exit Code | Meaning |
| :--- | :--- |
| `0` | Remote command exited `0` (or local CLI subcommand succeeded). |
| `1` | Local config/file error, failed `doctor` / `client verify` check, TLS/mTLS/CRL rejection, WebSocket transport failure, or normalized remote failure. |
| `2` | Invalid CLI flags/positional arguments, or malformed WebSocket `CommandRequest` payload. |
| `124` | Remote command exceeded effective timeout; remote process tree killed. |
| `127` | Target shell executable failed to spawn or was not found on the server. |
| `130` | Interrupted (`SIGINT`/`SIGTERM`) or client WebSocket disconnected mid-command (remote process tree killed). |
| `137` | Remote `stdout` or `stderr` exceeded the `10 MiB` (`10,485,760` B) per-stream limit; remote process tree killed. |
| `1–255` / `<N>` | Exact remote process exit code. On POSIX (`linux`/`darwin`), non-zero 32-bit Windows exit codes whose low 8 bits are `0x00` (e.g., `256`, `0xC0000000`) are normalized to `1` so failures never mask to `0`. |

## Multi-Node Clustering & Quorum Reference

| Members (`N`) | `Topology` | `QuorumState` Values | Partition & Failover Behavior |
| :--- | :--- | :--- | :--- |
| `N = 1` | `single-node` | `healthy` (`1/1`) | Immediate self-coordinator; zero peer wait. |
| `N = 2` | `two-node` | `healthy` (`2/2`), `degraded-two-node-failover` (`1/2`) | Survives single-node reboots (`HasQuorum: true` after `9s` unreachable threshold) without 2-of-2 Raft deadlock; deterministic priority (`HasCAKey` > earliest `JoinedAt` > lexicographic `NodeID`); automatic anti-entropy convergence on reconnect. |
| `N >= 3` | `multi-node-quorum` | `healthy` (`N/N`), `degraded-quorum` (`>= floor(N/2)+1`), `minority-partition` (`< floor(N/2)+1`) | Majority partition elects coordinator and processes token/policy updates; minority partition rejects cluster-wide mutations (`ErrNoQuorum`) while keeping local `/ws/exec` online with cached CRL + signed policy (**Graceful Degradation**). |
