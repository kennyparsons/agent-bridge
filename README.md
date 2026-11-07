# agent-bridge

Static, zero-dependency Go binary (`v0.1.0`) for synchronous remote command execution and multi-node security-state replication over private overlay networks (e.g., Tailscale) using Mutual TLS 1.3, self-contained ECDSA P-256 PKI, hot-reloading Certificate Revocation Lists (CRLs), and transactional WebSockets (`wss://<endpoint>/ws/exec`).

- **Protocol & Security Specification**: [spec.md](spec.md)
- **Clustering Architecture Decision Record**: [docs/ADR-001-clustering.md](docs/ADR-001-clustering.md)
- **Live Infrastructure Bring-Up Runbook**: [docs/FIELD-VALIDATION-RUNBOOK.md](docs/FIELD-VALIDATION-RUNBOOK.md)

## Verification Status

> [!IMPORTANT]
> `agent-bridge` has passed automated unit, race-detector, cryptographic, and multi-daemon loopback suites on Linux `amd64`, **but has not yet been executed on live Windows Server hardware or a multi-host Tailscale network**. Follow [docs/FIELD-VALIDATION-RUNBOOK.md](docs/FIELD-VALIDATION-RUNBOOK.md) gate-by-gate before production rollout.

| Scope | Status | Details |
| :--- | :--- | :--- |
| **Go Race & Integration Suites (`linux/amd64`)** | **Verified** | `64` `-race` tests passing across all 8 packages (`internal/pki`, `internal/protocol`, `internal/runner`, `internal/server`, `internal/config`, `internal/client`, `cluster`, `cmd/agent-bridge`). |
| **X.509v3 & RFC 5280 CRL Cryptography** | **Verified** | Cross-checked against `openssl x509` / `openssl crl` (`ECDSA P-256` + `SHA-256`, 128-bit positive serials, SKI/AKI, IP/DNS SANs, CA `NotAfter` clamping, monotonic `CRLNumber`). |
| **POSIX Process Isolation & Stream Bounds** | **Verified** | Linux `Setpgid` + `-pgid` `SIGKILL` orphan cleanup on timeout/disconnect, `10 MiB` per-stream overflow cutoff (`exit 137`), and 8-bit POSIX exit-code normalization. |
| **Multi-Daemon Cluster Mesh (`127.0.0.1`)** | **Verified** | Single-host `N=1`, `N=2`, and `N=3` daemons verified for `~55ms` CRL gossip, Mode A CSR join + peer CSR forwarding, Mode B offline-CA PoP join, failover, minority-partition Graceful Degradation, and EKU/ACL privilege boundaries. |
| **Static Cross-Compilation (`CGO_ENABLED=0`)** | **Verified** | Clean `go vet` and static binary builds for `windows/amd64`, `linux/amd64`, `linux/arm64`, and `darwin/arm64`. |
| **Live Windows Server 2022 (`WIN-DC-01` / `WIN-DC-02`)** | **Pending Field Test** | Real Win32 Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) child-tree kill, NTFS `icacls` DACLs, and `os.Rename` atomic swaps under Windows Defender / EDR real-time scanning. |
| **Windows Service Wrapper & Tailscale Boot Race** | **Pending Field Test** | `WinSW` / `NSSM` service lifecycle, `Tailscale` service dependency ordering, and `3s` restart-on-failure recovery while `100.x.y.z` initializes on reboot. |
| **Multi-Host Tailscale / Routed-Subnet Mesh** | **Pending Field Test** | Cross-host WireGuard / DERP latency, Windows Defender Firewall interface scoping (`8443/tcp`, `8444/tcp`), and live Domain Controller reboot failover. |

## Security & Execution Architecture

| Layer | Enforcement |
| :--- | :--- |
| **Network Binding** | Server binds strictly to `--bind <ip>` (e.g., `100.64.0.10`); preflight bind check fails fast before opening listeners or consuming join tokens if the interface is absent or port is in use. |
| **Transport & Identity** | `tls.VersionTLS13` minimum, `tls.RequireAndVerifyClientCert` on `/ws/exec`, ECDSA P-256 (`secp256r1`) + SHA-256 signatures, positive 128-bit random serials, IP/DNS SAN verification, `5m` `NotBefore` clock-skew leeway. |
| **Revocation (`crl.pem`)** | RFC 5280 v2 CRL validated synchronously at startup (`CheckSignatureFrom` + `NextUpdate`), hot-reloaded lock-free via `fsnotify` + stat fallback, and pushed across clustered peers on reload. |
| **Cluster Mesh (`8444/tcp`)** | Pure-Go TLS 1.3 TCP SWIM/anti-entropy mesh (`cluster/`, `1.5s` gossip tick, `4.5s` suspect, `9.0s` unreachable) with Root-CA-pinned single-use join tokens (`abjt1.<ca_sha256>.<id>.<secret>`) and ECDSA-signed `ExecutionPolicy` replication. |
| **Wire Protocol** | Single JSON `CommandRequest` text frame in, single compact JSON `CommandResponse` text frame (`omitempty` on empty streams) out, followed by WebSocket Close `1000`. |
| **Process Isolation** | Per-command timeout (`60s` default, `600s` ceiling), `10 MiB` (`10,485,760` B) per-stream cap, immediate process-tree termination on timeout or client disconnect (`JobObject` on Windows; `Setpgid` + `-pgid` `SIGKILL` on Linux/macOS). |

```text
[AI Agent / Operator CLI]
   │  agent-bridge exec --host win-dc-01 "Get-ADUser -Identity jdoe | ConvertTo-Json -Compress"
   ▼
[Client Wrapper] ── mTLS 1.3 + wss://100.64.0.10:8443/ws/exec ──► [Node 1 Daemon]
   │                                                                  ├─ Verify client chain against ca.crt
   │                                                                  ├─ Check leaf serial against live crl.pem
   │                                                                  ├─ Enforce signed cluster ExecutionPolicy (ACL / timeouts / shell)
   │                                                                  ├─ Spawn isolated shell (powershell / sh)
   ◄── {"exit_code":0,"stdout":"..."} + Close(1000) ──────────────────┘
                                                                      ▲
                                        TLS 1.3 TCP Gossip (:8444) ───┴───► Peer Nodes (CRL + Policy + Quorum)
```

## Build & Cross-Compilation

Requires Go `1.26+`. All targets compile with `CGO_ENABLED=0`, `-trimpath`, and `-ldflags="-s -w"`.

```bash
make build      # Host binary -> bin/agent-bridge
make build-all  # Static cross-compiled binaries -> dist/
make vet        # Static analysis
make test       # Full go test -race suite
```

| Target Artifact | `GOOS` | `GOARCH` |
| :--- | :--- | :--- |
| `dist/agent-bridge-windows-amd64.exe` | `windows` | `amd64` |
| `dist/agent-bridge-linux-amd64` | `linux` | `amd64` |
| `dist/agent-bridge-linux-arm64` | `linux` | `arm64` |
| `dist/agent-bridge-darwin-arm64` | `darwin` | `arm64` |

## CLI & Flag Reference

### Version & Help

```bash
agent-bridge version     # Also accepts --version, -version, -v -> "agent-bridge v0.1.0"
agent-bridge --help      # Subcommand help: agent-bridge <cmd> [subcmd] --help
```

### 1. PKI Lifecycle (`agent-bridge ca`)

#### `agent-bridge ca init`

Generates `ca.crt` (`0644`), `ca.key` (`0600`), and an initial signed `crl.pem` (`0644`, `CRLNumber=1`). Prints `CA Certificate:`, `CA Private Key:`, `CRL:`, and `Serial:`.

| Flag | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `--out-dir <dir>` | Yes | — | Output directory for `ca.crt`, `ca.key`, and `crl.pem`. |
| `--common-name <cn>` | No | `"Agent-Bridge-Root-CA"` | Root CA Subject Common Name. |
| `--org <name>` | No | `"Agent-Bridge PKI"` | Subject Organization applied to Root CA. |
| `--years <int>` | No | `10` | Root CA and initial CRL validity period in years. |

#### `agent-bridge ca issue`

Issues an ECDSA P-256 leaf certificate and private key signed by `ca.crt` / `ca.key`. Leaf `NotAfter` is automatically clamped so it never exceeds `ca.crt.NotAfter`. Prints `Certificate:`, `Private Key:`, and `Serial:` (colon-uppercase hex, e.g., `4A:2F:89:1B:...`) directly to `stdout` — `openssl` is not needed to extract serials.

| Flag | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `--ca-dir <dir>` | Yes | — | Directory containing `ca.crt` and `ca.key`. |
| `--type <profile>` | Yes | — | Certificate profile: `server`, `client`, or `peer`. |
| `--name <cn>` | Yes | — | Leaf Subject Common Name (used as default `--node-id` and ACL identity). |
| `--out-dir <dir>` | Yes | — | Output directory for generated certificate and private key. |
| `--ip <ip>` | For `server` | — | IPv4/IPv6 SAN (repeatable or comma-separated). Strictly required (at least one `--ip` or `--dns`) for `--type server`; optional at issuance for `--type peer`, though recommended and required whenever `peer.crt` also serves `/ws/exec`. |
| `--dns <name>` | For `server` | — | DNS SAN (repeatable or comma-separated; satisfies the SAN requirement for `--type server` and `/ws/exec`). |
| `--years <int>` | No | Profile-dependent | Validity period in years (`3` for `server`/`peer`, `1` for `client`). |

| `--type` Profile | Output Files (`--out-dir`) | Default Validity | Extended Key Usage (EKU) | Intended Use |
| :--- | :--- | :--- | :--- | :--- |
| `server` | `server.crt` (`0644`), `server.key` (`0600`) | `3` years | `ServerAuth` | Standalone servers or Mode B cluster nodes. |
| `peer` | `peer.crt` (`0644`), `peer.key` (`0600`) | `3` years | `ServerAuth` + `ClientAuth` | Pre-issued cluster nodes (`Mode B` air-gapped CA) that also run `cluster` admin CLI calls. |
| `client` | `client.crt` (`0644`), `client.key` (`0600`) | `1` year | `ClientAuth` | AI agents and operators calling `exec` and `cluster` admin subcommands. |

#### `agent-bridge ca revoke`

Appends a certificate serial to the CRL (idempotent if already revoked), increments `CRLNumber`, re-signs with `ca.key`, and atomically replaces the target CRL file. Prints `CRL:`, `CRL Number:`, and `Revoked Serial:`.

| Flag | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `--ca-dir <dir>` | Yes | — | Directory containing `ca.crt` and `ca.key`. |
| `--serial <hex>` | Yes | — | Serial number in colon-separated hex (`4A:2F:...`), plain hex (`4a2f...`), or `0x`-prefixed hex (`0x4A2F...`). |
| `--crl-out <path>` | No | `<ca-dir>/crl.pem` | Output file path for updated `crl.pem`. |

### 2. Execution & Cluster Daemon (`agent-bridge server`)

Runs in **standalone mode** when neither `--cluster-bind` nor `--join` is passed, or **cluster mode** when `--cluster-bind` and/or `--join` is supplied.

| Flag | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `--bind <ip>` | Yes | — | Local interface IPv4/IPv6 address for `/ws/exec` (e.g., Tailscale IP `100.64.0.10`). |
| `--port <int>` | No | `8443` | TCP port for `/ws/exec`. |
| `--cert <path>` | Standalone: Yes | `<data-dir>/server.crt` | Leaf certificate PEM (`server.crt` or `peer.crt`). |
| `--key <path>` | Standalone: Yes | `<data-dir>/server.key` | Leaf private key PEM (`server.key` or `peer.key`). |
| `--ca <path>` | Standalone: Yes | `<data-dir>/ca.crt` | Root CA certificate PEM. |
| `--crl <path>` | Standalone: Yes | `<data-dir>/crl.pem` | Signed CRL PEM watched for live hot-reload and peer gossip. |
| `--shell <name>` | No | `powershell` (Windows), `sh` (Linux/macOS) | Execution shell (`powershell`, `pwsh`, `cmd`, `sh`, `bash`). Passing `--shell` explicitly sets `ShellExplicit=true`, overriding cluster `ExecutionPolicy.DefaultShell`. |
| `--cluster-bind <ip:port>` | No | `<bind>:8444` when `--join` is set | Cluster TLS 1.3 gossip and admin API bind address. |
| `--cluster-advertise <addr>` | No | `--cluster-bind` | Routable `host:port` advertised to cluster peers. |
| `--join <peer_ip:port>` | No | — | Seed peer cluster address for initial enrollment and anti-entropy sync. |
| `--join-token <token>` | Initial `--join` only | — | Single-use `abjt1.<ca_sha256>.<id>.<secret>` token. Automatically skipped on restarts once bootstrapped on disk. |
| `--node-id <id>` | No | Leaf cert `CN` -> OS hostname -> `"node-1"` | Unique cluster member identifier. |
| `--ca-key <path>` | No | Auto-discovered at `<dir(--ca)>/ca.key` if present | Root CA private key for Mode A CSR signing (`HasCAKey: true`). Keep `ca.key` off server disks for air-gapped Mode B deployments. |
| `--cluster-state <path>` | No | `<dir(--crl)>/cluster-state-<node-id>.json` | Persistent JSON file storing peer roster, signed policy, and token tombstones. |
| `--data-dir <dir>` | No | `./agent-bridge-data/<node-id>` (with `--join`) | Base directory resolving omitted `--cert`, `--key`, `--ca`, and `--crl` paths. |

### 3. Client Command Execution (`agent-bridge exec`)

```bash
agent-bridge exec [flags] "<COMMAND>"
```

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--host <name>` | `default_host` | Named host profile from `agent-bridge.json` or global `config.json`. |
| `--endpoint <host:port>` | Profile / env | Target `/ws/exec` `ip:port`, `host`, or `wss://host:port/ws/exec` (defaults port to `8443`). |
| `--cert <path>` | Profile / env | Client certificate PEM path. |
| `--key <path>` | Profile / env | Client private key PEM path. |
| `--ca <path>` | Profile / env | Root CA certificate PEM path. |
| `--timeout <dur\|sec>` | `60s` | Per-command timeout (`1s` to `600s`; accepts Go durations like `45s`, `2m` or integer seconds `45`). |

`agent-bridge exec` dials a **single** resolved endpoint per invocation (no hidden multi-host retry), writes remote `stdout` strictly to local `stdout`, writes remote `stderr` and transport/TLS errors strictly to `stderr`, and exits with the remote process exit code. Switch nodes explicitly via `--host <peer>` or `--endpoint <peer_ip:8443>`.

#### 5-Tier Client Configuration Precedence (Highest to Lowest)

1. **CLI Flags**: `--endpoint` / `--cluster-addr`, `--host`, `--cert`, `--key`, `--ca`, `--timeout`
2. **Process Environment Variables**:
   - `AGENT_BRIDGE_HOST`
   - `AGENT_BRIDGE_ENDPOINT`
   - `AGENT_BRIDGE_CLUSTER_ADDR`
   - `AGENT_BRIDGE_CERT`
   - `AGENT_BRIDGE_KEY`
   - `AGENT_BRIDGE_CA`
   - `AGENT_BRIDGE_TIMEOUT`
3. **Working Directory `.env`**: `./.env` (`KEY=VALUE` lines; supports `export` prefix, `#` comments, and quoted values)
4. **Working Directory JSON**: `./agent-bridge.json`
5. **Global User Config JSON**: `~/.config/agent-bridge/config.json` (on Windows, checks `%APPDATA%\agent-bridge\config.json` first, then falls back to `~/.config/agent-bridge/config.json`)
6. **Built-in Defaults**: port `8443` (`exec`), `127.0.0.1:8444` (`cluster`), timeout `60s` (hard ceiling `600s`)

**Provenance-Aware Path Resolution**: `~/` and `~\` expand to the user home directory. Relative certificate paths (`client_cert`, `client_key`, `ca_cert`) configured inside the global `config.json` resolve relative to that global config file's directory; relative paths from `./agent-bridge.json`, `./.env`, environment variables, or CLI flags resolve relative to the current working directory.

```json
{
  "default_host": "win-dc-01",
  "client_cert": "client.crt",
  "client_key": "client.key",
  "ca_cert": "ca.crt",
  "timeout": "60s",
  "hosts": {
    "win-dc-01": {
      "endpoint": "100.64.0.10:8443",
      "cluster_endpoint": "100.64.0.10:8444",
      "timeout": "45s"
    },
    "win-dc-02": {
      "endpoint": "100.64.0.11:8443",
      "cluster_endpoint": "100.64.0.11:8444",
      "timeout": "60s"
    }
  }
}
```

### 4. Cluster Administration (`agent-bridge cluster`)

All `cluster` subcommands share the target/mTLS flags `--cluster-addr <host:port>` (default `127.0.0.1:8444` when no host/env is configured), `--host <name>`, `--cert <path>`, `--key <path>`, `--ca <path>`, and `--timeout <dur|sec>` (default `60s`).

| Subcommand | Subcommand-Specific Flags | Behavior |
| :--- | :--- | :--- |
| `cluster token-create` | `--ttl <dur\|sec>` (default `1h`), `--node-id <id>`, `--quiet` / `-q`, `--json` | Mints a single-use `abjt1...` join token on a quorum node (`--quiet` prints bare token string; mutually exclusive with `--json`). |
| `cluster status` | `--json` | Displays node ID, addresses, topology (`single-node`, `two-node`, `multi-node-quorum`), `QuorumState`, leader, `HasCAKey`, `CRLNumber`, and active `ExecutionPolicy`. |
| `cluster peers` | `--json` | Renders aligned peer table (`NODE_ID`, `STATE`, `ROLE`, `CLUSTER_ADDR`, `EXEC_ADDR`, `CRL_NUM`, `POLICY_VER`, `CA_SIGNER`, `LAST_SEEN`) or JSON array. |
| `cluster sync` | `--crl-file <path>`, `--default-timeout <dur\|0>`, `--max-timeout <dur\|0>`, `--default-shell <name>`, `--enforce-client-acl`, `--disable-client-acl`, `--allow-client <cn-or-serial>`, `--json` | Uploads a newer `crl.pem` and/or signs & broadcasts a new monotonic `ExecutionPolicy` (`Version + 1`). Passing `--allow-client` (repeatable/CSV) **replaces** the full `AllowedClients` allowlist. Calling `cluster sync` with **no** mutation flags forces an immediate local CRL reload + anti-entropy push/pull across all peers. |

## Exit Code Reference

| Exit Code | Meaning |
| :--- | :--- |
| `0` | Remote command exited `0` (or local CLI subcommand succeeded). |
| `1` | Local config/file error, TLS/mTLS/CRL rejection, WebSocket transport failure, or normalized remote failure. |
| `2` | Invalid CLI flags/positional arguments, or malformed WebSocket `CommandRequest` payload. |
| `124` | Remote command exceeded effective timeout; remote process tree killed. |
| `127` | Target shell executable failed to spawn or was not found on the server. |
| `130` | Interrupted (`SIGINT`/`SIGTERM`) or client WebSocket disconnected mid-command (remote process tree killed). |
| `137` | Remote `stdout` or `stderr` exceeded the `10 MiB` (`10,485,760` B) per-stream limit; remote process tree killed. |
| `1–255` / `<N>` | Exact remote process exit code. On POSIX (`linux`/`darwin`), non-zero 32-bit Windows exit codes whose low 8 bits are `0x00` (e.g., `256`, `0xC0000000`) are normalized to `1` so failures never mask to `0`. |

## Multi-Node Clustering & Enrollment Modes

### Topology & Quorum Matrix

| Members (`N`) | `Topology` | `QuorumState` Values | Partition & Failover Behavior |
| :--- | :--- | :--- | :--- |
| `N = 1` | `single-node` | `healthy` (`1/1`) | Immediate self-coordinator; zero peer wait. |
| `N = 2` | `two-node` | `healthy` (`2/2`), `degraded-two-node-failover` (`1/2`) | Survives single-DC reboots (`HasQuorum: true` after `9s` unreachable threshold) without 2-of-2 Raft deadlock; deterministic priority (`HasCAKey` > earliest `JoinedAt` > lexicographic `NodeID`); automatic anti-entropy convergence on reconnect. |
| `N >= 3` | `multi-node-quorum` | `healthy` (`N/N`), `degraded-quorum` (`>= floor(N/2)+1`), `minority-partition` (`< floor(N/2)+1`) | Majority partition elects coordinator and processes token/policy updates; minority partition rejects cluster-wide mutations (`ErrNoQuorum`) while keeping local `/ws/exec` online with cached CRL + signed policy (**Graceful Degradation**). |

### Mode B: Air-Gapped Offline Root CA Join (`pre-issued` — Recommended for Domain Controllers)

Keep `ca.key` on an offline administration workstation so no Domain Controller ever stores the Root CA private key:

```bash
# 1. On offline PKI workstation: initialize CA and pre-issue peer/client certs
agent-bridge ca init --out-dir ./offline-pki
agent-bridge ca issue --ca-dir ./offline-pki --type peer   --name win-dc-01 --ip 100.64.0.10 --dns win-dc-01 --out-dir ./out/win-dc-01
agent-bridge ca issue --ca-dir ./offline-pki --type peer   --name win-dc-02 --ip 100.64.0.11 --dns win-dc-02 --out-dir ./out/win-dc-02
agent-bridge ca issue --ca-dir ./offline-pki --type client --name agent-dc-operator --out-dir ./out/ops-agent
# Copy ONLY ca.crt, crl.pem, peer.crt, and peer.key to win-dc-01 (NEVER copy ca.key).
# Copy ONLY peer.crt and peer.key (plus optional ca.crt) to win-dc-02.

# 2. On win-dc-01: start seed node (HasCAKey=false)
agent-bridge server \
  --bind 100.64.0.10 --port 8443 \
  --cluster-bind 100.64.0.10:8444 \
  --node-id win-dc-01 \
  --cert /etc/agent-bridge/peer.crt \
  --key  /etc/agent-bridge/peer.key \
  --ca   /etc/agent-bridge/ca.crt \
  --crl  /etc/agent-bridge/crl.pem

# 3. Mint a single-use join token from operator host
JOIN_TOKEN=$(agent-bridge cluster token-create \
  --cluster-addr 100.64.0.10:8444 \
  --cert ./out/ops-agent/client.crt \
  --key  ./out/ops-agent/client.key \
  --ca   ./offline-pki/ca.crt \
  --node-id win-dc-02 --ttl 30m -q)

# 4. On win-dc-02: join presenting pre-issued peer.crt + peer.key (fetches ca.crt, crl.pem & policy)
agent-bridge server \
  --bind 100.64.0.11 --port 8443 \
  --cluster-bind 100.64.0.11:8444 \
  --node-id win-dc-02 \
  --join 100.64.0.10:8444 \
  --join-token "$JOIN_TOKEN" \
  --cert /etc/agent-bridge/peer.crt \
  --key  /etc/agent-bridge/peer.key \
  --ca   /etc/agent-bridge/ca.crt \
  --crl  /etc/agent-bridge/crl.pem
```

When revoking a certificate in Mode B, run `agent-bridge ca revoke` on the offline workstation and push the updated `crl.pem` into the mesh with `agent-bridge cluster sync --cluster-addr 100.64.0.10:8444 --crl-file ./offline-pki/crl.pem`.

### Mode A: Zero-Touch Online CSR Join (`csr-issued`)

When a designated seed/authority node holds `ca.key` (`--ca-key` or `<dir(--ca)>/ca.key`), joining nodes require **zero** pre-staged certificates or keys — `BootstrapJoin` generates an ECDSA P-256 key locally (`0600`), verifies the seed against the `<ca_sha256>` hash in `--join-token`, submits a signed CSR (forwarded automatically over `/cluster/v1/sign-join` if the contacted seed lacks `ca.key`), and writes `server.crt`, `server.key`, `ca.crt`, `crl.pem`, and `cluster-state-<node-id>.json` into `--data-dir`.

### Local Loopback 2-Node Walkthrough (Verified on Linux Build Host)

```bash
# 1. Clean workspace and initialize Root CA, Node 1 cert, and client cert (capture Serial natively without openssl)
rm -rf /tmp/ab-demo && mkdir -p /tmp/ab-demo
./bin/agent-bridge ca init --out-dir /tmp/ab-demo/pki
./bin/agent-bridge ca issue --ca-dir /tmp/ab-demo/pki --type server --name node-1 --ip 127.0.0.1 --out-dir /tmp/ab-demo/node1
CLIENT_OUT=$(./bin/agent-bridge ca issue --ca-dir /tmp/ab-demo/pki --type client --name ops-agent --out-dir /tmp/ab-demo/ops-agent)
printf '%s\n' "$CLIENT_OUT"
CLIENT_SERIAL=$(printf '%s\n' "$CLIENT_OUT" | awk '/^Serial:/ {print $2}')

# 2. Start Node 1 on 28443/28444 (auto-discovers /tmp/ab-demo/pki/ca.key for Mode A CSR signing)
./bin/agent-bridge server \
  --bind 127.0.0.1 --port 28443 \
  --cluster-bind 127.0.0.1:28444 \
  --node-id node-1 \
  --cert /tmp/ab-demo/node1/server.crt \
  --key  /tmp/ab-demo/node1/server.key \
  --ca   /tmp/ab-demo/pki/ca.crt \
  --crl  /tmp/ab-demo/pki/crl.pem &
NODE1_PID=$!
sleep 0.5

# 3. Mint single-use join token and enroll Node 2 on 29443/29444 with zero pre-staged certs (Mode A)
JOIN_TOKEN=$(./bin/agent-bridge cluster token-create \
  --cluster-addr 127.0.0.1:28444 \
  --cert /tmp/ab-demo/ops-agent/client.crt \
  --key  /tmp/ab-demo/ops-agent/client.key \
  --ca   /tmp/ab-demo/pki/ca.crt \
  --ttl 1h -q)

./bin/agent-bridge server \
  --bind 127.0.0.1 --port 29443 \
  --cluster-bind 127.0.0.1:29444 \
  --node-id node-2 \
  --join 127.0.0.1:28444 \
  --join-token "$JOIN_TOKEN" \
  --data-dir /tmp/ab-demo/node2 &
NODE2_PID=$!
sleep 0.5

# 4. Inspect peer mesh and execute a command on Node 2
./bin/agent-bridge cluster peers \
  --cluster-addr 127.0.0.1:29444 \
  --cert /tmp/ab-demo/ops-agent/client.crt \
  --key  /tmp/ab-demo/ops-agent/client.key \
  --ca   /tmp/ab-demo/pki/ca.crt

./bin/agent-bridge exec \
  --endpoint 127.0.0.1:29443 \
  --cert /tmp/ab-demo/ops-agent/client.crt \
  --key  /tmp/ab-demo/ops-agent/client.key \
  --ca   /tmp/ab-demo/pki/ca.crt \
  "uname -s"

# 5. Revoke client cert on Node 1 -> CRL gossips to Node 2 -> Node 2 rejects immediately
./bin/agent-bridge ca revoke --ca-dir /tmp/ab-demo/pki --serial "$CLIENT_SERIAL"
sleep 0.3
./bin/agent-bridge exec \
  --endpoint 127.0.0.1:29443 \
  --cert /tmp/ab-demo/ops-agent/client.crt \
  --key  /tmp/ab-demo/ops-agent/client.key \
  --ca   /tmp/ab-demo/pki/ca.crt \
  "uname -s"

kill "$NODE1_PID" "$NODE2_PID" && wait "$NODE1_PID" "$NODE2_PID" 2>/dev/null
rm -rf /tmp/ab-demo
```

## Critical Windows & Linux Deployment Notes

> [!WARNING]
> **Windows Service Control Manager (Error 1053)**: `agent-bridge.exe` is a foreground console process and does **not** implement `golang.org/x/sys/windows/svc`. Registering `agent-bridge.exe` directly via `sc.exe create` or `New-Service` will fail at start with **Error 1053: The service did not respond to the start or control request in a timely fashion**. Always wrap `agent-bridge.exe` with **WinSW**, **NSSM**, or a `SYSTEM` Scheduled Task configured with:
> 1. Service dependency on `Tailscale` (`DependOnService`), and
> 2. Restart-on-failure (`3s` delay) so if `agent-bridge.exe` starts before `tailscaled.exe` finishes assigning `100.x.y.z`, the wrapper retries cleanly until `--bind` succeeds.

### Windows Server (`WIN-DC-01` / `WIN-DC-02`)

1. **Lock down NTFS ACLs BEFORE copying or generating private keys** (Go's `0600` mode bits do not strip inherited `Users` read ACLs on Windows NTFS):

```powershell
New-Item -ItemType Directory -Force -Path "C:\Program Files\AgentBridge", "C:\ProgramData\agent-bridge" | Out-Null
icacls "C:\ProgramData\agent-bridge" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"
```

2. **Scope Windows Defender Firewall strictly to the Tailscale IP**:

```powershell
New-NetFirewallRule `
  -DisplayName "Agent-Bridge mTLS (Tailscale)" `
  -Direction Inbound `
  -Action Allow `
  -Protocol TCP `
  -LocalAddress 100.64.0.10 `
  -LocalPort 8443,8444
```

3. See **Gate 2** and **Gate 3** in [docs/FIELD-VALIDATION-RUNBOOK.md](docs/FIELD-VALIDATION-RUNBOOK.md) for interactive validation, Win32 Job Object orphan tests, and complete copy-pasteable **WinSW** / **NSSM** configurations.

### Linux (`systemd`)

Lock down `/etc/agent-bridge` (`chmod 0700 /etc/agent-bridge && chmod 0600 /etc/agent-bridge/*.key`) and configure `systemd` with `After=network-online.target tailscaled.service`, `Wants=tailscaled.service`, `Restart=on-failure`, and `RestartSec=3s` (full unit template in [docs/FIELD-VALIDATION-RUNBOOK.md](docs/FIELD-VALIDATION-RUNBOOK.md)).
