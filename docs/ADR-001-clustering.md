# ADR-001: Multi-Node Clustering, Topology-Aware Quorum & Cryptographic Node Joining

| Field | Value |
| :--- | :--- |
| **Status** | Accepted |
| **Date** | 2026-11-07 |
| **Component** | `cluster/` (`github.com/kennyparsons/agent-bridge/cluster`), `cmd/agent-bridge`, `internal/config`, `internal/pki`, `internal/protocol`, `internal/runner`, `internal/server` |
| **Verification Status** | Verified in Go `-race` suites & Linux loopback multi-daemon tests; pending live Windows Server & multi-host Tailscale field validation |

## Context & Constraints

`agent-bridge` provides synchronous mTLS 1.3 command execution across Windows Server Domain Controllers (e.g., `WIN-DC-01`, `WIN-DC-02`) and Linux/macOS hosts over private overlay networks such as Tailscale. Multi-node deployments must replicate security-critical control-plane state (`crl.pem` revocations, `ExecutionPolicy`, join-token consumption tombstones, and peer membership/health) across nodes while satisfying five hard invariants:

1. **Zero Heavy External Dependencies**: Static `CGO_ENABLED=0` cross-compilation across `windows/amd64`, `linux/amd64`, `linux/arm64`, and `darwin/arm64` without embedded C/C++ libraries or heavyweight storage engines.
2. **Universal Topology Support (`N=1`, `N=2`, `N>=3`)**: Identical binary and configuration model across standalone single-host deployments (`N=1`), two-node Active Directory Domain Controller pairs (`N=2`), and three-or-more node fleets (`N>=3`).
3. **Graceful Degradation of `/ws/exec`**: Network partitions or peer maintenance reboots must never brick local `/ws/exec` command execution on surviving reachable hosts; isolated nodes must continue enforcing their last-known cryptographically verified CRL and execution policy.
4. **Split-Brain & Tamper Immunity**: Replicated state must be cryptographically signed and monotonically versioned so partitioned, stale, or compromised peers cannot roll back revocations or inject unsigned policies.
5. **Dual-Mode Cryptographic Node Joining**: Support both online zero-private-key-transfer CSR enrollment and offline air-gapped `ca.key` pre-issued certificate registration.

## Evaluated Approaches

| Dimension | Approach A: Embedded Raft (`hashicorp/raft`) | Approach B (Selected): TLS 1.3 TCP Gossip Mesh + Signed Monotonic State + Topology-Aware Quorum | Approach C: Active-Passive Primary-Replica with Dynamic Lease |
| :--- | :--- | :--- | :--- |
| **`N=1` Standalone** | Requires single-server bootstrap special-casing and persistent BoltDB/WAL log dir | Native 0-config immediate self-coordinator (`1/1 healthy`) | Works as standalone primary |
| **`N=2` DC Pair Reboot** | **Fails**: $\lfloor 2/2 \rfloor + 1 = 2$; rebooting either DC halts quorum completely | **Survives**: deterministic tie-breaker transitions survivor to `degraded-two-node-failover` without lockup | Fails if primary reboots unless lease expires; clock skew risks dual-primary |
| **`N>=3` Node Loss** | Tolerates $\lfloor (N-1)/2 \rfloor$ failures in majority partition | Dynamic majority quorum ($\text{alive} \ge \lfloor N/2 \rfloor + 1$) elects new coordinator; minority degrades gracefully | Single-primary bottleneck; replica promotion vulnerable to asymmetric partition |
| **Overlay Firewall Traversal** | TCP stream transport | Single routable TLS 1.3 TCP port (`--cluster-bind`, default `:8444`); traverses Tailscale WireGuard & DERP TCP relays | TCP stream transport |
| **Split-Brain Safety** | Term + log index quorum | Cryptographic Root CA / ECDSA P-256 signatures + monotonic `CRLNumber` & `ExecutionPolicy.Version` | Vulnerable to lease-TTL clock drift / VM pause |
| **External Dependencies** | High (`hashicorp/raft`, `raft-boltdb`, `go-msgpack`, WAL engines) | **Zero** new third-party dependencies (`crypto/tls`, `crypto/x509`, `crypto/ecdsa`, `net/http`) | Zero to low |

### Approach A: Embedded Raft Consensus (`hashicorp/raft`) — Rejected

- **Strengths**: Linearizable replicated state machine (FSM) and well-understood leader election for odd-sized clusters (`N=3`, `N=5`).
- **Why Rejected**:
  1. **`N=2` Operational Deadlock**: Medium enterprise Active Directory environments commonly deploy exactly two Domain Controllers (`WIN-DC-01`, `WIN-DC-02`). Under strict Raft quorum ($\lfloor 2/2 \rfloor + 1 = 2$), monthly Windows Update reboots on either host drop quorum to `1/2`, halting cluster writes and leader operations.
  2. **Conflict with Graceful Degradation**: Raft optimizes for linearizable log commitment rather than autonomous local execution under partition, requiring manual `RecoverCluster` intervention if permanent majority loss occurs.
  3. **Disproportionate Footprint**: Replicating commutative, `< 64 KiB` signed control-plane artifacts (`crl.pem` and `ExecutionPolicy`) does not require an append-only WAL, snapshot compaction, or BoltDB B+trees.

### Approach C: Active-Passive / Primary-Replica with Dynamic Lease — Rejected

- **Strengths**: Straightforward pull/push replication while the designated primary is reachable.
- **Why Rejected**:
  1. **Lease Clock-Skew Split-Brain**: Hypervisor live-migration pauses, NTP step adjustments, or asymmetric Tailscale DERP partitions cause replicas to assume lease expiry while the old primary still considers itself active, creating dual-primary conflicts unless backed by monotonic cryptographic versioning anyway.
  2. **Control-Plane Stall on Primary Outage**: Without topology-aware quorum and deterministic peer failover, revocations and policy updates stall whenever the primary host is down.

### Approach B (Selected): Pure-Go TLS 1.3 TCP Gossip Mesh + Cryptographically Signed Monotonic State

`agent-bridge` implements a pure-Go SWIM-inspired heartbeat and push-pull anti-entropy mesh over mutual-authenticated TLS 1.3 TCP connections (`--cluster-bind <ip:port>`, `1.5s` default gossip tick, `4.5s` suspect threshold, `9.0s` unreachable threshold), paired with cryptographically signed monotonic state envelopes and topology-aware quorum evaluation.

#### 1. Why TLS 1.3 TCP Instead of UDP Gossip (`hashicorp/memberlist`)

UDP gossip protocols (`7946/udp`) suffer silent packet drops across Windows Defender Firewall host rules, corporate stateful firewalls, and Tailscale subnet routers or DERP TCP relays. Running heartbeat probes, join handshakes, and anti-entropy state sync over a single TLS 1.3 TCP listener guarantees reliable traversal wherever Tailscale TCP routing functions, enforces mutual X.509 peer authentication + live CRL checks on every inter-node socket, and introduces zero external dependencies.

#### 2. Topology Matrix (`N=1`, `N=2`, `N>=3`)

Coordinator ranking among alive, unrevoked cluster members uses a total, deterministic priority order:
1. **`HasCAKey == true`** (nodes holding the Root CA private key for CSR issuance and CRL signing take precedence)
2. **Earliest `JoinedAt` timestamp** (stable incumbency avoids leader flapping when new nodes join)
3. **Lexicographically smallest `NodeID`** (deterministic tie-breaker across simultaneous bootstrap)

| Cluster Size (`N`) | Quorum Threshold | Reachable Peers (`alive`) | `QuorumState` | Coordinator Behavior | `/ws/exec` & Revocation Behavior |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`N = 1`** | `1` | `1 / 1` | `healthy` | Immediate self-coordinator on startup; zero peer wait | Full local execution, CRL hot-reload, and policy enforcement |
| **`N = 2`** | `2` (full) / `1` (failover) | `2 / 2` | `healthy` | Highest-priority node acts as coordinator; peer syncs via push + anti-entropy | Full execution and instant bidirectional CRL/policy replication |
| **`N = 2`** | `2` (full) / `1` (failover) | `1 / 2` | `degraded-two-node-failover` | Surviving node assumes virtual coordinator (`HasQuorum: true`) without 2-of-2 deadlock | `/ws/exec` stays online; local CRL/policy updates replicate automatically via monotonic numbers when peer returns |
| **`N >= 3`** | $\lfloor N/2 \rfloor + 1$ | $\text{alive} = N$ | `healthy` | Highest-priority member is elected coordinator | Full cluster-wide token/policy coordination, CRL gossip, and explicit multi-host client targeting |
| **`N >= 3`** | $\lfloor N/2 \rfloor + 1$ | $\lfloor N/2 \rfloor + 1 \le \text{alive} < N$ | `degraded-quorum` | Highest-priority member inside the majority component is elected coordinator | Full cluster-wide token/policy coordination, CRL gossip, and explicit multi-host client targeting |
| **`N >= 3`** | $\lfloor N/2 \rfloor + 1$ | $\text{alive} < \lfloor N/2 \rfloor + 1$ | `minority-partition` | Minority nodes step down from cluster-wide token/policy mutation (`ErrNoQuorum`) | `/ws/exec` remains online enforcing last-known verified policy + cached `crl.pem`; higher-numbered CA-signed CRLs are still accepted immediately |

#### 3. Cryptographic Split-Brain Immunity

State convergence never trusts network transport alone; every replicated artifact carries an independent cryptographic proof chained to `ca.crt`:

- **Certificate Revocation List (`crl.pem`)**:
  - Verified via `x509.ParseRevocationList` + `crl.CheckSignatureFrom(caCert)` + `now < crl.NextUpdate`.
  - Monotonic acceptance rule: `incoming.Number > local.CRLNumber`. Stale, replayed, or equal CRLs are ignored idempotently; valid newer CRLs atomically replace `crl.pem` on disk and swap the in-memory `atomic.Pointer` snapshot in `0ms` before gossiping forward.
- **Execution Policy (`ExecutionPolicy`)**:
  - Canonicalized via `ExecutionPolicy.CanonicalBytes()` (sorted, deduplicated `AllowedClients`, deterministic JSON field ordering) and signed over the domain-separated digest `"agent-bridge-policy-v1:" || canonicalBytes` with ECDSA P-256 (`SHA-256`) by the Root CA or an unrevoked node certificate possessing `ExtKeyUsageServerAuth` chained to `ca.crt`.
  - Monotonic acceptance rule: valid signature + unrevoked `ServerAuth`/CA signer chain + `incoming.Version > local.Version`.
- **EKU Authorization Boundary on `--cluster-bind`**:
  - Internal peer mesh routes (`/cluster/v1/{sign-join,sync-push,sync-pull}`) and `SignedPolicyEnvelope` signers strictly require `ExtKeyUsageServerAuth` (or Root CA), preventing `ClientAuth`-only agent credentials from spoofing peer gossip or forging policies.
  - Administration routes (`/cluster/v1/{status,peers,tokens,sync}`) accept authenticated node certificates or `ClientAuth` operator certificates, enforcing `ExecutionPolicy.IsClientAllowed` on `ClientAuth`-only callers when `enforce_client_acl` is enabled.
- **Peer Revocation Eviction**:
  - Revoking a compromised server/peer certificate via `agent-bridge ca revoke` increments `CRLNumber`, propagates across the gossip mesh within milliseconds, causes `VerifyPeerCertDualEKU` to reject all subsequent TLS 1.3 cluster handshakes from that node, and tears down active peer sessions immediately.

#### 4. Dual-Mode Cryptographic Node Joining (`--join` + `--join-token`)

Join tokens follow the pinned v1 format:

```text
abjt1.<ca_sha256_64hex>.<token_id_16hex>.<secret_64hex>
```

- `<ca_sha256_64hex>`: 64-character lowercase SHA-256 digest of `ca.crt` DER (`pki.CertFingerprintSHA256`), enabling the joining node to pin and verify the seed node's Root CA certificate during initial TLS 1.3 contact without Trust-On-First-Use (TOFU) exposure.
- `<token_id_16hex>.<secret_64hex>`: 64-bit token identifier paired with a 256-bit capability secret validated in constant time (`subtle.ConstantTimeCompare`) against a domain-separated salted SHA-256 `TokenRecord` (`"agent-bridge-join-token-v1:"`). Plaintext token secrets are never persisted to disk or gossiped. Tokens have a bounded TTL (`15m` engine API default; `1h` CLI `cluster token-create --ttl` default), optional `--node-id` binding, and strictly **single-use** semantics (`Used=true` tombstones are retained and replicated across peers for `24h` so consumed tokens cannot be replayed across peer failovers).

Two enrollment workflows are supported seamlessly:

1. **Mode A (`csr-issued`) — Online CSR Enrollment (Zero Private-Key Transfer)**:
   - Joining node has no pre-existing leaf keypair at `--cert`/`--key` (or `--data-dir`); it generates an ECDSA P-256 private key (`0600`) locally, builds a signed PKCS#10 CSR embedding its bind/cluster/advertise IPs and DNS SANs (`pki.GenerateKeyAndCSR`), dials `--join <seed>` verifying the seed's certificate chain against `<ca_sha256_64hex>`, and submits `{token, node_id, cluster_addr, exec_addr, hostname, csr_pem}` to `/cluster/v1/join`.
   - The seed validates and atomically consumes the single-use join token, verifies CSR proof-of-possession (`csr.CheckSignature()`), and signs a dual-EKU (`ServerAuth + ClientAuth`) leaf certificate clamped to `ca.crt.NotAfter` (`pki.SignNodeCSR`) — either locally when `HasCAKey == true` or by forwarding the verified CSR over mutual-authenticated `/cluster/v1/sign-join` to an alive `HasCAKey` peer. The joiner atomically persists `server.crt` + `server.key` (or caller `--cert`/`--key`), `ca.crt`, `crl.pem`, and `cluster-state-<node-id>.json`.
2. **Mode B (`pre-issued`) — Offline / Air-Gapped `ca.key` Registration**:
   - Organizations keeping `ca.key` offline on an air-gapped workstation pre-issue the node's certificate via `agent-bridge ca issue --type peer` (`peer.crt`/`peer.key`) or `--type server` (`server.crt`/`server.key`) and place the leaf keypair (plus optional `ca.crt`) on the host.
   - Joining node signs a domain-separated ECDSA proof-of-possession digest (`"agent-bridge-join-pop-v1:"` over `token_id`, `node_id`, and `cluster_addr`), connects to `--join <seed>` presenting its pre-issued certificate and `--join-token`, and the seed verifies the certificate chain against `ca.crt` + live `crl.pem` + PoP signature, admits the node to the peer roster without needing `ca.key` online anywhere in the cluster, and returns `{ca_cert_pem, crl_pem, signed_policy, peers}`.

**Idempotent Restart Guarantee**: Once `StatePath` (`Bootstrapped: true`) alongside `cert`, `key`, `ca`, and `crl` exist and validate on disk, subsequent daemon restarts skip `BootstrapJoin` automatically without contacting `--join` for enrollment or attempting to re-consume `--join-token`.

## Consequences

- **Single-Endpoint Client Determinism & Explicit Host Failover**: `internal/client` (`agent-bridge exec`) dials a single resolved `wss://<endpoint>/ws/exec` target per invocation with zero hidden multi-host retries, guaranteeing non-idempotent administrative commands never execute twice across Domain Controllers. Operators and AI agents define named node profiles (`hosts.win-dc-01`, `hosts.win-dc-02`) in `config.json` and switch targets explicitly via `--host <peer>` or `--endpoint <ip:port>` during host maintenance, while mTLS/CRL authentication rejections surface immediately.
- **Deterministic Windows DC Pair Operation**: `N=2` deployments survive routine single-host reboots without Raft quorum lockup and reconcile state deterministically on reconnect.
- **Strict Cryptographic Monotonicity**: Rollback attacks and split-brain state overwrites are impossible without possessing an unrevoked signing key chained to the Root CA and a strictly higher monotonic version/CRL number.
