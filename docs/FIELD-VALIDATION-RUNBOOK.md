# Field Validation & Live Infrastructure Bring-Up Runbook

`agent-bridge v0.1.1` has been verified across Go `-race` suites, OpenSSL X.509v3/CRL checks, multi-daemon `127.0.0.1` loopback meshes, standalone (`N=1`) Windows Server 2022 (`powershell.exe`, Win32 Job Objects, NTFS `icacls`, `80ms` NTFS `crl.pem` hot-reload, Scheduled Task supervision), and cross-OS Debian 12 -> Windows Server 2022 mTLS 1.3 execution. **Multi-host (`N >= 2`) Tailscale clustering (Gates 4–5) remains to be validated on live multi-server infrastructure.**

Execute the five gates below in order when bringing up real hardware (e.g., `WIN-DC-01`, `WIN-DC-02`, and Linux hosts). Do not advance past a gate until every pass criterion in that gate succeeds.

---

## Gate 1 — PKI Architecture Choice & Host Preflight

### 1.1 Choose Your Root CA Operating Model

| Model | Where `ca.key` Lives | Node Enrollment Mode | Revocation Workflow | Recommended For |
| :--- | :--- | :--- | :--- | :--- |
| **Air-Gapped / Offline Root CA** *(Recommended for Domain Controllers)* | Encrypted operator/PKI workstation only (**never** copied to any server) | **Mode B (`pre-issued`)**: Pre-issue `--type peer` certs offline; join with `--cert`, `--key`, and `--join-token` | Run `ca revoke` offline, then push via `cluster sync --crl-file crl.pem` | Active Directory Domain Controllers (`WIN-DC-01`, `WIN-DC-02`) and high-security production hosts |
| **Online Seed Authority** | Single designated authority host (`--ca-key` or `<dir(--ca)>/ca.key`) | **Mode A (`csr-issued`)**: Zero pre-staged certs on joiners; node generates key locally and submits CSR via `--join-token` | Run `ca revoke` directly on authority node; `CRLWatcher` auto-gossips to all peers | Lab environments or fleets with a dedicated non-DC management server |

### 1.2 Verify Tailscale Overlay & System Clock Sync (Every Host)

TLS 1.3 leaf validation (`5m` `NotBefore` leeway) and RFC 5280 `crl.pem` checks (`NextUpdate`) fail closed on clock drift.

**Windows Server (Elevated PowerShell):**

```powershell
tailscale status
$TS_IP = (tailscale ip -4).Trim()
Write-Host "Tailscale IPv4: $TS_IP"

w32tm /query /status
```

**Linux:**

```bash
tailscale status
TS_IP=$(tailscale ip -4)
printf 'Tailscale IPv4: %s\n' "$TS_IP"

timedatectl status
```

**Pass Criteria**: `tailscale ip -4` returns a `100.x.y.z` address, peers are reachable over `tailscale ping <peer>`, and system clocks across all hosts + operator workstation agree within `< 60s`.

### 1.3 Lock Down Directory ACLs BEFORE Placing Private Keys

Go's `0600` file mode bits do not remove inherited `BUILTIN\Users` read permissions on Windows NTFS. Lock down the data directory **before** copying or generating any `.key` files.

**Windows Server (`WIN-DC-01` / `WIN-DC-02` — Elevated PowerShell):**

```powershell
New-Item -ItemType Directory -Force -Path `
  "C:\Program Files\AgentBridge", `
  "C:\ProgramData\agent-bridge", `
  "C:\ProgramData\agent-bridge\logs" | Out-Null

icacls "C:\ProgramData\agent-bridge" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"
icacls "C:\ProgramData\agent-bridge"
```

**Linux:**

```bash
sudo install -d -m 0700 -o root -g root /etc/agent-bridge
```

**Pass Criteria**: `icacls "C:\ProgramData\agent-bridge"` lists **only** `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators` (zero `Users` or `Everyone` ACEs).

### 1.4 Scope Host Firewall Rules to Tailscale (`8443/tcp` Only for Gate 2)

**Windows Server (Elevated PowerShell):**

```powershell
$TS_IP = (tailscale ip -4).Trim()
New-NetFirewallRule `
  -Name "AgentBridge-Exec-Tailscale" `
  -DisplayName "Agent-Bridge mTLS Exec (Tailscale)" `
  -Direction Inbound `
  -Action Allow `
  -Protocol TCP `
  -LocalAddress $TS_IP `
  -RemoteAddress 100.64.0.0/10 `
  -LocalPort 8443
```

**Linux (`ufw`):**

```bash
sudo ufw allow in on tailscale0 to any port 8443 proto tcp comment 'agent-bridge exec mTLS'
```

### 1.5 Provision Initial PKI & Dedicated Revocation-Test Credential

On your PKI workstation, initialize the Root CA, issue node certificates embedding every Tailscale IP and DNS name, issue your primary operator client certificate, and mint a **throwaway `smoke-revoke-test` client certificate** so you can test live CRL revocation in Gates 2 and 4 without burning your real operator credential:

```bash
# 1. Initialize Root CA (keep ./offline-pki/ca.key strictly on this workstation for Mode B)
agent-bridge ca init \
  --out-dir ./offline-pki \
  --common-name "Agent-Bridge-Root-CA" \
  --org "Agent-Bridge PKI" \
  --years 10

# 2. Issue dual-EKU peer certificates for WIN-DC-01 and WIN-DC-02
agent-bridge ca issue \
  --ca-dir ./offline-pki \
  --type peer \
  --name win-dc-01 \
  --ip 100.64.0.10 \
  --dns win-dc-01,win-dc-01.tailnet-example.ts.net \
  --out-dir ./issued/win-dc-01

agent-bridge ca issue \
  --ca-dir ./offline-pki \
  --type peer \
  --name win-dc-02 \
  --ip 100.64.0.11 \
  --dns win-dc-02,win-dc-02.tailnet-example.ts.net \
  --out-dir ./issued/win-dc-02

# 3. Issue primary operator/agent client certificate
agent-bridge ca issue \
  --ca-dir ./offline-pki \
  --type client \
  --name agent-dc-operator \
  --out-dir ./issued/ops-agent

# 4. Issue throwaway client certificate for Gate 2 revocation check
SMOKE_OUT=$(agent-bridge ca issue \
  --ca-dir ./offline-pki \
  --type client \
  --name smoke-revoke-test \
  --out-dir ./issued/smoke-revoke)
printf '%s\n' "$SMOKE_OUT"
SMOKE_SERIAL=$(printf '%s\n' "$SMOKE_OUT" | awk '/^Serial:/ {print $2}')
printf 'Smoke Serial: %s\n' "$SMOKE_SERIAL"
```

Copy `dist/agent-bridge-windows-amd64.exe` to `C:\Program Files\AgentBridge\agent-bridge.exe` on `WIN-DC-01`, and copy **only** `offline-pki/ca.crt`, `offline-pki/crl.pem`, `issued/win-dc-01/peer.crt`, and `issued/win-dc-01/peer.key` into `C:\ProgramData\agent-bridge\`.

---

## Gate 2 — Standalone (`N=1`) Interactive Validation on Windows Server

Run `agent-bridge.exe` interactively in an elevated PowerShell console **before** registering a background service so all `stderr` diagnostics are immediately visible.

### 2.1 Foreground Daemon Start (`WIN-DC-01`)

```powershell
$TS_IP = (tailscale ip -4).Trim()
& "C:\Program Files\AgentBridge\agent-bridge.exe" server `
  --bind $TS_IP `
  --port 8443 `
  --cert "C:\ProgramData\agent-bridge\peer.crt" `
  --key  "C:\ProgramData\agent-bridge\peer.key" `
  --ca   "C:\ProgramData\agent-bridge\ca.crt" `
  --crl  "C:\ProgramData\agent-bridge\crl.pem" `
  --shell powershell
```

**Expected Console Output**:
`[agent-bridge] YYYY/MM/DD HH:MM:SS listening on 100.64.0.10:8443 (tls=1.3 shell=powershell crl=C:\ProgramData\agent-bridge\crl.pem)`

### 2.2 Remote Functional Smoke Tests (From Operator Host)

```bash
DC01="100.64.0.10:8443"
CA="./offline-pki/ca.crt"
CERT="./issued/ops-agent/client.crt"
KEY="./issued/ops-agent/client.key"

# 1. Identity & stdout streaming -> must print identity and exit 0
agent-bridge exec --endpoint "$DC01" --ca "$CA" --cert "$CERT" --key "$KEY" "whoami"
echo "exit=$?"

# 2. Non-zero exit code propagation -> must exit 42
agent-bridge exec --endpoint "$DC01" --ca "$CA" --cert "$CERT" --key "$KEY" "exit 42"
echo "exit=$?"

# 3. Silent output (omitempty check) -> must produce 0 bytes and exit 0
OUT_BYTES=$(agent-bridge exec --endpoint "$DC01" --ca "$CA" --cert "$CERT" --key "$KEY" '$null' | wc -c)
echo "bytes=$OUT_BYTES"
```

### 2.3 mTLS & Interface Binding Negative Checks

```bash
# 1. Unauthenticated TLS probe (no client cert) -> MUST fail TLS 1.3 handshake
curl -vk "https://${DC01}/ws/exec"

# 2. LAN IP probe (replace with WIN-DC-01's non-Tailscale LAN IP) -> MUST fail to connect
curl -vk --connect-timeout 3 "https://192.168.1.10:8443/ws/exec"
```

### 2.4 Win32 Job Object Child-Process Tree Kill Verification (`exit 124`)

Verify that Windows `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` terminates grandchild processes (`ping.exe`) spawned by `powershell.exe` when a command times out:

```bash
# 1. Confirm zero baseline ping.exe processes on WIN-DC-01
agent-bridge exec --endpoint "$DC01" --ca "$CA" --cert "$CERT" --key "$KEY" \
  "@(Get-Process ping -ErrorAction SilentlyContinue).Count"

# 2. Spawn an infinite child ping.exe under a 3-second timeout -> MUST exit 124
agent-bridge exec --endpoint "$DC01" --ca "$CA" --cert "$CERT" --key "$KEY" --timeout 3s \
  "Start-Process -FilePath ping.exe -ArgumentList '-t','127.0.0.1' -NoNewWindow; Start-Sleep -Seconds 30"
echo "timeout_exit=$?"

# 3. Immediately verify zero orphaned ping.exe processes survived -> MUST print 0
agent-bridge exec --endpoint "$DC01" --ca "$CA" --cert "$CERT" --key "$KEY" \
  "@(Get-Process ping -ErrorAction SilentlyContinue).Count"
```

**Pass Criteria**: Step 2 exits **`124`** in `~3s`, and Step 3 prints **`0`**.

### 2.5 `10 MiB` Output Flood Guard Verification (`exit 137`)

```bash
# Emit 12 MiB on stdout -> MUST kill remote process tree and exit 137
agent-bridge exec --endpoint "$DC01" --ca "$CA" --cert "$CERT" --key "$KEY" \
  "'A' * 12582912" >/dev/null
echo "overflow_exit=$?"

# Confirm daemon remains healthy immediately afterward -> MUST exit 0
agent-bridge exec --endpoint "$DC01" --ca "$CA" --cert "$CERT" --key "$KEY" "'alive'"
```

### 2.6 Live NTFS `crl.pem` Hot-Reload & Defender/EDR Contention Check

```bash
# 1. Confirm throwaway cert currently succeeds -> exit 0
agent-bridge exec --endpoint "$DC01" --ca "$CA" \
  --cert ./issued/smoke-revoke/client.crt \
  --key  ./issued/smoke-revoke/client.key \
  "whoami"

# 2. Revoke throwaway serial on PKI workstation
agent-bridge ca revoke --ca-dir ./offline-pki --serial "$SMOKE_SERIAL"
```

Copy `./offline-pki/crl.pem` to `C:\ProgramData\agent-bridge\crl.pem.new` on `WIN-DC-01`, then atomically swap it in PowerShell:

```powershell
Move-Item -Force "C:\ProgramData\agent-bridge\crl.pem.new" "C:\ProgramData\agent-bridge\crl.pem"
```

Verify on `WIN-DC-01`'s console that `[agent-bridge] ... CRL hot-reloaded: crl_number=2 revoked_serials=1` logs within `< 1s` without NTFS lock errors, then re-test from the operator host:

```bash
# Revoked throwaway cert -> MUST fail with exit 1
# (Client stderr: "mTLS handshake rejected ... remote error: tls: bad certificate";
#  Server stderr: "TLS Handshake Rejected: Certificate Serial [...] is Revoked")
agent-bridge exec --endpoint "$DC01" --ca "$CA" \
  --cert ./issued/smoke-revoke/client.crt \
  --key  ./issued/smoke-revoke/client.key \
  "whoami"
echo "revoked_exit=$?"

# Primary operator cert -> MUST continue succeeding (exit 0)
agent-bridge exec --endpoint "$DC01" --ca "$CA" --cert "$CERT" --key "$KEY" "whoami"
```

Press `Ctrl+C` in the `WIN-DC-01` foreground PowerShell session once all Gate 2 checks pass.

---

## Gate 3 — Service Persistence & Boot-Time Tailscale Race Validation

> [!WARNING]
> Do **not** register `agent-bridge.exe` directly via `sc.exe create` or `New-Service`. `agent-bridge.exe` is a foreground console process (it does not implement `golang.org/x/sys/windows/svc`) and will fail with **Error 1053**. Use **WinSW** or **NSSM** with `Tailscale` service dependency + `3s` failure restart delay so boot-time races before `100.x.y.z` assignment recover automatically.

### 3.1 Windows Server Option A: WinSW (`WinSW-x64.exe`)

Place `WinSW-x64.exe` renamed to `C:\Program Files\AgentBridge\agent-bridge-service.exe` alongside `C:\Program Files\AgentBridge\agent-bridge-service.xml`:

```xml
<service>
  <id>agent-bridge</id>
  <name>Agent-Bridge mTLS Daemon</name>
  <description>Synchronous mTLS 1.3 execution and cluster state daemon over Tailscale</description>
  <executable>C:\Program Files\AgentBridge\agent-bridge.exe</executable>
  <arguments>server --bind 100.64.0.10 --port 8443 --cert "C:\ProgramData\agent-bridge\peer.crt" --key "C:\ProgramData\agent-bridge\peer.key" --ca "C:\ProgramData\agent-bridge\ca.crt" --crl "C:\ProgramData\agent-bridge\crl.pem" --shell powershell</arguments>
  <depend>Tailscale</depend>
  <startmode>Automatic</startmode>
  <onfailure action="restart" delay="3 sec"/>
  <resetfailure>1 hour</resetfailure>
  <logpath>C:\ProgramData\agent-bridge\logs</logpath>
  <log mode="roll-by-size">
    <sizeThreshold>10240</sizeThreshold>
    <keepFiles>5</keepFiles>
  </log>
</service>
```

```powershell
& "C:\Program Files\AgentBridge\agent-bridge-service.exe" install
& "C:\Program Files\AgentBridge\agent-bridge-service.exe" start
Get-Service agent-bridge
```

### 3.2 Windows Server Option B: NSSM (`nssm.exe`)

```powershell
$BIN = "C:\Program Files\AgentBridge\agent-bridge.exe"
$ARGS = 'server --bind 100.64.0.10 --port 8443 --cert "C:\ProgramData\agent-bridge\peer.crt" --key "C:\ProgramData\agent-bridge\peer.key" --ca "C:\ProgramData\agent-bridge\ca.crt" --crl "C:\ProgramData\agent-bridge\crl.pem" --shell powershell'

nssm install agent-bridge $BIN $ARGS
nssm set agent-bridge DependOnService Tailscale
nssm set agent-bridge Start SERVICE_AUTO_START
nssm set agent-bridge AppExit Default Restart
nssm set agent-bridge AppRestartDelay 3000
nssm set agent-bridge AppStdout "C:\ProgramData\agent-bridge\logs\agent-bridge.out.log"
nssm set agent-bridge AppStderr "C:\ProgramData\agent-bridge\logs\agent-bridge.err.log"
nssm set agent-bridge AppRotateFiles 1
nssm set agent-bridge AppRotateBytes 10485760
nssm start agent-bridge
```

### 3.3 Linux Hosts (`systemd`)

Create `/etc/systemd/system/agent-bridge.service`:

```ini
[Unit]
Description=Agent-Bridge mTLS 1.3 Execution & Cluster Daemon
After=network-online.target tailscaled.service
Wants=network-online.target tailscaled.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/agent-bridge server \
  --bind 100.64.0.12 \
  --port 8443 \
  --cert /etc/agent-bridge/peer.crt \
  --key /etc/agent-bridge/peer.key \
  --ca /etc/agent-bridge/ca.crt \
  --crl /etc/agent-bridge/crl.pem \
  --shell sh
Restart=on-failure
RestartSec=3s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now agent-bridge.service
sudo systemctl status agent-bridge.service
```

### 3.4 Full Host Reboot Validation

Reboot the target host (`Restart-Computer -Force` on Windows or `sudo systemctl reboot` on Linux). Without logging into the host locally after reboot, verify from your operator workstation once Tailscale reconnects:

```bash
agent-bridge exec --endpoint "$DC01" --ca "$CA" --cert "$CERT" --key "$KEY" \
  "hostname; (Get-Service agent-bridge).Status"
```

**Pass Criteria**: Service starts automatically after reboot, survives any transient Tailscale IP bring-up delay via the `3s` restart loop, and responds `Running` over mTLS 1.3.

---

## Gate 4 — `N=2` Multi-Host Cluster Validation over Tailscale (`WIN-DC-01` + `WIN-DC-02`)

### 4.1 Open Cluster Port `8444/tcp` on Both Hosts (Tailscale Only)

**Windows Server (`WIN-DC-01` and `WIN-DC-02` — Elevated PowerShell):**

```powershell
$TS_IP = (tailscale ip -4).Trim()
New-NetFirewallRule `
  -Name "AgentBridge-Cluster-Tailscale" `
  -DisplayName "Agent-Bridge Cluster Mesh (Tailscale)" `
  -Direction Inbound `
  -Action Allow `
  -Protocol TCP `
  -LocalAddress $TS_IP `
  -RemoteAddress 100.64.0.0/10 `
  -LocalPort 8444
```

**Linux:**

```bash
sudo ufw allow in on tailscale0 to any port 8444 proto tcp comment 'agent-bridge cluster mTLS'
```

### 4.2 Enable `--cluster-bind` on Seed Node (`WIN-DC-01`)

Update `WIN-DC-01`'s WinSW `<arguments>` (or `nssm set agent-bridge AppParameters`) to add `--cluster-bind 100.64.0.10:8444 --node-id win-dc-01`, restart the service, and verify single-node cluster health from your operator workstation:

```bash
agent-bridge cluster status \
  --cluster-addr 100.64.0.10:8444 \
  --ca "$CA" --cert "$CERT" --key "$KEY"
```

**Expected Output**: `Topology: single-node`, `Quorum State: healthy`, `Has Quorum: true`, `Members: 1/1 (quorum: 1)`.

### 4.3 Enroll `WIN-DC-02` into the Cluster

Mint a single-use join token bound to `win-dc-02`:

```bash
JOIN_TOKEN=$(agent-bridge cluster token-create \
  --cluster-addr 100.64.0.10:8444 \
  --ca "$CA" --cert "$CERT" --key "$KEY" \
  --node-id win-dc-02 --ttl 30m -q)
```

#### Path 4A — Mode B: Air-Gapped Pre-Issued Join (`pre-issued`, Recommended for DCs)

Prepare `WIN-DC-02` with Gate 1.3 NTFS ACLs + Gate 1.4/4.1 firewall rules, copy `agent-bridge.exe` and `issued/win-dc-02/{peer.crt,peer.key}` to `C:\ProgramData\agent-bridge\`, and run the initial bootstrap in an elevated PowerShell session:

```powershell
& "C:\Program Files\AgentBridge\agent-bridge.exe" server `
  --bind 100.64.0.11 `
  --port 8443 `
  --cluster-bind 100.64.0.11:8444 `
  --node-id win-dc-02 `
  --join 100.64.0.10:8444 `
  --join-token "<PASTE_JOIN_TOKEN>" `
  --cert "C:\ProgramData\agent-bridge\peer.crt" `
  --key  "C:\ProgramData\agent-bridge\peer.key" `
  --ca   "C:\ProgramData\agent-bridge\ca.crt" `
  --crl  "C:\ProgramData\agent-bridge\crl.pem" `
  --shell powershell
```

Confirm stderr logs `joined cluster via 100.64.0.10:8444 (mode=pre-issued node_id=win-dc-02 ...)` and creates `C:\ProgramData\agent-bridge\cluster-state-win-dc-02.json`. Then stop the foreground process (`Ctrl+C`) and register the WinSW/NSSM service on `WIN-DC-02` using `--join 100.64.0.10:8444` **without** `--join-token` (subsequent restarts detect `Bootstrapped: true` on disk and skip token enrollment automatically).

#### Path 4B — Mode A: Online CSR Join (`csr-issued`, Only When Seed Holds `ca.key`)

If the seed node has `ca.key` loaded (`CA Signer: true` in `cluster status`), `WIN-DC-02` requires zero pre-staged certificates:

```powershell
& "C:\Program Files\AgentBridge\agent-bridge.exe" server `
  --bind 100.64.0.11 `
  --port 8443 `
  --cluster-bind 100.64.0.11:8444 `
  --node-id win-dc-02 `
  --join 100.64.0.10:8444 `
  --join-token "<PASTE_JOIN_TOKEN>" `
  --data-dir "C:\ProgramData\agent-bridge" `
  --shell powershell
```

### 4.4 Verify Mesh Membership & Sub-Second Cross-Host CRL Revocation

```bash
# 1. Verify 2/2 healthy mesh from both nodes
agent-bridge cluster status --cluster-addr 100.64.0.10:8444 --ca "$CA" --cert "$CERT" --key "$KEY"
agent-bridge cluster peers  --cluster-addr 100.64.0.11:8444 --ca "$CA" --cert "$CERT" --key "$KEY"

# 2. Issue a second throwaway client cert and confirm exec works on WIN-DC-02
SMOKE2_OUT=$(agent-bridge ca issue --ca-dir ./offline-pki --type client --name smoke-mesh-revoke --out-dir ./issued/smoke-mesh)
SMOKE2_SERIAL=$(printf '%s\n' "$SMOKE2_OUT" | awk '/^Serial:/ {print $2}')

agent-bridge exec --endpoint 100.64.0.11:8443 --ca "$CA" \
  --cert ./issued/smoke-mesh/client.crt --key ./issued/smoke-mesh/client.key "hostname"

# 3. Revoke offline and push the new CRL to WIN-DC-01 ONLY
agent-bridge ca revoke --ca-dir ./offline-pki --serial "$SMOKE2_SERIAL"
agent-bridge cluster sync \
  --cluster-addr 100.64.0.10:8444 \
  --ca "$CA" --cert "$CERT" --key "$KEY" \
  --crl-file ./offline-pki/crl.pem

# 4. Immediately test against WIN-DC-02 -> MUST reject with exit 1
# (Client stderr: "mTLS handshake rejected ... remote error: tls: bad certificate";
#  WIN-DC-02 server log: "TLS Handshake Rejected: Certificate Serial [...] is Revoked")
agent-bridge exec --endpoint 100.64.0.11:8443 --ca "$CA" \
  --cert ./issued/smoke-mesh/client.crt --key ./issued/smoke-mesh/client.key "hostname"
echo "peer_revoked_exit=$?"
```

### 4.5 Single-DC Reboot & `degraded-two-node-failover` Check

1. Reboot `WIN-DC-02` (`Restart-Computer -Force`).
2. Wait **`10s`** (past the `9.0s` `UnreachableTimeout` = `6 * 1.5s` gossip tick) and query `WIN-DC-01`:

```bash
agent-bridge cluster status --cluster-addr 100.64.0.10:8444 --ca "$CA" --cert "$CERT" --key "$KEY"
```

**Pass Criteria While `WIN-DC-02` Is Down**:
- `Quorum State: degraded-two-node-failover`
- `Has Quorum: true`
- `Members: 1/2`
- Mutating policy on `WIN-DC-01` while `WIN-DC-02` is down (`agent-bridge cluster sync --cluster-addr 100.64.0.10:8444 --ca "$CA" --cert "$CERT" --key "$KEY" --default-timeout 45s`) **succeeds**, and `/ws/exec` on `WIN-DC-01` remains uninterrupted.
3. Once `WIN-DC-02` finishes rebooting, wait `5s` and run `cluster peers` against `WIN-DC-02`: confirm `Quorum State: healthy` (`2/2`) and confirm `WIN-DC-02`'s `POLICY_VER` automatically caught up to `WIN-DC-01`.

---

## Gate 5 — `N>=3` Quorum, Client ACL Lockdown & Partition Graceful Degradation

*(Execute this gate if deploying 3 or more cluster nodes; skip to the Troubleshooting Matrix if operating a 2-node DC pair.)*

### 5.1 Enroll Node 3 & Verify `multi-node-quorum`

Enroll your 3rd node (`node-3`) using the same Gate 4.3 workflow, then verify:

```bash
agent-bridge cluster status --cluster-addr 100.64.0.10:8444 --ca "$CA" --cert "$CERT" --key "$KEY"
```

**Pass Criteria**: `Topology: multi-node-quorum`, `Quorum State: healthy`, `Members: 3/3 (quorum: 2)`.

### 5.2 Enforce Cluster-Wide Client Certificate ACL

> [!IMPORTANT]
> `--allow-client` **replaces** the entire `AllowedClients` list on each update. Always pass every authorized client CommonName or serial hex together.

```bash
agent-bridge cluster sync \
  --cluster-addr 100.64.0.10:8444 \
  --ca "$CA" --cert "$CERT" --key "$KEY" \
  --enforce-client-acl \
  --allow-client agent-dc-operator \
  --default-timeout 45s \
  --max-timeout 180s
```

Verify that `agent-dc-operator` succeeds across all 3 nodes while a newly issued, unrevoked client certificate with CN `unlisted-operator` is rejected on `/ws/exec` across all 3 nodes.

### 5.3 Simulate Network Partition & Verify Graceful Degradation

On `node-3`, temporarily block non-loopback TCP `8444` (cluster gossip) in both directions while leaving local `lo` routing to `"${TS_IP}:8444"` and TCP `8443` (`/ws/exec`) open:

```bash
# On Linux node-3 (exclude lo so local "${TS_IP}:8444" cluster CLI checks on node-3 still work):
sudo iptables -I INPUT  ! -i lo -p tcp --dport 8444 -j DROP
sudo iptables -I OUTPUT ! -o lo -p tcp --dport 8444 -j DROP
```

Wait **`10s`** (`> 9.0s` unreachable timeout) and verify both sides of the partition:

1. **Majority Partition (`WIN-DC-01` + `WIN-DC-02`, `2/3`)**:
   - `cluster status` on `WIN-DC-01` reports `Quorum State: degraded-quorum`, `Has Quorum: true`, `Members: 2/3 (quorum: 2)`.
   - `cluster token-create` and `cluster sync` **succeed**.
2. **Isolated Minority Node (`node-3`, `1/3`)**:
   - Run `cluster status --cluster-addr "${TS_IP}:8444"` locally on `node-3` (routes via `lo`, matching `peer.crt`'s Tailscale IP SAN): reports `Quorum State: minority-partition`, `Has Quorum: false`, `Members: 1/3 (quorum: 2)`.
   - Run `cluster token-create --cluster-addr "${TS_IP}:8444"` locally on `node-3`: **fails closed** (`cluster operation rejected: node is in minority-partition without majority quorum`).
   - `agent-bridge exec` against `<node-3-ts-ip>:8443` **continues succeeding**, enforcing `node-3`'s cached `crl.pem` and signed `ExecutionPolicy`.

Remove the temporary `8444` block (`sudo iptables -D INPUT ! -i lo -p tcp --dport 8444 -j DROP && sudo iptables -D OUTPUT ! -o lo -p tcp --dport 8444 -j DROP`), wait `5s`, and confirm `3/3 healthy` reconvergence.

---

## Troubleshooting Matrix

| Symptom / Error Message | Root Cause | Resolution |
| :--- | :--- | :--- |
| **Windows Error 1053**: `The service did not respond to the start or control request in a timely fashion` | `agent-bridge.exe` was registered directly with `sc.exe create` or `New-Service` without a service wrapper. | Delete the broken SCM entry (`sc.exe delete agent-bridge`) and install via **WinSW** or **NSSM** (Gate 3.1 / 3.2). |
| `failed to bind TCP listener on 100.x.y.z:8443: bind: The requested address is not valid in its context` *(Windows)* or `cannot assign requested address` *(Linux)* | `tailscaled` has not yet assigned `100.x.y.z` at boot, Tailscale is logged out, or `--bind` specifies another host's IP. | Verify `tailscale ip -4` matches `--bind`, ensure service depends on `Tailscale` / `tailscaled.service`, and configure `3s` failure-restart backoff. |
| `x509: certificate has expired or is not yet valid` or `CRL initialization failed: CRL has expired` | Host system clock skew exceeds the `5m` `NotBefore` leeway, or `crl.pem` passed `NextUpdate`. | Resync NTP (`w32tm /resync` or `chronyc makestep`); re-sign `crl.pem` (`ca revoke` or `cluster sync --crl-file`). |
| `x509: certificate is valid for ..., not 100.x.y.z` | Target server/peer certificate was issued without `--ip 100.x.y.z` (or `--dns <fqdn>`) in its SAN extension. | Re-issue the node certificate with `agent-bridge ca issue --ip <tailscale-ip> --dns <hostname>` and restart `agent-bridge`. |
| `open C:\ProgramData\agent-bridge\server.key: Access is denied` or `Move-Item` lock failure on `crl.pem` | Service user lacks NTFS permissions on `C:\ProgramData\agent-bridge`, or EDR real-time scanner is holding an exclusive handle during atomic rename. | Run service as `LocalSystem` (`SYSTEM`), verify `icacls` grants `SYSTEM:(OI)(CI)F`, and scope Defender/EDR lock exclusions if atomic `crl.pem` swaps contend. |
| `join token has already been used`, `join token has expired`, or `CA certificate ... fingerprint does not match join token CA pin` | Single-use `abjt1` token was already consumed, exceeded `--ttl`, or `--ca` on disk belongs to a different `ca init` run. | Mint a fresh token via `agent-bridge cluster token-create --ttl 30m -q` and confirm `ca.crt` matches the cluster's `CA Fingerprint`. |
| `forbidden: client certificate CN="<cn>" Serial=[<serial>] is not authorized` (`HTTP 403` on `/ws/exec` `:8443`) or `client certificate is not authorized by cluster execution policy` (`HTTP 403` on `/cluster/v1/*` `:8444`) | `enforce_client_acl` is enabled and a subsequent `--allow-client` flag replaced the allowlist without including this client's `CommonName` or serial. | Re-run `agent-bridge cluster sync --enforce-client-acl` passing `--allow-client` for **every** authorized client CN/serial. |
| `cluster operation rejected: node is in minority-partition without majority quorum` | Target `N>=3` node can reach fewer than `floor(N/2)+1` members over TCP `8444`. | Check `agent-bridge cluster peers`, verify TCP `8444` firewall rules and `tailscale ping` between nodes, or run the admin command against a node in the majority partition. |
