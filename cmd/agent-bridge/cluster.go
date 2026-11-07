package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/kennyparsons/agent-bridge/cluster"
	"github.com/kennyparsons/agent-bridge/internal/config"
	"github.com/kennyparsons/agent-bridge/internal/protocol"
)

const defaultCLITokenTTL = "1h"

type clusterTargetFlags struct {
	clusterAddr *string
	host        *string
	certPath    *string
	keyPath     *string
	caPath      *string
	timeout     *string
}

func bindClusterTargetFlags(fs *flag.FlagSet) clusterTargetFlags {
	return clusterTargetFlags{
		clusterAddr: fs.String("cluster-addr", "", "Target cluster control-plane host:port (default 127.0.0.1:8444)"),
		host:        fs.String("host", "", "Named host profile from config.json"),
		certPath:    fs.String("cert", "", "Client or node certificate PEM path"),
		keyPath:     fs.String("key", "", "Client or node private key PEM path"),
		caPath:      fs.String("ca", "", "Root CA certificate PEM path"),
		timeout:     fs.String("timeout", "", "Control-plane request timeout (e.g. 30s, 2m)"),
	}
}

func (f clusterTargetFlags) newClient() (*cluster.Client, error) {
	resolved, err := config.ResolveClusterConfig(config.ClusterFlagOverrides{
		Host:        *f.host,
		ClusterAddr: *f.clusterAddr,
		CertPath:    *f.certPath,
		KeyPath:     *f.keyPath,
		CAPath:      *f.caPath,
		Timeout:     *f.timeout,
	})
	if err != nil {
		return nil, err
	}
	return cluster.NewClient(resolved)
}

func runCluster(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printClusterUsage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "token-create":
		return runClusterTokenCreate(ctx, args[1:], stdout, stderr)
	case "status":
		return runClusterStatus(ctx, args[1:], stdout, stderr)
	case "peers":
		return runClusterPeers(ctx, args[1:], stdout, stderr)
	case "sync":
		return runClusterSync(ctx, args[1:], stdout, stderr)
	case "help", "--help", "-help", "-h":
		printClusterUsage(stdout)
		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "Error: unknown cluster subcommand %q\n\n", args[0])
		printClusterUsage(stderr)
		return exitUsage
	}
}

func runClusterTokenCreate(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("cluster token-create")
	target := bindClusterTargetFlags(fs)
	ttlStr := fs.String("ttl", defaultCLITokenTTL, "Single-use token validity duration (e.g. 15m, 1h, 24h)")
	boundNodeID := fs.String("node-id", "", "Optional node_id binding for the join token")
	var quiet bool
	fs.BoolVar(&quiet, "quiet", false, "Print bare join token string only")
	fs.BoolVar(&quiet, "q", false, "Print bare join token string only (shorthand)")
	jsonOut := fs.Bool("json", false, "Format output as indented JSON")

	if code, handled := parseFlags(fs, args, stdout, stderr, printClusterTokenCreateUsage); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		printClusterTokenCreateUsage(stderr)
		return exitUsage
	}
	if quiet && *jsonOut {
		_, _ = fmt.Fprintln(stderr, "Error: --quiet and --json cannot be combined")
		printClusterTokenCreateUsage(stderr)
		return exitUsage
	}

	ttlDur, err := parsePositiveDuration(*ttlStr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: invalid --ttl %q: %v\n", *ttlStr, err)
		return exitUsage
	}

	cl, err := target.newClient()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
	defer func() {
		_ = cl.Close()
	}()

	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	resp, err := cl.CreateToken(sigCtx, ttlDur, strings.TrimSpace(*boundNodeID))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	if quiet {
		_, _ = fmt.Fprintln(stdout, resp.Token)
		return exitOK
	}
	if *jsonOut {
		return writeIndentedJSON(stdout, stderr, resp)
	}

	_, _ = fmt.Fprintf(stdout, "Token:          %s\n", resp.Token)
	if resp.TokenID != "" {
		_, _ = fmt.Fprintf(stdout, "Token ID:       %s\n", resp.TokenID)
	}
	if resp.CAFingerprint != "" {
		_, _ = fmt.Fprintf(stdout, "CA Fingerprint: %s\n", resp.CAFingerprint)
	}
	if resp.CreatedByNode != "" {
		_, _ = fmt.Fprintf(stdout, "Issued By:      %s\n", resp.CreatedByNode)
	}
	if resp.BoundNodeID != "" {
		_, _ = fmt.Fprintf(stdout, "Bound Node ID:  %s\n", resp.BoundNodeID)
	}
	_, _ = fmt.Fprintf(stdout, "Expires At:     %s\n", resp.ExpiresAt.UTC().Format(time.RFC3339))
	return exitOK
}

func runClusterStatus(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("cluster status")
	target := bindClusterTargetFlags(fs)
	jsonOut := fs.Bool("json", false, "Format output as indented JSON")

	if code, handled := parseFlags(fs, args, stdout, stderr, printClusterStatusUsage); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		printClusterStatusUsage(stderr)
		return exitUsage
	}

	cl, err := target.newClient()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
	defer func() {
		_ = cl.Close()
	}()

	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	st, err := cl.Status(sigCtx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	if *jsonOut {
		return writeIndentedJSON(stdout, stderr, st)
	}

	execAddr := st.ExecAddr
	if execAddr == "" {
		execAddr = "-"
	}

	leaderSummary := "none"
	if st.LeaderID != "" {
		leaderSummary = st.LeaderID
		if st.LeaderAddr != "" {
			leaderSummary += " (" + st.LeaderAddr + ")"
		}
		if st.IsLeader {
			leaderSummary += " [self]"
		}
	}

	crlNum := st.CRLNumber
	if crlNum == "" {
		crlNum = "-"
	}

	_, _ = fmt.Fprintf(stdout, "Node ID:        %s\n", st.NodeID)
	_, _ = fmt.Fprintf(stdout, "Cluster Addr:   %s\n", st.ClusterAddr)
	_, _ = fmt.Fprintf(stdout, "Exec Addr:      %s\n", execAddr)
	_, _ = fmt.Fprintf(stdout, "Topology:       %s\n", st.Topology)
	_, _ = fmt.Fprintf(stdout, "Quorum State:   %s\n", st.QuorumState)
	_, _ = fmt.Fprintf(stdout, "Has Quorum:     %t\n", st.HasQuorum)
	_, _ = fmt.Fprintf(stdout, "Members:        %d/%d (quorum: %d)\n", st.AliveNodes, st.TotalNodes, st.QuorumRequired)
	_, _ = fmt.Fprintf(stdout, "Leader:         %s\n", leaderSummary)
	_, _ = fmt.Fprintf(stdout, "CA Signer:      %t\n", st.HasCAKey)
	_, _ = fmt.Fprintf(stdout, "CRL Number:     %s (revoked: %d)\n", crlNum, st.RevokedCerts)
	_, _ = fmt.Fprintf(stdout, "Policy Version: %d (%s)\n", st.Policy.Version, formatPolicyBrief(st.Policy))
	return exitOK
}

func runClusterPeers(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("cluster peers")
	target := bindClusterTargetFlags(fs)
	jsonOut := fs.Bool("json", false, "Format output as indented JSON")

	if code, handled := parseFlags(fs, args, stdout, stderr, printClusterPeersUsage); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		printClusterPeersUsage(stderr)
		return exitUsage
	}

	cl, err := target.newClient()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
	defer func() {
		_ = cl.Close()
	}()

	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	peers, err := cl.Peers(sigCtx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	if *jsonOut {
		return writeIndentedJSON(stdout, stderr, peers)
	}

	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NODE_ID\tSTATE\tROLE\tCLUSTER_ADDR\tEXEC_ADDR\tCRL_NUM\tPOLICY_VER\tCA_SIGNER\tLAST_SEEN")
	for _, p := range peers {
		role := "member"
		if p.IsLeader {
			role = "leader"
		}
		if p.IsSelf {
			role += ",self"
		}

		execAddr := p.ExecAddr
		if execAddr == "" {
			execAddr = "-"
		}
		crlNum := p.CRLNumber
		if crlNum == "" {
			crlNum = "-"
		}
		lastSeen := "-"
		if p.LastSeenUnix > 0 {
			lastSeen = time.Unix(p.LastSeenUnix, 0).UTC().Format(time.RFC3339)
		}

		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%t\t%s\n",
			p.NodeID,
			p.State,
			role,
			p.ClusterAddr,
			execAddr,
			crlNum,
			p.PolicyVersion,
			p.HasCAKey,
			lastSeen,
		)
	}
	_ = tw.Flush()
	return exitOK
}

func runClusterSync(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("cluster sync")
	target := bindClusterTargetFlags(fs)
	jsonOut := fs.Bool("json", false, "Format output as indented JSON")
	crlFile := fs.String("crl-file", "", "Signed crl.pem path to upload and broadcast")
	defaultTimeout := fs.String("default-timeout", "", "Cluster policy default command timeout (e.g. 45s, 2m, or 0 to reset)")
	maxTimeout := fs.String("max-timeout", "", "Cluster policy max command timeout (e.g. 120s, 5m, or 0 to reset)")
	defaultShell := fs.String("default-shell", "", "Cluster policy default shell (powershell, pwsh, cmd, sh, bash, or empty to reset)")
	enforceACL := fs.Bool("enforce-client-acl", false, "Enable cluster-wide client certificate ACL enforcement")
	disableACL := fs.Bool("disable-client-acl", false, "Disable cluster-wide client certificate ACL enforcement")
	var allowClients stringSliceFlag
	fs.Var(&allowClients, "allow-client", "Allowed client CommonName or serial hex (repeatable or comma-separated)")

	if code, handled := parseFlags(fs, args, stdout, stderr, printClusterSyncUsage); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		printClusterSyncUsage(stderr)
		return exitUsage
	}

	visited := visitedFlags(fs)
	if visited["enforce-client-acl"] && *enforceACL && visited["disable-client-acl"] && *disableACL {
		_, _ = fmt.Fprintln(stderr, "Error: --enforce-client-acl and --disable-client-acl cannot both be true")
		printClusterSyncUsage(stderr)
		return exitUsage
	}

	var parsedDefaultTimeoutSec int
	if visited["default-timeout"] {
		sec, err := parsePolicyTimeoutSeconds(*defaultTimeout)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: invalid --default-timeout: %v\n", err)
			return exitUsage
		}
		parsedDefaultTimeoutSec = sec
	}

	var parsedMaxTimeoutSec int
	if visited["max-timeout"] {
		sec, err := parsePolicyTimeoutSeconds(*maxTimeout)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: invalid --max-timeout: %v\n", err)
			return exitUsage
		}
		parsedMaxTimeoutSec = sec
	}

	var normalizedDefaultShell string
	if visited["default-shell"] {
		trimmedShell := strings.ToLower(strings.TrimSpace(*defaultShell))
		if trimmedShell != "" && !isSupportedPolicyShell(trimmedShell) {
			_, _ = fmt.Fprintf(stderr, "Error: invalid --default-shell %q (expected powershell, pwsh, cmd, sh, bash, or empty)\n", *defaultShell)
			return exitUsage
		}
		normalizedDefaultShell = trimmedShell
	}

	var syncReq cluster.SyncRequest
	if strings.TrimSpace(*crlFile) != "" {
		homeDir, _ := os.UserHomeDir()
		expandedCRL := config.ExpandPath(*crlFile, homeDir, "")
		crlBytes, err := os.ReadFile(expandedCRL)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: failed to read --crl-file %q: %v\n", expandedCRL, err)
			return exitError
		}
		syncReq.CRLPEM = string(crlBytes)
	}

	hasPolicyFlag := visited["default-timeout"] ||
		visited["max-timeout"] ||
		visited["default-shell"] ||
		visited["enforce-client-acl"] ||
		visited["disable-client-acl"] ||
		visited["allow-client"]

	cl, err := target.newClient()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
	defer func() {
		_ = cl.Close()
	}()

	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	if hasPolicyFlag {
		curStatus, statusErr := cl.Status(sigCtx)
		if statusErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: failed to query current cluster policy before update: %v\n", statusErr)
			return exitError
		}

		nextPol := curStatus.Policy
		if len(curStatus.Policy.AllowedClients) > 0 {
			nextPol.AllowedClients = append([]string(nil), curStatus.Policy.AllowedClients...)
		}
		nextPol.Version = curStatus.Policy.Version + 1
		nextPol.UpdatedAtUnix = time.Now().UTC().Unix()

		if visited["default-timeout"] {
			nextPol.DefaultTimeoutSeconds = parsedDefaultTimeoutSec
		}
		if visited["max-timeout"] {
			nextPol.MaxTimeoutSeconds = parsedMaxTimeoutSec
		}
		if nextPol.DefaultTimeoutSeconds > 0 && nextPol.MaxTimeoutSeconds > 0 && nextPol.DefaultTimeoutSeconds > nextPol.MaxTimeoutSeconds {
			_, _ = fmt.Fprintf(stderr, "Error: policy default_timeout_seconds (%ds) cannot exceed max_timeout_seconds (%ds)\n",
				nextPol.DefaultTimeoutSeconds, nextPol.MaxTimeoutSeconds)
			return exitUsage
		}
		if visited["default-shell"] {
			nextPol.DefaultShell = normalizedDefaultShell
		}
		if visited["enforce-client-acl"] {
			nextPol.EnforceClientACL = *enforceACL
		}
		if visited["disable-client-acl"] && *disableACL {
			nextPol.EnforceClientACL = false
		}
		if visited["allow-client"] {
			nextPol.AllowedClients = append([]string(nil), allowClients...)
		}

		syncReq.PolicyUpdate = &nextPol
	}

	res, err := cl.Sync(sigCtx, syncReq)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	if *jsonOut {
		return writeIndentedJSON(stdout, stderr, res)
	}

	crlNum := res.CRLNumber
	if crlNum == "" {
		crlNum = "-"
	}
	syncedSummary := "none"
	if len(res.SyncedPeers) > 0 {
		syncedSummary = strings.Join(res.SyncedPeers, ", ")
	}

	_, _ = fmt.Fprintf(stdout, "Node ID:        %s\n", res.NodeID)
	_, _ = fmt.Fprintf(stdout, "CRL Number:     %s (applied=%t, revoked=%d)\n", crlNum, res.CRLApplied, res.RevokedCerts)
	_, _ = fmt.Fprintf(stdout, "Policy Version: %d (updated=%t, %s)\n", res.PolicyVersion, res.PolicyUpdated, formatPolicyBrief(res.Policy))
	_, _ = fmt.Fprintf(stdout, "Synced Peers:   %d (%s)\n", len(res.SyncedPeers), syncedSummary)
	if len(res.FailedPeers) > 0 {
		failedKeys := make([]string, 0, len(res.FailedPeers))
		for k := range res.FailedPeers {
			failedKeys = append(failedKeys, k)
		}
		sort.Strings(failedKeys)
		_, _ = fmt.Fprintf(stdout, "Failed Peers:   %d\n", len(failedKeys))
		for _, peerID := range failedKeys {
			_, _ = fmt.Fprintf(stdout, "  - %s: %s\n", peerID, res.FailedPeers[peerID])
		}
	} else {
		_, _ = fmt.Fprintln(stdout, "Failed Peers:   0")
	}
	return exitOK
}

func visitedFlags(fs *flag.FlagSet) map[string]bool {
	visited := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})
	return visited
}

func parsePositiveDuration(raw string) (time.Duration, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, errors.New("duration cannot be empty")
	}
	if sec, convErr := strconv.ParseInt(trimmed, 10, 64); convErr == nil {
		if sec <= 0 {
			return 0, errors.New("duration must be strictly positive")
		}
		return time.Duration(sec) * time.Second, nil
	}
	dur, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0, err
	}
	if dur <= 0 {
		return 0, errors.New("duration must be strictly positive")
	}
	return dur, nil
}

func parsePolicyTimeoutSeconds(raw string) (int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "0" || trimmed == "0s" {
		return 0, nil
	}
	_, sec, err := config.ParseTimeout(trimmed)
	return sec, err
}

func isSupportedPolicyShell(name string) bool {
	switch name {
	case "powershell", "pwsh", "cmd", "sh", "bash":
		return true
	default:
		return false
	}
}

func formatPolicyBrief(p protocol.ExecutionPolicy) string {
	var parts []string
	if p.DefaultTimeoutSeconds > 0 {
		parts = append(parts, fmt.Sprintf("default_timeout=%ds", p.DefaultTimeoutSeconds))
	} else {
		parts = append(parts, fmt.Sprintf("default_timeout=%ds(default)", protocol.DefaultTimeoutSeconds))
	}
	if p.MaxTimeoutSeconds > 0 {
		parts = append(parts, fmt.Sprintf("max_timeout=%ds", p.MaxTimeoutSeconds))
	} else {
		parts = append(parts, fmt.Sprintf("max_timeout=%ds(default)", protocol.MaxTimeoutSeconds))
	}
	if p.DefaultShell != "" {
		parts = append(parts, "shell="+p.DefaultShell)
	}
	if p.EnforceClientACL {
		parts = append(parts, fmt.Sprintf("client_acl=enforced(%d)", len(p.AllowedClients)))
	} else {
		parts = append(parts, "client_acl=disabled")
	}
	return strings.Join(parts, ", ")
}

func writeIndentedJSON(stdout, stderr io.Writer, v any) int {
	encoded, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: failed to encode JSON output: %v\n", err)
		return exitError
	}
	_, _ = fmt.Fprintf(stdout, "%s\n", encoded)
	return exitOK
}

func printClusterUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge cluster <subcommand> [flags]

Subcommands:
  token-create  Mint a single-use Root-CA-pinned join token
  status        Inspect node quorum state, coordinator leadership, CRL, and policy
  peers         List cluster peer membership, reachability, and replication state
  sync          Trigger anti-entropy sync and optionally push CRL or ExecutionPolicy
`)
}

func printClusterTokenCreateUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge cluster token-create [flags]

Flags:
  --ttl <duration>         Token validity duration, e.g. 15m, 1h, 24h (default "1h")
  --node-id <id>           Restrict token to a specific joining node_id
  --quiet, -q              Print bare join token string only
  --json                   Print response as indented JSON
  --cluster-addr <addr>    Cluster control-plane host:port (default 127.0.0.1:8444)
  --host <name>            Named host profile from config.json
  --cert <path>            Client or server certificate PEM path
  --key <path>             Client or server private key PEM path
  --ca <path>              Root CA certificate PEM path
  --timeout <duration>     Request timeout (default 60s)
`)
}

func printClusterStatusUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge cluster status [flags]

Flags:
  --json                   Print status as indented JSON
  --cluster-addr <addr>    Cluster control-plane host:port (default 127.0.0.1:8444)
  --host <name>            Named host profile from config.json
  --cert <path>            Client or server certificate PEM path
  --key <path>             Client or server private key PEM path
  --ca <path>              Root CA certificate PEM path
  --timeout <duration>     Request timeout (default 60s)
`)
}

func printClusterPeersUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge cluster peers [flags]

Flags:
  --json                   Print peer roster as indented JSON
  --cluster-addr <addr>    Cluster control-plane host:port (default 127.0.0.1:8444)
  --host <name>            Named host profile from config.json
  --cert <path>            Client or server certificate PEM path
  --key <path>             Client or server private key PEM path
  --ca <path>              Root CA certificate PEM path
  --timeout <duration>     Request timeout (default 60s)
`)
}

func printClusterSyncUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge cluster sync [flags]

Flags:
  --crl-file <path>        Signed crl.pem file to upload and broadcast
  --default-timeout <dur>  Set cluster policy default command timeout (0 to reset)
  --max-timeout <dur>      Set cluster policy max command timeout (0 to reset)
  --default-shell <name>   Set cluster policy default shell (powershell, pwsh, cmd, sh, bash)
  --enforce-client-acl     Require client certificate CN or serial match in AllowedClients
  --disable-client-acl     Disable cluster client certificate ACL enforcement
  --allow-client <entry>   Allowed client CN or serial hex (repeatable or comma-separated)
  --json                   Print sync result as indented JSON
  --cluster-addr <addr>    Cluster control-plane host:port (default 127.0.0.1:8444)
  --host <name>            Named host profile from config.json
  --cert <path>            Client or server certificate PEM path
  --key <path>             Client or server private key PEM path
  --ca <path>              Root CA certificate PEM path
  --timeout <duration>     Request timeout (default 60s)
`)
}
