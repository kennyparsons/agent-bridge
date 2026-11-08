package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/kennyparsons/agent-bridge/cluster"
	"github.com/kennyparsons/agent-bridge/internal/acl"
	"github.com/kennyparsons/agent-bridge/internal/config"
	"github.com/kennyparsons/agent-bridge/internal/daemonlog"
	"github.com/kennyparsons/agent-bridge/internal/doctor"
	"github.com/kennyparsons/agent-bridge/internal/netbind"
	"github.com/kennyparsons/agent-bridge/internal/pki"
	"github.com/kennyparsons/agent-bridge/internal/protocol"
	"github.com/kennyparsons/agent-bridge/internal/runner"
	"github.com/kennyparsons/agent-bridge/internal/service"
)

var (
	newServiceManager      = service.NewManager
	spawnDetachedRestartFn = service.SpawnDetachedServiceRestart
)

func runService(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printServiceUsage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "install":
		return runServiceInstall(ctx, args[1:], stdin, stdout, stderr)
	case "uninstall":
		return runServiceUninstall(ctx, args[1:], stdout, stderr)
	case "start":
		return runServiceStart(ctx, args[1:], stdout, stderr)
	case "stop":
		return runServiceStop(ctx, args[1:], stdout, stderr)
	case "restart":
		return runServiceRestart(ctx, args[1:], stdout, stderr)
	case "status":
		return runServiceStatus(ctx, args[1:], stdout, stderr)
	case "logs":
		return runServiceLogs(ctx, args[1:], stdout, stderr)
	case "_detached-restart":
		return runServiceDetachedRestart(ctx, args[1:], stdout, stderr)
	case "help", "--help", "-help", "-h":
		printServiceUsage(stdout)
		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "Error: unknown service subcommand %q\n\n", args[0])
		printServiceUsage(stderr)
		return exitUsage
	}
}

func runServiceInstall(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("service install")
	name := fs.String("name", service.DefaultServiceName, "OS service name")
	dataDir := fs.String("data-dir", "", "Server node PKI and state directory")
	serviceCfgFlag := fs.String("service-config", "", "Path to server.json configuration file")
	fs.StringVar(serviceCfgFlag, "config", "", "Alias for --service-config")
	binaryPath := fs.String("binary", "", "Optional agent-bridge executable path override")

	var bindSpecsFlag stringSliceFlag
	fs.Var(&bindSpecsFlag, "bind", "Exec bind selector(s): IP, CIDR, 0.0.0.0, ::, all (repeatable or CSV)")
	port := fs.Int("port", protocol.DefaultPort, "TCP port for /ws/exec listener(s)")
	waitBind := fs.String("wait-bind", "60s", "Boot readiness wait timeout for virtual NICs")

	clusterFlag := fs.Bool("cluster", false, "Enable multi-node cluster control-plane engine")
	nodeID := fs.String("node-id", "", "Unique cluster node ID")
	var clusterBindFlag stringSliceFlag
	fs.Var(&clusterBindFlag, "cluster-bind", "Cluster TLS 1.3 bind selector(s), inline :port allowed (repeatable or CSV)")
	clusterAdvertise := fs.String("cluster-advertise", "", "Advertised cluster host:port")
	var seedFlag stringSliceFlag
	fs.Var(&seedFlag, "seed", "Cluster peer seed address(es) host:port (repeatable or CSV)")
	var joinFlag stringSliceFlag
	fs.Var(&joinFlag, "join", "Seed peer address(es) host:port to enroll against during install (repeatable or CSV)")
	joinToken := fs.String("join-token", "", "Single-use Root-CA-pinned join token (consumed in-process, never persisted)")
	joinTokenStdin := fs.Bool("join-token-stdin", false, "Read single-use join token from stdin")

	certPath := fs.String("cert", "", "Server or peer certificate PEM path")
	keyPath := fs.String("key", "", "Server or peer private key PEM path")
	caPath := fs.String("ca", "", "Root CA certificate PEM path")
	caKeyPath := fs.String("ca-key", "", "Optional Root CA private key PEM path")
	crlPath := fs.String("crl", "", "CRL PEM path")
	statePath := fs.String("cluster-state", "", "Optional cluster state JSON path")

	var sanIPsFlag stringSliceFlag
	var sanDNSFlag stringSliceFlag
	fs.Var(&sanIPsFlag, "san-ip", "Additional X.509 IP SAN(s) during CSR join (repeatable or CSV)")
	fs.Var(&sanDNSFlag, "san-dns", "Additional X.509 DNS SAN(s) during CSR join (repeatable or CSV)")
	noAutoSANs := fs.Bool("no-auto-sans", false, "Disable automatic active-NIC IP SAN discovery")

	shell := fs.String("shell", "", "Optional execution shell override (powershell, pwsh, cmd, sh, bash)")
	policy := fs.String("policy", "", "Optional ExecutionPolicy JSON file path")
	logFile := fs.String("log-file", "", "Rotating daemon log file path")

	configureFirewall := fs.Bool("configure-firewall", false, "Configure inbound Windows Firewall rules")
	var firewallSubnets stringSliceFlag
	fs.Var(&firewallSubnets, "firewall-subnets", "Allowed remote CIDR subnets for Windows Firewall rules")
	defenderExclusion := fs.Bool("defender-exclusion", false, "Register binary path as Microsoft Defender exclusion")
	noStart := fs.Bool("no-start", false, "Register OS service without starting it immediately")
	skipPreflight := fs.Bool("skip-preflight", false, "Skip pre-flight doctor checks")
	jsonOut := fs.Bool("json", false, "Format output as indented JSON")

	if code, handled := parseFlags(fs, args, stdout, stderr, printServiceInstallUsage); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		printServiceInstallUsage(stderr)
		return exitUsage
	}

	svcName, err := service.ValidateServiceName(*name)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitUsage
	}

	resolvedToken, err := resolveJoinTokenInput(*joinToken, *joinTokenStdin, stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		printServiceInstallUsage(stderr)
		return exitUsage
	}
	if resolvedToken != "" && len(joinFlag) == 0 {
		_, _ = fmt.Fprintln(stderr, "Error: --join-token requires --join <seed_ip:port>")
		printServiceInstallUsage(stderr)
		return exitUsage
	}

	waitDur, err := time.ParseDuration(strings.TrimSpace(*waitBind))
	if err != nil || waitDur < 0 {
		_, _ = fmt.Fprintf(stderr, "Error: invalid --wait-bind %q: expected non-negative duration (e.g. 60s)\n", *waitBind)
		return exitUsage
	}

	visited := visitedFlags(fs)
	homeDir, _ := os.UserHomeDir()
	defaults := service.DefaultPaths()

	cfgPath := defaults.ConfigPath
	if strings.TrimSpace(*serviceCfgFlag) != "" {
		cfgPath = config.ExpandPath(*serviceCfgFlag, homeDir, "")
	} else if strings.TrimSpace(*dataDir) != "" {
		expandedDD := config.ExpandPath(*dataDir, homeDir, "")
		// When a custom --data-dir is passed without --service-config, place server.json inside <data-dir>/server.json.
		if filepath.Clean(expandedDD) != filepath.Clean(defaults.DataDir) {
			cfgPath = filepath.Join(filepath.Clean(expandedDD), "server.json")
		}
	}

	// Start from existing server.json if upgrading in place, then overlay provided install flags.
	daemonCfg := &service.ServerDaemonConfig{}
	if existing, loadErr := service.LoadServerDaemonConfig(cfgPath); loadErr == nil && existing != nil {
		*daemonCfg = *existing
	}

	if strings.TrimSpace(*dataDir) != "" {
		daemonCfg.DataDir = config.ExpandPath(*dataDir, homeDir, "")
	} else if daemonCfg.DataDir == "" {
		daemonCfg.DataDir = defaults.DataDir
	}

	if strings.TrimSpace(*logFile) != "" {
		daemonCfg.LogPath = config.ExpandPath(*logFile, homeDir, "")
	} else if daemonCfg.LogPath == "" {
		daemonCfg.LogPath = defaults.LogPath
	}

	if visited["bind"] || len(bindSpecsFlag) > 0 {
		daemonCfg.BindSpecs = netbind.SplitTokens(bindSpecsFlag)
	}
	if len(daemonCfg.BindSpecs) == 0 {
		_, _ = fmt.Fprintln(stderr, "Error: missing required flag(s): --bind")
		printServiceInstallUsage(stderr)
		return exitUsage
	}

	if visited["port"] || daemonCfg.Port == 0 {
		daemonCfg.Port = *port
	}
	if _, err := netbind.ParseSpecs(daemonCfg.BindSpecs, daemonCfg.Port, false); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: invalid --bind specification: %v\n", err)
		return exitError
	}

	daemonCfg.WaitBind = waitDur.String()

	if visited["cluster"] {
		daemonCfg.ClusterEnabled = *clusterFlag
	}
	if visited["cluster-bind"] || len(clusterBindFlag) > 0 {
		daemonCfg.ClusterBindSpecs = netbind.SplitTokens(clusterBindFlag)
	}
	if visited["cluster-advertise"] {
		daemonCfg.ClusterAdvertise = strings.TrimSpace(*clusterAdvertise)
	}
	if visited["node-id"] {
		daemonCfg.NodeID = strings.TrimSpace(*nodeID)
	}
	if visited["cert"] {
		daemonCfg.CertPath = config.ExpandPath(*certPath, homeDir, "")
	}
	if visited["key"] {
		daemonCfg.KeyPath = config.ExpandPath(*keyPath, homeDir, "")
	}
	if visited["ca"] {
		daemonCfg.CAPath = config.ExpandPath(*caPath, homeDir, "")
	}
	if visited["ca-key"] {
		daemonCfg.CAKeyPath = config.ExpandPath(*caKeyPath, homeDir, "")
	}
	if visited["crl"] {
		daemonCfg.CRLPath = config.ExpandPath(*crlPath, homeDir, "")
	}
	if visited["cluster-state"] {
		daemonCfg.StatePath = config.ExpandPath(*statePath, homeDir, "")
	}
	if visited["shell"] {
		daemonCfg.Shell = strings.TrimSpace(*shell)
	}
	if visited["policy"] {
		daemonCfg.PolicyPath = config.ExpandPath(*policy, homeDir, "")
	}
	if visited["san-ip"] {
		daemonCfg.SANIPs = netbind.SplitTokens(sanIPsFlag)
	}
	if visited["san-dns"] {
		daemonCfg.SANDNS = netbind.SplitTokens(sanDNSFlag)
	}
	if visited["no-auto-sans"] {
		daemonCfg.NoAutoSANs = *noAutoSANs
	}

	var parsedSeeds []string
	if len(seedFlag) > 0 {
		seeds, seedErr := cluster.ParseSeedAddrs(seedFlag...)
		if seedErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", seedErr)
			return exitError
		}
		parsedSeeds = seeds
		daemonCfg.SeedPeers = seeds
	}

	var parsedJoinSeeds []string
	if len(joinFlag) > 0 {
		jSeeds, jErr := cluster.ParseSeedAddrs(joinFlag...)
		if jErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", jErr)
			return exitError
		}
		parsedJoinSeeds = jSeeds
	}

	if len(daemonCfg.ClusterBindSpecs) > 0 || len(parsedSeeds) > 0 || len(parsedJoinSeeds) > 0 || len(daemonCfg.SeedPeers) > 0 {
		daemonCfg.ClusterEnabled = true
	}
	if daemonCfg.ClusterEnabled && len(daemonCfg.ClusterBindSpecs) == 0 {
		daemonCfg.ClusterBindSpecs = append([]string(nil), daemonCfg.BindSpecs...)
	}

	clusterPort := config.DefaultClusterPort
	if len(daemonCfg.ClusterBindSpecs) > 0 {
		sels, parseErr := netbind.ParseSpecs(daemonCfg.ClusterBindSpecs, config.DefaultClusterPort, true)
		if parseErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: invalid --cluster-bind specification: %v\n", parseErr)
			return exitError
		}
		if len(sels) > 0 && sels[0].Port > 0 {
			clusterPort = sels[0].Port
		}
	}

	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	mgr := newServiceManager()
	daemonRunning := false
	if st, stErr := mgr.Status(sigCtx, svcName); stErr == nil && st != nil && st.Running {
		daemonRunning = true
	}

	if !*skipPreflight {
		allDiagSeeds := append([]string(nil), parsedJoinSeeds...)
		allDiagSeeds = append(allDiagSeeds, parsedSeeds...)
		docRep := doctor.Run(sigCtx, doctor.Options{
			Seeds:            allDiagSeeds,
			BindSpecs:        daemonCfg.BindSpecs,
			DefaultPort:      daemonCfg.Port,
			DaemonRunning:    daemonRunning,
			ClusterBindSpecs: daemonCfg.ClusterBindSpecs,
			ClusterPort:      clusterPort,
			DialTimeout:      5 * time.Second,
		})
		if len(parsedJoinSeeds) > 0 {
			for _, id := range []string{doctor.CheckIDRouteHairpin, doctor.CheckIDSeedReachability} {
				if chk, ok := docRep.FindCheck(id); ok && chk.Status == doctor.StatusFail {
					if chk.Remediation != "" {
						_, _ = fmt.Fprintf(stderr, "Error: pre-flight check %q failed: %s (remediation: %s)\n", id, chk.Summary, chk.Remediation)
					} else {
						_, _ = fmt.Fprintf(stderr, "Error: pre-flight check %q failed: %s\n", id, chk.Summary)
					}
					return exitError
				}
			}
		}
		if !daemonRunning {
			if chk, ok := docRep.FindCheck(doctor.CheckIDBindAvailability); ok && chk.Status == doctor.StatusFail {
				_, _ = fmt.Fprintf(stderr, "Error: pre-flight check %q failed: %s\n", doctor.CheckIDBindAvailability, chk.Summary)
				return exitError
			}
		}
	}

	if err := acl.LockdownServerDir(daemonCfg.DataDir); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: failed to lock down data directory %q: %v\n", daemonCfg.DataDir, err)
		return exitError
	}

	// Resolve PKI file paths inside DataDir when omitted.
	candCert, candKey := config.ResolveNodeCertPaths(daemonCfg.DataDir)
	if daemonCfg.CertPath == "" {
		daemonCfg.CertPath = candCert
	}
	if daemonCfg.KeyPath == "" {
		daemonCfg.KeyPath = candKey
	}
	if daemonCfg.CAPath == "" {
		daemonCfg.CAPath = filepath.Join(daemonCfg.DataDir, pki.CACertFilename)
	}
	if daemonCfg.CRLPath == "" {
		daemonCfg.CRLPath = filepath.Join(daemonCfg.DataDir, pki.CRLFilename)
	}

	effectiveNodeID := daemonCfg.NodeID
	if effectiveNodeID == "" && fileExistsRegular(daemonCfg.CertPath) {
		if leaf, certErr := pki.LoadCertificate(daemonCfg.CertPath); certErr == nil {
			effectiveNodeID = strings.TrimSpace(leaf.Subject.CommonName)
		}
	}
	if effectiveNodeID == "" {
		if host, hErr := os.Hostname(); hErr == nil {
			effectiveNodeID = strings.TrimSpace(host)
		}
	}
	if effectiveNodeID == "" {
		effectiveNodeID = "node-1"
	}
	if daemonCfg.StatePath == "" && daemonCfg.ClusterEnabled {
		daemonCfg.StatePath = cluster.DefaultStatePath(daemonCfg.CRLPath, effectiveNodeID)
	}

	// SECURITY INVARIANT: Execute BootstrapJoin in-process BEFORE saving server.json so single-use
	// join tokens never touch server.json on disk.
	if len(parsedJoinSeeds) > 0 {
		alreadyBootstrapped := fileExistsRegular(daemonCfg.StatePath) &&
			fileExistsRegular(daemonCfg.CertPath) &&
			fileExistsRegular(daemonCfg.KeyPath) &&
			fileExistsRegular(daemonCfg.CAPath) &&
			fileExistsRegular(daemonCfg.CRLPath)

		if !alreadyBootstrapped && resolvedToken == "" {
			_, _ = fmt.Fprintln(stderr, "Error: missing required flag(s): --join-token (required when enrolling node during service install)")
			printServiceInstallUsage(stderr)
			return exitUsage
		}

		execSpecAddrs := buildExecBindSpecAddrs(daemonCfg.BindSpecs, nil, daemonCfg.Port)
		joinRes, joinErr := cluster.BootstrapJoin(sigCtx, cluster.BootstrapJoinOptions{
			JoinAddrs:                parsedJoinSeeds,
			JoinToken:                resolvedToken,
			NodeID:                   effectiveNodeID,
			ClusterBindAddrs:         daemonCfg.ClusterBindSpecs,
			AdvertiseAddr:            daemonCfg.ClusterAdvertise,
			ExecBindAddrs:            execSpecAddrs,
			CertPath:                 daemonCfg.CertPath,
			KeyPath:                  daemonCfg.KeyPath,
			CAPath:                   daemonCfg.CAPath,
			CRLPath:                  daemonCfg.CRLPath,
			StatePath:                daemonCfg.StatePath,
			ExtraIPs:                 daemonCfg.SANIPs,
			ExtraDNSNames:            daemonCfg.SANDNS,
			DisableAutoInterfaceSANs: daemonCfg.NoAutoSANs,
		})
		if joinErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cluster enrollment failed: %v\n", joinErr)
			return exitError
		}
		if joinRes.NodeID != "" {
			daemonCfg.NodeID = joinRes.NodeID
		}

		var collectedSeeds []string
		collectedSeeds = append(collectedSeeds, parsedJoinSeeds...)
		collectedSeeds = append(collectedSeeds, joinRes.SeedAddrs...)
		if joinRes.SeedAddr != "" {
			collectedSeeds = append(collectedSeeds, joinRes.SeedAddr)
		}
		for _, p := range joinRes.Peers {
			if p.NodeID != daemonCfg.NodeID && strings.TrimSpace(p.ClusterAddr) != "" {
				collectedSeeds = append(collectedSeeds, p.ClusterAddr)
			}
		}
		if deduped, dErr := cluster.ParseSeedAddrs(collectedSeeds...); dErr == nil {
			daemonCfg.SeedPeers = deduped
		}
		// Clear JoinAddr so server.json relies strictly on bootstrapped certificates + SeedPeers.
		daemonCfg.JoinAddr = ""
		daemonCfg.ClusterEnabled = true
	}

	if err := acl.LockdownServerDir(daemonCfg.DataDir); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: failed to lock down data directory %q: %v\n", daemonCfg.DataDir, err)
		return exitError
	}
	if fileExistsRegular(daemonCfg.KeyPath) {
		_ = acl.LockdownPrivateFile(daemonCfg.KeyPath)
	}
	if err := service.SaveServerDaemonConfig(cfgPath, daemonCfg); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
	if err := acl.LockdownPrivateFile(cfgPath); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	installClusterPort := 0
	if daemonCfg.ClusterEnabled {
		installClusterPort = clusterPort
	}

	var nonWinWarnings []string
	if runtime.GOOS != "windows" {
		if *configureFirewall {
			if _, fwErr := service.ConfigureWindowsFirewall(sigCtx, strings.TrimSpace(*binaryPath), daemonCfg.Port, installClusterPort, firewallSubnets); fwErr != nil {
				nonWinWarnings = append(nonWinWarnings, fwErr.Error())
			}
		}
		if *defenderExclusion {
			if defErr := service.AddWindowsDefenderExclusion(sigCtx, strings.TrimSpace(*binaryPath)); defErr != nil {
				nonWinWarnings = append(nonWinWarnings, defErr.Error())
			}
		}
	}

	res, err := mgr.Install(sigCtx, service.InstallOptions{
		Name:                   svcName,
		BinaryPath:             strings.TrimSpace(*binaryPath),
		ConfigPath:             cfgPath,
		Config:                 daemonCfg,
		StartNow:               !*noStart,
		ConfigureFirewall:      *configureFirewall,
		FirewallAllowedSubnets: firewallSubnets,
		ExecPort:               daemonCfg.Port,
		ClusterPort:            installClusterPort,
		DefenderExclusion:      *defenderExclusion,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
	res.Warnings = append(res.Warnings, nonWinWarnings...)

	if *jsonOut {
		return writeIndentedJSON(stdout, stderr, res)
	}

	_, _ = fmt.Fprintf(stdout, "Service:        %s (%s)\n", res.Name, res.ServiceType)
	_, _ = fmt.Fprintf(stdout, "Binary:         %s\n", res.BinaryPath)
	_, _ = fmt.Fprintf(stdout, "Config:         %s\n", res.ConfigPath)
	if res.LogPath != "" {
		_, _ = fmt.Fprintf(stdout, "Log File:       %s\n", res.LogPath)
	}
	if res.UnitPath != "" {
		_, _ = fmt.Fprintf(stdout, "Unit File:      %s\n", res.UnitPath)
	}
	_, _ = fmt.Fprintf(stdout, "Started:        %t\n", res.Started)
	if res.MigratedScheduledTask {
		_, _ = fmt.Fprintln(stdout, "Migrated Task:  removed legacy \\AgentBridge-Server scheduled task")
	}
	if res.FirewallConfigured {
		_, _ = fmt.Fprintf(stdout, "Firewall Rules: %s\n", strings.Join(res.FirewallRules, ", "))
	}
	if res.DefenderExcluded {
		_, _ = fmt.Fprintln(stdout, "Defender:       exclusion configured")
	}
	for _, w := range res.Warnings {
		_, _ = fmt.Fprintf(stdout, "Warning:        %s\n", w)
	}
	return exitOK
}

type serviceUninstallOutput struct {
	Name          string `json:"name"`
	Uninstalled   bool   `json:"uninstalled"`
	PurgedConfig  bool   `json:"purged_config,omitempty"`
	PurgedCfgPath string `json:"purged_config_path,omitempty"`
}

func runServiceUninstall(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("service uninstall")
	name := fs.String("name", service.DefaultServiceName, "OS service name")
	purgeConfig := fs.Bool("purge-config", false, "Delete server.json configuration file after uninstalling service")
	dataDir := fs.String("data-dir", "", "Optional server data directory")
	serviceCfgFlag := fs.String("service-config", "", "Optional server.json path")
	fs.StringVar(serviceCfgFlag, "config", "", "Alias for --service-config")
	jsonOut := fs.Bool("json", false, "Format output as indented JSON")

	if code, handled := parseFlags(fs, args, stdout, stderr, printServiceUninstallUsage); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		printServiceUninstallUsage(stderr)
		return exitUsage
	}

	svcName, err := service.ValidateServiceName(*name)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitUsage
	}

	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	mgr := newServiceManager()
	var discoveredCfgPath string
	if st, stErr := mgr.Status(sigCtx, svcName); stErr == nil && st != nil && st.ConfigPath != "" {
		discoveredCfgPath = st.ConfigPath
	}

	if err := mgr.Uninstall(sigCtx, svcName); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	out := serviceUninstallOutput{
		Name:        svcName,
		Uninstalled: true,
	}
	if *purgeConfig {
		homeDir, _ := os.UserHomeDir()
		cfgPath := resolveServiceConfigCandidate(*serviceCfgFlag, *dataDir, discoveredCfgPath, homeDir)
		if cfgPath != "" && fileExistsRegular(cfgPath) {
			if rmErr := os.Remove(cfgPath); rmErr != nil {
				_, _ = fmt.Fprintf(stderr, "Error: uninstalled service %q, failed to remove %q: %v\n", svcName, cfgPath, rmErr)
				return exitError
			}
			out.PurgedConfig = true
			out.PurgedCfgPath = cfgPath
		}
	}

	if *jsonOut {
		return writeIndentedJSON(stdout, stderr, out)
	}
	_, _ = fmt.Fprintf(stdout, "Service %q uninstalled.\n", svcName)
	if out.PurgedConfig {
		_, _ = fmt.Fprintf(stdout, "Removed config: %s\n", out.PurgedCfgPath)
	}
	return exitOK
}

func runServiceStart(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runSimpleServiceLifecycle(ctx, "start", args, stdout, stderr, func(c context.Context, mgr service.Manager, name string) error {
		return mgr.Start(c, name)
	})
}

func runServiceStop(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runSimpleServiceLifecycle(ctx, "stop", args, stdout, stderr, func(c context.Context, mgr service.Manager, name string) error {
		return mgr.Stop(c, name)
	})
}

func runSimpleServiceLifecycle(
	ctx context.Context,
	action string,
	args []string,
	stdout, stderr io.Writer,
	fn func(context.Context, service.Manager, string) error,
) int {
	fs := newFlagSet("service " + action)
	name := fs.String("name", service.DefaultServiceName, "OS service name")
	jsonOut := fs.Bool("json", false, "Format output as indented JSON")

	usageFn := func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "Usage: agent-bridge service %s [--name <name>] [--json]\n", action)
	}
	if code, handled := parseFlags(fs, args, stdout, stderr, usageFn); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		usageFn(stderr)
		return exitUsage
	}

	svcName, err := service.ValidateServiceName(*name)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitUsage
	}

	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	mgr := newServiceManager()
	if err := fn(sigCtx, mgr, svcName); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	st, _ := mgr.Status(sigCtx, svcName)
	if *jsonOut {
		if st != nil {
			return writeIndentedJSON(stdout, stderr, st)
		}
		return writeIndentedJSON(stdout, stderr, map[string]any{"name": svcName, "action": action, "ok": true})
	}
	if st != nil {
		_, _ = fmt.Fprintf(stdout, "Service %q %s complete (state=%s).\n", svcName, action, st.State)
	} else {
		_, _ = fmt.Fprintf(stdout, "Service %q %s complete.\n", svcName, action)
	}
	return exitOK
}

type serviceRestartOutput struct {
	Name     string                 `json:"name"`
	Detached bool                   `json:"detached"`
	Status   *service.ServiceStatus `json:"status,omitempty"`
}

func runServiceRestart(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("service restart")
	name := fs.String("name", service.DefaultServiceName, "OS service name")
	detach := fs.Bool("detach", false, "Schedule detached background restart (auto-enabled inside exec sessions)")
	jsonOut := fs.Bool("json", false, "Format output as indented JSON")

	usageFn := func(w io.Writer) {
		_, _ = fmt.Fprint(w, `Usage: agent-bridge service restart [--name <name>] [--detach] [--json]

Flags:
  --name <name>    OS service name (default "agent-bridge")
  --detach         Spawn detached restart helper (automatic when AGENT_BRIDGE_IN_EXEC=1)
  --json           Format output as indented JSON
`)
	}
	if code, handled := parseFlags(fs, args, stdout, stderr, usageFn); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		usageFn(stderr)
		return exitUsage
	}

	svcName, err := service.ValidateServiceName(*name)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitUsage
	}

	inExec := strings.TrimSpace(os.Getenv(runner.EnvInExec)) == "1"
	if *detach || inExec {
		if err := spawnDetachedRestartFn("", svcName, "", 500*time.Millisecond); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return exitError
		}
		if *jsonOut {
			return writeIndentedJSON(stdout, stderr, serviceRestartOutput{
				Name:     svcName,
				Detached: true,
			})
		}
		_, _ = fmt.Fprintf(stdout, "Scheduled detached restart for service %q.\n", svcName)
		return exitOK
	}

	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	mgr := newServiceManager()
	if err := mgr.Restart(sigCtx, svcName); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
	st, _ := mgr.Status(sigCtx, svcName)
	if *jsonOut {
		return writeIndentedJSON(stdout, stderr, serviceRestartOutput{
			Name:     svcName,
			Detached: false,
			Status:   st,
		})
	}
	if st != nil {
		_, _ = fmt.Fprintf(stdout, "Service %q restarted (state=%s).\n", svcName, st.State)
	} else {
		_, _ = fmt.Fprintf(stdout, "Service %q restarted.\n", svcName)
	}
	return exitOK
}

func runServiceStatus(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("service status")
	name := fs.String("name", service.DefaultServiceName, "OS service name")
	dataDir := fs.String("data-dir", "", "Optional server data directory")
	serviceCfgFlag := fs.String("service-config", "", "Optional server.json path")
	fs.StringVar(serviceCfgFlag, "config", "", "Alias for --service-config")
	jsonOut := fs.Bool("json", false, "Format output as indented JSON")

	usageFn := func(w io.Writer) {
		_, _ = fmt.Fprint(w, `Usage: agent-bridge service status [--name <name>] [--data-dir <dir>] [--json]

Flags:
  --name <name>             OS service name (default "agent-bridge")
  --data-dir <path>         Optional server data directory
  --service-config <path>   Optional server.json path
  --json                    Format status as indented JSON
`)
	}
	if code, handled := parseFlags(fs, args, stdout, stderr, usageFn); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		usageFn(stderr)
		return exitUsage
	}

	svcName, err := service.ValidateServiceName(*name)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitUsage
	}

	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	mgr := newServiceManager()
	st, err := mgr.Status(sigCtx, svcName)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	homeDir, _ := os.UserHomeDir()
	candCfg := resolveServiceConfigCandidate(*serviceCfgFlag, *dataDir, st.ConfigPath, homeDir)
	if st.ConfigPath == "" && candCfg != "" && fileExistsRegular(candCfg) {
		st.ConfigPath = candCfg
	}
	if st.LogPath == "" && st.ConfigPath != "" {
		if loaded, loadErr := service.LoadServerDaemonConfig(st.ConfigPath); loadErr == nil && loaded != nil && loaded.LogPath != "" {
			st.LogPath = loaded.LogPath
		}
	}

	if *jsonOut {
		return writeIndentedJSON(stdout, stderr, st)
	}

	_, _ = fmt.Fprintf(stdout, "Name:         %s\n", st.Name)
	_, _ = fmt.Fprintf(stdout, "Service Type: %s\n", st.ServiceType)
	_, _ = fmt.Fprintf(stdout, "Installed:    %t\n", st.Installed)
	_, _ = fmt.Fprintf(stdout, "Running:      %t\n", st.Running)
	_, _ = fmt.Fprintf(stdout, "State:        %s\n", st.State)
	if st.PID > 0 {
		_, _ = fmt.Fprintf(stdout, "PID:          %d\n", st.PID)
	}
	if st.BinaryPath != "" {
		_, _ = fmt.Fprintf(stdout, "Binary:       %s\n", st.BinaryPath)
	}
	if st.ConfigPath != "" {
		_, _ = fmt.Fprintf(stdout, "Config:       %s\n", st.ConfigPath)
	}
	if st.LogPath != "" {
		_, _ = fmt.Fprintf(stdout, "Log File:     %s\n", st.LogPath)
	}
	if st.UnitPath != "" {
		_, _ = fmt.Fprintf(stdout, "Unit File:    %s\n", st.UnitPath)
	}
	return exitOK
}

func runServiceLogs(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("service logs")
	dataDir := fs.String("data-dir", "", "Optional server data directory")
	serviceCfgFlag := fs.String("service-config", "", "Optional server.json path")
	fs.StringVar(serviceCfgFlag, "config", "", "Alias for --service-config")
	logFile := fs.String("log-file", "", "Explicit daemon log file path")
	lines := fs.Int("lines", 100, "Number of trailing log lines to print")
	var follow bool
	fs.BoolVar(&follow, "follow", false, "Stream newly appended log lines continuously")
	fs.BoolVar(&follow, "f", false, "Stream newly appended log lines continuously (shorthand)")

	usageFn := func(w io.Writer) {
		_, _ = fmt.Fprint(w, `Usage: agent-bridge service logs [--log-file <path>] [--data-dir <dir>] [--lines 100] [--follow]

Flags:
  --log-file <path>         Explicit rotating log file path
  --data-dir <path>         Server data directory
  --service-config <path>   Optional server.json path
  --lines <n>               Number of trailing lines to display (default 100)
  --follow, -f              Stream appended lines across log rotations until interrupted
`)
	}
	if code, handled := parseFlags(fs, args, stdout, stderr, usageFn); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		usageFn(stderr)
		return exitUsage
	}
	if *lines < 0 {
		_, _ = fmt.Fprintln(stderr, "Error: --lines must be non-negative")
		return exitUsage
	}

	homeDir, _ := os.UserHomeDir()
	resolvedLog := ""
	if strings.TrimSpace(*logFile) != "" {
		resolvedLog = config.ExpandPath(*logFile, homeDir, "")
	} else {
		candCfg := resolveServiceConfigCandidate(*serviceCfgFlag, *dataDir, "", homeDir)
		if candCfg != "" && fileExistsRegular(candCfg) {
			if loaded, err := service.LoadServerDaemonConfig(candCfg); err == nil && loaded != nil && strings.TrimSpace(loaded.LogPath) != "" {
				resolvedLog = config.ExpandPath(loaded.LogPath, homeDir, filepath.Dir(candCfg))
			}
		}
		if resolvedLog == "" {
			resolvedLog = service.DefaultPaths().LogPath
		}
	}

	if follow {
		sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stopSignals()
		if err := daemonlog.Follow(sigCtx, resolvedLog, *lines, stdout); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return exitError
		}
		return exitOK
	}

	tailed, err := daemonlog.TailLines(resolvedLog, *lines)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
	for _, line := range tailed {
		_, _ = fmt.Fprintln(stdout, line)
	}
	return exitOK
}

func runServiceDetachedRestart(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("service _detached-restart")
	name := fs.String("name", service.DefaultServiceName, "OS service name")
	delayStr := fs.String("delay", "500ms", "Delay before restarting service")
	rollbackBin := fs.String("rollback-bin", "", "Optional previous binary path for automatic rollback")
	targetBin := fs.String("target-bin", "", "Optional target binary path")

	usageFn := func(w io.Writer) {
		_, _ = fmt.Fprintln(w, "Usage: agent-bridge service _detached-restart --name <name> [--delay 500ms] [--rollback-bin <path>]")
	}
	if code, handled := parseFlags(fs, args, stdout, stderr, usageFn); handled {
		return code
	}

	delay, err := time.ParseDuration(strings.TrimSpace(*delayStr))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: invalid --delay %q: %v\n", *delayStr, err)
		return exitUsage
	}

	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	err = service.ExecuteDetachedRestart(sigCtx, service.DetachedRestartOptions{
		ServiceName: *name,
		Delay:       delay,
		RollbackBin: *rollbackBin,
		TargetBin:   *targetBin,
		Manager:     newServiceManager(),
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
	return exitOK
}

func resolveServiceConfigCandidate(serviceCfgFlag, dataDirFlag, mgrCfgPath, homeDir string) string {
	if strings.TrimSpace(serviceCfgFlag) != "" {
		return config.ExpandPath(serviceCfgFlag, homeDir, "")
	}
	if strings.TrimSpace(mgrCfgPath) != "" {
		return mgrCfgPath
	}
	if strings.TrimSpace(dataDirFlag) != "" {
		expandedDD := config.ExpandPath(dataDirFlag, homeDir, "")
		inDir := filepath.Join(expandedDD, "server.json")
		if fileExistsRegular(inDir) {
			return inDir
		}
		parentCfg := filepath.Join(filepath.Dir(filepath.Clean(expandedDD)), "server.json")
		if fileExistsRegular(parentCfg) {
			return parentCfg
		}
	}
	return service.DefaultPaths().ConfigPath
}

func printServiceUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge service <subcommand> [flags]

Subcommands:
  install       Enroll node (optional), write server.json, lock down ACLs, and install OS service
  uninstall     Stop and remove OS service (optional --purge-config)
  start         Start installed OS service
  stop          Stop running OS service
  restart       Restart OS service (automatically detaches inside exec sessions)
  status        Inspect OS service installation, state, PID, and paths
  logs          Read or follow rotating daemon log file
`)
}

func printServiceInstallUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `Usage: agent-bridge service install --bind <spec> [flags]

Service & Listener Flags:
  --name <name>                 OS service name (default %q)
  --data-dir <path>             Server PKI and state directory
  --service-config <path>       Custom server.json path
  --bind <spec>                 Bind IP, CIDR, 0.0.0.0, ::, or all (repeatable or CSV)
  --port <int>                  WebSocket mTLS TCP port (default %d)
  --wait-bind <duration>        Boot readiness wait timeout for virtual NICs (default "60s")
  --shell <name>                Optional execution shell override
  --policy <path>               Optional ExecutionPolicy JSON file path
  --log-file <path>             Rotating daemon log file path

Cluster & PKI Flags:
  --cluster                     Enable cluster TLS 1.3 control-plane engine
  --node-id <id>                Unique cluster node ID
  --cluster-bind <spec>         Cluster bind selector(s), inline :port allowed (repeatable or CSV)
  --cluster-advertise <ip:port> Advertised cluster host:port
  --seed <peer1:port,...>       Cluster peer seed address(es) (repeatable or CSV)
  --join <seed1:port,...>       Enroll node in-process during install (repeatable or CSV)
  --join-token <token>          Single-use join token (never persisted to server.json)
  --join-token-stdin            Read single-use join token from stdin
  --san-ip <ip1,ip2>            Extra X.509 IP SANs during CSR join (repeatable or CSV)
  --san-dns <dns1,dns2>         Extra X.509 DNS SANs during CSR join (repeatable or CSV)
  --no-auto-sans                Disable automatic active-NIC IP SAN discovery
  --cert <path>                 Server or peer certificate PEM path
  --key <path>                  Server or peer private key PEM path
  --ca <path>                   Root CA certificate PEM path
  --ca-key <path>               Root CA private key PEM path
  --crl <path>                  CRL PEM path

OS Hardening & Output Flags:
  --configure-firewall          Configure inbound Windows Firewall rules
  --firewall-subnets <cidrs>    Allowed remote subnets for Windows Firewall rules
  --defender-exclusion          Register binary as Microsoft Defender exclusion
  --no-start                    Install service without starting immediately
  --skip-preflight              Skip pre-flight routing/bind/seed checks
  --json                        Format output as indented JSON
`, service.DefaultServiceName, protocol.DefaultPort)
}

func printServiceUninstallUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `Usage: agent-bridge service uninstall [flags]

Flags:
  --name <name>             OS service name (default %q)
  --purge-config            Remove server.json configuration file
  --data-dir <path>         Optional server data directory
  --service-config <path>   Optional server.json path
  --json                    Format output as indented JSON
`, service.DefaultServiceName)
}
