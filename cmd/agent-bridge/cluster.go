package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/kennyparsons/agent-bridge/cluster"
	"github.com/kennyparsons/agent-bridge/internal/acl"
	"github.com/kennyparsons/agent-bridge/internal/config"
	"github.com/kennyparsons/agent-bridge/internal/netbind"
	"github.com/kennyparsons/agent-bridge/internal/pki"
	"github.com/kennyparsons/agent-bridge/internal/protocol"
	"github.com/kennyparsons/agent-bridge/internal/runner"
	"github.com/kennyparsons/agent-bridge/internal/service"
)

const defaultCLITokenTTL = "1h"

type clusterTargetFlags struct {
	clusterAddr   *string
	host          *string
	certPath      *string
	keyPath       *string
	caPath        *string
	clientCfgPath *string
	dataDir       *string
	serviceCfg    *string
	timeout       *string
}

func bindClusterTargetFlags(fs *flag.FlagSet) clusterTargetFlags {
	return clusterTargetFlags{
		clusterAddr:   fs.String("cluster-addr", "", "Target cluster control-plane host:port (default 127.0.0.1:8444)"),
		host:          fs.String("host", "", "Named host profile from config.json"),
		certPath:      fs.String("cert", "", "Client, server, or peer certificate PEM path"),
		keyPath:       fs.String("key", "", "Client, server, or peer private key PEM path"),
		caPath:        fs.String("ca", "", "Root CA certificate PEM path"),
		clientCfgPath: fs.String("config", "", "Client config.json path override"),
		dataDir:       fs.String("data-dir", "", "Server node PKI/state directory override"),
		serviceCfg:    fs.String("service-config", "", "Server server.json path override"),
		timeout:       fs.String("timeout", "", "Control-plane request timeout (e.g. 30s, 2m)"),
	}
}

func (f clusterTargetFlags) resolveConfig() (*config.ResolvedClusterConfig, error) {
	homeDir, _ := os.UserHomeDir()
	overrides := config.ClusterFlagOverrides{
		Host:        strings.TrimSpace(*f.host),
		ClusterAddr: strings.TrimSpace(*f.clusterAddr),
		CertPath:    strings.TrimSpace(*f.certPath),
		KeyPath:     strings.TrimSpace(*f.keyPath),
		CAPath:      strings.TrimSpace(*f.caPath),
		Timeout:     strings.TrimSpace(*f.timeout),
	}

	var opts config.ResolveOptions
	if strings.TrimSpace(*f.clientCfgPath) != "" {
		opts.GlobalConfigPath = config.ExpandPath(*f.clientCfgPath, homeDir, "")
	}
	if strings.TrimSpace(*f.dataDir) != "" {
		opts.ServerDataDir = config.ExpandPath(*f.dataDir, homeDir, "")
	}
	if strings.TrimSpace(*f.serviceCfg) != "" {
		opts.ServerConfigPath = config.ExpandPath(*f.serviceCfg, homeDir, "")
	}

	// When --data-dir or --service-config is explicitly passed, promote discovered server-local
	// credentials and port into explicit overrides so they win even on workstations with ~/.config/agent-bridge/config.json.
	if opts.ServerDataDir != "" || opts.ServerConfigPath != "" {
		applyExplicitServerTargetFallback(&overrides, opts.ServerDataDir, opts.ServerConfigPath, homeDir)
	}

	return config.ResolveClusterConfigWithOptions(overrides, opts)
}

func applyExplicitServerTargetFallback(overrides *config.ClusterFlagOverrides, dataDir, serviceCfgPath, homeDir string) {
	srvCfg := serviceCfgPath
	if srvCfg == "" && dataDir != "" {
		inDir := filepath.Join(dataDir, "server.json")
		parentCfg := filepath.Join(filepath.Dir(filepath.Clean(dataDir)), "server.json")
		if fileExistsRegular(inDir) {
			srvCfg = inDir
		} else if fileExistsRegular(parentCfg) {
			srvCfg = parentCfg
		}
	}

	clusterPort := config.DefaultClusterPort
	var concreteLoopbackAddr string
	effectiveDataDir := dataDir

	if srvCfg != "" && fileExistsRegular(srvCfg) {
		if loaded, err := service.LoadServerDaemonConfig(srvCfg); err == nil && loaded != nil {
			baseDir := filepath.Dir(srvCfg)
			if effectiveDataDir == "" && strings.TrimSpace(loaded.DataDir) != "" {
				effectiveDataDir = config.ExpandPath(loaded.DataDir, homeDir, baseDir)
			}
			if overrides.CertPath == "" && strings.TrimSpace(loaded.CertPath) != "" {
				cand := config.ExpandPath(loaded.CertPath, homeDir, baseDir)
				if fileExistsRegular(cand) {
					overrides.CertPath = cand
				}
			}
			if overrides.KeyPath == "" && strings.TrimSpace(loaded.KeyPath) != "" {
				cand := config.ExpandPath(loaded.KeyPath, homeDir, baseDir)
				if fileExistsRegular(cand) {
					overrides.KeyPath = cand
				}
			}
			if overrides.CAPath == "" && strings.TrimSpace(loaded.CAPath) != "" {
				cand := config.ExpandPath(loaded.CAPath, homeDir, baseDir)
				if fileExistsRegular(cand) {
					overrides.CAPath = cand
				}
			}
			if sels, pErr := netbind.ParseSpecs(loaded.ClusterBindSpecs, config.DefaultClusterPort, true); pErr == nil && len(sels) > 0 {
				if sels[0].Port > 0 {
					clusterPort = sels[0].Port
				}
				for _, sel := range sels {
					if sel.Kind == netbind.SelectorIP && sel.IP != nil && sel.IP.IsLoopback() && sel.Port > 0 {
						concreteLoopbackAddr = net.JoinHostPort(sel.IP.String(), strconv.Itoa(sel.Port))
						break
					}
				}
			} else if _, portStr, spErr := net.SplitHostPort(strings.TrimSpace(loaded.ClusterAdvertise)); spErr == nil {
				if p, cErr := strconv.Atoi(portStr); cErr == nil && p > 0 {
					clusterPort = p
				}
			}
		}
	}

	if effectiveDataDir != "" {
		if overrides.CertPath == "" || overrides.KeyPath == "" {
			candCert, candKey := config.ResolveNodeCertPaths(effectiveDataDir)
			if overrides.CertPath == "" && fileExistsRegular(candCert) {
				overrides.CertPath = candCert
			}
			if overrides.KeyPath == "" && fileExistsRegular(candKey) {
				overrides.KeyPath = candKey
			}
		}
		if overrides.CAPath == "" {
			candCA := filepath.Join(effectiveDataDir, pki.CACertFilename)
			if fileExistsRegular(candCA) {
				overrides.CAPath = candCA
			}
		}
		if concreteLoopbackAddr == "" && clusterPort == config.DefaultClusterPort {
			if p := inferLocalClusterPortFromState(effectiveDataDir); p > 0 {
				clusterPort = p
			}
		}
	}

	if overrides.ClusterAddr == "" && overrides.Host == "" {
		if concreteLoopbackAddr != "" {
			overrides.ClusterAddr = concreteLoopbackAddr
		} else {
			overrides.ClusterAddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(clusterPort))
		}
	}
}

func inferLocalClusterPortFromState(dataDir string) int {
	matches, err := filepath.Glob(filepath.Join(dataDir, "cluster-state-*.json"))
	if err != nil || len(matches) == 0 {
		single := filepath.Join(dataDir, "cluster-state.json")
		if fileExistsRegular(single) {
			matches = []string{single}
		}
	}
	type stateMinimal struct {
		NodeID string             `json:"node_id"`
		Peers  []cluster.PeerInfo `json:"peers"`
	}
	for _, m := range matches {
		raw, rErr := os.ReadFile(m)
		if rErr != nil {
			continue
		}
		var st stateMinimal
		if json.Unmarshal(raw, &st) != nil {
			continue
		}
		for _, p := range st.Peers {
			if p.NodeID == st.NodeID && strings.TrimSpace(p.ClusterAddr) != "" {
				if _, portStr, spErr := net.SplitHostPort(strings.TrimSpace(p.ClusterAddr)); spErr == nil {
					if portNum, cErr := strconv.Atoi(portStr); cErr == nil && portNum > 0 {
						return portNum
					}
				}
			}
		}
	}
	return 0
}

func (f clusterTargetFlags) newClient() (*cluster.Client, error) {
	resolved, err := f.resolveConfig()
	if err != nil {
		return nil, err
	}
	return cluster.NewClient(resolved)
}

func runCluster(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printClusterUsage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "join":
		return runClusterJoin(ctx, args[1:], stdin, stdout, stderr)
	case "rejoin":
		return runClusterRejoin(ctx, args[1:], stdin, stdout, stderr)
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

func runClusterJoin(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("cluster join")
	var joinSeedsFlag stringSliceFlag
	fs.Var(&joinSeedsFlag, "join", "Seed peer cluster address(es) host:port (repeatable or CSV)")
	fs.Var(&joinSeedsFlag, "seed", "Alias for --join")
	joinToken := fs.String("join-token", "", "Single-use Root-CA-pinned join token (abjt1...)")
	joinTokenStdin := fs.Bool("join-token-stdin", false, "Read single-use join token from stdin")
	dataDir := fs.String("data-dir", "", "Directory for enrolled node PKI and state files")
	nodeID := fs.String("node-id", "", "Unique cluster node ID (defaults to leaf cert CN or hostname)")

	var bindFlag stringSliceFlag
	fs.Var(&bindFlag, "bind", "Exec bind selector(s) for endpoint registration and SANs (repeatable or CSV)")
	port := fs.Int("port", protocol.DefaultPort, "Exec TCP port")
	var clusterBindFlag stringSliceFlag
	fs.Var(&clusterBindFlag, "cluster-bind", "Cluster bind selector(s), inline :port allowed (repeatable or CSV)")
	clusterAdvertise := fs.String("cluster-advertise", "", "Advertised cluster host:port")

	certFlag := fs.String("cert", "", "Optional pre-issued node certificate PEM path")
	keyFlag := fs.String("key", "", "Optional pre-issued node private key PEM path")
	caFlag := fs.String("ca", "", "Output or existing Root CA certificate PEM path")
	crlFlag := fs.String("crl", "", "Output or existing CRL PEM path")
	stateFlag := fs.String("cluster-state", "", "Output cluster state JSON path")

	var sanIPsFlag stringSliceFlag
	var sanDNSFlag stringSliceFlag
	fs.Var(&sanIPsFlag, "san-ip", "Extra X.509 IP SAN(s) for CSR issuance (repeatable or CSV)")
	fs.Var(&sanDNSFlag, "san-dns", "Extra X.509 DNS SAN(s) for CSR issuance (repeatable or CSV)")
	noAutoSANs := fs.Bool("no-auto-sans", false, "Disable automatic active-NIC IP SAN discovery")
	skipPreflight := fs.Bool("skip-preflight", false, "Skip pre-flight route hairpin check")
	jsonOut := fs.Bool("json", false, "Format output as indented JSON")

	if code, handled := parseFlags(fs, args, stdout, stderr, printClusterJoinUsage); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		printClusterJoinUsage(stderr)
		return exitUsage
	}

	if len(joinSeedsFlag) == 0 {
		_, _ = fmt.Fprintln(stderr, "Error: missing required flag(s): --join")
		printClusterJoinUsage(stderr)
		return exitUsage
	}

	resolvedToken, err := resolveJoinTokenInput(*joinToken, *joinTokenStdin, stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		printClusterJoinUsage(stderr)
		return exitUsage
	}

	parsedSeeds, err := cluster.ParseSeedAddrs(joinSeedsFlag...)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	homeDir, _ := os.UserHomeDir()
	resolvedDataDir := service.DefaultPaths().DataDir
	if strings.TrimSpace(*dataDir) != "" {
		resolvedDataDir = config.ExpandPath(*dataDir, homeDir, "")
	}

	certPath := ""
	keyPath := ""
	if strings.TrimSpace(*certFlag) != "" {
		certPath = config.ExpandPath(*certFlag, homeDir, "")
	}
	if strings.TrimSpace(*keyFlag) != "" {
		keyPath = config.ExpandPath(*keyFlag, homeDir, "")
	}
	if (certPath != "") != (keyPath != "") {
		_, _ = fmt.Fprintln(stderr, "Error: --cert and --key must be specified together")
		printClusterJoinUsage(stderr)
		return exitUsage
	}
	if certPath == "" && keyPath == "" {
		certPath, keyPath = config.ResolveNodeCertPaths(resolvedDataDir)
	}

	caPath := filepath.Join(resolvedDataDir, pki.CACertFilename)
	if strings.TrimSpace(*caFlag) != "" {
		caPath = config.ExpandPath(*caFlag, homeDir, "")
	}
	crlPath := filepath.Join(resolvedDataDir, pki.CRLFilename)
	if strings.TrimSpace(*crlFlag) != "" {
		crlPath = config.ExpandPath(*crlFlag, homeDir, "")
	}

	effectiveNodeID := strings.TrimSpace(*nodeID)
	if effectiveNodeID == "" && fileExistsRegular(certPath) {
		if leaf, lErr := pki.LoadCertificate(certPath); lErr == nil {
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

	statePath := cluster.DefaultStatePath(crlPath, effectiveNodeID)
	if strings.TrimSpace(*stateFlag) != "" {
		statePath = config.ExpandPath(*stateFlag, homeDir, "")
	}

	alreadyBootstrapped := fileExistsRegular(statePath) &&
		fileExistsRegular(certPath) &&
		fileExistsRegular(keyPath) &&
		fileExistsRegular(caPath) &&
		fileExistsRegular(crlPath)
	if !alreadyBootstrapped && resolvedToken == "" {
		_, _ = fmt.Fprintln(stderr, "Error: missing required flag(s): --join-token")
		printClusterJoinUsage(stderr)
		return exitUsage
	}

	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	if !*skipPreflight {
		if err := checkJoinRouteHairpin(sigCtx, parsedSeeds); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return exitError
		}
	}

	if err := acl.LockdownServerDir(resolvedDataDir); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: failed to lock down data directory %q: %v\n", resolvedDataDir, err)
		return exitError
	}

	bindSpecs := netbind.SplitTokens(bindFlag)
	clusterBindSpecs := netbind.SplitTokens(clusterBindFlag)
	if len(clusterBindSpecs) == 0 && len(bindSpecs) > 0 {
		clusterBindSpecs = append([]string(nil), bindSpecs...)
	}
	execBindAddrs := buildExecBindSpecAddrs(bindSpecs, nil, *port)

	res, err := cluster.BootstrapJoin(sigCtx, cluster.BootstrapJoinOptions{
		JoinAddrs:                parsedSeeds,
		JoinToken:                resolvedToken,
		NodeID:                   effectiveNodeID,
		ClusterBindAddrs:         clusterBindSpecs,
		AdvertiseAddr:            strings.TrimSpace(*clusterAdvertise),
		ExecBindAddrs:            execBindAddrs,
		CertPath:                 certPath,
		KeyPath:                  keyPath,
		CAPath:                   caPath,
		CRLPath:                  crlPath,
		StatePath:                statePath,
		ExtraIPs:                 netbind.SplitTokens(sanIPsFlag),
		ExtraDNSNames:            netbind.SplitTokens(sanDNSFlag),
		DisableAutoInterfaceSANs: *noAutoSANs,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	_ = acl.LockdownServerDir(resolvedDataDir)
	if fileExistsRegular(keyPath) {
		_ = acl.LockdownPrivateFile(keyPath)
	}

	if *jsonOut {
		return writeIndentedJSON(stdout, stderr, res)
	}

	_, _ = fmt.Fprintf(stdout, "Node ID:        %s\n", res.NodeID)
	_, _ = fmt.Fprintf(stdout, "Mode:           %s\n", res.Mode)
	_, _ = fmt.Fprintf(stdout, "Seed Addr:      %s\n", res.SeedAddr)
	_, _ = fmt.Fprintf(stdout, "Cluster Addr:   %s\n", res.ClusterAddr)
	_, _ = fmt.Fprintf(stdout, "Cert Serial:    %s\n", res.CertSerialHex)
	_, _ = fmt.Fprintf(stdout, "Data Dir:       %s\n", resolvedDataDir)
	return exitOK
}

type clusterRejoinOutput struct {
	Method                  string   `json:"method"`
	Mode                    string   `json:"mode"`
	NodeID                  string   `json:"node_id"`
	ClusterAddr             string   `json:"cluster_addr"`
	SeedAddr                string   `json:"seed_addr"`
	OldCertSerialHex        string   `json:"old_cert_serial_hex,omitempty"`
	CertSerialHex           string   `json:"cert_serial_hex"`
	OldSerialRevoked        bool     `json:"old_serial_revoked"`
	ServerConfigUpdated     bool     `json:"server_config_updated,omitempty"`
	ServiceRestarted        bool     `json:"service_restarted,omitempty"`
	ServiceRestartScheduled bool     `json:"service_restart_scheduled,omitempty"`
	Warnings                []string `json:"warnings,omitempty"`
}

func runClusterRejoin(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("cluster rejoin")
	dataDir := fs.String("data-dir", "", "Server node PKI and state directory")
	serviceCfgFlag := fs.String("service-config", "", "Optional server.json path")
	fs.StringVar(serviceCfgFlag, "config", "", "Alias for --service-config")

	var seedsFlag stringSliceFlag
	fs.Var(&seedsFlag, "seed", "Seed peer cluster address(es) host:port (repeatable or CSV)")
	fs.Var(&seedsFlag, "join", "Alias for --seed")

	joinToken := fs.String("join-token", "", "Optional single-use join token (omit for tokenless mTLS renewal)")
	joinTokenStdin := fs.Bool("join-token-stdin", false, "Read join token from stdin")
	nodeID := fs.String("node-id", "", "Node ID override")

	var bindFlag stringSliceFlag
	fs.Var(&bindFlag, "bind", "Exec bind selector(s) (repeatable or CSV)")
	port := fs.Int("port", protocol.DefaultPort, "Exec TCP port")
	var clusterBindFlag stringSliceFlag
	fs.Var(&clusterBindFlag, "cluster-bind", "Cluster bind selector(s), inline :port allowed (repeatable or CSV)")
	clusterAdvertise := fs.String("cluster-advertise", "", "Advertised cluster host:port")

	certFlag := fs.String("cert", "", "Node certificate PEM path (or pre-issued replacement cert)")
	keyFlag := fs.String("key", "", "Node private key PEM path (or pre-issued replacement key)")
	caFlag := fs.String("ca", "", "Root CA certificate PEM path")
	crlFlag := fs.String("crl", "", "CRL PEM path")
	stateFlag := fs.String("cluster-state", "", "Cluster state JSON path")

	var sanIPsFlag stringSliceFlag
	var sanDNSFlag stringSliceFlag
	fs.Var(&sanIPsFlag, "san-ip", "Additional X.509 IP SAN(s) to include in rotated cert (repeatable or CSV)")
	fs.Var(&sanDNSFlag, "san-dns", "Additional X.509 DNS SAN(s) to include in rotated cert (repeatable or CSV)")
	noAutoSANs := fs.Bool("no-auto-sans", false, "Disable automatic active-NIC IP SAN discovery")
	revokeOld := fs.Bool("revoke-old", false, "Revoke previous leaf certificate serial upon successful rotation")
	noRestart := fs.Bool("no-restart", false, "Do not restart local OS service after certificate rotation")
	serviceName := fs.String("service-name", service.DefaultServiceName, "OS service name to restart if running")
	skipPreflight := fs.Bool("skip-preflight", false, "Skip pre-flight route hairpin check")
	jsonOut := fs.Bool("json", false, "Format output as indented JSON")

	if code, handled := parseFlags(fs, args, stdout, stderr, printClusterRejoinUsage); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		printClusterRejoinUsage(stderr)
		return exitUsage
	}

	resolvedToken, err := resolveJoinTokenInput(*joinToken, *joinTokenStdin, stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		printClusterRejoinUsage(stderr)
		return exitUsage
	}

	visited := visitedFlags(fs)
	if visited["cert"] != visited["key"] {
		_, _ = fmt.Fprintln(stderr, "Error: --cert and --key must be specified together")
		printClusterRejoinUsage(stderr)
		return exitUsage
	}

	homeDir, _ := os.UserHomeDir()
	resolvedDataDir := ""
	if strings.TrimSpace(*dataDir) != "" {
		resolvedDataDir = config.ExpandPath(*dataDir, homeDir, "")
	}

	resolvedServiceCfg := ""
	if strings.TrimSpace(*serviceCfgFlag) != "" {
		resolvedServiceCfg = config.ExpandPath(*serviceCfgFlag, homeDir, "")
	} else if resolvedDataDir != "" {
		inDir := filepath.Join(resolvedDataDir, "server.json")
		parentCfg := filepath.Join(filepath.Dir(filepath.Clean(resolvedDataDir)), "server.json")
		if fileExistsRegular(inDir) {
			resolvedServiceCfg = inDir
		} else if fileExistsRegular(parentCfg) {
			resolvedServiceCfg = parentCfg
		}
	} else {
		defCfg := service.DefaultPaths().ConfigPath
		if fileExistsRegular(defCfg) {
			resolvedServiceCfg = defCfg
		}
	}

	var serverCfg *service.ServerDaemonConfig
	var cfgBaseDir string
	if resolvedServiceCfg != "" && fileExistsRegular(resolvedServiceCfg) {
		loaded, loadErr := service.LoadServerDaemonConfig(resolvedServiceCfg)
		if loadErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", loadErr)
			return exitError
		}
		serverCfg = loaded
		cfgBaseDir = filepath.Dir(resolvedServiceCfg)
	} else if visited["service-config"] || visited["config"] {
		_, _ = fmt.Fprintf(stderr, "Error: server config %q does not exist\n", resolvedServiceCfg)
		return exitError
	}

	if resolvedDataDir == "" {
		if serverCfg != nil && strings.TrimSpace(serverCfg.DataDir) != "" {
			resolvedDataDir = config.ExpandPath(serverCfg.DataDir, homeDir, cfgBaseDir)
		} else {
			resolvedDataDir = service.DefaultPaths().DataDir
		}
	}

	bindSpecs := netbind.SplitTokens(bindFlag)
	effectivePort := *port
	clusterBindSpecs := netbind.SplitTokens(clusterBindFlag)
	clusterAdv := strings.TrimSpace(*clusterAdvertise)
	effectiveNodeID := strings.TrimSpace(*nodeID)
	sanIPs := netbind.SplitTokens(sanIPsFlag)
	sanDNS := netbind.SplitTokens(sanDNSFlag)
	effectiveNoAutoSANs := *noAutoSANs

	certPath, keyPath := config.ResolveNodeCertPaths(resolvedDataDir)
	caPath := filepath.Join(resolvedDataDir, pki.CACertFilename)
	crlPath := filepath.Join(resolvedDataDir, pki.CRLFilename)
	statePath := ""

	var candidateSeeds []string
	if len(seedsFlag) > 0 {
		candidateSeeds = append(candidateSeeds, seedsFlag...)
	}

	if serverCfg != nil {
		if !visited["bind"] && len(serverCfg.BindSpecs) > 0 {
			bindSpecs = netbind.SplitTokens(serverCfg.BindSpecs)
		}
		if !visited["port"] && serverCfg.Port > 0 {
			effectivePort = serverCfg.Port
		}
		if !visited["cluster-bind"] && len(serverCfg.ClusterBindSpecs) > 0 {
			clusterBindSpecs = netbind.SplitTokens(serverCfg.ClusterBindSpecs)
		}
		if !visited["cluster-advertise"] && strings.TrimSpace(serverCfg.ClusterAdvertise) != "" {
			clusterAdv = strings.TrimSpace(serverCfg.ClusterAdvertise)
		}
		if !visited["node-id"] && strings.TrimSpace(serverCfg.NodeID) != "" {
			effectiveNodeID = strings.TrimSpace(serverCfg.NodeID)
		}
		if strings.TrimSpace(serverCfg.CertPath) != "" {
			certPath = config.ExpandPath(serverCfg.CertPath, homeDir, cfgBaseDir)
		}
		if strings.TrimSpace(serverCfg.KeyPath) != "" {
			keyPath = config.ExpandPath(serverCfg.KeyPath, homeDir, cfgBaseDir)
		}
		if strings.TrimSpace(serverCfg.CAPath) != "" {
			caPath = config.ExpandPath(serverCfg.CAPath, homeDir, cfgBaseDir)
		}
		if strings.TrimSpace(serverCfg.CRLPath) != "" {
			crlPath = config.ExpandPath(serverCfg.CRLPath, homeDir, cfgBaseDir)
		}
		if strings.TrimSpace(serverCfg.StatePath) != "" {
			statePath = config.ExpandPath(serverCfg.StatePath, homeDir, cfgBaseDir)
		}
		if len(serverCfg.SANIPs) > 0 {
			sanIPs = mergeStringSlices(serverCfg.SANIPs, sanIPs)
		}
		if len(serverCfg.SANDNS) > 0 {
			sanDNS = mergeStringSlices(serverCfg.SANDNS, sanDNS)
		}
		if !visited["no-auto-sans"] {
			effectiveNoAutoSANs = serverCfg.NoAutoSANs
		}
		if len(candidateSeeds) == 0 {
			candidateSeeds = append(candidateSeeds, serverCfg.SeedPeers...)
			if strings.TrimSpace(serverCfg.JoinAddr) != "" {
				candidateSeeds = append(candidateSeeds, serverCfg.JoinAddr)
			}
		}
	}

	if visited["ca"] {
		caPath = config.ExpandPath(*caFlag, homeDir, "")
	}
	if visited["crl"] {
		crlPath = config.ExpandPath(*crlFlag, homeDir, "")
	}
	if visited["cluster-state"] {
		statePath = config.ExpandPath(*stateFlag, homeDir, "")
	}

	var newCertOverride, newKeyOverride string
	if visited["cert"] && visited["key"] {
		explicitCert := config.ExpandPath(*certFlag, homeDir, "")
		explicitKey := config.ExpandPath(*keyFlag, homeDir, "")
		if resolvedToken == "" && fileExistsRegular(certPath) && fileExistsRegular(keyPath) &&
			filepath.Clean(explicitCert) != filepath.Clean(certPath) {
			newCertOverride = explicitCert
			newKeyOverride = explicitKey
		} else {
			certPath = explicitCert
			keyPath = explicitKey
		}
	}

	if effectiveNodeID == "" && fileExistsRegular(certPath) {
		if leaf, lErr := pki.LoadCertificate(certPath); lErr == nil {
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

	if statePath == "" {
		defState := cluster.DefaultStatePath(crlPath, effectiveNodeID)
		if fileExistsRegular(defState) {
			statePath = defState
		} else if matches, _ := filepath.Glob(filepath.Join(resolvedDataDir, "cluster-state-*.json")); len(matches) == 1 {
			statePath = matches[0]
		} else {
			statePath = defState
		}
	}

	// Auto-discover seeds + cluster/exec addresses from persisted cluster-state.json when omitted.
	stateSeeds, stateClusterAddr, stateExecAddr, persistedLeafSerial := inspectPersistedStateForRejoin(statePath, effectiveNodeID)
	if len(candidateSeeds) == 0 && len(stateSeeds) > 0 {
		candidateSeeds = append(candidateSeeds, stateSeeds...)
	}
	if len(clusterBindSpecs) == 0 {
		if len(bindSpecs) > 0 {
			clusterBindSpecs = append([]string(nil), bindSpecs...)
		} else if stateClusterAddr != "" {
			clusterBindSpecs = []string{stateClusterAddr}
		}
	}

	var parsedSeeds []string
	if len(candidateSeeds) > 0 {
		seeds, sErr := cluster.ParseSeedAddrs(candidateSeeds...)
		if sErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", sErr)
			return exitError
		}
		parsedSeeds = seeds
	}

	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	if len(parsedSeeds) > 0 && !*skipPreflight {
		if err := checkJoinRouteHairpin(sigCtx, parsedSeeds); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return exitError
		}
	}

	execBindAddrs := buildExecBindSpecAddrs(bindSpecs, nil, effectivePort)
	if len(bindSpecs) == 0 && stateExecAddr != "" {
		execBindAddrs = []string{stateExecAddr}
	}

	var oldSerialHex string
	if fileExistsRegular(certPath) {
		if oldLeaf, lErr := pki.LoadCertificate(certPath); lErr == nil && oldLeaf.SerialNumber != nil {
			oldSerialHex = pki.FormatSerialHex(oldLeaf.SerialNumber)
		}
	}

	var out clusterRejoinOutput
	if resolvedToken == "" {
		renewRes, renewErr := cluster.RenewPeerCert(sigCtx, cluster.RenewOptions{
			JoinAddrs:                parsedSeeds,
			NodeID:                   effectiveNodeID,
			ClusterBindAddrs:         clusterBindSpecs,
			AdvertiseAddr:            clusterAdv,
			ExecBindAddrs:            execBindAddrs,
			CertPath:                 certPath,
			KeyPath:                  keyPath,
			NewCertPath:              newCertOverride,
			NewKeyPath:               newKeyOverride,
			CAPath:                   caPath,
			CRLPath:                  crlPath,
			StatePath:                statePath,
			ExtraIPs:                 sanIPs,
			ExtraDNSNames:            sanDNS,
			DisableAutoInterfaceSANs: effectiveNoAutoSANs,
			RevokeOldSerial:          *revokeOld,
		})
		if renewErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", renewErr)
			return exitError
		}
		out = clusterRejoinOutput{
			Method:           "mtls-renew",
			Mode:             renewRes.Mode,
			NodeID:           renewRes.NodeID,
			ClusterAddr:      renewRes.ClusterAddr,
			SeedAddr:         renewRes.SeedAddr,
			OldCertSerialHex: renewRes.OldCertSerialHex,
			CertSerialHex:    renewRes.CertSerialHex,
			OldSerialRevoked: renewRes.OldSerialRevoked,
		}
	} else {
		if len(parsedSeeds) == 0 {
			_, _ = fmt.Fprintln(stderr, "Error: unable to auto-discover cluster seed addresses; pass --seed <host:port>")
			return exitError
		}
		_ = acl.LockdownServerDir(resolvedDataDir)

		// Determine whether to run Mode B PoP (pre-issued new serial already at certPath) or Mode A CSR re-issuance.
		usePreIssuedModeB := visited["cert"] || (oldSerialHex != "" && persistedLeafSerial != "" && !strings.EqualFold(oldSerialHex, persistedLeafSerial))

		joinCertTarget := certPath
		joinKeyTarget := keyPath
		stagedSwap := false
		if !usePreIssuedModeB && fileExistsRegular(certPath) && fileExistsRegular(keyPath) {
			joinCertTarget = certPath + ".rejoin-staged"
			joinKeyTarget = keyPath + ".rejoin-staged"
			_ = os.Remove(joinCertTarget)
			_ = os.Remove(joinKeyTarget)
			stagedSwap = true
			defer func() {
				_ = os.Remove(joinCertTarget)
				_ = os.Remove(joinKeyTarget)
			}()
		}

		joinRes, joinErr := cluster.BootstrapJoin(sigCtx, cluster.BootstrapJoinOptions{
			JoinAddrs:                parsedSeeds,
			JoinToken:                resolvedToken,
			NodeID:                   effectiveNodeID,
			ClusterBindAddrs:         clusterBindSpecs,
			AdvertiseAddr:            clusterAdv,
			ExecBindAddrs:            execBindAddrs,
			CertPath:                 joinCertTarget,
			KeyPath:                  joinKeyTarget,
			CAPath:                   caPath,
			CRLPath:                  crlPath,
			StatePath:                statePath,
			ExtraIPs:                 sanIPs,
			ExtraDNSNames:            sanDNS,
			DisableAutoInterfaceSANs: effectiveNoAutoSANs,
		})
		if joinErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", joinErr)
			return exitError
		}

		if stagedSwap {
			keyBytes, kErr := os.ReadFile(joinKeyTarget)
			if kErr != nil {
				_, _ = fmt.Fprintf(stderr, "Error: failed to read staged private key: %v\n", kErr)
				return exitError
			}
			certBytes, cErr := os.ReadFile(joinCertTarget)
			if cErr != nil {
				_, _ = fmt.Fprintf(stderr, "Error: failed to read staged certificate: %v\n", cErr)
				return exitError
			}
			if err := pki.WriteFileAtomic(keyPath, keyBytes, 0o600); err != nil {
				_, _ = fmt.Fprintf(stderr, "Error: failed to write rotated private key: %v\n", err)
				return exitError
			}
			if err := pki.WriteFileAtomic(certPath, certBytes, 0o644); err != nil {
				_, _ = fmt.Fprintf(stderr, "Error: failed to write rotated certificate: %v\n", err)
				return exitError
			}
			_ = os.Remove(joinKeyTarget)
			_ = os.Remove(joinCertTarget)
		}

		oldRevoked := false
		if *revokeOld && oldSerialHex != "" && !strings.EqualFold(oldSerialHex, joinRes.CertSerialHex) {
			caDir := filepath.Dir(caPath)
			if fileExistsRegular(filepath.Join(caDir, pki.CAKeyFilename)) {
				if revRes, revErr := pki.RevokeCert(pki.RevokeCertOptions{
					CADir:  caDir,
					Serial: oldSerialHex,
					CRLOut: crlPath,
				}); revErr == nil {
					oldRevoked = true
					if crlBytes, rErr := os.ReadFile(revRes.CRLPath); rErr == nil && joinRes.SeedAddr != "" {
						if clCfg, cfgErr := config.ResolveClusterConfigWithOptions(config.ClusterFlagOverrides{
							ClusterAddr: joinRes.SeedAddr,
							CertPath:    certPath,
							KeyPath:     keyPath,
							CAPath:      caPath,
						}, config.ResolveOptions{}); cfgErr == nil {
							if cl, clErr := cluster.NewClient(clCfg); clErr == nil {
								_, _ = cl.Sync(sigCtx, cluster.SyncRequest{CRLPEM: string(crlBytes)})
								_ = cl.Close()
							}
						}
					}
				} else {
					out.Warnings = append(out.Warnings, fmt.Sprintf("unable to revoke old serial %s locally: %v", oldSerialHex, revErr))
				}
			} else {
				out.Warnings = append(out.Warnings, fmt.Sprintf("Root CA private key not present locally to revoke old serial %s; run 'agent-bridge ca revoke --serial %s --sync' on the CA node", oldSerialHex, oldSerialHex))
			}
		}

		out = clusterRejoinOutput{
			Method:           "token-join",
			Mode:             joinRes.Mode,
			NodeID:           joinRes.NodeID,
			ClusterAddr:      joinRes.ClusterAddr,
			SeedAddr:         joinRes.SeedAddr,
			OldCertSerialHex: oldSerialHex,
			CertSerialHex:    joinRes.CertSerialHex,
			OldSerialRevoked: oldRevoked,
			Warnings:         out.Warnings,
		}
	}

	_ = acl.LockdownServerDir(resolvedDataDir)
	if fileExistsRegular(keyPath) {
		_ = acl.LockdownPrivateFile(keyPath)
	}

	// Persist any updated bind/advertise/SAN settings to server.json if present.
	if serverCfg != nil && resolvedServiceCfg != "" {
		cfgChanged := false
		if visited["bind"] {
			serverCfg.BindSpecs = bindSpecs
			cfgChanged = true
		}
		if visited["port"] {
			serverCfg.Port = effectivePort
			cfgChanged = true
		}
		if visited["cluster-bind"] {
			serverCfg.ClusterBindSpecs = clusterBindSpecs
			cfgChanged = true
		}
		if visited["cluster-advertise"] {
			serverCfg.ClusterAdvertise = clusterAdv
			cfgChanged = true
		}
		if visited["san-ip"] {
			serverCfg.SANIPs = sanIPs
			cfgChanged = true
		}
		if visited["san-dns"] {
			serverCfg.SANDNS = sanDNS
			cfgChanged = true
		}
		if visited["no-auto-sans"] {
			serverCfg.NoAutoSANs = effectiveNoAutoSANs
			cfgChanged = true
		}
		if len(parsedSeeds) > 0 && (visited["seed"] || visited["join"]) {
			serverCfg.SeedPeers = parsedSeeds
			cfgChanged = true
		}
		if cfgChanged {
			if saveErr := service.SaveServerDaemonConfig(resolvedServiceCfg, serverCfg); saveErr != nil {
				out.Warnings = append(out.Warnings, fmt.Sprintf("failed to update %s: %v", resolvedServiceCfg, saveErr))
			} else {
				out.ServerConfigUpdated = true
			}
		}
	}

	// Automatically restart managed OS service if installed & running (unless --no-restart).
	if !*noRestart {
		svcName, vErr := service.ValidateServiceName(*serviceName)
		if vErr == nil {
			mgr := newServiceManager()
			if st, stErr := mgr.Status(sigCtx, svcName); stErr == nil && st != nil && st.Installed && st.Running {
				if strings.TrimSpace(os.Getenv(runner.EnvInExec)) == "1" {
					if spErr := spawnDetachedRestartFn("", svcName, "", 500*time.Millisecond); spErr != nil {
						out.Warnings = append(out.Warnings, fmt.Sprintf("failed to schedule detached service restart: %v", spErr))
					} else {
						out.ServiceRestartScheduled = true
					}
				} else {
					if rErr := mgr.Restart(sigCtx, svcName); rErr != nil {
						out.Warnings = append(out.Warnings, fmt.Sprintf("failed to restart service %q: %v", svcName, rErr))
					} else {
						out.ServiceRestarted = true
					}
				}
			}
		}
	}

	if *jsonOut {
		return writeIndentedJSON(stdout, stderr, out)
	}

	_, _ = fmt.Fprintf(stdout, "Method:         %s (%s)\n", out.Method, out.Mode)
	_, _ = fmt.Fprintf(stdout, "Node ID:        %s\n", out.NodeID)
	_, _ = fmt.Fprintf(stdout, "Seed Addr:      %s\n", out.SeedAddr)
	_, _ = fmt.Fprintf(stdout, "Cluster Addr:   %s\n", out.ClusterAddr)
	if out.OldCertSerialHex != "" {
		_, _ = fmt.Fprintf(stdout, "Old Serial:     %s (revoked=%t)\n", out.OldCertSerialHex, out.OldSerialRevoked)
	}
	_, _ = fmt.Fprintf(stdout, "New Serial:     %s\n", out.CertSerialHex)
	if out.ServerConfigUpdated {
		_, _ = fmt.Fprintf(stdout, "Server Config:  updated (%s)\n", resolvedServiceCfg)
	}
	if out.ServiceRestarted {
		_, _ = fmt.Fprintf(stdout, "Service:        restarted\n")
	} else if out.ServiceRestartScheduled {
		_, _ = fmt.Fprintf(stdout, "Service:        detached restart scheduled\n")
	}
	for _, w := range out.Warnings {
		_, _ = fmt.Fprintf(stdout, "Warning:        %s\n", w)
	}
	return exitOK
}

func inspectPersistedStateForRejoin(statePath, selfNodeID string) (seeds []string, selfClusterAddr string, selfExecAddr string, leafSerial string) {
	if !fileExistsRegular(statePath) {
		return nil, "", "", ""
	}
	raw, err := os.ReadFile(statePath)
	if err != nil {
		return nil, "", "", ""
	}
	var snap struct {
		NodeID        string             `json:"node_id"`
		CertSerialHex string             `json:"cert_serial_hex"`
		SeedPeers     []string           `json:"seed_peers"`
		Peers         []cluster.PeerInfo `json:"peers"`
	}
	if json.Unmarshal(raw, &snap) != nil {
		return nil, "", "", ""
	}
	leafSerial = strings.TrimSpace(snap.CertSerialHex)
	effectiveSelf := selfNodeID
	if effectiveSelf == "" {
		effectiveSelf = strings.TrimSpace(snap.NodeID)
	}
	seeds = append(seeds, snap.SeedPeers...)
	for _, p := range snap.Peers {
		if p.NodeID == effectiveSelf {
			if selfClusterAddr == "" {
				selfClusterAddr = strings.TrimSpace(p.ClusterAddr)
			}
			if selfExecAddr == "" {
				selfExecAddr = strings.TrimSpace(p.ExecAddr)
			}
			if leafSerial == "" {
				leafSerial = strings.TrimSpace(p.CertSerialHex)
			}
			continue
		}
		if strings.TrimSpace(p.ClusterAddr) != "" {
			seeds = append(seeds, strings.TrimSpace(p.ClusterAddr))
		}
	}
	return seeds, selfClusterAddr, selfExecAddr, leafSerial
}

func mergeStringSlices(base, extra []string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, list := range [][]string{base, extra} {
		for _, item := range netbind.SplitTokens(list) {
			if _, exists := seen[item]; !exists {
				seen[item] = struct{}{}
				out = append(out, item)
			}
		}
	}
	return out
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

func printClusterUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge cluster <subcommand> [flags]

Subcommands:
  join          Enroll node into cluster without starting daemon (CSR or pre-issued cert)
  rejoin        Rotate node certificate and SANs live via tokenless mTLS or join token
  token-create  Mint a single-use Root-CA-pinned join token
  status        Inspect node quorum state, coordinator leadership, CRL, and policy
  peers         List cluster peer membership, reachability, and replication state
  sync          Trigger anti-entropy sync and optionally push CRL or ExecutionPolicy
`)
}

func printClusterJoinUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `Usage: agent-bridge cluster join --join <seed:port> --join-token <token> [flags]

Flags:
  --join, --seed <addrs>        Seed peer cluster address(es) host:port (repeatable or CSV)
  --join-token <token>          Single-use Root-CA-pinned join token
  --join-token-stdin            Read single-use join token from stdin
  --data-dir <path>             Output PKI and state directory
  --node-id <id>                Unique cluster node ID (defaults to leaf CN or hostname)
  --bind <spec>                 Exec bind selector(s) (repeatable or CSV)
  --port <int>                  Exec TCP port (default %d)
  --cluster-bind <spec>         Cluster bind selector(s) (repeatable or CSV)
  --cluster-advertise <ip:port> Advertised cluster host:port
  --san-ip <ip1,ip2>            Additional IP SANs for CSR issuance (repeatable or CSV)
  --san-dns <dns1,dns2>         Additional DNS SANs for CSR issuance (repeatable or CSV)
  --no-auto-sans                Disable automatic active-NIC IP SAN discovery
  --skip-preflight              Skip pre-flight route hairpin check
  --json                        Format output as indented JSON
`, protocol.DefaultPort)
}

func printClusterRejoinUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `Usage: agent-bridge cluster rejoin [flags]

Flags:
  --data-dir <path>             Server node PKI and state directory
  --service-config <path>       Optional server.json path
  --seed, --join <addrs>        Seed peer address(es) (auto-discovered if omitted)
  --join-token <token>          Optional join token (omit for tokenless mTLS renewal)
  --join-token-stdin            Read join token from stdin
  --node-id <id>                Node ID override
  --bind <spec>                 Exec bind selector(s) (repeatable or CSV)
  --port <int>                  Exec TCP port (default %d)
  --cluster-bind <spec>         Cluster bind selector(s) (repeatable or CSV)
  --cluster-advertise <ip:port> Advertised cluster host:port
  --cert <path>                 Node certificate path (or pre-issued replacement cert)
  --key <path>                  Node private key path (or pre-issued replacement key)
  --san-ip <ip1,ip2>            Additional IP SANs to add during rotation (repeatable or CSV)
  --san-dns <dns1,dns2>         Additional DNS SANs to add during rotation (repeatable or CSV)
  --no-auto-sans                Disable automatic active-NIC IP SAN discovery
  --revoke-old                  Revoke previous leaf certificate serial upon rotation
  --no-restart                  Skip restarting local OS service after rotation
  --service-name <name>         OS service name (default %q)
  --json                        Format output as indented JSON
`, protocol.DefaultPort, service.DefaultServiceName)
}

func printClusterTokenCreateUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge cluster token-create [flags]

Flags:
  --ttl <duration>          Token validity duration, e.g. 15m, 1h, 24h (default "1h")
  --node-id <id>            Restrict token to a specific joining node_id
  --quiet, -q               Print bare join token string only
  --json                    Print response as indented JSON
  --cluster-addr <addr>     Cluster control-plane host:port (default 127.0.0.1:8444)
  --host <name>             Named host profile from config.json
  --data-dir <path>         Server node PKI directory (auto-discovered on server nodes)
  --service-config <path>   Server server.json path
  --config <path>           Client config.json path override
  --cert <path>             Client, server, or peer certificate PEM path
  --key <path>              Client, server, or peer private key PEM path
  --ca <path>               Root CA certificate PEM path
  --timeout <duration>      Request timeout (default 60s)
`)
}

func printClusterStatusUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge cluster status [flags]

Flags:
  --json                    Print status as indented JSON
  --cluster-addr <addr>     Cluster control-plane host:port (default 127.0.0.1:8444)
  --host <name>             Named host profile from config.json
  --data-dir <path>         Server node PKI directory (auto-discovered on server nodes)
  --service-config <path>   Server server.json path
  --config <path>           Client config.json path override
  --cert <path>             Client, server, or peer certificate PEM path
  --key <path>              Client, server, or peer private key PEM path
  --ca <path>               Root CA certificate PEM path
  --timeout <duration>      Request timeout (default 60s)
`)
}

func printClusterPeersUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge cluster peers [flags]

Flags:
  --json                    Print peer roster as indented JSON
  --cluster-addr <addr>     Cluster control-plane host:port (default 127.0.0.1:8444)
  --host <name>             Named host profile from config.json
  --data-dir <path>         Server node PKI directory (auto-discovered on server nodes)
  --service-config <path>   Server server.json path
  --config <path>           Client config.json path override
  --cert <path>             Client, server, or peer certificate PEM path
  --key <path>              Client, server, or peer private key PEM path
  --ca <path>               Root CA certificate PEM path
  --timeout <duration>      Request timeout (default 60s)
`)
}

func printClusterSyncUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge cluster sync [flags]

Flags:
  --crl-file <path>         Signed crl.pem file to upload and broadcast
  --default-timeout <dur>   Set cluster policy default command timeout (0 to reset)
  --max-timeout <dur>       Set cluster policy max command timeout (0 to reset)
  --default-shell <name>    Set cluster policy default shell (powershell, pwsh, cmd, sh, bash)
  --enforce-client-acl      Require client certificate CN or serial match in AllowedClients
  --disable-client-acl      Disable cluster client certificate ACL enforcement
  --allow-client <entry>    Allowed client CN or serial hex (repeatable or comma-separated)
  --json                    Print sync result as indented JSON
  --cluster-addr <addr>     Cluster control-plane host:port (default 127.0.0.1:8444)
  --host <name>             Named host profile from config.json
  --data-dir <path>         Server node PKI directory (auto-discovered on server nodes)
  --service-config <path>   Server server.json path
  --config <path>           Client config.json path override
  --cert <path>             Client, server, or peer certificate PEM path
  --key <path>              Client, server, or peer private key PEM path
  --ca <path>               Root CA certificate PEM path
  --timeout <duration>      Request timeout (default 60s)
`)
}
