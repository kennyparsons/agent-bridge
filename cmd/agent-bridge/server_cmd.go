package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
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
	"github.com/kennyparsons/agent-bridge/internal/server"
	"github.com/kennyparsons/agent-bridge/internal/service"
)

const defaultServiceWaitBind = 60 * time.Second

type staticPolicyProvider struct {
	policy protocol.ExecutionPolicy
}

func (s staticPolicyProvider) ExecutionPolicy() protocol.ExecutionPolicy {
	cp := s.policy
	if len(s.policy.AllowedClients) > 0 {
		cp.AllowedClients = append([]string(nil), s.policy.AllowedClients...)
	}
	return cp
}

type resolvedServerRunConfig struct {
	serviceName      string
	bindSpecs        []string
	port             int
	waitBind         time.Duration
	certPath         string
	keyPath          string
	caPath           string
	caKeyPath        string
	crlPath          string
	statePath        string
	dataDir          string
	logPath          string
	policyPath       string
	shell            string
	shellExplicit    bool
	clusterEnabled   bool
	clusterBindSpecs []string
	clusterAdvertise string
	seedPeers        []string
	joinSeeds        []string
	joinToken        string
	nodeID           string
	sanIPs           []string
	sanDNS           []string
	noAutoSANs       bool
	skipPreflight    bool
	isManagedService bool
}

func runServer(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("server")
	serviceConfigPath := fs.String("service-config", "", "Path to server.json daemon configuration file")
	serviceName := fs.String("service-name", service.DefaultServiceName, "Managed OS service name")

	var bindSpecsFlag stringSliceFlag
	fs.Var(&bindSpecsFlag, "bind", "Exec bind selector(s): IP, CIDR, 0.0.0.0, ::, all (repeatable or CSV)")
	port := fs.Int("port", protocol.DefaultPort, "TCP port for /ws/exec listener(s)")
	waitBindStr := fs.String("wait-bind", "", "Boot readiness wait timeout for virtual NICs (0s interactive, 60s service)")

	certPath := fs.String("cert", "", "Server or peer certificate PEM path")
	keyPath := fs.String("key", "", "Server or peer private key PEM path")
	caPath := fs.String("ca", "", "Root CA certificate PEM path")
	crlPath := fs.String("crl", "", "Certificate Revocation List PEM path")
	caKeyPath := fs.String("ca-key", "", "Optional Root CA private key PEM path for signing joining node CSRs")
	shell := fs.String("shell", runner.DefaultShell(), "Execution shell (powershell, pwsh, cmd, sh, bash)")
	policyPath := fs.String("policy", "", "Optional JSON ExecutionPolicy file path")
	logFile := fs.String("log-file", "", "Optional rotating daemon log file path")

	clusterFlag := fs.Bool("cluster", false, "Enable multi-node cluster control-plane engine")
	var clusterBindFlag stringSliceFlag
	fs.Var(&clusterBindFlag, "cluster-bind", "Cluster TLS 1.3 bind selector(s), inline :port allowed (repeatable or CSV)")
	clusterAdvertise := fs.String("cluster-advertise", "", "Advertised cluster host:port")
	var seedFlag stringSliceFlag
	fs.Var(&seedFlag, "seed", "Existing cluster peer seed address(es) host:port (repeatable or CSV)")
	var joinFlag stringSliceFlag
	fs.Var(&joinFlag, "join", "Seed peer cluster address(es) host:port to bootstrap/join (repeatable or CSV)")
	joinToken := fs.String("join-token", "", "Single-use cryptographic join token (abjt1...)")
	joinTokenStdin := fs.Bool("join-token-stdin", false, "Read single-use cryptographic join token from stdin")
	nodeID := fs.String("node-id", "", "Unique cluster node ID (defaults to leaf cert CN or hostname)")
	clusterState := fs.String("cluster-state", "", "Optional persistent cluster state JSON file path")
	dataDir := fs.String("data-dir", "", "Directory for node PKI and cluster state files")

	var sanIPsFlag stringSliceFlag
	var sanDNSFlag stringSliceFlag
	fs.Var(&sanIPsFlag, "san-ip", "Additional X.509 IP SAN(s) when joining via CSR (repeatable or CSV)")
	fs.Var(&sanDNSFlag, "san-dns", "Additional X.509 DNS SAN(s) when joining via CSR (repeatable or CSV)")
	noAutoSANs := fs.Bool("no-auto-sans", false, "Disable automatic active-NIC IP SAN discovery during CSR join")
	skipPreflight := fs.Bool("skip-preflight", false, "Skip pre-flight route hairpin check before cluster join")

	if code, handled := parseFlags(fs, args, stdout, stderr, printServerUsage); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		return exitUsage
	}

	visited := visitedFlags(fs)
	resolvedJoinToken, err := resolveJoinTokenInput(*joinToken, *joinTokenStdin, stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		printServerUsage(stderr)
		return exitUsage
	}

	homeDir, _ := os.UserHomeDir()
	isManaged := service.IsManagedServiceProcess()

	effectiveServiceCfgPath := ""
	if strings.TrimSpace(*serviceConfigPath) != "" {
		effectiveServiceCfgPath = config.ExpandPath(*serviceConfigPath, homeDir, "")
	} else if isManaged {
		defCfg := service.DefaultPaths().ConfigPath
		if fileExistsRegular(defCfg) {
			effectiveServiceCfgPath = defCfg
		}
	}

	var fileCfg *service.ServerDaemonConfig
	var cfgBaseDir string
	if effectiveServiceCfgPath != "" {
		loaded, loadErr := service.LoadServerDaemonConfig(effectiveServiceCfgPath)
		if loadErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", loadErr)
			return exitError
		}
		fileCfg = loaded
		cfgBaseDir = filepath.Dir(effectiveServiceCfgPath)
	}

	rc, usageErr, cfgErr := mergeServerConfig(
		fileCfg,
		cfgBaseDir,
		homeDir,
		visited,
		isManaged,
		strings.TrimSpace(*serviceName),
		bindSpecsFlag,
		*port,
		strings.TrimSpace(*waitBindStr),
		strings.TrimSpace(*certPath),
		strings.TrimSpace(*keyPath),
		strings.TrimSpace(*caPath),
		strings.TrimSpace(*caKeyPath),
		strings.TrimSpace(*crlPath),
		strings.TrimSpace(*clusterState),
		strings.TrimSpace(*dataDir),
		strings.TrimSpace(*logFile),
		strings.TrimSpace(*policyPath),
		strings.TrimSpace(*shell),
		*clusterFlag,
		clusterBindFlag,
		strings.TrimSpace(*clusterAdvertise),
		seedFlag,
		joinFlag,
		resolvedJoinToken,
		strings.TrimSpace(*nodeID),
		sanIPsFlag,
		sanDNSFlag,
		*noAutoSANs,
		*skipPreflight,
	)
	if usageErr != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", usageErr)
		printServerUsage(stderr)
		return exitUsage
	}
	if cfgErr != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", cfgErr)
		return exitError
	}

	if rc.isManagedService {
		exitCode, svcErr := service.RunManagedService(rc.serviceName, func(svcCtx context.Context) int {
			return executeServer(svcCtx, rc, stderr)
		})
		if svcErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", svcErr)
			return exitError
		}
		return exitCode
	}

	return executeServer(ctx, rc, stderr)
}

func mergeServerConfig(
	fileCfg *service.ServerDaemonConfig,
	cfgBaseDir string,
	homeDir string,
	visited map[string]bool,
	isManaged bool,
	serviceName string,
	bindFlag []string,
	portFlag int,
	waitBindFlag string,
	certFlag string,
	keyFlag string,
	caFlag string,
	caKeyFlag string,
	crlFlag string,
	stateFlag string,
	dataDirFlag string,
	logFileFlag string,
	policyFlag string,
	shellFlag string,
	clusterFlag bool,
	clusterBindFlag []string,
	clusterAdvFlag string,
	seedFlag []string,
	joinFlag []string,
	joinToken string,
	nodeIDFlag string,
	sanIPsFlag []string,
	sanDNSFlag []string,
	noAutoSANsFlag bool,
	skipPreflightFlag bool,
) (resolvedServerRunConfig, error, error) {
	var rc resolvedServerRunConfig
	rc.isManagedService = isManaged

	normSvcName, svcErr := service.ValidateServiceName(serviceName)
	if svcErr != nil {
		return rc, svcErr, nil
	}
	rc.serviceName = normSvcName

	rc.port = protocol.DefaultPort
	rc.shell = runner.DefaultShell()

	expandFromCfg := func(p string) string {
		if strings.TrimSpace(p) == "" {
			return ""
		}
		return config.ExpandPath(p, homeDir, cfgBaseDir)
	}

	var cfgWaitBind string
	if fileCfg != nil {
		if len(fileCfg.BindSpecs) > 0 {
			rc.bindSpecs = netbind.SplitTokens(fileCfg.BindSpecs)
		}
		if fileCfg.Port > 0 {
			rc.port = fileCfg.Port
		}
		rc.clusterEnabled = fileCfg.ClusterEnabled
		if len(fileCfg.ClusterBindSpecs) > 0 {
			rc.clusterBindSpecs = netbind.SplitTokens(fileCfg.ClusterBindSpecs)
		}
		rc.clusterAdvertise = strings.TrimSpace(fileCfg.ClusterAdvertise)
		if len(fileCfg.SeedPeers) > 0 {
			rc.seedPeers = netbind.SplitTokens(fileCfg.SeedPeers)
		}
		if strings.TrimSpace(fileCfg.JoinAddr) != "" {
			rc.joinSeeds = netbind.SplitTokens([]string{fileCfg.JoinAddr})
		}
		rc.nodeID = strings.TrimSpace(fileCfg.NodeID)
		rc.dataDir = expandFromCfg(fileCfg.DataDir)
		rc.certPath = expandFromCfg(fileCfg.CertPath)
		rc.keyPath = expandFromCfg(fileCfg.KeyPath)
		rc.caPath = expandFromCfg(fileCfg.CAPath)
		rc.caKeyPath = expandFromCfg(fileCfg.CAKeyPath)
		rc.crlPath = expandFromCfg(fileCfg.CRLPath)
		rc.statePath = expandFromCfg(fileCfg.StatePath)
		rc.logPath = expandFromCfg(fileCfg.LogPath)
		rc.policyPath = expandFromCfg(fileCfg.PolicyPath)
		if strings.TrimSpace(fileCfg.Shell) != "" {
			rc.shell = strings.TrimSpace(fileCfg.Shell)
			rc.shellExplicit = true
		}
		cfgWaitBind = strings.TrimSpace(fileCfg.WaitBind)
		if len(fileCfg.SANIPs) > 0 {
			rc.sanIPs = netbind.SplitTokens(fileCfg.SANIPs)
		}
		if len(fileCfg.SANDNS) > 0 {
			rc.sanDNS = netbind.SplitTokens(fileCfg.SANDNS)
		}
		rc.noAutoSANs = fileCfg.NoAutoSANs
	}

	// Overlay explicitly set CLI flags on top of server.json defaults.
	if visited["bind"] {
		rc.bindSpecs = netbind.SplitTokens(bindFlag)
	}
	if visited["port"] {
		rc.port = portFlag
	}
	if visited["cert"] {
		rc.certPath = config.ExpandPath(certFlag, homeDir, "")
	}
	if visited["key"] {
		rc.keyPath = config.ExpandPath(keyFlag, homeDir, "")
	}
	if visited["ca"] {
		rc.caPath = config.ExpandPath(caFlag, homeDir, "")
	}
	if visited["ca-key"] {
		rc.caKeyPath = config.ExpandPath(caKeyFlag, homeDir, "")
	}
	if visited["crl"] {
		rc.crlPath = config.ExpandPath(crlFlag, homeDir, "")
	}
	if visited["cluster-state"] {
		rc.statePath = config.ExpandPath(stateFlag, homeDir, "")
	}
	if visited["data-dir"] {
		rc.dataDir = config.ExpandPath(dataDirFlag, homeDir, "")
	}
	if visited["log-file"] {
		rc.logPath = config.ExpandPath(logFileFlag, homeDir, "")
	}
	if visited["policy"] {
		rc.policyPath = config.ExpandPath(policyFlag, homeDir, "")
	}
	if visited["shell"] {
		rc.shell = shellFlag
		rc.shellExplicit = true
	}
	if visited["cluster"] {
		rc.clusterEnabled = clusterFlag
	}
	if visited["cluster-bind"] {
		rc.clusterBindSpecs = netbind.SplitTokens(clusterBindFlag)
	}
	if visited["cluster-advertise"] {
		rc.clusterAdvertise = clusterAdvFlag
	}
	if visited["seed"] {
		rc.seedPeers = netbind.SplitTokens(seedFlag)
	}
	if visited["join"] {
		rc.joinSeeds = netbind.SplitTokens(joinFlag)
	}
	if visited["node-id"] {
		rc.nodeID = nodeIDFlag
	}
	if visited["san-ip"] {
		rc.sanIPs = netbind.SplitTokens(sanIPsFlag)
	}
	if visited["san-dns"] {
		rc.sanDNS = netbind.SplitTokens(sanDNSFlag)
	}
	if visited["no-auto-sans"] {
		rc.noAutoSANs = noAutoSANsFlag
	}
	rc.skipPreflight = skipPreflightFlag
	rc.joinToken = joinToken

	rawWait := cfgWaitBind
	if visited["wait-bind"] {
		rawWait = waitBindFlag
	}
	if rawWait != "" {
		dur, err := time.ParseDuration(rawWait)
		if err != nil || dur < 0 {
			return rc, fmt.Errorf("invalid --wait-bind duration %q (expected non-negative duration such as 0s or 60s)", rawWait), nil
		}
		rc.waitBind = dur
	} else if fileCfg != nil || isManaged {
		rc.waitBind = defaultServiceWaitBind
	}

	if rc.joinToken != "" && len(rc.joinSeeds) == 0 {
		return rc, fmt.Errorf("--join-token requires --join <seed_ip:port>"), nil
	}

	if len(rc.clusterBindSpecs) > 0 || len(rc.joinSeeds) > 0 || len(rc.seedPeers) > 0 {
		rc.clusterEnabled = true
	}
	if rc.clusterAdvertise != "" && !rc.clusterEnabled {
		return rc, fmt.Errorf("--cluster-advertise requires --cluster, --cluster-bind, --seed, or --join"), nil
	}

	if rc.port == 0 {
		rc.port = protocol.DefaultPort
	}
	if rc.port < 1 || rc.port > 65535 {
		return rc, nil, fmt.Errorf("invalid server port %d: must be between 1 and 65535", rc.port)
	}

	return rc, nil, nil
}

func executeServer(ctx context.Context, rc resolvedServerRunConfig, stderr io.Writer) int {
	var rotLog *daemonlog.RotatingWriter
	logDest := stderr
	if rc.logPath != "" {
		openedLog, err := daemonlog.Open(rc.logPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: failed to open daemon log %q: %v\n", rc.logPath, err)
			return exitError
		}
		rotLog = openedLog
		defer func() {
			_ = rotLog.Close()
		}()
		if rc.isManagedService {
			logDest = rotLog
		} else {
			logDest = io.MultiWriter(stderr, rotLog)
		}
	}

	logger := log.New(logDest, "[agent-bridge] ", log.LstdFlags)

	var staticPol *protocol.ExecutionPolicy
	if rc.policyPath != "" {
		loadedPol, err := loadExecutionPolicyFile(rc.policyPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return exitError
		}
		staticPol = loadedPol
	}

	if !rc.clusterEnabled {
		return runStandaloneServer(ctx, rc, logger, staticPol, stderr)
	}
	return runClusteredServer(ctx, rc, logger, staticPol, stderr)
}

func loadExecutionPolicyFile(path string) (*protocol.ExecutionPolicy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read --policy file %q: %w", path, err)
	}
	var pol protocol.ExecutionPolicy
	if err := json.Unmarshal(raw, &pol); err != nil {
		return nil, fmt.Errorf("failed to parse --policy JSON %q: %w", path, err)
	}
	return &pol, nil
}

func runStandaloneServer(
	ctx context.Context,
	rc resolvedServerRunConfig,
	logger *log.Logger,
	staticPol *protocol.ExecutionPolicy,
	stderr io.Writer,
) int {
	certPath := rc.certPath
	keyPath := rc.keyPath
	caPath := rc.caPath
	crlPath := rc.crlPath

	if rc.dataDir != "" {
		candCert, candKey := config.ResolveNodeCertPaths(rc.dataDir)
		if certPath == "" {
			certPath = candCert
		}
		if keyPath == "" {
			keyPath = candKey
		}
		if caPath == "" {
			caPath = filepath.Join(rc.dataDir, pki.CACertFilename)
		}
		if crlPath == "" {
			crlPath = filepath.Join(rc.dataDir, pki.CRLFilename)
		}
	}

	var missing []string
	if len(rc.bindSpecs) == 0 {
		missing = append(missing, "--bind")
	}
	if certPath == "" {
		missing = append(missing, "--cert")
	}
	if keyPath == "" {
		missing = append(missing, "--key")
	}
	if caPath == "" {
		missing = append(missing, "--ca")
	}
	if crlPath == "" {
		missing = append(missing, "--crl")
	}
	if len(missing) > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: missing required flag(s): %s\n", strings.Join(missing, ", "))
		printServerUsage(stderr)
		return exitUsage
	}

	var polProvider server.PolicyProvider
	if staticPol != nil {
		polProvider = staticPolicyProvider{policy: *staticPol}
	}

	srvCfg := server.Config{
		BindSpecs:      rc.bindSpecs,
		WaitBind:       rc.waitBind,
		Port:           rc.port,
		CertPath:       certPath,
		KeyPath:        keyPath,
		CAPath:         caPath,
		CRLPath:        crlPath,
		PolicyProvider: polProvider,
		Shell:          rc.shell,
		ShellExplicit:  rc.shellExplicit,
		Logger:         logger,
	}

	srv, err := server.New(srvCfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	resolvedShell := runner.ResolveShell(srvCfg.Shell).Name
	readyStop := make(chan struct{})
	readyLogDone := make(chan struct{})
	go func() {
		defer close(readyLogDone)
		select {
		case <-srv.Ready():
			logger.Printf("listening on %s (tls=1.3 shell=%s crl=%s)",
				strings.Join(srv.BoundAddrs(), ", "),
				resolvedShell,
				srvCfg.CRLPath,
			)
		case <-readyStop:
		}
	}()

	serveErr := srv.ListenAndServe(sigCtx)
	close(readyStop)
	<-readyLogDone

	if serveErr != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", serveErr)
		return exitError
	}
	return exitOK
}

func runClusteredServer(
	ctx context.Context,
	rc resolvedServerRunConfig,
	logger *log.Logger,
	staticPol *protocol.ExecutionPolicy,
	stderr io.Writer,
) int {
	if len(rc.bindSpecs) == 0 {
		_, _ = fmt.Fprintln(stderr, "Error: missing required flag(s): --bind")
		printServerUsage(stderr)
		return exitUsage
	}
	if _, err := netbind.ParseSpecs(rc.bindSpecs, rc.port, false); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: invalid server bind address %q: %v\n", strings.Join(rc.bindSpecs, ","), err)
		return exitError
	}

	clusterBindSpecs := rc.clusterBindSpecs
	if len(clusterBindSpecs) == 0 {
		clusterBindSpecs = append([]string(nil), rc.bindSpecs...)
	}
	if _, err := netbind.ParseSpecs(clusterBindSpecs, config.DefaultClusterPort, true); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: invalid cluster bind address %q: %v\n", strings.Join(clusterBindSpecs, ","), err)
		return exitError
	}

	var parsedJoinSeeds []string
	if len(rc.joinSeeds) > 0 {
		seeds, err := cluster.ParseSeedAddrs(rc.joinSeeds...)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return exitError
		}
		parsedJoinSeeds = seeds
	}
	var parsedSeedPeers []string
	if len(rc.seedPeers) > 0 {
		seeds, err := cluster.ParseSeedAddrs(rc.seedPeers...)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return exitError
		}
		parsedSeedPeers = seeds
	}

	resolvedCert := rc.certPath
	resolvedKey := rc.keyPath
	resolvedCA := rc.caPath
	resolvedCRL := rc.crlPath
	resolvedState := rc.statePath

	// Pre-resolve existing node cert if dataDir is already populated so NodeID defaults to existing leaf CN.
	if rc.dataDir != "" && resolvedCert == "" && resolvedKey == "" {
		candCert, candKey := config.ResolveNodeCertPaths(rc.dataDir)
		if fileExistsRegular(candCert) && fileExistsRegular(candKey) {
			resolvedCert = candCert
			resolvedKey = candKey
		}
	}

	effectiveNodeID := rc.nodeID
	if effectiveNodeID == "" && resolvedCert != "" && fileExistsRegular(resolvedCert) {
		if leafCert, err := pki.LoadCertificate(resolvedCert); err == nil {
			effectiveNodeID = strings.TrimSpace(leafCert.Subject.CommonName)
		}
	}
	if effectiveNodeID == "" {
		if host, err := os.Hostname(); err == nil {
			effectiveNodeID = strings.TrimSpace(host)
		}
	}
	if effectiveNodeID == "" {
		effectiveNodeID = "node-1"
	}

	var baseDataDir string
	if len(parsedJoinSeeds) > 0 {
		if (rc.certPath != "") != (rc.keyPath != "") {
			_, _ = fmt.Fprintln(stderr, "Error: --cert and --key must be specified together when joining a cluster")
			printServerUsage(stderr)
			return exitUsage
		}
		if rc.dataDir != "" {
			baseDataDir = rc.dataDir
		} else {
			baseDataDir = filepath.Join(".", "agent-bridge-data", sanitizeDirName(effectiveNodeID))
		}
		if resolvedCert == "" || resolvedKey == "" {
			candCert, candKey := config.ResolveNodeCertPaths(baseDataDir)
			if resolvedCert == "" {
				resolvedCert = candCert
			}
			if resolvedKey == "" {
				resolvedKey = candKey
			}
		}
		if resolvedCA == "" {
			resolvedCA = filepath.Join(baseDataDir, pki.CACertFilename)
		}
		if resolvedCRL == "" {
			resolvedCRL = filepath.Join(baseDataDir, pki.CRLFilename)
		}
		if resolvedState == "" {
			resolvedState = cluster.DefaultStatePath(resolvedCRL, effectiveNodeID)
		}
	} else {
		if rc.dataDir != "" {
			baseDataDir = rc.dataDir
			candCert, candKey := config.ResolveNodeCertPaths(baseDataDir)
			if resolvedCert == "" {
				resolvedCert = candCert
			}
			if resolvedKey == "" {
				resolvedKey = candKey
			}
			if resolvedCA == "" {
				resolvedCA = filepath.Join(baseDataDir, pki.CACertFilename)
			}
			if resolvedCRL == "" {
				resolvedCRL = filepath.Join(baseDataDir, pki.CRLFilename)
			}
		}

		var missing []string
		if resolvedCert == "" {
			missing = append(missing, "--cert")
		}
		if resolvedKey == "" {
			missing = append(missing, "--key")
		}
		if resolvedCA == "" {
			missing = append(missing, "--ca")
		}
		if resolvedCRL == "" {
			missing = append(missing, "--crl")
		}
		if len(missing) > 0 {
			_, _ = fmt.Fprintf(stderr, "Error: missing required flag(s): %s\n", strings.Join(missing, ", "))
			printServerUsage(stderr)
			return exitUsage
		}
		if resolvedState == "" {
			resolvedState = cluster.DefaultStatePath(resolvedCRL, effectiveNodeID)
		}
	}

	alreadyOnDisk := len(parsedJoinSeeds) > 0 &&
		fileExistsRegular(resolvedState) &&
		fileExistsRegular(resolvedCert) &&
		fileExistsRegular(resolvedKey) &&
		fileExistsRegular(resolvedCA) &&
		fileExistsRegular(resolvedCRL)

	if len(parsedJoinSeeds) > 0 && !alreadyOnDisk && rc.joinToken == "" {
		_, _ = fmt.Fprintln(stderr, "Error: missing required flag(s): --join-token (required on initial cluster join)")
		printServerUsage(stderr)
		return exitUsage
	}

	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	// Pre-flight route hairpin check before binding or consuming a single-use join token.
	if len(parsedJoinSeeds) > 0 && !rc.skipPreflight && (!alreadyOnDisk || rc.joinToken != "") {
		if err := checkJoinRouteHairpin(sigCtx, parsedJoinSeeds); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return exitError
		}
	}

	// Probe exec listener(s) up front (waiting up to --wait-bind for virtual NICs) so we fail fast
	// before consuming a single-use join token or starting the cluster engine if any exec socket is
	// unassignable or already in use. When a fixed port is configured, close the probe sockets immediately
	// and re-bind right before ServeListeners so TCP readiness probes only succeed once BootstrapJoin
	// and the cluster engine have completed initialization.
	probeListeners, bindErr := netbind.WaitAndBindWithOptions(sigCtx, netbind.BindOptions{
		Specs:             rc.bindSpecs,
		DefaultPort:       rc.port,
		AllowPortOverride: false,
		WaitTimeout:       rc.waitBind,
	})
	if bindErr != nil {
		_, _ = fmt.Fprintf(stderr, "Error: failed to bind TCP listener(s): %v\n", bindErr)
		return exitError
	}
	var execListeners []net.Listener
	execListenersTransferred := false
	defer func() {
		if !execListenersTransferred && len(execListeners) > 0 {
			_ = netbind.CloseListeners(execListeners)
		}
	}()

	boundExecAddrs := netbind.ListenerAddrs(probeListeners)
	if rc.port == 0 && len(parsedJoinSeeds) == 0 {
		execListeners = probeListeners
	} else {
		_ = netbind.CloseListeners(probeListeners)
	}
	execSpecAddrs := buildExecBindSpecAddrs(rc.bindSpecs, boundExecAddrs, rc.port)

	var joinedSeeds []string
	if len(parsedJoinSeeds) > 0 {
		if baseDataDir != "" {
			_ = acl.LockdownServerDir(baseDataDir)
		}
		joinRes, err := cluster.BootstrapJoin(sigCtx, cluster.BootstrapJoinOptions{
			JoinAddrs:                parsedJoinSeeds,
			JoinToken:                rc.joinToken,
			NodeID:                   effectiveNodeID,
			ClusterBindAddrs:         clusterBindSpecs,
			AdvertiseAddr:            rc.clusterAdvertise,
			ExecBindAddrs:            execSpecAddrs,
			CertPath:                 resolvedCert,
			KeyPath:                  resolvedKey,
			CAPath:                   resolvedCA,
			CRLPath:                  resolvedCRL,
			StatePath:                resolvedState,
			ExtraIPs:                 rc.sanIPs,
			ExtraDNSNames:            rc.sanDNS,
			DisableAutoInterfaceSANs: rc.noAutoSANs,
		})
		if err != nil {
			if rc.joinToken == "" {
				_, _ = fmt.Fprintf(stderr, "Error: node is not yet bootstrapped and --join-token was omitted: %v\n", err)
				return exitError
			}
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return exitError
		}
		if joinRes.NodeID != "" {
			effectiveNodeID = joinRes.NodeID
		}
		if baseDataDir != "" {
			_ = acl.LockdownServerDir(baseDataDir)
		}
		if fileExistsRegular(resolvedKey) {
			_ = acl.LockdownPrivateFile(resolvedKey)
		}
		joinedSeeds = append(joinedSeeds, joinRes.SeedAddrs...)
		if joinRes.SeedAddr != "" {
			joinedSeeds = append(joinedSeeds, joinRes.SeedAddr)
		}
		if !joinRes.AlreadyBootstrapped {
			logger.Printf("joined cluster via %s (mode=%s node_id=%s serial=%s)",
				joinRes.SeedAddr, joinRes.Mode, joinRes.NodeID, joinRes.CertSerialHex)
		}
	}

	resolvedCAKey := rc.caKeyPath
	if resolvedCAKey == "" {
		candidateCAKey := filepath.Join(filepath.Dir(resolvedCA), pki.CAKeyFilename)
		if fileExistsRegular(candidateCAKey) {
			if _, _, err := pki.LoadCAKeyPair(resolvedCA, candidateCAKey); err == nil {
				resolvedCAKey = candidateCAKey
			}
		}
	}

	caCert, _, err := pki.LoadCACertPool(resolvedCA)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: failed to load Root CA pool: %v\n", err)
		return exitError
	}

	crlWatcher, err := pki.NewCRLWatcher(
		resolvedCRL,
		caCert,
		func(revokedCount int, crlNum *big.Int) {
			logger.Printf("CRL hot-reloaded: crl_number=%v revoked_serials=%d", crlNum, revokedCount)
		},
		func(watchErr error) {
			logger.Printf("CRL reload error: %v", watchErr)
		},
	)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: CRL initialization failed: %v\n", err)
		return exitError
	}
	defer func() {
		_ = crlWatcher.Close()
	}()

	var allSeedPeers []string
	allSeedPeers = append(allSeedPeers, parsedSeedPeers...)
	allSeedPeers = append(allSeedPeers, parsedJoinSeeds...)
	allSeedPeers = append(allSeedPeers, joinedSeeds...)
	if deduped, seedErr := cluster.ParseSeedAddrs(allSeedPeers...); seedErr == nil {
		allSeedPeers = deduped
	}

	if rc.port == 0 && len(execListeners) == 0 {
		execListeners, bindErr = netbind.WaitAndBindWithOptions(sigCtx, netbind.BindOptions{
			Specs:             rc.bindSpecs,
			DefaultPort:       rc.port,
			AllowPortOverride: false,
			WaitTimeout:       rc.waitBind,
		})
		if bindErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: failed to bind TCP listener(s): %v\n", bindErr)
			return exitError
		}
		execSpecAddrs = buildExecBindSpecAddrs(rc.bindSpecs, netbind.ListenerAddrs(execListeners), rc.port)
	}

	primaryExec := ""
	if len(execSpecAddrs) > 0 {
		primaryExec = execSpecAddrs[0]
	}

	clusterEngine, err := cluster.NewEngine(cluster.Config{
		NodeID:              effectiveNodeID,
		ClusterBindAddrs:    clusterBindSpecs,
		ClusterWaitBind:     rc.waitBind,
		ClusterAutoLoopback: true,
		AdvertiseAddr:       rc.clusterAdvertise,
		ExecAddr:            primaryExec,
		CertPath:            resolvedCert,
		KeyPath:             resolvedKey,
		CAPath:              resolvedCA,
		CAKeyPath:           resolvedCAKey,
		StatePath:           resolvedState,
		SeedPeers:           allSeedPeers,
		CRLWatcher:          crlWatcher,
		Logger:              logger,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
	defer func() {
		_ = clusterEngine.Close()
	}()

	srvCfg := server.Config{
		BindSpecs:      rc.bindSpecs,
		WaitBind:       rc.waitBind,
		Port:           rc.port,
		CertPath:       resolvedCert,
		KeyPath:        resolvedKey,
		CAPath:         resolvedCA,
		CRLPath:        resolvedCRL,
		CRLWatcher:     crlWatcher,
		PolicyProvider: clusterEngine,
		Shell:          rc.shell,
		ShellExplicit:  rc.shellExplicit,
		Logger:         logger,
	}

	srv, err := server.New(srvCfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
	defer func() {
		_ = srv.Close()
	}()

	if err := clusterEngine.Start(sigCtx); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
	<-clusterEngine.Ready()

	if staticPol != nil && clusterEngine.Status().Policy.Version == 0 {
		polCopy := *staticPol
		if polCopy.Version == 0 {
			polCopy.Version = 1
		}
		if polCopy.UpdatedAtUnix == 0 {
			polCopy.UpdatedAtUnix = time.Now().UTC().Unix()
		}
		if _, syncErr := clusterEngine.Sync(sigCtx, cluster.SyncRequest{PolicyUpdate: &polCopy}); syncErr != nil {
			logger.Printf("warning: initial --policy sync skipped: %v", syncErr)
		}
	}

	st := clusterEngine.Status()
	logger.Printf("cluster engine listening on %s (node_id=%s ca_signer=%t)",
		clusterEngine.Addr(), st.NodeID, st.HasCAKey)

	resolvedShell := runner.ResolveShell(srvCfg.Shell).Name
	readyStop := make(chan struct{})
	readyLogDone := make(chan struct{})
	go func() {
		defer close(readyLogDone)
		select {
		case <-srv.Ready():
			logger.Printf("listening on %s (tls=1.3 shell=%s crl=%s cluster=%s)",
				strings.Join(srv.BoundAddrs(), ", "),
				resolvedShell,
				srvCfg.CRLPath,
				clusterEngine.Addr(),
			)
		case <-readyStop:
		}
	}()

	if len(execListeners) == 0 {
		execListeners, bindErr = netbind.WaitAndBindWithOptions(sigCtx, netbind.BindOptions{
			Specs:             rc.bindSpecs,
			DefaultPort:       rc.port,
			AllowPortOverride: false,
			WaitTimeout:       rc.waitBind,
		})
		if bindErr != nil {
			close(readyStop)
			<-readyLogDone
			_, _ = fmt.Fprintf(stderr, "Error: failed to bind TCP listener(s): %v\n", bindErr)
			return exitError
		}
	}

	execListenersTransferred = true
	serveErr := srv.ServeListeners(sigCtx, execListeners)
	close(readyStop)
	<-readyLogDone

	// Explicit ordered teardown: srv -> clusterEngine -> crlWatcher.
	_ = srv.Close()
	_ = clusterEngine.Close()
	_ = crlWatcher.Close()

	if serveErr != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", serveErr)
		return exitError
	}
	return exitOK
}

func buildExecBindSpecAddrs(bindSpecs []string, boundAddrs []string, port int) []string {
	var out []string
	seen := make(map[string]struct{})
	add := func(s string) {
		trimmed := strings.TrimSpace(s)
		if trimmed == "" {
			return
		}
		if _, exists := seen[trimmed]; !exists {
			seen[trimmed] = struct{}{}
			out = append(out, trimmed)
		}
	}
	for _, b := range boundAddrs {
		add(b)
	}
	portStr := strconv.Itoa(port)
	for _, spec := range bindSpecs {
		if ip := net.ParseIP(strings.TrimSpace(spec)); ip != nil {
			add(net.JoinHostPort(ip.String(), portStr))
		}
	}
	if len(out) == 0 && len(bindSpecs) > 0 {
		add(net.JoinHostPort("0.0.0.0", portStr))
	}
	return out
}

func checkJoinRouteHairpin(ctx context.Context, seeds []string) error {
	rep := doctor.Run(ctx, doctor.Options{
		Seeds:       seeds,
		DialTimeout: 2 * time.Second,
	})
	chk, ok := rep.FindCheck(doctor.CheckIDRouteHairpin)
	if !ok || chk.Status != doctor.StatusFail {
		return nil
	}
	if chk.Remediation != "" {
		return fmt.Errorf("pre-flight route hairpin check failed: %s (remediation: %s)", chk.Summary, chk.Remediation)
	}
	return fmt.Errorf("pre-flight route hairpin check failed: %s", chk.Summary)
}

func printServerUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `Usage: agent-bridge server [flags]

Execution Listener & Daemon Flags:
  --service-config <path>       Load base daemon configuration from server.json
  --service-name <name>         OS service name when running under SCM (default %q)
  --bind <spec>                 Bind IP, CIDR, 0.0.0.0, ::, or all (repeatable or CSV)
  --port <int>                  WebSocket mTLS TCP port (default %d)
  --wait-bind <duration>        Wait timeout for virtual NICs at boot (0s interactive, 60s service)
  --cert <path>                 Server or peer certificate PEM path
  --key <path>                  Server or peer private key PEM path
  --ca <path>                   Root CA certificate PEM path
  --crl <path>                  CRL PEM path
  --shell <name>                Execution shell: powershell, pwsh, cmd, sh, bash (default %q)
  --policy <path>               Optional ExecutionPolicy JSON file path
  --log-file <path>             Rotating daemon log file path

Multi-Node Cluster Flags:
  --cluster                     Enable cluster TLS 1.3 control-plane engine
  --cluster-bind <spec>         Cluster bind selector(s), inline :port allowed (repeatable or CSV)
  --cluster-advertise <ip:port> Advertised cluster host:port
  --seed <peer1:port,...>       Cluster peer seed address(es) (repeatable or CSV)
  --join <seed1:port,...>       Seed peer address(es) to bootstrap/join (repeatable or CSV)
  --join-token <token>          Single-use Root-CA-pinned join token (abjt1...)
  --join-token-stdin            Read single-use join token from stdin
  --node-id <id>                Unique cluster node ID (defaults to leaf cert CN or hostname)
  --ca-key <path>               Root CA private key PEM path for signing CSRs
  --cluster-state <path>        Persistent cluster state JSON path
  --data-dir <path>             Directory for node PKI and state files
  --san-ip <ip1,ip2>            Extra X.509 IP SANs for CSR enrollment (repeatable or CSV)
  --san-dns <dns1,dns2>         Extra X.509 DNS SANs for CSR enrollment (repeatable or CSV)
  --no-auto-sans                Disable automatic active-NIC IP SAN discovery
  --skip-preflight              Skip pre-flight route hairpin check before join
`, service.DefaultServiceName, protocol.DefaultPort, runner.DefaultShell())
}
