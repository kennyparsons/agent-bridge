package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/kennyparsons/agent-bridge/cluster"
	"github.com/kennyparsons/agent-bridge/internal/client"
	"github.com/kennyparsons/agent-bridge/internal/config"
	"github.com/kennyparsons/agent-bridge/internal/pki"
	"github.com/kennyparsons/agent-bridge/internal/protocol"
	"github.com/kennyparsons/agent-bridge/internal/runner"
	"github.com/kennyparsons/agent-bridge/internal/server"
)

var version = "v0.1.0"

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(val string) error {
	for _, item := range strings.Split(val, ",") {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			*s = append(*s, trimmed)
		}
	}
	return nil
}

func main() {
	os.Exit(normalizeProcessExitCode(run(os.Args[1:], os.Stdout, os.Stderr), runtime.GOOS))
}

// normalizeProcessExitCode ensures non-zero 32-bit remote exit codes (such as 256, -1, or
// 0xC0000000 whose low 8 bits are 0x00) never collapse to 0 under POSIX 8-bit os.Exit masking.
func normalizeProcessExitCode(code int, goos string) int {
	if goos == "windows" {
		return code
	}
	if code == 0 {
		return 0
	}
	if code >= 1 && code <= 255 {
		return code
	}
	if masked := code & 0xFF; masked != 0 {
		return masked
	}
	return exitError
}

func run(args []string, stdout, stderr io.Writer) int {
	return runContext(context.Background(), args, stdout, stderr)
}

func runContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(args) == 0 {
		printRootUsage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "ca":
		return runCA(args[1:], stdout, stderr)
	case "cluster":
		return runCluster(ctx, args[1:], stdout, stderr)
	case "server":
		return runServer(ctx, args[1:], stdout, stderr)
	case "exec":
		return runExec(ctx, args[1:], stdout, stderr)
	case "version", "--version", "-version", "-v":
		_, _ = fmt.Fprintf(stdout, "agent-bridge %s\n", version)
		return exitOK
	case "help", "--help", "-help", "-h":
		printRootUsage(stdout)
		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "Error: unknown command %q\n\n", args[0])
		printRootUsage(stderr)
		return exitUsage
	}
}

func runCA(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printCAUsage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "init":
		return runCAInit(args[1:], stdout, stderr)
	case "issue":
		return runCAIssue(args[1:], stdout, stderr)
	case "revoke":
		return runCARevoke(args[1:], stdout, stderr)
	case "help", "--help", "-help", "-h":
		printCAUsage(stdout)
		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "Error: unknown ca subcommand %q\n\n", args[0])
		printCAUsage(stderr)
		return exitUsage
	}
}

func runCAInit(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("ca init")
	outDir := fs.String("out-dir", "", "Output directory for ca.crt, ca.key, and crl.pem (required)")
	commonName := fs.String("common-name", pki.DefaultCACommonName, "Root CA Subject Common Name")
	org := fs.String("org", pki.DefaultCAOrg, "Root CA Subject Organization")
	years := fs.Int("years", pki.DefaultCAYears, "Validity period in years")

	if code, handled := parseFlags(fs, args, stdout, stderr, printCAInitUsage); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		return exitUsage
	}
	if strings.TrimSpace(*outDir) == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --out-dir is required")
		printCAInitUsage(stderr)
		return exitUsage
	}

	homeDir, _ := os.UserHomeDir()
	res, err := pki.InitCA(pki.InitCAOptions{
		OutDir:     config.ExpandPath(*outDir, homeDir, ""),
		CommonName: *commonName,
		Org:        *org,
		Years:      *years,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	_, _ = fmt.Fprintf(stdout, "CA Certificate: %s\nCA Private Key: %s\nCRL:            %s\nSerial:         %s\n",
		res.CACertPath, res.CAKeyPath, res.CRLPath, res.SerialHex)
	return exitOK
}

func runCAIssue(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("ca issue")
	caDir := fs.String("ca-dir", "", "Directory containing ca.crt and ca.key (required)")
	certType := fs.String("type", "", "Certificate profile: server, client, or peer (required)")
	name := fs.String("name", "", "Subject Common Name (required)")
	outDir := fs.String("out-dir", "", "Output directory for issued certificate and key (required)")
	years := fs.Int("years", 0, "Validity period in years (default: 3 for server/peer, 1 for client)")

	var ips stringSliceFlag
	var dnsNames stringSliceFlag
	fs.Var(&ips, "ip", "Server/peer IPv4/IPv6 SAN (repeatable or comma-separated)")
	fs.Var(&dnsNames, "dns", "Server/peer DNS SAN (repeatable or comma-separated)")

	if code, handled := parseFlags(fs, args, stdout, stderr, printCAIssueUsage); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		return exitUsage
	}

	var missing []string
	if strings.TrimSpace(*caDir) == "" {
		missing = append(missing, "--ca-dir")
	}
	if strings.TrimSpace(*certType) == "" {
		missing = append(missing, "--type")
	}
	if strings.TrimSpace(*name) == "" {
		missing = append(missing, "--name")
	}
	if strings.TrimSpace(*outDir) == "" {
		missing = append(missing, "--out-dir")
	}
	if len(missing) > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: missing required flag(s): %s\n", strings.Join(missing, ", "))
		printCAIssueUsage(stderr)
		return exitUsage
	}

	homeDir, _ := os.UserHomeDir()
	res, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:    config.ExpandPath(*caDir, homeDir, ""),
		OutDir:   config.ExpandPath(*outDir, homeDir, ""),
		Type:     *certType,
		Name:     *name,
		IPs:      ips,
		DNSNames: dnsNames,
		Years:    *years,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	_, _ = fmt.Fprintf(stdout, "Certificate: %s\nPrivate Key: %s\nSerial:      %s\n",
		res.CertPath, res.KeyPath, res.SerialHex)
	return exitOK
}

func runCARevoke(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("ca revoke")
	caDir := fs.String("ca-dir", "", "Directory containing ca.crt and ca.key (required)")
	serial := fs.String("serial", "", "Certificate serial number in hex (required)")
	crlOut := fs.String("crl-out", "", "Output path for updated CRL (default: <ca-dir>/crl.pem)")

	if code, handled := parseFlags(fs, args, stdout, stderr, printCARevokeUsage); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		return exitUsage
	}

	var missing []string
	if strings.TrimSpace(*caDir) == "" {
		missing = append(missing, "--ca-dir")
	}
	if strings.TrimSpace(*serial) == "" {
		missing = append(missing, "--serial")
	}
	if len(missing) > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: missing required flag(s): %s\n", strings.Join(missing, ", "))
		printCARevokeUsage(stderr)
		return exitUsage
	}

	homeDir, _ := os.UserHomeDir()
	expandedCRLOut := ""
	if strings.TrimSpace(*crlOut) != "" {
		expandedCRLOut = config.ExpandPath(*crlOut, homeDir, "")
	}

	res, err := pki.RevokeCert(pki.RevokeCertOptions{
		CADir:  config.ExpandPath(*caDir, homeDir, ""),
		Serial: *serial,
		CRLOut: expandedCRLOut,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	_, _ = fmt.Fprintf(stdout, "CRL:            %s\nCRL Number:     %s\nRevoked Serial: %s\n",
		res.CRLPath, res.CRLNumber.String(), res.SerialHex)
	return exitOK
}

func runServer(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("server")
	bindIP := fs.String("bind", "", "IP address to bind listener (required)")
	port := fs.Int("port", protocol.DefaultPort, "TCP port to listen on")
	certPath := fs.String("cert", "", "Server certificate PEM path")
	keyPath := fs.String("key", "", "Server private key PEM path")
	caPath := fs.String("ca", "", "Root CA certificate PEM path")
	crlPath := fs.String("crl", "", "Certificate Revocation List PEM path")
	shell := fs.String("shell", runner.DefaultShell(), "Execution shell (powershell, pwsh, cmd, sh, bash)")

	clusterBind := fs.String("cluster-bind", "", "Cluster TLS 1.3 control-plane bind address (ip:port)")
	clusterAdvertise := fs.String("cluster-advertise", "", "Advertised cluster host:port (defaults to --cluster-bind)")
	joinAddr := fs.String("join", "", "Seed peer cluster address (ip:port) to bootstrap/join")
	joinToken := fs.String("join-token", "", "Single-use cryptographic join token (abjt1...)")
	nodeID := fs.String("node-id", "", "Unique cluster node ID (defaults to leaf cert CN or hostname)")
	caKeyPath := fs.String("ca-key", "", "Optional Root CA private key PEM path for signing joining node CSRs")
	clusterState := fs.String("cluster-state", "", "Optional persistent cluster state JSON file path")
	dataDir := fs.String("data-dir", "", "Directory for node PKI and state files when joining without explicit --cert/--key/--ca/--crl")

	if code, handled := parseFlags(fs, args, stdout, stderr, printServerUsage); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		return exitUsage
	}

	visited := visitedFlags(fs)
	shellExplicit := visited["shell"]

	trimmedBind := strings.TrimSpace(*bindIP)
	trimmedClusterBind := strings.TrimSpace(*clusterBind)
	trimmedClusterAdv := strings.TrimSpace(*clusterAdvertise)
	trimmedJoin := strings.TrimSpace(*joinAddr)
	trimmedJoinToken := strings.TrimSpace(*joinToken)
	trimmedNodeID := strings.TrimSpace(*nodeID)
	trimmedCAKey := strings.TrimSpace(*caKeyPath)
	trimmedStatePath := strings.TrimSpace(*clusterState)
	trimmedDataDir := strings.TrimSpace(*dataDir)

	if trimmedJoinToken != "" && trimmedJoin == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --join-token requires --join <peer_ip:port>")
		printServerUsage(stderr)
		return exitUsage
	}
	if trimmedClusterAdv != "" && trimmedClusterBind == "" && trimmedJoin == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --cluster-advertise requires --cluster-bind or --join")
		printServerUsage(stderr)
		return exitUsage
	}

	clusterEnabled := trimmedClusterBind != "" || trimmedJoin != ""
	if !clusterEnabled {
		var missing []string
		if trimmedBind == "" {
			missing = append(missing, "--bind")
		}
		if strings.TrimSpace(*certPath) == "" {
			missing = append(missing, "--cert")
		}
		if strings.TrimSpace(*keyPath) == "" {
			missing = append(missing, "--key")
		}
		if strings.TrimSpace(*caPath) == "" {
			missing = append(missing, "--ca")
		}
		if strings.TrimSpace(*crlPath) == "" {
			missing = append(missing, "--crl")
		}
		if len(missing) > 0 {
			_, _ = fmt.Fprintf(stderr, "Error: missing required flag(s): %s\n", strings.Join(missing, ", "))
			printServerUsage(stderr)
			return exitUsage
		}

		homeDir, _ := os.UserHomeDir()
		logger := log.New(stderr, "[agent-bridge] ", log.LstdFlags)

		srvCfg := server.Config{
			BindIP:        trimmedBind,
			Port:          *port,
			CertPath:      config.ExpandPath(*certPath, homeDir, ""),
			KeyPath:       config.ExpandPath(*keyPath, homeDir, ""),
			CAPath:        config.ExpandPath(*caPath, homeDir, ""),
			CRLPath:       config.ExpandPath(*crlPath, homeDir, ""),
			Shell:         strings.TrimSpace(*shell),
			ShellExplicit: shellExplicit,
			Logger:        logger,
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
					srv.Addr(),
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

	return runClusteredServer(
		ctx,
		stderr,
		serverClusterParams{
			bindIP:           trimmedBind,
			port:             *port,
			certPath:         strings.TrimSpace(*certPath),
			keyPath:          strings.TrimSpace(*keyPath),
			caPath:           strings.TrimSpace(*caPath),
			crlPath:          strings.TrimSpace(*crlPath),
			shell:            strings.TrimSpace(*shell),
			shellExplicit:    shellExplicit,
			clusterBind:      trimmedClusterBind,
			clusterAdvertise: trimmedClusterAdv,
			joinAddr:         trimmedJoin,
			joinToken:        trimmedJoinToken,
			nodeID:           trimmedNodeID,
			caKeyPath:        trimmedCAKey,
			statePath:        trimmedStatePath,
			dataDir:          trimmedDataDir,
		},
	)
}

type serverClusterParams struct {
	bindIP           string
	port             int
	certPath         string
	keyPath          string
	caPath           string
	crlPath          string
	shell            string
	shellExplicit    bool
	clusterBind      string
	clusterAdvertise string
	joinAddr         string
	joinToken        string
	nodeID           string
	caKeyPath        string
	statePath        string
	dataDir          string
}

func runClusteredServer(ctx context.Context, stderr io.Writer, p serverClusterParams) int {
	if p.bindIP == "" {
		_, _ = fmt.Fprintln(stderr, "Error: missing required flag(s): --bind")
		printServerUsage(stderr)
		return exitUsage
	}
	if net.ParseIP(p.bindIP) == nil {
		_, _ = fmt.Fprintf(stderr, "Error: invalid server bind IP address %q\n", p.bindIP)
		return exitError
	}
	effectivePort := p.port
	if effectivePort == 0 {
		effectivePort = protocol.DefaultPort
	}
	if effectivePort < 1 || effectivePort > 65535 {
		_, _ = fmt.Fprintf(stderr, "Error: invalid server port %d: must be between 1 and 65535\n", p.port)
		return exitError
	}

	homeDir, _ := os.UserHomeDir()
	logger := log.New(stderr, "[agent-bridge] ", log.LstdFlags)

	clusterBindAddr := p.clusterBind
	if clusterBindAddr == "" {
		clusterBindAddr = net.JoinHostPort(p.bindIP, strconv.Itoa(config.DefaultClusterPort))
	}

	resolvedCert := ""
	if p.certPath != "" {
		resolvedCert = config.ExpandPath(p.certPath, homeDir, "")
	}
	resolvedKey := ""
	if p.keyPath != "" {
		resolvedKey = config.ExpandPath(p.keyPath, homeDir, "")
	}
	resolvedCA := ""
	if p.caPath != "" {
		resolvedCA = config.ExpandPath(p.caPath, homeDir, "")
	}
	resolvedCRL := ""
	if p.crlPath != "" {
		resolvedCRL = config.ExpandPath(p.crlPath, homeDir, "")
	}
	resolvedState := ""
	if p.statePath != "" {
		resolvedState = config.ExpandPath(p.statePath, homeDir, "")
	}

	effectiveNodeID := p.nodeID
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

	if p.joinAddr != "" {
		if (resolvedCert != "") != (resolvedKey != "") {
			_, _ = fmt.Fprintln(stderr, "Error: --cert and --key must be specified together when joining a cluster")
			printServerUsage(stderr)
			return exitUsage
		}

		baseDataDir := ""
		if p.dataDir != "" {
			baseDataDir = config.ExpandPath(p.dataDir, homeDir, "")
		} else {
			baseDataDir = filepath.Join(".", "agent-bridge-data", sanitizeDirName(effectiveNodeID))
		}
		if resolvedCert == "" {
			resolvedCert = filepath.Join(baseDataDir, pki.ServerCertFilename)
		}
		if resolvedKey == "" {
			resolvedKey = filepath.Join(baseDataDir, pki.ServerKeyFilename)
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
		if p.dataDir != "" {
			baseDataDir := config.ExpandPath(p.dataDir, homeDir, "")
			if resolvedCert == "" {
				resolvedCert = filepath.Join(baseDataDir, pki.ServerCertFilename)
			}
			if resolvedKey == "" {
				resolvedKey = filepath.Join(baseDataDir, pki.ServerKeyFilename)
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
	}

	alreadyOnDisk := p.joinAddr != "" &&
		fileExistsRegular(resolvedState) &&
		fileExistsRegular(resolvedCert) &&
		fileExistsRegular(resolvedKey) &&
		fileExistsRegular(resolvedCA) &&
		fileExistsRegular(resolvedCRL)

	if p.joinAddr != "" && !alreadyOnDisk && p.joinToken == "" {
		_, _ = fmt.Fprintln(stderr, "Error: missing required flag(s): --join-token (required on initial cluster join)")
		printServerUsage(stderr)
		return exitUsage
	}

	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	execListenAddr := net.JoinHostPort(p.bindIP, strconv.Itoa(effectivePort))

	// Fail fast before consuming a join token or starting cluster listeners if --bind:<port> is unassignable or in use.
	if probeLn, probeErr := net.Listen("tcp", execListenAddr); probeErr != nil {
		_, _ = fmt.Fprintf(stderr, "Error: failed to bind TCP listener on %s: %v\n", execListenAddr, probeErr)
		return exitError
	} else {
		_ = probeLn.Close()
	}

	if p.joinAddr != "" {
		joinRes, err := cluster.BootstrapJoin(sigCtx, cluster.BootstrapJoinOptions{
			JoinAddr:        p.joinAddr,
			JoinToken:       p.joinToken,
			NodeID:          effectiveNodeID,
			ClusterBindAddr: clusterBindAddr,
			AdvertiseAddr:   p.clusterAdvertise,
			ExecBindAddr:    execListenAddr,
			CertPath:        resolvedCert,
			KeyPath:         resolvedKey,
			CAPath:          resolvedCA,
			CRLPath:         resolvedCRL,
			StatePath:       resolvedState,
		})
		if err != nil {
			if p.joinToken == "" {
				_, _ = fmt.Fprintf(stderr, "Error: node is not yet bootstrapped and --join-token was omitted: %v\n", err)
				return exitError
			}
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return exitError
		}
		if joinRes.NodeID != "" {
			effectiveNodeID = joinRes.NodeID
		}
		if !joinRes.AlreadyBootstrapped {
			logger.Printf("joined cluster via %s (mode=%s node_id=%s serial=%s)",
				joinRes.SeedAddr, joinRes.Mode, joinRes.NodeID, joinRes.CertSerialHex)
		}
	}

	resolvedCAKey := ""
	if p.caKeyPath != "" {
		resolvedCAKey = config.ExpandPath(p.caKeyPath, homeDir, "")
	} else {
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

	var seedPeers []string
	if p.joinAddr != "" {
		seedPeers = append(seedPeers, p.joinAddr)
	}

	clusterEngine, err := cluster.NewEngine(cluster.Config{
		NodeID:          effectiveNodeID,
		ClusterBindAddr: clusterBindAddr,
		AdvertiseAddr:   p.clusterAdvertise,
		ExecAddr:        execListenAddr,
		CertPath:        resolvedCert,
		KeyPath:         resolvedKey,
		CAPath:          resolvedCA,
		CAKeyPath:       resolvedCAKey,
		StatePath:       resolvedState,
		SeedPeers:       seedPeers,
		CRLWatcher:      crlWatcher,
		Logger:          logger,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
	defer func() {
		_ = clusterEngine.Close()
	}()

	srvCfg := server.Config{
		BindIP:         p.bindIP,
		Port:           effectivePort,
		CertPath:       resolvedCert,
		KeyPath:        resolvedKey,
		CAPath:         resolvedCA,
		CRLPath:        resolvedCRL,
		CRLWatcher:     crlWatcher,
		PolicyProvider: clusterEngine,
		Shell:          p.shell,
		ShellExplicit:  p.shellExplicit,
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

	if err := clusterEngine.Start(context.Background()); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
	<-clusterEngine.Ready()

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
				srv.Addr(),
				resolvedShell,
				srvCfg.CRLPath,
				clusterEngine.Addr(),
			)
		case <-readyStop:
		}
	}()

	serveErr := srv.ListenAndServe(sigCtx)
	close(readyStop)
	<-readyLogDone

	// Explicit ordered teardown: srv -> clusterEngine -> crlWatcher (defers remain idempotent safety nets).
	_ = srv.Close()
	_ = clusterEngine.Close()
	_ = crlWatcher.Close()

	if serveErr != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", serveErr)
		return exitError
	}
	return exitOK
}

func runExec(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("exec")
	host := fs.String("host", "", "Named host profile from config.json")
	endpoint := fs.String("endpoint", "", "Target host:port override")
	certPath := fs.String("cert", "", "Client certificate PEM path")
	keyPath := fs.String("key", "", "Client private key PEM path")
	caPath := fs.String("ca", "", "Root CA certificate PEM path")
	timeout := fs.String("timeout", "", "Execution timeout (e.g. 60s, 2m; max 600s)")

	if code, handled := parseFlags(fs, args, stdout, stderr, printExecUsage); handled {
		return code
	}

	command := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if command == "" {
		_, _ = fmt.Fprintln(stderr, "Error: missing <COMMAND> argument")
		printExecUsage(stderr)
		return exitUsage
	}

	resolvedCfg, err := config.Resolve(config.FlagOverrides{
		Host:     *host,
		Endpoint: *endpoint,
		CertPath: *certPath,
		KeyPath:  *keyPath,
		CAPath:   *caPath,
		Timeout:  *timeout,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	exitCode, err := client.Run(sigCtx, resolvedCfg, command, stdout, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		if exitCode != 0 {
			return exitCode
		}
		return exitError
	}
	return exitCode
}

func fileExistsRegular(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func sanitizeDirName(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "node-1"
	}
	var sb strings.Builder
	sb.Grow(len(trimmed))
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		if (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('_')
		}
	}
	out := strings.Trim(sb.String(), "._ ")
	if out == "" {
		return "node-1"
	}
	if len(out) > 96 {
		out = out[:96]
	}
	return out
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parseFlags(
	fs *flag.FlagSet,
	args []string,
	stdout, stderr io.Writer,
	usageFn func(io.Writer),
) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usageFn(stdout)
			return exitOK, true
		}
		_, _ = fmt.Fprintf(stderr, "Error: %v\n\n", err)
		usageFn(stderr)
		return exitUsage, true
	}
	return exitOK, false
}

func printRootUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `Usage: agent-bridge <command> [flags]

Commands:
  ca init       Initialize ECDSA P-256 Root CA and empty CRL
  ca issue      Issue server, client, or peer certificate
  ca revoke     Revoke certificate serial and update CRL
  cluster       Manage multi-node cluster tokens, status, peers, and sync
  server        Run mTLS 1.3 WebSocket execution daemon (standalone or clustered)
  exec          Execute synchronous command on remote host
  version       Print binary version (%s)

Run 'agent-bridge <command> --help' for command flags.
`, version)
}

func printCAUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge ca <subcommand> [flags]

Subcommands:
  init          Initialize Root CA (ca.crt, ca.key, crl.pem)
  issue         Issue server, client, or peer certificate
  revoke        Revoke certificate serial and regenerate CRL
`)
}

func printCAInitUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `Usage: agent-bridge ca init --out-dir <dir> [flags]

Flags:
  --out-dir <path>         Output directory for ca.crt, ca.key, and crl.pem (required)
  --common-name <string>   Root CA Common Name (default %q)
  --org <string>           Root CA Organization (default %q)
  --years <int>            Validity in years (default %d)
`, pki.DefaultCACommonName, pki.DefaultCAOrg, pki.DefaultCAYears)
}

func printCAIssueUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `Usage: agent-bridge ca issue --ca-dir <dir> --type <server|client|peer> --name <cn> --out-dir <dir> [flags]

Flags:
  --ca-dir <path>              Directory containing ca.crt and ca.key (required)
  --type <server|client|peer>  Certificate profile: server, client, or peer (required)
  --name <string>              Subject Common Name (required)
  --out-dir <path>             Output directory for certificate and key (required)
  --ip <ip>                    Server/peer IPv4/IPv6 SAN (repeatable or comma-separated)
  --dns <hostname>             Server/peer DNS SAN (repeatable or comma-separated)
  --years <int>                Validity in years (default %d for server/peer, %d for client)
`, pki.DefaultServerYears, pki.DefaultClientYears)
}

func printCARevokeUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge ca revoke --ca-dir <dir> --serial <hex> [flags]

Flags:
  --ca-dir <path>          Directory containing ca.crt and ca.key (required)
  --serial <hex>           Certificate serial number in hex (required)
  --crl-out <path>         Output CRL path (default <ca-dir>/crl.pem)
`)
}

func printServerUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `Usage: agent-bridge server --bind <ip> [flags]

Execution Listener & PKI Flags:
  --bind <ip>                   IP address to bind listener (required)
  --port <int>                  WebSocket mTLS TCP port (default %d)
  --cert <path>                 Server certificate PEM path (required unless joining via CSR)
  --key <path>                  Server private key PEM path (required unless joining via CSR)
  --ca <path>                   Root CA certificate PEM path (required unless joining via CSR)
  --crl <path>                  CRL PEM path (required unless joining via CSR)
  --shell <name>                Execution shell: powershell, pwsh, cmd, sh, bash (default %q)

Multi-Node Cluster Flags:
  --cluster-bind <ip:port>      Cluster TLS 1.3 gossip/admin bind address (defaults to <bind>:%d with --join)
  --cluster-advertise <ip:port> Advertised cluster host:port (defaults to --cluster-bind)
  --join <peer_ip:port>         Existing cluster peer address to bootstrap and seed from
  --join-token <token>          Single-use Root-CA-pinned join token (abjt1...)
  --node-id <id>                Unique cluster node ID (defaults to leaf cert CN or hostname)
  --ca-key <path>               Root CA private key PEM path for signing CSRs (auto-discovered beside --ca if present)
  --cluster-state <path>        Persistent cluster state JSON path
  --data-dir <path>             Directory for node PKI/state files when --join omits --cert/--key/--ca/--crl
`, protocol.DefaultPort, runner.DefaultShell(), config.DefaultClusterPort)
}

func printExecUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge exec [flags] "<COMMAND>"

Flags:
  --host <name>            Named host profile from config.json
  --endpoint <ip:port>     Target host:port override
  --cert <path>            Client certificate PEM path
  --key <path>             Client private key PEM path
  --ca <path>              Root CA certificate PEM path
  --timeout <duration>     Execution timeout, e.g. 60s or 2m (default 60s, max 600s)
`)
}
