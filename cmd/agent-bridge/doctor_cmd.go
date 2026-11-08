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

	"github.com/kennyparsons/agent-bridge/internal/acl"
	"github.com/kennyparsons/agent-bridge/internal/config"
	"github.com/kennyparsons/agent-bridge/internal/doctor"
	"github.com/kennyparsons/agent-bridge/internal/netbind"
	"github.com/kennyparsons/agent-bridge/internal/pki"
	"github.com/kennyparsons/agent-bridge/internal/protocol"
	"github.com/kennyparsons/agent-bridge/internal/service"
)

const checkIDACLPermissions = "acl_permissions"

func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("doctor")
	dataDir := fs.String("data-dir", "", "Server node PKI and state directory")
	serviceCfgFlag := fs.String("service-config", "", "Optional server.json path")
	fs.StringVar(serviceCfgFlag, "config", "", "Alias for --service-config")

	var seedsFlag stringSliceFlag
	fs.Var(&seedsFlag, "seed", "Cluster seed peer address(es) to probe (repeatable or CSV)")
	fs.Var(&seedsFlag, "join", "Cluster join seed address(es) to probe (repeatable or CSV)")

	var bindFlag stringSliceFlag
	fs.Var(&bindFlag, "bind", "Exec bind selector(s) to check for port availability and SANs (repeatable or CSV)")
	port := fs.Int("port", protocol.DefaultPort, "Exec TCP port")

	var clusterBindFlag stringSliceFlag
	fs.Var(&clusterBindFlag, "cluster-bind", "Cluster bind selector(s) to check (repeatable or CSV)")
	clusterPort := fs.Int("cluster-port", config.DefaultClusterPort, "Cluster control-plane TCP port")

	certFlag := fs.String("cert", "", "Node certificate PEM path")
	caFlag := fs.String("ca", "", "Root CA certificate PEM path")
	crlFlag := fs.String("crl", "", "CRL PEM path")
	strictSANs := fs.Bool("strict-sans", false, "Treat missing live NIC SANs on node certificate as FAIL instead of WARN")
	requirePKI := fs.Bool("require-pki", false, "Fail when node certificate, Root CA, or CRL files are absent")
	daemonRunning := fs.Bool("daemon-running", false, "Skip local bind port probe when daemon is already bound")
	jsonOut := fs.Bool("json", false, "Format diagnostic report as indented JSON")

	if code, handled := parseFlags(fs, args, stdout, stderr, printDoctorUsage); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		printDoctorUsage(stderr)
		return exitUsage
	}

	visited := visitedFlags(fs)
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
		defPaths := service.DefaultPaths()
		if fileExistsRegular(defPaths.ConfigPath) {
			resolvedServiceCfg = defPaths.ConfigPath
		}
	}

	var loadedCfg *service.ServerDaemonConfig
	var cfgBaseDir string
	if resolvedServiceCfg != "" && (visited["service-config"] || visited["config"] || fileExistsRegular(resolvedServiceCfg)) {
		cfg, err := service.LoadServerDaemonConfig(resolvedServiceCfg)
		if err != nil {
			if visited["service-config"] || visited["config"] {
				_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
				return exitError
			}
		} else {
			loadedCfg = cfg
			cfgBaseDir = filepath.Dir(resolvedServiceCfg)
		}
	}

	bindSpecs := netbind.SplitTokens(bindFlag)
	clusterBindSpecs := netbind.SplitTokens(clusterBindFlag)
	seeds := netbind.SplitTokens(seedsFlag)
	effectivePort := *port
	effectiveClusterPort := *clusterPort
	certPath := ""
	keyPath := ""
	caPath := ""
	crlPath := ""

	if loadedCfg != nil {
		if resolvedDataDir == "" && strings.TrimSpace(loadedCfg.DataDir) != "" {
			resolvedDataDir = config.ExpandPath(loadedCfg.DataDir, homeDir, cfgBaseDir)
		}
		if !visited["bind"] && len(loadedCfg.BindSpecs) > 0 {
			bindSpecs = netbind.SplitTokens(loadedCfg.BindSpecs)
		}
		if !visited["port"] && loadedCfg.Port > 0 {
			effectivePort = loadedCfg.Port
		}
		if !visited["cluster-bind"] && len(loadedCfg.ClusterBindSpecs) > 0 {
			clusterBindSpecs = netbind.SplitTokens(loadedCfg.ClusterBindSpecs)
		}
		if !visited["seed"] && !visited["join"] {
			if len(loadedCfg.SeedPeers) > 0 {
				seeds = append(seeds, netbind.SplitTokens(loadedCfg.SeedPeers)...)
			}
			if strings.TrimSpace(loadedCfg.JoinAddr) != "" {
				seeds = append(seeds, netbind.SplitTokens([]string{loadedCfg.JoinAddr})...)
			}
		}
		if strings.TrimSpace(loadedCfg.CertPath) != "" {
			certPath = config.ExpandPath(loadedCfg.CertPath, homeDir, cfgBaseDir)
		}
		if strings.TrimSpace(loadedCfg.KeyPath) != "" {
			keyPath = config.ExpandPath(loadedCfg.KeyPath, homeDir, cfgBaseDir)
		}
		if strings.TrimSpace(loadedCfg.CAPath) != "" {
			caPath = config.ExpandPath(loadedCfg.CAPath, homeDir, cfgBaseDir)
		}
		if strings.TrimSpace(loadedCfg.CRLPath) != "" {
			crlPath = config.ExpandPath(loadedCfg.CRLPath, homeDir, cfgBaseDir)
		}
	}

	if resolvedDataDir != "" {
		candCert, candKey := config.ResolveNodeCertPaths(resolvedDataDir)
		if certPath == "" && (*requirePKI || fileExistsRegular(candCert)) {
			certPath = candCert
		}
		if keyPath == "" && fileExistsRegular(candKey) {
			keyPath = candKey
		}
		candCA := filepath.Join(resolvedDataDir, pki.CACertFilename)
		if caPath == "" && (*requirePKI || fileExistsRegular(candCA)) {
			caPath = candCA
		}
		candCRL := filepath.Join(resolvedDataDir, pki.CRLFilename)
		if crlPath == "" && (*requirePKI || fileExistsRegular(candCRL)) {
			crlPath = candCRL
		}
	}

	if visited["cert"] {
		certPath = config.ExpandPath(*certFlag, homeDir, "")
	}
	if visited["ca"] {
		caPath = config.ExpandPath(*caFlag, homeDir, "")
	}
	if visited["crl"] {
		crlPath = config.ExpandPath(*crlFlag, homeDir, "")
	}

	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	effectiveDaemonRunning := *daemonRunning
	if !visited["daemon-running"] {
		if st, stErr := newServiceManager().Status(sigCtx, service.DefaultServiceName); stErr == nil && st != nil && st.Running {
			effectiveDaemonRunning = true
		}
	}

	report := doctor.Run(sigCtx, doctor.Options{
		Seeds:               seeds,
		BindSpecs:           bindSpecs,
		DefaultPort:         effectivePort,
		DaemonRunning:       effectiveDaemonRunning,
		ClusterBindSpecs:    clusterBindSpecs,
		ClusterPort:         effectiveClusterPort,
		CertPath:            certPath,
		CAPath:              caPath,
		CRLPath:             crlPath,
		RequirePKI:          *requirePKI,
		StrictInterfaceSANs: *strictSANs,
		DialTimeout:         5 * time.Second,
	})

	if aclChk, ok := buildDoctorACLCheck(resolvedDataDir, keyPath, resolvedServiceCfg); ok {
		report.Checks = append(report.Checks, aclChk)
	}

	if *jsonOut {
		if code := writeIndentedJSON(stdout, stderr, report); code != exitOK {
			return code
		}
		if report.HasFailures() {
			return exitError
		}
		return exitOK
	}

	for _, chk := range report.Checks {
		tag := "[PASS]"
		switch chk.Status {
		case doctor.StatusWarn:
			tag = "[WARN]"
		case doctor.StatusFail:
			tag = "[FAIL]"
		}
		_, _ = fmt.Fprintf(stdout, "%s %-20s %s\n", tag, chk.ID, chk.Summary)
		if chk.Remediation != "" && chk.Status != doctor.StatusPass {
			_, _ = fmt.Fprintf(stdout, "       Remediation: %s\n", chk.Remediation)
		}
	}

	if report.HasFailures() {
		return exitError
	}
	return exitOK
}

func buildDoctorACLCheck(dataDir, keyPath, serviceCfgPath string) (doctor.CheckResult, bool) {
	var targets []string
	seen := make(map[string]struct{})
	addIfExists := func(p string) {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			return
		}
		clean := filepath.Clean(trimmed)
		if _, exists := seen[clean]; exists {
			return
		}
		if _, err := os.Stat(clean); err == nil {
			seen[clean] = struct{}{}
			targets = append(targets, clean)
		}
	}

	addIfExists(dataDir)
	addIfExists(keyPath)
	addIfExists(serviceCfgPath)

	if len(targets) == 0 {
		return doctor.CheckResult{}, false
	}

	var violations []string
	var summaries []string
	for _, t := range targets {
		st, err := acl.AuditPathACL(t, false)
		if err != nil {
			violations = append(violations, fmt.Sprintf("%s: %v", t, err))
			continue
		}
		if !st.Secure {
			if len(st.Violations) > 0 {
				violations = append(violations, fmt.Sprintf("%s: %s", t, strings.Join(st.Violations, "; ")))
			} else {
				violations = append(violations, fmt.Sprintf("%s: %s", t, st.Summary))
			}
			continue
		}
		summaries = append(summaries, fmt.Sprintf("%s (%s)", filepath.Base(t), st.Summary))
	}

	if len(violations) > 0 {
		remediation := "Restrict directory permissions to 0700 and private files to 0600 (or re-run 'agent-bridge service install')."
		if runtime.GOOS == "windows" {
			remediation = "Re-run 'agent-bridge service install' to enforce protected SDDL DACLs (NT AUTHORITY\\SYSTEM + BUILTIN\\Administrators)."
		}
		return doctor.CheckResult{
			ID:          checkIDACLPermissions,
			Status:      doctor.StatusFail,
			Summary:     strings.Join(violations, " | "),
			Remediation: remediation,
		}, true
	}

	return doctor.CheckResult{
		ID:      checkIDACLPermissions,
		Status:  doctor.StatusPass,
		Summary: fmt.Sprintf("verified locked-down ACLs on %d path(s): %s", len(targets), strings.Join(summaries, ", ")),
	}, true
}

func printDoctorUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `Usage: agent-bridge doctor [flags]

Flags:
  --data-dir <path>         Server PKI and state directory to audit
  --service-config <path>   Optional server.json path to load defaults from
  --seed, --join <addrs>    Cluster seed peer address(es) to probe (repeatable or CSV)
  --bind <spec>             Exec bind selector(s) to check (repeatable or CSV)
  --port <int>              Exec TCP port (default %d)
  --cluster-bind <spec>     Cluster bind selector(s) to check (repeatable or CSV)
  --cluster-port <int>      Cluster TCP port (default %d)
  --cert <path>             Node certificate PEM path
  --ca <path>               Root CA certificate PEM path
  --crl <path>              CRL PEM path
  --strict-sans             Fail (instead of warn) if active NIC IPs are absent from cert SANs
  --require-pki             Fail if certificate, CA, or CRL files are missing
  --daemon-running          Skip local socket bind probe when daemon is already active
  --json                    Format report as indented JSON
`, protocol.DefaultPort, config.DefaultClusterPort)
}
