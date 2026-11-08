package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kennyparsons/agent-bridge/cluster"
	"github.com/kennyparsons/agent-bridge/internal/acl"
	"github.com/kennyparsons/agent-bridge/internal/config"
	"github.com/kennyparsons/agent-bridge/internal/pki"
)

const (
	maxBundleStdinBytes  = 4 * 1024 * 1024
	defaultVerifyTimeout = 10 * time.Second
)

func runCA(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printCAUsage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "init":
		return runCAInit(args[1:], stdout, stderr)
	case "issue":
		return runCAIssue(args[1:], stdout, stderr)
	case "bundle":
		return runCABundle(args[1:], stdout, stderr)
	case "revoke":
		return runCARevoke(ctx, args[1:], stdout, stderr)
	case "help", "--help", "-help", "-h":
		printCAUsage(stdout)
		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "Error: unknown ca subcommand %q\n\n", args[0])
		printCAUsage(stderr)
		return exitUsage
	}
}

type caInitOutput struct {
	CACertPath      string   `json:"ca_cert_path"`
	CAKeyPath       string   `json:"ca_key_path"`
	CRLPath         string   `json:"crl_path"`
	CASerialHex     string   `json:"serial_hex"`
	NodeName        string   `json:"node_name,omitempty"`
	ServerCertPath  string   `json:"server_cert_path,omitempty"`
	ServerKeyPath   string   `json:"server_key_path,omitempty"`
	ServerSerialHex string   `json:"server_serial_hex,omitempty"`
	PeerCertPath    string   `json:"peer_cert_path,omitempty"`
	PeerKeyPath     string   `json:"peer_key_path,omitempty"`
	PeerSerialHex   string   `json:"peer_serial_hex,omitempty"`
	SANIPs          []string `json:"san_ips,omitempty"`
	SANDNS          []string `json:"san_dns,omitempty"`
}

func runCAInit(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("ca init")
	outDir := fs.String("out-dir", "", "Output directory for Root CA, initial CRL, and seed node certs (required)")
	commonName := fs.String("common-name", pki.DefaultCACommonName, "Root CA Subject Common Name")
	org := fs.String("org", pki.DefaultCAOrg, "Root CA Subject Organization")
	years := fs.Int("years", pki.DefaultCAYears, "Root CA and CRL validity period in years")
	nodeName := fs.String("node-id", "", "Initial seed node Common Name for server.crt/peer.crt (defaults to hostname)")
	fs.StringVar(nodeName, "node-name", "", "Alias for --node-id")

	var sanIPsFlag stringSliceFlag
	var sanDNSFlag stringSliceFlag
	fs.Var(&sanIPsFlag, "san-ip", "Additional X.509 IP SAN(s) for initial seed server/peer certs (repeatable or CSV)")
	fs.Var(&sanDNSFlag, "san-dns", "Additional X.509 DNS SAN(s) for initial seed server/peer certs (repeatable or CSV)")
	noAutoSANs := fs.Bool("no-auto-sans", false, "Disable automatic active-NIC IP SAN discovery for seed certs")
	caOnly := fs.Bool("ca-only", false, "Generate only ca.crt, ca.key, and crl.pem without initial server/peer certs")
	jsonOut := fs.Bool("json", false, "Format output as indented JSON")

	if code, handled := parseFlags(fs, args, stdout, stderr, printCAInitUsage); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		printCAInitUsage(stderr)
		return exitUsage
	}
	if strings.TrimSpace(*outDir) == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --out-dir is required")
		printCAInitUsage(stderr)
		return exitUsage
	}

	homeDir, _ := os.UserHomeDir()
	resolvedOutDir := config.ExpandPath(*outDir, homeDir, "")

	res, err := pki.InitCA(pki.InitCAOptions{
		OutDir:     resolvedOutDir,
		CommonName: *commonName,
		Org:        *org,
		Years:      *years,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	out := caInitOutput{
		CACertPath:  res.CACertPath,
		CAKeyPath:   res.CAKeyPath,
		CRLPath:     res.CRLPath,
		CASerialHex: res.SerialHex,
	}

	if !*caOnly {
		effectiveNode := strings.TrimSpace(*nodeName)
		if effectiveNode == "" {
			if host, hErr := os.Hostname(); hErr == nil {
				effectiveNode = strings.TrimSpace(host)
			}
		}
		if effectiveNode == "" {
			effectiveNode = "node-1"
		}

		extraIPs := append([]string(nil), sanIPsFlag...)
		extraDNS := append([]string(nil), sanDNSFlag...)
		if !*noAutoSANs {
			extraIPs = append([]string{"127.0.0.1", "::1"}, extraIPs...)
			extraDNS = append([]string{"localhost"}, extraDNS...)
		}
		ips, dnsNames := cluster.CollectNodeSANs(cluster.NodeSANOptions{
			Hostname:          effectiveNode,
			ExtraIPs:          extraIPs,
			ExtraDNSNames:     extraDNS,
			AutoInterfaceSANs: !*noAutoSANs,
		})

		srvRes, srvErr := pki.IssueCert(pki.IssueCertOptions{
			CADir:    resolvedOutDir,
			OutDir:   resolvedOutDir,
			Type:     pki.TypeServer,
			Name:     effectiveNode,
			IPs:      ips,
			DNSNames: dnsNames,
		})
		if srvErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: failed issuing initial server certificate: %v\n", srvErr)
			return exitError
		}

		peerRes, peerErr := pki.IssueCert(pki.IssueCertOptions{
			CADir:    resolvedOutDir,
			OutDir:   resolvedOutDir,
			Type:     pki.TypePeer,
			Name:     effectiveNode,
			IPs:      ips,
			DNSNames: dnsNames,
		})
		if peerErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: failed issuing initial peer certificate: %v\n", peerErr)
			return exitError
		}

		_ = acl.LockdownPrivateFile(srvRes.KeyPath)
		_ = acl.LockdownPrivateFile(peerRes.KeyPath)

		out.NodeName = effectiveNode
		out.ServerCertPath = srvRes.CertPath
		out.ServerKeyPath = srvRes.KeyPath
		out.ServerSerialHex = srvRes.SerialHex
		out.PeerCertPath = peerRes.CertPath
		out.PeerKeyPath = peerRes.KeyPath
		out.PeerSerialHex = peerRes.SerialHex
		out.SANIPs = ips
		out.SANDNS = dnsNames
	}

	if err := acl.LockdownServerDir(resolvedOutDir); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
	if err := acl.LockdownPrivateFile(res.CAKeyPath); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	if *jsonOut {
		return writeIndentedJSON(stdout, stderr, out)
	}

	_, _ = fmt.Fprintf(stdout, "CA Certificate: %s\n", out.CACertPath)
	_, _ = fmt.Fprintf(stdout, "CA Private Key: %s\n", out.CAKeyPath)
	_, _ = fmt.Fprintf(stdout, "CRL:            %s\n", out.CRLPath)
	_, _ = fmt.Fprintf(stdout, "Serial:         %s\n", out.CASerialHex)
	if out.ServerCertPath != "" {
		_, _ = fmt.Fprintf(stdout, "Server Cert:    %s (serial %s)\n", out.ServerCertPath, out.ServerSerialHex)
	}
	if out.PeerCertPath != "" {
		_, _ = fmt.Fprintf(stdout, "Peer Cert:      %s (serial %s)\n", out.PeerCertPath, out.PeerSerialHex)
	}
	if len(out.SANIPs) > 0 || len(out.SANDNS) > 0 {
		_, _ = fmt.Fprintf(stdout, "Node SANs:      IPs=[%s] DNS=[%s]\n",
			strings.Join(out.SANIPs, ","),
			strings.Join(out.SANDNS, ","),
		)
	}
	return exitOK
}

type caIssueOutput struct {
	Type            string   `json:"type"`
	CommonName      string   `json:"common_name"`
	SerialHex       string   `json:"serial_hex"`
	CertPath        string   `json:"cert_path,omitempty"`
	KeyPath         string   `json:"key_path,omitempty"`
	BundlePath      string   `json:"bundle_path,omitempty"`
	BundleEncrypted bool     `json:"bundle_encrypted,omitempty"`
	SANIPs          []string `json:"san_ips,omitempty"`
	SANDNS          []string `json:"san_dns,omitempty"`
}

func runCAIssue(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("ca issue")
	caDir := fs.String("ca-dir", "", "Directory containing ca.crt and ca.key (required)")
	certType := fs.String("type", "", "Certificate profile: server, client, or peer (required)")
	name := fs.String("name", "", "Subject Common Name (required)")
	outDir := fs.String("out-dir", "", "Output directory for PEM artifacts (optional when --bundle-out is set)")

	var ipsFlag stringSliceFlag
	var dnsFlag stringSliceFlag
	fs.Var(&ipsFlag, "ip", "IPv4/IPv6 SAN(s), repeatable or comma-separated")
	fs.Var(&ipsFlag, "san-ip", "Alias for --ip")
	fs.Var(&dnsFlag, "dns", "DNS SAN(s), repeatable or comma-separated")
	fs.Var(&dnsFlag, "san-dns", "Alias for --dns")
	autoSANs := fs.Bool("auto-sans", false, "Automatically harvest active local NIC IP SANs")
	noAutoSANs := fs.Bool("no-auto-sans", false, "Disable automatic local NIC IP SAN fallback on server/peer certs")
	years := fs.Int("years", 0, "Certificate validity in years (default: 3 server/peer, 1 client)")

	bundleOut := fs.String("bundle-out", "", "Optional output .abbundle path (or '-' for stdout) for client onboarding")
	passphraseEnv := fs.String("passphrase-env", "", "Environment variable name holding AES-256-GCM passphrase for --bundle-out")
	endpoint := fs.String("endpoint", "", "Optional default host:port endpoint embedded in client bundle")
	clusterEndpoint := fs.String("cluster-endpoint", "", "Optional cluster host:port endpoint embedded in client bundle")
	var hostsFlag stringSliceFlag
	fs.Var(&hostsFlag, "hosts", "Named host profile(s) alias=host:port[@cluster_host:port] for client bundle (repeatable or CSV)")
	defaultHost := fs.String("default-host", "", "Default host alias in client bundle")
	timeout := fs.String("timeout", "", "Default execution timeout in client bundle (e.g. 60s)")
	jsonOut := fs.Bool("json", false, "Format output as indented JSON")

	if code, handled := parseFlags(fs, args, stdout, stderr, printCAIssueUsage); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		printCAIssueUsage(stderr)
		return exitUsage
	}

	trimmedCADir := strings.TrimSpace(*caDir)
	trimmedType := strings.ToLower(strings.TrimSpace(*certType))
	trimmedName := strings.TrimSpace(*name)
	trimmedOutDir := strings.TrimSpace(*outDir)
	trimmedBundleOut := strings.TrimSpace(*bundleOut)

	var missing []string
	if trimmedCADir == "" {
		missing = append(missing, "--ca-dir")
	}
	if trimmedType == "" {
		missing = append(missing, "--type")
	}
	if trimmedName == "" {
		missing = append(missing, "--name")
	}
	if trimmedOutDir == "" && trimmedBundleOut == "" {
		missing = append(missing, "--out-dir (or --bundle-out)")
	}
	if len(missing) > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: missing required flag(s): %s\n", strings.Join(missing, ", "))
		printCAIssueUsage(stderr)
		return exitUsage
	}

	if trimmedBundleOut != "" && trimmedType == pki.TypeServer {
		_, _ = fmt.Fprintln(stderr, "Error: --bundle-out requires --type client (or --type peer) possessing ClientAuth EKU")
		printCAIssueUsage(stderr)
		return exitUsage
	}
	if trimmedBundleOut == "-" && *jsonOut {
		_, _ = fmt.Fprintln(stderr, "Error: --bundle-out - cannot be combined with --json")
		printCAIssueUsage(stderr)
		return exitUsage
	}

	passphrase, err := resolveOptionalPassphraseFromEnv(*passphraseEnv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	homeDir, _ := os.UserHomeDir()
	expandedCADir := config.ExpandPath(trimmedCADir, homeDir, "")

	var effectiveOutDir string
	keepPEMFiles := trimmedOutDir != ""
	if keepPEMFiles {
		effectiveOutDir = config.ExpandPath(trimmedOutDir, homeDir, "")
	} else {
		tmpDir, tmpErr := os.MkdirTemp("", "agent-bridge-issue-*")
		if tmpErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: failed creating temporary staging directory: %v\n", tmpErr)
			return exitError
		}
		defer func() {
			_ = os.RemoveAll(tmpDir)
		}()
		effectiveOutDir = tmpDir
	}

	ips := []string(ipsFlag)
	dnsNames := []string(dnsFlag)
	if (trimmedType == pki.TypeServer || trimmedType == pki.TypePeer) &&
		(*autoSANs || (len(ips) == 0 && len(dnsNames) == 0 && !*noAutoSANs)) {
		ips, dnsNames = cluster.CollectNodeSANs(cluster.NodeSANOptions{
			Hostname:          trimmedName,
			ExtraIPs:          append([]string{"127.0.0.1", "::1"}, ips...),
			ExtraDNSNames:     append([]string{"localhost"}, dnsNames...),
			AutoInterfaceSANs: true,
		})
	}

	res, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:    expandedCADir,
		OutDir:   effectiveOutDir,
		Type:     trimmedType,
		Name:     trimmedName,
		IPs:      ips,
		DNSNames: dnsNames,
		Years:    *years,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	if keepPEMFiles {
		_ = acl.LockdownPrivateFile(res.KeyPath)
	}

	var resolvedBundlePath string
	if trimmedBundleOut != "" {
		bundleOpts, bErr := buildBundleMetadataOptions(
			filepath.Join(expandedCADir, pki.CACertFilename),
			res.CertPath,
			res.KeyPath,
			"",
			*endpoint,
			*clusterEndpoint,
			hostsFlag,
			*defaultHost,
			*timeout,
		)
		if bErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", bErr)
			return exitError
		}
		bundle, buildErr := pki.BuildClientBundle(bundleOpts)
		if buildErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", buildErr)
			return exitError
		}

		if trimmedBundleOut == "-" {
			rawBundle, mErr := pki.MarshalBundle(bundle, passphrase)
			if mErr != nil {
				_, _ = fmt.Fprintf(stderr, "Error: %v\n", mErr)
				return exitError
			}
			_, _ = stdout.Write(rawBundle)
			return exitOK
		}

		resolvedBundlePath = config.ExpandPath(trimmedBundleOut, homeDir, "")
		if wErr := pki.WriteBundleFile(resolvedBundlePath, bundle, passphrase); wErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", wErr)
			return exitError
		}
	}

	var sanIPOut []string
	if res.Certificate != nil {
		for _, ip := range res.Certificate.IPAddresses {
			sanIPOut = append(sanIPOut, ip.String())
		}
	}
	var sanDNSOut []string
	if res.Certificate != nil && len(res.Certificate.DNSNames) > 0 {
		sanDNSOut = append([]string(nil), res.Certificate.DNSNames...)
	}

	out := caIssueOutput{
		Type:            trimmedType,
		CommonName:      trimmedName,
		SerialHex:       res.SerialHex,
		BundlePath:      resolvedBundlePath,
		BundleEncrypted: resolvedBundlePath != "" && passphrase != "",
		SANIPs:          sanIPOut,
		SANDNS:          sanDNSOut,
	}
	if keepPEMFiles {
		out.CertPath = res.CertPath
		out.KeyPath = res.KeyPath
	}

	if *jsonOut {
		return writeIndentedJSON(stdout, stderr, out)
	}

	if out.CertPath != "" {
		_, _ = fmt.Fprintf(stdout, "Certificate: %s\n", out.CertPath)
		_, _ = fmt.Fprintf(stdout, "Private Key: %s\n", out.KeyPath)
	}
	if out.BundlePath != "" {
		_, _ = fmt.Fprintf(stdout, "Bundle:      %s\n", out.BundlePath)
	}
	_, _ = fmt.Fprintf(stdout, "Serial:      %s\n", out.SerialHex)
	return exitOK
}

type caBundleOutput struct {
	BundlePath  string   `json:"bundle_path"`
	Encrypted   bool     `json:"encrypted"`
	DefaultHost string   `json:"default_host,omitempty"`
	Endpoint    string   `json:"endpoint,omitempty"`
	Hosts       []string `json:"hosts,omitempty"`
}

func runCABundle(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("ca bundle")
	caPath := fs.String("ca", "", "Root CA certificate PEM path (required)")
	certPath := fs.String("cert", "", "Client certificate PEM path (required)")
	keyPath := fs.String("key", "", "Client private key PEM path (required)")
	outPath := fs.String("out", "", "Output .abbundle path or '-' for stdout (required)")
	fs.StringVar(outPath, "bundle-out", "", "Alias for --out")
	name := fs.String("name", "", "Optional host profile alias when --endpoint is set without --hosts")
	passphraseEnv := fs.String("passphrase-env", "", "Environment variable name holding AES-256-GCM bundle passphrase")
	endpoint := fs.String("endpoint", "", "Default target host:port endpoint")
	clusterEndpoint := fs.String("cluster-endpoint", "", "Optional cluster control-plane host:port endpoint")
	var hostsFlag stringSliceFlag
	fs.Var(&hostsFlag, "hosts", "Named host profile(s) alias=host:port[@cluster_host:port] (repeatable or CSV)")
	defaultHost := fs.String("default-host", "", "Default host alias")
	timeout := fs.String("timeout", "", "Default execution timeout (e.g. 60s)")
	jsonOut := fs.Bool("json", false, "Format output as indented JSON")

	if code, handled := parseFlags(fs, args, stdout, stderr, printCABundleUsage); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		printCABundleUsage(stderr)
		return exitUsage
	}

	var missing []string
	if strings.TrimSpace(*caPath) == "" {
		missing = append(missing, "--ca")
	}
	if strings.TrimSpace(*certPath) == "" {
		missing = append(missing, "--cert")
	}
	if strings.TrimSpace(*keyPath) == "" {
		missing = append(missing, "--key")
	}
	if strings.TrimSpace(*outPath) == "" {
		missing = append(missing, "--out")
	}
	if len(missing) > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: missing required flag(s): %s\n", strings.Join(missing, ", "))
		printCABundleUsage(stderr)
		return exitUsage
	}

	trimmedOut := strings.TrimSpace(*outPath)
	if trimmedOut == "-" && *jsonOut {
		_, _ = fmt.Fprintln(stderr, "Error: --out - cannot be combined with --json")
		printCABundleUsage(stderr)
		return exitUsage
	}

	passphrase, err := resolveOptionalPassphraseFromEnv(*passphraseEnv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	homeDir, _ := os.UserHomeDir()
	bundleOpts, err := buildBundleMetadataOptions(
		config.ExpandPath(*caPath, homeDir, ""),
		config.ExpandPath(*certPath, homeDir, ""),
		config.ExpandPath(*keyPath, homeDir, ""),
		strings.TrimSpace(*name),
		*endpoint,
		*clusterEndpoint,
		hostsFlag,
		*defaultHost,
		*timeout,
	)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	bundle, err := pki.BuildClientBundle(bundleOpts)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	if trimmedOut == "-" {
		rawBundle, mErr := pki.MarshalBundle(bundle, passphrase)
		if mErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", mErr)
			return exitError
		}
		_, _ = stdout.Write(rawBundle)
		return exitOK
	}

	resolvedOut := config.ExpandPath(trimmedOut, homeDir, "")
	if err := pki.WriteBundleFile(resolvedOut, bundle, passphrase); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	var hostAliases []string
	for k := range bundle.Hosts {
		hostAliases = append(hostAliases, k)
	}
	sort.Strings(hostAliases)

	out := caBundleOutput{
		BundlePath:  resolvedOut,
		Encrypted:   passphrase != "",
		DefaultHost: bundle.DefaultHost,
		Endpoint:    bundle.Endpoint,
		Hosts:       hostAliases,
	}
	if *jsonOut {
		return writeIndentedJSON(stdout, stderr, out)
	}

	_, _ = fmt.Fprintf(stdout, "Bundle:       %s\n", out.BundlePath)
	_, _ = fmt.Fprintf(stdout, "Encrypted:    %t\n", out.Encrypted)
	if out.DefaultHost != "" {
		_, _ = fmt.Fprintf(stdout, "Default Host: %s\n", out.DefaultHost)
	}
	if len(out.Hosts) > 0 {
		_, _ = fmt.Fprintf(stdout, "Hosts:        %s\n", strings.Join(out.Hosts, ", "))
	}
	return exitOK
}

type caRevokeOutput struct {
	CRLPath           string `json:"crl_path"`
	CRLNumber         string `json:"crl_number"`
	RevokedSerialHex  string `json:"revoked_serial_hex"`
	AlreadyRevoked    bool   `json:"already_revoked"`
	RevokedCount      int    `json:"revoked_count"`
	ClusterSynced     bool   `json:"cluster_synced,omitempty"`
	ClusterCRLApplied bool   `json:"cluster_crl_applied,omitempty"`
	ClusterCRLNumber  string `json:"cluster_crl_number,omitempty"`
	SyncedPeers       int    `json:"synced_peers,omitempty"`
}

func runCARevoke(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("ca revoke")
	caDir := fs.String("ca-dir", "", "Directory containing ca.crt and ca.key (required)")
	serial := fs.String("serial", "", "Hexadecimal serial number to revoke (required unless --cert is passed)")
	certToRevoke := fs.String("cert", "", "Path to PEM certificate to revoke (required unless --serial is passed)")
	crlOut := fs.String("crl-out", "", "CRL file path to update (defaults to <ca-dir>/crl.pem)")

	syncCluster := fs.Bool("sync", false, "Immediately broadcast the updated CRL into the live cluster mesh")
	clusterAddr := fs.String("cluster-addr", "", "Target cluster control-plane host:port when --sync is set")
	host := fs.String("host", "", "Named host profile from config.json when --sync is set")
	dataDir := fs.String("data-dir", "", "Server node data directory for local mTLS credentials when --sync is set")
	serviceCfg := fs.String("service-config", "", "Server server.json path when --sync is set")
	clientCfg := fs.String("config", "", "Client config.json path override when --sync is set")
	authCert := fs.String("auth-cert", "", "Explicit mTLS client/peer certificate PEM for --sync")
	authKey := fs.String("auth-key", "", "Explicit mTLS client/peer private key PEM for --sync")
	caOverride := fs.String("ca", "", "Explicit Root CA PEM for --sync")
	timeout := fs.String("timeout", "", "Cluster sync timeout (e.g. 30s)")
	jsonOut := fs.Bool("json", false, "Format output as indented JSON")

	if code, handled := parseFlags(fs, args, stdout, stderr, printCARevokeUsage); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		printCARevokeUsage(stderr)
		return exitUsage
	}

	var missing []string
	if strings.TrimSpace(*caDir) == "" {
		missing = append(missing, "--ca-dir")
	}
	if strings.TrimSpace(*serial) == "" && strings.TrimSpace(*certToRevoke) == "" {
		missing = append(missing, "--serial or --cert")
	}
	if len(missing) > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: missing required flag(s): %s\n", strings.Join(missing, ", "))
		printCARevokeUsage(stderr)
		return exitUsage
	}

	homeDir, _ := os.UserHomeDir()
	expandedCADir := config.ExpandPath(*caDir, homeDir, "")
	expandedCert := ""
	if strings.TrimSpace(*certToRevoke) != "" {
		expandedCert = config.ExpandPath(*certToRevoke, homeDir, "")
	}
	expandedCRLOut := ""
	if strings.TrimSpace(*crlOut) != "" {
		expandedCRLOut = config.ExpandPath(*crlOut, homeDir, "")
	}

	res, err := pki.RevokeCert(pki.RevokeCertOptions{
		CADir:    expandedCADir,
		Serial:   strings.TrimSpace(*serial),
		CertPath: expandedCert,
		CRLOut:   expandedCRLOut,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	var crlNum string
	if res.CRLNumber != nil {
		crlNum = res.CRLNumber.String()
	}

	out := caRevokeOutput{
		CRLPath:          res.CRLPath,
		CRLNumber:        crlNum,
		RevokedSerialHex: res.SerialHex,
		AlreadyRevoked:   res.AlreadyRevoked,
		RevokedCount:     res.RevokedCount,
	}

	if *syncCluster {
		crlBytes, readErr := os.ReadFile(res.CRLPath)
		if readErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: failed reading updated CRL %q for --sync: %v\n", res.CRLPath, readErr)
			return exitError
		}

		// Fall back to --ca-dir node credentials if neither --data-dir nor --auth-cert was explicitly supplied.
		fallbackDataDir := strings.TrimSpace(*dataDir)
		if fallbackDataDir == "" && strings.TrimSpace(*authCert) == "" && strings.TrimSpace(*clientCfg) == "" {
			candCert, candKey := config.ResolveNodeCertPaths(expandedCADir)
			if fileExistsRegular(candCert) && fileExistsRegular(candKey) {
				fallbackDataDir = expandedCADir
			}
		}

		tf := clusterTargetFlags{
			clusterAddr:   clusterAddr,
			host:          host,
			certPath:      authCert,
			keyPath:       authKey,
			caPath:        caOverride,
			clientCfgPath: clientCfg,
			dataDir:       &fallbackDataDir,
			serviceCfg:    serviceCfg,
			timeout:       timeout,
		}
		cl, clErr := tf.newClient()
		if clErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: failed resolving cluster target for --sync: %v\n", clErr)
			return exitError
		}
		defer func() {
			_ = cl.Close()
		}()

		sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stopSignals()

		syncRes, syncErr := cl.Sync(sigCtx, cluster.SyncRequest{
			CRLPEM: string(crlBytes),
		})
		if syncErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cluster CRL sync failed: %v\n", syncErr)
			return exitError
		}
		out.ClusterSynced = true
		out.ClusterCRLApplied = syncRes.CRLApplied
		out.ClusterCRLNumber = syncRes.CRLNumber
		out.SyncedPeers = len(syncRes.SyncedPeers)
	}

	if *jsonOut {
		return writeIndentedJSON(stdout, stderr, out)
	}

	_, _ = fmt.Fprintf(stdout, "CRL:            %s\n", res.CRLPath)
	_, _ = fmt.Fprintf(stdout, "CRL Number:     %s\n", res.CRLNumber.String())
	_, _ = fmt.Fprintf(stdout, "Revoked Serial: %s\n", res.SerialHex)
	if out.ClusterSynced {
		_, _ = fmt.Fprintf(stdout, "Cluster Sync:   crl_number=%s peers=%d\n", out.ClusterCRLNumber, out.SyncedPeers)
	}
	return exitOK
}

func runClient(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printClientUsage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "init":
		return runClientInit(ctx, args[1:], stdin, stdout, stderr)
	case "verify":
		return runClientVerify(ctx, args[1:], stdout, stderr)
	case "help", "--help", "-help", "-h":
		printClientUsage(stdout)
		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "Error: unknown client subcommand %q\n\n", args[0])
		printClientUsage(stderr)
		return exitUsage
	}
}

func runHealth(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runClientVerifyWithUsage(ctx, "health", args, stdout, stderr, printHealthUsage)
}

type clientInitOutput struct {
	*config.InstallClientBundleResult
	Verified bool                     `json:"verified,omitempty"`
	Healthy  bool                     `json:"healthy,omitempty"`
	Probes   []clientVerifyHostResult `json:"probes,omitempty"`
}

func runClientInit(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("client init")
	bundleFlag := fs.String("bundle", "", "Path to .abbundle file or '-' for stdin (required)")
	configDirFlag := fs.String("config-dir", "", "Target client credential & configuration directory")
	configFileFlag := fs.String("config", "", "Target client config.json file path override")
	passphraseEnv := fs.String("passphrase-env", "", "Environment variable name holding decryption passphrase")
	overwrite := fs.Bool("overwrite", false, "Replace existing host entries instead of merging")
	defaultHost := fs.String("default-host", "", "Override default_host stored in config.json")
	verify := fs.Bool("verify", false, "Run live mTLS 1.3 health probe(s) against installed host(s)")
	timeout := fs.String("timeout", "", "Health probe timeout when --verify is passed (default 10s)")
	jsonOut := fs.Bool("json", false, "Format output as indented JSON")

	if code, handled := parseFlags(fs, args, stdout, stderr, printClientInitUsage); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		printClientInitUsage(stderr)
		return exitUsage
	}

	trimmedBundle := strings.TrimSpace(*bundleFlag)
	if trimmedBundle == "" {
		_, _ = fmt.Fprintln(stderr, "Error: missing required flag(s): --bundle")
		printClientInitUsage(stderr)
		return exitUsage
	}

	homeDir, _ := os.UserHomeDir()
	var rawBundle []byte
	var err error
	if trimmedBundle == "-" {
		rawBundle, err = io.ReadAll(io.LimitReader(stdin, maxBundleStdinBytes))
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: failed reading bundle from stdin: %v\n", err)
			return exitError
		}
	} else {
		expandedBundle := config.ExpandPath(trimmedBundle, homeDir, "")
		rawBundle, err = os.ReadFile(expandedBundle)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: failed reading bundle %q: %v\n", expandedBundle, err)
			return exitError
		}
	}

	passphrase, err := resolveOptionalPassphraseFromEnv(*passphraseEnv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
	if passphrase == "" && pki.IsEncryptedBundle(rawBundle) {
		_, _ = fmt.Fprintln(stderr, "Error: bundle is encrypted (abbundle.enc.v1); pass --passphrase-env <ENV_VAR> with the decryption passphrase")
		return exitError
	}

	bundle, err := pki.UnmarshalBundle(rawBundle, passphrase)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	if dh := strings.TrimSpace(*defaultHost); dh != "" {
		bundle.DefaultHost = dh
		if vErr := bundle.Validate(); vErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", vErr)
			return exitError
		}
	}

	targetDir := ""
	customConfigPath := ""
	if strings.TrimSpace(*configDirFlag) != "" {
		targetDir = config.ExpandPath(*configDirFlag, homeDir, "")
	}
	if strings.TrimSpace(*configFileFlag) != "" {
		customConfigPath = config.ExpandPath(*configFileFlag, homeDir, "")
		if targetDir == "" {
			targetDir = filepath.Dir(customConfigPath)
		}
	}

	installRes, err := config.InstallClientBundleWithOptions(bundle, config.InstallClientBundleOptions{
		ConfigDir: targetDir,
		Overwrite: *overwrite,
		HomeDir:   homeDir,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	if customConfigPath != "" && filepath.Clean(customConfigPath) != filepath.Clean(installRes.ConfigPath) {
		cfgBytes, rErr := os.ReadFile(installRes.ConfigPath)
		if rErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", rErr)
			return exitError
		}
		if wErr := pki.WriteFileAtomic(customConfigPath, cfgBytes, 0o600); wErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", wErr)
			return exitError
		}
		_ = acl.LockdownClientFile(customConfigPath)
		installRes.ConfigPath = customConfigPath
	}

	_ = acl.LockdownClientDir(installRes.ConfigDir)
	_ = acl.LockdownClientFile(installRes.ClientKeyPath)
	_ = acl.LockdownClientFile(installRes.ConfigPath)

	out := clientInitOutput{
		InstallClientBundleResult: installRes,
	}

	if *verify {
		sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stopSignals()

		probeAll := len(installRes.InstalledHosts) > 1
		rep, vErr := executeClientVerifyProbes(sigCtx, verifyProbeOptions{
			configPath: installRes.ConfigPath,
			all:        probeAll,
			timeout:    strings.TrimSpace(*timeout),
			isolated:   true,
		})
		if vErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: post-install mTLS verification failed: %v\n", vErr)
			return exitError
		}
		out.Verified = true
		out.Healthy = rep.Healthy
		out.Probes = rep.Hosts

		if *jsonOut {
			if code := writeIndentedJSON(stdout, stderr, out); code != exitOK {
				return code
			}
			if !rep.Healthy {
				return exitError
			}
			return exitOK
		}

		printClientInitHuman(stdout, installRes)
		printClientVerifyHuman(stdout, rep)
		if !rep.Healthy {
			return exitError
		}
		return exitOK
	}

	if *jsonOut {
		return writeIndentedJSON(stdout, stderr, out)
	}
	printClientInitHuman(stdout, installRes)
	return exitOK
}

func printClientInitHuman(w io.Writer, res *config.InstallClientBundleResult) {
	_, _ = fmt.Fprintf(w, "Config Dir:   %s\n", res.ConfigDir)
	_, _ = fmt.Fprintf(w, "Config File:  %s\n", res.ConfigPath)
	_, _ = fmt.Fprintf(w, "CA Cert:      %s\n", res.CACertPath)
	_, _ = fmt.Fprintf(w, "Client Cert:  %s\n", res.ClientCertPath)
	_, _ = fmt.Fprintf(w, "Client Key:   %s\n", res.ClientKeyPath)
	if res.DefaultHost != "" {
		_, _ = fmt.Fprintf(w, "Default Host: %s\n", res.DefaultHost)
	}
	if len(res.InstalledHosts) > 0 {
		_, _ = fmt.Fprintf(w, "Hosts:        %s\n", strings.Join(res.InstalledHosts, ", "))
	}
}

type clientVerifyHostResult struct {
	Host         string `json:"host,omitempty"`
	Endpoint     string `json:"endpoint"`
	Healthy      bool   `json:"healthy"`
	LatencyMS    int64  `json:"latency_ms"`
	TLSVersion   string `json:"tls_version,omitempty"`
	CipherSuite  string `json:"cipher_suite,omitempty"`
	ServerCN     string `json:"server_cn,omitempty"`
	ServerSerial string `json:"server_serial,omitempty"`
	Error        string `json:"error,omitempty"`
}

type clientVerifyReport struct {
	Healthy bool                     `json:"healthy"`
	Hosts   []clientVerifyHostResult `json:"hosts"`
}

type verifyProbeOptions struct {
	host       string
	endpoint   string
	all        bool
	allVisited bool
	configPath string
	caPath     string
	certPath   string
	keyPath    string
	serverName string
	timeout    string
	isolated   bool
}

func runClientVerify(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runClientVerifyWithUsage(ctx, "client verify", args, stdout, stderr, printClientVerifyUsage)
}

func runClientVerifyWithUsage(
	ctx context.Context,
	cmdName string,
	args []string,
	stdout, stderr io.Writer,
	usageFn func(io.Writer),
) int {
	fs := newFlagSet(cmdName)
	host := fs.String("host", "", "Named host alias or target host:port")
	endpoint := fs.String("endpoint", "", "Explicit target host:port override")
	all := fs.Bool("all", false, "Probe all configured hosts (default when multiple hosts exist and --host is omitted)")
	cfgPath := fs.String("config", "", "Client config.json path override")
	caPath := fs.String("ca", "", "Root CA certificate PEM path")
	certPath := fs.String("cert", "", "Client certificate PEM path")
	keyPath := fs.String("key", "", "Client private key PEM path")
	serverName := fs.String("server-name", "", "Optional TLS SNI / SAN hostname or IP override")
	timeout := fs.String("timeout", "", "Handshake probe timeout (default 10s)")
	jsonOut := fs.Bool("json", false, "Format verification report as indented JSON")

	if code, handled := parseFlags(fs, args, stdout, stderr, usageFn); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		usageFn(stderr)
		return exitUsage
	}

	visited := visitedFlags(fs)
	homeDir, _ := os.UserHomeDir()
	expandedCfg := ""
	if strings.TrimSpace(*cfgPath) != "" {
		expandedCfg = config.ExpandPath(*cfgPath, homeDir, "")
	}

	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	rep, err := executeClientVerifyProbes(sigCtx, verifyProbeOptions{
		host:       strings.TrimSpace(*host),
		endpoint:   strings.TrimSpace(*endpoint),
		all:        *all,
		allVisited: visited["all"],
		configPath: expandedCfg,
		caPath:     strings.TrimSpace(*caPath),
		certPath:   strings.TrimSpace(*certPath),
		keyPath:    strings.TrimSpace(*keyPath),
		serverName: strings.TrimSpace(*serverName),
		timeout:    strings.TrimSpace(*timeout),
		isolated:   expandedCfg != "",
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	if *jsonOut {
		if code := writeIndentedJSON(stdout, stderr, rep); code != exitOK {
			return code
		}
		if !rep.Healthy {
			return exitError
		}
		return exitOK
	}

	printClientVerifyHuman(stdout, rep)
	if !rep.Healthy {
		return exitError
	}
	return exitOK
}

func executeClientVerifyProbes(ctx context.Context, opts verifyProbeOptions) (*clientVerifyReport, error) {
	var resolveOpts config.ResolveOptions
	if opts.configPath != "" {
		resolveOpts.GlobalConfigPath = opts.configPath
		if opts.isolated {
			// Avoid accidentally mixing CWD .env or project-local agent-bridge.json when --config was explicitly given.
			resolveOpts.WorkDir = filepath.Dir(opts.configPath)
			resolveOpts.EnvLookup = func(string) (string, bool) { return "", false }
		}
	}

	var probeTimeout time.Duration = defaultVerifyTimeout
	if opts.timeout != "" {
		dur, _, err := config.ParseTimeout(opts.timeout)
		if err != nil {
			return nil, err
		}
		probeTimeout = dur
	}

	type targetSpec struct {
		label string
		cfg   *config.ResolvedConfig
	}
	var targets []targetSpec

	switch {
	case opts.endpoint != "":
		rc, err := config.ResolveWithOptions(config.FlagOverrides{
			Host:     opts.host,
			Endpoint: opts.endpoint,
			CAPath:   opts.caPath,
			CertPath: opts.certPath,
			KeyPath:  opts.keyPath,
			Timeout:  opts.timeout,
		}, resolveOpts)
		if err != nil {
			return nil, err
		}
		targets = append(targets, targetSpec{label: rc.Host, cfg: rc})

	case opts.host != "":
		rc, err := config.ResolveWithOptions(config.FlagOverrides{
			Host:     opts.host,
			CAPath:   opts.caPath,
			CertPath: opts.certPath,
			KeyPath:  opts.keyPath,
			Timeout:  opts.timeout,
		}, resolveOpts)
		if err != nil {
			// Allow --host <addr:port> direct endpoint syntax if not found in configured host aliases.
			if strings.Contains(err.Error(), "unknown host") {
				if _, _, normErr := config.NormalizeEndpoint(opts.host); normErr == nil {
					if rcDirect, dErr := config.ResolveWithOptions(config.FlagOverrides{
						Endpoint: opts.host,
						CAPath:   opts.caPath,
						CertPath: opts.certPath,
						KeyPath:  opts.keyPath,
						Timeout:  opts.timeout,
					}, resolveOpts); dErr == nil {
						rc = rcDirect
						err = nil
					}
				}
			}
			if err != nil {
				return nil, err
			}
		}
		targets = append(targets, targetSpec{label: rc.Host, cfg: rc})

	default:
		hostAliases := discoverConfiguredHostAliases(opts.configPath, opts.isolated)
		shouldProbeAll := opts.all
		if !opts.allVisited && len(hostAliases) > 1 {
			shouldProbeAll = true
		}

		if shouldProbeAll && len(hostAliases) > 0 {
			for _, alias := range hostAliases {
				rc, err := config.ResolveWithOptions(config.FlagOverrides{
					Host:     alias,
					CAPath:   opts.caPath,
					CertPath: opts.certPath,
					KeyPath:  opts.keyPath,
					Timeout:  opts.timeout,
				}, resolveOpts)
				if err != nil {
					return nil, err
				}
				targets = append(targets, targetSpec{label: alias, cfg: rc})
			}
		} else {
			rc, err := config.ResolveWithOptions(config.FlagOverrides{
				CAPath:   opts.caPath,
				CertPath: opts.certPath,
				KeyPath:  opts.keyPath,
				Timeout:  opts.timeout,
			}, resolveOpts)
			if err != nil {
				return nil, err
			}
			targets = append(targets, targetSpec{label: rc.Host, cfg: rc})
		}
	}

	results := make([]clientVerifyHostResult, 0, len(targets))
	allHealthy := true
	for _, t := range targets {
		res := probeSingleHostMTLS(ctx, t.label, t.cfg, opts.serverName, probeTimeout)
		if !res.Healthy {
			allHealthy = false
		}
		results = append(results, res)
	}

	return &clientVerifyReport{
		Healthy: allHealthy,
		Hosts:   results,
	}, nil
}

func discoverConfiguredHostAliases(explicitCfgPath string, isolated bool) []string {
	seen := make(map[string]struct{})
	addFromFile := func(path string) {
		if !fileExistsRegular(path) {
			return
		}
		fc, err := config.LoadFileConfig(path)
		if err != nil || fc == nil {
			return
		}
		for alias, hc := range fc.Hosts {
			trimmed := strings.TrimSpace(alias)
			if trimmed != "" && strings.TrimSpace(hc.Endpoint) != "" {
				seen[trimmed] = struct{}{}
			}
		}
	}

	if explicitCfgPath != "" {
		addFromFile(explicitCfgPath)
	} else {
		if globalPath, err := config.DefaultGlobalConfigPath(); err == nil && globalPath != "" {
			addFromFile(globalPath)
		}
	}
	if !isolated {
		if cwd, err := os.Getwd(); err == nil {
			addFromFile(filepath.Join(cwd, config.LocalConfigFilename))
		}
	}

	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func probeSingleHostMTLS(
	ctx context.Context,
	hostLabel string,
	cfg *config.ResolvedConfig,
	serverName string,
	timeout time.Duration,
) clientVerifyHostResult {
	start := time.Now()
	out := clientVerifyHostResult{
		Host:     hostLabel,
		Endpoint: cfg.Endpoint,
	}

	clientCert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		out.LatencyMS = time.Since(start).Milliseconds()
		out.Error = fmt.Sprintf("failed to load client mTLS keypair: %v", err)
		return out
	}

	_, caPool, err := pki.LoadCACertPool(cfg.CAPath)
	if err != nil {
		out.LatencyMS = time.Since(start).Milliseconds()
		out.Error = fmt.Sprintf("failed to load Root CA certificate: %v", err)
		return out
	}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   strings.TrimSpace(serverName),
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := websocket.Dialer{
		TLSClientConfig:  tlsCfg,
		HandshakeTimeout: timeout,
	}

	conn, httpResp, dialErr := dialer.DialContext(probeCtx, cfg.WSURL, nil)
	out.LatencyMS = time.Since(start).Milliseconds()
	if dialErr != nil {
		out.Error = formatProbeDialError(cfg.Endpoint, dialErr, httpResp)
		return out
	}
	if httpResp != nil && httpResp.Body != nil {
		_ = httpResp.Body.Close()
	}
	defer func() {
		_ = conn.Close()
	}()

	if tlsConn, ok := conn.NetConn().(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		out.TLSVersion = tlsVersionLabel(state.Version)
		out.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
		if len(state.PeerCertificates) > 0 && state.PeerCertificates[0] != nil {
			leaf := state.PeerCertificates[0]
			out.ServerCN = leaf.Subject.CommonName
			out.ServerSerial = pki.FormatSerialHex(leaf.SerialNumber)
		}
	}

	_ = conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(2*time.Second),
	)
	out.Healthy = true
	return out
}

func formatProbeDialError(endpoint string, err error, httpResp *http.Response) string {
	if httpResp != nil {
		defer func() {
			if httpResp.Body != nil {
				_ = httpResp.Body.Close()
			}
		}()
		var snippet string
		if httpResp.Body != nil {
			if raw, rErr := io.ReadAll(io.LimitReader(httpResp.Body, 512)); rErr == nil {
				snippet = strings.TrimSpace(string(raw))
			}
		}
		if snippet != "" {
			return fmt.Sprintf("HTTP %d %s from %s: %s", httpResp.StatusCode, http.StatusText(httpResp.StatusCode), endpoint, snippet)
		}
		return fmt.Sprintf("HTTP %d %s from %s: %v", httpResp.StatusCode, http.StatusText(httpResp.StatusCode), endpoint, err)
	}
	return err.Error()
}

func tlsVersionLabel(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	default:
		if v == 0 {
			return ""
		}
		return fmt.Sprintf("0x%04x", v)
	}
}

func printClientVerifyHuman(w io.Writer, rep *clientVerifyReport) {
	for _, h := range rep.Hosts {
		label := h.Endpoint
		if h.Host != "" {
			label = fmt.Sprintf("%s (%s)", h.Host, h.Endpoint)
		}
		if h.Healthy {
			_, _ = fmt.Fprintf(w, "[PASS] %-30s %s %s server_cn=%s latency=%dms\n",
				label, h.TLSVersion, h.CipherSuite, h.ServerCN, h.LatencyMS)
		} else {
			_, _ = fmt.Fprintf(w, "[FAIL] %-30s %s\n", label, h.Error)
		}
	}
}

func runHost(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printHostUsage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "list", "ls":
		return runHostList(args[1:], stdout, stderr)
	case "add", "set":
		return runHostAdd(args[1:], stdout, stderr)
	case "remove", "rm", "delete":
		return runHostRemove(args[1:], stdout, stderr)
	case "set-default", "default":
		return runHostSetDefault(args[1:], stdout, stderr)
	case "help", "--help", "-help", "-h":
		printHostUsage(stdout)
		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "Error: unknown host subcommand %q\n\n", args[0])
		printHostUsage(stderr)
		return exitUsage
	}
}

type hostListEntry struct {
	Name            string `json:"name"`
	Endpoint        string `json:"endpoint"`
	ClusterEndpoint string `json:"cluster_endpoint,omitempty"`
	Timeout         string `json:"timeout,omitempty"`
	Default         bool   `json:"default"`
}

type hostListOutput struct {
	ConfigPath  string          `json:"config_path"`
	DefaultHost string          `json:"default_host,omitempty"`
	Hosts       []hostListEntry `json:"hosts"`
}

func runHostList(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("host list")
	cfgFlag := fs.String("config", "", "Client config.json path override")
	jsonOut := fs.Bool("json", false, "Format output as indented JSON")

	usageFn := func(w io.Writer) {
		_, _ = fmt.Fprint(w, "Usage: agent-bridge host list [--config <path>] [--json]\n")
	}
	if code, handled := parseFlags(fs, args, stdout, stderr, usageFn); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		usageFn(stderr)
		return exitUsage
	}

	cfgPath, fc, err := loadEditableClientConfig(*cfgFlag)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	var names []string
	for k := range fc.Hosts {
		names = append(names, k)
	}
	sort.Strings(names)

	entries := make([]hostListEntry, 0, len(names))
	for _, n := range names {
		hc := fc.Hosts[n]
		entries = append(entries, hostListEntry{
			Name:            n,
			Endpoint:        hc.Endpoint,
			ClusterEndpoint: hc.ClusterEndpoint,
			Timeout:         hc.Timeout,
			Default:         n == fc.DefaultHost,
		})
	}

	if *jsonOut {
		return writeIndentedJSON(stdout, stderr, hostListOutput{
			ConfigPath:  cfgPath,
			DefaultHost: fc.DefaultHost,
			Hosts:       entries,
		})
	}

	if len(entries) == 0 {
		_, _ = fmt.Fprintf(stdout, "No hosts configured in %s.\n", cfgPath)
		return exitOK
	}

	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "DEFAULT\tHOST\tENDPOINT\tCLUSTER_ENDPOINT\tTIMEOUT")
	for _, e := range entries {
		defMark := ""
		if e.Default {
			defMark = "*"
		}
		cep := e.ClusterEndpoint
		if cep == "" {
			cep = "-"
		}
		to := e.Timeout
		if to == "" {
			to = "-"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", defMark, e.Name, e.Endpoint, cep, to)
	}
	_ = tw.Flush()
	return exitOK
}

func runHostAdd(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("host add")
	nameFlag := fs.String("name", "", "Host profile alias")
	endpoint := fs.String("endpoint", "", "Target exec host:port (required)")
	clusterEndpoint := fs.String("cluster-endpoint", "", "Optional cluster control-plane host:port")
	timeout := fs.String("timeout", "", "Optional per-host timeout (e.g. 60s)")
	makeDefault := fs.Bool("default", false, "Set this host as default_host")
	cfgFlag := fs.String("config", "", "Client config.json path override")
	jsonOut := fs.Bool("json", false, "Format output as indented JSON")

	usageFn := func(w io.Writer) {
		_, _ = fmt.Fprint(w, `Usage: agent-bridge host add [--name <alias>] --endpoint <host:port> [flags] [<alias>]

Flags:
  --name <alias>                 Host profile alias (or pass <alias> positionally)
  --endpoint <host:port>         Target exec endpoint (required)
  --cluster-endpoint <host:port> Optional cluster control-plane endpoint
  --timeout <duration>           Optional per-host timeout (e.g. 60s)
  --default                      Mark this host as default_host
  --config <path>                Client config.json path override
  --json                         Format output as indented JSON
`)
	}

	// Support `agent-bridge host add <alias> --endpoint ...` as well as flags-first ordering.
	aliasPositional, flagArgs := extractLeadingPositional(args)
	if code, handled := parseFlags(fs, flagArgs, stdout, stderr, usageFn); handled {
		return code
	}
	if fs.NArg() > 1 || (aliasPositional != "" && fs.NArg() > 0) {
		_, _ = fmt.Fprintln(stderr, "Error: too many positional arguments")
		usageFn(stderr)
		return exitUsage
	}
	if aliasPositional == "" && fs.NArg() == 1 {
		aliasPositional = fs.Arg(0)
	}

	alias := strings.TrimSpace(*nameFlag)
	if alias == "" {
		alias = strings.TrimSpace(aliasPositional)
	}
	if alias == "" || strings.TrimSpace(*endpoint) == "" {
		_, _ = fmt.Fprintln(stderr, "Error: missing required host alias and/or --endpoint")
		usageFn(stderr)
		return exitUsage
	}

	normEp, _, err := config.NormalizeEndpoint(*endpoint)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
	normClusterEp := ""
	if strings.TrimSpace(*clusterEndpoint) != "" {
		cep, _, cErr := config.NormalizeClusterAddr(*clusterEndpoint)
		if cErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", cErr)
			return exitError
		}
		normClusterEp = cep
	}
	normTimeout := strings.TrimSpace(*timeout)
	if normTimeout != "" {
		if _, _, tErr := config.ParseTimeout(normTimeout); tErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", tErr)
			return exitError
		}
	}

	cfgPath, fc, err := loadEditableClientConfig(*cfgFlag)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
	if fc.Hosts == nil {
		fc.Hosts = make(map[string]config.HostConfig)
	}
	fc.Hosts[alias] = config.HostConfig{
		Endpoint:        normEp,
		ClusterEndpoint: normClusterEp,
		Timeout:         normTimeout,
	}
	if *makeDefault || (fc.DefaultHost == "" && fc.Endpoint == "" && len(fc.Hosts) == 1) {
		fc.DefaultHost = alias
	}

	if err := saveEditableClientConfig(cfgPath, fc); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	entry := hostListEntry{
		Name:            alias,
		Endpoint:        normEp,
		ClusterEndpoint: normClusterEp,
		Timeout:         normTimeout,
		Default:         fc.DefaultHost == alias,
	}
	if *jsonOut {
		return writeIndentedJSON(stdout, stderr, entry)
	}
	_, _ = fmt.Fprintf(stdout, "Added host %q -> %s (default=%t) in %s\n", alias, normEp, entry.Default, cfgPath)
	return exitOK
}

func runHostRemove(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("host remove")
	nameFlag := fs.String("name", "", "Host profile alias to remove")
	cfgFlag := fs.String("config", "", "Client config.json path override")
	jsonOut := fs.Bool("json", false, "Format output as indented JSON")

	usageFn := func(w io.Writer) {
		_, _ = fmt.Fprint(w, "Usage: agent-bridge host remove <alias> [--config <path>] [--json]\n")
	}
	aliasPositional, flagArgs := extractLeadingPositional(args)
	if code, handled := parseFlags(fs, flagArgs, stdout, stderr, usageFn); handled {
		return code
	}
	if fs.NArg() > 1 || (aliasPositional != "" && fs.NArg() > 0) {
		_, _ = fmt.Fprintln(stderr, "Error: too many positional arguments")
		usageFn(stderr)
		return exitUsage
	}
	if aliasPositional == "" && fs.NArg() == 1 {
		aliasPositional = fs.Arg(0)
	}
	alias := strings.TrimSpace(*nameFlag)
	if alias == "" {
		alias = strings.TrimSpace(aliasPositional)
	}
	if alias == "" {
		_, _ = fmt.Fprintln(stderr, "Error: missing host <alias>")
		usageFn(stderr)
		return exitUsage
	}

	cfgPath, fc, err := loadEditableClientConfig(*cfgFlag)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
	if _, exists := fc.Hosts[alias]; !exists {
		_, _ = fmt.Fprintf(stderr, "Error: host %q does not exist in %s\n", alias, cfgPath)
		return exitError
	}
	delete(fc.Hosts, alias)
	if fc.DefaultHost == alias {
		fc.DefaultHost = ""
		var remaining []string
		for k := range fc.Hosts {
			remaining = append(remaining, k)
		}
		sort.Strings(remaining)
		if len(remaining) > 0 {
			fc.DefaultHost = remaining[0]
		}
	}

	if err := saveEditableClientConfig(cfgPath, fc); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	if *jsonOut {
		return writeIndentedJSON(stdout, stderr, map[string]any{
			"removed":      alias,
			"default_host": fc.DefaultHost,
			"config_path":  cfgPath,
		})
	}
	_, _ = fmt.Fprintf(stdout, "Removed host %q from %s\n", alias, cfgPath)
	return exitOK
}

func runHostSetDefault(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("host set-default")
	nameFlag := fs.String("name", "", "Host profile alias to set as default")
	cfgFlag := fs.String("config", "", "Client config.json path override")
	jsonOut := fs.Bool("json", false, "Format output as indented JSON")

	usageFn := func(w io.Writer) {
		_, _ = fmt.Fprint(w, "Usage: agent-bridge host set-default <alias> [--config <path>] [--json]\n")
	}
	aliasPositional, flagArgs := extractLeadingPositional(args)
	if code, handled := parseFlags(fs, flagArgs, stdout, stderr, usageFn); handled {
		return code
	}
	if fs.NArg() > 1 || (aliasPositional != "" && fs.NArg() > 0) {
		_, _ = fmt.Fprintln(stderr, "Error: too many positional arguments")
		usageFn(stderr)
		return exitUsage
	}
	if aliasPositional == "" && fs.NArg() == 1 {
		aliasPositional = fs.Arg(0)
	}
	alias := strings.TrimSpace(*nameFlag)
	if alias == "" {
		alias = strings.TrimSpace(aliasPositional)
	}
	if alias == "" {
		_, _ = fmt.Fprintln(stderr, "Error: missing host <alias>")
		usageFn(stderr)
		return exitUsage
	}

	cfgPath, fc, err := loadEditableClientConfig(*cfgFlag)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}
	if _, exists := fc.Hosts[alias]; !exists {
		_, _ = fmt.Fprintf(stderr, "Error: host %q does not exist in %s\n", alias, cfgPath)
		return exitError
	}
	fc.DefaultHost = alias

	if err := saveEditableClientConfig(cfgPath, fc); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	if *jsonOut {
		return writeIndentedJSON(stdout, stderr, map[string]any{
			"default_host": alias,
			"config_path":  cfgPath,
		})
	}
	_, _ = fmt.Fprintf(stdout, "Default host set to %q in %s\n", alias, cfgPath)
	return exitOK
}

func extractLeadingPositional(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

func loadEditableClientConfig(cfgFlag string) (string, *config.FileConfig, error) {
	homeDir, _ := os.UserHomeDir()
	var cfgPath string
	if strings.TrimSpace(cfgFlag) != "" {
		cfgPath = config.ExpandPath(cfgFlag, homeDir, "")
	} else {
		defPath, err := config.DefaultGlobalConfigPath()
		if err != nil {
			return "", nil, err
		}
		cfgPath = defPath
	}

	if !fileExistsRegular(cfgPath) {
		return cfgPath, &config.FileConfig{}, nil
	}
	loaded, err := config.LoadFileConfig(cfgPath)
	if err != nil {
		return "", nil, err
	}
	return cfgPath, loaded, nil
}

func saveEditableClientConfig(cfgPath string, fc *config.FileConfig) error {
	dir := filepath.Dir(cfgPath)
	if err := acl.LockdownClientDir(dir); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(fc, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := pki.WriteFileAtomic(cfgPath, encoded, 0o600); err != nil {
		return err
	}
	return acl.LockdownClientFile(cfgPath)
}

func resolveOptionalPassphraseFromEnv(envVar string) (string, error) {
	trimmed := strings.TrimSpace(envVar)
	if trimmed == "" {
		return "", nil
	}
	val, ok := os.LookupEnv(trimmed)
	if !ok || val == "" {
		return "", fmt.Errorf("--passphrase-env variable %q is unset or empty", trimmed)
	}
	return val, nil
}

func buildBundleMetadataOptions(
	caCertPath string,
	clientCertPath string,
	clientKeyPath string,
	optionalHostName string,
	rawEndpoint string,
	rawClusterEndpoint string,
	rawHosts []string,
	rawDefaultHost string,
	rawTimeout string,
) (pki.BuildClientBundleOptions, error) {
	var normEp string
	if strings.TrimSpace(rawEndpoint) != "" {
		ep, _, err := config.NormalizeEndpoint(rawEndpoint)
		if err != nil {
			return pki.BuildClientBundleOptions{}, err
		}
		normEp = ep
	}

	var normClusterEp string
	if strings.TrimSpace(rawClusterEndpoint) != "" {
		cep, _, err := config.NormalizeClusterAddr(rawClusterEndpoint)
		if err != nil {
			return pki.BuildClientBundleOptions{}, err
		}
		normClusterEp = cep
	}

	normTimeout := strings.TrimSpace(rawTimeout)
	if normTimeout != "" {
		if _, _, err := config.ParseTimeout(normTimeout); err != nil {
			return pki.BuildClientBundleOptions{}, err
		}
	}

	hostsMap, orderedAliases, err := parseHostBundleSpecs(rawHosts)
	if err != nil {
		return pki.BuildClientBundleOptions{}, err
	}

	defaultHost := strings.TrimSpace(rawDefaultHost)
	if len(hostsMap) == 0 && optionalHostName != "" && normEp != "" {
		hostsMap = map[string]pki.HostBundleEntry{
			optionalHostName: {
				Endpoint:        normEp,
				ClusterEndpoint: normClusterEp,
				Timeout:         normTimeout,
			},
		}
		orderedAliases = []string{optionalHostName}
	}
	if defaultHost != "" && len(hostsMap) == 0 && normEp != "" {
		hostsMap = map[string]pki.HostBundleEntry{
			defaultHost: {
				Endpoint:        normEp,
				ClusterEndpoint: normClusterEp,
				Timeout:         normTimeout,
			},
		}
		orderedAliases = []string{defaultHost}
	}
	if defaultHost == "" && normEp == "" && len(orderedAliases) > 0 {
		defaultHost = orderedAliases[0]
	}

	return pki.BuildClientBundleOptions{
		CACertPath:      caCertPath,
		ClientCertPath:  clientCertPath,
		ClientKeyPath:   clientKeyPath,
		DefaultHost:     defaultHost,
		Endpoint:        normEp,
		ClusterEndpoint: normClusterEp,
		Timeout:         normTimeout,
		Hosts:           hostsMap,
	}, nil
}

func parseHostBundleSpecs(specs []string) (map[string]pki.HostBundleEntry, []string, error) {
	if len(specs) == 0 {
		return nil, nil, nil
	}
	out := make(map[string]pki.HostBundleEntry, len(specs))
	var order []string

	for _, raw := range specs {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		eq := strings.IndexByte(trimmed, '=')
		if eq <= 0 || eq == len(trimmed)-1 {
			return nil, nil, fmt.Errorf("invalid --hosts entry %q: expected <alias>=<host:port>[@<cluster_host:port>]", raw)
		}
		alias := strings.TrimSpace(trimmed[:eq])
		rhs := strings.TrimSpace(trimmed[eq+1:])
		if alias == "" || rhs == "" {
			return nil, nil, fmt.Errorf("invalid --hosts entry %q: alias and endpoint cannot be empty", raw)
		}

		var rawExec, rawCluster string
		if at := strings.IndexByte(rhs, '@'); at != -1 {
			rawExec = strings.TrimSpace(rhs[:at])
			rawCluster = strings.TrimSpace(rhs[at+1:])
		} else {
			rawExec = rhs
		}

		normExec, _, err := config.NormalizeEndpoint(rawExec)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid exec endpoint in --hosts %q: %w", raw, err)
		}
		var normCluster string
		if rawCluster != "" {
			cep, _, cErr := config.NormalizeClusterAddr(rawCluster)
			if cErr != nil {
				return nil, nil, fmt.Errorf("invalid cluster endpoint in --hosts %q: %w", raw, cErr)
			}
			normCluster = cep
		}

		if _, exists := out[alias]; !exists {
			order = append(order, alias)
		}
		out[alias] = pki.HostBundleEntry{
			Endpoint:        normExec,
			ClusterEndpoint: normCluster,
		}
	}

	return out, order, nil
}

func printCAUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge ca <subcommand> [flags]

Subcommands:
  init      Initialize Root CA, initial CRL, and auto-SAN seed node certificates
  issue     Issue server, client, or peer certificate (and optional .abbundle)
  bundle    Package existing CA + client certificate/key into an .abbundle
  revoke    Revoke certificate by --cert or --serial and optionally --sync to cluster
`)
}

func printCAInitUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge ca init --out-dir <dir> [flags]

Flags:
  --out-dir <dir>          Output directory for ca.crt, ca.key, crl.pem, and node certs (required)
  --common-name <cn>       Root CA Common Name (default "Agent-Bridge-Root-CA")
  --org <org>              Root CA Organization (default "Agent-Bridge PKI")
  --years <int>            Validity period in years (default 10)
  --node-id <name>         Seed node Common Name for initial server.crt/peer.crt (defaults to hostname)
  --san-ip <ips>           Additional X.509 IP SAN(s) for initial node certs (repeatable or CSV)
  --san-dns <names>        Additional X.509 DNS SAN(s) for initial node certs (repeatable or CSV)
  --no-auto-sans           Disable automatic active-NIC IP SAN discovery
  --ca-only                Generate only ca.crt, ca.key, and crl.pem
  --json                   Format output as indented JSON
`)
}

func printCAIssueUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge ca issue --ca-dir <dir> --type <server|client|peer> --name <cn> [flags]

Flags:
  --ca-dir <dir>                 Directory containing ca.crt and ca.key (required)
  --type <server|client|peer>    Certificate profile (required)
  --name <cn>                    Subject Common Name (required)
  --out-dir <dir>                Output directory for PEM files (optional when --bundle-out is set)
  --ip, --san-ip <ip>            IPv4/IPv6 SAN(s) (repeatable or CSV)
  --dns, --san-dns <dns>         DNS SAN(s) (repeatable or CSV)
  --auto-sans                    Merge active local NIC IPs into certificate SANs
  --no-auto-sans                 Disable automatic NIC SAN fallback on server/peer certs
  --years <int>                  Validity in years (default: 3 server/peer, 1 client)
  --bundle-out <path|->          Emit self-contained client .abbundle (or '-' for stdout)
  --passphrase-env <ENV>         Encrypt --bundle-out with AES-256-GCM passphrase from <ENV>
  --hosts <alias=host:port,...>  Named host map entries for --bundle-out (repeatable or CSV)
  --default-host <alias>         Default host alias in --bundle-out
  --endpoint <host:port>         Default target endpoint in --bundle-out
  --cluster-endpoint <host:port> Default cluster endpoint in --bundle-out
  --timeout <duration>           Default timeout in --bundle-out
  --json                         Format output as indented JSON
`)
}

func printCABundleUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge ca bundle --ca <ca.crt> --cert <client.crt> --key <client.key> --out <file.abbundle|-> [flags]

Flags:
  --ca <path>                    Root CA certificate PEM path (required)
  --cert <path>                  Client certificate PEM path (required)
  --key <path>                   Client private key PEM path (required)
  --out <path|->                 Output .abbundle path or '-' for stdout (required)
  --name <alias>                 Optional host alias when --endpoint is used without --hosts
  --passphrase-env <ENV>         Encrypt bundle with AES-256-GCM passphrase from <ENV>
  --hosts <alias=host:port,...>  Named host profile(s) (repeatable or CSV)
  --default-host <alias>         Default host alias
  --endpoint <host:port>         Default target endpoint
  --cluster-endpoint <host:port> Default cluster control-plane endpoint
  --timeout <duration>           Default execution timeout (e.g. 60s)
  --json                         Format output as indented JSON
`)
}

func printCARevokeUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge ca revoke --ca-dir <dir> (--cert <pem> | --serial <hex>) [flags]

Flags:
  --ca-dir <dir>           Directory containing ca.crt and ca.key (required)
  --cert <path>            Certificate PEM file to revoke (extracts X.509 serial)
  --serial <hex>           Hexadecimal serial number to revoke
  --crl-out <path>         CRL file path to update (defaults to <ca-dir>/crl.pem)
  --sync                   Broadcast updated CRL immediately into the live cluster mesh
  --cluster-addr <addr>    Target cluster host:port for --sync
  --host <alias>           Named host profile from config.json for --sync
  --data-dir <dir>         Server node data directory for --sync mTLS credentials
  --service-config <path>  Server server.json path for --sync
  --config <path>          Client config.json path for --sync
  --auth-cert <path>       Explicit client/peer auth certificate PEM for --sync
  --auth-key <path>        Explicit client/peer auth private key PEM for --sync
  --ca <path>              Explicit Root CA PEM for --sync
  --timeout <duration>     Cluster sync timeout
  --json                   Format output as indented JSON
`)
}

func printClientUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge client <subcommand> [flags]

Subcommands:
  init      Unpack .abbundle into locked-down client directory and optionally verify mTLS
  verify    Run mTLS 1.3 handshake + CRL/ACL health probes against configured host(s)
`)
}

func printClientInitUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge client init --bundle <file.abbundle|-> [flags]

Flags:
  --bundle <path|->        Client .abbundle path or '-' for stdin (required)
  --config-dir <dir>       Target client config directory override
  --config <path>          Target config.json file path override
  --passphrase-env <ENV>   Environment variable holding decryption passphrase
  --overwrite              Replace existing hosts map instead of merging
  --default-host <alias>   Override default_host written to config.json
  --verify                 Run live mTLS 1.3 health probe(s) after installation
  --timeout <duration>     Health probe timeout when --verify is set (default 10s)
  --json                   Format output as indented JSON
`)
}

func printClientVerifyUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge client verify [flags]

Flags:
  --host <alias|addr>      Named host profile or target host:port
  --endpoint <host:port>   Target host:port override
  --all                    Probe all configured hosts (default when multiple hosts exist)
  --config <path>          Client config.json path override
  --ca <path>              Root CA certificate PEM path
  --cert <path>            Client certificate PEM path
  --key <path>             Client private key PEM path
  --server-name <sni>      TLS SNI / SAN hostname or IP override
  --timeout <duration>     Probe timeout (default 10s)
  --json                   Format verification report as indented JSON
`)
}

func printHealthUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge health [flags]

Alias for 'agent-bridge client verify': performs a TLS 1.3 mutual-auth, CRL, and ACL
health probe against wss://<endpoint>/ws/exec without spawning a remote shell.

Flags:
  --host <alias|addr>      Named host profile or target host:port
  --endpoint <host:port>   Target host:port override
  --all                    Probe all configured hosts (default when multiple hosts exist)
  --config <path>          Client config.json path override
  --ca <path>              Root CA certificate PEM path
  --cert <path>            Client certificate PEM path
  --key <path>             Client private key PEM path
  --server-name <sni>      TLS SNI / SAN hostname or IP override
  --timeout <duration>     Probe timeout (default 10s)
  --json                   Format verification report as indented JSON
`)
}

func printHostUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge host <subcommand> [flags]

Subcommands:
  list          List named host profiles in client config.json
  add           Add or update a named host profile in client config.json
  remove        Remove a named host profile from client config.json
  set-default   Set default_host in client config.json
`)
}
