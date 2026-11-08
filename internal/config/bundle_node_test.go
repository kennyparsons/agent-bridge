package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kennyparsons/agent-bridge/internal/acl"
	"github.com/kennyparsons/agent-bridge/internal/pki"
)

func TestResolveNodeCertPathsDualServerAndPeerFallback(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// 1. Empty directory defaults to server.{crt,key}.
	gotCert, gotKey := ResolveNodeCertPaths(dir)
	if gotCert != filepath.Join(dir, "server.crt") || gotKey != filepath.Join(dir, "server.key") {
		t.Fatalf("empty dir ResolveNodeCertPaths = (%q, %q), want server.{crt,key}", gotCert, gotKey)
	}

	// 2. Only peer.{crt,key} present (e.g. `ca issue --type peer`) -> returns peer.{crt,key}.
	peerCert := filepath.Join(dir, "peer.crt")
	peerKey := filepath.Join(dir, "peer.key")
	if err := os.WriteFile(peerCert, []byte("cert"), 0o644); err != nil {
		t.Fatalf("write peer.crt: %v", err)
	}
	if err := os.WriteFile(peerKey, []byte("key"), 0o600); err != nil {
		t.Fatalf("write peer.key: %v", err)
	}
	gotCert, gotKey = ResolveNodeCertPaths(dir)
	if gotCert != peerCert || gotKey != peerKey {
		t.Fatalf("peer-only ResolveNodeCertPaths = (%q, %q), want (%q, %q)", gotCert, gotKey, peerCert, peerKey)
	}

	// 3. Both server.{crt,key} and peer.{crt,key} present -> prefers server.{crt,key}.
	srvCert := filepath.Join(dir, "server.crt")
	srvKey := filepath.Join(dir, "server.key")
	if err := os.WriteFile(srvCert, []byte("cert"), 0o644); err != nil {
		t.Fatalf("write server.crt: %v", err)
	}
	if err := os.WriteFile(srvKey, []byte("key"), 0o600); err != nil {
		t.Fatalf("write server.key: %v", err)
	}
	gotCert, gotKey = ResolveNodeCertPaths(dir)
	if gotCert != srvCert || gotKey != srvKey {
		t.Fatalf("both-present ResolveNodeCertPaths = (%q, %q), want (%q, %q)", gotCert, gotKey, srvCert, srvKey)
	}
}

func TestInstallClientBundleMergeAndACLLockdown(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	caDir := filepath.Join(tmp, "ca")
	if _, err := pki.InitCA(pki.InitCAOptions{OutDir: caDir}); err != nil {
		t.Fatalf("InitCA failed: %v", err)
	}

	cliRes, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:  caDir,
		OutDir: filepath.Join(tmp, "issued-client"),
		Type:   pki.TypeClient,
		Name:   "admin-laptop",
	})
	if err != nil {
		t.Fatalf("IssueCert(client) failed: %v", err)
	}

	b1, err := pki.BuildClientBundle(pki.BuildClientBundleOptions{
		CACertPath:     filepath.Join(caDir, pki.CACertFilename),
		ClientCertPath: cliRes.CertPath,
		ClientKeyPath:  cliRes.KeyPath,
		DefaultHost:    "win-dc-01",
		Hosts: map[string]pki.HostBundleEntry{
			"win-dc-01": {
				Endpoint:        "100.64.0.10:8443",
				ClusterEndpoint: "100.64.0.10:8444",
				Timeout:         "45s",
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildClientBundle(b1) failed: %v", err)
	}

	homeDir := filepath.Join(tmp, "home")
	emptyEnv := func(string) (string, bool) { return "", false }

	res1, err := InstallClientBundleWithOptions(b1, InstallClientBundleOptions{
		HomeDir:   homeDir,
		GOOS:      "linux",
		EnvLookup: emptyEnv,
	})
	if err != nil {
		t.Fatalf("InstallClientBundleWithOptions(b1) failed: %v", err)
	}

	wantDir := filepath.Join(homeDir, ".config", "agent-bridge")
	if res1.ConfigDir != wantDir {
		t.Fatalf("ConfigDir = %q, want %q", res1.ConfigDir, wantDir)
	}
	for _, secretPath := range []string{res1.ConfigDir, res1.ClientKeyPath, res1.ConfigPath} {
		st, auditErr := acl.AuditPathACL(secretPath, true)
		if auditErr != nil || !st.Secure {
			t.Fatalf("expected %q to pass client ACL audit, got st=%+v err=%v", secretPath, st, auditErr)
		}
	}

	// Verify zero-flag Resolve and ResolveClusterConfig succeed immediately against the installed bundle.
	resolveOpts := ResolveOptions{
		WorkDir:   t.TempDir(),
		HomeDir:   homeDir,
		GOOS:      "linux",
		EnvLookup: emptyEnv,
	}
	execCfg, err := ResolveWithOptions(FlagOverrides{}, resolveOpts)
	if err != nil {
		t.Fatalf("ResolveWithOptions after bundle install failed: %v", err)
	}
	if execCfg.Host != "win-dc-01" || execCfg.Endpoint != "100.64.0.10:8443" || execCfg.TimeoutSeconds != 45 {
		t.Fatalf("unexpected resolved exec config: %+v", execCfg)
	}

	clusterCfg, err := ResolveClusterConfigWithOptions(ClusterFlagOverrides{}, resolveOpts)
	if err != nil {
		t.Fatalf("ResolveClusterConfigWithOptions after bundle install failed: %v", err)
	}
	if clusterCfg.ClusterAddr != "100.64.0.10:8444" {
		t.Fatalf("unexpected resolved cluster config: %+v", clusterCfg)
	}

	// Merge a second bundle adding win-dc-02 while preserving win-dc-01.
	b2, err := pki.BuildClientBundle(pki.BuildClientBundleOptions{
		CACertPath:     filepath.Join(caDir, pki.CACertFilename),
		ClientCertPath: cliRes.CertPath,
		ClientKeyPath:  cliRes.KeyPath,
		DefaultHost:    "win-dc-02",
		Hosts: map[string]pki.HostBundleEntry{
			"win-dc-02": {
				Endpoint:        "100.64.0.11:8443",
				ClusterEndpoint: "100.64.0.11:8444",
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildClientBundle(b2) failed: %v", err)
	}
	if _, err := InstallClientBundleWithOptions(b2, InstallClientBundleOptions{
		HomeDir:   homeDir,
		GOOS:      "linux",
		EnvLookup: emptyEnv,
	}); err != nil {
		t.Fatalf("InstallClientBundleWithOptions(b2 merge) failed: %v", err)
	}

	// Both win-dc-01 and win-dc-02 remain addressable, and default_host updated to win-dc-02.
	mergedDefault, err := ResolveWithOptions(FlagOverrides{}, resolveOpts)
	if err != nil || mergedDefault.Host != "win-dc-02" {
		t.Fatalf("expected merged default_host=win-dc-02, got cfg=%+v err=%v", mergedDefault, err)
	}
	mergedOldHost, err := ResolveWithOptions(FlagOverrides{Host: "win-dc-01"}, resolveOpts)
	if err != nil || mergedOldHost.Endpoint != "100.64.0.10:8443" {
		t.Fatalf("expected preserved host win-dc-01 after merge, got cfg=%+v err=%v", mergedOldHost, err)
	}

	// Windows %APPDATA%\agent-bridge directory target resolution.
	winAppData := filepath.Join(tmp, "appdata")
	resWin, err := InstallClientBundleWithOptions(b1, InstallClientBundleOptions{
		HomeDir: homeDir,
		GOOS:    "windows",
		EnvLookup: func(k string) (string, bool) {
			if k == "APPDATA" {
				return winAppData, true
			}
			return "", false
		},
	})
	if err != nil {
		t.Fatalf("Windows APPDATA bundle install failed: %v", err)
	}
	if resWin.ConfigDir != filepath.Join(winAppData, "agent-bridge") {
		t.Fatalf("Windows ConfigDir = %q, want %q", resWin.ConfigDir, filepath.Join(winAppData, "agent-bridge"))
	}
}

func TestResolveClusterConfigServerLocalFallback(t *testing.T) {
	t.Parallel()

	// Verify OS server path defaults match specification.
	winData, winCfg, winLog := DefaultServerPathsForOS("windows")
	if winData != `C:\ProgramData\agent-bridge\node` ||
		winCfg != `C:\ProgramData\agent-bridge\server.json` ||
		winLog != `C:\ProgramData\agent-bridge\logs\daemon.log` {
		t.Fatalf("unexpected Windows server paths: %q, %q, %q", winData, winCfg, winLog)
	}
	linData, linCfg, linLog := DefaultServerPathsForOS("linux")
	if linData != "/var/lib/agent-bridge/node" ||
		linCfg != "/etc/agent-bridge/server.json" ||
		linLog != "/var/log/agent-bridge/daemon.log" {
		t.Fatalf("unexpected Linux server paths: %q, %q, %q", linData, linCfg, linLog)
	}
	macData, macCfg, macLog := DefaultServerPathsForOS("darwin")
	if macData != "/Library/Application Support/agent-bridge/node" ||
		macCfg != "/Library/Application Support/agent-bridge/server.json" ||
		macLog != "/Library/Logs/agent-bridge/daemon.log" {
		t.Fatalf("unexpected macOS server paths: %q, %q, %q", macData, macCfg, macLog)
	}

	tmp := t.TempDir()
	caDir := filepath.Join(tmp, "ca")
	caRes, err := pki.InitCA(pki.InitCAOptions{OutDir: caDir})
	if err != nil {
		t.Fatalf("InitCA failed: %v", err)
	}

	// Case A: Server node using peer.{crt,key} + server.json with custom cluster port 9444, no client config.json!
	nodeDir := filepath.Join(tmp, "node-peer")
	peerRes, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:  caDir,
		OutDir: nodeDir,
		Type:   pki.TypePeer,
		Name:   "win-dc-01",
		IPs:    []string{"127.0.0.1", "100.64.0.10"},
	})
	if err != nil {
		t.Fatalf("IssueCert(peer) failed: %v", err)
	}
	caBytes, err := os.ReadFile(caRes.CACertPath)
	if err != nil {
		t.Fatalf("ReadFile(ca.crt) failed: %v", err)
	}
	nodeCAPath := filepath.Join(nodeDir, pki.CACertFilename)
	if err := os.WriteFile(nodeCAPath, caBytes, 0o644); err != nil {
		t.Fatalf("WriteFile(node ca.crt) failed: %v", err)
	}

	serverJSONPath := filepath.Join(tmp, "etc", "server.json")
	if err := os.MkdirAll(filepath.Dir(serverJSONPath), 0o700); err != nil {
		t.Fatalf("MkdirAll(etc) failed: %v", err)
	}
	serverJSON := `{
  "bind_specs": ["tailscale0:8443"],
  "cluster_bind_specs": ["tailscale0:9444", "127.0.0.1:9444"],
  "data_dir": "` + filepath.ToSlash(nodeDir) + `"
}`
	if err := os.WriteFile(serverJSONPath, []byte(serverJSON), 0o600); err != nil {
		t.Fatalf("WriteFile(server.json) failed: %v", err)
	}

	emptyEnv := func(string) (string, bool) { return "", false }
	srvOpts := ResolveOptions{
		WorkDir:          t.TempDir(),
		GlobalConfigPath: filepath.Join(tmp, "missing-client-config.json"),
		HomeDir:          filepath.Join(tmp, "empty-home"),
		GOOS:             "linux",
		EnvLookup:        emptyEnv,
		ServerConfigPath: serverJSONPath,
		ServerDataDir:    filepath.Join(tmp, "unused-default-data"),
	}

	resolvedPeer, err := ResolveClusterConfigWithOptions(ClusterFlagOverrides{}, srvOpts)
	if err != nil {
		t.Fatalf("server-local ResolveClusterConfigWithOptions(peer + server.json) failed: %v", err)
	}
	if resolvedPeer.ClusterAddr != "127.0.0.1:9444" || resolvedPeer.BaseHTTPSURL != "https://127.0.0.1:9444" {
		t.Fatalf("ClusterAddr = %q (%q), want 127.0.0.1:9444", resolvedPeer.ClusterAddr, resolvedPeer.BaseHTTPSURL)
	}
	if resolvedPeer.CertPath != peerRes.CertPath || resolvedPeer.KeyPath != peerRes.KeyPath || resolvedPeer.CAPath != nodeCAPath {
		t.Fatalf("unexpected cert paths from server.json fallback: %+v", resolvedPeer)
	}

	// Case B: No server.json on disk, only OS default ServerDataDir with server.{crt,key} and ca.crt.
	dataOnlyDir := filepath.Join(tmp, "var-lib-node")
	srvRes, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:  caDir,
		OutDir: dataOnlyDir,
		Type:   pki.TypeServer,
		Name:   "linux-node-01",
		IPs:    []string{"127.0.0.1", "100.64.0.11"},
	})
	if err != nil {
		t.Fatalf("IssueCert(server) failed: %v", err)
	}
	dataOnlyCA := filepath.Join(dataOnlyDir, pki.CACertFilename)
	if err := os.WriteFile(dataOnlyCA, caBytes, 0o644); err != nil {
		t.Fatalf("WriteFile(dataOnlyCA) failed: %v", err)
	}

	dataOnlyOpts := srvOpts
	dataOnlyOpts.ServerConfigPath = filepath.Join(tmp, "nonexistent-server.json")
	dataOnlyOpts.ServerDataDir = dataOnlyDir

	resolvedDataOnly, err := ResolveClusterConfigWithOptions(ClusterFlagOverrides{}, dataOnlyOpts)
	if err != nil {
		t.Fatalf("server-local ResolveClusterConfigWithOptions(DataDir only) failed: %v", err)
	}
	if resolvedDataOnly.ClusterAddr != "127.0.0.1:8444" {
		t.Fatalf("ClusterAddr = %q, want 127.0.0.1:8444", resolvedDataOnly.ClusterAddr)
	}
	if resolvedDataOnly.CertPath != srvRes.CertPath || resolvedDataOnly.KeyPath != srvRes.KeyPath || resolvedDataOnly.CAPath != dataOnlyCA {
		t.Fatalf("unexpected cert paths from DataDir fallback: %+v", resolvedDataOnly)
	}
}
