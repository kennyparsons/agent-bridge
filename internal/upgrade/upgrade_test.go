package upgrade

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

var (
	testBinsOnce sync.Once
	testBinsDir  string
	testBinV011  []byte
	testBinV020  []byte
	testBinBad   []byte
	testBinsErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if testBinsDir != "" {
		_ = os.RemoveAll(testBinsDir)
	}
	os.Exit(code)
}

func ensureTestBinaries(t *testing.T) (v011, v020, broken []byte) {
	t.Helper()
	testBinsOnce.Do(func() {
		dir, err := os.MkdirTemp("", "agent-bridge-upgrade-testbins-*")
		if err != nil {
			testBinsErr = err
			return
		}
		testBinsDir = dir

		srcPath := filepath.Join(dir, "main.go")
		src := `package main

import "os"

var (
	ver  = "v0.0.0"
	fail = "0"
)

func main() {
	if fail == "1" {
		_, _ = os.Stderr.WriteString("fatal smoke error\n")
		os.Exit(1)
	}
	_, _ = os.Stdout.WriteString("agent-bridge " + ver + "\n")
}
`
		if err := os.WriteFile(srcPath, []byte(src), 0o600); err != nil {
			testBinsErr = err
			return
		}

		ext := ""
		if runtime.GOOS == "windows" {
			ext = ".exe"
		}
		buildOne := func(name, ldflags string) ([]byte, error) {
			outPath := filepath.Join(dir, name+ext)
			cmd := exec.Command("go", "build", "-ldflags="+ldflags, "-o", outPath, srcPath)
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
			if out, bErr := cmd.CombinedOutput(); bErr != nil {
				return nil, fmt.Errorf("go build %s failed: %v (%s)", name, bErr, string(out))
			}
			return os.ReadFile(outPath)
		}

		testBinV011, testBinsErr = buildOne("v011", "-X main.ver=v0.1.1 -X main.fail=0")
		if testBinsErr != nil {
			return
		}
		testBinV020, testBinsErr = buildOne("v020", "-X main.ver=v0.2.0 -X main.fail=0")
		if testBinsErr != nil {
			return
		}
		testBinBad, testBinsErr = buildOne("broken", "-X main.ver=v0.2.0 -X main.fail=1")
	})
	if testBinsErr != nil {
		t.Fatalf("failed building test binaries: %v", testBinsErr)
	}
	return testBinV011, testBinV020, testBinBad
}

func isolateEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"HTTP_PROXY", "http_proxy",
		"HTTPS_PROXY", "https_proxy",
		"NO_PROXY", "no_proxy",
		"AGENT_BRIDGE_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN",
		EnvInExec,
	} {
		t.Setenv(k, "")
	}
}

func writeExecutable(t *testing.T, dir, baseName string, content []byte) string {
	t.Helper()
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(baseName), ".exe") {
		baseName += ".exe"
	}
	p := filepath.Join(dir, baseName)
	if err := os.WriteFile(p, content, 0o755); err != nil {
		t.Fatalf("WriteFile(%q): %v", p, err)
	}
	return p
}

func execVersionOutput(t *testing.T, exePath string) string {
	t.Helper()
	out, err := exec.Command(exePath, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("executing %q version failed: %v (%s)", exePath, err, string(out))
	}
	return strings.TrimSpace(string(out))
}

func assertNoStageFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".agent-bridge.stage.") {
			t.Fatalf("unexpected leftover staging file in %q: %s", dir, e.Name())
		}
	}
}

type mockReleaseFixture struct {
	pubKey             ed25519.PublicKey
	privKey            ed25519.PrivateKey
	tag                string
	assetName          string
	binaryPayload      []byte
	servedBinary       []byte // defaults to binaryPayload unless overridden to simulate tamper
	tamperChecksums    bool
	omitSignatureAsset bool
	sig404             bool
	binaryHits         atomic.Int32
	checksumHits       atomic.Int32
	sigHits            atomic.Int32
	lastAuthHeader     atomic.Value
	usedAssetAPI       atomic.Bool
}

func newReleaseServer(t *testing.T, fx *mockReleaseFixture) *httptest.Server {
	t.Helper()
	if fx.pubKey == nil || fx.privKey == nil {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		fx.pubKey = pub
		fx.privKey = priv
	}
	if fx.tag == "" {
		fx.tag = "v0.2.0"
	}
	if fx.assetName == "" {
		name, err := AssetNameForPlatform(runtime.GOOS, runtime.GOARCH)
		if err != nil {
			t.Fatalf("AssetNameForPlatform: %v", err)
		}
		fx.assetName = name
	}
	if fx.servedBinary == nil {
		fx.servedBinary = fx.binaryPayload
	}

	sum := sha256.Sum256(fx.binaryPayload)
	checksumsText := fmt.Sprintf(
		"%s  %s\n%s  agent-bridge-other-arch\n",
		hex.EncodeToString(sum[:]),
		fx.assetName,
		strings.Repeat("a", 64),
	)
	sigBytes := ed25519.Sign(fx.privKey, []byte(checksumsText))
	sigHex := hex.EncodeToString(sigBytes) + "\n"

	servedChecksums := checksumsText
	if fx.tamperChecksums {
		tamperedSum := sha256.Sum256(fx.servedBinary)
		servedChecksums = fmt.Sprintf("%s  %s\n", hex.EncodeToString(tamperedSum[:]), fx.assetName)
		if servedChecksums == checksumsText {
			servedChecksums += "# tampered\n"
		}
	}

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-GitHub-Request-Id", "ABCD:1234")
		if auth := r.Header.Get("Authorization"); auth != "" {
			fx.lastAuthHeader.Store(auth)
		}

		releasePayload := func(tag string, prerelease bool) githubRelease {
			assets := []githubAsset{
				{
					Name:               fx.assetName,
					URL:                srv.URL + "/repos/kennyparsons/agent-bridge/releases/assets/101",
					BrowserDownloadURL: srv.URL + "/download/" + tag + "/" + fx.assetName,
					Size:               int64(len(fx.binaryPayload)),
				},
				{
					Name:               ChecksumsAssetName,
					URL:                srv.URL + "/repos/kennyparsons/agent-bridge/releases/assets/102",
					BrowserDownloadURL: srv.URL + "/download/" + tag + "/" + ChecksumsAssetName,
					Size:               int64(len(servedChecksums)),
				},
			}
			if !fx.omitSignatureAsset {
				assets = append(assets, githubAsset{
					Name:               SignatureAssetName,
					URL:                srv.URL + "/repos/kennyparsons/agent-bridge/releases/assets/103",
					BrowserDownloadURL: srv.URL + "/download/" + tag + "/" + SignatureAssetName,
					Size:               int64(len(sigHex)),
				})
			}
			return githubRelease{
				TagName:     tag,
				Name:        tag,
				Prerelease:  prerelease,
				HTMLURL:     srv.URL + "/html/releases/" + tag,
				PublishedAt: "2026-11-08T03:00:00Z",
				Assets:      assets,
			}
		}

		switch r.URL.Path {
		case "/repos/kennyparsons/agent-bridge/releases/latest",
			"/repos/kennyparsons/agent-bridge/releases/tags/" + fx.tag:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(releasePayload(fx.tag, false))

		case "/repos/kennyparsons/agent-bridge/releases":
			list := []githubRelease{
				{TagName: "v0.9.0-draft", Draft: true, Prerelease: true},
				releasePayload("v0.2.0", false),
				releasePayload(fx.tag, strings.Contains(fx.tag, "-")),
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(list)

		case "/repos/kennyparsons/agent-bridge/releases/assets/101":
			if r.Header.Get("Accept") != "application/octet-stream" {
				http.Error(w, "missing Accept: application/octet-stream", http.StatusBadRequest)
				return
			}
			fx.usedAssetAPI.Store(true)
			http.Redirect(w, r, srv.URL+"/download/"+fx.tag+"/"+fx.assetName, http.StatusFound)

		case "/repos/kennyparsons/agent-bridge/releases/assets/102":
			if r.Header.Get("Accept") != "application/octet-stream" {
				http.Error(w, "missing Accept: application/octet-stream", http.StatusBadRequest)
				return
			}
			fx.usedAssetAPI.Store(true)
			http.Redirect(w, r, srv.URL+"/download/"+fx.tag+"/"+ChecksumsAssetName, http.StatusFound)

		case "/repos/kennyparsons/agent-bridge/releases/assets/103":
			if r.Header.Get("Accept") != "application/octet-stream" {
				http.Error(w, "missing Accept: application/octet-stream", http.StatusBadRequest)
				return
			}
			fx.usedAssetAPI.Store(true)
			http.Redirect(w, r, srv.URL+"/download/"+fx.tag+"/"+SignatureAssetName, http.StatusFound)

		case "/download/" + fx.tag + "/" + ChecksumsAssetName:
			fx.checksumHits.Add(1)
			_, _ = w.Write([]byte(servedChecksums))

		case "/download/" + fx.tag + "/" + SignatureAssetName:
			fx.sigHits.Add(1)
			if fx.sig404 {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(sigHex))

		case "/download/" + fx.tag + "/" + fx.assetName:
			fx.binaryHits.Add(1)
			_, _ = w.Write(fx.servedBinary)

		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDefaultReleasePublicKeysAndSignatureParsing(t *testing.T) {
	if len(DefaultReleasePublicKeys) != 1 {
		t.Fatalf("len(DefaultReleasePublicKeys) = %d, want 1", len(DefaultReleasePublicKeys))
	}
	gotHex := hex.EncodeToString(DefaultReleasePublicKeys[0])
	const wantHex = "66541112f44401142904d2d931e4cd181e8b235d12fe3126a8fe892aa35a6d8f"
	if DefaultReleasePublicKeyHex != wantHex || gotHex != wantHex {
		t.Fatalf("compiled public key = %q, want %q", gotHex, wantHex)
	}

	parsedPub, err := ParsePublicKeyHex("  " + wantHex + "\n")
	if err != nil {
		t.Fatalf("ParsePublicKeyHex failed: %v", err)
	}
	if !bytes.Equal(parsedPub, DefaultReleasePublicKeys[0]) {
		t.Fatal("ParsePublicKeyHex mismatch")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	payload := []byte("abc123  agent-bridge-linux-amd64\n")
	rawSig := ed25519.Sign(priv, payload)
	hexSig := []byte(hex.EncodeToString(rawSig) + "\r\n")

	if err := VerifyDetachedEd25519(payload, hexSig, []ed25519.PublicKey{pub}); err != nil {
		t.Fatalf("hex signature verify failed: %v", err)
	}
	if err := VerifyDetachedEd25519(payload, rawSig, []ed25519.PublicKey{pub}); err != nil {
		t.Fatalf("raw 64-byte signature verify failed: %v", err)
	}
}

func TestSemVerAndPlatformAssets(t *testing.T) {
	ordered := []string{
		"v0.1.0",
		"0.1.1",
		"v0.2.0-alpha.1",
		"v0.2.0-alpha.2",
		"v0.2.0-alpha.10",
		"v0.2.0-beta.1",
		"v0.2.0-rc.1+build.9",
		"v0.2.0+20261108",
		"v1.0.0",
	}
	for i := 0; i < len(ordered)-1; i++ {
		cmp, err := CompareSemVer(ordered[i], ordered[i+1])
		if err != nil {
			t.Fatalf("CompareSemVer(%q, %q) error: %v", ordered[i], ordered[i+1], err)
		}
		if cmp >= 0 {
			t.Fatalf("CompareSemVer(%q, %q) = %d, want -1", ordered[i], ordered[i+1], cmp)
		}
	}

	eqCmp, err := CompareSemVer("v0.2.0+build.1", "0.2.0+build.2")
	if err != nil || eqCmp != 0 {
		t.Fatalf("CompareSemVer build metadata = (%d, %v), want (0, nil)", eqCmp, err)
	}

	for _, bad := range []string{"", "v", "v1.2", "v01.2.3", "v1.2.3-01", "vv1.2.3", "v1.2.3-", "v1.2.3+"} {
		if _, err := ParseSemVer(bad); err == nil {
			t.Fatalf("ParseSemVer(%q) unexpectedly succeeded", bad)
		}
	}

	for _, dev := range []string{"", "dev", "devel", "(devel)", "72d161e", "v0.1.1-dirty", "v0.1.1-4-g72d161e", "v0.0.0-dev"} {
		if !IsDevBuild(dev) {
			t.Fatalf("IsDevBuild(%q) = false, want true", dev)
		}
	}
	for _, rel := range []string{"v0.1.1", "0.2.0", "v0.2.0-rc.1", "v1.0.0-beta.2"} {
		if IsDevBuild(rel) {
			t.Fatalf("IsDevBuild(%q) = true, want false", rel)
		}
	}

	gotWin, err := AssetNameForPlatform("windows", "amd64")
	if err != nil || gotWin != "agent-bridge-windows-amd64.exe" {
		t.Fatalf("windows/amd64 = (%q, %v)", gotWin, err)
	}
	gotLinux, err := AssetNameForPlatform("linux", "arm64")
	if err != nil || gotLinux != "agent-bridge-linux-arm64" {
		t.Fatalf("linux/arm64 = (%q, %v)", gotLinux, err)
	}
	if _, err := AssetNameForPlatform("../linux", "amd64"); err == nil {
		t.Fatal("expected error for invalid GOOS")
	}
}

func TestCheckModeUpToDateUpdateAvailableAndDevBuild(t *testing.T) {
	isolateEnv(t)
	_, binV020, _ := ensureTestBinaries(t)
	fx := &mockReleaseFixture{
		tag:           "v0.2.0",
		binaryPayload: binV020,
	}
	srv := newReleaseServer(t, fx)

	baseOpts := Options{
		APIBaseURL:        srv.URL,
		TrustedPublicKeys: []ed25519.PublicKey{fx.pubKey},
		NoProxy:           true,
	}

	// 1. Up-to-date
	o1 := baseOpts
	o1.CurrentVersion = "v0.2.0"
	res1, err := Check(context.Background(), o1)
	if err != nil {
		t.Fatalf("Check up-to-date failed: %v", err)
	}
	if res1.UpdateAvailable || res1.CurrentIsDev || !res1.SignatureVerified {
		t.Fatalf("unexpected up-to-date CheckResult: %+v", res1)
	}

	// 2. Update available
	o2 := baseOpts
	o2.CurrentVersion = "v0.1.1"
	res2, err := Check(context.Background(), o2)
	if err != nil {
		t.Fatalf("Check update-available failed: %v", err)
	}
	if !res2.UpdateAvailable || res2.CurrentIsDev || res2.TargetVersion != "v0.2.0" || !res2.SignatureVerified {
		t.Fatalf("unexpected update-available CheckResult: %+v", res2)
	}
	wantHash := sha256.Sum256(binV020)
	if res2.ExpectedSHA256 != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("ExpectedSHA256 = %q, want %x", res2.ExpectedSHA256, wantHash)
	}

	// 3. Dev build
	o3 := baseOpts
	o3.CurrentVersion = "dev"
	res3, err := Check(context.Background(), o3)
	if err != nil {
		t.Fatalf("Check dev-build failed: %v", err)
	}
	if !res3.UpdateAvailable || !res3.CurrentIsDev || !strings.Contains(res3.Message, "development build") {
		t.Fatalf("unexpected dev-build CheckResult: %+v", res3)
	}

	if fx.binaryHits.Load() != 0 {
		t.Fatalf("--check must never download binary asset; got %d binary hits", fx.binaryHits.Load())
	}
}

func TestEndToEndUpgradeAtomicSwapAndSweepOldExecutables(t *testing.T) {
	isolateEnv(t)
	binV011, binV020, _ := ensureTestBinaries(t)

	fx := &mockReleaseFixture{
		tag:           "v0.2.0",
		binaryPayload: binV020,
	}
	srv := newReleaseServer(t, fx)

	tmpDir := t.TempDir()
	exePath := writeExecutable(t, tmpDir, "agent-bridge", binV011)
	if got := execVersionOutput(t, exePath); got != "agent-bridge v0.1.1" {
		t.Fatalf("initial binary version = %q", got)
	}

	res, err := Run(context.Background(), Options{
		CurrentVersion:    "dev",
		APIBaseURL:        srv.URL,
		TrustedPublicKeys: []ed25519.PublicKey{fx.pubKey},
		ExecutablePath:    exePath,
		NoProxy:           true,
	})
	if err != nil {
		t.Fatalf("Run upgrade failed: %v", err)
	}
	if !res.Upgraded || !res.SignatureVerified || res.TargetVersion != "v0.2.0" {
		t.Fatalf("unexpected upgrade Result: %+v", res)
	}
	if got := execVersionOutput(t, exePath); got != "agent-bridge v0.2.0" {
		t.Fatalf("upgraded binary version = %q, want agent-bridge v0.2.0", got)
	}
	assertNoStageFiles(t, tmpDir)

	// Verify SweepOldExecutables removes <exe>.old and <exe>.old.* without touching unrelated files.
	staleOld := exePath + ".old"
	staleRot := exePath + ".old.1731000001"
	keepFile := filepath.Join(tmpDir, "config.json")
	for _, p := range []string{staleOld, staleRot, keepFile} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile(%q): %v", p, err)
		}
	}

	SweepOldExecutables(exePath)

	for _, removed := range []string{staleOld, staleRot} {
		if _, err := os.Stat(removed); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected %q to be swept, stat err = %v", removed, err)
		}
	}
	for _, kept := range []string{exePath, keepFile} {
		if _, err := os.Stat(kept); err != nil {
			t.Fatalf("expected %q to remain intact: %v", kept, err)
		}
	}
}

func TestTamperedChecksumsRejectedBeforeBinaryDownload(t *testing.T) {
	isolateEnv(t)
	binV011, binV020, _ := ensureTestBinaries(t)

	fx := &mockReleaseFixture{
		tag:             "v0.2.0",
		binaryPayload:   binV020,
		tamperChecksums: true,
	}
	srv := newReleaseServer(t, fx)

	tmpDir := t.TempDir()
	exePath := writeExecutable(t, tmpDir, "agent-bridge", binV011)

	_, err := Run(context.Background(), Options{
		CurrentVersion:    "v0.1.1",
		APIBaseURL:        srv.URL,
		TrustedPublicKeys: []ed25519.PublicKey{fx.pubKey},
		ExecutablePath:    exePath,
		NoProxy:           true,
	})
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid, got: %v", err)
	}
	if fx.binaryHits.Load() != 0 {
		t.Fatalf("expected 0 binary downloads when Ed25519 signature fails, got %d", fx.binaryHits.Load())
	}
	gotBytes, _ := os.ReadFile(exePath)
	if !bytes.Equal(gotBytes, binV011) {
		t.Fatal("live executable was modified despite Ed25519 failure")
	}
	assertNoStageFiles(t, tmpDir)
}

func TestTamperedBinaryPayloadRejectedAndCleaned(t *testing.T) {
	isolateEnv(t)
	binV011, binV020, _ := ensureTestBinaries(t)

	corrupted := make([]byte, len(binV020))
	copy(corrupted, binV020)
	corrupted[len(corrupted)/2] ^= 0xFF

	fx := &mockReleaseFixture{
		tag:           "v0.2.0",
		binaryPayload: binV020,
		servedBinary:  corrupted,
	}
	srv := newReleaseServer(t, fx)

	tmpDir := t.TempDir()
	exePath := writeExecutable(t, tmpDir, "agent-bridge", binV011)

	_, err := Run(context.Background(), Options{
		CurrentVersion:    "v0.1.1",
		APIBaseURL:        srv.URL,
		TrustedPublicKeys: []ed25519.PublicKey{fx.pubKey},
		ExecutablePath:    exePath,
		NoProxy:           true,
	})
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("expected ErrChecksumMismatch, got: %v", err)
	}
	gotBytes, _ := os.ReadFile(exePath)
	if !bytes.Equal(gotBytes, binV011) {
		t.Fatal("live executable was modified despite SHA-256 mismatch")
	}
	assertNoStageFiles(t, tmpDir)
}

func TestFailedSmokeTestLeavesLiveBinaryUntouched(t *testing.T) {
	isolateEnv(t)
	binV011, _, binBad := ensureTestBinaries(t)

	fx := &mockReleaseFixture{
		tag:           "v0.2.0",
		binaryPayload: binBad,
	}
	srv := newReleaseServer(t, fx)

	tmpDir := t.TempDir()
	exePath := writeExecutable(t, tmpDir, "agent-bridge", binV011)

	_, err := Run(context.Background(), Options{
		CurrentVersion:    "v0.1.1",
		APIBaseURL:        srv.URL,
		TrustedPublicKeys: []ed25519.PublicKey{fx.pubKey},
		ExecutablePath:    exePath,
		NoProxy:           true,
	})
	if !errors.Is(err, ErrSmokeTestFailed) {
		t.Fatalf("expected ErrSmokeTestFailed, got: %v", err)
	}
	if got := execVersionOutput(t, exePath); got != "agent-bridge v0.1.1" {
		t.Fatalf("live binary should remain v0.1.1, got %q", got)
	}
	assertNoStageFiles(t, tmpDir)
}

type mockServiceController struct {
	installed        bool
	running          bool
	serviceName      string
	restartCalls     int
	detachedCalls    int
	detachedExe      string
	detachedSvc      string
	detachedBackup   string
	detachedBackupOK bool
	restartFn        func(call int) error
}

func (m *mockServiceController) IsServiceInstalledAndRunning(context.Context) (bool, bool, string, error) {
	return m.installed, m.running, m.serviceName, nil
}

func (m *mockServiceController) RestartAndVerify(_ context.Context, _ string) error {
	m.restartCalls++
	if m.restartFn != nil {
		return m.restartFn(m.restartCalls)
	}
	return nil
}

func (m *mockServiceController) ScheduleDetachedRestart(_ context.Context, newExePath, serviceName, backupExePath string) error {
	m.detachedCalls++
	m.detachedExe = newExePath
	m.detachedSvc = serviceName
	m.detachedBackup = backupExePath
	if _, err := os.Stat(backupExePath); err == nil {
		m.detachedBackupOK = true
	}
	return nil
}

func TestServiceRestartFailureAutomaticallyRollsBackOriginalBinary(t *testing.T) {
	isolateEnv(t)
	binV011, binV020, _ := ensureTestBinaries(t)

	fx := &mockReleaseFixture{
		tag:           "v0.2.0",
		binaryPayload: binV020,
	}
	srv := newReleaseServer(t, fx)

	tmpDir := t.TempDir()
	exePath := writeExecutable(t, tmpDir, "agent-bridge", binV011)

	svc := &mockServiceController{
		installed:   true,
		running:     true,
		serviceName: "agent-bridge",
	}
	svc.restartFn = func(call int) error {
		ver := execVersionOutput(t, exePath)
		if call == 1 {
			if ver != "agent-bridge v0.2.0" {
				t.Fatalf("expected v0.2.0 on first restart attempt, got %q", ver)
			}
			return errors.New("service exited immediately with code 1")
		}
		if ver != "agent-bridge v0.1.1" {
			t.Fatalf("expected rollback to restore v0.1.1 before second restart, got %q", ver)
		}
		return nil
	}

	_, err := Run(context.Background(), Options{
		CurrentVersion:    "v0.1.1",
		APIBaseURL:        srv.URL,
		TrustedPublicKeys: []ed25519.PublicKey{fx.pubKey},
		ExecutablePath:    exePath,
		ServiceController: svc,
		NoProxy:           true,
	})
	if !errors.Is(err, ErrServiceRestartFailed) {
		t.Fatalf("expected ErrServiceRestartFailed, got: %v", err)
	}
	if !strings.Contains(err.Error(), "automatic rollback succeeded") {
		t.Fatalf("expected rollback confirmation in error, got: %v", err)
	}
	if svc.restartCalls != 2 {
		t.Fatalf("restartCalls = %d, want 2 (upgrade attempt + rollback restart)", svc.restartCalls)
	}
	if got := execVersionOutput(t, exePath); got != "agent-bridge v0.1.1" {
		t.Fatalf("rolled-back binary version = %q, want agent-bridge v0.1.1", got)
	}
}

func TestInExecSessionSchedulesDetachedRestartInsteadOfSynchronousStop(t *testing.T) {
	isolateEnv(t)
	t.Setenv(EnvInExec, "1")
	binV011, binV020, _ := ensureTestBinaries(t)

	fx := &mockReleaseFixture{
		tag:           "v0.2.0",
		binaryPayload: binV020,
	}
	srv := newReleaseServer(t, fx)

	tmpDir := t.TempDir()
	exePath := writeExecutable(t, tmpDir, "agent-bridge", binV011)

	svc := &mockServiceController{
		installed:   true,
		running:     true,
		serviceName: "agent-bridge",
	}

	res, err := Run(context.Background(), Options{
		CurrentVersion:    "v0.1.1",
		APIBaseURL:        srv.URL,
		TrustedPublicKeys: []ed25519.PublicKey{fx.pubKey},
		ExecutablePath:    exePath,
		ServiceController: svc,
		NoProxy:           true,
	})
	if err != nil {
		t.Fatalf("Run in exec session failed: %v", err)
	}
	if svc.restartCalls != 0 {
		t.Fatalf("synchronous RestartAndVerify must NOT be called when AGENT_BRIDGE_IN_EXEC=1; got %d calls", svc.restartCalls)
	}
	if svc.detachedCalls != 1 || !svc.detachedBackupOK {
		t.Fatalf("expected 1 detached restart call with valid backup file; calls=%d backupOK=%v", svc.detachedCalls, svc.detachedBackupOK)
	}
	if !res.ServiceRestartScheduled || res.RestartMode != RestartModeDetached {
		t.Fatalf("unexpected Result restart metadata: %+v", res)
	}
	if got := execVersionOutput(t, exePath); got != "agent-bridge v0.2.0" {
		t.Fatalf("upgraded binary version = %q, want agent-bridge v0.2.0", got)
	}
}

func TestBrokenHTTPProxy502AndDeadProxyAutomaticDirectFallback(t *testing.T) {
	isolateEnv(t)
	binV011, binV020, _ := ensureTestBinaries(t)

	fx := &mockReleaseFixture{
		tag:           "v0.2.0",
		binaryPayload: binV020,
	}
	githubSrv := newReleaseServer(t, fx)

	var proxyHits atomic.Int32
	brokenProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHits.Add(1)
		http.Error(w, "corporate gateway upstream failure", http.StatusBadGateway)
	}))
	t.Cleanup(brokenProxy.Close)

	t.Setenv("HTTP_PROXY", brokenProxy.URL)
	t.Setenv("HTTPS_PROXY", brokenProxy.URL)
	t.Setenv("NO_PROXY", "")

	tmpDir := t.TempDir()
	exePath := writeExecutable(t, tmpDir, "agent-bridge", binV011)

	res, err := Run(context.Background(), Options{
		CurrentVersion:    "v0.1.1",
		APIBaseURL:        githubSrv.URL,
		TrustedPublicKeys: []ed25519.PublicKey{fx.pubKey},
		ExecutablePath:    exePath,
		NoProxy:           false,
	})
	if err != nil {
		t.Fatalf("expected automatic direct fallback on 502 proxy, got error: %v", err)
	}
	if proxyHits.Load() == 0 {
		t.Fatal("expected HTTP_PROXY to be attempted first before failing over")
	}
	if !res.ProxyFallbackUsed || !res.Upgraded {
		t.Fatalf("expected ProxyFallbackUsed=true and Upgraded=true, got %+v", res)
	}
	if got := execVersionOutput(t, exePath); got != "agent-bridge v0.2.0" {
		t.Fatalf("upgraded binary version = %q", got)
	}

	// Also verify connection-refused dead proxy falls back cleanly.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()

	t.Setenv("HTTP_PROXY", "http://"+deadAddr)
	chk, err := Check(context.Background(), Options{
		CurrentVersion:    "v0.1.1",
		APIBaseURL:        githubSrv.URL,
		TrustedPublicKeys: []ed25519.PublicKey{fx.pubKey},
		NoProxy:           false,
	})
	if err != nil || !chk.UpdateAvailable {
		t.Fatalf("dead proxy fallback Check failed: chk=%+v err=%v", chk, err)
	}
}

func TestAuthenticatedAssetDownloadAndLegacyUnsignedHandling(t *testing.T) {
	isolateEnv(t)
	binV011, binV020, _ := ensureTestBinaries(t)

	// 1. Authenticated download uses asset API URL + Bearer token.
	t.Setenv("AGENT_BRIDGE_GITHUB_TOKEN", "ghs_testtoken123")
	fxAuth := &mockReleaseFixture{
		tag:           "v0.2.0",
		binaryPayload: binV020,
	}
	srvAuth := newReleaseServer(t, fxAuth)
	chk, err := Check(context.Background(), Options{
		CurrentVersion:    "v0.1.1",
		APIBaseURL:        srvAuth.URL,
		TrustedPublicKeys: []ed25519.PublicKey{fxAuth.pubKey},
		NoProxy:           true,
	})
	if err != nil || !chk.SignatureVerified {
		t.Fatalf("authenticated Check failed: %v", err)
	}
	if gotAuth, _ := fxAuth.lastAuthHeader.Load().(string); gotAuth != "Bearer ghs_testtoken123" {
		t.Fatalf("Authorization header = %q, want Bearer ghs_testtoken123", gotAuth)
	}
	if !fxAuth.usedAssetAPI.Load() {
		t.Fatal("expected authenticated client to use asset API URL with Accept: application/octet-stream")
	}

	// 2. Legacy release missing SHA256SUMS.txt.sig (404) requires --allow-unsigned by default.
	t.Setenv("AGENT_BRIDGE_GITHUB_TOKEN", "")
	fxUnsigned := &mockReleaseFixture{
		tag:           "v0.1.1",
		binaryPayload: binV011,
		sig404:        true,
	}
	srvUnsigned := newReleaseServer(t, fxUnsigned)
	tmpDir := t.TempDir()
	exePath := writeExecutable(t, tmpDir, "agent-bridge", binV020)

	_, err = Run(context.Background(), Options{
		CurrentVersion:    "dev",
		TargetVersion:     "v0.1.1",
		APIBaseURL:        srvUnsigned.URL,
		TrustedPublicKeys: []ed25519.PublicKey{fxUnsigned.pubKey},
		ExecutablePath:    exePath,
		NoProxy:           true,
	})
	if !errors.Is(err, ErrSignatureMissing) || !strings.Contains(err.Error(), "--allow-unsigned") {
		t.Fatalf("expected ErrSignatureMissing mentioning --allow-unsigned, got: %v", err)
	}
	if fxUnsigned.binaryHits.Load() != 0 {
		t.Fatal("binary should not be downloaded when signature is missing and AllowUnsigned=false")
	}

	resUnsigned, err := Run(context.Background(), Options{
		CurrentVersion:    "dev",
		TargetVersion:     "v0.1.1",
		AllowUnsigned:     true,
		APIBaseURL:        srvUnsigned.URL,
		TrustedPublicKeys: []ed25519.PublicKey{fxUnsigned.pubKey},
		ExecutablePath:    exePath,
		NoProxy:           true,
	})
	if err != nil {
		t.Fatalf("expected AllowUnsigned=true to succeed on legacy release, got: %v", err)
	}
	if !resUnsigned.Upgraded || resUnsigned.SignatureVerified {
		t.Fatalf("expected Upgraded=true and SignatureVerified=false, got: %+v", resUnsigned)
	}
}

func TestPrereleaseChannelAndDirectMirrorOverride(t *testing.T) {
	isolateEnv(t)
	_, binV020, _ := ensureTestBinaries(t)

	fx := &mockReleaseFixture{
		tag:           "v0.3.0-rc.2",
		binaryPayload: binV020,
	}
	srv := newReleaseServer(t, fx)

	chk, err := Check(context.Background(), Options{
		CurrentVersion:    "v0.2.0",
		Channel:           ChannelPrerelease,
		APIBaseURL:        srv.URL,
		TrustedPublicKeys: []ed25519.PublicKey{fx.pubKey},
		NoProxy:           true,
	})
	if err != nil {
		t.Fatalf("prerelease Check failed: %v", err)
	}
	if chk.TargetVersion != "v0.3.0-rc.2" || !chk.UpdateAvailable {
		t.Fatalf("expected v0.3.0-rc.2 prerelease update, got: %+v", chk)
	}

	// Direct mirror override test
	chkDirect, err := Check(context.Background(), Options{
		CurrentVersion:    "v0.1.1",
		TargetVersion:     "v0.3.0-rc.2",
		DirectAssetURL:    srv.URL + "/download/v0.3.0-rc.2/" + fx.assetName,
		ChecksumsURL:      srv.URL + "/download/v0.3.0-rc.2/" + ChecksumsAssetName,
		SignatureURL:      srv.URL + "/download/v0.3.0-rc.2/" + SignatureAssetName,
		TrustedPublicKeys: []ed25519.PublicKey{fx.pubKey},
		NoProxy:           true,
	})
	if err != nil || !chkDirect.SignatureVerified || !chkDirect.UpdateAvailable {
		t.Fatalf("direct mirror Check failed: chk=%+v err=%v", chkDirect, err)
	}
}

func TestUpToDateSkipDowngradeGuardCrossOSSmokeAndNoProxyRules(t *testing.T) {
	isolateEnv(t)
	binV011, binV020, _ := ensureTestBinaries(t)

	fx := &mockReleaseFixture{
		tag:           "v0.2.0",
		binaryPayload: binV020,
	}
	srv := newReleaseServer(t, fx)

	tmpDir := t.TempDir()
	exePath := writeExecutable(t, tmpDir, "agent-bridge", binV020)

	// 1. Already up to date -> skips binary download.
	resUpToDate, err := Run(context.Background(), Options{
		CurrentVersion:    "v0.2.0",
		APIBaseURL:        srv.URL,
		TrustedPublicKeys: []ed25519.PublicKey{fx.pubKey},
		ExecutablePath:    exePath,
		NoProxy:           true,
	})
	if err != nil {
		t.Fatalf("Run already-up-to-date failed: %v", err)
	}
	if resUpToDate.Upgraded || !resUpToDate.AlreadyUpToDate || fx.binaryHits.Load() != 0 {
		t.Fatalf("expected AlreadyUpToDate without binary download, got res=%+v hits=%d", resUpToDate, fx.binaryHits.Load())
	}

	// 2. Explicit downgrade without --force is rejected; Force allows it.
	_, err = Run(context.Background(), Options{
		CurrentVersion:    "v0.3.0",
		TargetVersion:     "0.2.0",
		APIBaseURL:        srv.URL,
		TrustedPublicKeys: []ed25519.PublicKey{fx.pubKey},
		ExecutablePath:    exePath,
		NoProxy:           true,
	})
	if !errors.Is(err, ErrDowngradeNotAllowed) {
		t.Fatalf("expected ErrDowngradeNotAllowed, got: %v", err)
	}

	resForced, err := Run(context.Background(), Options{
		CurrentVersion:    "v0.3.0",
		TargetVersion:     "0.2.0",
		Force:             true,
		APIBaseURL:        srv.URL,
		TrustedPublicKeys: []ed25519.PublicKey{fx.pubKey},
		ExecutablePath:    exePath,
		NoProxy:           true,
	})
	if err != nil || !resForced.Upgraded {
		t.Fatalf("expected forced downgrade to succeed, res=%+v err=%v", resForced, err)
	}

	// 3. Cross-OS target asset with custom SmokeTestFn + symlinked executable path.
	fxWin := &mockReleaseFixture{
		tag:           "v0.2.0",
		assetName:     "agent-bridge-windows-amd64.exe",
		binaryPayload: binV020,
	}
	srvWin := newReleaseServer(t, fxWin)

	realTarget := writeExecutable(t, tmpDir, "real-bridge", binV011)
	targetForUpgrade := realTarget
	if runtime.GOOS != "windows" {
		linkPath := filepath.Join(tmpDir, "symlink-bridge")
		if err := os.Symlink(realTarget, linkPath); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		targetForUpgrade = linkPath
	}

	smokeCalled := false
	resCross, err := Run(context.Background(), Options{
		CurrentVersion:    "v0.1.1",
		GOOS:              "windows",
		GOARCH:            "amd64",
		APIBaseURL:        srvWin.URL,
		TrustedPublicKeys: []ed25519.PublicKey{fxWin.pubKey},
		ExecutablePath:    targetForUpgrade,
		NoProxy:           true,
		SmokeTestFn: func(_ context.Context, stagedPath string) error {
			smokeCalled = true
			if !strings.HasSuffix(stagedPath, ".exe") {
				return fmt.Errorf("expected .exe staged suffix for windows target, got %q", stagedPath)
			}
			return nil
		},
	})
	if err != nil || !smokeCalled || !resCross.Upgraded {
		t.Fatalf("cross-OS SmokeTestFn upgrade failed: smokeCalled=%v res=%+v err=%v", smokeCalled, resCross, err)
	}

	// 4. NO_PROXY CIDR/domain/wildcard matching.
	rules := parseNoProxyRules("127.0.0.0/8, .internal.example, exact.example:8443")
	for _, rawURL := range []string{
		"http://127.0.0.1:8080/x",
		"https://api.internal.example/v1",
		"https://exact.example:8443/v1",
	} {
		req, _ := netURLParse(t, rawURL)
		if !shouldBypassProxy(req.URL, rules) {
			t.Fatalf("expected %q to bypass proxy", rawURL)
		}
	}
	for _, rawURL := range []string{
		"https://internal.example/v1",
		"https://exact.example:443/v1",
		"https://api.github.com/repos",
	} {
		req, _ := netURLParse(t, rawURL)
		if shouldBypassProxy(req.URL, rules) {
			t.Fatalf("expected %q NOT to bypass proxy", rawURL)
		}
	}
}

func netURLParse(t *testing.T, raw string) (*http.Request, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		t.Fatalf("http.NewRequest(%q): %v", raw, err)
	}
	return req, nil
}
