// Package upgrade implements Ed25519-verified self-upgrades from GitHub Releases
// (or direct mirrors) with proxy-failover transport, streaming SHA-256 verification,
// pre-swap smoke execution, cross-OS atomic binary replacement, and service rollback.
package upgrade

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// DefaultRepo is the default "<owner>/<repo>" queried on GitHub Releases.
	DefaultRepo = "kennyparsons/agent-bridge"

	// DefaultGitHubAPIBaseURL is the default GitHub REST API base URL.
	DefaultGitHubAPIBaseURL = "https://api.github.com"

	// ChannelStable selects the latest stable non-prerelease GitHub Release.
	ChannelStable = "stable"

	// ChannelPrerelease selects the highest-SemVer non-draft GitHub Release (including prereleases).
	ChannelPrerelease = "prerelease"

	// EnvInExec is set to "1" inside `agent-bridge exec` child environments so selfupgrade
	// schedules a detached 500ms service restart instead of killing its own parent session mid-flight.
	EnvInExec = "AGENT_BRIDGE_IN_EXEC"

	// DefaultHTTPTimeout caps individual HTTP client operations when Options.HTTPTimeout is unset.
	DefaultHTTPTimeout = 5 * time.Minute
)

// RestartMode describes how a running system service was handled after binary replacement.
type RestartMode string

const (
	RestartModeNone        RestartMode = "none"
	RestartModeSynchronous RestartMode = "synchronous"
	RestartModeDetached    RestartMode = "detached"
)

// SmokeTestFunc validates a newly staged binary before it replaces the live executable.
type SmokeTestFunc func(ctx context.Context, stagedBinaryPath string) error

// ServiceController abstracts OS service inspection, synchronous restart+health verification,
// and detached background restart when upgrading from inside an active `agent-bridge exec` session.
type ServiceController interface {
	IsServiceInstalledAndRunning(ctx context.Context) (installed bool, running bool, serviceName string, err error)
	RestartAndVerify(ctx context.Context, serviceName string) error
	ScheduleDetachedRestart(ctx context.Context, newExePath, serviceName, backupExePath string) error
}

// Options configures a version check or in-place self-upgrade run.
type Options struct {
	// CurrentVersion is the running binary's compiled-in version (e.g. "v0.1.1" or "dev").
	CurrentVersion string

	// TargetVersion is "" / "latest" or an explicit release tag (e.g. "v0.2.0").
	TargetVersion string

	// Channel selects "stable" (default) or "prerelease" when TargetVersion is "" or "latest".
	Channel string

	// Repo overrides DefaultRepo ("kennyparsons/agent-bridge").
	Repo string

	// APIBaseURL overrides DefaultGitHubAPIBaseURL ("https://api.github.com").
	APIBaseURL string

	// DirectAssetURL, ChecksumsURL, and SignatureURL bypass GitHub Releases API discovery
	// to download artifacts directly from an internal mirror or custom URL.
	DirectAssetURL string
	ChecksumsURL   string
	SignatureURL   string

	// GitHubToken overrides environment lookup (AGENT_BRIDGE_GITHUB_TOKEN, GITHUB_TOKEN, GH_TOKEN).
	GitHubToken string

	// NoProxy bypasses HTTP_PROXY/HTTPS_PROXY and dials directly with Proxy: nil.
	NoProxy bool

	// CheckOnly (--check) verifies release metadata, signature, and checksums without modifying disk.
	CheckOnly bool

	// Force installs TargetVersion even when CurrentVersion is already equal or newer.
	Force bool

	// AllowDowngrade permits installing an explicit older TargetVersion without Force.
	AllowDowngrade bool

	// AllowUnsigned (--allow-unsigned) permits legacy releases that lack SHA256SUMS.txt.sig.
	// When false (the default), SHA256SUMS.txt.sig is strictly required.
	AllowUnsigned bool

	// TrustedPublicKeys overrides DefaultReleasePublicKeys when non-nil.
	TrustedPublicKeys []ed25519.PublicKey

	// ExecutablePath overrides os.Executable() resolution (primarily for tests).
	ExecutablePath string

	// GOOS and GOARCH override runtime.GOOS and runtime.GOARCH for asset selection.
	GOOS   string
	GOARCH string

	// SmokeTestFn overrides default `<stagedPath> version` execution (used in cross-OS tests).
	SmokeTestFn SmokeTestFunc

	// SmokeTimeout overrides DefaultSmokeTimeout (5s).
	SmokeTimeout time.Duration

	// HTTPTimeout overrides DefaultHTTPTimeout (5m).
	HTTPTimeout time.Duration

	// ServiceController coordinates OS service restart and post-restart rollback.
	ServiceController ServiceController

	// SkipServiceRestart replaces the executable on disk without restarting a running service.
	SkipServiceRestart bool

	// InExecSession forces detached service restart (also enabled automatically when AGENT_BRIDGE_IN_EXEC=1).
	InExecSession bool

	// Getenv overrides os.Getenv when non-nil.
	Getenv func(string) string

	// Logf receives optional diagnostic messages (such as proxy failover notices).
	Logf func(format string, args ...any)
}

// CheckResult reports release discovery and cryptographic manifest inspection without modifying disk.
type CheckResult struct {
	CurrentVersion    string `json:"current_version"`
	CurrentIsDev      bool   `json:"current_is_dev,omitempty"`
	TargetVersion     string `json:"target_version"`
	Channel           string `json:"channel,omitempty"`
	UpdateAvailable   bool   `json:"update_available"`
	AssetName         string `json:"asset_name"`
	AssetSize         int64  `json:"asset_size"`
	ExpectedSHA256    string `json:"expected_sha256"`
	SignatureVerified bool   `json:"signature_verified"`
	ReleaseURL        string `json:"release_url,omitempty"`
	PublishedAt       string `json:"published_at,omitempty"`
	Message           string `json:"message,omitempty"`
}

// Result reports the outcome of Run (either --check or a full atomic upgrade).
type Result struct {
	CheckResult

	CheckOnly               bool        `json:"check_only,omitempty"`
	Upgraded                bool        `json:"upgraded"`
	AlreadyUpToDate         bool        `json:"already_up_to_date,omitempty"`
	ExecutablePath          string      `json:"executable_path,omitempty"`
	BackupPath              string      `json:"backup_path,omitempty"`
	ProxyFallbackUsed       bool        `json:"proxy_fallback_used,omitempty"`
	ServiceInstalled        bool        `json:"service_installed,omitempty"`
	ServiceWasRunning       bool        `json:"service_was_running,omitempty"`
	ServiceName             string      `json:"service_name,omitempty"`
	RestartMode             RestartMode `json:"restart_mode,omitempty"`
	ServiceRestarted        bool        `json:"service_restarted,omitempty"`
	ServiceRestartScheduled bool        `json:"service_restart_scheduled,omitempty"`
}

// Check discovers the target release, verifies SHA256SUMS.txt(.sig), and returns CheckResult
// without downloading the binary or modifying any files on disk.
func Check(ctx context.Context, opts Options) (*CheckResult, error) {
	opts.CheckOnly = true
	res, err := Run(ctx, opts)
	if err != nil {
		return nil, err
	}
	out := res.CheckResult
	return &out, nil
}

// Run executes either a read-only release check (Options.CheckOnly) or a full verified
// atomic binary upgrade with optional OS service restart and automatic rollback.
func Run(ctx context.Context, opts Options) (*Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	getenv := opts.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}

	goos := strings.ToLower(strings.TrimSpace(opts.GOOS))
	if goos == "" {
		goos = runtime.GOOS
	}
	goarch := strings.ToLower(strings.TrimSpace(opts.GOARCH))
	if goarch == "" {
		goarch = runtime.GOARCH
	}

	assetName, err := AssetNameForPlatform(goos, goarch)
	if err != nil {
		return nil, err
	}

	channel := strings.ToLower(strings.TrimSpace(opts.Channel))
	if channel == "" {
		channel = ChannelStable
	}

	client := newResilientHTTPClient(opts, getenv)
	rel, err := discoverRelease(ctx, client, opts, assetName)
	if err != nil {
		return nil, err
	}

	expectedDigest, expectedHex, sigVerified, err := fetchAndVerifyChecksums(ctx, client, rel, opts)
	if err != nil {
		return nil, err
	}

	currentRaw := strings.TrimSpace(opts.CurrentVersion)
	currentDisplay := currentRaw
	if currentDisplay == "" {
		currentDisplay = "dev"
	}
	currentIsDev := IsDevBuild(currentRaw)
	explicitTarget := strings.TrimSpace(opts.TargetVersion) != "" && !strings.EqualFold(strings.TrimSpace(opts.TargetVersion), "latest")

	updateAvailable, alreadyUpToDate, isDowngrade, msg := evaluateVersionComparison(
		currentRaw, currentDisplay, currentIsDev, rel.TagName, assetName, explicitTarget,
	)

	checkRes := CheckResult{
		CurrentVersion:    currentDisplay,
		CurrentIsDev:      currentIsDev,
		TargetVersion:     rel.TagName,
		Channel:           channel,
		UpdateAvailable:   updateAvailable,
		AssetName:         assetName,
		AssetSize:         rel.BinarySize,
		ExpectedSHA256:    expectedHex,
		SignatureVerified: sigVerified,
		ReleaseURL:        rel.ReleaseURL,
		PublishedAt:       rel.PublishedAt,
		Message:           msg,
	}

	if opts.CheckOnly {
		return &Result{
			CheckResult:       checkRes,
			CheckOnly:         true,
			ProxyFallbackUsed: client.ProxyFallbackUsed(),
		}, nil
	}

	if isDowngrade && !opts.Force && !opts.AllowDowngrade {
		if explicitTarget {
			return nil, fmt.Errorf(
				"%w: current version %s is newer than requested release %s",
				ErrDowngradeNotAllowed, currentDisplay, rel.TagName,
			)
		}
		return &Result{
			CheckResult:       checkRes,
			Upgraded:          false,
			AlreadyUpToDate:   true,
			ProxyFallbackUsed: client.ProxyFallbackUsed(),
			RestartMode:       RestartModeNone,
		}, nil
	}

	if alreadyUpToDate && !opts.Force {
		return &Result{
			CheckResult:       checkRes,
			Upgraded:          false,
			AlreadyUpToDate:   true,
			ProxyFallbackUsed: client.ProxyFallbackUsed(),
			RestartMode:       RestartModeNone,
		}, nil
	}

	exePath, err := ResolveExecutablePath(opts.ExecutablePath)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(exePath)
	if err != nil {
		return nil, fmt.Errorf("failed stating target executable %q: %w", exePath, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("target executable %q is not a regular file", exePath)
	}

	var svcInstalled, svcRunning bool
	var svcName string
	if opts.ServiceController != nil && !opts.SkipServiceRestart {
		svcInstalled, svcRunning, svcName, err = opts.ServiceController.IsServiceInstalledAndRunning(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed checking system service status: %w", err)
		}
	}

	stagedPath, writtenBytes, err := stageAndVerifyBinary(ctx, client, rel, expectedDigest, exePath, goos, opts)
	if err != nil {
		return nil, err
	}
	if checkRes.AssetSize == 0 {
		checkRes.AssetSize = writtenBytes
	}

	stageSwapped := false
	defer func() {
		if !stageSwapped {
			_ = os.Remove(stagedPath)
		}
	}()

	backupPath, err := atomicSwapExecutable(exePath, stagedPath)
	if err != nil {
		return nil, err
	}
	stageSwapped = true

	res := &Result{
		CheckResult:       checkRes,
		Upgraded:          true,
		ExecutablePath:    exePath,
		ProxyFallbackUsed: client.ProxyFallbackUsed(),
		ServiceInstalled:  svcInstalled,
		ServiceWasRunning: svcRunning,
		ServiceName:       svcName,
		RestartMode:       RestartModeNone,
	}

	if opts.ServiceController == nil || opts.SkipServiceRestart || !svcRunning {
		cleanupBackupExecutable(backupPath)
		return res, nil
	}

	inExec := opts.InExecSession || strings.TrimSpace(getenv(EnvInExec)) == "1"
	if inExec {
		if err := opts.ServiceController.ScheduleDetachedRestart(ctx, exePath, svcName, backupPath); err != nil {
			if rbErr := restoreBackupExecutable(exePath, backupPath); rbErr != nil {
				return nil, fmt.Errorf(
					"failed scheduling detached restart for service %q (%v) and failed restoring backup %q (%v)",
					svcName, err, backupPath, rbErr,
				)
			}
			cleanupBackupExecutable(backupPath)
			return nil, fmt.Errorf(
				"failed scheduling detached restart for service %q (automatic rollback restored previous binary %s): %w",
				svcName, currentDisplay, err,
			)
		}
		res.BackupPath = backupPath
		res.RestartMode = RestartModeDetached
		res.ServiceRestartScheduled = true
		return res, nil
	}

	if err := opts.ServiceController.RestartAndVerify(ctx, svcName); err != nil {
		rbErr := restoreBackupExecutable(exePath, backupPath)
		if rbErr != nil {
			return nil, fmt.Errorf(
				"%w: service %q failed verification (%v) and automatic binary rollback from %q failed (%v)",
				ErrServiceRestartFailed, svcName, err, backupPath, rbErr,
			)
		}
		reErr := opts.ServiceController.RestartAndVerify(ctx, svcName)
		if reErr != nil {
			return nil, fmt.Errorf(
				"%w: service %q failed verification (%v); restored previous binary (%s) but restarting rolled-back service failed (%v)",
				ErrServiceRestartFailed, svcName, err, currentDisplay, reErr,
			)
		}
		cleanupBackupExecutable(backupPath)
		return nil, fmt.Errorf(
			"%w: service %q failed verification (%v); automatic rollback succeeded and restored previous binary (%s)",
			ErrServiceRestartFailed, svcName, err, currentDisplay,
		)
	}

	cleanupBackupExecutable(backupPath)
	res.RestartMode = RestartModeSynchronous
	res.ServiceRestarted = true
	return res, nil
}

// ResolveExecutablePath resolves override (or os.Executable() when empty) through symlinks
// to the canonical on-disk binary path.
func ResolveExecutablePath(override string) (string, error) {
	raw := strings.TrimSpace(override)
	if raw == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("failed locating current executable: %w", err)
		}
		raw = exe
	}
	absPath, err := filepath.Abs(raw)
	if err != nil {
		return "", fmt.Errorf("failed resolving absolute executable path %q: %w", raw, err)
	}
	resolved, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("executable %q does not exist: %w", absPath, err)
		}
		return "", fmt.Errorf("failed evaluating symlinks for %q: %w", absPath, err)
	}
	return resolved, nil
}

// SweepOldExecutables performs best-effort removal of `<exe>.old` and `<exe>.old.*`
// left behind by prior self-upgrades (especially on Windows or detached restarts).
// Passing an empty exePath automatically resolves os.Executable().
func SweepOldExecutables(exePath string) {
	resolved := strings.TrimSpace(exePath)
	if resolved == "" {
		p, err := ResolveExecutablePath("")
		if err != nil {
			return
		}
		resolved = p
	} else if sym, err := filepath.EvalSymlinks(resolved); err == nil {
		resolved = sym
	}

	dir := filepath.Dir(resolved)
	base := filepath.Base(resolved)
	if base == "" || base == "." || base == string(filepath.Separator) {
		return
	}

	exactOld := base + ".old"
	prefixOld := base + ".old."

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == exactOld || strings.HasPrefix(name, prefixOld) {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}

func evaluateVersionComparison(
	currentRaw string,
	currentDisplay string,
	currentIsDev bool,
	targetTag string,
	assetName string,
	explicitTarget bool,
) (updateAvailable bool, alreadyUpToDate bool, isDowngrade bool, message string) {
	if targetTag == "direct" {
		return true, false, false, fmt.Sprintf("direct artifact %s ready for installation", assetName)
	}
	if currentIsDev {
		return true, false, false, fmt.Sprintf("development build (%s) can be upgraded to %s", currentDisplay, targetTag)
	}

	curSV, curErr := ParseSemVer(currentRaw)
	tgtSV, tgtErr := ParseSemVer(targetTag)
	if curErr == nil && tgtErr == nil {
		cmp := tgtSV.Compare(curSV)
		switch {
		case cmp > 0:
			return true, false, false, fmt.Sprintf("update available: %s -> %s", curSV, tgtSV)
		case cmp == 0:
			return false, true, false, fmt.Sprintf("already up to date (%s)", curSV)
		default:
			return false, false, true, fmt.Sprintf("current version %s is newer than %s", curSV, tgtSV)
		}
	}

	if currentRaw == targetTag {
		return false, true, false, fmt.Sprintf("already up to date (%s)", currentDisplay)
	}
	if explicitTarget {
		return true, false, false, fmt.Sprintf("explicit target %s selected (current %s)", targetTag, currentDisplay)
	}
	return false, true, false, fmt.Sprintf("already up to date (%s)", currentDisplay)
}
