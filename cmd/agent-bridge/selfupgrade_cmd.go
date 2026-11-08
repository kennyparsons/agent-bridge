package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kennyparsons/agent-bridge/internal/config"
	"github.com/kennyparsons/agent-bridge/internal/service"
	"github.com/kennyparsons/agent-bridge/internal/upgrade"
)

type serviceUpgradeController struct {
	serviceName string
}

func (c serviceUpgradeController) IsServiceInstalledAndRunning(ctx context.Context) (bool, bool, string, error) {
	mgr := newServiceManager()
	st, err := mgr.Status(ctx, c.serviceName)
	if err != nil {
		return false, false, c.serviceName, err
	}
	if st == nil {
		return false, false, c.serviceName, nil
	}
	name := strings.TrimSpace(st.Name)
	if name == "" {
		name = c.serviceName
	}
	return st.Installed, st.Running, name, nil
}

func (c serviceUpgradeController) RestartAndVerify(ctx context.Context, serviceName string) error {
	target := strings.TrimSpace(serviceName)
	if target == "" {
		target = c.serviceName
	}
	mgr := newServiceManager()
	if err := mgr.Restart(ctx, target); err != nil {
		return err
	}
	st, err := mgr.Status(ctx, target)
	if err != nil {
		return fmt.Errorf("failed querying service %q after restart: %w", target, err)
	}
	if st == nil || !st.Running {
		state := "unknown"
		if st != nil && st.State != "" {
			state = st.State
		}
		return fmt.Errorf("service %q is not running after restart (state=%s)", target, state)
	}
	return nil
}

func (c serviceUpgradeController) ScheduleDetachedRestart(_ context.Context, newExePath, serviceName, backupExePath string) error {
	target := strings.TrimSpace(serviceName)
	if target == "" {
		target = c.serviceName
	}
	return spawnDetachedRestartFn(newExePath, target, backupExePath, 500*time.Millisecond)
}

func runSelfUpgrade(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("selfupgrade")
	checkOnly := fs.Bool("check", false, "Check for available updates and verify release signatures without modifying disk")
	targetVersion := fs.String("version", "", "Target release version ('latest' or explicit tag such as 'v0.2.0')")
	channel := fs.String("channel", upgrade.ChannelStable, "Release channel when --version is omitted/latest: stable or prerelease")
	yes := fs.Bool("yes", false, "Skip interactive confirmation prompt")
	fs.BoolVar(yes, "y", false, "Shorthand for --yes")
	force := fs.Bool("force", false, "Reinstall even when current version matches or exceeds target")
	allowDowngrade := fs.Bool("allow-downgrade", false, "Allow installing an explicit older release tag without --force")
	allowUnsigned := fs.Bool("allow-unsigned", false, "Allow legacy releases without SHA256SUMS.txt.sig")
	repo := fs.String("repo", upgrade.DefaultRepo, "GitHub repository (<owner>/<name>)")
	apiURL := fs.String("api-url", "", "Optional GitHub API base URL override")

	var pubKeysFlag stringSliceFlag
	fs.Var(&pubKeysFlag, "public-key", "Trusted 64-hex-char Ed25519 release public key override (repeatable or CSV)")

	directURL := fs.String("url", "", "Direct binary download URL (bypasses GitHub Releases API when paired with --checksums-url)")
	checksumsURL := fs.String("checksums-url", "", "Direct SHA256SUMS.txt URL")
	sigURL := fs.String("sig-url", "", "Direct SHA256SUMS.txt.sig URL")
	exeOverride := fs.String("exe", "", "Optional target executable path override")
	noProxy := fs.Bool("no-proxy", false, "Bypass HTTP_PROXY/HTTPS_PROXY and dial release endpoints directly")
	noRestart := fs.Bool("no-restart", false, "Replace executable without restarting a running OS service")
	serviceName := fs.String("service-name", service.DefaultServiceName, "OS service name to inspect and restart after upgrade")
	jsonOut := fs.Bool("json", false, "Format output as indented JSON")

	if code, handled := parseFlags(fs, args, stdout, stderr, printSelfUpgradeUsage); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		printSelfUpgradeUsage(stderr)
		return exitUsage
	}

	normChannel := strings.ToLower(strings.TrimSpace(*channel))
	if normChannel == "" {
		normChannel = upgrade.ChannelStable
	}
	if normChannel != upgrade.ChannelStable && normChannel != upgrade.ChannelPrerelease {
		_, _ = fmt.Fprintf(stderr, "Error: invalid --channel %q: expected %q or %q\n", *channel, upgrade.ChannelStable, upgrade.ChannelPrerelease)
		printSelfUpgradeUsage(stderr)
		return exitUsage
	}

	svcName, err := service.ValidateServiceName(*serviceName)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitUsage
	}

	var trustedKeys []ed25519.PublicKey
	if len(pubKeysFlag) > 0 {
		for _, hexKey := range pubKeysFlag {
			pk, pErr := upgrade.ParsePublicKeyHex(hexKey)
			if pErr != nil {
				_, _ = fmt.Fprintf(stderr, "Error: invalid --public-key: %v\n", pErr)
				return exitUsage
			}
			trustedKeys = append(trustedKeys, pk)
		}
	}

	homeDir, _ := os.UserHomeDir()
	expandedExe := ""
	if strings.TrimSpace(*exeOverride) != "" {
		expandedExe = config.ExpandPath(*exeOverride, homeDir, "")
	}

	opts := upgrade.Options{
		CurrentVersion:     version,
		TargetVersion:      strings.TrimSpace(*targetVersion),
		Channel:            normChannel,
		Repo:               strings.TrimSpace(*repo),
		APIBaseURL:         strings.TrimSpace(*apiURL),
		DirectAssetURL:     strings.TrimSpace(*directURL),
		ChecksumsURL:       strings.TrimSpace(*checksumsURL),
		SignatureURL:       strings.TrimSpace(*sigURL),
		NoProxy:            *noProxy,
		CheckOnly:          *checkOnly,
		Force:              *force,
		AllowDowngrade:     *allowDowngrade,
		AllowUnsigned:      *allowUnsigned,
		TrustedPublicKeys:  trustedKeys,
		ExecutablePath:     expandedExe,
		ServiceController:  serviceUpgradeController{serviceName: svcName},
		SkipServiceRestart: *noRestart,
		Logf: func(format string, a ...any) {
			if !*jsonOut {
				_, _ = fmt.Fprintf(stderr, "[selfupgrade] "+format+"\n", a...)
			}
		},
	}

	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	if *checkOnly {
		chk, chkErr := upgrade.Check(sigCtx, opts)
		if chkErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", chkErr)
			return exitError
		}
		if *jsonOut {
			return writeIndentedJSON(stdout, stderr, chk)
		}
		printSelfUpgradeCheckHuman(stdout, chk)
		return exitOK
	}

	// When --yes is omitted, run a read-only cryptographic manifest check first so we only prompt
	// when an actual verified upgrade will be applied (and require --yes in non-TTY / --json mode).
	if !*yes {
		chk, chkErr := upgrade.Check(sigCtx, opts)
		if chkErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", chkErr)
			return exitError
		}
		if !chk.UpdateAvailable && !*force {
			res := &upgrade.Result{
				CheckResult:     *chk,
				Upgraded:        false,
				AlreadyUpToDate: true,
				RestartMode:     upgrade.RestartModeNone,
			}
			if *jsonOut {
				return writeIndentedJSON(stdout, stderr, res)
			}
			_, _ = fmt.Fprintf(stdout, "Already up to date (%s).\n", chk.CurrentVersion)
			return exitOK
		}

		if *jsonOut || !isInteractiveStdin(stdin) {
			_, _ = fmt.Fprintf(stderr, "Error: confirmation required to upgrade agent-bridge (%s -> %s); pass --yes (-y) for non-interactive upgrades\n",
				chk.CurrentVersion, chk.TargetVersion)
			return exitError
		}

		_, _ = fmt.Fprintf(stderr, "Upgrade agent-bridge %s -> %s (%s)? [y/N]: ",
			chk.CurrentVersion, chk.TargetVersion, chk.AssetName)
		answer, rErr := readFirstLineTrimmed(stdin)
		if rErr != nil {
			_, _ = fmt.Fprintf(stderr, "\nError: failed reading confirmation: %v\n", rErr)
			return exitError
		}
		lowerAns := strings.ToLower(strings.TrimSpace(answer))
		if lowerAns != "y" && lowerAns != "yes" {
			_, _ = fmt.Fprintln(stderr, "Upgrade canceled.")
			return exitError
		}
	}

	res, err := upgrade.Run(sigCtx, opts)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	if *jsonOut {
		return writeIndentedJSON(stdout, stderr, res)
	}

	if res.AlreadyUpToDate && !res.Upgraded {
		_, _ = fmt.Fprintf(stdout, "Already up to date (%s).\n", res.CurrentVersion)
		return exitOK
	}

	_, _ = fmt.Fprintf(stdout, "Upgraded:           %s -> %s\n", res.CurrentVersion, res.TargetVersion)
	_, _ = fmt.Fprintf(stdout, "Executable:         %s\n", res.ExecutablePath)
	_, _ = fmt.Fprintf(stdout, "Asset:              %s (%d bytes)\n", res.AssetName, res.AssetSize)
	_, _ = fmt.Fprintf(stdout, "SHA-256:            %s\n", res.ExpectedSHA256)
	_, _ = fmt.Fprintf(stdout, "Signature Verified: %t\n", res.SignatureVerified)
	if res.ServiceRestarted {
		_, _ = fmt.Fprintf(stdout, "Service Restart:    restarted %q synchronously\n", res.ServiceName)
	} else if res.ServiceRestartScheduled {
		_, _ = fmt.Fprintf(stdout, "Service Restart:    scheduled detached restart for %q\n", res.ServiceName)
	}
	return exitOK
}

func printSelfUpgradeCheckHuman(w io.Writer, chk *upgrade.CheckResult) {
	_, _ = fmt.Fprintf(w, "Current Version:    %s\n", chk.CurrentVersion)
	_, _ = fmt.Fprintf(w, "Target Version:     %s\n", chk.TargetVersion)
	_, _ = fmt.Fprintf(w, "Update Available:   %t\n", chk.UpdateAvailable)
	_, _ = fmt.Fprintf(w, "Asset:              %s\n", chk.AssetName)
	_, _ = fmt.Fprintf(w, "Expected SHA-256:   %s\n", chk.ExpectedSHA256)
	_, _ = fmt.Fprintf(w, "Signature Verified: %t\n", chk.SignatureVerified)
	if chk.Message != "" {
		_, _ = fmt.Fprintf(w, "Summary:            %s\n", chk.Message)
	}
}

func printSelfUpgradeUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `Usage: agent-bridge selfupgrade [flags]

Flags:
  --check                     Check release availability and verify Ed25519/SHA-256 manifest only
  --version <latest|vX.Y.Z>   Target release tag (default "latest")
  --channel <stable|prerelease> Release channel when --version is latest (default "stable")
  --yes, -y                   Apply upgrade without interactive confirmation prompt
  --force                     Reinstall even if already at or newer than target version
  --allow-downgrade           Permit installing an explicit older release tag
  --allow-unsigned            Permit legacy releases without SHA256SUMS.txt.sig
  --repo <owner/name>         GitHub repository (default %q)
  --api-url <url>             GitHub REST API base URL override
  --public-key <hex>          Trusted 64-hex-char Ed25519 public key override (repeatable or CSV)
  --url <asset-url>           Direct binary download URL (requires --checksums-url)
  --checksums-url <url>       Direct SHA256SUMS.txt URL
  --sig-url <url>             Direct SHA256SUMS.txt.sig URL
  --exe <path>                Target binary path override
  --no-proxy                  Bypass HTTP_PROXY/HTTPS_PROXY and connect directly
  --no-restart                Do not restart local OS service after binary swap
  --service-name <name>       OS service name to inspect/restart (default %q)
  --json                      Format output as indented JSON
`, upgrade.DefaultRepo, service.DefaultServiceName)
}
