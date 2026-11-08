//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/kennyparsons/agent-bridge/internal/acl"
)

type winCmdRunnerFunc func(ctx context.Context, env []string, name string, args ...string) ([]byte, error)

func defaultWinCmdRunner(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if len(env) > 0 {
		cmd.Env = env
	}
	return cmd.CombinedOutput()
}

type windowsManager struct {
	runCmd winCmdRunnerFunc
}

func newPlatformManager() Manager {
	return &windowsManager{
		runCmd: defaultWinCmdRunner,
	}
}

// IsManagedServiceProcess reports whether the current process is executing under the Windows
// Service Control Manager (`services.exe`).
func IsManagedServiceProcess() bool {
	isSvc, err := svc.IsWindowsService()
	return err == nil && isSvc
}

// RunManagedService connects the process to the Windows Service Control Manager and manages
// StartPending -> Running -> StopPending -> Stopped transitions around `runFn`.
func RunManagedService(name string, runFn func(ctx context.Context) int) (int, error) {
	if runFn == nil {
		return 1, errors.New("service runFn cannot be nil")
	}
	svcName, err := ValidateServiceName(name)
	if err != nil {
		return 1, err
	}

	elog, _ := eventlog.Open(svcName)
	if elog != nil {
		defer elog.Close()
	}

	h := &winSvcHandler{
		name:  svcName,
		runFn: runFn,
		elog:  elog,
	}
	if err := svc.Run(svcName, h); err != nil {
		if elog != nil {
			_ = elog.Error(1, fmt.Sprintf("%s SCM dispatcher failed: %v", svcName, err))
		}
		return 1, fmt.Errorf("windows service %q failed: %w", svcName, err)
	}
	return h.exitCode, nil
}

func (m *windowsManager) IsManagedServiceProcess() bool {
	return IsManagedServiceProcess()
}

func (m *windowsManager) RunManagedService(name string, runFn func(ctx context.Context) int) (int, error) {
	return RunManagedService(name, runFn)
}

type winSvcHandler struct {
	name     string
	runFn    func(ctx context.Context) int
	elog     *eventlog.Log
	exitCode int
}

func (h *winSvcHandler) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	s <- svc.Status{State: svc.StartPending, WaitHint: 15000, CheckPoint: 1}

	svcCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	doneCh := make(chan int, 1)
	go func() {
		doneCh <- h.runFn(svcCtx)
	}()

	s <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	if h.elog != nil {
		_ = h.elog.Info(1, fmt.Sprintf("%s service entered Running state", h.name))
	}

	for {
		select {
		case code := <-doneCh:
			h.exitCode = code
			if code != 0 {
				if h.elog != nil {
					_ = h.elog.Error(1, fmt.Sprintf("%s exited unexpectedly with code %d", h.name, code))
				}
				s <- svc.Status{
					State:                   svc.Stopped,
					Win32ExitCode:           uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR),
					ServiceSpecificExitCode: uint32(code),
				}
				return true, uint32(code)
			}
			s <- svc.Status{State: svc.Stopped}
			return false, 0

		case req := <-r:
			switch req.Cmd {
			case svc.Interrogate:
				s <- req.CurrentStatus

			case svc.Stop, svc.Shutdown:
				if h.elog != nil {
					_ = h.elog.Info(1, fmt.Sprintf("%s received SCM stop/shutdown control", h.name))
				}
				var checkPoint uint32 = 1
				s <- svc.Status{State: svc.StopPending, WaitHint: 15000, CheckPoint: checkPoint}
				cancel()

				ticker := time.NewTicker(2 * time.Second)
				for {
					select {
					case code := <-doneCh:
						ticker.Stop()
						h.exitCode = code
						s <- svc.Status{State: svc.Stopped}
						return false, 0
					case <-ticker.C:
						checkPoint++
						s <- svc.Status{State: svc.StopPending, WaitHint: 15000, CheckPoint: checkPoint}
					}
				}
			}
		}
	}
}

func (m *windowsManager) execCmd(ctx context.Context, extraEnv []string, name string, args ...string) (string, error) {
	runner := m.runCmd
	if runner == nil {
		runner = defaultWinCmdRunner
	}
	var env []string
	if len(extraEnv) > 0 {
		env = append(os.Environ(), extraEnv...)
	}
	out, err := runner(ctx, env, name, args...)
	trimmed := strings.TrimSpace(string(out))
	if err != nil {
		if trimmed != "" {
			return trimmed, fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, trimmed)
		}
		return "", fmt.Errorf("%s %s failed: %w", name, strings.Join(args, " "), err)
	}
	return trimmed, nil
}

// migrateLegacyScheduledTask detects and tears down the legacy `\AgentBridge-Server` Scheduled Task,
// terminates lingering `powershell.exe` (`run-daemon.ps1`) and non-ancestor `agent-bridge.exe` processes,
// deletes the Scheduled Task, and removes legacy `run-daemon.ps1` next to `exePath`.
func (m *windowsManager) migrateLegacyScheduledTask(ctx context.Context, exePath string) (migrated bool, warnings []string) {
	_, queryErr := m.execCmd(ctx, nil, "schtasks.exe", "/Query", "/TN", LegacyWindowsScheduledTaskName)
	legacyScriptPath := filepath.Join(filepath.Dir(exePath), LegacyWindowsRunScriptFilename)

	if queryErr == nil {
		migrated = true
		_, _ = m.execCmd(ctx, nil, "schtasks.exe", "/End", "/TN", LegacyWindowsScheduledTaskName)

		// Terminate lingering powershell.exe running run-daemon.ps1 and non-ancestor agent-bridge.exe
		// processes without ever terminating our own PID or an ancestor `/ws/exec` server process.
		cleanupScript := `$ancestors = @{}; ` +
			`$cur = [int]$env:AB_SELF_PID; ` +
			`for ($i = 0; $i -lt 32 -and $cur -gt 0; $i++) { ` +
			`  $ancestors[$cur] = $true; ` +
			`  $proc = Get-CimInstance Win32_Process -Filter "ProcessId = $cur" -ErrorAction SilentlyContinue; ` +
			`  if (-not $proc) { break }; ` +
			`  $cur = [int]$proc.ParentProcessId ` +
			`}; ` +
			`Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object { ` +
			`  $p = $_; ` +
			`  if (-not $ancestors[[int]$p.ProcessId]) { ` +
			`    if (($p.Name -match '^(powershell|pwsh)(\.exe)?$' -and $p.CommandLine -like '*run-daemon.ps1*') -or ` +
			`        ($p.Name -ieq 'agent-bridge.exe' -and $p.CommandLine -match '\bserver\b')) { ` +
			`      Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue ` +
			`    } ` +
			`  } ` +
			`}`
		_, _ = m.execCmd(
			ctx,
			[]string{"AB_SELF_PID=" + strconv.Itoa(os.Getpid())},
			"powershell.exe",
			"-NoProfile",
			"-NonInteractive",
			"-Command",
			cleanupScript,
		)

		if _, delErr := m.execCmd(ctx, nil, "schtasks.exe", "/Delete", "/TN", LegacyWindowsScheduledTaskName, "/F"); delErr != nil {
			warnings = append(warnings, fmt.Sprintf("failed to delete legacy scheduled task %s: %v", LegacyWindowsScheduledTaskName, delErr))
		}
	}

	if _, statErr := os.Stat(legacyScriptPath); statErr == nil {
		if rmErr := os.Remove(legacyScriptPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			warnings = append(warnings, fmt.Sprintf("failed to remove legacy %s: %v", legacyScriptPath, rmErr))
		} else {
			migrated = true
		}
	}

	return migrated, warnings
}

// ConfigureWindowsFirewall idempotently deletes and recreates inbound Windows Firewall rules
// (`AgentBridge-Exec` and `AgentBridge-Cluster`) scoped to `exePath` and `allowedSubnets`.
func ConfigureWindowsFirewall(
	ctx context.Context,
	exePath string,
	execPort int,
	clusterPort int,
	allowedSubnets []string,
) ([]string, error) {
	wm := &windowsManager{runCmd: defaultWinCmdRunner}
	return wm.configureFirewall(ctx, exePath, execPort, clusterPort, allowedSubnets)
}

func (m *windowsManager) configureFirewall(
	ctx context.Context,
	exePath string,
	execPort int,
	clusterPort int,
	allowedSubnets []string,
) ([]string, error) {
	cmds, ruleNames, err := BuildNetshFirewallCommands(exePath, execPort, clusterPort, allowedSubnets)
	if err != nil {
		return nil, err
	}
	for _, args := range cmds {
		isDelete := len(args) >= 3 && args[2] == "delete"
		if _, runErr := m.execCmd(ctx, nil, "netsh.exe", args...); runErr != nil && !isDelete {
			return nil, fmt.Errorf("failed to configure Windows Firewall rule: %w", runErr)
		}
	}
	return ruleNames, nil
}

// AddWindowsDefenderExclusion registers `exePath` as a Microsoft Defender exclusion path, passing
// the path exclusively via environment variable `$env:AB_EXE_PATH` so PowerShell injection is impossible.
func AddWindowsDefenderExclusion(ctx context.Context, exePath string) error {
	wm := &windowsManager{runCmd: defaultWinCmdRunner}
	return wm.addDefenderExclusion(ctx, exePath)
}

func (m *windowsManager) addDefenderExclusion(ctx context.Context, exePath string) error {
	trimmed := strings.TrimSpace(exePath)
	if trimmed == "" {
		return errors.New("executable path cannot be empty for Defender exclusion")
	}
	_, err := m.execCmd(
		ctx,
		[]string{"AB_EXE_PATH=" + trimmed},
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		"Add-MpPreference -ExclusionPath $env:AB_EXE_PATH",
	)
	if err != nil {
		return fmt.Errorf("failed to add Microsoft Defender exclusion for %q: %w", trimmed, err)
	}
	return nil
}

func (m *windowsManager) Install(ctx context.Context, opts InstallOptions) (*InstallResult, error) {
	svcName, displayName, description, exePath, cfgPath, logPath, err := resolveInstallBasics(opts)
	if err != nil {
		return nil, err
	}

	if opts.Config != nil {
		if strings.TrimSpace(opts.Config.DataDir) != "" {
			if err := acl.LockdownServerDir(opts.Config.DataDir); err != nil {
				return nil, fmt.Errorf("failed to lock down server data directory %q: %w", opts.Config.DataDir, err)
			}
		}
		if strings.TrimSpace(logPath) != "" {
			if err := acl.LockdownServerDir(filepath.Dir(logPath)); err != nil {
				return nil, fmt.Errorf("failed to lock down server log directory %q: %w", filepath.Dir(logPath), err)
			}
		}
		if err := SaveServerDaemonConfig(cfgPath, opts.Config); err != nil {
			return nil, err
		}
	}

	migratedTask, warnings := m.migrateLegacyScheduledTask(ctx, exePath)
	_, _ = m.execCmd(ctx, nil, "schtasks.exe", "/Delete", "/TN", TransientDetachedRestartTaskName, "/F")

	scm, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Windows Service Control Manager (administrator privileges required): %w", err)
	}
	defer scm.Disconnect()

	cmdLine := FormatWindowsServiceCommandLine(exePath, cfgPath)
	desiredCfg := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  displayName,
		Description:  description,
	}

	s, openErr := scm.OpenService(svcName)
	if openErr != nil {
		if !errors.Is(openErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil, fmt.Errorf("failed to open Windows service %q: %w", svcName, openErr)
		}
		s, err = scm.CreateService(svcName, exePath, desiredCfg, "server", "--service-config", cfgPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create Windows service %q: %w", svcName, err)
		}
	}
	defer s.Close()

	// Enforce explicitly quoted `<quotedExePath> server --service-config <quotedCfgPath>` via UpdateConfig
	// so paths without spaces are still quoted consistently and existing services update cleanly in place.
	existingCfg, cfgErr := s.Config()
	if cfgErr == nil {
		existingCfg.ServiceType = windows.SERVICE_WIN32_OWN_PROCESS
		existingCfg.StartType = mgr.StartAutomatic
		existingCfg.ErrorControl = mgr.ErrorNormal
		existingCfg.BinaryPathName = cmdLine
		existingCfg.DisplayName = displayName
		existingCfg.Description = description
		if updErr := s.UpdateConfig(existingCfg); updErr != nil {
			return nil, fmt.Errorf("failed to update Windows service %q configuration: %w", svcName, updErr)
		}
	} else {
		desiredCfg.BinaryPathName = cmdLine
		if updErr := s.UpdateConfig(desiredCfg); updErr != nil {
			return nil, fmt.Errorf("failed to configure Windows service %q: %w", svcName, updErr)
		}
	}

	recoveryActions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 3 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
	}
	if recErr := s.SetRecoveryActions(recoveryActions, 86400); recErr != nil {
		warnings = append(warnings, fmt.Sprintf("failed to set SCM recovery actions: %v", recErr))
	}
	if flagErr := s.SetRecoveryActionsOnNonCrashFailures(true); flagErr != nil {
		warnings = append(warnings, fmt.Sprintf("failed to enable SCM recovery actions on non-crash failures: %v", flagErr))
	}

	// Best-effort EventLog source registration (ignores already-exists errors).
	_ = eventlog.InstallAsEventCreate(svcName, eventlog.Error|eventlog.Warning|eventlog.Info)

	res := &InstallResult{
		Name:                  svcName,
		ServiceType:           "windows-scm",
		BinaryPath:            exePath,
		ConfigPath:            cfgPath,
		LogPath:               logPath,
		MigratedScheduledTask: migratedTask,
	}

	if opts.ConfigureFirewall {
		execPort, clusterPort := resolveFirewallPorts(opts)
		rules, fwErr := m.configureFirewall(ctx, exePath, execPort, clusterPort, opts.FirewallAllowedSubnets)
		if fwErr != nil {
			return nil, fwErr
		}
		res.FirewallConfigured = true
		res.FirewallRules = rules
	}

	if opts.DefenderExclusion {
		if defErr := m.addDefenderExclusion(ctx, exePath); defErr != nil {
			warnings = append(warnings, defErr.Error())
		} else {
			res.DefenderExcluded = true
		}
	}

	if opts.StartNow {
		if err := stopServiceHandleIfActive(ctx, s); err != nil {
			return nil, fmt.Errorf("failed to stop existing Windows service %q before start: %w", svcName, err)
		}
		if err := startServiceHandleAndWait(ctx, s); err != nil {
			return nil, fmt.Errorf("failed to start Windows service %q: %w", svcName, err)
		}
		res.Started = true
	}

	res.Warnings = warnings
	return res, nil
}

func (m *windowsManager) Uninstall(ctx context.Context, name string) error {
	svcName, err := ValidateServiceName(name)
	if err != nil {
		return err
	}
	_, _ = m.execCmd(ctx, nil, "schtasks.exe", "/Delete", "/TN", TransientDetachedRestartTaskName, "/F")

	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows Service Control Manager: %w", err)
	}
	defer scm.Disconnect()

	s, openErr := scm.OpenService(svcName)
	if openErr != nil {
		if errors.Is(openErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return fmt.Errorf("failed to open Windows service %q: %w", svcName, openErr)
	}
	defer s.Close()

	_ = stopServiceHandleIfActive(ctx, s)
	if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return fmt.Errorf("failed to delete Windows service %q: %w", svcName, err)
	}
	_ = eventlog.Remove(svcName)
	return nil
}

func (m *windowsManager) Start(ctx context.Context, name string) error {
	svcName, err := ValidateServiceName(name)
	if err != nil {
		return err
	}
	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows Service Control Manager: %w", err)
	}
	defer scm.Disconnect()

	s, err := scm.OpenService(svcName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return fmt.Errorf("%w: %s", ErrServiceNotInstalled, svcName)
		}
		return fmt.Errorf("failed to open Windows service %q: %w", svcName, err)
	}
	defer s.Close()

	return startServiceHandleAndWait(ctx, s)
}

func (m *windowsManager) Stop(ctx context.Context, name string) error {
	svcName, err := ValidateServiceName(name)
	if err != nil {
		return err
	}
	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows Service Control Manager: %w", err)
	}
	defer scm.Disconnect()

	s, err := scm.OpenService(svcName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return fmt.Errorf("%w: %s", ErrServiceNotInstalled, svcName)
		}
		return fmt.Errorf("failed to open Windows service %q: %w", svcName, err)
	}
	defer s.Close()

	return stopServiceHandleIfActive(ctx, s)
}

func (m *windowsManager) Restart(ctx context.Context, name string) error {
	svcName, err := ValidateServiceName(name)
	if err != nil {
		return err
	}
	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows Service Control Manager: %w", err)
	}
	defer scm.Disconnect()

	s, err := scm.OpenService(svcName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return fmt.Errorf("%w: %s", ErrServiceNotInstalled, svcName)
		}
		return fmt.Errorf("failed to open Windows service %q: %w", svcName, err)
	}
	defer s.Close()

	if err := stopServiceHandleIfActive(ctx, s); err != nil {
		return fmt.Errorf("failed to stop Windows service %q during restart: %w", svcName, err)
	}
	if err := startServiceHandleAndWait(ctx, s); err != nil {
		return fmt.Errorf("failed to start Windows service %q during restart: %w", svcName, err)
	}
	return nil
}

func (m *windowsManager) Status(_ context.Context, name string) (*ServiceStatus, error) {
	svcName, err := ValidateServiceName(name)
	if err != nil {
		return nil, err
	}
	scm, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Windows Service Control Manager: %w", err)
	}
	defer scm.Disconnect()

	s, openErr := scm.OpenService(svcName)
	if openErr != nil {
		if errors.Is(openErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return &ServiceStatus{
				Name:        svcName,
				Installed:   false,
				Running:     false,
				State:       "not-installed",
				ServiceType: "windows-scm",
			}, nil
		}
		return nil, fmt.Errorf("failed to open Windows service %q: %w", svcName, openErr)
	}
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return nil, fmt.Errorf("failed to query Windows service %q status: %w", svcName, err)
	}

	var exePath, cfgPath string
	if cfg, cfgErr := s.Config(); cfgErr == nil {
		exePath, cfgPath = ParseServiceCommandLine(cfg.BinaryPathName)
	}
	if cfgPath == "" {
		cfgPath = DefaultPaths().ConfigPath
	}

	return &ServiceStatus{
		Name:        svcName,
		Installed:   true,
		Running:     st.State == svc.Running,
		State:       windowsStateString(st.State),
		PID:         int(st.ProcessId),
		BinaryPath:  exePath,
		ConfigPath:  cfgPath,
		LogPath:     resolveLogPathFromConfig(cfgPath),
		ServiceType: "windows-scm",
	}, nil
}

func windowsStateString(st svc.State) string {
	switch st {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start-pending"
	case svc.StopPending:
		return "stop-pending"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "continue-pending"
	case svc.PausePending:
		return "pause-pending"
	case svc.Paused:
		return "paused"
	default:
		return fmt.Sprintf("unknown(%d)", st)
	}
}

func startServiceHandleAndWait(ctx context.Context, s *mgr.Service) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if st, err := s.Query(); err == nil && st.State == svc.Running {
		return nil
	}
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}

	deadline := time.Now().Add(30 * time.Second)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Running {
			return nil
		}
		if st.State == svc.Stopped {
			return fmt.Errorf("service exited immediately during startup (Win32ExitCode=%d ServiceSpecificExitCode=%d)", st.Win32ExitCode, st.ServiceSpecificExitCode)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for service %q to reach Running state (current=%s)", s.Name, windowsStateString(st.State))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func stopServiceHandleIfActive(ctx context.Context, s *mgr.Service) error {
	if ctx == nil {
		ctx = context.Background()
	}
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if st.State != svc.StopPending {
		if _, ctrlErr := s.Control(svc.Stop); ctrlErr != nil && !errors.Is(ctrlErr, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return ctrlErr
		}
	}

	deadline := time.Now().Add(30 * time.Second)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		st, err = s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Stopped {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for service %q to reach Stopped state (current=%s)", s.Name, windowsStateString(st.State))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// SpawnDetachedServiceRestart spawns `<exePath> service _detached-restart --name <serviceName> --delay <delay> [--rollback-bin <rollbackPath>]`
// outside the current Win32 Job Object and process group so in-band `/ws/exec` upgrades survive
// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` when the service stops.
func SpawnDetachedServiceRestart(exePath, serviceName, rollbackPath string, delay time.Duration) error {
	resolvedExe := strings.TrimSpace(exePath)
	if resolvedExe == "" {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to resolve executable path for detached restart: %w", err)
		}
		resolvedExe = exe
	}
	absExe, err := filepath.Abs(resolvedExe)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute executable path %q: %w", resolvedExe, err)
	}
	cleanExe := filepath.Clean(absExe)

	args, err := BuildDetachedRestartArgs(serviceName, rollbackPath, delay)
	if err != nil {
		return err
	}

	// 1. Primary path: native CreateProcess with CREATE_BREAKAWAY_FROM_JOB | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP.
	cmd := exec.Command(cleanExe, args...)
	cmd.Dir = os.TempDir()
	cmd.Env = stripInExecEnv(os.Environ())
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_BREAKAWAY_FROM_JOB | windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
	startErr := cmd.Start()
	if startErr == nil {
		if cmd.Process != nil {
			_ = cmd.Process.Release()
		}
		return nil
	}

	// Build full quoted command line for out-of-job fallbacks (WMI Win32_Process.Create / transient schtasks)
	// when the parent Job Object forbids CREATE_BREAKAWAY_FROM_JOB (ERROR_ACCESS_DENIED).
	quotedParts := make([]string, 0, 1+len(args))
	quotedParts = append(quotedParts, quoteWin32ArgAlways(cleanExe))
	for _, a := range args {
		quotedParts = append(quotedParts, quoteWin32ArgAlways(a))
	}
	fullCmdLine := strings.Join(quotedParts, " ")

	// 2. Fallback 1: WMI Win32_Process.Create spawns via WmiPrvSE.exe outside the current Job Object.
	wmiCmd := exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		"$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $env:AB_DETACHED_CMD }; if ($r.ReturnValue -ne 0) { exit [int]$r.ReturnValue }",
	)
	wmiCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	wmiCmd.Env = append(stripInExecEnv(os.Environ()), "AB_DETACHED_CMD="+fullCmdLine)
	if wmiOut, wmiErr := wmiCmd.CombinedOutput(); wmiErr == nil {
		return nil
	} else {
		_ = wmiOut
	}

	// 3. Fallback 2: 1-minute transient SYSTEM Scheduled Task triggered immediately via `schtasks /Run`.
	runAt := time.Now().Add(1 * time.Minute).Format("15:04")
	createTask := exec.Command(
		"schtasks.exe",
		"/Create",
		"/TN", TransientDetachedRestartTaskName,
		"/SC", "ONCE",
		"/ST", runAt,
		"/RU", "SYSTEM",
		"/RL", "HIGHEST",
		"/TR", fullCmdLine,
		"/F",
	)
	createTask.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, createErr := createTask.CombinedOutput(); createErr != nil {
		return fmt.Errorf(
			"detached restart failed (breakaway=%v; transient schtasks create=%v: %s)",
			startErr,
			createErr,
			strings.TrimSpace(string(out)),
		)
	}
	runTask := exec.Command("schtasks.exe", "/Run", "/TN", TransientDetachedRestartTaskName)
	runTask.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, runErr := runTask.CombinedOutput(); runErr != nil {
		return fmt.Errorf(
			"detached restart failed to trigger transient scheduled task (breakaway=%v; schtasks run=%v: %s)",
			startErr,
			runErr,
			strings.TrimSpace(string(out)),
		)
	}
	return nil
}
