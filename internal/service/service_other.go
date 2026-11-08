//go:build !windows && !linux && !darwin

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

type unsupportedManager struct{}

func newPlatformManager() Manager {
	return &unsupportedManager{}
}

func IsManagedServiceProcess() bool {
	return false
}

func RunManagedService(_ string, runFn func(ctx context.Context) int) (int, error) {
	if runFn == nil {
		return 1, errors.New("service runFn cannot be nil")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runFn(ctx), nil
}

func (m *unsupportedManager) IsManagedServiceProcess() bool {
	return false
}

func (m *unsupportedManager) RunManagedService(name string, runFn func(ctx context.Context) int) (int, error) {
	return RunManagedService(name, runFn)
}

func (m *unsupportedManager) Install(_ context.Context, _ InstallOptions) (*InstallResult, error) {
	return nil, fmt.Errorf("OS service management is not supported on %s", runtime.GOOS)
}

func (m *unsupportedManager) Uninstall(_ context.Context, _ string) error {
	return fmt.Errorf("OS service management is not supported on %s", runtime.GOOS)
}

func (m *unsupportedManager) Start(_ context.Context, _ string) error {
	return fmt.Errorf("OS service management is not supported on %s", runtime.GOOS)
}

func (m *unsupportedManager) Stop(_ context.Context, _ string) error {
	return fmt.Errorf("OS service management is not supported on %s", runtime.GOOS)
}

func (m *unsupportedManager) Restart(_ context.Context, _ string) error {
	return fmt.Errorf("OS service management is not supported on %s", runtime.GOOS)
}

func (m *unsupportedManager) Status(_ context.Context, name string) (*ServiceStatus, error) {
	svcName, err := ValidateServiceName(name)
	if err != nil {
		return nil, err
	}
	return &ServiceStatus{
		Name:        svcName,
		Installed:   false,
		Running:     false,
		State:       "unsupported",
		ServiceType: runtime.GOOS,
	}, nil
}
