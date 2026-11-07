package protocol

import (
	"strings"
	"time"
)

const (
	// DefaultPort is the default mTLS WebSocket listener and dialer TCP port.
	DefaultPort = 8443

	// DefaultTimeoutSeconds is applied when CommandRequest.TimeoutSeconds is omitted or <= 0.
	DefaultTimeoutSeconds = 60

	// MaxTimeoutSeconds is the hard ceiling enforced on CommandRequest.TimeoutSeconds.
	MaxTimeoutSeconds = 600

	// MaxStreamBytes is the maximum buffer size (10 MiB) captured per stream (stdout/stderr).
	MaxStreamBytes = 10 * 1024 * 1024

	// ExecWSPath is the WebSocket HTTP upgrade path exposed by the server daemon.
	ExecWSPath = "/ws/exec"
)

// CommandRequest represents the single JSON text frame sent by the client to initiate execution.
type CommandRequest struct {
	Command        string `json:"command"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

// EffectiveTimeoutSeconds normalizes TimeoutSeconds into [1, MaxTimeoutSeconds],
// defaulting to DefaultTimeoutSeconds when omitted or non-positive.
func (r CommandRequest) EffectiveTimeoutSeconds() int {
	if r.TimeoutSeconds <= 0 {
		return DefaultTimeoutSeconds
	}
	if r.TimeoutSeconds > MaxTimeoutSeconds {
		return MaxTimeoutSeconds
	}
	return r.TimeoutSeconds
}

// EffectiveTimeout returns EffectiveTimeoutSeconds as a time.Duration.
func (r CommandRequest) EffectiveTimeout() time.Duration {
	return time.Duration(r.EffectiveTimeoutSeconds()) * time.Second
}

// CommandResponse represents the lean JSON text frame returned by the server upon command completion.
type CommandResponse struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
}

// SanitizeOutput trims leading and trailing linebreaks and whitespace for token conservation.
func SanitizeOutput(s string) string {
	return strings.TrimSpace(s)
}
