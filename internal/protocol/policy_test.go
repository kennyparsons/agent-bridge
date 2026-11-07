package protocol

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestExecutionPolicyCanonicalBytesDeterminism(t *testing.T) {
	p1 := ExecutionPolicy{
		Version:               7,
		UpdatedAtUnix:         1762500000,
		DefaultTimeoutSeconds: 45,
		MaxTimeoutSeconds:     300,
		DefaultShell:          "  powershell  ",
		EnforceClientACL:      true,
		AllowedClients:        []string{"ops-agent", "4A:2F:89:1B", "alpha-agent", "ops-agent", "  "},
	}
	p2 := ExecutionPolicy{
		Version:               7,
		UpdatedAtUnix:         1762500000,
		DefaultTimeoutSeconds: 45,
		MaxTimeoutSeconds:     300,
		DefaultShell:          "powershell",
		EnforceClientACL:      true,
		AllowedClients:        []string{"alpha-agent", "ops-agent", "4A:2F:89:1B"},
	}

	b1, err := p1.CanonicalBytes()
	if err != nil {
		t.Fatalf("p1.CanonicalBytes() failed: %v", err)
	}
	b2, err := p2.CanonicalBytes()
	if err != nil {
		t.Fatalf("p2.CanonicalBytes() failed: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("CanonicalBytes mismatch:\n  b1=%s\n  b2=%s", string(b1), string(b2))
	}

	// Verify caller's slice order was not mutated in place.
	if p1.AllowedClients[0] != "ops-agent" || p1.AllowedClients[2] != "alpha-agent" {
		t.Fatalf("CanonicalBytes mutated caller AllowedClients slice: %v", p1.AllowedClients)
	}

	// Verify JSON round-trip preserves identical CanonicalBytes.
	var wireDecoded ExecutionPolicy
	if err := json.Unmarshal(b1, &wireDecoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	bRoundTrip, err := wireDecoded.CanonicalBytes()
	if err != nil {
		t.Fatalf("wireDecoded.CanonicalBytes() failed: %v", err)
	}
	if !bytes.Equal(b1, bRoundTrip) {
		t.Fatalf("round-trip CanonicalBytes mismatch:\n  got=%s\n  want=%s", string(bRoundTrip), string(b1))
	}

	// Empty vs nil AllowedClients must produce identical canonical bytes.
	emptySlicePolicy := ExecutionPolicy{Version: 1, AllowedClients: []string{"   "}}
	nilSlicePolicy := ExecutionPolicy{Version: 1, AllowedClients: nil}
	bEmpty, _ := emptySlicePolicy.CanonicalBytes()
	bNil, _ := nilSlicePolicy.CanonicalBytes()
	if !bytes.Equal(bEmpty, bNil) {
		t.Fatalf("empty vs nil AllowedClients CanonicalBytes mismatch: %s vs %s", string(bEmpty), string(bNil))
	}
}

func TestExecutionPolicyIsClientAllowed(t *testing.T) {
	// 1. Disabled ACL allows any client even when AllowedClients is empty.
	disabled := ExecutionPolicy{
		Version:          1,
		EnforceClientACL: false,
	}
	if !disabled.IsClientAllowed("any-agent", "01:02:03:04") {
		t.Fatal("expected IsClientAllowed=true when EnforceClientACL=false")
	}

	// 2. Enabled ACL with empty AllowedClients denies all clients.
	denyAll := ExecutionPolicy{
		Version:          2,
		EnforceClientACL: true,
	}
	if denyAll.IsClientAllowed("automation-prod", "4A:2F:89:1B") {
		t.Fatal("expected IsClientAllowed=false when EnforceClientACL=true and AllowedClients is empty")
	}

	// 3. Enabled ACL matches case-exact CommonName and normalized hex serials.
	acl := ExecutionPolicy{
		Version:          3,
		EnforceClientACL: true,
		AllowedClients: []string{
			"automation-prod",
			"4A:2F:89:1B:3E:00:1C:78",
			"0x05a1b2",
		},
	}

	cases := []struct {
		name   string
		cn     string
		serial string
		want   bool
	}{
		{name: "exact CN match", cn: "automation-prod", serial: "99:99:99:99", want: true},
		{name: "wrong CN case denied", cn: "Automation-Prod", serial: "99:99:99:99", want: false},
		{name: "uppercase colon serial match", cn: "other", serial: "4A:2F:89:1B:3E:00:1C:78", want: true},
		{name: "lowercase colon serial match", cn: "other", serial: "4a:2f:89:1b:3e:00:1c:78", want: true},
		{name: "plain hex serial match", cn: "other", serial: "4a2f891b3e001c78", want: true},
		{name: "0x-prefixed hex serial match", cn: "other", serial: "0x4A2F891B3E001C78", want: true},
		{name: "0x-prefixed ACL entry matches colon serial", cn: "other", serial: "05:A1:B2", want: true},
		{name: "unlisted CN and serial denied", cn: "rogue-bot", serial: "DE:AD:BE:EF", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := acl.IsClientAllowed(tc.cn, tc.serial); got != tc.want {
				t.Fatalf("IsClientAllowed(%q, %q) = %v, want %v", tc.cn, tc.serial, got, tc.want)
			}
		})
	}
}

func TestEffectiveTimeoutWithPolicy(t *testing.T) {
	// nil policy delegates to standard EffectiveTimeout.
	reqZero := CommandRequest{Command: "whoami"}
	if got := reqZero.EffectiveTimeoutWithPolicy(nil); got != 60*time.Second {
		t.Fatalf("nil policy default timeout = %v, want 60s", got)
	}

	// Custom default and custom max within [1, 600].
	pol := &ExecutionPolicy{
		Version:               1,
		DefaultTimeoutSeconds: 25,
		MaxTimeoutSeconds:     120,
	}
	if got := reqZero.EffectiveTimeoutWithPolicy(pol); got != 25*time.Second {
		t.Fatalf("policy default timeout = %v, want 25s", got)
	}
	if got := (CommandRequest{Command: "whoami", TimeoutSeconds: 90}).EffectiveTimeoutWithPolicy(pol); got != 90*time.Second {
		t.Fatalf("in-range request timeout = %v, want 90s", got)
	}
	if got := (CommandRequest{Command: "whoami", TimeoutSeconds: 300}).EffectiveTimeoutWithPolicy(pol); got != 120*time.Second {
		t.Fatalf("clamped request timeout = %v, want 120s", got)
	}

	// Policy with MaxTimeoutSeconds < DefaultTimeoutSeconds clamps default to policy max.
	tightPol := &ExecutionPolicy{
		Version:           2,
		MaxTimeoutSeconds: 30,
	}
	if got := reqZero.EffectiveTimeoutWithPolicy(tightPol); got != 30*time.Second {
		t.Fatalf("tight policy default timeout = %v, want 30s", got)
	}

	// Policy attempting to exceed protocol ceiling (600s) or unset (0) never exceeds 600s or drops below 60s default.
	overMaxPol := &ExecutionPolicy{
		Version:               3,
		DefaultTimeoutSeconds: 0,
		MaxTimeoutSeconds:     9999,
	}
	if got := reqZero.EffectiveTimeoutWithPolicy(overMaxPol); got != 60*time.Second {
		t.Fatalf("unset policy default timeout = %v, want 60s", got)
	}
	if got := (CommandRequest{Command: "whoami", TimeoutSeconds: 1500}).EffectiveTimeoutWithPolicy(overMaxPol); got != 600*time.Second {
		t.Fatalf("protocol ceiling clamp = %v, want 600s", got)
	}
}
