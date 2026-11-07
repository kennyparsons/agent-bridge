package protocol

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestConstants(t *testing.T) {
	if DefaultPort != 8443 {
		t.Fatalf("DefaultPort = %d, want 8443", DefaultPort)
	}
	if DefaultTimeoutSeconds != 60 {
		t.Fatalf("DefaultTimeoutSeconds = %d, want 60", DefaultTimeoutSeconds)
	}
	if MaxTimeoutSeconds != 600 {
		t.Fatalf("MaxTimeoutSeconds = %d, want 600", MaxTimeoutSeconds)
	}
	if MaxStreamBytes != 10*1024*1024 {
		t.Fatalf("MaxStreamBytes = %d, want %d", MaxStreamBytes, 10*1024*1024)
	}
	if ExecWSPath != "/ws/exec" {
		t.Fatalf("ExecWSPath = %q, want %q", ExecWSPath, "/ws/exec")
	}
}

func TestCommandRequestSerialization(t *testing.T) {
	t.Run("omits zero timeout_seconds and formats compactly", func(t *testing.T) {
		req := CommandRequest{
			Command: "Get-ADUser -Identity jdoe | ConvertTo-Json -Compress",
		}
		raw, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		got := string(raw)
		want := `{"command":"Get-ADUser -Identity jdoe | ConvertTo-Json -Compress"}`
		if got != want {
			t.Fatalf("json.Marshal(req) = %s, want %s", got, want)
		}
		if strings.Contains(got, "timeout_seconds") {
			t.Fatalf("expected timeout_seconds to be omitted when 0, got %s", got)
		}
	})

	t.Run("includes explicit timeout_seconds and round-trips", func(t *testing.T) {
		req := CommandRequest{
			Command:        "whoami",
			TimeoutSeconds: 30,
		}
		raw, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		want := `{"command":"whoami","timeout_seconds":30}`
		if string(raw) != want {
			t.Fatalf("json.Marshal(req) = %s, want %s", string(raw), want)
		}

		var decoded CommandRequest
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}
		if decoded != req {
			t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, req)
		}
	})
}

func TestCommandResponseSerializationAndOmitEmpty(t *testing.T) {
	tests := []struct {
		name         string
		resp         CommandResponse
		wantJSON     string
		forbidSubstr []string
	}{
		{
			name: "zero exit code with stdout only omits stderr",
			resp: CommandResponse{
				ExitCode: 0,
				Stdout:   `{"SamAccountName":"jdoe","Enabled":true}`,
			},
			wantJSON:     `{"exit_code":0,"stdout":"{\"SamAccountName\":\"jdoe\",\"Enabled\":true}"}`,
			forbidSubstr: []string{`"stderr"`},
		},
		{
			name: "non-zero exit code with stderr only omits stdout",
			resp: CommandResponse{
				ExitCode: 1,
				Stderr:   "Cannot find an object with identity: 'jdoe-missing'",
			},
			wantJSON:     `{"exit_code":1,"stderr":"Cannot find an object with identity: 'jdoe-missing'"}`,
			forbidSubstr: []string{`"stdout"`},
		},
		{
			name: "silent success omits both stdout and stderr while keeping exit_code",
			resp: CommandResponse{
				ExitCode: 0,
			},
			wantJSON:     `{"exit_code":0}`,
			forbidSubstr: []string{`"stdout"`, `"stderr"`},
		},
		{
			name: "both stdout and stderr populated",
			resp: CommandResponse{
				ExitCode: 2,
				Stdout:   "partial-result",
				Stderr:   "warning-msg",
			},
			wantJSON: `{"exit_code":2,"stdout":"partial-result","stderr":"warning-msg"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.resp)
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}
			if bytes.ContainsAny(raw, "\n\r\t") {
				t.Fatalf("expected single-line compact JSON, got %q", string(raw))
			}
			got := string(raw)
			if got != tc.wantJSON {
				t.Fatalf("json.Marshal = %s, want %s", got, tc.wantJSON)
			}
			for _, forbidden := range tc.forbidSubstr {
				if strings.Contains(got, forbidden) {
					t.Fatalf("expected %s to be omitted from %s", forbidden, got)
				}
			}

			var decoded CommandResponse
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatalf("json.Unmarshal failed: %v", err)
			}
			if decoded != tc.resp {
				t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, tc.resp)
			}
		})
	}
}

func TestEffectiveTimeout(t *testing.T) {
	cases := []struct {
		in      int
		wantSec int
	}{
		{in: 0, wantSec: DefaultTimeoutSeconds},
		{in: -15, wantSec: DefaultTimeoutSeconds},
		{in: 1, wantSec: 1},
		{in: 45, wantSec: 45},
		{in: MaxTimeoutSeconds, wantSec: MaxTimeoutSeconds},
		{in: 9999, wantSec: MaxTimeoutSeconds},
	}

	for _, tc := range cases {
		req := CommandRequest{Command: "hostname", TimeoutSeconds: tc.in}
		if got := req.EffectiveTimeoutSeconds(); got != tc.wantSec {
			t.Errorf("EffectiveTimeoutSeconds(%d) = %d, want %d", tc.in, got, tc.wantSec)
		}
		if got := req.EffectiveTimeout(); got != time.Duration(tc.wantSec)*time.Second {
			t.Errorf("EffectiveTimeout(%d) = %v, want %v", tc.in, got, time.Duration(tc.wantSec)*time.Second)
		}
	}
}

func TestSanitizeOutput(t *testing.T) {
	raw := "\r\n  {\"status\":\"ok\"}\r\n\n "
	if got := SanitizeOutput(raw); got != `{"status":"ok"}` {
		t.Fatalf("SanitizeOutput(%q) = %q, want %q", raw, got, `{"status":"ok"}`)
	}
}
