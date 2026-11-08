package upgrade

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// DefaultReleasePublicKeyHex is the compiled-in hex-encoded 32-byte Ed25519 public key
// used to verify detached SHA256SUMS.txt.sig release manifests.
const DefaultReleasePublicKeyHex = "66541112f44401142904d2d931e4cd181e8b235d12fe3126a8fe892aa35a6d8f"

// DefaultReleasePublicKeys holds the compiled-in trusted Ed25519 release signing public keys.
var DefaultReleasePublicKeys = []ed25519.PublicKey{
	{
		0x66, 0x54, 0x11, 0x12, 0xf4, 0x44, 0x01, 0x14,
		0x29, 0x04, 0xd2, 0xd9, 0x31, 0xe4, 0xcd, 0x18,
		0x1e, 0x8b, 0x23, 0x5d, 0x12, 0xfe, 0x31, 0x26,
		0xa8, 0xfe, 0x89, 0x2a, 0xa3, 0x5a, 0x6d, 0x8f,
	},
}

// ParsePublicKeyHex parses a 64-character hexadecimal Ed25519 public key string.
func ParsePublicKeyHex(raw string) (ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("empty Ed25519 public key")
	}
	if len(trimmed) != ed25519.PublicKeySize*2 {
		return nil, fmt.Errorf("invalid Ed25519 public key length: got %d hex chars, want %d", len(trimmed), ed25519.PublicKeySize*2)
	}
	decoded, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid hex Ed25519 public key: %w", err)
	}
	return ed25519.PublicKey(decoded), nil
}

// ParseEd25519Signature parses an Ed25519 signature in either:
//   - 128 hex characters with optional leading/trailing whitespace/newline (emitted by cmd/agent-bridge-sign), or
//   - raw 64-byte binary Ed25519 signature bytes.
func ParseEd25519Signature(raw []byte) ([]byte, error) {
	if len(raw) == ed25519.SignatureSize {
		out := make([]byte, ed25519.SignatureSize)
		copy(out, raw)
		return out, nil
	}

	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) != ed25519.SignatureSize*2 {
		return nil, fmt.Errorf(
			"invalid Ed25519 signature length: got %d bytes (%d trimmed chars), want %d raw bytes or %d hex chars",
			len(raw), len(trimmed), ed25519.SignatureSize, ed25519.SignatureSize*2,
		)
	}
	sig, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid hex Ed25519 signature: %w", err)
	}
	return sig, nil
}
