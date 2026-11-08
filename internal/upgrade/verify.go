package upgrade

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// ChecksumsAssetName is the SHA-256 manifest filename published in GitHub Releases.
	ChecksumsAssetName = "SHA256SUMS.txt"

	// SignatureAssetName is the detached Ed25519 signature over SHA256SUMS.txt.
	SignatureAssetName = "SHA256SUMS.txt.sig"

	// MaxChecksumsBytes caps SHA256SUMS.txt downloads at 64 KiB.
	MaxChecksumsBytes = 64 * 1024

	// MaxSignatureBytes caps SHA256SUMS.txt.sig downloads at 4 KiB.
	MaxSignatureBytes = 4 * 1024

	// MaxBinaryBytes caps release binary downloads at 512 MiB.
	MaxBinaryBytes = 512 * 1024 * 1024

	// DefaultSmokeTimeout is the timeout enforced on `<stagedPath> version` before swapping.
	DefaultSmokeTimeout = 5 * time.Second
)

var (
	// ErrSignatureMissing indicates SHA256SUMS.txt.sig is absent and AllowUnsigned is false.
	ErrSignatureMissing = errors.New("release signature SHA256SUMS.txt.sig is missing")

	// ErrSignatureInvalid indicates Ed25519 verification of SHA256SUMS.txt failed.
	ErrSignatureInvalid = errors.New("Ed25519 signature verification failed for SHA256SUMS.txt")

	// ErrChecksumNotFound indicates SHA256SUMS.txt has no entry for the target platform asset.
	ErrChecksumNotFound = errors.New("platform asset checksum not found in SHA256SUMS.txt")

	// ErrChecksumMismatch indicates the streamed binary digest differed from SHA256SUMS.txt.
	ErrChecksumMismatch = errors.New("downloaded binary SHA-256 mismatch")

	// ErrSmokeTestFailed indicates the staged binary failed `<stagedPath> version` execution.
	ErrSmokeTestFailed = errors.New("staged binary failed pre-swap smoke test")

	// ErrDowngradeNotAllowed indicates TargetVersion < CurrentVersion without Force/AllowDowngrade.
	ErrDowngradeNotAllowed = errors.New("downgrade requires --force")

	// ErrServiceRestartFailed indicates the upgraded service failed health/restart verification.
	ErrServiceRestartFailed = errors.New("service failed post-upgrade restart verification")
)

// VerifyDetachedEd25519 verifies sigRaw (128-hex or 64-byte raw Ed25519 signature)
// over payload against any key in trustedKeys.
func VerifyDetachedEd25519(payload, sigRaw []byte, trustedKeys []ed25519.PublicKey) error {
	if len(trustedKeys) == 0 {
		return fmt.Errorf("%w: no trusted Ed25519 public keys configured", ErrSignatureInvalid)
	}
	for i, k := range trustedKeys {
		if len(k) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: trusted key at index %d has invalid length %d", ErrSignatureInvalid, i, len(k))
		}
	}

	sigBytes, err := ParseEd25519Signature(sigRaw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}

	for _, pubKey := range trustedKeys {
		if ed25519.Verify(pubKey, payload, sigBytes) {
			return nil
		}
	}
	return fmt.Errorf("%w: signature not valid for any trusted release key", ErrSignatureInvalid)
}

// ParseChecksums parses a GNU sha256sum / BSD shasum manifest into a map of asset basename -> 32-byte digest.
func ParseChecksums(raw []byte) (map[string][]byte, error) {
	entries := make(map[string][]byte)
	lines := strings.Split(string(raw), "\n")
	for lineNo, rawLine := range lines {
		line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		sepIdx := strings.IndexAny(line, " \t")
		if sepIdx <= 0 {
			return nil, fmt.Errorf("malformed %s line %d: missing filename separator", ChecksumsAssetName, lineNo+1)
		}
		digestHex := strings.TrimSpace(line[:sepIdx])
		if len(digestHex) != sha256.Size*2 {
			return nil, fmt.Errorf("malformed %s line %d: invalid SHA-256 hex length %d", ChecksumsAssetName, lineNo+1, len(digestHex))
		}
		digestBytes, err := hex.DecodeString(digestHex)
		if err != nil {
			return nil, fmt.Errorf("malformed %s line %d: invalid SHA-256 hex: %w", ChecksumsAssetName, lineNo+1, err)
		}

		namePart := strings.TrimSpace(line[sepIdx+1:])
		namePart = strings.TrimPrefix(namePart, "*")
		namePart = strings.TrimSpace(namePart)
		namePart = strings.ReplaceAll(namePart, `\`, "/")
		namePart = strings.TrimPrefix(namePart, "./")
		namePart = strings.TrimPrefix(namePart, "dist/")

		if namePart == "" || strings.Contains(namePart, "/") || namePart == "." || namePart == ".." {
			return nil, fmt.Errorf("malformed %s line %d: unsafe asset filename %q", ChecksumsAssetName, lineNo+1, namePart)
		}

		if prev, exists := entries[namePart]; exists {
			if subtle.ConstantTimeCompare(prev, digestBytes) != 1 {
				return nil, fmt.Errorf("conflicting SHA-256 entries for %q in %s", namePart, ChecksumsAssetName)
			}
			continue
		}
		entries[namePart] = digestBytes
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("%s contains no checksum entries", ChecksumsAssetName)
	}
	return entries, nil
}

// LookupAssetSHA256 parses raw SHA256SUMS.txt bytes and returns the 32-byte digest and lowercase hex string for assetName.
func LookupAssetSHA256(raw []byte, assetName string) ([]byte, string, error) {
	entries, err := ParseChecksums(raw)
	if err != nil {
		return nil, "", err
	}
	sum, ok := entries[assetName]
	if !ok {
		return nil, "", fmt.Errorf("%w: %q", ErrChecksumNotFound, assetName)
	}
	out := make([]byte, len(sum))
	copy(out, sum)
	return out, hex.EncodeToString(out), nil
}

func resolveTrustedPublicKeys(opts Options) ([]ed25519.PublicKey, error) {
	if opts.TrustedPublicKeys == nil {
		out := make([]ed25519.PublicKey, len(DefaultReleasePublicKeys))
		for i, k := range DefaultReleasePublicKeys {
			dup := make(ed25519.PublicKey, len(k))
			copy(dup, k)
			out[i] = dup
		}
		return out, nil
	}
	if len(opts.TrustedPublicKeys) == 0 {
		return nil, fmt.Errorf("%w: TrustedPublicKeys cannot be empty", ErrSignatureInvalid)
	}
	for i, k := range opts.TrustedPublicKeys {
		if len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: TrustedPublicKeys[%d] has length %d, want %d", ErrSignatureInvalid, i, len(k), ed25519.PublicKeySize)
		}
	}
	return opts.TrustedPublicKeys, nil
}

func fetchAndVerifyChecksums(
	ctx context.Context,
	client *resilientHTTPClient,
	rel *resolvedRelease,
	opts Options,
) (expectedDigest []byte, expectedHex string, sigVerified bool, err error) {
	trustedKeys, err := resolveTrustedPublicKeys(opts)
	if err != nil {
		return nil, "", false, err
	}

	if rel.SignatureURL == "" && !opts.AllowUnsigned {
		return nil, "", false, fmt.Errorf(
			"%w: release %s does not publish %s; pass --allow-unsigned only if intentionally installing a legacy unsigned release",
			ErrSignatureMissing, rel.TagName, SignatureAssetName,
		)
	}

	checksumsRaw, status, err := downloadBoundedBytes(ctx, client, rel.ChecksumsURL, rel.ChecksumsAcceptOctetStream, MaxChecksumsBytes, ChecksumsAssetName)
	if err != nil {
		return nil, "", false, err
	}
	if status != http.StatusOK {
		return nil, "", false, fmt.Errorf("failed to download %s: HTTP %d", ChecksumsAssetName, status)
	}

	if rel.SignatureURL != "" {
		sigRaw, sigStatus, sigErr := downloadBoundedBytes(ctx, client, rel.SignatureURL, rel.SignatureAcceptOctetStream, MaxSignatureBytes, SignatureAssetName)
		if sigErr != nil {
			return nil, "", false, sigErr
		}
		switch sigStatus {
		case http.StatusOK:
			if err := VerifyDetachedEd25519(checksumsRaw, sigRaw, trustedKeys); err != nil {
				return nil, "", false, err
			}
			sigVerified = true
		case http.StatusNotFound:
			if !opts.AllowUnsigned {
				return nil, "", false, fmt.Errorf(
					"%w: %s returned HTTP 404 for release %s; pass --allow-unsigned only if intentionally installing a legacy unsigned release",
					ErrSignatureMissing, SignatureAssetName, rel.TagName,
				)
			}
			sigVerified = false
		default:
			return nil, "", false, fmt.Errorf("failed to download %s: HTTP %d", SignatureAssetName, sigStatus)
		}
	}

	digest, digestHex, err := LookupAssetSHA256(checksumsRaw, rel.BinaryName)
	if err != nil {
		return nil, "", sigVerified, err
	}
	return digest, digestHex, sigVerified, nil
}

func downloadBoundedBytes(
	ctx context.Context,
	client *resilientHTTPClient,
	targetURL string,
	acceptOctetStream bool,
	maxBytes int64,
	label string,
) ([]byte, int, error) {
	accept := ""
	if acceptOctetStream {
		accept = "application/octet-stream"
	}
	resp, err := client.get(ctx, targetURL, accept, false)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to download %s: %w", label, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, resp.StatusCode, nil
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed reading %s response body: %w", label, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, resp.StatusCode, fmt.Errorf("%s exceeds maximum allowed size of %d bytes", label, maxBytes)
	}
	return data, http.StatusOK, nil
}

func stageAndVerifyBinary(
	ctx context.Context,
	client *resilientHTTPClient,
	rel *resolvedRelease,
	expectedDigest []byte,
	exePath string,
	targetGOOS string,
	opts Options,
) (stagedPath string, writtenBytes int64, err error) {
	dir := filepath.Dir(exePath)
	randHex, err := randomHexToken(8)
	if err != nil {
		return "", 0, fmt.Errorf("failed generating staging suffix: %w", err)
	}

	ext := ""
	if targetGOOS == "windows" || runtime.GOOS == "windows" || strings.HasSuffix(strings.ToLower(exePath), ".exe") {
		ext = ".exe"
	}
	stageName := fmt.Sprintf(".agent-bridge.stage.%d.%s%s", os.Getpid(), randHex, ext)
	stagePath := filepath.Join(dir, stageName)

	f, err := os.OpenFile(stagePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return "", 0, fmt.Errorf("failed creating staged executable %q: %w", stagePath, err)
	}

	keepStage := false
	fileClosed := false
	defer func() {
		if !fileClosed {
			_ = f.Close()
		}
		if !keepStage {
			_ = os.Remove(stagePath)
		}
	}()

	if runtime.GOOS != "windows" {
		if chmodErr := f.Chmod(0o755); chmodErr != nil {
			return "", 0, fmt.Errorf("failed setting executable mode on %q: %w", stagePath, chmodErr)
		}
	}

	accept := ""
	if rel.BinaryAcceptOctetStream {
		accept = "application/octet-stream"
	}
	resp, err := client.get(ctx, rel.BinaryURL, accept, false)
	if err != nil {
		return "", 0, fmt.Errorf("failed downloading binary asset %q: %w", rel.BinaryName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", 0, fmt.Errorf("binary asset download %q failed with HTTP %d: %s", rel.BinaryName, resp.StatusCode, summarizeHTTPErrorBody(errBody))
	}

	hasher := sha256.New()
	limited := io.LimitReader(resp.Body, MaxBinaryBytes+1)
	tee := io.TeeReader(limited, hasher)

	written, err := io.Copy(f, tee)
	if err != nil {
		return "", 0, fmt.Errorf("failed streaming binary asset %q: %w", rel.BinaryName, err)
	}
	if written > MaxBinaryBytes {
		return "", 0, fmt.Errorf("binary asset %q exceeds maximum allowed size of %d bytes", rel.BinaryName, MaxBinaryBytes)
	}

	if err := f.Sync(); err != nil {
		return "", 0, fmt.Errorf("failed syncing staged binary %q: %w", stagePath, err)
	}
	if err := f.Close(); err != nil {
		return "", 0, fmt.Errorf("failed closing staged binary %q: %w", stagePath, err)
	}
	fileClosed = true

	actualDigest := hasher.Sum(nil)
	if subtle.ConstantTimeCompare(actualDigest, expectedDigest) != 1 {
		return "", 0, fmt.Errorf(
			"%w for %s: got %s, expected %s",
			ErrChecksumMismatch,
			rel.BinaryName,
			hex.EncodeToString(actualDigest),
			hex.EncodeToString(expectedDigest),
		)
	}

	smokeTimeout := opts.SmokeTimeout
	if smokeTimeout <= 0 {
		smokeTimeout = DefaultSmokeTimeout
	}
	smokeCtx, cancelSmoke := context.WithTimeout(ctx, smokeTimeout)
	defer cancelSmoke()

	smokeFn := opts.SmokeTestFn
	if smokeFn == nil {
		smokeFn = defaultSmokeTest
	}
	if err := smokeFn(smokeCtx, stagePath); err != nil {
		return "", 0, fmt.Errorf("%w: %v", ErrSmokeTestFailed, err)
	}

	keepStage = true
	return stagePath, written, nil
}

func defaultSmokeTest(ctx context.Context, stagedPath string) error {
	cmd := exec.CommandContext(ctx, stagedPath, "version")
	var out bytes.Buffer
	lw := &limitedBufferWriter{buf: &out, max: 4096}
	cmd.Stdout = lw
	cmd.Stderr = lw
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(out.String())
		if detail != "" {
			return fmt.Errorf("executing %q version failed (%v): %s", filepath.Base(stagedPath), err, detail)
		}
		return fmt.Errorf("executing %q version failed: %w", filepath.Base(stagedPath), err)
	}
	return nil
}

type limitedBufferWriter struct {
	buf *bytes.Buffer
	max int
}

func (w *limitedBufferWriter) Write(p []byte) (int, error) {
	rem := w.max - w.buf.Len()
	if rem > 0 {
		if len(p) <= rem {
			_, _ = w.buf.Write(p)
		} else {
			_, _ = w.buf.Write(p[:rem])
		}
	}
	return len(p), nil
}

func randomHexToken(numBytes int) (string, error) {
	b := make([]byte, numBytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
