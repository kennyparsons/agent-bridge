package upgrade

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// SemVer represents a parsed Semantic Version 2.0.0 identifier.
type SemVer struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string
	Build      string
}

// String formats SemVer with a canonical leading "v" (e.g. "v0.2.0" or "v0.2.0-rc.1+build.4").
func (v SemVer) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "v%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Prerelease != "" {
		b.WriteByte('-')
		b.WriteString(v.Prerelease)
	}
	if v.Build != "" {
		b.WriteByte('+')
		b.WriteString(v.Build)
	}
	return b.String()
}

// IsPrerelease reports whether this version carries a prerelease suffix.
func (v SemVer) IsPrerelease() bool {
	return v.Prerelease != ""
}

// ParseSemVer parses "vMAJOR.MINOR.PATCH" (or "MAJOR.MINOR.PATCH") with optional
// "-prerelease" and "+build" metadata according to Semantic Versioning 2.0.0.
func ParseSemVer(raw string) (SemVer, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return SemVer{}, errors.New("empty version string")
	}
	if s[0] == 'v' || s[0] == 'V' {
		s = s[1:]
	}
	if s == "" {
		return SemVer{}, fmt.Errorf("invalid semantic version %q", raw)
	}

	var buildMeta string
	if plusIdx := strings.IndexByte(s, '+'); plusIdx >= 0 {
		buildMeta = s[plusIdx+1:]
		s = s[:plusIdx]
		if err := validateDotIdentifiers(buildMeta, false); err != nil {
			return SemVer{}, fmt.Errorf("invalid build metadata in %q: %w", raw, err)
		}
	}

	var prerelease string
	if dashIdx := strings.IndexByte(s, '-'); dashIdx >= 0 {
		prerelease = s[dashIdx+1:]
		s = s[:dashIdx]
		if err := validateDotIdentifiers(prerelease, true); err != nil {
			return SemVer{}, fmt.Errorf("invalid prerelease in %q: %w", raw, err)
		}
	}

	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return SemVer{}, fmt.Errorf("invalid semantic version %q: expected MAJOR.MINOR.PATCH", raw)
	}

	maj, err := parseNonNegativeNoLeadingZero(parts[0])
	if err != nil {
		return SemVer{}, fmt.Errorf("invalid major version in %q: %w", raw, err)
	}
	minVer, err := parseNonNegativeNoLeadingZero(parts[1])
	if err != nil {
		return SemVer{}, fmt.Errorf("invalid minor version in %q: %w", raw, err)
	}
	pat, err := parseNonNegativeNoLeadingZero(parts[2])
	if err != nil {
		return SemVer{}, fmt.Errorf("invalid patch version in %q: %w", raw, err)
	}

	return SemVer{
		Major:      maj,
		Minor:      minVer,
		Patch:      pat,
		Prerelease: prerelease,
		Build:      buildMeta,
	}, nil
}

// Compare returns -1 if v < other, 0 if v == other, or +1 if v > other
// following Semantic Versioning 2.0.0 precedence rules (build metadata is ignored).
func (v SemVer) Compare(other SemVer) int {
	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}
	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}
	if v.Patch != other.Patch {
		if v.Patch < other.Patch {
			return -1
		}
		return 1
	}

	if v.Prerelease == "" && other.Prerelease == "" {
		return 0
	}
	if v.Prerelease == "" {
		return 1
	}
	if other.Prerelease == "" {
		return -1
	}
	return comparePrerelease(v.Prerelease, other.Prerelease)
}

// CompareSemVer parses and compares two semantic version strings.
func CompareSemVer(a, b string) (int, error) {
	va, err := ParseSemVer(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseSemVer(b)
	if err != nil {
		return 0, err
	}
	return va.Compare(vb), nil
}

// IsDevBuild reports whether v represents a development, dirty, untagged git-describe,
// or non-SemVer build rather than a formal tagged release.
func IsDevBuild(v string) bool {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return true
	}
	lower := strings.ToLower(trimmed)
	switch lower {
	case "dev", "devel", "(devel)", "unknown", "snapshot", "nightly", "local":
		return true
	}
	if strings.HasSuffix(lower, "-dirty") || strings.HasSuffix(lower, "+dirty") {
		return true
	}

	sv, err := ParseSemVer(trimmed)
	if err != nil {
		return true
	}
	if sv.Major == 0 && sv.Minor == 0 && sv.Patch == 0 && strings.EqualFold(sv.Prerelease, "dev") {
		return true
	}
	if isGitDescribePrerelease(sv.Prerelease) {
		return true
	}
	return false
}

// AssetNameForPlatform returns the canonical release binary asset filename for goos/goarch
// ("agent-bridge-<goos>-<goarch>", with ".exe" appended on Windows).
func AssetNameForPlatform(goos, goarch string) (string, error) {
	osName := strings.ToLower(strings.TrimSpace(goos))
	archName := strings.ToLower(strings.TrimSpace(goarch))
	if !isCleanPlatformToken(osName) {
		return "", fmt.Errorf("invalid GOOS %q", goos)
	}
	if !isCleanPlatformToken(archName) {
		return "", fmt.Errorf("invalid GOARCH %q", goarch)
	}
	name := fmt.Sprintf("agent-bridge-%s-%s", osName, archName)
	if osName == "windows" {
		name += ".exe"
	}
	return name, nil
}

func isCleanPlatformToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func isGitDescribePrerelease(pre string) bool {
	// Matches "<commits>-g<hex>" emitted by `git describe --tags --always` (e.g. "4-g72d161e").
	dash := strings.IndexByte(pre, '-')
	if dash <= 0 || dash+2 >= len(pre) {
		return false
	}
	commitsPart := pre[:dash]
	if !isDigitsOnly(commitsPart) {
		return false
	}
	rest := pre[dash+1:]
	if rest[0] != 'g' && rest[0] != 'G' {
		return false
	}
	hexPart := rest[1:]
	if len(hexPart) < 6 {
		return false
	}
	for i := 0; i < len(hexPart); i++ {
		c := hexPart[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func parseNonNegativeNoLeadingZero(s string) (int, error) {
	if !isDigitsOnly(s) {
		return 0, errors.New("must contain only ASCII digits")
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, errors.New("must not contain leading zeros")
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, errors.New("integer overflow")
	}
	return n, nil
}

func validateDotIdentifiers(s string, disallowNumericLeadingZero bool) error {
	if s == "" {
		return errors.New("empty identifier")
	}
	parts := strings.Split(s, ".")
	for _, p := range parts {
		if p == "" {
			return errors.New("empty dot-separated identifier")
		}
		for i := 0; i < len(p); i++ {
			c := p[i]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-') {
				return fmt.Errorf("invalid character %q in identifier %q", c, p)
			}
		}
		if disallowNumericLeadingZero && isDigitsOnly(p) && len(p) > 1 && p[0] == '0' {
			return fmt.Errorf("numeric prerelease identifier %q must not have leading zeros", p)
		}
	}
	return nil
}

func comparePrerelease(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	limit := len(aParts)
	if len(bParts) < limit {
		limit = len(bParts)
	}

	for i := 0; i < limit; i++ {
		ap, bp := aParts[i], bParts[i]
		if ap == bp {
			continue
		}
		aNum := isDigitsOnly(ap)
		bNum := isDigitsOnly(bp)
		switch {
		case aNum && bNum:
			// Neither has leading zeros (validated by ParseSemVer), so length decides magnitude first.
			if len(ap) != len(bp) {
				if len(ap) < len(bp) {
					return -1
				}
				return 1
			}
			if ap < bp {
				return -1
			}
			return 1
		case aNum && !bNum:
			return -1
		case !aNum && bNum:
			return 1
		default:
			if ap < bp {
				return -1
			}
			return 1
		}
	}

	if len(aParts) < len(bParts) {
		return -1
	}
	if len(aParts) > len(bParts) {
		return 1
	}
	return 0
}

func isDigitsOnly(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
