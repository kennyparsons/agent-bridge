package upgrade

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"sync/atomic"
	"time"
)

const (
	defaultMetadataMaxBytes = 4 * 1024 * 1024 // 4 MiB cap on GitHub Release JSON
	userAgentValue          = "agent-bridge-selfupgrade"
	githubAPIVersion        = "2022-11-28"
)

type githubRelease struct {
	TagName     string        `json:"tag_name"`
	Name        string        `json:"name"`
	Draft       bool          `json:"draft"`
	Prerelease  bool          `json:"prerelease"`
	HTMLURL     string        `json:"html_url"`
	PublishedAt string        `json:"published_at"`
	Assets      []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	URL                string `json:"url"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

type resolvedRelease struct {
	TagName                    string
	ReleaseURL                 string
	PublishedAt                string
	BinaryName                 string
	BinaryURL                  string
	BinaryAcceptOctetStream    bool
	BinarySize                 int64
	ChecksumsURL               string
	ChecksumsAcceptOctetStream bool
	SignatureURL               string
	SignatureAcceptOctetStream bool
}

type proxyAttemptKey struct{}

type proxyAttempt struct {
	usedProxy atomic.Bool
}

type resilientHTTPClient struct {
	noProxy      bool
	proxyClient  *http.Client
	directClient *http.Client
	proxyTripped atomic.Bool
	fallbackUsed atomic.Bool
	authToken    string
	trustedHosts map[string]struct{}
	logf         func(string, ...any)
}

func newResilientHTTPClient(opts Options, getenv func(string) string) *resilientHTTPClient {
	reqTimeout := opts.HTTPTimeout
	if reqTimeout <= 0 {
		reqTimeout = DefaultHTTPTimeout
	}

	directTransport := newBaseTransport(nil)
	directClient := &http.Client{
		Transport: directTransport,
		Timeout:   reqTimeout,
	}

	c := &resilientHTTPClient{
		noProxy:      opts.NoProxy,
		directClient: directClient,
		authToken:    resolveGitHubToken(opts.GitHubToken, getenv),
		trustedHosts: buildTrustedAuthHosts(opts),
		logf:         opts.Logf,
	}

	if !opts.NoProxy {
		proxyFunc := buildEnvProxyFunc(getenv)
		proxiedTransport := newBaseTransport(func(req *http.Request) (*url.URL, error) {
			pURL, err := proxyFunc(req)
			if err != nil {
				if att, ok := req.Context().Value(proxyAttemptKey{}).(*proxyAttempt); ok {
					att.usedProxy.Store(true)
				}
				return nil, err
			}
			if pURL != nil {
				if att, ok := req.Context().Value(proxyAttemptKey{}).(*proxyAttempt); ok {
					att.usedProxy.Store(true)
				}
			}
			return pURL, nil
		})
		c.proxyClient = &http.Client{
			Transport: proxiedTransport,
			Timeout:   reqTimeout,
		}
	}

	return c
}

func newBaseTransport(proxyFn func(*http.Request) (*url.URL, error)) *http.Transport {
	return &http.Transport{
		Proxy: proxyFn,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}

func resolveGitHubToken(explicit string, getenv func(string) string) string {
	if tok := strings.TrimSpace(explicit); tok != "" {
		return tok
	}
	for _, key := range []string{"AGENT_BRIDGE_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"} {
		if tok := strings.TrimSpace(getenv(key)); tok != "" {
			return tok
		}
	}
	return ""
}

func buildTrustedAuthHosts(opts Options) map[string]struct{} {
	hosts := map[string]struct{}{
		"api.github.com": {},
		"github.com":     {},
	}
	addHost := func(raw string) {
		if strings.TrimSpace(raw) != "" {
			if u, err := url.Parse(strings.TrimSpace(raw)); err == nil && u.Host != "" {
				hosts[strings.ToLower(u.Host)] = struct{}{}
			}
		}
	}
	addHost(opts.APIBaseURL)
	if strings.TrimSpace(opts.GitHubToken) != "" {
		addHost(opts.DirectAssetURL)
		addHost(opts.ChecksumsURL)
		addHost(opts.SignatureURL)
	}
	return hosts
}

func (c *resilientHTTPClient) shouldAttachAuth(targetURL string) bool {
	if c.authToken == "" {
		return false
	}
	u, err := url.Parse(targetURL)
	if err != nil || u.Host == "" {
		return false
	}
	_, ok := c.trustedHosts[strings.ToLower(u.Host)]
	return ok
}

func (c *resilientHTTPClient) ProxyFallbackUsed() bool {
	return c.fallbackUsed.Load()
}

func (c *resilientHTTPClient) get(ctx context.Context, targetURL string, accept string, attachAPIVersion bool) (*http.Response, error) {
	buildReq := func(reqCtx context.Context) (*http.Request, error) {
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgentValue)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if attachAPIVersion {
			req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
		}
		if c.shouldAttachAuth(targetURL) {
			req.Header.Set("Authorization", "Bearer "+c.authToken)
		}
		return req, nil
	}

	if c.noProxy || c.proxyClient == nil || c.proxyTripped.Load() {
		req, err := buildReq(ctx)
		if err != nil {
			return nil, err
		}
		return c.directClient.Do(req)
	}

	attempt := &proxyAttempt{}
	attemptCtx := context.WithValue(ctx, proxyAttemptKey{}, attempt)
	req, err := buildReq(attemptCtx)
	if err != nil {
		return nil, err
	}

	resp, err := c.proxyClient.Do(req)
	if !attempt.usedProxy.Load() {
		return resp, err
	}

	if err != nil {
		if ctx.Err() != nil {
			return nil, err
		}
		c.tripProxyFallback("proxy request error (%v); retrying directly without proxy", err)
		directReq, rErr := buildReq(ctx)
		if rErr != nil {
			return nil, rErr
		}
		return c.directClient.Do(directReq)
	}

	if isProxyGatewayFailure(resp) {
		status := resp.StatusCode
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		c.tripProxyFallback("proxy returned HTTP %d before reaching GitHub; retrying directly without proxy", status)
		directReq, rErr := buildReq(ctx)
		if rErr != nil {
			return nil, rErr
		}
		return c.directClient.Do(directReq)
	}

	return resp, nil
}

func (c *resilientHTTPClient) tripProxyFallback(format string, args ...any) {
	c.proxyTripped.Store(true)
	c.fallbackUsed.Store(true)
	if c.logf != nil {
		c.logf(format, args...)
	}
}

func isProxyGatewayFailure(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	switch resp.StatusCode {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		// GitHub responses always carry X-GitHub-Request-Id; its absence indicates
		// an upstream corporate proxy failure before reaching GitHub.
		return strings.TrimSpace(resp.Header.Get("X-GitHub-Request-Id")) == ""
	default:
		return false
	}
}

func discoverRelease(ctx context.Context, client *resilientHTTPClient, opts Options, binaryAssetName string) (*resolvedRelease, error) {
	if strings.TrimSpace(opts.DirectAssetURL) != "" || strings.TrimSpace(opts.ChecksumsURL) != "" {
		return resolveDirectRelease(opts, binaryAssetName)
	}

	repo := strings.TrimSpace(opts.Repo)
	if repo == "" {
		repo = DefaultRepo
	}
	owner, repoName, err := splitRepo(repo)
	if err != nil {
		return nil, err
	}

	apiBase := strings.TrimSpace(opts.APIBaseURL)
	if apiBase == "" {
		apiBase = DefaultGitHubAPIBaseURL
	}
	apiBase = strings.TrimRight(apiBase, "/")

	channel := strings.ToLower(strings.TrimSpace(opts.Channel))
	if channel == "" {
		channel = ChannelStable
	}
	if channel != ChannelStable && channel != ChannelPrerelease {
		return nil, fmt.Errorf("unsupported release channel %q: expected %q or %q", opts.Channel, ChannelStable, ChannelPrerelease)
	}

	target := strings.TrimSpace(opts.TargetVersion)
	var rel githubRelease
	switch {
	case target == "" || strings.EqualFold(target, "latest"):
		if channel == ChannelStable {
			endpoint := fmt.Sprintf("%s/repos/%s/%s/releases/latest", apiBase, url.PathEscape(owner), url.PathEscape(repoName))
			r, err := fetchSingleRelease(ctx, client, endpoint)
			if err != nil {
				return nil, err
			}
			if r.Draft {
				return nil, errors.New("latest release returned by API is marked as a draft")
			}
			rel = r
		} else {
			endpoint := fmt.Sprintf("%s/repos/%s/%s/releases?per_page=15", apiBase, url.PathEscape(owner), url.PathEscape(repoName))
			r, err := fetchHighestRelease(ctx, client, endpoint)
			if err != nil {
				return nil, err
			}
			rel = r
		}
	default:
		normalizedTag := normalizeReleaseTag(target)
		endpoint := fmt.Sprintf("%s/repos/%s/%s/releases/tags/%s", apiBase, url.PathEscape(owner), url.PathEscape(repoName), url.PathEscape(normalizedTag))
		r, err := fetchSingleRelease(ctx, client, endpoint)
		if err != nil {
			return nil, err
		}
		if r.Draft {
			return nil, fmt.Errorf("release %q is a draft and cannot be installed", normalizedTag)
		}
		rel = r
	}

	if strings.TrimSpace(rel.TagName) == "" {
		return nil, errors.New("GitHub release metadata is missing tag_name")
	}

	binAsset, ok := findReleaseAsset(rel.Assets, binaryAssetName)
	if !ok {
		return nil, fmt.Errorf("release %s does not include platform asset %q", rel.TagName, binaryAssetName)
	}
	sumAsset, ok := findReleaseAsset(rel.Assets, ChecksumsAssetName)
	if !ok {
		return nil, fmt.Errorf("release %s does not include %s", rel.TagName, ChecksumsAssetName)
	}

	binURL, binOctet, err := selectAssetDownloadURL(binAsset, client.authToken != "")
	if err != nil {
		return nil, fmt.Errorf("platform asset %q: %w", binaryAssetName, err)
	}
	sumURL, sumOctet, err := selectAssetDownloadURL(sumAsset, client.authToken != "")
	if err != nil {
		return nil, fmt.Errorf("checksums asset %q: %w", ChecksumsAssetName, err)
	}

	out := &resolvedRelease{
		TagName:                    strings.TrimSpace(rel.TagName),
		ReleaseURL:                 strings.TrimSpace(rel.HTMLURL),
		PublishedAt:                normalizePublishedAt(rel.PublishedAt),
		BinaryName:                 binaryAssetName,
		BinaryURL:                  binURL,
		BinaryAcceptOctetStream:    binOctet,
		BinarySize:                 binAsset.Size,
		ChecksumsURL:               sumURL,
		ChecksumsAcceptOctetStream: sumOctet,
	}

	if sigAsset, hasSig := findReleaseAsset(rel.Assets, SignatureAssetName); hasSig {
		sigURL, sigOctet, sigErr := selectAssetDownloadURL(sigAsset, client.authToken != "")
		if sigErr != nil {
			return nil, fmt.Errorf("signature asset %q: %w", SignatureAssetName, sigErr)
		}
		out.SignatureURL = sigURL
		out.SignatureAcceptOctetStream = sigOctet
	}

	return out, nil
}

func resolveDirectRelease(opts Options, binaryAssetName string) (*resolvedRelease, error) {
	directBin := strings.TrimSpace(opts.DirectAssetURL)
	if directBin == "" {
		return nil, errors.New("DirectAssetURL is required when using direct/mirror URL override")
	}
	binParsed, err := url.Parse(directBin)
	if err != nil || binParsed.Scheme == "" || binParsed.Host == "" {
		return nil, fmt.Errorf("invalid DirectAssetURL %q", directBin)
	}

	checksumsURL := strings.TrimSpace(opts.ChecksumsURL)
	if checksumsURL == "" {
		derived := *binParsed
		derived.Path = path.Join(path.Dir(binParsed.Path), ChecksumsAssetName)
		derived.RawQuery = ""
		derived.Fragment = ""
		checksumsURL = derived.String()
	}

	sigURL := strings.TrimSpace(opts.SignatureURL)
	if sigURL == "" {
		if sumParsed, sErr := url.Parse(checksumsURL); sErr == nil {
			derivedSig := *sumParsed
			derivedSig.Path = sumParsed.Path + ".sig"
			sigURL = derivedSig.String()
		} else {
			sigURL = checksumsURL + ".sig"
		}
	}

	tag := strings.TrimSpace(opts.TargetVersion)
	if tag == "" || strings.EqualFold(tag, "latest") {
		tag = "direct"
	} else {
		tag = normalizeReleaseTag(tag)
	}

	return &resolvedRelease{
		TagName:      tag,
		ReleaseURL:   directBin,
		BinaryName:   binaryAssetName,
		BinaryURL:    directBin,
		ChecksumsURL: checksumsURL,
		SignatureURL: sigURL,
	}, nil
}

func fetchSingleRelease(ctx context.Context, client *resilientHTTPClient, endpoint string) (githubRelease, error) {
	resp, err := client.get(ctx, endpoint, "application/vnd.github+json", true)
	if err != nil {
		return githubRelease{}, fmt.Errorf("failed to query GitHub release metadata: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, defaultMetadataMaxBytes+1))
	if err != nil {
		return githubRelease{}, fmt.Errorf("failed reading GitHub release metadata: %w", err)
	}
	if len(body) > defaultMetadataMaxBytes {
		return githubRelease{}, errors.New("GitHub release metadata exceeded maximum response size")
	}
	if resp.StatusCode != http.StatusOK {
		return githubRelease{}, fmt.Errorf("GitHub release lookup failed with HTTP %d: %s", resp.StatusCode, summarizeHTTPErrorBody(body))
	}

	var rel githubRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		return githubRelease{}, fmt.Errorf("invalid GitHub release JSON: %w", err)
	}
	return rel, nil
}

func fetchHighestRelease(ctx context.Context, client *resilientHTTPClient, endpoint string) (githubRelease, error) {
	resp, err := client.get(ctx, endpoint, "application/vnd.github+json", true)
	if err != nil {
		return githubRelease{}, fmt.Errorf("failed to list GitHub releases: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, defaultMetadataMaxBytes+1))
	if err != nil {
		return githubRelease{}, fmt.Errorf("failed reading GitHub releases list: %w", err)
	}
	if len(body) > defaultMetadataMaxBytes {
		return githubRelease{}, errors.New("GitHub releases list exceeded maximum response size")
	}
	if resp.StatusCode != http.StatusOK {
		return githubRelease{}, fmt.Errorf("GitHub releases list failed with HTTP %d: %s", resp.StatusCode, summarizeHTTPErrorBody(body))
	}

	var releases []githubRelease
	if err := json.Unmarshal(body, &releases); err != nil {
		return githubRelease{}, fmt.Errorf("invalid GitHub releases list JSON: %w", err)
	}

	var best githubRelease
	var bestVer SemVer
	found := false
	for _, r := range releases {
		if r.Draft {
			continue
		}
		sv, err := ParseSemVer(r.TagName)
		if err != nil {
			continue
		}
		if !found || sv.Compare(bestVer) > 0 {
			best = r
			bestVer = sv
			found = true
		}
	}
	if !found {
		return githubRelease{}, errors.New("no non-draft SemVer releases found")
	}
	return best, nil
}

func findReleaseAsset(assets []githubAsset, wantName string) (githubAsset, bool) {
	for _, a := range assets {
		if a.Name == wantName {
			return a, true
		}
	}
	return githubAsset{}, false
}

func selectAssetDownloadURL(asset githubAsset, authenticated bool) (string, bool, error) {
	apiURL := strings.TrimSpace(asset.URL)
	browserURL := strings.TrimSpace(asset.BrowserDownloadURL)
	if authenticated {
		if apiURL != "" {
			return apiURL, true, nil
		}
		if browserURL != "" {
			return browserURL, false, nil
		}
	} else {
		if browserURL != "" {
			return browserURL, false, nil
		}
		if apiURL != "" {
			return apiURL, true, nil
		}
	}
	return "", false, errors.New("asset has neither url nor browser_download_url")
}

func splitRepo(repo string) (string, string, error) {
	parts := strings.Split(strings.TrimSpace(repo), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || parts[0] == "." || parts[0] == ".." || parts[1] == "." || parts[1] == ".." {
		return "", "", fmt.Errorf("invalid repository %q: expected <owner>/<repo>", repo)
	}
	if strings.ContainsAny(repo, " \t\r\n?#\\") {
		return "", "", fmt.Errorf("invalid repository %q: contains forbidden characters", repo)
	}
	return parts[0], parts[1], nil
}

func normalizeReleaseTag(target string) string {
	trimmed := strings.TrimSpace(target)
	if sv, err := ParseSemVer(trimmed); err == nil {
		if trimmed[0] != 'v' && trimmed[0] != 'V' {
			return sv.String()
		}
	}
	return trimmed
}

func normalizePublishedAt(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if t, err := time.Parse(time.RFC3339, trimmed); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	return trimmed
}

func summarizeHTTPErrorBody(body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) > 240 {
		s = s[:240] + "..."
	}
	if s == "" {
		return "empty response body"
	}
	return s
}

func buildEnvProxyFunc(getenv func(string) string) func(*http.Request) (*url.URL, error) {
	httpProxyRaw := firstNonEmptyEnv(getenv, "HTTP_PROXY", "http_proxy")
	httpsProxyRaw := firstNonEmptyEnv(getenv, "HTTPS_PROXY", "https_proxy")
	noProxyRaw := firstNonEmptyEnv(getenv, "NO_PROXY", "no_proxy")

	if httpProxyRaw == "" && httpsProxyRaw == "" {
		return func(*http.Request) (*url.URL, error) {
			return nil, nil
		}
	}

	httpProxyURL, httpProxyErr := parseProxyEnvURL(httpProxyRaw)
	httpsProxyURL, httpsProxyErr := parseProxyEnvURL(httpsProxyRaw)
	noProxyRules := parseNoProxyRules(noProxyRaw)

	return func(req *http.Request) (*url.URL, error) {
		if req == nil || req.URL == nil {
			return nil, nil
		}
		if shouldBypassProxy(req.URL, noProxyRules) {
			return nil, nil
		}
		switch strings.ToLower(req.URL.Scheme) {
		case "https":
			if httpsProxyRaw != "" {
				return httpsProxyURL, httpsProxyErr
			}
			return nil, nil
		case "http":
			if httpProxyRaw != "" {
				return httpProxyURL, httpProxyErr
			}
			return nil, nil
		default:
			return nil, nil
		}
	}
}

func firstNonEmptyEnv(getenv func(string) string, names ...string) string {
	for _, n := range names {
		if v := strings.TrimSpace(getenv(n)); v != "" {
			return v
		}
	}
	return ""
}

func parseProxyEnvURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, nil
	}
	candidate := raw
	if !strings.Contains(candidate, "://") {
		candidate = "http://" + candidate
	}
	u, err := url.Parse(candidate)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid proxy URL %q", raw)
	}
	return u, nil
}

type noProxyRule struct {
	wildcard bool
	cidr     *netip.Prefix
	addr     *netip.Addr
	domain   string // lowercase, without leading dot
	subOnly  bool   // had leading dot in NO_PROXY
	port     string
}

func parseNoProxyRules(raw string) []noProxyRule {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var rules []noProxyRule
	for _, item := range strings.Split(raw, ",") {
		tok := strings.TrimSpace(item)
		if tok == "" {
			continue
		}
		if tok == "*" {
			return []noProxyRule{{wildcard: true}}
		}

		if pfx, err := netip.ParsePrefix(tok); err == nil {
			p := pfx.Masked()
			rules = append(rules, noProxyRule{cidr: &p})
			continue
		}

		hostPart, portPart := splitHostOptionalPort(tok)
		if addr, err := netip.ParseAddr(strings.Trim(hostPart, "[]")); err == nil {
			a := addr.Unmap()
			rules = append(rules, noProxyRule{addr: &a, port: portPart})
			continue
		}

		lowerHost := strings.ToLower(hostPart)
		subOnly := strings.HasPrefix(lowerHost, ".")
		lowerHost = strings.TrimPrefix(lowerHost, ".")
		if lowerHost != "" {
			rules = append(rules, noProxyRule{
				domain:  lowerHost,
				subOnly: subOnly,
				port:    portPart,
			})
		}
	}
	return rules
}

func shouldBypassProxy(u *url.URL, rules []noProxyRule) bool {
	if len(rules) == 0 || u == nil {
		return false
	}
	reqHost := strings.ToLower(u.Hostname())
	if reqHost == "" {
		return false
	}
	reqPort := u.Port()
	if reqPort == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			reqPort = "443"
		case "http":
			reqPort = "80"
		}
	}

	var reqAddr *netip.Addr
	if parsed, err := netip.ParseAddr(reqHost); err == nil {
		unmapped := parsed.Unmap()
		reqAddr = &unmapped
	}

	for _, r := range rules {
		if r.wildcard {
			return true
		}
		if r.port != "" && r.port != reqPort {
			continue
		}
		if r.cidr != nil {
			if reqAddr != nil && r.cidr.Contains(*reqAddr) {
				return true
			}
			continue
		}
		if r.addr != nil {
			if reqAddr != nil && *reqAddr == *r.addr {
				return true
			}
			continue
		}
		if r.domain != "" && reqAddr == nil {
			if !r.subOnly && reqHost == r.domain {
				return true
			}
			if strings.HasSuffix(reqHost, "."+r.domain) {
				return true
			}
		}
	}
	return false
}

func splitHostOptionalPort(s string) (string, string) {
	if strings.HasPrefix(s, "[") {
		if h, p, err := net.SplitHostPort(s); err == nil {
			return h, p
		}
		return strings.Trim(s, "[]"), ""
	}
	if strings.Count(s, ":") == 1 {
		if h, p, err := net.SplitHostPort(s); err == nil {
			return h, p
		}
	}
	return s, ""
}
