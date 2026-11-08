package service

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/kennyparsons/agent-bridge/internal/config"
	"github.com/kennyparsons/agent-bridge/internal/protocol"
)

// RenderSystemdUnit renders a hardened Linux systemd `.service` unit file starting
// `"<exePath>" server --service-config "<cfgPath>"` after network-online.target and tailscaled.service.
func RenderSystemdUnit(name, description, exePath, cfgPath string) (string, error) {
	if _, err := ValidateServiceName(name); err != nil {
		return "", err
	}
	if err := rejectControlChars(description, "description"); err != nil {
		return "", err
	}
	if strings.TrimSpace(exePath) == "" {
		return "", errors.New("executable path cannot be empty")
	}
	if strings.TrimSpace(cfgPath) == "" {
		return "", errors.New("config path cannot be empty")
	}
	if err := rejectControlChars(exePath, "executable path"); err != nil {
		return "", err
	}
	if err := rejectControlChars(cfgPath, "config path"); err != nil {
		return "", err
	}

	desc := strings.TrimSpace(description)
	if desc == "" {
		desc = DefaultDescription
	}

	unit := fmt.Sprintf(`[Unit]
Description=%s
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s server --service-config %s
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, desc, quoteSystemdArg(exePath), quoteSystemdArg(cfgPath))

	return unit, nil
}

func quoteSystemdArg(s string) string {
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	escaped = strings.ReplaceAll(escaped, `%`, `%%`)
	escaped = strings.ReplaceAll(escaped, `$`, `$$`)
	return `"` + escaped + `"`
}

func rejectControlChars(val, field string) error {
	for i := 0; i < len(val); i++ {
		if val[i] == 0 || val[i] == '\n' || val[i] == '\r' {
			return fmt.Errorf("%s contains invalid control characters", field)
		}
	}
	return nil
}

// ParseSystemctlShow parses `systemctl show` KEY=VALUE lines into a map.
func ParseSystemctlShow(output string) map[string]string {
	props := make(map[string]string)
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimRight(rawLine, "\r")
		if line == "" {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		props[strings.TrimSpace(line[:eq])] = strings.TrimSpace(line[eq+1:])
	}
	return props
}

// LaunchdLabel returns the canonical macOS LaunchDaemon label `io.agent-bridge.<name>`.
func LaunchdLabel(name string) (string, error) {
	norm, err := ValidateServiceName(name)
	if err != nil {
		return "", err
	}
	return "io.agent-bridge." + norm, nil
}

// RenderLaunchdPlist renders a macOS `/Library/LaunchDaemons/io.agent-bridge.<name>.plist` XML file
// with XML-escaped paths, RunAtLoad=true, KeepAlive=true, and ThrottleInterval=3.
func RenderLaunchdPlist(name, exePath, cfgPath string) (string, error) {
	label, err := LaunchdLabel(name)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(exePath) == "" {
		return "", errors.New("executable path cannot be empty")
	}
	if strings.TrimSpace(cfgPath) == "" {
		return "", errors.New("config path cannot be empty")
	}
	if err := rejectControlChars(exePath, "executable path"); err != nil {
		return "", err
	}
	if err := rejectControlChars(cfgPath, "config path"); err != nil {
		return "", err
	}

	escLabel, err := xmlEscapeString(label)
	if err != nil {
		return "", err
	}
	escExe, err := xmlEscapeString(exePath)
	if err != nil {
		return "", err
	}
	escCfg, err := xmlEscapeString(cfgPath)
	if err != nil {
		return "", err
	}

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>server</string>
		<string>--service-config</string>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>3</integer>
</dict>
</plist>
`, escLabel, escExe, escCfg)

	return plist, nil
}

func xmlEscapeString(s string) (string, error) {
	var buf bytes.Buffer
	if err := xml.EscapeText(&buf, []byte(s)); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ParseLaunchctlPrint extracts running status, state string, and PID from `launchctl print system/...` output.
func ParseLaunchctlPrint(output string) (running bool, state string, pid int) {
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "state =") {
			state = strings.TrimSpace(strings.TrimPrefix(line, "state ="))
		} else if strings.HasPrefix(line, "pid =") {
			rawPID := strings.TrimSpace(strings.TrimPrefix(line, "pid ="))
			if p, err := strconv.Atoi(rawPID); err == nil && p > 0 {
				pid = p
			}
		}
	}
	if strings.EqualFold(state, "running") {
		running = true
	} else if state == "" && pid > 0 {
		running = true
		state = "running"
	}
	if state == "" {
		state = "stopped"
	}
	return running, state, pid
}

// ParseLaunchdPlistProgramArgs extracts the executable path and `--service-config` value from a
// rendered LaunchDaemon XML `.plist` document.
func ParseLaunchdPlistProgramArgs(plistXML string) (exePath, cfgPath string) {
	dec := xml.NewDecoder(strings.NewReader(plistXML))
	inDict := false
	lastKey := ""
	inProgArgs := false
	var args []string

	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch se := tok.(type) {
		case xml.StartElement:
			switch se.Name.Local {
			case "dict":
				inDict = true
			case "key":
				if inDict && !inProgArgs {
					var k string
					if err := dec.DecodeElement(&k, &se); err == nil {
						lastKey = strings.TrimSpace(k)
					}
				}
			case "array":
				if inDict && lastKey == "ProgramArguments" {
					inProgArgs = true
				}
			case "string":
				if inProgArgs {
					var s string
					if err := dec.DecodeElement(&s, &se); err == nil {
						args = append(args, s)
					}
				}
			}
		case xml.EndElement:
			if se.Name.Local == "array" && inProgArgs {
				inProgArgs = false
				lastKey = ""
			}
		}
	}

	if len(args) == 0 {
		return "", ""
	}
	exePath = args[0]
	for i := 1; i < len(args); i++ {
		tok := args[i]
		if (tok == "--service-config" || tok == "-service-config") && i+1 < len(args) {
			cfgPath = args[i+1]
			break
		}
		if strings.HasPrefix(tok, "--service-config=") {
			cfgPath = strings.TrimPrefix(tok, "--service-config=")
			break
		}
		if strings.HasPrefix(tok, "-service-config=") {
			cfgPath = strings.TrimPrefix(tok, "-service-config=")
			break
		}
	}
	return exePath, cfgPath
}

// FormatWindowsServiceCommandLine formats `<quotedExePath> server --service-config <quotedCfgPath>`
// with explicit double quotes around both paths to prevent unquoted-service-path ambiguity.
func FormatWindowsServiceCommandLine(exePath, cfgPath string) string {
	return fmt.Sprintf("%s server --service-config %s", quoteWin32ArgAlways(exePath), quoteWin32ArgAlways(cfgPath))
}

func quoteWin32ArgAlways(arg string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	backslashes := 0
	for i := 0; i < len(arg); i++ {
		ch := arg[i]
		switch ch {
		case '\\':
			backslashes++
		case '"':
			for j := 0; j < backslashes*2+1; j++ {
				sb.WriteByte('\\')
			}
			backslashes = 0
			sb.WriteByte('"')
		default:
			for j := 0; j < backslashes; j++ {
				sb.WriteByte('\\')
			}
			backslashes = 0
			sb.WriteByte(ch)
		}
	}
	for j := 0; j < backslashes*2; j++ {
		sb.WriteByte('\\')
	}
	sb.WriteByte('"')
	return sb.String()
}

// ParseServiceCommandLine extracts the binary path and `--service-config` value from a Windows SCM
// BinaryPathName or systemd ExecStart line.
func ParseServiceCommandLine(cmdLine string) (exePath, cfgPath string) {
	tokens := splitCommandLineTokens(strings.TrimSpace(cmdLine))
	if len(tokens) == 0 {
		return "", ""
	}
	exePath = tokens[0]
	for i := 1; i < len(tokens); i++ {
		tok := tokens[i]
		if (tok == "--service-config" || tok == "-service-config") && i+1 < len(tokens) {
			cfgPath = tokens[i+1]
			break
		}
		if strings.HasPrefix(tok, "--service-config=") {
			cfgPath = strings.TrimPrefix(tok, "--service-config=")
			break
		}
		if strings.HasPrefix(tok, "-service-config=") {
			cfgPath = strings.TrimPrefix(tok, "-service-config=")
			break
		}
	}
	return exePath, cfgPath
}

func splitCommandLineTokens(s string) []string {
	var tokens []string
	var cur strings.Builder
	inQuote := false
	hasToken := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' {
			bs := 0
			for i < len(s) && s[i] == '\\' {
				bs++
				i++
			}
			if i < len(s) && s[i] == '"' {
				for j := 0; j < bs/2; j++ {
					cur.WriteByte('\\')
				}
				hasToken = true
				if bs%2 == 0 {
					inQuote = !inQuote
				} else {
					cur.WriteByte('"')
				}
				continue
			}
			for j := 0; j < bs; j++ {
				cur.WriteByte('\\')
			}
			hasToken = true
			i--
			continue
		}
		if ch == '"' {
			inQuote = !inQuote
			hasToken = true
			continue
		}
		if !inQuote && (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
			if hasToken {
				tokens = append(tokens, cur.String())
				cur.Reset()
				hasToken = false
			}
			continue
		}
		cur.WriteByte(ch)
		hasToken = true
	}
	if hasToken {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

// NormalizeFirewallSubnets validates and normalizes a list of CIDR subnets (or single IPs),
// returning DefaultFirewallSubnetsCSV when subnets is empty.
func NormalizeFirewallSubnets(subnets []string) (string, error) {
	var normalized []string
	seen := make(map[string]struct{})

	for _, entry := range subnets {
		for _, tok := range strings.Split(entry, ",") {
			candidate := strings.TrimSpace(tok)
			if candidate == "" {
				continue
			}
			if strings.Contains(candidate, "/") {
				_, ipNet, err := net.ParseCIDR(candidate)
				if err != nil {
					return "", fmt.Errorf("invalid firewall subnet CIDR %q: %w", candidate, err)
				}
				canon := ipNet.String()
				if _, ok := seen[canon]; !ok {
					seen[canon] = struct{}{}
					normalized = append(normalized, canon)
				}
			} else {
				ip := net.ParseIP(candidate)
				if ip == nil {
					return "", fmt.Errorf("invalid firewall IP/CIDR %q", candidate)
				}
				canon := ip.String()
				if _, ok := seen[canon]; !ok {
					seen[canon] = struct{}{}
					normalized = append(normalized, canon)
				}
			}
		}
	}

	if len(normalized) == 0 {
		return DefaultFirewallSubnetsCSV, nil
	}
	return strings.Join(normalized, ","), nil
}

// BuildNetshFirewallCommands constructs the pure argument-slice `netsh.exe` command invocations
// (delete existing + add inbound program/subnet-scoped rules) for AgentBridge-Exec and AgentBridge-Cluster.
func BuildNetshFirewallCommands(
	exePath string,
	execPort int,
	clusterPort int,
	allowedSubnets []string,
) (commands [][]string, ruleNames []string, err error) {
	trimmedExe := strings.TrimSpace(exePath)
	if trimmedExe == "" {
		return nil, nil, errors.New("executable path cannot be empty when configuring firewall")
	}
	if err := rejectControlChars(trimmedExe, "executable path"); err != nil {
		return nil, nil, err
	}

	remoteIPCSV, err := NormalizeFirewallSubnets(allowedSubnets)
	if err != nil {
		return nil, nil, err
	}

	if execPort <= 0 {
		execPort = protocol.DefaultPort
	}
	if execPort > 65535 {
		return nil, nil, fmt.Errorf("invalid exec port %d", execPort)
	}

	if clusterPort <= 0 {
		clusterPort = config.DefaultClusterPort
	}
	if clusterPort > 65535 {
		return nil, nil, fmt.Errorf("invalid cluster port %d", clusterPort)
	}

	specs := []struct {
		name string
		port int
	}{
		{name: FirewallRuleExecName, port: execPort},
		{name: FirewallRuleClusterName, port: clusterPort},
	}

	for _, sp := range specs {
		commands = append(commands,
			[]string{
				"advfirewall", "firewall", "delete", "rule",
				"name=" + sp.name,
			},
			[]string{
				"advfirewall", "firewall", "add", "rule",
				"name=" + sp.name,
				"dir=in",
				"action=allow",
				"protocol=TCP",
				"localport=" + strconv.Itoa(sp.port),
				"program=" + trimmedExe,
				"remoteip=" + remoteIPCSV,
				"profile=any",
			},
		)
		ruleNames = append(ruleNames, sp.name)
	}
	return commands, ruleNames, nil
}

func resolveFirewallPorts(opts InstallOptions) (execPort, clusterPort int) {
	execPort = opts.ExecPort
	if execPort <= 0 && opts.Config != nil && opts.Config.Port > 0 {
		execPort = opts.Config.Port
	}
	if execPort <= 0 {
		execPort = protocol.DefaultPort
	}

	clusterPort = opts.ClusterPort
	if clusterPort <= 0 && opts.Config != nil {
		for _, spec := range opts.Config.ClusterBindSpecs {
			if _, pStr, err := net.SplitHostPort(strings.TrimSpace(spec)); err == nil {
				if p, convErr := strconv.Atoi(pStr); convErr == nil && p >= 1 && p <= 65535 {
					clusterPort = p
					break
				}
			}
		}
	}
	if clusterPort <= 0 {
		clusterPort = config.DefaultClusterPort
	}
	return execPort, clusterPort
}
