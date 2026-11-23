package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"mcpguard/internal/configpatch"
	"mcpguard/internal/model"
)

// CustomPath represents a user-registered custom MCP config file path.
type CustomPath struct {
	Label string
	Path  string
}

type candidateLocation struct {
	ClientName string
	Path       string
	IsCustom   bool
}

// DefaultLocations returns OS-specific standard MCP client config file paths.
func DefaultLocations() []candidateLocation {
	home, _ := os.UserHomeDir()
	appData := os.Getenv("APPDATA")
	if appData == "" && runtime.GOOS == "windows" && home != "" {
		appData = filepath.Join(home, "AppData", "Roaming")
	}

	var locs []candidateLocation
	switch runtime.GOOS {
	case "windows":
		if appData != "" {
			locs = append(locs,
				candidateLocation{ClientName: "Claude Desktop", Path: filepath.Join(appData, "Claude", "claude_desktop_config.json")},
				candidateLocation{ClientName: "VS Code", Path: filepath.Join(appData, "Code", "User", "mcp.json")},
				candidateLocation{ClientName: "Cline (VS Code)", Path: filepath.Join(appData, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")},
				candidateLocation{ClientName: "Roo Code (VS Code)", Path: filepath.Join(appData, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json")},
				candidateLocation{ClientName: "Zed", Path: filepath.Join(appData, "Zed", "settings.json")},
			)
		}
	case "darwin":
		if home != "" {
			appSupport := filepath.Join(home, "Library", "Application Support")
			locs = append(locs,
				candidateLocation{ClientName: "Claude Desktop", Path: filepath.Join(appSupport, "Claude", "claude_desktop_config.json")},
				candidateLocation{ClientName: "VS Code", Path: filepath.Join(appSupport, "Code", "User", "mcp.json")},
				candidateLocation{ClientName: "Cline (VS Code)", Path: filepath.Join(appSupport, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")},
				candidateLocation{ClientName: "Zed", Path: filepath.Join(home, ".config", "zed", "settings.json")},
			)
		}
	default:
		if home != "" {
			cfgDir := filepath.Join(home, ".config")
			locs = append(locs,
				candidateLocation{ClientName: "Claude Desktop", Path: filepath.Join(cfgDir, "Claude", "claude_desktop_config.json")},
				candidateLocation{ClientName: "VS Code", Path: filepath.Join(cfgDir, "Code", "User", "mcp.json")},
				candidateLocation{ClientName: "Cline (VS Code)", Path: filepath.Join(cfgDir, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")},
				candidateLocation{ClientName: "Zed", Path: filepath.Join(cfgDir, "zed", "settings.json")},
			)
		}
	}

	if home != "" {
		locs = append(locs,
			candidateLocation{ClientName: "Cursor", Path: filepath.Join(home, ".cursor", "mcp.json")},
			candidateLocation{ClientName: "Windsurf", Path: filepath.Join(home, ".codeium", "windsurf", "mcp_config.json")},
			candidateLocation{ClientName: "Claude Code", Path: filepath.Join(home, ".claude.json")},
			candidateLocation{ClientName: "Antigravity", Path: filepath.Join(home, ".gemini", "antigravity", "mcp_config.json")},
		)
	}

	return locs
}

// DiscoverAll scans default OS locations plus any custom user-provided paths.
func DiscoverAll(customs []CustomPath) ([]model.ConfigSource, []model.MCPServerConfig) {
	locations := DefaultLocations()
	seenPaths := make(map[string]bool)
	for _, l := range locations {
		seenPaths[strings.ToLower(filepath.Clean(l.Path))] = true
	}

	for _, c := range customs {
		cleaned := filepath.Clean(c.Path)
		key := strings.ToLower(cleaned)
		if seenPaths[key] {
			continue
		}
		seenPaths[key] = true
		label := c.Label
		if strings.TrimSpace(label) == "" {
			label = "Custom (" + filepath.Base(cleaned) + ")"
		}
		locations = append(locations, candidateLocation{
			ClientName: label,
			Path:       cleaned,
			IsCustom:   true,
		})
	}

	var sources []model.ConfigSource
	var servers []model.MCPServerConfig

	for _, loc := range locations {
		src := model.ConfigSource{
			ClientName: loc.ClientName,
			Path:       loc.Path,
			IsCustom:   loc.IsCustom,
		}

		info, err := os.Stat(loc.Path)
		if err != nil || info.IsDir() {
			src.Exists = false
			sources = append(sources, src)
			continue
		}

		src.Exists = true
		parsed, parseErr := ParseConfigFile(loc.ClientName, loc.Path)
		if parseErr != nil {
			src.ParseError = parseErr.Error()
		} else {
			src.ServerCount = len(parsed)
			servers = append(servers, parsed...)
		}
		sources = append(sources, src)
	}

	return sources, servers
}

// ParseConfigFile parses an MCP JSON configuration file into normalized server records.
func ParseConfigFile(clientName, path string) ([]model.MCPServerConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cleaned := stripJSONComments(raw)
	return ParseConfigBytes(clientName, path, cleaned)
}

// ParseConfigBytes parses raw JSON/JSONC bytes from an MCP config into normalized server definitions.
func ParseConfigBytes(clientName, configPath string, data []byte) ([]model.MCPServerConfig, error) {
	data = stripJSONComments(data)
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// Support standard keys: mcpServers (Claude/Cursor/Windsurf/Cline), servers (VS Code), context_servers (Zed)
	serverMapKeys := []string{"mcpServers", "servers", "context_servers"}
	var serverRawMap map[string]json.RawMessage

	for _, k := range serverMapKeys {
		if rawMap, ok := root[k]; ok {
			var m map[string]json.RawMessage
			if err := json.Unmarshal(rawMap, &m); err == nil && len(m) > 0 {
				serverRawMap = m
				break
			}
		}
	}

	if len(serverRawMap) == 0 {
		return nil, nil
	}

	names := make([]string, 0, len(serverRawMap))
	for name := range serverRawMap {
		names = append(names, name)
	}
	sort.Strings(names)

	var results []model.MCPServerConfig
	for _, name := range names {
		var entry struct {
			Command   string            `json:"command"`
			Args      []string          `json:"args"`
			URL       string            `json:"url"`
			ServerURL string            `json:"serverUrl"`
			Type      string            `json:"type"`
			Transport string            `json:"transport"`
			Env       map[string]string `json:"env"`
			Headers   map[string]string `json:"headers"`
			Disabled  bool              `json:"disabled"`
			CommandObj *struct {
				Path string            `json:"path"`
				Args []string          `json:"args"`
				Env  map[string]string `json:"env"`
			} `json:"-"`
		}

		rawEntry := serverRawMap[name]
		if err := json.Unmarshal(rawEntry, &entry); err != nil {
			// Handle Zed's nested command object format: {"command": {"path": "...", "args": [...]}}
			var zedEntry struct {
				Command struct {
					Path string            `json:"path"`
					Args []string          `json:"args"`
					Env  map[string]string `json:"env"`
				} `json:"command"`
			}
			if zErr := json.Unmarshal(rawEntry, &zedEntry); zErr == nil && zedEntry.Command.Path != "" {
				entry.Command = zedEntry.Command.Path
				entry.Args = zedEntry.Command.Args
				entry.Env = zedEntry.Command.Env
			} else {
				continue
			}
		}

		urlVal := strings.TrimSpace(entry.URL)
		if urlVal == "" {
			urlVal = strings.TrimSpace(entry.ServerURL)
		}

		transport := detectTransport(entry.Type, entry.Transport, entry.Command, urlVal)

		cfg := model.MCPServerConfig{
			ID:         MakeServerID(clientName, configPath, name),
			ClientName: clientName,
			ConfigPath: configPath,
			ServerName: name,
			Transport:  transport,
			Command:    strings.TrimSpace(entry.Command),
			Args:       entry.Args,
			URL:        urlVal,
			Env:        entry.Env,
			MaskedEnv:  MaskMap(entry.Env),
			Headers:     entry.Headers,
			MaskedHdrs:  MaskMap(entry.Headers),
			Disabled:    entry.Disabled,
			IsProtected: configpatch.IsWrappedCommand(strings.TrimSpace(entry.Command), entry.Args),
		}
		results = append(results, cfg)
	}

	return results, nil
}

// MakeServerID generates a deterministic 16-char hex ID for a server entry.
func MakeServerID(clientName, configPath, serverName string) string {
	h := sha256.Sum256([]byte(strings.ToLower(clientName) + "|" + strings.ToLower(filepath.Clean(configPath)) + "|" + serverName))
	return hex.EncodeToString(h[:8])
}

func detectTransport(typ, tr, cmd, urlVal string) model.TransportType {
	hint := strings.ToLower(strings.TrimSpace(typ))
	if hint == "" {
		hint = strings.ToLower(strings.TrimSpace(tr))
	}
	switch {
	case hint == "sse":
		return model.TransportSSE
	case hint == "http" || hint == "streamable-http" || hint == "streamablehttp":
		return model.TransportHTTP
	case urlVal != "" && cmd == "":
		if strings.Contains(strings.ToLower(urlVal), "/sse") {
			return model.TransportSSE
		}
		return model.TransportHTTP
	default:
		return model.TransportStdio
	}
}

// MaskMap returns a copy of m with potentially sensitive values partially masked.
func MaskMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if looksSensitiveKey(k) || looksLikeToken(v) {
			out[k] = MaskSecret(v)
		} else {
			out[k] = v
		}
	}
	return out
}

// MaskSecret obscures the middle of a secret string while keeping prefix/suffix recognizable.
func MaskSecret(v string) string {
	v = strings.TrimSpace(v)
	if len(v) <= 6 {
		return "******"
	}
	if len(v) <= 12 {
		return v[:2] + "****" + v[len(v)-2:]
	}
	return v[:4] + "••••••••" + v[len(v)-4:]
}

func looksSensitiveKey(k string) bool {
	u := strings.ToUpper(k)
	keywords := []string{"KEY", "TOKEN", "SECRET", "PASS", "AUTH", "CREDENTIAL", "COOKIE", "PRIVATE"}
	for _, kw := range keywords {
		if strings.Contains(u, kw) {
			return true
		}
	}
	return false
}

func looksLikeToken(v string) bool {
	prefixes := []string{"sk-", "ghp_", "github_pat_", "xoxb-", "xoxp-", "AKIA", "AIza", "Bearer ", "eyJ"}
	for _, p := range prefixes {
		if strings.HasPrefix(v, p) {
			return true
		}
	}
	return false
}

// stripJSONComments strips // line comments and /* block comments */ outside string literals (for JSONC like Zed/VS Code).
func stripJSONComments(input []byte) []byte {
	var out strings.Builder
	out.Grow(len(input))
	inString := false
	escaped := false

	for i := 0; i < len(input); i++ {
		c := input[i]
		if inString {
			out.WriteByte(c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}

		if c == '"' {
			inString = true
			out.WriteByte(c)
			continue
		}

		if c == '/' && i+1 < len(input) {
			if input[i+1] == '/' {
				i += 2
				for i < len(input) && input[i] != '\n' {
					i++
				}
				if i < len(input) {
					out.WriteByte('\n')
				}
				continue
			}
			if input[i+1] == '*' {
				i += 2
				for i+1 < len(input) && !(input[i] == '*' && input[i+1] == '/') {
					i++
				}
				i++
				continue
			}
		}

		out.WriteByte(c)
	}

	return []byte(out.String())
}
