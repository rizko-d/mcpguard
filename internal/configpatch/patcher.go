package configpatch

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// IsWrappedCommand returns true if the command is already wrapped by mcpguard-proxy.
func IsWrappedCommand(command string, args []string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(command)))
	if base == "mcpguard-proxy" || base == "mcpguard-proxy.exe" {
		return true
	}
	// Also detect if wrapped via full path containing mcpguard-proxy
	return strings.Contains(strings.ToLower(command), "mcpguard-proxy")
}

// ResolveProxyBinary locates mcpguard-proxy(.exe) next to the running executable or in build/bin.
func ResolveProxyBinary() (string, bool) {
	candidates := []string{}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "mcpguard-proxy.exe"),
			filepath.Join(exeDir, "mcpguard-proxy"),
		)
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(wd, "build", "bin", "mcpguard-proxy.exe"),
			filepath.Join(wd, "build", "bin", "mcpguard-proxy"),
			filepath.Join(wd, "mcpguard-proxy.exe"),
			filepath.Join(wd, "mcpguard-proxy"),
		)
	}

	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c, true
		}
	}
	if len(candidates) > 0 {
		return candidates[0], false
	}
	return "mcpguard-proxy", false
}

// ProtectServer wraps an existing stdio MCP server entry inside a JSON config file with mcpguard-proxy.
// A backup file (<configPath>.mcpguard.bak) is automatically created before the first modification.
func ProtectServer(configPath, serverName, proxyBinary, controlURL string) error {
	if strings.HasPrefix(configPath, "mcpguard://") {
		return errors.New("cannot patch simulated Demo Lab config; use Protect on a local config file")
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config %q: %w", configPath, err)
	}

	root, mapKey, srvMap, err := loadServerMap(raw)
	if err != nil {
		return err
	}

	entryAny, ok := srvMap[serverName]
	if !ok {
		return fmt.Errorf("server %q not found in %s", serverName, configPath)
	}
	entry, ok := entryAny.(map[string]interface{})
	if !ok {
		return fmt.Errorf("server %q has unsupported JSON structure", serverName)
	}

	origCmd, _ := entry["command"].(string)
	if strings.TrimSpace(origCmd) == "" {
		return fmt.Errorf("server %q is not a stdio command server (missing 'command' field)", serverName)
	}
	origArgs := toStringSlice(entry["args"])
	if IsWrappedCommand(origCmd, origArgs) {
		return nil // Already protected
	}

	// Create backup if one does not already exist
	backupPath := configPath + ".mcpguard.bak"
	if _, statErr := os.Stat(backupPath); os.IsNotExist(statErr) {
		if err := os.WriteFile(backupPath, raw, 0o600); err != nil {
			return fmt.Errorf("create backup %q: %w", backupPath, err)
		}
	}

	newArgs := []string{"--server", serverName}
	if controlURL != "" {
		newArgs = append(newArgs, "--control-url", controlURL)
	}
	newArgs = append(newArgs, "--", origCmd)
	newArgs = append(newArgs, origArgs...)

	entry["command"] = proxyBinary
	entry["args"] = newArgs
	srvMap[serverName] = entry
	root[mapKey] = srvMap

	return writeFormattedJSON(configPath, root)
}

// UnprotectServer unwraps a previously protected MCP server entry back to its original command and args.
func UnprotectServer(configPath, serverName string) error {
	if strings.HasPrefix(configPath, "mcpguard://") {
		return errors.New("cannot unpatch simulated Demo Lab config")
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config %q: %w", configPath, err)
	}

	root, mapKey, srvMap, err := loadServerMap(raw)
	if err != nil {
		return err
	}

	entryAny, ok := srvMap[serverName]
	if !ok {
		return fmt.Errorf("server %q not found in %s", serverName, configPath)
	}
	entry, ok := entryAny.(map[string]interface{})
	if !ok {
		return fmt.Errorf("server %q has unsupported JSON structure", serverName)
	}

	currCmd, _ := entry["command"].(string)
	currArgs := toStringSlice(entry["args"])
	if !IsWrappedCommand(currCmd, currArgs) {
		return nil // Already unprotected
	}

	sepIdx := -1
	for i, a := range currArgs {
		if a == "--" {
			sepIdx = i
			break
		}
	}
	if sepIdx == -1 || sepIdx+1 >= len(currArgs) {
		return fmt.Errorf("cannot unwrap server %q: missing '-- <command>' delimiter", serverName)
	}

	origCmd := currArgs[sepIdx+1]
	origArgs := currArgs[sepIdx+2:]

	entry["command"] = origCmd
	if len(origArgs) > 0 {
		entry["args"] = origArgs
	} else {
		entry["args"] = []string{}
	}
	srvMap[serverName] = entry
	root[mapKey] = srvMap

	return writeFormattedJSON(configPath, root)
}

func loadServerMap(raw []byte) (map[string]interface{}, string, map[string]interface{}, error) {
	var root map[string]interface{}
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, "", nil, fmt.Errorf("parse JSON config: %w", err)
	}
	for _, key := range []string{"mcpServers", "servers"} {
		if v, ok := root[key]; ok {
			if m, ok := v.(map[string]interface{}); ok {
				return root, key, m, nil
			}
		}
	}
	return nil, "", nil, errors.New("config file does not contain 'mcpServers' or 'servers' object")
}

func toStringSlice(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func writeFormattedJSON(path string, data map[string]interface{}) error {
	out, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(path, out, 0o600)
}
