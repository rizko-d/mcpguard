package configpatch_test

import (
	"os"
	"path/filepath"
	"testing"

	"mcpguard/internal/configpatch"
	"mcpguard/internal/discovery"
)

func TestProtectAndUnprotectServerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "claude_desktop_config.json")
	original := `{
  "mcpServers": {
    "fs": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.2", "/workspace"]
    }
  }
}
`
	if err := os.WriteFile(cfgPath, []byte(original), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	proxyBin := `C:\MCPGuard\mcpguard-proxy.exe`
	if err := configpatch.ProtectServer(cfgPath, "fs", proxyBin, "http://127.0.0.1:43771"); err != nil {
		t.Fatalf("ProtectServer failed: %v", err)
	}

	// Backup file must exist
	if _, err := os.Stat(cfgPath + ".mcpguard.bak"); err != nil {
		t.Fatalf("expected backup file to exist: %v", err)
	}

	// Discovery must detect IsProtected == true
	srvs, err := discovery.ParseConfigFile("Claude Desktop", cfgPath)
	if err != nil || len(srvs) != 1 {
		t.Fatalf("ParseConfigFile after protect: err=%v len=%d", err, len(srvs))
	}
	if !srvs[0].IsProtected {
		t.Fatalf("expected server to be marked IsProtected=true, got command=%q args=%v", srvs[0].Command, srvs[0].Args)
	}

	// Unprotect must restore original command & args cleanly
	if err := configpatch.UnprotectServer(cfgPath, "fs"); err != nil {
		t.Fatalf("UnprotectServer failed: %v", err)
	}
	srvs, err = discovery.ParseConfigFile("Claude Desktop", cfgPath)
	if err != nil || len(srvs) != 1 {
		t.Fatalf("ParseConfigFile after unprotect: err=%v len=%d", err, len(srvs))
	}
	if srvs[0].IsProtected || srvs[0].Command != "npx" || len(srvs[0].Args) != 3 {
		t.Fatalf("expected original command restored, got %+v", srvs[0])
	}
}
