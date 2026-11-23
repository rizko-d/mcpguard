package discovery_test

import (
	"testing"

	"mcpguard/internal/discovery"
	"mcpguard/internal/model"
)

func TestParseConfigBytesMultiFormatAndMasking(t *testing.T) {
	jsonc := []byte(`{
		// Claude Desktop / Cursor style with comments
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.2", "/tmp"],
				"env": {
					"API_TOKEN": "sk-proj-VerySecretValue1234567890",
					"LOG_LEVEL": "info"
				}
			},
			"remote-api": {
				"url": "https://mcp.example.com/sse"
			}
		}
	}`)

	servers, err := discovery.ParseConfigBytes("Claude Desktop", "/fake/config.json", jsonc)
	if err != nil {
		t.Fatalf("ParseConfigBytes failed: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}

	fs := servers[0]
	if fs.ServerName != "filesystem" || fs.Transport != model.TransportStdio {
		t.Errorf("unexpected filesystem server: %+v", fs)
	}
	if fs.MaskedEnv["API_TOKEN"] == fs.Env["API_TOKEN"] {
		t.Errorf("expected API_TOKEN to be masked in MaskedEnv, got %q", fs.MaskedEnv["API_TOKEN"])
	}
	if fs.MaskedEnv["LOG_LEVEL"] != "info" {
		t.Errorf("expected non-sensitive LOG_LEVEL unchanged, got %q", fs.MaskedEnv["LOG_LEVEL"])
	}

	remote := servers[1]
	if remote.ServerName != "remote-api" || remote.Transport != model.TransportSSE {
		t.Errorf("expected remote-api with SSE transport, got %+v", remote)
	}
}
