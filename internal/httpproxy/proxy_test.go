package httpproxy_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"mcpguard/internal/firewall"
	"mcpguard/internal/httpproxy"
	"mcpguard/internal/storage"
)

func TestHTTPProxyEnforcesPolicyAndDLP(t *testing.T) {
	st, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer st.Close()

	cp, err := firewall.NewControlPlane(st, firewall.Callbacks{})
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"text":"leaked sk-proj-UpstreamSecret1234567890abcdef"}}`))
	}))
	defer upstream.Close()

	proxySrv := httpproxy.NewServer(st, cp)
	if err := proxySrv.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start proxy: %v", err)
	}
	defer proxySrv.Stop(context.Background())

	route, err := proxySrv.AddRoute("remote-docs", upstream.URL)
	if err != nil {
		t.Fatalf("AddRoute: %v", err)
	}

	// 1. Sensitive path call must be blocked with -32001 before hitting upstream
	denyReq := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"~/.ssh/id_rsa"}}}`)
	resp1, err := http.Post(route.LocalURL, "application/json", bytes.NewReader(denyReq))
	if err != nil {
		t.Fatalf("POST denyReq: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	if !strings.Contains(string(body1), "-32001") {
		t.Fatalf("expected JSON-RPC -32001 block error, got: %s", string(body1))
	}

	// 2. Allowed call must forward to upstream and DLP-redact the leaked key in response
	allowReq := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_docs","arguments":{"query":"hello"}}}`)
	resp2, err := http.Post(route.LocalURL, "application/json", bytes.NewReader(allowReq))
	if err != nil {
		t.Fatalf("POST allowReq: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if strings.Contains(string(body2), "sk-proj-") || !strings.Contains(string(body2), "[REDACTED:") {
		t.Fatalf("expected DLP redaction in HTTP proxy response, got: %s", string(body2))
	}

	stSnap := proxySrv.Status()
	if len(stSnap.Routes) != 1 || stSnap.Routes[0].RequestCount != 2 || stSnap.Routes[0].BlockedCount != 1 {
		t.Fatalf("unexpected route counters: %+v", stSnap.Routes)
	}
}
