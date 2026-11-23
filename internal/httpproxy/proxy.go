package httpproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mcpguard/internal/firewall"
	"mcpguard/internal/model"
	"mcpguard/internal/storage"
)

const DefaultProxyAddr = "127.0.0.1:43772"

var slugSanitizer = regexp.MustCompile(`[^a-z0-9\-]+`)

type routeEntry struct {
	route        model.HTTPProxyRoute
	upstream     *url.URL
	requestCount atomic.Int64
	blockedCount atomic.Int64
}

// Server runs a local loopback HTTP & Streamable-HTTP/SSE reverse proxy that routes remote MCP
// tool traffic through the MCPGuard Firewall ControlPlane (Policy + HITL + DLP + Injection Guard).
type Server struct {
	mu      sync.RWMutex
	store   *storage.Store
	cp      *firewall.ControlPlane
	addr    string
	httpSrv *http.Server
	client  *http.Client
	running bool
	routes  map[string]*routeEntry
}

// NewServer initializes the HTTP/SSE MCP reverse proxy and restores persisted routes from SQLite.
func NewServer(store *storage.Store, cp *firewall.ControlPlane) *Server {
	s := &Server{
		store:  store,
		cp:     cp,
		addr:   DefaultProxyAddr,
		client: &http.Client{Timeout: 45 * time.Second},
		routes: make(map[string]*routeEntry),
	}

	if store != nil {
		if saved, err := store.ListHTTPProxyRoutes(); err == nil {
			for _, r := range saved {
				if u, uErr := url.Parse(r.UpstreamURL); uErr == nil {
					s.routes[r.Slug] = &routeEntry{route: r, upstream: u}
				}
			}
		}
	}
	return s
}

// Start binds the loopback HTTP/SSE reverse proxy server.
func (s *Server) Start(listenAddr string) error {
	if listenAddr == "" {
		listenAddr = DefaultProxyAddr
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("bind http proxy listener: %w", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "service": "mcpguard-http-proxy"})
	})
	mux.HandleFunc("/mcp/", s.handleMCPProxy)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	s.mu.Lock()
	s.addr = ln.Addr().String()
	s.httpSrv = srv
	s.running = true
	s.mu.Unlock()

	go func() {
		_ = srv.Serve(ln)
	}()
	return nil
}

// Stop shuts down the HTTP reverse proxy listener.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	srv := s.httpSrv
	s.running = false
	s.mu.Unlock()
	if srv != nil {
		return srv.Shutdown(ctx)
	}
	return nil
}

// BaseURL returns the local proxy base URL (e.g., http://127.0.0.1:43772).
func (s *Server) BaseURL() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return "http://" + s.addr
}

// AddRoute validates and registers a new remote HTTP/SSE MCP proxy route.
func (s *Server) AddRoute(serverName, upstreamURL string) (model.HTTPProxyRoute, error) {
	serverName = strings.TrimSpace(serverName)
	upstreamURL = strings.TrimSpace(upstreamURL)
	if serverName == "" {
		return model.HTTPProxyRoute{}, fmt.Errorf("server name is required")
	}
	u, err := url.Parse(upstreamURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return model.HTTPProxyRoute{}, fmt.Errorf("invalid upstream URL %q (must start with http:// or https://)", upstreamURL)
	}

	slug := sanitizeSlug(serverName)
	if slug == "" {
		slug = "mcp-route"
	}

	route := model.HTTPProxyRoute{
		ID:          "route-" + slug,
		Slug:        slug,
		ServerName:  serverName,
		UpstreamURL: upstreamURL,
		LocalURL:    fmt.Sprintf("%s/mcp/%s", s.BaseURL(), slug),
		Enabled:     true,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}

	if s.store != nil {
		if err := s.store.SaveHTTPProxyRoute(route); err != nil {
			return model.HTTPProxyRoute{}, err
		}
	}

	s.mu.Lock()
	s.routes[slug] = &routeEntry{route: route, upstream: u}
	s.mu.Unlock()

	return route, nil
}

// ToggleRoute enables or disables forwarding for a specific route slug.
func (s *Server) ToggleRoute(slug string, enabled bool) error {
	s.mu.Lock()
	entry, ok := s.routes[slug]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("route %q not found", slug)
	}
	entry.route.Enabled = enabled
	copyRoute := entry.route
	s.mu.Unlock()

	if s.store != nil {
		return s.store.SaveHTTPProxyRoute(copyRoute)
	}
	return nil
}

// DeleteRoute removes a route by slug.
func (s *Server) DeleteRoute(slug string) error {
	s.mu.Lock()
	delete(s.routes, slug)
	s.mu.Unlock()
	if s.store != nil {
		return s.store.DeleteHTTPProxyRoute(slug)
	}
	return nil
}

// Status returns the current HTTP/SSE proxy status and all registered routes.
func (s *Server) Status() model.HTTPProxyStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	base := "http://" + s.addr
	routes := make([]model.HTTPProxyRoute, 0, len(s.routes))
	for _, entry := range s.routes {
		r := entry.route
		r.LocalURL = fmt.Sprintf("%s/mcp/%s", base, r.Slug)
		r.RequestCount = entry.requestCount.Load()
		r.BlockedCount = entry.blockedCount.Load()
		routes = append(routes, r)
	}
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Slug < routes[j].Slug
	})

	return model.HTTPProxyStatus{
		Running:    s.running,
		ListenAddr: s.addr,
		BaseURL:    base,
		Routes:     routes,
	}
}

func (s *Server) handleMCPProxy(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/mcp/")
	parts := strings.SplitN(trimmed, "/", 2)
	slug := parts[0]
	extraPath := ""
	if len(parts) == 2 {
		extraPath = "/" + parts[1]
	}

	s.mu.RLock()
	entry, ok := s.routes[slug]
	s.mu.RUnlock()

	if !ok {
		http.Error(w, "unknown MCPGuard proxy route", http.StatusNotFound)
		return
	}
	if !entry.route.Enabled {
		http.Error(w, "MCPGuard proxy route is disabled", http.StatusServiceUnavailable)
		return
	}

	entry.requestCount.Add(1)
	start := time.Now()

	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024))
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	// Inspect JSON-RPC 2.0 POST bodies for tools/call enforcement
	var toolName string
	var rpcID json.RawMessage
	isToolCall := false
	forwardBody := bodyBytes

	if r.Method == http.MethodPost && len(bytes.TrimSpace(bodyBytes)) > 0 {
		var env struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		if json.Unmarshal(bodyBytes, &env) == nil && env.Method == "tools/call" && s.cp != nil {
			isToolCall = true
			rpcID = env.ID
			var params struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			_ = json.Unmarshal(env.Params, &params)
			toolName = params.Name
			argsStr := string(params.Arguments)
			if argsStr == "" {
				argsStr = "{}"
			}

			evalResp := s.cp.EvaluateToolCall(r.Context(), firewall.EvaluateRequest{
				RequestID:  strings.TrimSpace(string(env.ID)),
				ServerName: entry.route.ServerName,
				ToolName:   toolName,
				ArgsJSON:   argsStr,
			})

			if !evalResp.Allowed {
				entry.blockedCount.Add(1)
				writeJSONRPCError(w, env.ID, -32001, fmt.Sprintf("[MCPGuard HTTP Firewall Blocked] %s (%s)", evalResp.Reason, evalResp.RuleID))
				return
			}

			if len(evalResp.DLPHits) > 0 && evalResp.RedactedArgs != "" {
				if rewritten, ok := rewriteArgs(bodyBytes, evalResp.RedactedArgs); ok {
					forwardBody = rewritten
				}
			}
		}
	}

	// Build upstream target URL
	targetURL := *entry.upstream
	if extraPath != "" {
		targetURL.Path = strings.TrimRight(targetURL.Path, "/") + extraPath
	}
	if r.URL.RawQuery != "" {
		targetURL.RawQuery = r.URL.RawQuery
	}

	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), bytes.NewReader(forwardBody))
	if err != nil {
		http.Error(w, "failed to construct upstream request", http.StatusBadGateway)
		return
	}

	// Copy safe headers
	for k, vals := range r.Header {
		lk := strings.ToLower(k)
		if lk == "host" || lk == "content-length" || lk == "connection" {
			continue
		}
		for _, v := range vals {
			upReq.Header.Add(k, v)
		}
	}

	upResp, err := s.client.Do(upReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream MCP server error: %v", err), http.StatusBadGateway)
		return
	}
	defer upResp.Body.Close()

	ct := strings.ToLower(upResp.Header.Get("Content-Type"))

	// Streaming SSE (GET /sse) passthrough with flush support
	if r.Method == http.MethodGet && strings.Contains(ct, "text/event-stream") {
		copyHeaders(w.Header(), upResp.Header)
		w.WriteHeader(upResp.StatusCode)
		flusher, canFlush := w.(http.Flusher)
		buf := make([]byte, 4096)
		for {
			n, rErr := upResp.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				if canFlush {
					flusher.Flush()
				}
			}
			if rErr != nil {
				return
			}
		}
	}

	respBytes, err := io.ReadAll(io.LimitReader(upResp.Body, 4*1024*1024))
	if err != nil {
		http.Error(w, "failed to read upstream response", http.StatusBadGateway)
		return
	}

	// Inspect tools/call responses for DLP secrets and Indirect Prompt Injection
	if isToolCall && s.cp != nil {
		insp := s.cp.InspectToolResponse(firewall.ResponseInspectRequest{
			RequestID:    strings.TrimSpace(string(rpcID)),
			ServerName:   entry.route.ServerName,
			ToolName:     toolName,
			ResponseJSON: string(respBytes),
			LatencyMs:    time.Since(start).Milliseconds(),
		})
		if insp.Blocked {
			entry.blockedCount.Add(1)
			writeJSONRPCError(w, rpcID, -32002, fmt.Sprintf("[MCPGuard Indirect Prompt Injection Blocked] %s", insp.InjectionEvidence))
			return
		}
		if len(insp.DLPHits) > 0 && insp.RedactedResponse != "" {
			respBytes = []byte(insp.RedactedResponse)
		}
	}

	copyHeaders(w.Header(), upResp.Header)
	w.Header().Del("Content-Length")
	w.WriteHeader(upResp.StatusCode)
	_, _ = w.Write(respBytes)
}

func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func writeJSONRPCError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]interface{}{
			"code":    code,
			"message": msg,
		},
	})
}

func rewriteArgs(raw []byte, redactedArgs string) ([]byte, bool) {
	var root map[string]interface{}
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, false
	}
	params, ok := root["params"].(map[string]interface{})
	if !ok {
		return nil, false
	}
	var parsed interface{}
	if err := json.Unmarshal([]byte(redactedArgs), &parsed); err != nil {
		return nil, false
	}
	params["arguments"] = parsed
	root["params"] = params
	out, err := json.Marshal(root)
	if err != nil {
		return nil, false
	}
	return out, true
}

func sanitizeSlug(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = slugSanitizer.ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}
