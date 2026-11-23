package firewall

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"mcpguard/internal/configpatch"
	"mcpguard/internal/model"
	"mcpguard/internal/policy"
	"mcpguard/internal/storage"
)

const DefaultControlAddr = "127.0.0.1:43771"

// Callbacks decouples the Firewall Control Plane from the Wails GUI runtime.
type Callbacks struct {
	OnTraffic          func(ev model.TrafficEvent)
	OnApprovalNeeded   func(req model.PendingApproval)
	OnApprovalResolved func(id string)
}

// EvaluateRequest is sent by mcpguard-proxy before forwarding a tools/call JSON-RPC frame.
type EvaluateRequest struct {
	RequestID  string `json:"requestId"`
	ServerName string `json:"serverName"`
	ToolName   string `json:"toolName"`
	ArgsJSON   string `json:"argsJson"`
}

// EvaluateResponse is returned to mcpguard-proxy with the policy / HITL decision and DLP-redacted args.
type EvaluateResponse struct {
	Decision     string   `json:"decision"` // ALLOW, DENY, APPROVED_ONCE, APPROVED_SESSION, DENIED_USER, TIMEOUT
	Allowed      bool     `json:"allowed"`
	RuleID       string   `json:"ruleId,omitempty"`
	RuleName     string   `json:"ruleName,omitempty"`
	Reason       string   `json:"reason,omitempty"`
	RedactedArgs string   `json:"redactedArgs,omitempty"`
	DLPHits      []string `json:"dlpHits,omitempty"`
}

// ResponseInspectRequest is sent by mcpguard-proxy when a tool response returns from the MCP server.
type ResponseInspectRequest struct {
	RequestID    string `json:"requestId"`
	ServerName   string `json:"serverName"`
	ToolName     string `json:"toolName"`
	ResponseJSON string `json:"responseJson"`
	LatencyMs    int64  `json:"latencyMs"`
}

// ResponseInspectResult is returned to mcpguard-proxy after DLP & indirect prompt injection scanning.
type ResponseInspectResult struct {
	RedactedResponse  string   `json:"redactedResponse"`
	DLPHits           []string `json:"dlpHits,omitempty"`
	InjectionDetected bool     `json:"injectionDetected"`
	InjectionEvidence string   `json:"injectionEvidence,omitempty"`
	Blocked           bool     `json:"blocked"`
}

// LogMethodRequest records non-tools/call JSON-RPC traffic (initialize, tools/list, etc.).
type LogMethodRequest struct {
	RequestID  string `json:"requestId"`
	ServerName string `json:"serverName"`
	Direction  string `json:"direction"`
	Method     string `json:"method"`
	Preview    string `json:"preview"`
}

type approvalWaiter struct {
	pending model.PendingApproval
	ch      chan string // "APPROVE_ONCE", "APPROVE_SESSION", "DENY"
}

// ControlPlane runs the local loopback IPC server, evaluates policies, and coordinates HITL approvals.
type ControlPlane struct {
	mu               sync.RWMutex
	store            *storage.Store
	engine           *policy.Engine
	policyYAML       string
	callbacks        Callbacks
	token            string
	addr             string
	server           *http.Server
	running          bool
	sessionApprovals map[string]bool // key: serverName + "::" + toolName
	pending          map[string]*approvalWaiter
}

// NewControlPlane initializes the firewall control plane with persisted or default YAML policy.
func NewControlPlane(store *storage.Store, callbacks Callbacks) (*ControlPlane, error) {
	yamlStr := policy.DefaultYAML()
	if store != nil {
		if saved, err := store.GetPolicyYAML(); err == nil && strings.TrimSpace(saved) != "" {
			yamlStr = saved
		} else {
			_ = store.SavePolicyYAML(yamlStr)
		}
	}

	eng, err := policy.ParseYAML(yamlStr)
	if err != nil {
		// Recover cleanly to default YAML if corrupted
		yamlStr = policy.DefaultYAML()
		eng, _ = policy.ParseYAML(yamlStr)
	}

	tok, err := loadOrCreateToken()
	if err != nil {
		tok = randomHex(16)
	}

	return &ControlPlane{
		store:            store,
		engine:           eng,
		policyYAML:       yamlStr,
		callbacks:        callbacks,
		token:            tok,
		addr:             DefaultControlAddr,
		sessionApprovals: make(map[string]bool),
		pending:          make(map[string]*approvalWaiter),
	}, nil
}

// Start binds the loopback HTTP IPC server on 127.0.0.1:43771 (or an ephemeral port if preferred).
func (cp *ControlPlane) Start(listenAddr string) error {
	if listenAddr == "" {
		listenAddr = DefaultControlAddr
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		// Fall back to ephemeral loopback port if default is occupied
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("bind firewall IPC listener: %w", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", cp.handleHealth)
	mux.HandleFunc("/v1/evaluate", cp.requireAuth(cp.handleEvaluate))
	mux.HandleFunc("/v1/log-response", cp.requireAuth(cp.handleLogResponse))
	mux.HandleFunc("/v1/log-event", cp.requireAuth(cp.handleLogEvent))

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	cp.mu.Lock()
	cp.addr = ln.Addr().String()
	cp.server = srv
	cp.running = true
	cp.mu.Unlock()

	// Write current control URL alongside token so mcpguard-proxy can auto-discover it
	_ = saveControlMetadata(cp.ControlURL(), cp.token)

	go func() {
		_ = srv.Serve(ln)
	}()
	return nil
}

// Stop gracefully shuts down the local IPC HTTP server.
func (cp *ControlPlane) Stop(ctx context.Context) error {
	cp.mu.Lock()
	srv := cp.server
	cp.running = false
	// Release any waiting HITL goroutines as DENY
	for id, w := range cp.pending {
		select {
		case w.ch <- "DENY":
		default:
		}
		delete(cp.pending, id)
	}
	cp.mu.Unlock()

	if srv != nil {
		return srv.Shutdown(ctx)
	}
	return nil
}

// ControlURL returns the loopback base URL (e.g. http://127.0.0.1:43771).
func (cp *ControlPlane) ControlURL() string {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return "http://" + cp.addr
}

// Token returns the local IPC bearer token.
func (cp *ControlPlane) Token() string {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.token
}

// PolicyYAML returns the active YAML policy document.
func (cp *ControlPlane) PolicyYAML() string {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.policyYAML
}

// Engine returns the currently active compiled policy engine.
func (cp *ControlPlane) Engine() *policy.Engine {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.engine
}

// UpdatePolicy validates, activates, and persists a new YAML policy document.
func (cp *ControlPlane) UpdatePolicy(rawYAML string) error {
	eng, err := policy.ParseYAML(rawYAML)
	if err != nil {
		return err
	}
	if cp.store != nil {
		if err := cp.store.SavePolicyYAML(rawYAML); err != nil {
			return err
		}
	}
	cp.mu.Lock()
	cp.engine = eng
	cp.policyYAML = rawYAML
	cp.mu.Unlock()
	return nil
}

// ResetPolicy restores the default Phase 2 YAML policy.
func (cp *ControlPlane) ResetPolicy() (string, error) {
	def := policy.DefaultYAML()
	if err := cp.UpdatePolicy(def); err != nil {
		return "", err
	}
	return def, nil
}

// ClearSessionApprovals revokes all cached session-scoped HITL approvals.
func (cp *ControlPlane) ClearSessionApprovals() {
	cp.mu.Lock()
	cp.sessionApprovals = make(map[string]bool)
	cp.mu.Unlock()
}

// Status returns a live snapshot of the Runtime Firewall Control Plane.
func (cp *ControlPlane) Status() model.FirewallStatus {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	proxyPath, proxyFound := configpatch.ResolveProxyBinary()

	sessions := make([]string, 0, len(cp.sessionApprovals))
	for k := range cp.sessionApprovals {
		sessions = append(sessions, k)
	}
	sort.Strings(sessions)

	pendings := make([]model.PendingApproval, 0, len(cp.pending))
	for _, w := range cp.pending {
		pendings = append(pendings, w.pending)
	}
	sort.Slice(pendings, func(i, j int) bool {
		return pendings[i].RequestedAt < pendings[j].RequestedAt
	})

	cfg := cp.engine.Config()
	return model.FirewallStatus{
		Running:          cp.running,
		ControlURL:       "http://" + cp.addr,
		ProxyBinaryPath:  proxyPath,
		ProxyBinaryFound: proxyFound,
		ActiveRulesCount: cp.engine.ActiveRuleCount(),
		DLPEnabled:       cfg.DLPRedactSecrets,
		InjectionGuard:   cfg.BlockIndirectInjection,
		SessionApprovals: sessions,
		PendingApprovals: pendings,
	}
}

// EvaluateToolCall executes policy matching, DLP redaction, and (when required) blocking HITL approval.
func (cp *ControlPlane) EvaluateToolCall(ctx context.Context, req EvaluateRequest) EvaluateResponse {
	start := time.Now()
	if req.RequestID == "" {
		req.RequestID = "req-" + randomHex(6)
	}

	cp.mu.RLock()
	eng := cp.engine
	sessionKey := req.ServerName + "::" + req.ToolName
	sessionApproved := cp.sessionApprovals[sessionKey]
	cp.mu.RUnlock()

	decision := eng.EvaluateToolCall(req.ServerName, req.ToolName, req.ArgsJSON)
	redactedArgs, dlpHits := eng.RedactSecrets(req.ArgsJSON)

	resp := EvaluateResponse{
		RuleID:       decision.RuleID,
		RuleName:     decision.RuleName,
		Reason:       decision.Reason,
		RedactedArgs: redactedArgs,
		DLPHits:      dlpHits,
	}

	switch decision.Action {
	case policy.ActionDeny:
		resp.Decision = "DENY"
		resp.Allowed = false
	case policy.ActionAllow:
		resp.Decision = "ALLOW"
		resp.Allowed = true
	case policy.ActionAsk:
		if sessionApproved {
			resp.Decision = "APPROVED_SESSION"
			resp.Allowed = true
			resp.Reason = "Auto-approved via active session grant (" + sessionKey + ")."
		} else {
			verdict := cp.requestHITLApproval(ctx, req, redactedArgs, decision, eng.Config().ApprovalTimeoutSec)
			switch verdict {
			case "APPROVE_ONCE":
				resp.Decision = "APPROVED_ONCE"
				resp.Allowed = true
				resp.Reason = "Approved once by user via HITL gate."
			case "APPROVE_SESSION":
				cp.mu.Lock()
				cp.sessionApprovals[sessionKey] = true
				cp.mu.Unlock()
				resp.Decision = "APPROVED_SESSION"
				resp.Allowed = true
				resp.Reason = "Approved for session by user via HITL gate."
			case "TIMEOUT":
				resp.Decision = "TIMEOUT"
				resp.Allowed = false
				resp.Reason = "HITL approval timed out (fail-closed DENY)."
			default:
				resp.Decision = "DENIED_USER"
				resp.Allowed = false
				resp.Reason = "Explicitly denied by user via HITL gate."
			}
		}
	}

	ev := model.TrafficEvent{
		RequestID:   req.RequestID,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		ServerName:  req.ServerName,
		Direction:   "CLIENT_TO_SERVER",
		Method:      "tools/call",
		ToolName:    req.ToolName,
		ArgsPreview: truncate(redactedArgs, 1000),
		Decision:    resp.Decision,
		RuleID:      resp.RuleID,
		RuleName:    resp.RuleName,
		Reason:      resp.Reason,
		Severity:    decision.Severity,
		DLPHits:     dlpHits,
		LatencyMs:   time.Since(start).Milliseconds(),
	}
	cp.persistAndEmit(ev)
	return resp
}

// InspectToolResponse scans an MCP tool response for leaked secrets (DLP) and indirect prompt injection.
func (cp *ControlPlane) InspectToolResponse(req ResponseInspectRequest) ResponseInspectResult {
	cp.mu.RLock()
	eng := cp.engine
	cp.mu.RUnlock()

	redacted, dlpHits := eng.RedactSecrets(req.ResponseJSON)
	injDetected, injEvidence := eng.DetectIndirectInjection(redacted)

	decision := "ALLOW"
	reason := "Tool response inspected cleanly."
	sev := model.SeverityInfo
	blocked := false

	if injDetected {
		decision = "DENY"
		sev = model.SeverityCritical
		reason = "Indirect Prompt Injection detected in MCP tool response."
		blocked = eng.Config().BlockIndirectInjection
	} else if len(dlpHits) > 0 {
		decision = "REDACTED"
		sev = model.SeverityHigh
		reason = fmt.Sprintf("DLP redacted %d secret category(s) from tool response: %s", len(dlpHits), strings.Join(dlpHits, ", "))
	}

	ev := model.TrafficEvent{
		RequestID:         req.RequestID,
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
		ServerName:        req.ServerName,
		Direction:         "SERVER_TO_CLIENT",
		Method:            "tools/call:response",
		ToolName:          req.ToolName,
		ResponsePreview:   truncate(redacted, 1000),
		Decision:          decision,
		RuleID:            "DLP-INJ-GUARD",
		RuleName:          "Response DLP & Injection Guard",
		Reason:            reason,
		Severity:          sev,
		DLPHits:           dlpHits,
		InjectionDetected: injDetected,
		InjectionEvidence: truncate(injEvidence, 240),
		LatencyMs:         req.LatencyMs,
	}
	cp.persistAndEmit(ev)

	return ResponseInspectResult{
		RedactedResponse:  redacted,
		DLPHits:           dlpHits,
		InjectionDetected: injDetected,
		InjectionEvidence: injEvidence,
		Blocked:           blocked,
	}
}

// ResolveApproval delivers a user's HITL decision ("APPROVE_ONCE", "APPROVE_SESSION", or "DENY") to a waiting call.
func (cp *ControlPlane) ResolveApproval(approvalID, decision string) error {
	cp.mu.Lock()
	waiter, ok := cp.pending[approvalID]
	if ok {
		delete(cp.pending, approvalID)
	}
	cp.mu.Unlock()

	if !ok {
		return fmt.Errorf("approval request %q not found or already expired", approvalID)
	}

	decision = strings.ToUpper(strings.TrimSpace(decision))
	if decision != "APPROVE_ONCE" && decision != "APPROVE_SESSION" {
		decision = "DENY"
	}

	select {
	case waiter.ch <- decision:
	default:
	}

	if cp.callbacks.OnApprovalResolved != nil {
		cp.callbacks.OnApprovalResolved(approvalID)
	}
	return nil
}

func (cp *ControlPlane) requestHITLApproval(ctx context.Context, req EvaluateRequest, redactedArgs string, dec policy.Decision, timeoutSec int) string {
	id := "hitl-" + randomHex(6)
	now := time.Now().UTC()
	if timeoutSec <= 0 {
		timeoutSec = 60
	}
	expires := now.Add(time.Duration(timeoutSec) * time.Second)

	pending := model.PendingApproval{
		ID:          id,
		ServerName:  req.ServerName,
		ToolName:    req.ToolName,
		ArgsJSON:    redactedArgs,
		RuleID:      dec.RuleID,
		RuleName:    dec.RuleName,
		Severity:    dec.Severity,
		Reason:      dec.Reason,
		RequestedAt: now.Format(time.RFC3339),
		ExpiresAt:   expires.Format(time.RFC3339),
	}

	waiter := &approvalWaiter{
		pending: pending,
		ch:      make(chan string, 1),
	}

	cp.mu.Lock()
	cp.pending[id] = waiter
	cp.mu.Unlock()

	if cp.callbacks.OnApprovalNeeded != nil {
		cp.callbacks.OnApprovalNeeded(pending)
	}

	timer := time.NewTimer(time.Duration(timeoutSec) * time.Second)
	defer timer.Stop()

	select {
	case verdict := <-waiter.ch:
		return verdict
	case <-timer.C:
		cp.mu.Lock()
		delete(cp.pending, id)
		cp.mu.Unlock()
		if cp.callbacks.OnApprovalResolved != nil {
			cp.callbacks.OnApprovalResolved(id)
		}
		return "TIMEOUT"
	case <-ctx.Done():
		cp.mu.Lock()
		delete(cp.pending, id)
		cp.mu.Unlock()
		if cp.callbacks.OnApprovalResolved != nil {
			cp.callbacks.OnApprovalResolved(id)
		}
		return "DENY"
	}
}

func (cp *ControlPlane) persistAndEmit(ev model.TrafficEvent) {
	if cp.store != nil {
		if id, err := cp.store.RecordTrafficEvent(ev); err == nil {
			ev.ID = id
		}
	}
	if cp.callbacks.OnTraffic != nil {
		cp.callbacks.OnTraffic(ev)
	}
}

// HTTP handlers for local mcpguard-proxy IPC
func (cp *ControlPlane) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(auth), []byte(cp.Token())) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (cp *ControlPlane) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "service": "mcpguard-control-plane"})
}

func (cp *ControlPlane) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	var req EvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	resp := cp.EvaluateToolCall(r.Context(), req)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (cp *ControlPlane) handleLogResponse(w http.ResponseWriter, r *http.Request) {
	var req ResponseInspectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	res := cp.InspectToolResponse(req)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func (cp *ControlPlane) handleLogEvent(w http.ResponseWriter, r *http.Request) {
	var req LogMethodRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	ev := model.TrafficEvent{
		RequestID:   req.RequestID,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		ServerName:  req.ServerName,
		Direction:   req.Direction,
		Method:      req.Method,
		ArgsPreview: truncate(req.Preview, 600),
		Decision:    "LOGGED",
		Severity:    model.SeverityInfo,
	}
	cp.persistAndEmit(ev)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// IPCMetadata is stored in the local user config dir so mcpguard-proxy can authenticate cleanly.
type IPCMetadata struct {
	ControlURL string `json:"controlUrl"`
	Token      string `json:"token"`
}

// MetadataPath returns the local file path storing the IPC URL and bearer token.
func MetadataPath() (string, error) {
	dbPath, err := storage.DefaultDBPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(dbPath), "ipc.json"), nil
}

// LoadIPCMetadata reads the local Control Plane URL and bearer token for mcpguard-proxy.
func LoadIPCMetadata() (*IPCMetadata, error) {
	p, err := MetadataPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var m IPCMetadata
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m.Token == "" {
		return nil, errors.New("empty ipc token")
	}
	return &m, nil
}

func loadOrCreateToken() (string, error) {
	if existing, err := LoadIPCMetadata(); err == nil && existing.Token != "" {
		return existing.Token, nil
	}
	return randomHex(24), nil
}

func saveControlMetadata(controlURL, token string) error {
	p, err := MetadataPath()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(IPCMetadata{
		ControlURL: controlURL,
		Token:      token,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...[truncated]"
}
