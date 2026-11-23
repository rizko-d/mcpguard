package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"mcpguard/internal/firewall"
	"mcpguard/internal/policy"
	"mcpguard/internal/storage"
)

type rpcEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

type pendingCall struct {
	toolName  string
	startedAt time.Time
}

type proxyClient struct {
	serverName     string
	controlURL     string
	token          string
	httpClient     *http.Client
	fallbackEngine *policy.Engine
}

func main() {
	serverName, controlURL, targetCmd, targetArgs, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcpguard-proxy: %v\nUsage: mcpguard-proxy --server <name> [--control-url <url>] -- <command> [args...]\n", err)
		os.Exit(2)
	}

	token := ""
	if meta, mErr := firewall.LoadIPCMetadata(); mErr == nil {
		if controlURL == "" {
			controlURL = meta.ControlURL
		}
		token = meta.Token
	}
	if controlURL == "" {
		controlURL = "http://" + firewall.DefaultControlAddr
	}

	fallbackEng := loadFallbackPolicy()

	pc := &proxyClient{
		serverName:     serverName,
		controlURL:     strings.TrimRight(controlURL, "/"),
		token:          token,
		httpClient:     &http.Client{Timeout: 75 * time.Second},
		fallbackEngine: fallbackEng,
	}

	cmd := exec.Command(targetCmd, targetArgs...)
	cmd.Env = os.Environ()
	cmd.Stderr = os.Stderr

	childStdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcpguard-proxy: stdin pipe: %v\n", err)
		os.Exit(1)
	}
	childStdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcpguard-proxy: stdout pipe: %v\n", err)
		os.Exit(1)
	}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "mcpguard-proxy: failed to start %q: %v\n", targetCmd, err)
		os.Exit(1)
	}

	var stdoutMu sync.Mutex
	writeClient := func(line []byte) {
		stdoutMu.Lock()
		defer stdoutMu.Unlock()
		if !bytes.HasSuffix(line, []byte("\n")) {
			line = append(line, '\n')
		}
		_, _ = os.Stdout.Write(line)
	}

	var pendingMu sync.Mutex
	pendingCalls := make(map[string]pendingCall)

	// Goroutine 1: Server -> Client (inspect responses for DLP & Indirect Prompt Injection)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		reader := bufio.NewReaderSize(childStdout, 2*1024*1024)
		for {
			line, rErr := reader.ReadBytes('\n')
			if len(line) > 0 {
				trimmed := bytes.TrimSpace(line)
				if len(trimmed) > 0 && trimmed[0] == '{' {
					var env rpcEnvelope
					if uErr := json.Unmarshal(trimmed, &env); uErr == nil && len(env.ID) > 0 {
						idKey := strings.TrimSpace(string(env.ID))
						pendingMu.Lock()
						call, isToolResp := pendingCalls[idKey]
						if isToolResp {
							delete(pendingCalls, idKey)
						}
						pendingMu.Unlock()

						if isToolResp {
							res := pc.inspectResponse(firewall.ResponseInspectRequest{
								RequestID:    idKey,
								ServerName:   pc.serverName,
								ToolName:     call.toolName,
								ResponseJSON: string(trimmed),
								LatencyMs:    time.Since(call.startedAt).Milliseconds(),
							})
							if res.Blocked {
								writeClient(buildRPCError(env.ID, -32002,
									fmt.Sprintf("[MCPGuard Indirect Prompt Injection Blocked] Suspicious directive detected in %q response: %s", call.toolName, res.InjectionEvidence)))
								continue
							}
							if len(res.DLPHits) > 0 && res.RedactedResponse != "" {
								writeClient([]byte(res.RedactedResponse))
								continue
							}
						}
					}
				}
				writeClient(line)
			}
			if rErr != nil {
				if rErr != io.EOF {
					fmt.Fprintf(os.Stderr, "mcpguard-proxy: child stdout error: %v\n", rErr)
				}
				return
			}
		}
	}()

	// Main Loop: Client -> Server (enforce Policy Engine & HITL Gate on tools/call)
	stdinReader := bufio.NewReaderSize(os.Stdin, 2*1024*1024)
	for {
		line, rErr := stdinReader.ReadBytes('\n')
		if len(line) > 0 {
			trimmed := bytes.TrimSpace(line)
			forwardLine := line

			if len(trimmed) > 0 && trimmed[0] == '{' {
				var env rpcEnvelope
				if uErr := json.Unmarshal(trimmed, &env); uErr == nil && env.Method != "" {
					idKey := strings.TrimSpace(string(env.ID))
					if env.Method == "tools/call" {
						var params struct {
							Name      string          `json:"name"`
							Arguments json.RawMessage `json:"arguments"`
						}
						_ = json.Unmarshal(env.Params, &params)
						argsStr := string(params.Arguments)
						if argsStr == "" {
							argsStr = "{}"
						}

						evalResp := pc.evaluate(firewall.EvaluateRequest{
							RequestID:  idKey,
							ServerName: pc.serverName,
							ToolName:   params.Name,
							ArgsJSON:   argsStr,
						})

						if !evalResp.Allowed {
							writeClient(buildRPCError(env.ID, -32001,
								fmt.Sprintf("[MCPGuard Firewall Blocked] %s (%s)", evalResp.Reason, evalResp.RuleID)))
							if rErr != nil {
								break
							}
							continue
						}

						if len(evalResp.DLPHits) > 0 && evalResp.RedactedArgs != "" {
							if rewritten, ok := rewriteToolCallArgs(trimmed, evalResp.RedactedArgs); ok {
								forwardLine = append(rewritten, '\n')
							}
						}

						if idKey != "" {
							pendingMu.Lock()
							pendingCalls[idKey] = pendingCall{
								toolName:  params.Name,
								startedAt: time.Now(),
							}
							pendingMu.Unlock()
						}
					} else {
						go pc.logMethod(firewall.LogMethodRequest{
							RequestID:  idKey,
							ServerName: pc.serverName,
							Direction:  "CLIENT_TO_SERVER",
							Method:     env.Method,
							Preview:    string(env.Params),
						})
					}
				}
			}

			if _, wErr := childStdin.Write(forwardLine); wErr != nil {
				break
			}
		}

		if rErr != nil {
			break
		}
	}

	_ = childStdin.Close()
	wg.Wait()
	_ = cmd.Wait()
}

func (pc *proxyClient) evaluate(req firewall.EvaluateRequest) firewall.EvaluateResponse {
	var resp firewall.EvaluateResponse
	if err := pc.postJSON("/v1/evaluate", req, &resp); err == nil {
		return resp
	}

	// Headless fallback: enforce local policy directly if MCPGuard Desktop is not running
	dec := pc.fallbackEngine.EvaluateToolCall(req.ServerName, req.ToolName, req.ArgsJSON)
	redacted, hits := pc.fallbackEngine.RedactSecrets(req.ArgsJSON)

	switch dec.Action {
	case policy.ActionAllow:
		return firewall.EvaluateResponse{
			Decision:     "ALLOW",
			Allowed:      true,
			RuleID:       dec.RuleID,
			RuleName:     dec.RuleName,
			Reason:       dec.Reason + " (offline fallback)",
			RedactedArgs: redacted,
			DLPHits:      hits,
		}
	case policy.ActionAsk:
		return firewall.EvaluateResponse{
			Decision: "DENY",
			Allowed:  false,
			RuleID:   dec.RuleID,
			RuleName: dec.RuleName,
			Reason:   "Tool requires HITL approval, but MCPGuard Desktop is offline (fail-closed DENY). Launch MCPGuard to approve.",
		}
	default:
		return firewall.EvaluateResponse{
			Decision: "DENY",
			Allowed:  false,
			RuleID:   dec.RuleID,
			RuleName: dec.RuleName,
			Reason:   dec.Reason + " (offline fallback)",
		}
	}
}

func (pc *proxyClient) inspectResponse(req firewall.ResponseInspectRequest) firewall.ResponseInspectResult {
	var res firewall.ResponseInspectResult
	if err := pc.postJSON("/v1/log-response", req, &res); err == nil {
		return res
	}
	redacted, hits := pc.fallbackEngine.RedactSecrets(req.ResponseJSON)
	inj, ev := pc.fallbackEngine.DetectIndirectInjection(redacted)
	return firewall.ResponseInspectResult{
		RedactedResponse:  redacted,
		DLPHits:           hits,
		InjectionDetected: inj,
		InjectionEvidence: ev,
		Blocked:           inj && pc.fallbackEngine.Config().BlockIndirectInjection,
	}
}

func (pc *proxyClient) logMethod(req firewall.LogMethodRequest) {
	var discard map[string]interface{}
	_ = pc.postJSON("/v1/log-event", req, &discard)
}

func (pc *proxyClient) postJSON(path string, body interface{}, out interface{}) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, pc.controlURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if pc.token != "" {
		req.Header.Set("Authorization", "Bearer "+pc.token)
	}
	resp, err := pc.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("control plane status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func loadFallbackPolicy() *policy.Engine {
	if dbPath, err := storage.DefaultDBPath(); err == nil {
		if st, sErr := storage.Open(dbPath); sErr == nil {
			defer st.Close()
			if saved, gErr := st.GetPolicyYAML(); gErr == nil && strings.TrimSpace(saved) != "" {
				if eng, pErr := policy.ParseYAML(saved); pErr == nil {
					return eng
				}
			}
		}
	}
	eng, _ := policy.ParseYAML(policy.DefaultYAML())
	return eng
}

func parseArgs(args []string) (serverName, controlURL, targetCmd string, targetArgs []string, err error) {
	sepIdx := -1
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			sepIdx = i
			break
		}
		switch args[i] {
		case "--server":
			if i+1 >= len(args) {
				return "", "", "", nil, fmt.Errorf("missing value for --server")
			}
			serverName = args[i+1]
			i++
		case "--control-url":
			if i+1 >= len(args) {
				return "", "", "", nil, fmt.Errorf("missing value for --control-url")
			}
			controlURL = args[i+1]
			i++
		}
	}
	if sepIdx == -1 || sepIdx+1 >= len(args) {
		return "", "", "", nil, fmt.Errorf("missing '-- <target-command>' separator")
	}
	targetCmd = args[sepIdx+1]
	targetArgs = args[sepIdx+2:]
	if serverName == "" {
		serverName = targetCmd
	}
	return serverName, controlURL, targetCmd, targetArgs, nil
}

func buildRPCError(id json.RawMessage, code int, message string) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	resp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
		},
	}
	b, _ := json.Marshal(resp)
	return append(b, '\n')
}

func rewriteToolCallArgs(rawLine []byte, redactedArgsJSON string) ([]byte, bool) {
	var msg map[string]interface{}
	if err := json.Unmarshal(rawLine, &msg); err != nil {
		return nil, false
	}
	params, ok := msg["params"].(map[string]interface{})
	if !ok {
		return nil, false
	}
	var parsedArgs interface{}
	if err := json.Unmarshal([]byte(redactedArgsJSON), &parsedArgs); err != nil {
		return nil, false
	}
	params["arguments"] = parsedArgs
	msg["params"] = params
	out, err := json.Marshal(msg)
	if err != nil {
		return nil, false
	}
	return out, true
}
