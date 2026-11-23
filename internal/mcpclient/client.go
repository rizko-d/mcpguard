package mcpclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"mcpguard/internal/model"
)

// InspectionResult captures the read-only metadata retrieved from a live MCP server.
type InspectionResult struct {
	ServerInfo      string
	ProtocolVersion string
	Tools           []model.MCPTool
	Resources       []model.MCPResource
	Prompts         []model.MCPPrompt
}

type jsonRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Inspect connects to an MCP server in strict read-only mode (initialize + list endpoints only; never invokes tools/call).
func Inspect(ctx context.Context, srv model.MCPServerConfig) (*InspectionResult, error) {
	if srv.Disabled {
		return nil, errors.New("server is marked disabled in configuration")
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
	}

	switch srv.Transport {
	case model.TransportStdio:
		return inspectStdio(ctx, srv)
	case model.TransportHTTP, model.TransportSSE:
		return inspectHTTP(ctx, srv)
	default:
		return nil, fmt.Errorf("unsupported transport: %s", srv.Transport)
	}
}

func inspectStdio(ctx context.Context, srv model.MCPServerConfig) (*InspectionResult, error) {
	if strings.TrimSpace(srv.Command) == "" {
		return nil, errors.New("missing command for stdio MCP server")
	}

	cmd := exec.CommandContext(ctx, srv.Command, srv.Args...)
	cmd.Env = os.Environ()
	for k, v := range srv.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("open stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("open stdout pipe: %w", err)
	}

	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("spawn MCP server %q: %w", srv.Command, err)
	}

	defer func() {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	reader := bufio.NewReaderSize(stdout, 1024*1024)

	call := func(id int, method string, params interface{}) (json.RawMessage, error) {
		req := jsonRPCRequest{
			JSONRPC: "2.0",
			ID:      id,
			Method:  method,
			Params:  params,
		}
		payload, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		if _, err := stdin.Write(append(payload, '\n')); err != nil {
			return nil, fmt.Errorf("write %s: %w", method, err)
		}

		type readOut struct {
			msg json.RawMessage
			err error
		}
		ch := make(chan readOut, 1)
		go func() {
			for {
				line, rErr := reader.ReadBytes('\n')
				if rErr != nil {
					ch <- readOut{err: rErr}
					return
				}
				trimmed := bytes.TrimSpace(line)
				if len(trimmed) == 0 || trimmed[0] != '{' {
					continue
				}
				var resp jsonRPCResponse
				if uErr := json.Unmarshal(trimmed, &resp); uErr != nil {
					continue
				}
				if !idMatches(resp.ID, id) {
					continue
				}
				if resp.Error != nil {
					ch <- readOut{err: fmt.Errorf("rpc error %d: %s", resp.Error.Code, resp.Error.Message)}
					return
				}
				ch <- readOut{msg: resp.Result}
				return
			}
		}()

		select {
		case <-ctx.Done():
			errMsg := strings.TrimSpace(stderrBuf.String())
			if len(errMsg) > 200 {
				errMsg = errMsg[:200] + "..."
			}
			if errMsg != "" {
				return nil, fmt.Errorf("timeout waiting for %s (stderr: %s)", method, errMsg)
			}
			return nil, fmt.Errorf("timeout waiting for %s", method)
		case out := <-ch:
			return out.msg, out.err
		}
	}

	notify := func(method string) {
		n := jsonRPCRequest{JSONRPC: "2.0", Method: method}
		if b, err := json.Marshal(n); err == nil {
			_, _ = stdin.Write(append(b, '\n'))
		}
	}

	initParams := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]string{
			"name":    "MCPGuard",
			"version": "0.1.0",
		},
	}

	initRaw, err := call(1, "initialize", initParams)
	if err != nil {
		return nil, fmt.Errorf("MCP initialize failed: %w", err)
	}

	result := parseInitialize(initRaw)
	notify("notifications/initialized")

	if toolsRaw, err := call(2, "tools/list", map[string]interface{}{}); err == nil {
		result.Tools = parseTools(toolsRaw)
	}
	if resRaw, err := call(3, "resources/list", map[string]interface{}{}); err == nil {
		result.Resources = parseResources(resRaw)
	}
	if promptsRaw, err := call(4, "prompts/list", map[string]interface{}{}); err == nil {
		result.Prompts = parsePrompts(promptsRaw)
	}

	return result, nil
}

func inspectHTTP(ctx context.Context, srv model.MCPServerConfig) (*InspectionResult, error) {
	if strings.TrimSpace(srv.URL) == "" {
		return nil, errors.New("missing URL for HTTP/SSE MCP server")
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	sessionID := ""

	postRPC := func(id int, method string, params interface{}) (json.RawMessage, error) {
		reqBody, err := json.Marshal(jsonRPCRequest{
			JSONRPC: "2.0",
			ID:      id,
			Method:  method,
			Params:  params,
		})
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, bytes.NewReader(reqBody))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if sessionID != "" {
			req.Header.Set("Mcp-Session-Id", sessionID)
		}
		for k, v := range srv.Headers {
			req.Header.Set(k, v)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
			sessionID = sid
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}

		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		if strings.Contains(ct, "text/event-stream") {
			return extractSSEJSONRPC(body, id)
		}

		var rpcResp jsonRPCResponse
		if err := json.Unmarshal(body, &rpcResp); err != nil {
			return nil, fmt.Errorf("decode JSON-RPC response: %w", err)
		}
		if rpcResp.Error != nil {
			return nil, fmt.Errorf("rpc error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
		}
		return rpcResp.Result, nil
	}

	initRaw, err := postRPC(1, "initialize", map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]interface{}{},
		"clientInfo":      map[string]string{"name": "MCPGuard", "version": "0.1.0"},
	})
	if err != nil {
		return nil, fmt.Errorf("HTTP MCP initialize failed: %w", err)
	}

	result := parseInitialize(initRaw)
	if toolsRaw, err := postRPC(2, "tools/list", map[string]interface{}{}); err == nil {
		result.Tools = parseTools(toolsRaw)
	}
	if resRaw, err := postRPC(3, "resources/list", map[string]interface{}{}); err == nil {
		result.Resources = parseResources(resRaw)
	}
	if promptsRaw, err := postRPC(4, "prompts/list", map[string]interface{}{}); err == nil {
		result.Prompts = parsePrompts(promptsRaw)
	}

	return result, nil
}

func extractSSEJSONRPC(body []byte, expectedID int) (json.RawMessage, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload[0] != '{' {
			continue
		}
		var rpcResp jsonRPCResponse
		if err := json.Unmarshal([]byte(payload), &rpcResp); err != nil {
			continue
		}
		if idMatches(rpcResp.ID, expectedID) {
			if rpcResp.Error != nil {
				return nil, fmt.Errorf("rpc error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
			}
			return rpcResp.Result, nil
		}
	}
	return nil, errors.New("no matching JSON-RPC payload found in SSE stream")
}

func idMatches(raw interface{}, expected int) bool {
	switch v := raw.(type) {
	case float64:
		return int(v) == expected
	case int:
		return v == expected
	case json.Number:
		n, err := v.Int64()
		return err == nil && int(n) == expected
	default:
		return false
	}
}

func parseInitialize(raw json.RawMessage) *InspectionResult {
	res := &InspectionResult{}
	var parsed struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(raw, &parsed); err == nil {
		res.ProtocolVersion = parsed.ProtocolVersion
		if parsed.ServerInfo.Name != "" {
			if parsed.ServerInfo.Version != "" {
				res.ServerInfo = parsed.ServerInfo.Name + " v" + parsed.ServerInfo.Version
			} else {
				res.ServerInfo = parsed.ServerInfo.Name
			}
		}
	}
	return res
}

func parseTools(raw json.RawMessage) []model.MCPTool {
	var parsed struct {
		Tools []model.MCPTool `json:"tools"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil
	}
	for i := range parsed.Tools {
		parsed.Tools[i].SchemaHash = ComputeToolHash(parsed.Tools[i])
	}
	sort.Slice(parsed.Tools, func(i, j int) bool {
		return parsed.Tools[i].Name < parsed.Tools[j].Name
	})
	return parsed.Tools
}

func parseResources(raw json.RawMessage) []model.MCPResource {
	var parsed struct {
		Resources []model.MCPResource `json:"resources"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil
	}
	return parsed.Resources
}

func parsePrompts(raw json.RawMessage) []model.MCPPrompt {
	var parsed struct {
		Prompts []model.MCPPrompt `json:"prompts"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil
	}
	return parsed.Prompts
}

// ComputeToolHash produces a deterministic SHA-256 fingerprint of a tool's name, description, and input schema.
func ComputeToolHash(tool model.MCPTool) string {
	canonical := struct {
		Name        string                 `json:"name"`
		Description string                 `json:"description"`
		InputSchema map[string]interface{} `json:"inputSchema,omitempty"`
	}{
		Name:        tool.Name,
		Description: tool.Description,
		InputSchema: tool.InputSchema,
	}
	b, _ := json.Marshal(canonical)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ComputeServerSchemaHash computes an aggregate SHA-256 fingerprint across all tools of an MCP server.
func ComputeServerSchemaHash(tools []model.MCPTool) string {
	if len(tools) == 0 {
		return ""
	}
	copied := make([]model.MCPTool, len(tools))
	copy(copied, tools)
	sort.Slice(copied, func(i, j int) bool {
		return copied[i].Name < copied[j].Name
	})
	var sb strings.Builder
	for _, t := range copied {
		h := t.SchemaHash
		if h == "" {
			h = ComputeToolHash(t)
		}
		sb.WriteString(t.Name)
		sb.WriteByte(':')
		sb.WriteString(h)
		sb.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}
