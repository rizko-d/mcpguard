package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"mcpguard/internal/discovery"
	"mcpguard/internal/mcpclient"
	"mcpguard/internal/model"
)

var (
	// Secret detection patterns
	secretPatterns = []struct {
		Name  string
		Regex *regexp.Regexp
	}{
		{"OpenAI API Key", regexp.MustCompile(`\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}\b`)},
		{"Anthropic API Key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`)},
		{"GitHub Token", regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b`)},
		{"AWS Access Key ID", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
		{"Slack Token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z\-]{10,}\b`)},
		{"Google API Key", regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
		{"Private Key PEM", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)},
		{"JWT Token", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`)},
		{"Bearer Secret", regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9_\-\.]{20,}\b`)},
	}

	// Tool poisoning & prompt injection patterns
	hiddenTagRegex = regexp.MustCompile(`(?i)<\s*/?\s*(?:IMPORTANT|SYSTEM|INSTRUCTIONS?|HIDDEN|SECRET|ADMIN|OVERRIDE|PROMPT|TOOL_CALL|INTERNAL)\b[^>]*>|<!--[\s\S]*?-->`)

	stealthDirectiveRegex = regexp.MustCompile(`(?i)\b(?:ignore (?:all )?(?:previous|prior|above) instructions|do not (?:tell|inform|mention|notify|show|alert) (?:the )?user|without (?:telling|informing|notifying) (?:the )?user|hide this from (?:the )?user|silently (?:send|read|exfiltrate|execute|forward|pass|include)|never mention this|before calling this tool,?\s*(?:first\s+)?(?:read|fetch|pass|include)|override (?:system|safety|security) (?:prompt|instructions|rules)|disregard (?:previous|prior|safety))\b`)

	sensitiveFileExfilRegex = regexp.MustCompile(`(?i)(?:~/\.ssh|/\.ssh/|id_rsa|id_ed25519|authorized_keys|~/\.aws|/\.aws/credentials|/etc/passwd|/etc/shadow|\.env\b|claude_desktop_config\.json|mcp_config\.json|mcp\.json|\.npmrc|\.pypirc|\.git-credentials|keychain|browser\s+cookies|crypto\s+wallet|seed\s+phrase)`)

	exfilCommandRegex = regexp.MustCompile(`(?i)\b(?:curl\s+-[a-zA-Z]*\s*https?://|wget\s+https?://|nc\s+-e|bash\s+-i|powershell\s+-enc|base64\s+(?:-w0|-d)|exfiltrat|sidenote\s+parameter|pass\s+(?:the\s+)?contents?\s+(?:of|into))\b`)

	base64BlobRegex = regexp.MustCompile(`\b[A-Za-z0-9+/]{64,}={0,2}\b`)

	// Cross-server / cross-tool hijacking indicators in descriptions
	crossToolManipRegex = regexp.MustCompile(`(?i)\b(?:whenever (?:the user|you) (?:call|use|invoke)s?\s+[a-zA-Z0-9_\-]+|instead of calling|always (?:also )?(?:call|invoke|trigger|forward to)|modify the behavior of|intercept calls to|re-?route (?:all )?(?:emails?|messages?|requests?))\b`)

	// Dangerous capability keywords
	shellCapRegex = regexp.MustCompile(`(?i)(?:^|[_\-\s])(?:exec|execute|shell|bash|sh|cmd|powershell|terminal|run_command|run_script|spawn|eval|system_command)(?:$|[_\-\s])`)
	fsWriteRegex  = regexp.MustCompile(`(?i)(?:^|[_\-\s])(?:write_file|delete_file|remove_file|unlink|rmdir|rm|edit_file|modify_file|overwrite|chmod|chown|move_file)(?:$|[_\-\s])`)
	netCapRegex   = regexp.MustCompile(`(?i)(?:^|[_\-\s])(?:http_request|fetch_url|webhook|send_email|post_message|upload|download_file|curl|request)(?:$|[_\-\s])`)
)

// AuditServer performs static config auditing, tool poisoning analysis, capability scoring,
// and baseline drift (Rug Pull) detection for a single MCP server.
func AuditServer(
	srv model.MCPServerConfig,
	tools []model.MCPTool,
	resources []model.MCPResource,
	prompts []model.MCPPrompt,
	baseline *model.BaselineRecord,
) []model.Finding {
	var findings []model.Finding

	// Ensure every tool has its canonical SHA-256 hash computed
	for i := range tools {
		if tools[i].SchemaHash == "" {
			tools[i].SchemaHash = mcpclient.ComputeToolHash(tools[i])
		}
	}

	// 1. Configuration, Secrets & Supply Chain Hygiene
	findings = append(findings, auditConfigSecrets(srv)...)
	findings = append(findings, auditSupplyChain(srv)...)
	findings = append(findings, auditTransport(srv)...)

	// 2. Tool Poisoning, Unicode Obfuscation & Capabilities
	for _, tool := range tools {
		findings = append(findings, auditToolSecurity(srv.ServerName, tool)...)
	}

	// 3. Resources & Prompts Poisoning
	for _, res := range resources {
		target := fmt.Sprintf("%s/resource:%s", srv.ServerName, res.Name)
		findings = append(findings, scanTextForPoisoning(target, res.Description+" "+res.URI)...)
	}
	for _, pr := range prompts {
		target := fmt.Sprintf("%s/prompt:%s", srv.ServerName, pr.Name)
		findings = append(findings, scanTextForPoisoning(target, pr.Description)...)
	}

	// 4. Rug Pull / Schema Drift Analysis against Baseline
	if baseline != nil && len(tools) > 0 {
		driftFindings, _ := CompareBaseline(srv.ServerName, tools, baseline)
		findings = append(findings, driftFindings...)
	}

	return dedupeAndSortFindings(findings)
}

// CompareBaseline compares current tools against a previously approved baseline snapshot.
func CompareBaseline(serverName string, currentTools []model.MCPTool, baseline *model.BaselineRecord) ([]model.Finding, []model.DriftChange) {
	if baseline == nil {
		return nil, nil
	}

	baseMap := make(map[string]model.MCPTool, len(baseline.Tools))
	for _, t := range baseline.Tools {
		if t.SchemaHash == "" {
			t.SchemaHash = mcpclient.ComputeToolHash(t)
		}
		baseMap[t.Name] = t
	}

	currMap := make(map[string]model.MCPTool, len(currentTools))
	for _, t := range currentTools {
		if t.SchemaHash == "" {
			t.SchemaHash = mcpclient.ComputeToolHash(t)
		}
		currMap[t.Name] = t
	}

	var findings []model.Finding
	var changes []model.DriftChange

	// Check modified or added tools
	for name, curr := range currMap {
		prev, existed := baseMap[name]
		if !existed {
			changes = append(changes, model.DriftChange{
				ToolName:           name,
				ChangeType:         "ADDED",
				CurrentHash:        curr.SchemaHash,
				CurrentDescription: curr.Description,
			})
			findings = append(findings, makeFinding(
				"MCP-DRF-002",
				"Unapproved New Tool Added (Schema Drift)",
				"Rug Pull / Schema Drift",
				model.SeverityHigh,
				fmt.Sprintf("Tool %q appeared on server %q after the trusted baseline was approved.", name, serverName),
				fmt.Sprintf("New tool hash: %s", shortHash(curr.SchemaHash)),
				"Review the newly added tool definition thoroughly before re-approving the server baseline.",
				fmt.Sprintf("%s/%s", serverName, name),
				"MCP02: Rug Pull / Dynamic Tool Mutation",
			))
			continue
		}

		if prev.SchemaHash != curr.SchemaHash {
			changes = append(changes, model.DriftChange{
				ToolName:            name,
				ChangeType:          "MODIFIED",
				PreviousHash:        prev.SchemaHash,
				CurrentHash:         curr.SchemaHash,
				PreviousDescription: prev.Description,
				CurrentDescription:  curr.Description,
			})
			findings = append(findings, makeFinding(
				"MCP-DRF-001",
				"Potential Rug Pull: Approved Tool Definition Mutated",
				"Rug Pull / Schema Drift",
				model.SeverityCritical,
				fmt.Sprintf("Tool %q on server %q silently changed its description or input schema since baseline approval (%s).", name, serverName, baseline.ApprovedAt),
				fmt.Sprintf("SHA-256 changed: %s -> %s", shortHash(prev.SchemaHash), shortHash(curr.SchemaHash)),
				"Disable this MCP server immediately and inspect the diff between the previous approved definition and the current schema.",
				fmt.Sprintf("%s/%s", serverName, name),
				"MCP02: Rug Pull / Dynamic Tool Mutation",
			))
		}
	}

	// Check removed tools
	for name, prev := range baseMap {
		if _, exists := currMap[name]; !exists {
			changes = append(changes, model.DriftChange{
				ToolName:            name,
				ChangeType:          "REMOVED",
				PreviousHash:        prev.SchemaHash,
				PreviousDescription: prev.Description,
			})
			findings = append(findings, makeFinding(
				"MCP-DRF-003",
				"Baselined Tool Removed",
				"Rug Pull / Schema Drift",
				model.SeverityLow,
				fmt.Sprintf("Tool %q was previously part of the approved baseline for %q but is no longer exposed.", name, serverName),
				fmt.Sprintf("Previous hash: %s", shortHash(prev.SchemaHash)),
				"Verify if this removal corresponds to an expected server upgrade and update the baseline if legitimate.",
				fmt.Sprintf("%s/%s", serverName, name),
				"MCP02: Rug Pull / Dynamic Tool Mutation",
			))
		}
	}

	sort.Slice(changes, func(i, j int) bool {
		return changes[i].ToolName < changes[j].ToolName
	})

	return findings, changes
}

// AuditCrossServerShadowing detects tool name collisions and cross-server manipulation across all servers.
func AuditCrossServerShadowing(results []model.ServerAuditResult) {
	toolOwners := make(map[string][]int) // normalized tool name -> indices of servers exposing it

	for idx, res := range results {
		for _, t := range res.Tools {
			key := strings.ToLower(strings.TrimSpace(t.Name))
			if key != "" {
				toolOwners[key] = append(toolOwners[key], idx)
			}
		}
	}

	// 1. Detect duplicate tool names across distinct servers
	for toolName, serverIndices := range toolOwners {
		if len(serverIndices) < 2 {
			continue
		}
		var names []string
		for _, i := range serverIndices {
			names = append(names, results[i].Server.ServerName)
		}
		sort.Strings(names)
		peerList := strings.Join(names, ", ")

		for _, i := range serverIndices {
			f := makeFinding(
				"MCP-SHD-001",
				"Cross-Server Tool Name Collision (Shadowing Risk)",
				"Tool Shadowing",
				model.SeverityHigh,
				fmt.Sprintf("Tool %q is exposed by multiple MCP servers (%s). A malicious server can shadow a legitimate tool to intercept LLM invocations.", toolName, peerList),
				fmt.Sprintf("Colliding tool: %s across [%s]", toolName, peerList),
				"Namespace tool names per server, remove redundant MCP servers, or restrict which server is trusted for this tool.",
				fmt.Sprintf("%s/%s", results[i].Server.ServerName, toolName),
				"MCP03: Tool Shadowing & Cross-Server Hijacking",
			)
			results[i].Findings = dedupeAndSortFindings(append(results[i].Findings, f))
		}
	}

	// 2. Detect descriptions in Server A explicitly mentioning tools owned by Server B
	for i := range results {
		ownTools := make(map[string]bool)
		for _, t := range results[i].Tools {
			ownTools[strings.ToLower(t.Name)] = true
		}

		for _, tool := range results[i].Tools {
			descLower := strings.ToLower(tool.Description)
			if crossToolManipRegex.MatchString(tool.Description) {
				f := makeFinding(
					"MCP-SHD-002",
					"Cross-Tool Manipulation Directive Detected",
					"Tool Shadowing",
					model.SeverityCritical,
					fmt.Sprintf("Tool %q contains instructions attempting to alter or hijack how the AI invokes other tools.", tool.Name),
					truncateEvidence(crossToolManipRegex.FindString(tool.Description), 160),
					"Audit the MCP server source code and remove any tool attempting to override behavior of unrelated tools.",
					fmt.Sprintf("%s/%s", results[i].Server.ServerName, tool.Name),
					"MCP03: Tool Shadowing & Cross-Server Hijacking",
				)
				results[i].Findings = dedupeAndSortFindings(append(results[i].Findings, f))
				continue
			}

			// Check explicit references to another server's tool name alongside imperative verbs
			for foreignTool, owners := range toolOwners {
				if len(foreignTool) < 5 || ownTools[foreignTool] {
					continue
				}
				if strings.Contains(descLower, foreignTool) &&
					(strings.Contains(descLower, "before ") || strings.Contains(descLower, "instead") || strings.Contains(descLower, "always ") || strings.Contains(descLower, "redirect")) {
					otherServer := results[owners[0]].Server.ServerName
					f := makeFinding(
						"MCP-SHD-003",
						"Description References Foreign Server Tool",
						"Tool Shadowing",
						model.SeverityHigh,
						fmt.Sprintf("Tool %q on %q references foreign tool %q (owned by %q) in a directive context.", tool.Name, results[i].Server.ServerName, foreignTool, otherServer),
						fmt.Sprintf("Referenced foreign tool: %s (from %s)", foreignTool, otherServer),
						"Inspect why this tool references another MCP server's tool; this is a common vector for cross-server shadowing attacks.",
						fmt.Sprintf("%s/%s", results[i].Server.ServerName, tool.Name),
						"MCP03: Tool Shadowing & Cross-Server Hijacking",
					)
					results[i].Findings = dedupeAndSortFindings(append(results[i].Findings, f))
				}
			}
		}
	}

	// Recalculate risk scores after cross-server findings are added
	for i := range results {
		results[i].RiskScore, results[i].RiskLevel = CalculateRiskScore(results[i].Findings)
	}
}

func auditConfigSecrets(srv model.MCPServerConfig) []model.Finding {
	var findings []model.Finding

	checkValue := func(location, key, val string) {
		val = strings.TrimSpace(val)
		if val == "" || strings.HasPrefix(val, "${") || strings.HasPrefix(val, "$") {
			return
		}
		for _, pat := range secretPatterns {
			if match := pat.Regex.FindString(val); match != "" {
				findings = append(findings, makeFinding(
					"MCP-SEC-001",
					fmt.Sprintf("Hardcoded %s in MCP Configuration", pat.Name),
					"Secrets Exposure",
					model.SeverityHigh,
					fmt.Sprintf("A plaintext %s was detected in %s (%s) for server %q.", pat.Name, location, key, srv.ServerName),
					fmt.Sprintf("%s=%s", key, discovery.MaskSecret(match)),
					"Rotate the exposed credential and inject it via an OS secret manager or runtime environment variable instead of storing it in plaintext JSON.",
					srv.ServerName,
					"LLM02: Sensitive Information Disclosure",
				))
				return
			}
		}

		// High-entropy heuristic for sensitive env/header key names
		upperKey := strings.ToUpper(key)
		isSensitiveKey := strings.Contains(upperKey, "SECRET") ||
			strings.Contains(upperKey, "TOKEN") ||
			strings.Contains(upperKey, "API_KEY") ||
			strings.Contains(upperKey, "APIKEY") ||
			strings.Contains(upperKey, "PASSWORD") ||
			strings.Contains(upperKey, "AUTHORIZATION")

		if isSensitiveKey && len(val) >= 16 && shannonEntropy(val) >= 3.5 && !strings.Contains(strings.ToLower(val), "your_") && !strings.Contains(strings.ToLower(val), "placeholder") {
			findings = append(findings, makeFinding(
				"MCP-SEC-002",
				"Plaintext Credential Stored in MCP Config",
				"Secrets Exposure",
				model.SeverityMedium,
				fmt.Sprintf("High-entropy credential value found in %s key %q for server %q.", location, key, srv.ServerName),
				fmt.Sprintf("%s=%s", key, discovery.MaskSecret(val)),
				"Avoid hardcoding static secrets in local AI client config files; use scoped, short-lived tokens or OS keychain integration.",
				srv.ServerName,
				"LLM02: Sensitive Information Disclosure",
			))
		}
	}

	for k, v := range srv.Env {
		checkValue("env", k, v)
	}
	for k, v := range srv.Headers {
		checkValue("headers", k, v)
	}
	for idx, arg := range srv.Args {
		checkValue("args", fmt.Sprintf("arg[%d]", idx), arg)
	}

	return findings
}

func auditSupplyChain(srv model.MCPServerConfig) []model.Finding {
	if srv.Transport != model.TransportStdio {
		return nil
	}
	var findings []model.Finding

	cmdBase := strings.ToLower(strings.TrimSuffix(baseName(srv.Command), ".exe"))
	cmdBase = strings.TrimSuffix(cmdBase, ".cmd")
	fullCmd := srv.Command + " " + strings.Join(srv.Args, " ")

	// 1. Unpinned npx / uvx / pipx ephemeral execution
	switch cmdBase {
	case "npx":
		pkg := extractRunnerPackage(srv.Args)
		if pkg != "" && !hasPinnedNpmVersion(pkg) {
			findings = append(findings, makeFinding(
				"MCP-SUP-001",
				"Unpinned Ephemeral NPM Package (npx)",
				"Supply Chain",
				model.SeverityMedium,
				fmt.Sprintf("Server %q runs %q via npx without pinning an exact version. A compromised upstream release will execute automatically on next launch.", srv.ServerName, pkg),
				fullCmd,
				fmt.Sprintf("Pin the package to an audited exact version (e.g., %s@1.2.3) or install locally with lockfile integrity verification.", strings.TrimSuffix(pkg, "@latest")),
				srv.ServerName,
				"LLM03: Supply Chain Vulnerabilities",
			))
		}
	case "uvx", "pipx":
		pkg := extractRunnerPackage(srv.Args)
		if pkg != "" && !strings.Contains(pkg, "==") {
			findings = append(findings, makeFinding(
				"MCP-SUP-001",
				fmt.Sprintf("Unpinned Ephemeral Python Package (%s)", cmdBase),
				"Supply Chain",
				model.SeverityMedium,
				fmt.Sprintf("Server %q runs %q via %s without an exact version pin (==x.y.z).", srv.ServerName, pkg, cmdBase),
				fullCmd,
				fmt.Sprintf("Pin an audited exact version (e.g., %s==1.0.0) to prevent silent upstream tampering.", pkg),
				srv.ServerName,
				"LLM03: Supply Chain Vulnerabilities",
			))
		}
	case "docker":
		for _, arg := range srv.Args {
			if strings.HasSuffix(arg, ":latest") {
				findings = append(findings, makeFinding(
					"MCP-SUP-001",
					"Mutable Docker Tag (:latest) in MCP Server",
					"Supply Chain",
					model.SeverityMedium,
					fmt.Sprintf("Server %q uses mutable Docker image tag %q.", srv.ServerName, arg),
					fullCmd,
					"Pin the container image by immutable digest (@sha256:...) or fixed release tag.",
					srv.ServerName,
					"LLM03: Supply Chain Vulnerabilities",
				))
				break
			}
		}
		// Check for overly permissive host root mounts or privileged mode
		joined := strings.Join(srv.Args, " ")
		if strings.Contains(joined, "--privileged") || strings.Contains(joined, "/:/") || strings.Contains(joined, "docker.sock") {
			findings = append(findings, makeFinding(
				"MCP-SUP-003",
				"Overprivileged Docker Container Configuration",
				"Supply Chain",
				model.SeverityCritical,
				fmt.Sprintf("Server %q launches a Docker container with privileged flags or sensitive host mount (e.g., docker.sock or root filesystem).", srv.ServerName),
				fullCmd,
				"Remove --privileged and docker.sock mounts; restrict volume mounts to read-only specific project directories.",
				srv.ServerName,
				"LLM06: Excessive Agency",
			))
		}
	case "sh", "bash", "cmd", "powershell", "pwsh":
		findings = append(findings, makeFinding(
			"MCP-SUP-002",
			"Shell Interpreter Wrapper Used as MCP Entrypoint",
			"Supply Chain",
			model.SeverityHigh,
			fmt.Sprintf("Server %q invokes a shell interpreter (%s) directly as its MCP command, increasing command-injection and obfuscation risk.", srv.ServerName, cmdBase),
			fullCmd,
			"Invoke the target MCP server binary directly without wrapping it in a shell interpreter.",
			srv.ServerName,
			"LLM03: Supply Chain Vulnerabilities",
		))
	}

	return findings
}

func auditTransport(srv model.MCPServerConfig) []model.Finding {
	if srv.Transport == model.TransportStdio || srv.URL == "" {
		return nil
	}
	var findings []model.Finding
	parsed, err := url.Parse(srv.URL)
	if err != nil {
		return nil
	}

	host := strings.ToLower(parsed.Hostname())
	isLocal := host == "localhost" || host == "127.0.0.1" || host == "::1"

	if parsed.Scheme == "http" && !isLocal {
		findings = append(findings, makeFinding(
			"MCP-NET-001",
			"Unencrypted HTTP Transport for Remote MCP Server",
			"Transport Security",
			model.SeverityHigh,
			fmt.Sprintf("Remote MCP server %q communicates over cleartext HTTP (%s), exposing tool payloads and tokens to MITM interception.", srv.ServerName, srv.URL),
			srv.URL,
			"Switch the MCP endpoint to HTTPS with valid TLS certificates.",
			srv.ServerName,
			"MCP04: Insecure Transport & Authentication",
		))
	}

	return findings
}

func auditToolSecurity(serverName string, tool model.MCPTool) []model.Finding {
	target := fmt.Sprintf("%s/%s", serverName, tool.Name)
	var findings []model.Finding

	// Collect tool description + all parameter descriptions inside inputSchema
	var corpus strings.Builder
	corpus.WriteString(tool.Description)
	if len(tool.InputSchema) > 0 {
		schemaBytes, _ := json.Marshal(tool.InputSchema)
		corpus.WriteByte('\n')
		corpus.Write(schemaBytes)
	}
	fullText := corpus.String()

	// 1. Poisoning & Prompt Injection checks
	findings = append(findings, scanTextForPoisoning(target, fullText)...)

	// 2. Dangerous Capability / Excessive Agency scoring
	nameAndDesc := tool.Name + " " + tool.Description
	if shellCapRegex.MatchString(tool.Name) || (strings.Contains(strings.ToLower(tool.Description), "execute") && strings.Contains(strings.ToLower(tool.Description), "command")) {
		findings = append(findings, makeFinding(
			"MCP-CAP-001",
			"Arbitrary Command / Shell Execution Capability",
			"Excessive Capability",
			model.SeverityHigh,
			fmt.Sprintf("Tool %q exposes shell or arbitrary command execution capability to the LLM.", tool.Name),
			fmt.Sprintf("Tool: %s — %s", tool.Name, truncateEvidence(tool.Description, 140)),
			"Require explicit Human-in-the-Loop (HITL) approval before execution, enforce strict command allowlists, or sandbox this server.",
			target,
			"LLM06: Excessive Agency",
		))
	} else if fsWriteRegex.MatchString(tool.Name) {
		findings = append(findings, makeFinding(
			"MCP-CAP-002",
			"Filesystem Write / Destructive Capability",
			"Excessive Capability",
			model.SeverityMedium,
			fmt.Sprintf("Tool %q can create, modify, or delete local files. Ensure workspace path confinement is enforced.", tool.Name),
			fmt.Sprintf("Tool: %s — %s", tool.Name, truncateEvidence(tool.Description, 140)),
			"Restrict write/delete operations to an explicit workspace directory and require approval for destructive actions.",
			target,
			"LLM06: Excessive Agency",
		))
	} else if netCapRegex.MatchString(tool.Name) {
		findings = append(findings, makeFinding(
			"MCP-CAP-003",
			"Outbound Network / External Action Capability",
			"Excessive Capability",
			model.SeverityLow,
			fmt.Sprintf("Tool %q can send outbound network requests or external communications, creating a potential data exfiltration channel if combined with file readers.", tool.Name),
			fmt.Sprintf("Tool: %s — %s", tool.Name, truncateEvidence(nameAndDesc, 140)),
			"Apply egress domain allowlists and monitor outbound payloads for sensitive data leakage.",
			target,
			"LLM06: Excessive Agency",
		))
	}

	return findings
}

func scanTextForPoisoning(target, text string) []model.Finding {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	var findings []model.Finding

	if match := hiddenTagRegex.FindString(text); match != "" {
		findings = append(findings, makeFinding(
			"MCP-POI-001",
			"Hidden Instruction Tag in Tool/Resource Metadata",
			"Tool Poisoning",
			model.SeverityCritical,
			"Detected XML/HTML directive tags (such as <IMPORTANT>, <SYSTEM>, or hidden comments) commonly used to smuggle covert prompt-injection instructions inside MCP descriptions.",
			truncateEvidence(match, 180),
			"Block and remove this MCP server immediately. Legitimate MCP tool descriptions should never embed covert system/instruction tags.",
			target,
			"LLM01: Prompt Injection / MCP01: Tool Poisoning",
		))
	}

	if match := stealthDirectiveRegex.FindString(text); match != "" {
		findings = append(findings, makeFinding(
			"MCP-POI-002",
			"Covert / Stealth Prompt Override Directive",
			"Tool Poisoning",
			model.SeverityCritical,
			"Tool metadata contains stealth language instructing the LLM to hide actions from the user or override previous safety instructions.",
			truncateEvidence(match, 180),
			"Quarantine this MCP server and audit its source code. Never trust tools that instruct the model to conceal behavior from the user.",
			target,
			"LLM01: Prompt Injection / MCP01: Tool Poisoning",
		))
	}

	if match := sensitiveFileExfilRegex.FindString(text); match != "" {
		findings = append(findings, makeFinding(
			"MCP-POI-003",
			"Sensitive Local File Reference in Tool Schema",
			"Tool Poisoning",
			model.SeverityCritical,
			"Tool metadata explicitly references high-value credential or system files (e.g., SSH keys, AWS credentials, .env, or AI client configs), strongly indicating a data exfiltration payload.",
			truncateEvidence(match, 160),
			"Do not allow this tool to run. Verify why a tool description references sensitive local credential files.",
			target,
			"LLM02: Sensitive Information Disclosure / MCP01: Tool Poisoning",
		))
	}

	if invisCount, invisSample := detectInvisibleUnicode(text); invisCount > 0 {
		findings = append(findings, makeFinding(
			"MCP-POI-004",
			"Invisible Unicode / ASCII Smuggling Characters Detected",
			"Tool Poisoning",
			model.SeverityCritical,
			fmt.Sprintf("Detected %d invisible Unicode control/tag characters (e.g., Zero-Width or Unicode Tag block U+E0000-U+E007F) that hide malicious prompts from human reviewers while remaining readable by LLMs.", invisCount),
			invisSample,
			"Treat this MCP server as malicious until inspected in hex/codepoint view and stripped of all invisible control characters.",
			target,
			"LLM01: Prompt Injection / MCP01: Tool Poisoning",
		))
	}

	if match := exfilCommandRegex.FindString(text); match != "" {
		findings = append(findings, makeFinding(
			"MCP-POI-005",
			"Suspicious Exfiltration Pattern in Tool Description",
			"Tool Poisoning",
			model.SeverityHigh,
			"Tool metadata contains command or exfiltration directives (e.g., curl/wget, side-channel parameter smuggling).",
			truncateEvidence(match, 160),
			"Inspect the tool definition and remove any embedded shell or data-exfiltration instructions.",
			target,
			"LLM01: Prompt Injection / MCP01: Tool Poisoning",
		))
	}

	if match := base64BlobRegex.FindString(text); match != "" {
		findings = append(findings, makeFinding(
			"MCP-POI-006",
			"Obfuscated Base64 Payload in Tool Metadata",
			"Tool Poisoning",
			model.SeverityMedium,
			"A long Base64-like encoded string was embedded inside the tool metadata, which can conceal encoded prompt injections or payloads.",
			truncateEvidence(match, 80),
			"Decode and review the Base64 blob to confirm it is benign documentation rather than an obfuscated instruction.",
			target,
			"MCP01: Tool Poisoning",
		))
	}

	return findings
}

func detectInvisibleUnicode(s string) (int, string) {
	count := 0
	var codepoints []string
	for _, r := range s {
		isZeroWidth := r == '\u200B' || r == '\u200C' || r == '\u200D' || r == '\uFEFF' || r == '\u2060'
		isBidi := (r >= '\u202A' && r <= '\u202E') || (r >= '\u2066' && r <= '\u2069')
		isTagBlock := r >= 0xE0000 && r <= 0xE007F // Unicode Tags used in LLM ASCII smuggling
		if isZeroWidth || isBidi || isTagBlock {
			count++
			if len(codepoints) < 6 {
				codepoints = append(codepoints, fmt.Sprintf("U+%04X", r))
			}
		}
	}
	if count == 0 {
		return 0, ""
	}
	return count, fmt.Sprintf("%d invisible chars: %s", count, strings.Join(codepoints, ", "))
}

// CalculateRiskScore returns a 0-100 risk score and categorical risk level for a list of findings.
func CalculateRiskScore(findings []model.Finding) (int, string) {
	if len(findings) == 0 {
		return 0, "SAFE"
	}
	score := 0
	hasCritical := false
	hasHigh := false

	for _, f := range findings {
		switch f.Severity {
		case model.SeverityCritical:
			score += 35
			hasCritical = true
		case model.SeverityHigh:
			score += 20
			hasHigh = true
		case model.SeverityMedium:
			score += 10
		case model.SeverityLow:
			score += 4
		case model.SeverityInfo:
			score += 1
		}
	}

	if score > 100 {
		score = 100
	}

	switch {
	case hasCritical || score >= 75:
		return score, "CRITICAL"
	case hasHigh || score >= 45:
		return score, "HIGH"
	case score >= 20:
		return score, "MEDIUM"
	default:
		return score, "LOW"
	}
}

func makeFinding(ruleID, title, category string, sev model.Severity, desc, evidence, remediation, target, owasp string) model.Finding {
	sum := sha256.Sum256([]byte(ruleID + "|" + target + "|" + evidence))
	return model.Finding{
		ID:          hex.EncodeToString(sum[:6]),
		RuleID:      ruleID,
		Title:       title,
		Category:    category,
		Severity:    sev,
		Description: desc,
		Evidence:    evidence,
		Remediation: remediation,
		Target:      target,
		OWASPRef:    owasp,
	}
}

func dedupeAndSortFindings(in []model.Finding) []model.Finding {
	seen := make(map[string]bool, len(in))
	out := make([]model.Finding, 0, len(in))
	for _, f := range in {
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		out = append(out, f)
	}

	rank := map[model.Severity]int{
		model.SeverityCritical: 0,
		model.SeverityHigh:     1,
		model.SeverityMedium:   2,
		model.SeverityLow:      3,
		model.SeverityInfo:     4,
	}
	sort.Slice(out, func(i, j int) bool {
		if rank[out[i].Severity] != rank[out[j].Severity] {
			return rank[out[i].Severity] < rank[out[j].Severity]
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	var total float64
	for _, r := range s {
		if unicode.IsSpace(r) {
			continue
		}
		freq[r]++
		total++
	}
	if total == 0 {
		return 0
	}
	var entropy float64
	for _, c := range freq {
		p := c / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func extractRunnerPackage(args []string) string {
	for i := 0; i < len(args); i++ {
		a := strings.TrimSpace(args[i])
		if a == "" {
			continue
		}
		if strings.HasPrefix(a, "-") {
			// Skip flag values like -p pkg or --package pkg
			if a == "-p" || a == "--package" || a == "--from" {
				if i+1 < len(args) {
					return args[i+1]
				}
			}
			continue
		}
		return a
	}
	return ""
}

func hasPinnedNpmVersion(pkg string) bool {
	if strings.HasSuffix(pkg, "@latest") || strings.HasSuffix(pkg, "@next") {
		return false
	}
	// Handle scoped packages like @modelcontextprotocol/server-filesystem@0.6.2
	trimmed := strings.TrimPrefix(pkg, "@")
	idx := strings.LastIndex(trimmed, "@")
	if idx == -1 {
		return false
	}
	ver := trimmed[idx+1:]
	return ver != "" && (ver[0] >= '0' && ver[0] <= '9')
}

func baseName(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	parts := strings.Split(p, "/")
	return parts[len(parts)-1]
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func truncateEvidence(s string, max int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
