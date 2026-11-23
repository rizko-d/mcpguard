package policy

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"mcpguard/internal/model"
)

// Action defines what the Runtime Firewall does when a policy rule matches.
type Action string

const (
	ActionAllow Action = "ALLOW"
	ActionDeny  Action = "DENY"
	ActionAsk   Action = "ASK"
)

// Rule defines a single policy evaluation rule.
type Rule struct {
	ID            string         `yaml:"id" json:"id"`
	Name          string         `yaml:"name" json:"name"`
	Enabled       bool           `yaml:"enabled" json:"enabled"`
	Action        Action         `yaml:"action" json:"action"`
	Severity      model.Severity `yaml:"severity" json:"severity"`
	ServerPattern string         `yaml:"serverPattern,omitempty" json:"serverPattern,omitempty"`
	ToolPattern   string         `yaml:"toolPattern,omitempty" json:"toolPattern,omitempty"`
	ArgRegex      string         `yaml:"argRegex,omitempty" json:"argRegex,omitempty"`
	Reason        string         `yaml:"reason" json:"reason"`

	compiledArg *regexp.Regexp
}

// Config is the root YAML configuration for the MCPGuard Runtime Policy Engine.
type Config struct {
	Version                string `yaml:"version" json:"version"`
	DefaultAction          Action `yaml:"defaultAction" json:"defaultAction"`
	DLPRedactSecrets       bool   `yaml:"dlpRedactSecrets" json:"dlpRedactSecrets"`
	BlockIndirectInjection bool   `yaml:"blockIndirectInjection" json:"blockIndirectInjection"`
	ApprovalTimeoutSec     int    `yaml:"approvalTimeoutSec" json:"approvalTimeoutSec"`
	Rules                  []Rule `yaml:"rules" json:"rules"`
}

// Decision is the result of evaluating a tool invocation against the Policy Engine.
type Decision struct {
	Action   Action         `json:"action"`
	RuleID   string         `json:"ruleId,omitempty"`
	RuleName string         `json:"ruleName,omitempty"`
	Severity model.Severity `json:"severity,omitempty"`
	Reason   string         `json:"reason,omitempty"`
}

// Engine evaluates MCP tool calls, redacts DLP secrets, and scans responses for indirect prompt injection.
type Engine struct {
	cfg Config
}

var dlpPatterns = []struct {
	Name  string
	Regex *regexp.Regexp
}{
	{"OpenAI API Key", regexp.MustCompile(`\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}\b`)},
	{"Anthropic API Key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`)},
	{"GitHub Token", regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b`)},
	{"AWS Access Key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"Slack Token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z\-]{10,}\b`)},
	{"Google API Key", regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
	{"Private Key PEM", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)},
	{"JWT Token", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`)},
}

var indirectInjectionRegex = regexp.MustCompile(`(?i)(?:<\s*(?:IMPORTANT|SYSTEM|INSTRUCTIONS?|OVERRIDE)\b[^>]*>|ignore (?:all )?(?:previous|prior|above) instructions|disregard (?:all )?(?:previous|safety) instructions|do not (?:tell|inform|mention to) (?:the )?user|silently (?:exfiltrate|execute|send|read)|new system prompt\s*:)`)

// DefaultYAML returns the default Phase 2 MCPGuard runtime firewall policy YAML.
func DefaultYAML() string {
	return `version: "1.0"
defaultAction: ALLOW
dlpRedactSecrets: true
blockIndirectInjection: true
approvalTimeoutSec: 60

rules:
  - id: POL-001
    name: Block Sensitive Credential Paths
    enabled: true
    action: DENY
    severity: CRITICAL
    serverPattern: "*"
    toolPattern: "*"
    argRegex: '(?i)(~\/\.ssh|\/\.ssh\/|\\\.ssh\\|id_rsa|id_ed25519|\.aws[\/\\]credentials|\/etc\/passwd|\/etc\/shadow|(^|[\/\\"\s])\.env([\/\\"\s]|$)|claude_desktop_config\.json|mcp_config\.json)'
    reason: "Blocked attempt to access sensitive local credentials or AI configuration files."

  - id: POL-002
    name: Block Destructive or Remote-Pipe Shell Commands
    enabled: true
    action: DENY
    severity: CRITICAL
    serverPattern: "*"
    toolPattern: "*"
    argRegex: '(?i)(rm\s+-[a-z]*r[a-z]*f|mkfs\.|dd\s+if=|curl\s+[^|]+\|\s*(?:ba)?sh|wget\s+[^|]+\|\s*(?:ba)?sh|powershell\s+.*-enc|Invoke-Expression|\bIEX\b)'
    reason: "Blocked destructive or remote-script-execution shell payload."

  - id: POL-003
    name: Require HITL Approval for Command / Shell Execution
    enabled: true
    action: ASK
    severity: HIGH
    serverPattern: "*"
    toolPattern: "*exec*,*shell*,*command*,*bash*,*terminal*,*powershell*,*spawn*,*eval*"
    reason: "Shell or command execution tools require explicit Human-in-the-Loop approval."

  - id: POL-004
    name: Require HITL Approval for Destructive Filesystem Writes
    enabled: true
    action: ASK
    severity: MEDIUM
    serverPattern: "*"
    toolPattern: "write_file,delete_file,remove_*,rm*,edit_file,modify_file,move_file,chmod,chown"
    reason: "Filesystem write/delete operations require user approval before execution."

  - id: POL-005
    name: Require HITL Approval for External Network / Messaging Tools
    enabled: true
    action: ASK
    severity: MEDIUM
    serverPattern: "*"
    toolPattern: "send_email,post_webhook,http_request,upload*,publish*,send_message"
    reason: "Outbound network or messaging actions require approval to prevent data exfiltration."
`
}

// ParseYAML compiles and validates a YAML policy document into a live Engine.
func ParseYAML(raw string) (*Engine, error) {
	var cfg Config
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("invalid policy YAML: %w", err)
	}

	if cfg.DefaultAction == "" {
		cfg.DefaultAction = ActionAllow
	}
	if !isValidAction(cfg.DefaultAction) {
		return nil, fmt.Errorf("invalid defaultAction %q (must be ALLOW, DENY, or ASK)", cfg.DefaultAction)
	}
	if cfg.ApprovalTimeoutSec <= 0 {
		cfg.ApprovalTimeoutSec = 60
	}

	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		r.Action = Action(strings.ToUpper(strings.TrimSpace(string(r.Action))))
		if !isValidAction(r.Action) {
			return nil, fmt.Errorf("rule %q has invalid action %q", r.ID, r.Action)
		}
		if r.Severity == "" {
			r.Severity = model.SeverityMedium
		}
		if strings.TrimSpace(r.ArgRegex) != "" {
			re, err := regexp.Compile(r.ArgRegex)
			if err != nil {
				return nil, fmt.Errorf("rule %q has invalid argRegex: %w", r.ID, err)
			}
			r.compiledArg = re
		}
	}

	return &Engine{cfg: cfg}, nil
}

// Config returns a copy of the loaded policy configuration.
func (e *Engine) Config() Config {
	return e.cfg
}

// ActiveRuleCount returns the number of enabled rules.
func (e *Engine) ActiveRuleCount() int {
	n := 0
	for _, r := range e.cfg.Rules {
		if r.Enabled {
			n++
		}
	}
	return n
}

// EvaluateToolCall checks a tools/call invocation against ordered policy rules (first match wins).
func (e *Engine) EvaluateToolCall(serverName, toolName, argsJSON string) Decision {
	for _, r := range e.cfg.Rules {
		if !r.Enabled {
			continue
		}
		if !matchPatternList(r.ServerPattern, serverName) {
			continue
		}
		if !matchPatternList(r.ToolPattern, toolName) {
			continue
		}
		if r.compiledArg != nil && !r.compiledArg.MatchString(argsJSON) {
			continue
		}
		return Decision{
			Action:   r.Action,
			RuleID:   r.ID,
			RuleName: r.Name,
			Severity: r.Severity,
			Reason:   r.Reason,
		}
	}

	return Decision{
		Action:   e.cfg.DefaultAction,
		RuleID:   "DEFAULT",
		RuleName: "Default Policy",
		Severity: model.SeverityInfo,
		Reason:   fmt.Sprintf("Matched default policy action (%s).", e.cfg.DefaultAction),
	}
}

// RedactSecrets scans text for known secret patterns and replaces matches with redaction markers.
func (e *Engine) RedactSecrets(input string) (string, []string) {
	if !e.cfg.DLPRedactSecrets || input == "" {
		return input, nil
	}
	redacted := input
	var hits []string
	seen := make(map[string]bool)

	for _, pat := range dlpPatterns {
		if pat.Regex.MatchString(redacted) {
			redacted = pat.Regex.ReplaceAllString(redacted, fmt.Sprintf("[REDACTED:%s]", pat.Name))
			if !seen[pat.Name] {
				seen[pat.Name] = true
				hits = append(hits, pat.Name)
			}
		}
	}
	return redacted, hits
}

// DetectIndirectInjection inspects tool output for indirect prompt injection payloads.
func (e *Engine) DetectIndirectInjection(responseText string) (bool, string) {
	if !e.cfg.BlockIndirectInjection || responseText == "" {
		return false, ""
	}
	if match := indirectInjectionRegex.FindString(responseText); match != "" {
		return true, match
	}
	return false, ""
}

func isValidAction(a Action) bool {
	return a == ActionAllow || a == ActionDeny || a == ActionAsk
}

func matchPatternList(patternList, value string) bool {
	patternList = strings.TrimSpace(patternList)
	if patternList == "" || patternList == "*" {
		return true
	}
	valLower := strings.ToLower(strings.TrimSpace(value))
	for _, p := range strings.Split(patternList, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if p == "*" {
			return true
		}
		if matched, err := filepath.Match(p, valLower); err == nil && matched {
			return true
		}
		if !strings.ContainsAny(p, "*?[") && valLower == p {
			return true
		}
	}
	return false
}
