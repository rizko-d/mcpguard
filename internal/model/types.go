package model

// Severity represents the severity level of a security finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// TransportType represents the MCP transport mechanism.
type TransportType string

const (
	TransportStdio TransportType = "stdio"
	TransportHTTP  TransportType = "http"
	TransportSSE   TransportType = "sse"
)

// BaselineStatus represents the schema drift state against the stored trusted baseline.
type BaselineStatus string

const (
	BaselineUntrusted BaselineStatus = "UNTRUSTED"
	BaselineMatch     BaselineStatus = "BASELINE_MATCH"
	BaselineDrift     BaselineStatus = "DRIFT_DETECTED"
)

// ConfigSource describes an MCP client configuration file location.
type ConfigSource struct {
	ClientName  string `json:"clientName"`
	Path        string `json:"path"`
	Exists      bool   `json:"exists"`
	ServerCount int    `json:"serverCount"`
	ParseError  string `json:"parseError,omitempty"`
	IsCustom    bool   `json:"isCustom"`
}

// MCPServerConfig represents a single discovered MCP server configuration.
type MCPServerConfig struct {
	ID         string            `json:"id"`
	ClientName string            `json:"clientName"`
	ConfigPath string            `json:"configPath"`
	ServerName string            `json:"serverName"`
	Transport  TransportType     `json:"transport"`
	Command    string            `json:"command,omitempty"`
	Args       []string          `json:"args,omitempty"`
	URL        string            `json:"url,omitempty"`
	Env        map[string]string `json:"-"` // Never serialize raw secret values to UI
	MaskedEnv  map[string]string `json:"maskedEnv,omitempty"`
	Headers    map[string]string `json:"-"` // Never serialize raw auth headers to UI
	MaskedHdrs map[string]string `json:"maskedHeaders,omitempty"`
	Disabled    bool              `json:"disabled"`
	IsDemo      bool              `json:"isDemo,omitempty"`
	IsProtected bool              `json:"isProtected"`
}

// MCPTool represents an MCP tool definition retrieved from tools/list.
type MCPTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema,omitempty"`
	SchemaHash  string                 `json:"schemaHash"`
}

// MCPResource represents an MCP resource definition retrieved from resources/list.
type MCPResource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// MCPPrompt represents an MCP prompt template retrieved from prompts/list.
type MCPPrompt struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Finding represents a single security finding from static, drift, or cross-server analysis.
type Finding struct {
	ID          string   `json:"id"`
	RuleID      string   `json:"ruleId"`
	Title       string   `json:"title"`
	Category    string   `json:"category"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation"`
	Target      string   `json:"target"`
	OWASPRef    string   `json:"owaspRef,omitempty"`
}

// DriftChange captures a tool schema change relative to an approved baseline (Rug Pull detection).
type DriftChange struct {
	ToolName            string `json:"toolName"`
	ChangeType          string `json:"changeType"` // ADDED, MODIFIED, REMOVED
	PreviousHash        string `json:"previousHash,omitempty"`
	CurrentHash         string `json:"currentHash,omitempty"`
	PreviousDescription string `json:"previousDescription,omitempty"`
	CurrentDescription  string `json:"currentDescription,omitempty"`
}

// ServerAuditResult holds the complete Phase 1 audit output for a single MCP server.
type ServerAuditResult struct {
	Server              MCPServerConfig `json:"server"`
	InspectedAt         string          `json:"inspectedAt"`
	LiveInspectionDone  bool            `json:"liveInspectionDone"`
	LiveInspectionError string          `json:"liveInspectionError,omitempty"`
	ServerInfo          string          `json:"serverInfo,omitempty"`
	ProtocolVersion     string          `json:"protocolVersion,omitempty"`
	Tools               []MCPTool       `json:"tools"`
	Resources           []MCPResource   `json:"resources"`
	Prompts             []MCPPrompt     `json:"prompts"`
	Findings            []Finding       `json:"findings"`
	DriftChanges        []DriftChange   `json:"driftChanges"`
	BaselineStatus      BaselineStatus  `json:"baselineStatus"`
	BaselineHash        string          `json:"baselineHash,omitempty"`
	CurrentHash         string          `json:"currentHash,omitempty"`
	BaselineApprovedAt  string          `json:"baselineApprovedAt,omitempty"`
	RiskScore           int             `json:"riskScore"`
	RiskLevel           string          `json:"riskLevel"`
}

// AuditHistoryEntry represents a historical audit snapshot stored in SQLite.
type AuditHistoryEntry struct {
	ID            int64  `json:"id"`
	ServerID      string `json:"serverId"`
	ServerName    string `json:"serverName"`
	ClientName    string `json:"clientName"`
	RiskScore     int    `json:"riskScore"`
	RiskLevel     string `json:"riskLevel"`
	FindingsCount int    `json:"findingsCount"`
	ToolCount     int    `json:"toolCount"`
	ScannedAt     string `json:"scannedAt"`
}

// DashboardSummary aggregates all discovered configs, servers, findings, and posture metrics.
type DashboardSummary struct {
	TotalConfigs      int                 `json:"totalConfigs"`
	FoundConfigs      int                 `json:"foundConfigs"`
	TotalServers      int                 `json:"totalServers"`
	TotalTools        int                 `json:"totalTools"`
	TotalFindings     int                 `json:"totalFindings"`
	CriticalCount     int                 `json:"criticalCount"`
	HighCount         int                 `json:"highCount"`
	MediumCount       int                 `json:"mediumCount"`
	LowCount          int                 `json:"lowCount"`
	InfoCount         int                 `json:"infoCount"`
	DriftCount        int                 `json:"driftCount"`
	BaselinedCount    int                 `json:"baselinedCount"`
	PostureScore      int                 `json:"postureScore"` // 0-100 (100 = cleanest)
	LastScanAt        string              `json:"lastScanAt"`
	DemoModeActive    bool                `json:"demoModeActive"`
	DiscoveredConfigs []ConfigSource      `json:"discoveredConfigs"`
	Servers           []ServerAuditResult `json:"servers"`
}

// BaselineRecord represents a trusted tool-schema snapshot persisted in SQLite.
type BaselineRecord struct {
	ServerID      string    `json:"serverId"`
	ServerName    string    `json:"serverName"`
	AggregateHash string    `json:"aggregateHash"`
	Tools         []MCPTool `json:"tools"`
	ApprovedAt    string    `json:"approvedAt"`
}

// TrafficEvent represents a single intercepted JSON-RPC 2.0 event recorded by the Runtime MCP Firewall.
type TrafficEvent struct {
	ID                int64    `json:"id"`
	RequestID         string   `json:"requestId"`
	Timestamp         string   `json:"timestamp"`
	ServerName        string   `json:"serverName"`
	Direction         string   `json:"direction"` // CLIENT_TO_SERVER, SERVER_TO_CLIENT
	Method            string   `json:"method"`
	ToolName          string   `json:"toolName,omitempty"`
	ArgsPreview       string   `json:"argsPreview,omitempty"`
	ResponsePreview   string   `json:"responsePreview,omitempty"`
	Decision          string   `json:"decision"` // ALLOW, DENY, APPROVED_ONCE, APPROVED_SESSION, DENIED_USER, TIMEOUT, LOGGED
	RuleID            string   `json:"ruleId,omitempty"`
	RuleName          string   `json:"ruleName,omitempty"`
	Reason            string   `json:"reason,omitempty"`
	Severity          Severity `json:"severity,omitempty"`
	DLPHits           []string `json:"dlpHits,omitempty"`
	InjectionDetected bool     `json:"injectionDetected"`
	InjectionEvidence string   `json:"injectionEvidence,omitempty"`
	LatencyMs         int64    `json:"latencyMs"`
}

// PendingApproval represents an active Human-in-the-Loop (HITL) approval request awaiting user action.
type PendingApproval struct {
	ID          string   `json:"id"`
	ServerName  string   `json:"serverName"`
	ToolName    string   `json:"toolName"`
	ArgsJSON    string   `json:"argsJson"`
	RuleID      string   `json:"ruleId"`
	RuleName    string   `json:"ruleName"`
	Severity    Severity `json:"severity"`
	Reason      string   `json:"reason"`
	RequestedAt string   `json:"requestedAt"`
	ExpiresAt   string   `json:"expiresAt"`
}

// FirewallStatus reports the live status of the Phase 2 Runtime Firewall Control Plane.
type FirewallStatus struct {
	Running          bool              `json:"running"`
	ControlURL       string            `json:"controlUrl"`
	ProxyBinaryPath  string            `json:"proxyBinaryPath"`
	ProxyBinaryFound bool              `json:"proxyBinaryFound"`
	ActiveRulesCount int               `json:"activeRulesCount"`
	DLPEnabled       bool              `json:"dlpEnabled"`
	InjectionGuard   bool              `json:"injectionGuard"`
	SessionApprovals []string          `json:"sessionApprovals"`
	PendingApprovals []PendingApproval `json:"pendingApprovals"`
}

// HTTPProxyRoute represents a managed local reverse proxy route protecting a remote HTTP/SSE MCP server.
type HTTPProxyRoute struct {
	ID            string            `json:"id"`
	Slug          string            `json:"slug"`
	ServerName    string            `json:"serverName"`
	UpstreamURL   string            `json:"upstreamUrl"`
	LocalURL      string            `json:"localUrl"`
	Enabled       bool              `json:"enabled"`
	RequestCount  int64             `json:"requestCount"`
	BlockedCount  int64             `json:"blockedCount"`
	CustomHeaders map[string]string `json:"-"`
	CreatedAt     string            `json:"createdAt"`
}

// HTTPProxyStatus reports the status of the local HTTP/SSE MCP Reverse Proxy listener.
type HTTPProxyStatus struct {
	Running    bool             `json:"running"`
	ListenAddr string           `json:"listenAddr"`
	BaseURL    string           `json:"baseUrl"`
	Routes     []HTTPProxyRoute `json:"routes"`
}

// SchemaHardeningIssue flags missing input validation constraints in an MCP tool's JSON Schema.
type SchemaHardeningIssue struct {
	ID             string   `json:"id"`
	RuleID         string   `json:"ruleId"`
	Severity       Severity `json:"severity"`
	ServerName     string   `json:"serverName"`
	ToolName       string   `json:"toolName"`
	Parameter      string   `json:"parameter"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Recommendation string   `json:"recommendation"`
}

// PolicyBenchmarkCase captures one defensive policy coverage self-test result.
type PolicyBenchmarkCase struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Name        string `json:"name"`
	Expected    string `json:"expected"`
	Actual      string `json:"actual"`
	Passed      bool   `json:"passed"`
	MatchedRule string `json:"matchedRule,omitempty"`
	Notes       string `json:"notes"`
}

// OWASPControlStatus maps audit results and firewall safeguards to an OWASP LLM/MCP security control.
type OWASPControlStatus struct {
	ControlID    string `json:"controlId"`
	Name         string `json:"name"`
	Status       string `json:"status"` // PASS, WARN, FAIL
	FindingCount int    `json:"findingCount"`
	Mitigation   string `json:"mitigation"`
}

// ComplianceReport aggregates OWASP mapping, tool schema hardening checks, and firewall policy coverage.
type ComplianceReport struct {
	GeneratedAt         string                 `json:"generatedAt"`
	PolicyCoverageScore int                    `json:"policyCoverageScore"` // 0-100
	SchemaHardeningRate int                    `json:"schemaHardeningRate"` // 0-100
	OverallGrade        string                 `json:"overallGrade"`        // A, B, C, D, F
	OWASPControls       []OWASPControlStatus   `json:"owaspControls"`
	PolicyBenchmarks    []PolicyBenchmarkCase  `json:"policyBenchmarks"`
	SchemaIssues        []SchemaHardeningIssue `json:"schemaIssues"`
}
