export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type TransportType = 'stdio' | 'http' | 'sse';
export type BaselineStatus = 'UNTRUSTED' | 'BASELINE_MATCH' | 'DRIFT_DETECTED';

export interface ConfigSource {
  clientName: string;
  path: string;
  exists: boolean;
  serverCount: number;
  parseError?: string;
  isCustom: boolean;
}

export interface MCPServerConfig {
  id: string;
  clientName: string;
  configPath: string;
  serverName: string;
  transport: TransportType;
  command?: string;
  args?: string[];
  url?: string;
  maskedEnv?: Record<string, string>;
  maskedHeaders?: Record<string, string>;
  disabled: boolean;
  isDemo?: boolean;
  isProtected?: boolean;
}

export interface MCPTool {
  name: string;
  description: string;
  inputSchema?: Record<string, unknown>;
  schemaHash: string;
}

export interface MCPResource {
  uri: string;
  name: string;
  description?: string;
  mimeType?: string;
}

export interface MCPPrompt {
  name: string;
  description?: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  category: string;
  severity: Severity;
  description: string;
  evidence?: string;
  remediation: string;
  target: string;
  owaspRef?: string;
}

export interface DriftChange {
  toolName: string;
  changeType: 'ADDED' | 'MODIFIED' | 'REMOVED';
  previousHash?: string;
  currentHash?: string;
  previousDescription?: string;
  currentDescription?: string;
}

export interface ServerAuditResult {
  server: MCPServerConfig;
  inspectedAt: string;
  liveInspectionDone: boolean;
  liveInspectionError?: string;
  serverInfo?: string;
  protocolVersion?: string;
  tools: MCPTool[];
  resources: MCPResource[];
  prompts: MCPPrompt[];
  findings: Finding[];
  driftChanges: DriftChange[];
  baselineStatus: BaselineStatus;
  baselineHash?: string;
  currentHash?: string;
  baselineApprovedAt?: string;
  riskScore: number;
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';
}

export interface AuditHistoryEntry {
  id: number;
  serverId: string;
  serverName: string;
  clientName: string;
  riskScore: number;
  riskLevel: string;
  findingsCount: number;
  toolCount: number;
  scannedAt: string;
}

export interface DashboardSummary {
  totalConfigs: number;
  foundConfigs: number;
  totalServers: number;
  totalTools: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  driftCount: number;
  baselinedCount: number;
  postureScore: number;
  lastScanAt: string;
  demoModeActive: boolean;
  discoveredConfigs: ConfigSource[];
  servers: ServerAuditResult[];
}

export interface ScanProgressEvent {
  completed: number;
  total: number;
  server: string;
}

export interface TrafficEvent {
  id: number;
  requestId: string;
  timestamp: string;
  serverName: string;
  direction: string;
  method: string;
  toolName?: string;
  argsPreview?: string;
  responsePreview?: string;
  decision: string;
  ruleId?: string;
  ruleName?: string;
  reason?: string;
  severity?: Severity;
  dlpHits?: string[];
  injectionDetected: boolean;
  injectionEvidence?: string;
  latencyMs: number;
}

export interface PendingApproval {
  id: string;
  serverName: string;
  toolName: string;
  argsJson: string;
  ruleId: string;
  ruleName: string;
  severity: Severity;
  reason: string;
  requestedAt: string;
  expiresAt: string;
}

export interface FirewallStatus {
  running: boolean;
  controlUrl: string;
  proxyBinaryPath: string;
  proxyBinaryFound: boolean;
  activeRulesCount: number;
  dlpEnabled: boolean;
  injectionGuard: boolean;
  sessionApprovals: string[];
  pendingApprovals: PendingApproval[];
}

export interface HTTPProxyRoute {
  id: string;
  slug: string;
  serverName: string;
  upstreamUrl: string;
  localUrl: string;
  enabled: boolean;
  requestCount: number;
  blockedCount: number;
  createdAt: string;
}

export interface HTTPProxyStatus {
  running: boolean;
  listenAddr: string;
  baseUrl: string;
  routes: HTTPProxyRoute[];
}

export interface SchemaHardeningIssue {
  id: string;
  ruleId: string;
  severity: Severity;
  serverName: string;
  toolName: string;
  parameter: string;
  title: string;
  description: string;
  recommendation: string;
}

export interface PolicyBenchmarkCase {
  id: string;
  category: string;
  name: string;
  expected: string;
  actual: string;
  passed: boolean;
  matchedRule?: string;
  notes: string;
}

export interface OWASPControlStatus {
  controlId: string;
  name: string;
  status: 'PASS' | 'WARN' | 'FAIL';
  findingCount: number;
  mitigation: string;
}

export interface ComplianceReport {
  generatedAt: string;
  policyCoverageScore: number;
  schemaHardeningRate: number;
  overallGrade: string;
  owaspControls: OWASPControlStatus[];
  policyBenchmarks: PolicyBenchmarkCase[];
  schemaIssues: SchemaHardeningIssue[];
}
