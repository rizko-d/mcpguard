export namespace model {
	
	export class AuditHistoryEntry {
	    id: number;
	    serverId: string;
	    serverName: string;
	    clientName: string;
	    riskScore: number;
	    riskLevel: string;
	    findingsCount: number;
	    toolCount: number;
	    scannedAt: string;
	
	    static createFrom(source: any = {}) {
	        return new AuditHistoryEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.serverId = source["serverId"];
	        this.serverName = source["serverName"];
	        this.clientName = source["clientName"];
	        this.riskScore = source["riskScore"];
	        this.riskLevel = source["riskLevel"];
	        this.findingsCount = source["findingsCount"];
	        this.toolCount = source["toolCount"];
	        this.scannedAt = source["scannedAt"];
	    }
	}
	export class SchemaHardeningIssue {
	    id: string;
	    ruleId: string;
	    severity: string;
	    serverName: string;
	    toolName: string;
	    parameter: string;
	    title: string;
	    description: string;
	    recommendation: string;
	
	    static createFrom(source: any = {}) {
	        return new SchemaHardeningIssue(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.ruleId = source["ruleId"];
	        this.severity = source["severity"];
	        this.serverName = source["serverName"];
	        this.toolName = source["toolName"];
	        this.parameter = source["parameter"];
	        this.title = source["title"];
	        this.description = source["description"];
	        this.recommendation = source["recommendation"];
	    }
	}
	export class PolicyBenchmarkCase {
	    id: string;
	    category: string;
	    name: string;
	    expected: string;
	    actual: string;
	    passed: boolean;
	    matchedRule?: string;
	    notes: string;
	
	    static createFrom(source: any = {}) {
	        return new PolicyBenchmarkCase(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.category = source["category"];
	        this.name = source["name"];
	        this.expected = source["expected"];
	        this.actual = source["actual"];
	        this.passed = source["passed"];
	        this.matchedRule = source["matchedRule"];
	        this.notes = source["notes"];
	    }
	}
	export class OWASPControlStatus {
	    controlId: string;
	    name: string;
	    status: string;
	    findingCount: number;
	    mitigation: string;
	
	    static createFrom(source: any = {}) {
	        return new OWASPControlStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.controlId = source["controlId"];
	        this.name = source["name"];
	        this.status = source["status"];
	        this.findingCount = source["findingCount"];
	        this.mitigation = source["mitigation"];
	    }
	}
	export class ComplianceReport {
	    generatedAt: string;
	    policyCoverageScore: number;
	    schemaHardeningRate: number;
	    overallGrade: string;
	    owaspControls: OWASPControlStatus[];
	    policyBenchmarks: PolicyBenchmarkCase[];
	    schemaIssues: SchemaHardeningIssue[];
	
	    static createFrom(source: any = {}) {
	        return new ComplianceReport(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.generatedAt = source["generatedAt"];
	        this.policyCoverageScore = source["policyCoverageScore"];
	        this.schemaHardeningRate = source["schemaHardeningRate"];
	        this.overallGrade = source["overallGrade"];
	        this.owaspControls = this.convertValues(source["owaspControls"], OWASPControlStatus);
	        this.policyBenchmarks = this.convertValues(source["policyBenchmarks"], PolicyBenchmarkCase);
	        this.schemaIssues = this.convertValues(source["schemaIssues"], SchemaHardeningIssue);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ConfigSource {
	    clientName: string;
	    path: string;
	    exists: boolean;
	    serverCount: number;
	    parseError?: string;
	    isCustom: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ConfigSource(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.clientName = source["clientName"];
	        this.path = source["path"];
	        this.exists = source["exists"];
	        this.serverCount = source["serverCount"];
	        this.parseError = source["parseError"];
	        this.isCustom = source["isCustom"];
	    }
	}
	export class DriftChange {
	    toolName: string;
	    changeType: string;
	    previousHash?: string;
	    currentHash?: string;
	    previousDescription?: string;
	    currentDescription?: string;
	
	    static createFrom(source: any = {}) {
	        return new DriftChange(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.toolName = source["toolName"];
	        this.changeType = source["changeType"];
	        this.previousHash = source["previousHash"];
	        this.currentHash = source["currentHash"];
	        this.previousDescription = source["previousDescription"];
	        this.currentDescription = source["currentDescription"];
	    }
	}
	export class Finding {
	    id: string;
	    ruleId: string;
	    title: string;
	    category: string;
	    severity: string;
	    description: string;
	    evidence?: string;
	    remediation: string;
	    target: string;
	    owaspRef?: string;
	
	    static createFrom(source: any = {}) {
	        return new Finding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.ruleId = source["ruleId"];
	        this.title = source["title"];
	        this.category = source["category"];
	        this.severity = source["severity"];
	        this.description = source["description"];
	        this.evidence = source["evidence"];
	        this.remediation = source["remediation"];
	        this.target = source["target"];
	        this.owaspRef = source["owaspRef"];
	    }
	}
	export class MCPPrompt {
	    name: string;
	    description?: string;
	
	    static createFrom(source: any = {}) {
	        return new MCPPrompt(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.description = source["description"];
	    }
	}
	export class MCPResource {
	    uri: string;
	    name: string;
	    description?: string;
	    mimeType?: string;
	
	    static createFrom(source: any = {}) {
	        return new MCPResource(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.uri = source["uri"];
	        this.name = source["name"];
	        this.description = source["description"];
	        this.mimeType = source["mimeType"];
	    }
	}
	export class MCPTool {
	    name: string;
	    description: string;
	    inputSchema?: Record<string, any>;
	    schemaHash: string;
	
	    static createFrom(source: any = {}) {
	        return new MCPTool(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.description = source["description"];
	        this.inputSchema = source["inputSchema"];
	        this.schemaHash = source["schemaHash"];
	    }
	}
	export class MCPServerConfig {
	    id: string;
	    clientName: string;
	    configPath: string;
	    serverName: string;
	    transport: string;
	    command?: string;
	    args?: string[];
	    url?: string;
	    maskedEnv?: Record<string, string>;
	    maskedHeaders?: Record<string, string>;
	    disabled: boolean;
	    isDemo?: boolean;
	    isProtected: boolean;
	
	    static createFrom(source: any = {}) {
	        return new MCPServerConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.clientName = source["clientName"];
	        this.configPath = source["configPath"];
	        this.serverName = source["serverName"];
	        this.transport = source["transport"];
	        this.command = source["command"];
	        this.args = source["args"];
	        this.url = source["url"];
	        this.maskedEnv = source["maskedEnv"];
	        this.maskedHeaders = source["maskedHeaders"];
	        this.disabled = source["disabled"];
	        this.isDemo = source["isDemo"];
	        this.isProtected = source["isProtected"];
	    }
	}
	export class ServerAuditResult {
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
	    baselineStatus: string;
	    baselineHash?: string;
	    currentHash?: string;
	    baselineApprovedAt?: string;
	    riskScore: number;
	    riskLevel: string;
	
	    static createFrom(source: any = {}) {
	        return new ServerAuditResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.server = this.convertValues(source["server"], MCPServerConfig);
	        this.inspectedAt = source["inspectedAt"];
	        this.liveInspectionDone = source["liveInspectionDone"];
	        this.liveInspectionError = source["liveInspectionError"];
	        this.serverInfo = source["serverInfo"];
	        this.protocolVersion = source["protocolVersion"];
	        this.tools = this.convertValues(source["tools"], MCPTool);
	        this.resources = this.convertValues(source["resources"], MCPResource);
	        this.prompts = this.convertValues(source["prompts"], MCPPrompt);
	        this.findings = this.convertValues(source["findings"], Finding);
	        this.driftChanges = this.convertValues(source["driftChanges"], DriftChange);
	        this.baselineStatus = source["baselineStatus"];
	        this.baselineHash = source["baselineHash"];
	        this.currentHash = source["currentHash"];
	        this.baselineApprovedAt = source["baselineApprovedAt"];
	        this.riskScore = source["riskScore"];
	        this.riskLevel = source["riskLevel"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class DashboardSummary {
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
	
	    static createFrom(source: any = {}) {
	        return new DashboardSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.totalConfigs = source["totalConfigs"];
	        this.foundConfigs = source["foundConfigs"];
	        this.totalServers = source["totalServers"];
	        this.totalTools = source["totalTools"];
	        this.totalFindings = source["totalFindings"];
	        this.criticalCount = source["criticalCount"];
	        this.highCount = source["highCount"];
	        this.mediumCount = source["mediumCount"];
	        this.lowCount = source["lowCount"];
	        this.infoCount = source["infoCount"];
	        this.driftCount = source["driftCount"];
	        this.baselinedCount = source["baselinedCount"];
	        this.postureScore = source["postureScore"];
	        this.lastScanAt = source["lastScanAt"];
	        this.demoModeActive = source["demoModeActive"];
	        this.discoveredConfigs = this.convertValues(source["discoveredConfigs"], ConfigSource);
	        this.servers = this.convertValues(source["servers"], ServerAuditResult);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	export class PendingApproval {
	    id: string;
	    serverName: string;
	    toolName: string;
	    argsJson: string;
	    ruleId: string;
	    ruleName: string;
	    severity: string;
	    reason: string;
	    requestedAt: string;
	    expiresAt: string;
	
	    static createFrom(source: any = {}) {
	        return new PendingApproval(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.serverName = source["serverName"];
	        this.toolName = source["toolName"];
	        this.argsJson = source["argsJson"];
	        this.ruleId = source["ruleId"];
	        this.ruleName = source["ruleName"];
	        this.severity = source["severity"];
	        this.reason = source["reason"];
	        this.requestedAt = source["requestedAt"];
	        this.expiresAt = source["expiresAt"];
	    }
	}
	export class FirewallStatus {
	    running: boolean;
	    controlUrl: string;
	    proxyBinaryPath: string;
	    proxyBinaryFound: boolean;
	    activeRulesCount: number;
	    dlpEnabled: boolean;
	    injectionGuard: boolean;
	    sessionApprovals: string[];
	    pendingApprovals: PendingApproval[];
	
	    static createFrom(source: any = {}) {
	        return new FirewallStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.controlUrl = source["controlUrl"];
	        this.proxyBinaryPath = source["proxyBinaryPath"];
	        this.proxyBinaryFound = source["proxyBinaryFound"];
	        this.activeRulesCount = source["activeRulesCount"];
	        this.dlpEnabled = source["dlpEnabled"];
	        this.injectionGuard = source["injectionGuard"];
	        this.sessionApprovals = source["sessionApprovals"];
	        this.pendingApprovals = this.convertValues(source["pendingApprovals"], PendingApproval);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class HTTPProxyRoute {
	    id: string;
	    slug: string;
	    serverName: string;
	    upstreamUrl: string;
	    localUrl: string;
	    enabled: boolean;
	    requestCount: number;
	    blockedCount: number;
	    createdAt: string;
	
	    static createFrom(source: any = {}) {
	        return new HTTPProxyRoute(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.slug = source["slug"];
	        this.serverName = source["serverName"];
	        this.upstreamUrl = source["upstreamUrl"];
	        this.localUrl = source["localUrl"];
	        this.enabled = source["enabled"];
	        this.requestCount = source["requestCount"];
	        this.blockedCount = source["blockedCount"];
	        this.createdAt = source["createdAt"];
	    }
	}
	export class HTTPProxyStatus {
	    running: boolean;
	    listenAddr: string;
	    baseUrl: string;
	    routes: HTTPProxyRoute[];
	
	    static createFrom(source: any = {}) {
	        return new HTTPProxyStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.listenAddr = source["listenAddr"];
	        this.baseUrl = source["baseUrl"];
	        this.routes = this.convertValues(source["routes"], HTTPProxyRoute);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	
	
	
	
	
	
	
	export class TrafficEvent {
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
	    severity?: string;
	    dlpHits?: string[];
	    injectionDetected: boolean;
	    injectionEvidence?: string;
	    latencyMs: number;
	
	    static createFrom(source: any = {}) {
	        return new TrafficEvent(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.requestId = source["requestId"];
	        this.timestamp = source["timestamp"];
	        this.serverName = source["serverName"];
	        this.direction = source["direction"];
	        this.method = source["method"];
	        this.toolName = source["toolName"];
	        this.argsPreview = source["argsPreview"];
	        this.responsePreview = source["responsePreview"];
	        this.decision = source["decision"];
	        this.ruleId = source["ruleId"];
	        this.ruleName = source["ruleName"];
	        this.reason = source["reason"];
	        this.severity = source["severity"];
	        this.dlpHits = source["dlpHits"];
	        this.injectionDetected = source["injectionDetected"];
	        this.injectionEvidence = source["injectionEvidence"];
	        this.latencyMs = source["latencyMs"];
	    }
	}

}

