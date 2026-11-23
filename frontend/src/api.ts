import type {
  AuditHistoryEntry,
  ComplianceReport,
  DashboardSummary,
  FirewallStatus,
  HTTPProxyStatus,
  PendingApproval,
  ScanProgressEvent,
  TrafficEvent,
} from './types';

interface WailsAppBridge {
  // Phase 1
  ScanAll(liveInspect: boolean): Promise<DashboardSummary>;
  InspectSingleServer(serverID: string): Promise<DashboardSummary>;
  ApproveBaseline(serverID: string): Promise<DashboardSummary>;
  RevokeBaseline(serverID: string): Promise<DashboardSummary>;
  ToggleDemoLab(enable: boolean): Promise<DashboardSummary>;
  TriggerDemoRugPull(active: boolean): Promise<DashboardSummary>;
  IsDemoRugPullActive(): Promise<boolean>;
  BrowseConfigFile(): Promise<string>;
  AddCustomConfigPath(label: string, path: string): Promise<DashboardSummary>;
  RemoveCustomConfigPath(path: string): Promise<DashboardSummary>;
  GetAuditHistory(limit: number): Promise<AuditHistoryEntry[]>;
  ExportAuditJSON(): Promise<string>;

  // Phase 2
  GetFirewallStatus(): Promise<FirewallStatus>;
  GetTrafficLogs(limit: number): Promise<TrafficEvent[]>;
  ClearTrafficLogs(): Promise<void>;
  GetPolicyYAML(): Promise<string>;
  SavePolicyYAML(yamlContent: string): Promise<FirewallStatus>;
  ResetPolicyYAML(): Promise<string>;
  ResolveApproval(approvalID: string, decision: string): Promise<void>;
  ClearSessionApprovals(): Promise<FirewallStatus>;
  ProtectServerWithProxy(serverID: string): Promise<DashboardSummary>;
  UnprotectServerProxy(serverID: string): Promise<DashboardSummary>;
  SimulateFirewallScenario(scenario: string): Promise<string>;

  // Phase 3
  GetHTTPProxyStatus(): Promise<HTTPProxyStatus>;
  AddHTTPProxyRoute(serverName: string, upstreamURL: string): Promise<HTTPProxyStatus>;
  ToggleHTTPProxyRoute(slug: string, enabled: boolean): Promise<HTTPProxyStatus>;
  DeleteHTTPProxyRoute(slug: string): Promise<HTTPProxyStatus>;
  RunHTTPProxySelfTest(): Promise<string>;
  GetComplianceReport(): Promise<ComplianceReport>;
  ExportAuditSARIF(): Promise<string>;
  ExportAuditHTML(): Promise<string>;
  ExportAuditMarkdown(): Promise<string>;
}

interface WailsRuntimeBridge {
  EventsOn(eventName: string, callback: (...data: unknown[]) => void): () => void;
}

declare global {
  interface Window {
    go?: {
      main?: {
        App?: WailsAppBridge;
      };
    };
    runtime?: WailsRuntimeBridge;
  }
}

function getBridge(): WailsAppBridge {
  const bridge = window.go?.main?.App;
  if (!bridge) {
    throw new Error('Wails backend bridge is not available. Run via Wails desktop app.');
  }
  return bridge;
}

function onEvent<T>(name: string, cb: (payload: T) => void): () => void {
  if (window.runtime?.EventsOn) {
    return window.runtime.EventsOn(name, (data: unknown) => {
      cb(data as T);
    });
  }
  return () => {};
}

export const api = {
  // Phase 1
  scanAll: (liveInspect: boolean) => getBridge().ScanAll(liveInspect),
  inspectSingleServer: (serverID: string) => getBridge().InspectSingleServer(serverID),
  approveBaseline: (serverID: string) => getBridge().ApproveBaseline(serverID),
  revokeBaseline: (serverID: string) => getBridge().RevokeBaseline(serverID),
  toggleDemoLab: (enable: boolean) => getBridge().ToggleDemoLab(enable),
  triggerDemoRugPull: (active: boolean) => getBridge().TriggerDemoRugPull(active),
  isDemoRugPullActive: () => getBridge().IsDemoRugPullActive(),
  browseConfigFile: () => getBridge().BrowseConfigFile(),
  addCustomConfigPath: (label: string, path: string) => getBridge().AddCustomConfigPath(label, path),
  removeCustomConfigPath: (path: string) => getBridge().RemoveCustomConfigPath(path),
  getAuditHistory: (limit = 50) => getBridge().GetAuditHistory(limit),
  exportAuditJSON: () => getBridge().ExportAuditJSON(),

  // Phase 2
  getFirewallStatus: () => getBridge().GetFirewallStatus(),
  getTrafficLogs: (limit = 200) => getBridge().GetTrafficLogs(limit),
  clearTrafficLogs: () => getBridge().ClearTrafficLogs(),
  getPolicyYAML: () => getBridge().GetPolicyYAML(),
  savePolicyYAML: (yamlContent: string) => getBridge().SavePolicyYAML(yamlContent),
  resetPolicyYAML: () => getBridge().ResetPolicyYAML(),
  resolveApproval: (approvalID: string, decision: 'APPROVE_ONCE' | 'APPROVE_SESSION' | 'DENY') =>
    getBridge().ResolveApproval(approvalID, decision),
  clearSessionApprovals: () => getBridge().ClearSessionApprovals(),
  protectServerWithProxy: (serverID: string) => getBridge().ProtectServerWithProxy(serverID),
  unprotectServerProxy: (serverID: string) => getBridge().UnprotectServerProxy(serverID),
  simulateFirewallScenario: (scenario: 'deny_ssh' | 'hitl_shell' | 'dlp_leak' | 'indirect_injection') =>
    getBridge().SimulateFirewallScenario(scenario),

  // Phase 3
  getHTTPProxyStatus: () => getBridge().GetHTTPProxyStatus(),
  addHTTPProxyRoute: (serverName: string, upstreamURL: string) =>
    getBridge().AddHTTPProxyRoute(serverName, upstreamURL),
  toggleHTTPProxyRoute: (slug: string, enabled: boolean) => getBridge().ToggleHTTPProxyRoute(slug, enabled),
  deleteHTTPProxyRoute: (slug: string) => getBridge().DeleteHTTPProxyRoute(slug),
  runHTTPProxySelfTest: () => getBridge().RunHTTPProxySelfTest(),
  getComplianceReport: () => getBridge().GetComplianceReport(),
  exportAuditSARIF: () => getBridge().ExportAuditSARIF(),
  exportAuditHTML: () => getBridge().ExportAuditHTML(),
  exportAuditMarkdown: () => getBridge().ExportAuditMarkdown(),

  // Real-time Wails Events
  onScanProgress: (cb: (ev: ScanProgressEvent) => void) => onEvent<ScanProgressEvent>('scan:progress', cb),
  onFirewallTraffic: (cb: (ev: TrafficEvent) => void) => onEvent<TrafficEvent>('firewall:traffic', cb),
  onApprovalNeeded: (cb: (req: PendingApproval) => void) => onEvent<PendingApproval>('firewall:approval_needed', cb),
  onApprovalResolved: (cb: (id: string) => void) => onEvent<string>('firewall:approval_resolved', cb),
};
