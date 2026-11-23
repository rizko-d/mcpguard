import React, { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  Award,
  CheckCircle2,
  Download,
  FileCode2,
  FileSearch,
  FlaskConical,
  FolderOpen,
  Globe,
  History,
  Lock,
  Plus,
  Radio,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Sliders,
  Terminal,
  Trash2,
  Unlock,
  Wrench,
  Zap,
} from 'lucide-react';
import { api } from './api';
import ApprovalModal from './components/ApprovalModal';
import ComplianceView from './components/ComplianceView';
import FirewallView from './components/FirewallView';
import HttpProxyView from './components/HttpProxyView';
import PolicyView from './components/PolicyView';
import type {
  AuditHistoryEntry,
  ComplianceReport,
  DashboardSummary,
  Finding,
  FirewallStatus,
  HTTPProxyStatus,
  PendingApproval,
  ScanProgressEvent,
  ServerAuditResult,
  Severity,
  TrafficEvent,
} from './types';

type NavTab =
  | 'overview'
  | 'servers'
  | 'findings'
  | 'configs'
  | 'history'
  | 'firewall'
  | 'httpproxy'
  | 'policy'
  | 'compliance';
type ServerDetailTab = 'findings' | 'tools' | 'drift' | 'config';

function formatTime(iso?: string): string {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleString();
  } catch {
    return iso;
  }
}

function shortHash(hash?: string): string {
  if (!hash) return '—';
  return hash.slice(0, 12);
}

function postureColor(score: number): string {
  if (score >= 85) return '#10b981';
  if (score >= 60) return '#eab308';
  if (score >= 40) return '#f97316';
  return '#ef4444';
}

export default function App() {
  const [nav, setNav] = useState<NavTab>('overview');
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [history, setHistory] = useState<AuditHistoryEntry[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [inspectingId, setInspectingId] = useState<string | null>(null);
  const [progress, setProgress] = useState<ScanProgressEvent | null>(null);
  const [rugPullActive, setRugPullActive] = useState<boolean>(false);
  const [toast, setToast] = useState<{ kind: 'info' | 'danger' | 'success'; text: string } | null>(null);

  // Server master-detail state
  const [selectedServerId, setSelectedServerId] = useState<string | null>(null);
  const [detailTab, setDetailTab] = useState<ServerDetailTab>('findings');

  // Findings filter state
  const [sevFilter, setSevFilter] = useState<string>('ALL');
  const [catFilter, setCatFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Custom config input state
  const [customLabel, setCustomLabel] = useState<string>('');
  const [customPath, setCustomPath] = useState<string>('');

  // Phase 2: Runtime Firewall, Policy & HITL state
  const [fwStatus, setFwStatus] = useState<FirewallStatus | null>(null);
  const [traffic, setTraffic] = useState<TrafficEvent[]>([]);
  const [approvalQueue, setApprovalQueue] = useState<PendingApproval[]>([]);
  const [policyYAML, setPolicyYAML] = useState<string>('');
  const [policyDirty, setPolicyDirty] = useState<boolean>(false);
  const [policySaving, setPolicySaving] = useState<boolean>(false);
  const [policyError, setPolicyError] = useState<string | null>(null);

  // Phase 3: HTTP/SSE Reverse Proxy & Compliance state
  const [httpProxyStatus, setHttpProxyStatus] = useState<HTTPProxyStatus | null>(null);
  const [complianceReport, setComplianceReport] = useState<ComplianceReport | null>(null);

  const refreshHttpProxy = async () => {
    try {
      const st = await api.getHTTPProxyStatus();
      setHttpProxyStatus(st);
    } catch {
      // Ignore
    }
  };

  const refreshCompliance = async () => {
    try {
      const rep = await api.getComplianceReport();
      setComplianceReport(rep);
    } catch {
      // Ignore
    }
  };

  const refreshFirewall = async () => {
    try {
      const [st, logs] = await Promise.all([api.getFirewallStatus(), api.getTrafficLogs(200)]);
      setFwStatus(st);
      setTraffic(logs);
      if (st.pendingApprovals && st.pendingApprovals.length > 0) {
        setApprovalQueue(st.pendingApprovals);
      }
    } catch {
      // Ignore if backend not ready
    }
  };

  const loadPolicy = async () => {
    try {
      const y = await api.getPolicyYAML();
      setPolicyYAML(y);
      setPolicyDirty(false);
      setPolicyError(null);
    } catch {
      // Ignore
    }
  };

  const showToast = (kind: 'info' | 'danger' | 'success', text: string) => {
    setToast({ kind, text });
    window.setTimeout(() => {
      setToast((prev) => (prev?.text === text ? null : prev));
    }, 5000);
  };

  const refreshHistory = async () => {
    try {
      const entries = await api.getAuditHistory(60);
      setHistory(entries);
    } catch {
      // Ignore history read error in initial boot
    }
  };

  const runScan = async (liveInspect: boolean) => {
    setLoading(true);
    setProgress(null);
    try {
      const res = await api.scanAll(liveInspect);
      setSummary(res);
      if (res.servers.length > 0) {
        setSelectedServerId((prev) =>
          prev && res.servers.some((s) => s.server.id === prev) ? prev : res.servers[0].server.id,
        );
      } else {
        setSelectedServerId(null);
      }
      await refreshHistory();
      await refreshCompliance();
      if (liveInspect) {
        showToast('success', `Live MCP inspection finished across ${res.totalServers} server(s).`);
      }
    } catch (err) {
      showToast('danger', `Scan failed: ${String(err)}`);
    } finally {
      setLoading(false);
      setProgress(null);
    }
  };

  useEffect(() => {
    const offScan = api.onScanProgress((ev) => setProgress(ev));
    const offTraffic = api.onFirewallTraffic((ev) => {
      setTraffic((prev) => [ev, ...prev].slice(0, 300));
      api.getFirewallStatus().then(setFwStatus).catch(() => {});
    });
    const offApproval = api.onApprovalNeeded((req) => {
      setApprovalQueue((prev) => (prev.some((p) => p.id === req.id) ? prev : [...prev, req]));
    });
    const offResolved = api.onApprovalResolved((id) => {
      setApprovalQueue((prev) => prev.filter((p) => p.id !== id));
    });

    runScan(false);
    refreshFirewall();
    refreshHttpProxy();
    loadPolicy();
    api
      .isDemoRugPullActive()
      .then(setRugPullActive)
      .catch(() => {});

    return () => {
      offScan();
      offTraffic();
      offApproval();
      offResolved();
    };
  }, []);

  const selectedServer: ServerAuditResult | null = useMemo(() => {
    if (!summary || !selectedServerId) return null;
    return summary.servers.find((s) => s.server.id === selectedServerId) ?? null;
  }, [summary, selectedServerId]);

  const allFindings: Array<{ finding: Finding; server: ServerAuditResult }> = useMemo(() => {
    if (!summary) return [];
    const list: Array<{ finding: Finding; server: ServerAuditResult }> = [];
    for (const s of summary.servers) {
      for (const f of s.findings) {
        list.push({ finding: f, server: s });
      }
    }
    const order: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    list.sort((a, b) => order[a.finding.severity] - order[b.finding.severity]);
    return list;
  }, [summary]);

  const categories = useMemo(() => {
    const set = new Set<string>();
    for (const item of allFindings) set.add(item.finding.category);
    return Array.from(set).sort();
  }, [allFindings]);

  const filteredFindings = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return allFindings.filter(({ finding, server }) => {
      if (sevFilter !== 'ALL' && finding.severity !== sevFilter) return false;
      if (catFilter !== 'ALL' && finding.category !== catFilter) return false;
      if (q) {
        const hay = `${finding.ruleId} ${finding.title} ${finding.description} ${finding.evidence ?? ''} ${finding.target} ${server.server.serverName}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [allFindings, sevFilter, catFilter, searchQuery]);

  const handleToggleDemo = async () => {
    const next = !(summary?.demoModeActive ?? false);
    setLoading(true);
    try {
      const res = await api.toggleDemoLab(next);
      setSummary(res);
      if (!next) setRugPullActive(false);
      if (res.servers.length > 0) {
        setSelectedServerId(res.servers[0].server.id);
      }
      await refreshHistory();
      showToast(
        'info',
        next
          ? 'Demo Security Lab loaded with 4 realistic MCP servers (Poisoning, Rug Pull, Shadowing, Clean).'
          : 'Demo Security Lab disabled. Showing local machine configurations only.',
      );
    } catch (err) {
      showToast('danger', String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleToggleRugPull = async () => {
    const next = !rugPullActive;
    setLoading(true);
    try {
      const res = await api.triggerDemoRugPull(next);
      setSummary(res);
      setRugPullActive(next);
      setSelectedServerId('demo-notes-rugpull');
      setNav('servers');
      setDetailTab('drift');
      await refreshHistory();
      showToast(
        next ? 'danger' : 'success',
        next
          ? 'Rug Pull simulated on notes-sync-mcp! SHA-256 schema drift & stealth tool injection detected.'
          : 'Demo Rug Pull reverted back to clean baseline.',
      );
    } catch (err) {
      showToast('danger', String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleInspectServer = async (serverID: string) => {
    setInspectingId(serverID);
    try {
      const res = await api.inspectSingleServer(serverID);
      setSummary(res);
      await refreshHistory();
      showToast('success', 'Read-only live MCP handshake & tool schema extraction completed.');
    } catch (err) {
      showToast('danger', `Live inspection error: ${String(err)}`);
    } finally {
      setInspectingId(null);
    }
  };

  const handleApproveBaseline = async (serverID: string) => {
    try {
      const res = await api.approveBaseline(serverID);
      setSummary(res);
      showToast('success', 'SHA-256 tool schema baseline pinned in SQLite for Rug Pull monitoring.');
    } catch (err) {
      showToast('danger', String(err));
    }
  };

  const handleRevokeBaseline = async (serverID: string) => {
    try {
      const res = await api.revokeBaseline(serverID);
      setSummary(res);
      showToast('info', 'Trusted baseline revoked.');
    } catch (err) {
      showToast('danger', String(err));
    }
  };

  const handleBrowseConfig = async () => {
    try {
      const picked = await api.browseConfigFile();
      if (picked) setCustomPath(picked);
    } catch (err) {
      showToast('danger', String(err));
    }
  };

  const handleAddCustomConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!customPath.trim()) return;
    try {
      const res = await api.addCustomConfigPath(customLabel.trim(), customPath.trim());
      setSummary(res);
      setCustomLabel('');
      setCustomPath('');
      showToast('success', 'Custom MCP configuration added and audited.');
    } catch (err) {
      showToast('danger', String(err));
    }
  };

  const handleRemoveCustomConfig = async (path: string) => {
    try {
      const res = await api.removeCustomConfigPath(path);
      setSummary(res);
      showToast('info', 'Custom configuration removed.');
    } catch (err) {
      showToast('danger', String(err));
    }
  };

  const handleExportJSON = async () => {
    try {
      const savedPath = await api.exportAuditJSON();
      if (savedPath) {
        showToast('success', `Audit report exported to ${savedPath}`);
      }
    } catch (err) {
      showToast('danger', `Export failed: ${String(err)}`);
    }
  };

  // Phase 2 Handlers
  const handleResolveApproval = async (
    id: string,
    decision: 'APPROVE_ONCE' | 'APPROVE_SESSION' | 'DENY',
  ) => {
    try {
      await api.resolveApproval(id, decision);
      setApprovalQueue((prev) => prev.filter((p) => p.id !== id));
      refreshFirewall();
      showToast(
        decision === 'DENY' ? 'danger' : 'success',
        decision === 'APPROVE_SESSION'
          ? 'Tool call approved for current session.'
          : decision === 'APPROVE_ONCE'
            ? 'Tool call approved once.'
            : 'Tool call denied by user.',
      );
    } catch (err) {
      showToast('danger', String(err));
    }
  };

  const handleSavePolicy = async () => {
    setPolicySaving(true);
    setPolicyError(null);
    try {
      const st = await api.savePolicyYAML(policyYAML);
      setFwStatus(st);
      setPolicyDirty(false);
      showToast('success', `Policy saved and hot-reloaded (${st.activeRulesCount} active rules).`);
    } catch (err) {
      setPolicyError(String(err));
    } finally {
      setPolicySaving(false);
    }
  };

  const handleResetPolicy = async () => {
    setPolicySaving(true);
    setPolicyError(null);
    try {
      const def = await api.resetPolicyYAML();
      setPolicyYAML(def);
      setPolicyDirty(false);
      await refreshFirewall();
      showToast('info', 'Restored default AppSec YAML policy.');
    } catch (err) {
      setPolicyError(String(err));
    } finally {
      setPolicySaving(false);
    }
  };

  const handleClearTrafficLogs = async () => {
    try {
      await api.clearTrafficLogs();
      setTraffic([]);
      showToast('info', 'Runtime firewall traffic log cleared.');
    } catch (err) {
      showToast('danger', String(err));
    }
  };

  const handleClearSessionApprovals = async () => {
    try {
      const st = await api.clearSessionApprovals();
      setFwStatus(st);
      showToast('info', 'All session-scoped HITL approvals revoked.');
    } catch (err) {
      showToast('danger', String(err));
    }
  };

  const handleSimulateFirewall = async (
    scenario: 'deny_ssh' | 'hitl_shell' | 'dlp_leak' | 'indirect_injection',
  ) => {
    try {
      const msg = await api.simulateFirewallScenario(scenario);
      showToast(scenario === 'deny_ssh' || scenario === 'indirect_injection' ? 'danger' : 'info', msg);
    } catch (err) {
      showToast('danger', String(err));
    }
  };

  const handleProtectServer = async (serverID: string, protect: boolean) => {
    try {
      const res = protect
        ? await api.protectServerWithProxy(serverID)
        : await api.unprotectServerProxy(serverID);
      setSummary(res);
      showToast(
        'success',
        protect
          ? 'Server wrapped with mcpguard-proxy (backup saved to .mcpguard.bak). Restart your AI client to enforce!'
          : 'Server unwrapped back to its original MCP command.',
      );
    } catch (err) {
      showToast('danger', String(err));
    }
  };

  // Phase 3 Handlers
  const handleAddHTTPProxyRoute = async (serverName: string, upstreamURL: string) => {
    try {
      const st = await api.addHTTPProxyRoute(serverName, upstreamURL);
      setHttpProxyStatus(st);
      showToast('success', `HTTP/SSE proxy route registered for ${serverName}.`);
    } catch (err) {
      showToast('danger', String(err));
    }
  };

  const handleToggleHTTPProxyRoute = async (slug: string, enabled: boolean) => {
    try {
      const st = await api.toggleHTTPProxyRoute(slug, enabled);
      setHttpProxyStatus(st);
    } catch (err) {
      showToast('danger', String(err));
    }
  };

  const handleDeleteHTTPProxyRoute = async (slug: string) => {
    try {
      const st = await api.deleteHTTPProxyRoute(slug);
      setHttpProxyStatus(st);
      showToast('info', 'HTTP/SSE proxy route deleted.');
    } catch (err) {
      showToast('danger', String(err));
    }
  };

  const handleRunHTTPProxySelfTest = async () => {
    try {
      const msg = await api.runHTTPProxySelfTest();
      await refreshHttpProxy();
      await refreshFirewall();
      showToast('success', msg);
    } catch (err) {
      showToast('danger', String(err));
    }
  };

  const handleCopyURL = (url: string) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(url).catch(() => {});
    }
    showToast('info', `Copied protected endpoint URL: ${url}`);
  };

  const handleExportHTML = async () => {
    try {
      const p = await api.exportAuditHTML();
      if (p) showToast('success', `Executive HTML report saved to ${p} (open in browser & Ctrl+P for PDF).`);
    } catch (err) {
      showToast('danger', `HTML export failed: ${String(err)}`);
    }
  };

  const handleExportSARIF = async () => {
    try {
      const p = await api.exportAuditSARIF();
      if (p) showToast('success', `SARIF 2.1.0 CI/CD report saved to ${p}`);
    } catch (err) {
      showToast('danger', `SARIF export failed: ${String(err)}`);
    }
  };

  const handleExportMarkdown = async () => {
    try {
      const p = await api.exportAuditMarkdown();
      if (p) showToast('success', `Markdown report saved to ${p}`);
    } catch (err) {
      showToast('danger', `Markdown export failed: ${String(err)}`);
    }
  };

  const pageTitleMap: Record<NavTab, string> = {
    overview: 'Security Posture Overview',
    servers: 'MCP Server Inventory & Deep Inspector',
    findings: 'Security Findings & Remediations',
    configs: 'Local MCP Client Config Discovery',
    history: 'SQLite Audit History',
    firewall: 'Runtime MCP Firewall & Live JSON-RPC Inspector',
    httpproxy: 'HTTP / SSE Remote MCP Reverse Proxy',
    policy: 'YAML Policy Engine & DLP Configuration',
    compliance: 'OWASP Compliance, Policy Benchmark & Reports',
  };

  return (
    <div className="app-shell">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={19} />
          </div>
          <div>
            <div className="brand-title">MCPGuard</div>
            <div className="brand-sub">
              <span>AI Tool-Use Auditor</span>
              <span className="phase-tag">v1.0</span>
            </div>
          </div>
        </div>

        <div className="nav-section-label">Static Audit</div>
        <nav className="nav-list">
          <button
            className={`nav-item ${nav === 'overview' ? 'active' : ''}`}
            onClick={() => setNav('overview')}
          >
            <span className="nav-item-left">
              <Activity size={15} /> Overview
            </span>
          </button>

          <button
            className={`nav-item ${nav === 'servers' ? 'active' : ''}`}
            onClick={() => setNav('servers')}
          >
            <span className="nav-item-left">
              <Server size={15} /> MCP Servers
            </span>
            <span className="nav-badge">{summary?.totalServers ?? 0}</span>
          </button>

          <button
            className={`nav-item ${nav === 'findings' ? 'active' : ''}`}
            onClick={() => setNav('findings')}
          >
            <span className="nav-item-left">
              <ShieldAlert size={15} /> Findings
            </span>
            <span className={`nav-badge ${(summary?.criticalCount ?? 0) > 0 ? 'danger' : ''}`}>
              {summary?.totalFindings ?? 0}
            </span>
          </button>

          <button
            className={`nav-item ${nav === 'configs' ? 'active' : ''}`}
            onClick={() => setNav('configs')}
          >
            <span className="nav-item-left">
              <FileSearch size={15} /> Config Discovery
            </span>
            <span className="nav-badge">{summary?.foundConfigs ?? 0}</span>
          </button>

          <button
            className={`nav-item ${nav === 'history' ? 'active' : ''}`}
            onClick={() => {
              setNav('history');
              refreshHistory();
            }}
          >
            <span className="nav-item-left">
              <History size={15} /> Audit History
            </span>
          </button>

          <div className="nav-section-label" style={{ marginTop: 10 }}>
            Runtime Firewall
          </div>

          <button
            className={`nav-item ${nav === 'firewall' ? 'active' : ''}`}
            onClick={() => {
              setNav('firewall');
              refreshFirewall();
            }}
          >
            <span className="nav-item-left">
              <Radio size={15} color={fwStatus?.running ? '#10b981' : undefined} /> Live Firewall
            </span>
            <span className="nav-badge">{traffic.length}</span>
          </button>

          <button
            className={`nav-item ${nav === 'httpproxy' ? 'active' : ''}`}
            onClick={() => {
              setNav('httpproxy');
              refreshHttpProxy();
            }}
          >
            <span className="nav-item-left">
              <Globe size={15} /> HTTP/SSE Proxy
            </span>
            <span className="nav-badge">{httpProxyStatus?.routes?.length ?? 0}</span>
          </button>

          <button
            className={`nav-item ${nav === 'policy' ? 'active' : ''}`}
            onClick={() => {
              setNav('policy');
              if (!policyYAML) loadPolicy();
            }}
          >
            <span className="nav-item-left">
              <Sliders size={15} /> Policy Engine
            </span>
            <span className="nav-badge">{fwStatus?.activeRulesCount ?? 0}</span>
          </button>

          <button
            className={`nav-item ${nav === 'compliance' ? 'active' : ''}`}
            onClick={() => {
              setNav('compliance');
              refreshCompliance();
            }}
          >
            <span className="nav-item-left">
              <Award size={15} /> Compliance &amp; Reports
            </span>
            {complianceReport && <span className="nav-badge">{complianceReport.overallGrade}</span>}
          </button>
        </nav>

        {/* Built-in Vulnerable Demo Lab */}
        <div className="demo-box">
          <div className="demo-box-header">
            <span className="demo-box-title">
              <FlaskConical size={14} color="#38bdf8" /> Demo Security Lab
            </span>
            <span className={`pill ${summary?.demoModeActive ? 'pill-trusted' : ''}`}>
              {summary?.demoModeActive ? 'ON' : 'OFF'}
            </span>
          </div>
          <p className="demo-box-desc">
            Simulate Tool Poisoning, Unicode smuggling, Rug Pull drift &amp; shadowing safely.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <button
              className={`btn btn-sm btn-full ${summary?.demoModeActive ? '' : 'btn-primary'}`}
              onClick={handleToggleDemo}
              disabled={loading}
            >
              <FlaskConical size={13} />
              {summary?.demoModeActive ? 'Disable Demo Lab' : 'Load Demo Lab'}
            </button>
            {summary?.demoModeActive && (
              <button
                className={`btn btn-sm btn-full ${rugPullActive ? 'btn-success' : 'btn-danger'}`}
                onClick={handleToggleRugPull}
                disabled={loading}
              >
                <Zap size={13} />
                {rugPullActive ? 'Revert Rug Pull' : 'Simulate Rug Pull'}
              </button>
            )}
          </div>
        </div>
      </aside>

      {/* Main Column */}
      <main className="main-area">
        <header className="topbar">
          <div className="topbar-left">
            <h1>{pageTitleMap[nav]}</h1>
            <div className="topbar-meta">
              <span>Last scan: {formatTime(summary?.lastScanAt)}</span>
              {progress && (
                <span style={{ color: '#38bdf8' }}>
                  • Inspecting {progress.server} ({progress.completed}/{progress.total})
                </span>
              )}
            </div>
          </div>

          <div className="topbar-actions">
            <button className="btn" onClick={() => runScan(false)} disabled={loading}>
              <RefreshCw size={14} className={loading ? 'spin' : ''} />
              Quick Scan
            </button>
            <button className="btn btn-primary" onClick={() => runScan(true)} disabled={loading}>
              <Zap size={14} />
              Live Inspect All
            </button>
            <button className="btn" onClick={handleExportJSON} disabled={!summary}>
              <Download size={14} />
              Export JSON
            </button>
          </div>
        </header>

        <div className="content-scroll">
          {toast && (
            <div className={`banner banner-${toast.kind}`}>
              <span>{toast.text}</span>
              <button className="btn btn-sm" onClick={() => setToast(null)}>
                Dismiss
              </button>
            </div>
          )}

          {/* OVERVIEW TAB */}
          {nav === 'overview' && summary && (
            <>
              {summary.totalServers === 0 && (
                <div className="banner banner-info">
                  <div>
                    <strong>No local MCP servers detected yet.</strong> Add a custom MCP JSON config in{' '}
                    <em>Config Discovery</em> or activate the <strong>Demo Security Lab</strong> in the sidebar to test all
                    Phase 1 detectors immediately.
                  </div>
                  <button className="btn btn-primary btn-sm" onClick={handleToggleDemo}>
                    <FlaskConical size={13} /> Load Demo Lab
                  </button>
                </div>
              )}

              {summary.driftCount > 0 && (
                <div className="banner banner-danger">
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <AlertOctagon size={16} />
                    <span>
                      <strong>Rug Pull Alert:</strong> {summary.driftCount} baselined MCP server(s) changed tool schemas
                      since approval!
                    </span>
                  </div>
                  <button
                    className="btn btn-danger btn-sm"
                    onClick={() => {
                      const drifted = summary.servers.find((s) => s.baselineStatus === 'DRIFT_DETECTED');
                      if (drifted) setSelectedServerId(drifted.server.id);
                      setNav('servers');
                      setDetailTab('drift');
                    }}
                  >
                    Inspect Drift
                  </button>
                </div>
              )}

              {/* KPI Grid */}
              <div className="kpi-grid">
                <div className="card kpi-card">
                  <div className="kpi-label">
                    <span>Discovered Servers</span>
                    <Server size={15} color="#38bdf8" />
                  </div>
                  <div className="kpi-value">{summary.totalServers}</div>
                  <div className="kpi-sub">
                    From {summary.foundConfigs} of {summary.totalConfigs} config paths
                  </div>
                </div>

                <div className="card kpi-card">
                  <div className="kpi-label">
                    <span>Inspected MCP Tools</span>
                    <Wrench size={15} color="#a78bfa" />
                  </div>
                  <div className="kpi-value">{summary.totalTools}</div>
                  <div className="kpi-sub">{summary.baselinedCount} server(s) baselined (SHA-256)</div>
                </div>

                <div className="card kpi-card">
                  <div className="kpi-label">
                    <span>Critical &amp; High Alerts</span>
                    <ShieldAlert size={15} color="#ef4444" />
                  </div>
                  <div className="kpi-value" style={{ color: summary.criticalCount > 0 ? '#ef4444' : '#f1f5f9' }}>
                    {summary.criticalCount + summary.highCount}
                  </div>
                  <div className="kpi-sub">
                    {summary.criticalCount} Critical · {summary.highCount} High
                  </div>
                </div>

                <div className="card kpi-card">
                  <div className="kpi-label">
                    <span>Schema Drift (Rug Pull)</span>
                    <AlertTriangle size={15} color={summary.driftCount > 0 ? '#ef4444' : '#10b981'} />
                  </div>
                  <div className="kpi-value" style={{ color: summary.driftCount > 0 ? '#ef4444' : '#10b981' }}>
                    {summary.driftCount}
                  </div>
                  <div className="kpi-sub">
                    {summary.driftCount > 0 ? 'Action required immediately' : 'All baselines intact'}
                  </div>
                </div>
              </div>

              {/* Posture & Severity Distribution */}
              <div className="overview-grid">
                <div className="card">
                  <div className="section-header">
                    <div className="section-title">
                      <ShieldCheck size={15} color="#38bdf8" /> Security Posture
                    </div>
                  </div>
                  <div className="posture-wrap">
                    <div
                      className="posture-ring"
                      style={{
                        background: `conic-gradient(${postureColor(summary.postureScore)} ${
                          summary.postureScore * 3.6
                        }deg, #1c283f 0deg)`,
                      }}
                    >
                      <div className="posture-inner">
                        <div className="posture-score" style={{ color: postureColor(summary.postureScore) }}>
                          {summary.postureScore}
                        </div>
                        <div className="posture-label">/ 100</div>
                      </div>
                    </div>
                    <div style={{ fontSize: 12.5, color: '#94a3b8' }}>
                      {summary.postureScore >= 85
                        ? 'Strong MCP hygiene'
                        : summary.postureScore >= 60
                          ? 'Moderate risk — review findings'
                          : 'High exposure — immediate remediation advised'}
                    </div>
                  </div>
                </div>

                <div className="card">
                  <div className="section-header">
                    <div className="section-title">Findings by Severity</div>
                    <button className="btn btn-sm" onClick={() => setNav('findings')}>
                      View All ({summary.totalFindings})
                    </button>
                  </div>
                  {(
                    [
                      ['CRITICAL', summary.criticalCount, '#ef4444'],
                      ['HIGH', summary.highCount, '#f97316'],
                      ['MEDIUM', summary.mediumCount, '#eab308'],
                      ['LOW', summary.lowCount, '#38bdf8'],
                      ['INFO', summary.infoCount, '#94a3b8'],
                    ] as const
                  ).map(([label, count, color]) => {
                    const pct = summary.totalFindings > 0 ? Math.round((count / summary.totalFindings) * 100) : 0;
                    return (
                      <div className="sev-bar-row" key={label}>
                        <span style={{ fontSize: 11.5, fontWeight: 600, color }}>{label}</span>
                        <div className="sev-track">
                          <div className="sev-fill" style={{ width: `${pct}%`, background: color }} />
                        </div>
                        <span className="mono" style={{ textAlign: 'right', color: '#cbd5e1' }}>
                          {count}
                        </span>
                      </div>
                    );
                  })}

                  <div style={{ marginTop: 18, borderTop: '1px solid #1f2b42', paddingTop: 12 }}>
                    <div className="section-title" style={{ fontSize: 12.5, marginBottom: 8 }}>
                      Server Risk Breakdown
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                      {summary.servers.slice(0, 5).map((s) => (
                        <div
                          key={s.server.id}
                          onClick={() => {
                            setSelectedServerId(s.server.id);
                            setNav('servers');
                          }}
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            padding: '7px 10px',
                            borderRadius: 7,
                            background: 'rgba(11,15,23,0.5)',
                            cursor: 'pointer',
                            border: '1px solid #1f2b42',
                          }}
                        >
                          <div>
                            <span style={{ fontWeight: 600 }}>{s.server.serverName}</span>
                            <span style={{ color: '#64748b', fontSize: 11.5, marginLeft: 8 }}>
                              {s.server.clientName} · {s.tools.length} tool(s)
                            </span>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span className={`badge badge-${s.riskLevel}`}>
                              {s.riskLevel} ({s.riskScore})
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* Top Critical & High Findings */}
              <div className="card">
                <div className="section-header">
                  <div className="section-title">
                    <AlertOctagon size={15} color="#ef4444" /> Top Priority Findings
                  </div>
                  <button className="btn btn-sm" onClick={() => setNav('findings')}>
                    Open Findings Explorer
                  </button>
                </div>
                {allFindings.length === 0 ? (
                  <div className="empty-state" style={{ padding: '24px 12px' }}>
                    <CheckCircle2 size={28} color="#10b981" />
                    <h3>Zero Security Findings</h3>
                    <p>No static, poisoning, supply-chain, or drift issues detected across audited servers.</p>
                  </div>
                ) : (
                  allFindings.slice(0, 5).map(({ finding }) => <FindingCard key={finding.id} finding={finding} />)
                )}
              </div>
            </>
          )}

          {/* SERVERS MASTER-DETAIL TAB */}
          {nav === 'servers' && summary && (
            <div className="split-view">
              <div className="server-list-pane">
                {summary.servers.length === 0 ? (
                  <div className="empty-state">
                    <Server size={28} color="#64748b" />
                    <h3>No Servers Found</h3>
                    <p>Enable Demo Lab or add a config file to inspect MCP servers.</p>
                  </div>
                ) : (
                  summary.servers.map((s) => (
                    <button
                      key={s.server.id}
                      className={`server-list-item ${selectedServerId === s.server.id ? 'selected' : ''}`}
                      onClick={() => setSelectedServerId(s.server.id)}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                        <strong style={{ fontSize: 13 }}>{s.server.serverName}</strong>
                        <span className={`badge badge-${s.riskLevel}`}>{s.riskLevel}</span>
                      </div>
                      <div style={{ fontSize: 11.5, color: '#94a3b8', marginTop: 4 }}>
                        {s.server.clientName} · <span className="mono">{s.server.transport}</span>
                      </div>
                      <div style={{ display: 'flex', gap: 6, marginTop: 8, flexWrap: 'wrap' }}>
                        <span className="pill">{s.tools.length} tools</span>
                        <span className="pill">{s.findings.length} findings</span>
                        {s.server.isProtected && <span className="pill pill-trusted">Firewall Proxy</span>}
                        {s.baselineStatus === 'DRIFT_DETECTED' && <span className="pill pill-drift">DRIFT</span>}
                        {s.baselineStatus === 'BASELINE_MATCH' && <span className="pill pill-trusted">Baselined</span>}
                      </div>
                    </button>
                  ))
                )}
              </div>

              <div className="server-detail-pane">
                {!selectedServer ? (
                  <div className="empty-state">
                    <Shield size={32} color="#64748b" />
                    <h3>Select an MCP Server</h3>
                    <p>Choose a server on the left to inspect its tools, security findings, and SHA-256 baseline.</p>
                  </div>
                ) : (
                  <>
                    <div className="detail-header">
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                          <h2 style={{ fontSize: 17 }}>{selectedServer.server.serverName}</h2>
                          <span className={`badge badge-${selectedServer.riskLevel}`}>
                            {selectedServer.riskLevel} · Risk {selectedServer.riskScore}/100
                          </span>
                          {selectedServer.baselineStatus === 'DRIFT_DETECTED' && (
                            <span className="pill pill-drift">
                              <AlertOctagon size={12} /> Rug Pull Drift
                            </span>
                          )}
                          {selectedServer.baselineStatus === 'BASELINE_MATCH' && (
                            <span className="pill pill-trusted">
                              <Lock size={12} /> Trusted Baseline
                            </span>
                          )}
                        </div>
                        <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 4 }}>
                          {selectedServer.server.clientName} · Transport:{' '}
                          <span className="mono">{selectedServer.server.transport}</span>
                          {selectedServer.serverInfo && <> · Server: {selectedServer.serverInfo}</>}
                        </div>
                      </div>

                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        {!selectedServer.server.isDemo && selectedServer.server.transport === 'stdio' && (
                          selectedServer.server.isProtected ? (
                            <button
                              className="btn btn-sm btn-danger"
                              onClick={() => handleProtectServer(selectedServer.server.id, false)}
                              title="Unwrap mcpguard-proxy and restore original command"
                            >
                              <ShieldOff size={13} /> Unwrap Proxy
                            </button>
                          ) : (
                            <button
                              className="btn btn-sm btn-success"
                              onClick={() => handleProtectServer(selectedServer.server.id, true)}
                              title="Wrap this stdio server with mcpguard-proxy for live firewall enforcement"
                            >
                              <ShieldCheck size={13} /> Protect via Proxy
                            </button>
                          )
                        )}
                        {!selectedServer.server.isDemo && (
                          <button
                            className="btn btn-sm btn-primary"
                            onClick={() => handleInspectServer(selectedServer.server.id)}
                            disabled={inspectingId === selectedServer.server.id}
                          >
                            <Zap size={13} />
                            {inspectingId === selectedServer.server.id ? 'Inspecting...' : 'Live Inspect'}
                          </button>
                        )}
                        <button
                          className="btn btn-sm btn-success"
                          onClick={() => handleApproveBaseline(selectedServer.server.id)}
                          disabled={selectedServer.tools.length === 0}
                          title="Save current tool SHA-256 hashes as trusted baseline"
                        >
                          <Lock size={13} /> Approve Baseline
                        </button>
                        {selectedServer.baselineStatus !== 'UNTRUSTED' && (
                          <button
                            className="btn btn-sm"
                            onClick={() => handleRevokeBaseline(selectedServer.server.id)}
                          >
                            <Unlock size={13} /> Revoke
                          </button>
                        )}
                      </div>
                    </div>

                    {selectedServer.liveInspectionError && (
                      <div style={{ padding: '10px 18px 0' }}>
                        <div className="banner banner-danger" style={{ marginBottom: 0 }}>
                          <span>
                            <strong>Live Inspection Note:</strong> {selectedServer.liveInspectionError}
                          </span>
                        </div>
                      </div>
                    )}

                    <div className="detail-tabs">
                      <button
                        className={`tab-btn ${detailTab === 'findings' ? 'active' : ''}`}
                        onClick={() => setDetailTab('findings')}
                      >
                        Findings ({selectedServer.findings.length})
                      </button>
                      <button
                        className={`tab-btn ${detailTab === 'tools' ? 'active' : ''}`}
                        onClick={() => setDetailTab('tools')}
                      >
                        Tools &amp; Schemas ({selectedServer.tools.length})
                      </button>
                      <button
                        className={`tab-btn ${detailTab === 'drift' ? 'active' : ''}`}
                        onClick={() => setDetailTab('drift')}
                      >
                        Baseline &amp; Drift ({selectedServer.driftChanges.length})
                      </button>
                      <button
                        className={`tab-btn ${detailTab === 'config' ? 'active' : ''}`}
                        onClick={() => setDetailTab('config')}
                      >
                        Config &amp; Env
                      </button>
                    </div>

                    <div className="detail-body">
                      {detailTab === 'findings' && (
                        <>
                          {selectedServer.findings.length === 0 ? (
                            <div className="empty-state">
                              <CheckCircle2 size={30} color="#10b981" />
                              <h3>Clean Audit</h3>
                              <p>No security findings detected for this MCP server.</p>
                            </div>
                          ) : (
                            selectedServer.findings.map((f) => <FindingCard key={f.id} finding={f} />)
                          )}
                        </>
                      )}

                      {detailTab === 'tools' && (
                        <>
                          {selectedServer.tools.length === 0 ? (
                            <div className="empty-state">
                              <Wrench size={28} color="#64748b" />
                              <h3>No Tools Inspected Yet</h3>
                              <p>
                                Click <strong>Live Inspect</strong> to perform a safe read-only MCP handshake (
                                <span className="mono">initialize</span> → <span className="mono">tools/list</span>).
                              </p>
                            </div>
                          ) : (
                            selectedServer.tools.map((t) => (
                              <div key={t.name} className="finding-card" style={{ borderLeftColor: '#38bdf8' }}>
                                <div className="finding-header">
                                  <div className="finding-title">
                                    <Wrench size={14} color="#38bdf8" />
                                    <span className="mono" style={{ fontSize: 13 }}>
                                      {t.name}
                                    </span>
                                  </div>
                                  <span className="pill mono" title={t.schemaHash}>
                                    SHA-256: {shortHash(t.schemaHash)}
                                  </span>
                                </div>
                                <div style={{ color: '#cbd5e1', fontSize: 12.5, whiteSpace: 'pre-wrap' }}>
                                  {t.description || <em>(No description provided)</em>}
                                </div>
                                {t.inputSchema && (
                                  <pre className="code-block">{JSON.stringify(t.inputSchema, null, 2)}</pre>
                                )}
                              </div>
                            ))
                          )}
                        </>
                      )}

                      {detailTab === 'drift' && (
                        <>
                          <div className="card" style={{ marginBottom: 14, background: 'rgba(11,15,23,0.45)' }}>
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
                              <div>
                                <div style={{ fontSize: 11, color: '#64748b' }}>BASELINE STATUS</div>
                                <div style={{ fontWeight: 700, marginTop: 4 }}>{selectedServer.baselineStatus}</div>
                              </div>
                              <div>
                                <div style={{ fontSize: 11, color: '#64748b' }}>APPROVED HASH</div>
                                <div className="mono" style={{ marginTop: 4 }}>
                                  {shortHash(selectedServer.baselineHash)}
                                </div>
                              </div>
                              <div>
                                <div style={{ fontSize: 11, color: '#64748b' }}>CURRENT HASH</div>
                                <div className="mono" style={{ marginTop: 4 }}>
                                  {shortHash(selectedServer.currentHash)}
                                </div>
                              </div>
                            </div>
                            {selectedServer.baselineApprovedAt && (
                              <div style={{ fontSize: 11.5, color: '#94a3b8', marginTop: 10 }}>
                                Approved at: {formatTime(selectedServer.baselineApprovedAt)}
                              </div>
                            )}
                          </div>

                          {selectedServer.driftChanges.length === 0 ? (
                            <div className="empty-state">
                              <Lock size={28} color="#10b981" />
                              <h3>
                                {selectedServer.baselineStatus === 'UNTRUSTED'
                                  ? 'No Baseline Pinned Yet'
                                  : 'No Schema Drift Detected'}
                              </h3>
                              <p>
                                {selectedServer.baselineStatus === 'UNTRUSTED'
                                  ? 'Click "Approve Baseline" to pin the current SHA-256 hashes of this server’s tools so MCPGuard can alert you on future Rug Pull mutations.'
                                  : 'Every exposed tool matches its approved SHA-256 fingerprint.'}
                              </p>
                            </div>
                          ) : (
                            selectedServer.driftChanges.map((ch) => (
                              <div key={ch.toolName} className="finding-card sev-CRITICAL">
                                <div className="finding-header">
                                  <div className="finding-title">
                                    <span className="badge badge-CRITICAL">{ch.changeType}</span>
                                    <span className="mono">{ch.toolName}</span>
                                  </div>
                                  <span className="mono" style={{ color: '#94a3b8' }}>
                                    {shortHash(ch.previousHash)} → {shortHash(ch.currentHash)}
                                  </span>
                                </div>
                                <div className="diff-box">
                                  <div className="diff-old">
                                    <div style={{ fontSize: 11, fontWeight: 700, color: '#fca5a5', marginBottom: 4 }}>
                                      PREVIOUS APPROVED DESCRIPTION
                                    </div>
                                    <div className="mono" style={{ color: '#e2e8f0', whiteSpace: 'pre-wrap' }}>
                                      {ch.previousDescription || '(Tool did not exist in baseline)'}
                                    </div>
                                  </div>
                                  <div className="diff-new">
                                    <div style={{ fontSize: 11, fontWeight: 700, color: '#fde047', marginBottom: 4 }}>
                                      CURRENT MUTATED DESCRIPTION
                                    </div>
                                    <div className="mono" style={{ color: '#e2e8f0', whiteSpace: 'pre-wrap' }}>
                                      {ch.currentDescription || '(Tool removed)'}
                                    </div>
                                  </div>
                                </div>
                              </div>
                            ))
                          )}
                        </>
                      )}

                      {detailTab === 'config' && (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                          <div>
                            <div style={{ fontSize: 11.5, color: '#94a3b8', marginBottom: 4 }}>Config File Path</div>
                            <div className="code-block" style={{ marginTop: 0 }}>
                              {selectedServer.server.configPath}
                            </div>
                          </div>

                          {selectedServer.server.transport === 'stdio' ? (
                            <div>
                              <div style={{ fontSize: 11.5, color: '#94a3b8', marginBottom: 4 }}>
                                <Terminal size={12} style={{ verticalAlign: 'middle', marginRight: 5 }} />
                                Spawn Command &amp; Arguments
                              </div>
                              <div className="code-block" style={{ marginTop: 0 }}>
                                {selectedServer.server.command} {(selectedServer.server.args ?? []).join(' ')}
                              </div>
                            </div>
                          ) : (
                            <div>
                              <div style={{ fontSize: 11.5, color: '#94a3b8', marginBottom: 4 }}>Endpoint URL</div>
                              <div className="code-block" style={{ marginTop: 0 }}>
                                {selectedServer.server.url}
                              </div>
                            </div>
                          )}

                          <div>
                            <div style={{ fontSize: 11.5, color: '#94a3b8', marginBottom: 6 }}>
                              Environment Variables (Sensitive values automatically masked)
                            </div>
                            {selectedServer.server.maskedEnv &&
                            Object.keys(selectedServer.server.maskedEnv).length > 0 ? (
                              <table className="data-table">
                                <thead>
                                  <tr>
                                    <th>Key</th>
                                    <th>Value (Masked)</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {Object.entries(selectedServer.server.maskedEnv).map(([k, v]) => (
                                    <tr key={k}>
                                      <td className="mono">{k}</td>
                                      <td className="mono" style={{ color: '#94a3b8' }}>
                                        {v}
                                      </td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            ) : (
                              <div style={{ color: '#64748b', fontSize: 12 }}>No custom environment variables defined.</div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>
            </div>
          )}

          {/* FINDINGS EXPLORER TAB */}
          {nav === 'findings' && summary && (
            <>
              <div className="filter-bar">
                <div style={{ position: 'relative', flex: 1, minWidth: 220 }}>
                  <Search
                    size={14}
                    color="#64748b"
                    style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)' }}
                  />
                  <input
                    className="input"
                    style={{ width: '100%', paddingLeft: 32 }}
                    placeholder="Search rule ID, title, evidence, server, or tool..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                  />
                </div>

                <select className="select" value={sevFilter} onChange={(e) => setSevFilter(e.target.value)}>
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                  <option value="INFO">INFO</option>
                </select>

                <select className="select" value={catFilter} onChange={(e) => setCatFilter(e.target.value)}>
                  <option value="ALL">All Categories</option>
                  {categories.map((c) => (
                    <option key={c} value={c}>
                      {c}
                    </option>
                  ))}
                </select>
              </div>

              {filteredFindings.length === 0 ? (
                <div className="card empty-state">
                  <CheckCircle2 size={30} color="#10b981" />
                  <h3>No Matching Findings</h3>
                  <p>Adjust your filters or run a scan to inspect MCP servers.</p>
                </div>
              ) : (
                filteredFindings.map(({ finding }) => <FindingCard key={finding.id} finding={finding} />)
              )}
            </>
          )}

          {/* CONFIG DISCOVERY TAB */}
          {nav === 'configs' && summary && (
            <>
              <div className="card" style={{ marginBottom: 16 }}>
                <div className="section-header">
                  <div className="section-title">
                    <Plus size={15} color="#38bdf8" /> Add Custom MCP Config File
                  </div>
                </div>
                <form onSubmit={handleAddCustomConfig} style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  <input
                    className="input"
                    style={{ width: 200 }}
                    placeholder="Label (e.g. Project MCP)"
                    value={customLabel}
                    onChange={(e) => setCustomLabel(e.target.value)}
                  />
                  <input
                    className="input"
                    style={{ flex: 1, minWidth: 260 }}
                    placeholder="Absolute path to mcp.json / claude_desktop_config.json"
                    value={customPath}
                    onChange={(e) => setCustomPath(e.target.value)}
                  />
                  <button type="button" className="btn" onClick={handleBrowseConfig}>
                    <FolderOpen size={14} /> Browse...
                  </button>
                  <button type="submit" className="btn btn-primary" disabled={!customPath.trim()}>
                    <Plus size={14} /> Add &amp; Scan
                  </button>
                </form>
              </div>

              <div className="card">
                <div className="section-header">
                  <div className="section-title">
                    <FileCode2 size={15} color="#38bdf8" /> Scanned Client Configuration Paths
                  </div>
                </div>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Client / Source</th>
                      <th>Config File Path</th>
                      <th>Status</th>
                      <th>Servers</th>
                      <th style={{ textAlign: 'right' }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {summary.discoveredConfigs.map((cfg) => (
                      <tr key={cfg.path}>
                        <td style={{ fontWeight: 600 }}>{cfg.clientName}</td>
                        <td className="mono" style={{ color: '#94a3b8' }}>
                          {cfg.path}
                          {cfg.parseError && (
                            <div style={{ color: '#fca5a5', fontSize: 11, marginTop: 2 }}>{cfg.parseError}</div>
                          )}
                        </td>
                        <td>
                          {cfg.exists ? (
                            <span className="pill pill-trusted">Found</span>
                          ) : (
                            <span className="pill">Not Found</span>
                          )}
                        </td>
                        <td className="mono">{cfg.serverCount}</td>
                        <td style={{ textAlign: 'right' }}>
                          {cfg.isCustom && !cfg.path.startsWith('mcpguard://') && (
                            <button
                              className="btn btn-sm btn-danger"
                              onClick={() => handleRemoveCustomConfig(cfg.path)}
                            >
                              <Trash2 size={12} /> Remove
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {/* AUDIT HISTORY TAB */}
          {nav === 'history' && (
            <div className="card">
              <div className="section-header">
                <div className="section-title">
                  <History size={15} color="#38bdf8" /> Persisted Audit Snapshots (SQLite)
                </div>
                <button className="btn btn-sm" onClick={refreshHistory}>
                  <RefreshCw size={12} /> Refresh
                </button>
              </div>
              {history.length === 0 ? (
                <div className="empty-state">
                  <History size={28} color="#64748b" />
                  <h3>No Audit History Yet</h3>
                  <p>Run a scan or enable Demo Lab to start recording audit snapshots.</p>
                </div>
              ) : (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Server</th>
                      <th>Client</th>
                      <th>Tools</th>
                      <th>Findings</th>
                      <th>Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((h) => (
                      <tr key={h.id}>
                        <td className="mono" style={{ color: '#94a3b8' }}>
                          {formatTime(h.scannedAt)}
                        </td>
                        <td style={{ fontWeight: 600 }}>{h.serverName}</td>
                        <td>{h.clientName}</td>
                        <td className="mono">{h.toolCount}</td>
                        <td className="mono">{h.findingsCount}</td>
                        <td>
                          <span className={`badge badge-${h.riskLevel}`}>
                            {h.riskLevel} ({h.riskScore})
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
          {/* LIVE FIREWALL TAB (PHASE 2) */}
          {nav === 'firewall' && (
            <FirewallView
              status={fwStatus}
              traffic={traffic}
              onRefresh={refreshFirewall}
              onClearLogs={handleClearTrafficLogs}
              onClearSessions={handleClearSessionApprovals}
              onSimulate={handleSimulateFirewall}
            />
          )}

          {/* HTTP / SSE REVERSE PROXY TAB (PHASE 3) */}
          {nav === 'httpproxy' && (
            <HttpProxyView
              status={httpProxyStatus}
              onRefresh={refreshHttpProxy}
              onAddRoute={handleAddHTTPProxyRoute}
              onToggleRoute={handleToggleHTTPProxyRoute}
              onDeleteRoute={handleDeleteHTTPProxyRoute}
              onRunSelfTest={handleRunHTTPProxySelfTest}
              onCopyURL={handleCopyURL}
            />
          )}

          {/* POLICY ENGINE TAB (PHASE 2) */}
          {nav === 'policy' && (
            <PolicyView
              yamlText={policyYAML}
              dirty={policyDirty}
              saving={policySaving}
              errorText={policyError}
              status={fwStatus}
              onChange={(next) => {
                setPolicyYAML(next);
                setPolicyDirty(true);
              }}
              onSave={handleSavePolicy}
              onReset={handleResetPolicy}
            />
          )}

          {/* COMPLIANCE & ENTERPRISE REPORTS TAB (PHASE 3) */}
          {nav === 'compliance' && (
            <ComplianceView
              report={complianceReport}
              onRefresh={refreshCompliance}
              onExportHTML={handleExportHTML}
              onExportSARIF={handleExportSARIF}
              onExportMarkdown={handleExportMarkdown}
              onExportJSON={handleExportJSON}
            />
          )}
        </div>
      </main>

      {/* Global Real-Time HITL Approval Modal */}
      <ApprovalModal
        approval={approvalQueue[0] ?? null}
        queueCount={approvalQueue.length}
        onResolve={handleResolveApproval}
      />
    </div>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div className={`finding-card sev-${finding.severity}`}>
      <div className="finding-header">
        <div className="finding-title">
          <span className={`badge badge-${finding.severity}`}>{finding.severity}</span>
          <span className="mono" style={{ color: '#94a3b8' }}>
            {finding.ruleId}
          </span>
          <span>{finding.title}</span>
        </div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <span className="pill">{finding.category}</span>
          <span className="pill mono">{finding.target}</span>
          {finding.owaspRef && (
            <span className="pill" style={{ color: '#7dd3fc' }}>
              {finding.owaspRef}
            </span>
          )}
        </div>
      </div>

      <p style={{ color: '#cbd5e1', fontSize: 12.5 }}>{finding.description}</p>

      {finding.evidence && (
        <div className="code-block">
          <strong style={{ color: '#94a3b8' }}>Evidence: </strong>
          {finding.evidence}
        </div>
      )}

      <div className="remediation-box">
        <strong>Remediation:</strong> {finding.remediation}
      </div>
    </div>
  );
}
