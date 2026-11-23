import React, { useMemo, useState } from 'react';
import {
  AlertOctagon,
  EyeOff,
  Flame,
  Play,
  Radio,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Trash2,
} from 'lucide-react';
import type { FirewallStatus, TrafficEvent } from '../types';

interface FirewallViewProps {
  status: FirewallStatus | null;
  traffic: TrafficEvent[];
  onRefresh: () => void;
  onClearLogs: () => void;
  onClearSessions: () => void;
  onSimulate: (scenario: 'deny_ssh' | 'hitl_shell' | 'dlp_leak' | 'indirect_injection') => void;
}

function formatTime(iso: string): string {
  try {
    return new Date(iso).toLocaleTimeString();
  } catch {
    return iso;
  }
}

export default function FirewallView({
  status,
  traffic,
  onRefresh,
  onClearLogs,
  onClearSessions,
  onSimulate,
}: FirewallViewProps) {
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [decisionFilter, setDecisionFilter] = useState<string>('ALL');

  const filtered = useMemo(() => {
    if (decisionFilter === 'ALL') return traffic;
    if (decisionFilter === 'BLOCKED') {
      return traffic.filter((t) => ['DENY', 'DENIED_USER', 'TIMEOUT'].includes(t.decision) || t.injectionDetected);
    }
    if (decisionFilter === 'DLP') {
      return traffic.filter((t) => (t.dlpHits && t.dlpHits.length > 0) || t.decision === 'REDACTED');
    }
    return traffic.filter((t) => t.decision === decisionFilter);
  }, [traffic, decisionFilter]);

  const selectedEvent = useMemo(
    () => filtered.find((e) => e.id === selectedId) ?? filtered[0] ?? null,
    [filtered, selectedId],
  );

  return (
    <>
      {/* Control Plane Status Bar */}
      <div className="kpi-grid" style={{ marginBottom: 16 }}>
        <div className="card kpi-card">
          <div className="kpi-label">
            <span>Control Plane IPC</span>
            <Radio size={14} color={status?.running ? '#10b981' : '#ef4444'} />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 2 }}>
            <span className={`status-dot ${status?.running ? 'online' : 'offline'}`} />
            <span style={{ fontWeight: 700, fontSize: 16 }}>{status?.running ? 'ONLINE' : 'OFFLINE'}</span>
          </div>
          <div className="kpi-sub mono">{status?.controlUrl || '127.0.0.1:43771'}</div>
        </div>

        <div className="card kpi-card">
          <div className="kpi-label">
            <span>Stdio Proxy Binary</span>
            <Terminal size={14} color={status?.proxyBinaryFound ? '#10b981' : '#eab308'} />
          </div>
          <div style={{ fontWeight: 700, fontSize: 16, marginTop: 2 }}>
            {status?.proxyBinaryFound ? 'Ready' : 'Not Built Yet'}
          </div>
          <div className="kpi-sub mono" title={status?.proxyBinaryPath} style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {status?.proxyBinaryPath || 'mcpguard-proxy.exe'}
          </div>
        </div>

        <div className="card kpi-card">
          <div className="kpi-label">
            <span>Active Policy &amp; Guards</span>
            <ShieldCheck size={14} color="#38bdf8" />
          </div>
          <div className="kpi-value" style={{ fontSize: 22 }}>
            {status?.activeRulesCount ?? 0} Rules
          </div>
          <div className="kpi-sub">
            DLP: {status?.dlpEnabled ? 'ON' : 'OFF'} · Injection Guard: {status?.injectionGuard ? 'ON' : 'OFF'}
          </div>
        </div>

        <div className="card kpi-card">
          <div className="kpi-label">
            <span>Session Grants</span>
            <Shield size={14} color="#a78bfa" />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 2 }}>
            <span className="kpi-value" style={{ fontSize: 22 }}>
              {status?.sessionApprovals?.length ?? 0}
            </span>
            {(status?.sessionApprovals?.length ?? 0) > 0 && (
              <button className="btn btn-sm" onClick={onClearSessions}>
                Revoke All
              </button>
            )}
          </div>
          <div className="kpi-sub">Temporary HITL session overrides</div>
        </div>
      </div>

      {/* Live Interactive Attack Simulator */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-header" style={{ marginBottom: 8 }}>
          <div className="section-title">
            <Play size={14} color="#38bdf8" /> Interactive Firewall Test Bench (Live Control Plane)
          </div>
          <span style={{ fontSize: 11.5, color: '#64748b' }}>
            Trigger real policy evaluations, HITL modals, DLP redaction &amp; injection blocks
          </span>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button className="btn btn-sm btn-danger" onClick={() => onSimulate('deny_ssh')}>
            <AlertOctagon size={13} /> Test Policy DENY (~/.ssh/id_rsa)
          </button>
          <button className="btn btn-sm btn-primary" onClick={() => onSimulate('hitl_shell')}>
            <ShieldAlert size={13} /> Test HITL Modal (run_command)
          </button>
          <button className="btn btn-sm" onClick={() => onSimulate('dlp_leak')}>
            <EyeOff size={13} /> Test DLP Secret Redaction
          </button>
          <button className="btn btn-sm btn-danger" onClick={() => onSimulate('indirect_injection')}>
            <Flame size={13} /> Test Indirect Prompt Injection
          </button>
        </div>
      </div>

      {/* Live Traffic Inspector Split View */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.35fr 1fr', gap: 14, minHeight: 420 }}>
        <div className="card" style={{ display: 'flex', flexDirection: 'column', padding: 14 }}>
          <div className="section-header">
            <div className="section-title">
              <Radio size={14} color="#10b981" /> Live JSON-RPC Traffic ({filtered.length})
            </div>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <select className="select" value={decisionFilter} onChange={(e) => setDecisionFilter(e.target.value)}>
                <option value="ALL">All Events</option>
                <option value="BLOCKED">Blocked / Injections</option>
                <option value="DLP">DLP Redacted</option>
                <option value="ALLOW">Allowed</option>
              </select>
              <button className="btn btn-sm" onClick={onRefresh}>
                <RefreshCw size={12} />
              </button>
              <button className="btn btn-sm btn-danger" onClick={onClearLogs}>
                <Trash2 size={12} /> Clear
              </button>
            </div>
          </div>

          {filtered.length === 0 ? (
            <div className="empty-state">
              <Radio size={28} color="#64748b" />
              <h3>No Runtime Traffic Captured Yet</h3>
              <p>
                Wrap a local stdio MCP server via <strong>MCP Servers → Protect via Proxy</strong> or click any button
                in the <strong>Test Bench</strong> above.
              </p>
            </div>
          ) : (
            <div style={{ overflowY: 'auto', maxHeight: 420 }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Server / Tool</th>
                    <th>Decision</th>
                    <th>Guard</th>
                    <th>Latency</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((ev) => (
                    <tr
                      key={ev.id || `${ev.requestId}-${ev.timestamp}`}
                      onClick={() => setSelectedId(ev.id)}
                      style={{
                        cursor: 'pointer',
                        background: selectedEvent?.id === ev.id ? 'rgba(56, 189, 248, 0.1)' : undefined,
                      }}
                    >
                      <td className="mono" style={{ color: '#94a3b8', whiteSpace: 'nowrap' }}>
                        {formatTime(ev.timestamp)}
                      </td>
                      <td>
                        <div style={{ fontWeight: 600 }}>{ev.serverName}</div>
                        <div className="mono" style={{ color: '#38bdf8', fontSize: 11 }}>
                          {ev.toolName || ev.method}
                        </div>
                      </td>
                      <td>
                        <span className={`decision-pill decision-${ev.decision}`}>{ev.decision}</span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {ev.ruleId && <span className="pill mono">{ev.ruleId}</span>}
                          {ev.dlpHits && ev.dlpHits.length > 0 && (
                            <span className="decision-pill decision-REDACTED">DLP ({ev.dlpHits.length})</span>
                          )}
                          {ev.injectionDetected && (
                            <span className="decision-pill decision-DENY">INJECTION</span>
                          )}
                        </div>
                      </td>
                      <td className="mono" style={{ color: '#94a3b8' }}>
                        {ev.latencyMs}ms
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Event Inspector Pane */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 10, padding: 14 }}>
          <div className="section-title">Packet &amp; Verdict Inspector</div>
          {!selectedEvent ? (
            <div className="empty-state" style={{ padding: 24 }}>
              <p>Select a traffic row to inspect payloads, policy match, and DLP/Injection findings.</p>
            </div>
          ) : (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 6 }}>
                <span className={`decision-pill decision-${selectedEvent.decision}`}>{selectedEvent.decision}</span>
                <span className="pill mono">{selectedEvent.direction}</span>
                <span className="mono" style={{ color: '#94a3b8' }}>
                  {selectedEvent.method}
                </span>
              </div>

              <div style={{ fontSize: 12.5, color: '#cbd5e1' }}>
                <strong>Server:</strong> {selectedEvent.serverName}
                {selectedEvent.toolName && (
                  <>
                    {' '}
                    · <strong>Tool:</strong> <span className="mono">{selectedEvent.toolName}</span>
                  </>
                )}
              </div>

              {selectedEvent.reason && (
                <div
                  style={{
                    padding: '8px 10px',
                    borderRadius: 7,
                    background: 'rgba(11,15,23,0.6)',
                    border: '1px solid #1f2b42',
                    fontSize: 12,
                  }}
                >
                  <strong>{selectedEvent.ruleId || 'Policy'}:</strong> {selectedEvent.reason}
                </div>
              )}

              {selectedEvent.dlpHits && selectedEvent.dlpHits.length > 0 && (
                <div className="banner banner-info" style={{ marginBottom: 0 }}>
                  <span>
                    <strong>DLP Redacted Secrets:</strong> {selectedEvent.dlpHits.join(', ')}
                  </span>
                </div>
              )}

              {selectedEvent.injectionDetected && (
                <div className="banner banner-danger" style={{ marginBottom: 0 }}>
                  <span>
                    <strong>Indirect Prompt Injection Evidence:</strong>{' '}
                    <span className="mono">{selectedEvent.injectionEvidence}</span>
                  </span>
                </div>
              )}

              {selectedEvent.argsPreview && (
                <div>
                  <div style={{ fontSize: 11, color: '#94a3b8' }}>REQUEST ARGUMENTS (POST-DLP)</div>
                  <pre className="code-block" style={{ maxHeight: 160 }}>
                    {selectedEvent.argsPreview}
                  </pre>
                </div>
              )}

              {selectedEvent.responsePreview && (
                <div>
                  <div style={{ fontSize: 11, color: '#94a3b8' }}>TOOL RESPONSE (POST-DLP)</div>
                  <pre className="code-block" style={{ maxHeight: 160 }}>
                    {selectedEvent.responsePreview}
                  </pre>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </>
  );
}
