import React, { useState } from 'react';
import { Copy, Globe, Play, Plus, Power, RefreshCw, ShieldCheck, Trash2 } from 'lucide-react';
import type { HTTPProxyStatus } from '../types';

interface HttpProxyViewProps {
  status: HTTPProxyStatus | null;
  onRefresh: () => void;
  onAddRoute: (serverName: string, upstreamURL: string) => Promise<void>;
  onToggleRoute: (slug: string, enabled: boolean) => Promise<void>;
  onDeleteRoute: (slug: string) => Promise<void>;
  onRunSelfTest: () => Promise<void>;
  onCopyURL: (url: string) => void;
}

export default function HttpProxyView({
  status,
  onRefresh,
  onAddRoute,
  onToggleRoute,
  onDeleteRoute,
  onRunSelfTest,
  onCopyURL,
}: HttpProxyViewProps) {
  const [serverName, setServerName] = useState('');
  const [upstreamUrl, setUpstreamUrl] = useState('');
  const [testing, setTesting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!serverName.trim() || !upstreamUrl.trim()) return;
    await onAddRoute(serverName.trim(), upstreamUrl.trim());
    setServerName('');
    setUpstreamUrl('');
  };

  const handleSelfTest = async () => {
    setTesting(true);
    try {
      await onRunSelfTest();
    } finally {
      setTesting(false);
    }
  };

  return (
    <>
      <div className="banner banner-info">
        <div>
          <strong>HTTP / Streamable-HTTP / SSE Reverse Proxy Firewall:</strong> Register any remote MCP endpoint below,
          then point your AI client (Cursor, Claude, VS Code) to the generated{' '}
          <span className="mono">http://127.0.0.1:43772/mcp/&lt;slug&gt;</span> URL. Every{' '}
          <span className="mono">tools/call</span> passes through MCPGuard Policy Engine, HITL Approval, DLP, and
          Indirect Injection Guard.
        </div>
        <button className="btn btn-primary btn-sm" onClick={handleSelfTest} disabled={testing}>
          <Play size={13} /> {testing ? 'Testing...' : 'Run Loopback Self-Test'}
        </button>
      </div>

      {/* Status Header */}
      <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
        <div className="card kpi-card">
          <div className="kpi-label">
            <span>Reverse Proxy Listener</span>
            <Globe size={15} color={status?.running ? '#10b981' : '#ef4444'} />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 2 }}>
            <span className={`status-dot ${status?.running ? 'online' : 'offline'}`} />
            <span style={{ fontWeight: 700, fontSize: 16 }}>{status?.running ? 'LISTENING' : 'STOPPED'}</span>
          </div>
          <div className="kpi-sub mono">{status?.baseUrl || 'http://127.0.0.1:43772'}</div>
        </div>

        <div className="card kpi-card">
          <div className="kpi-label">
            <span>Protected Remote Routes</span>
            <ShieldCheck size={15} color="#38bdf8" />
          </div>
          <div className="kpi-value">{status?.routes?.length ?? 0}</div>
          <div className="kpi-sub">Persisted in local SQLite</div>
        </div>

        <div className="card kpi-card">
          <div className="kpi-label">
            <span>Total Intercepted / Blocked</span>
            <Play size={15} color="#a78bfa" />
          </div>
          <div className="kpi-value">
            {(status?.routes ?? []).reduce((a, r) => a + r.requestCount, 0)} /{' '}
            <span style={{ color: '#fca5a5' }}>{(status?.routes ?? []).reduce((a, r) => a + r.blockedCount, 0)}</span>
          </div>
          <div className="kpi-sub">Real-time reverse proxy counters</div>
        </div>
      </div>

      {/* Add Route Form */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-header">
          <div className="section-title">
            <Plus size={15} color="#38bdf8" /> Register Remote HTTP / SSE MCP Server
          </div>
        </div>
        <form onSubmit={handleSubmit} style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          <input
            className="input"
            style={{ width: 210 }}
            placeholder="Server Name (e.g. github-remote)"
            value={serverName}
            onChange={(e) => setServerName(e.target.value)}
          />
          <input
            className="input"
            style={{ flex: 1, minWidth: 280 }}
            placeholder="Upstream Remote MCP URL (e.g. https://mcp.example.com/mcp)"
            value={upstreamUrl}
            onChange={(e) => setUpstreamUrl(e.target.value)}
          />
          <button type="submit" className="btn btn-primary" disabled={!serverName.trim() || !upstreamUrl.trim()}>
            <Plus size={14} /> Add Proxy Route
          </button>
        </form>
      </div>

      {/* Routes Table */}
      <div className="card">
        <div className="section-header">
          <div className="section-title">
            <Globe size={15} color="#38bdf8" /> Active HTTP / SSE Reverse Proxy Routes
          </div>
          <button className="btn btn-sm" onClick={onRefresh}>
            <RefreshCw size={12} /> Refresh
          </button>
        </div>

        {!status || status.routes.length === 0 ? (
          <div className="empty-state">
            <Globe size={28} color="#64748b" />
            <h3>No Remote HTTP/SSE Routes Configured</h3>
            <p>
              Add a remote MCP URL above or click <strong>Run Loopback Self-Test</strong> to verify live HTTP policy
              blocking and DLP redaction end-to-end.
            </p>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Server</th>
                <th>Protected Local Endpoint (Use in AI Client)</th>
                <th>Upstream Target</th>
                <th>Traffic</th>
                <th>Status</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {status.routes.map((r) => (
                <tr key={r.slug}>
                  <td style={{ fontWeight: 600 }}>{r.serverName}</td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span className="mono" style={{ color: '#38bdf8' }}>
                        {r.localUrl}
                      </span>
                      <button
                        className="btn btn-sm"
                        style={{ padding: '2px 6px' }}
                        onClick={() => onCopyURL(r.localUrl)}
                        title="Copy Local Protected URL"
                      >
                        <Copy size={11} />
                      </button>
                    </div>
                  </td>
                  <td className="mono" style={{ color: '#94a3b8' }}>
                    {r.upstreamUrl}
                  </td>
                  <td className="mono">
                    {r.requestCount} req / <span style={{ color: '#fca5a5' }}>{r.blockedCount} blk</span>
                  </td>
                  <td>
                    <span className={`pill ${r.enabled ? 'pill-trusted' : ''}`}>
                      {r.enabled ? 'Active' : 'Paused'}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <div style={{ display: 'inline-flex', gap: 6 }}>
                      <button className="btn btn-sm" onClick={() => onToggleRoute(r.slug, !r.enabled)}>
                        <Power size={12} /> {r.enabled ? 'Pause' : 'Enable'}
                      </button>
                      <button className="btn btn-sm btn-danger" onClick={() => onDeleteRoute(r.slug)}>
                        <Trash2 size={12} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
