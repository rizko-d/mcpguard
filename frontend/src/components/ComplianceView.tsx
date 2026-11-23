import React, { useState } from 'react';
import {
  Award,
  CheckCircle2,
  ClipboardCheck,
  Download,
  FileCode2,
  FileText,
  Printer,
  RefreshCw,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import type { ComplianceReport } from '../types';

interface ComplianceViewProps {
  report: ComplianceReport | null;
  onRefresh: () => void;
  onExportHTML: () => void;
  onExportSARIF: () => void;
  onExportMarkdown: () => void;
  onExportJSON: () => void;
}

export default function ComplianceView({
  report,
  onRefresh,
  onExportHTML,
  onExportSARIF,
  onExportMarkdown,
  onExportJSON,
}: ComplianceViewProps) {
  const [subTab, setSubTab] = useState<'owasp' | 'benchmark' | 'schema'>('owasp');

  const gradeColor = (g?: string) => {
    if (g === 'A') return '#10b981';
    if (g === 'B') return '#38bdf8';
    if (g === 'C') return '#eab308';
    if (g === 'D') return '#f97316';
    return '#ef4444';
  };

  return (
    <>
      {/* Enterprise Report Export Bar */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-header" style={{ marginBottom: 8 }}>
          <div className="section-title">
            <Download size={15} color="#38bdf8" /> Enterprise Audit Report Exporters
          </div>
          <button className="btn btn-sm" onClick={onRefresh}>
            <RefreshCw size={12} /> Recompute Compliance
          </button>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button className="btn btn-primary btn-sm" onClick={onExportHTML}>
            <Printer size={13} /> Export Executive HTML (Print to PDF)
          </button>
          <button className="btn btn-sm" onClick={onExportSARIF}>
            <FileCode2 size={13} /> Export SARIF 2.1.0 (GitHub / CI-CD)
          </button>
          <button className="btn btn-sm" onClick={onExportMarkdown}>
            <FileText size={13} /> Export Markdown Summary
          </button>
          <button className="btn btn-sm" onClick={onExportJSON}>
            <Download size={13} /> Export Raw JSON
          </button>
        </div>
      </div>

      {/* Compliance KPI Cards */}
      <div className="kpi-grid">
        <div className="card kpi-card">
          <div className="kpi-label">
            <span>Overall Compliance Grade</span>
            <Award size={15} color={gradeColor(report?.overallGrade)} />
          </div>
          <div className="kpi-value" style={{ color: gradeColor(report?.overallGrade) }}>
            {report?.overallGrade ?? '—'}
          </div>
          <div className="kpi-sub">Posture + Policy + Schema weighted</div>
        </div>

        <div className="card kpi-card">
          <div className="kpi-label">
            <span>Firewall Policy Coverage</span>
            <ShieldCheck size={15} color="#10b981" />
          </div>
          <div className="kpi-value">{report?.policyCoverageScore ?? 0}%</div>
          <div className="kpi-sub">
            {(report?.policyBenchmarks ?? []).filter((b) => b.passed).length} / {report?.policyBenchmarks?.length ?? 0}{' '}
            defensive self-tests passed
          </div>
        </div>

        <div className="card kpi-card">
          <div className="kpi-label">
            <span>Tool Schema Hardening</span>
            <ClipboardCheck size={15} color="#38bdf8" />
          </div>
          <div className="kpi-value">{report?.schemaHardeningRate ?? 0}%</div>
          <div className="kpi-sub">{report?.schemaIssues?.length ?? 0} schema constraint gap(s)</div>
        </div>

        <div className="card kpi-card">
          <div className="kpi-label">
            <span>OWASP Controls Passing</span>
            <CheckCircle2 size={15} color="#10b981" />
          </div>
          <div className="kpi-value">
            {(report?.owaspControls ?? []).filter((c) => c.status === 'PASS').length} /{' '}
            {report?.owaspControls?.length ?? 0}
          </div>
          <div className="kpi-sub">OWASP LLM Top 10 &amp; MCP Matrix</div>
        </div>
      </div>

      {/* Sub-navigation tabs */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="detail-tabs">
          <button className={`tab-btn ${subTab === 'owasp' ? 'active' : ''}`} onClick={() => setSubTab('owasp')}>
            OWASP LLM &amp; MCP Matrix ({report?.owaspControls?.length ?? 0})
          </button>
          <button
            className={`tab-btn ${subTab === 'benchmark' ? 'active' : ''}`}
            onClick={() => setSubTab('benchmark')}
          >
            Firewall Policy Coverage Self-Audit ({report?.policyBenchmarks?.length ?? 0})
          </button>
          <button className={`tab-btn ${subTab === 'schema' ? 'active' : ''}`} onClick={() => setSubTab('schema')}>
            JSON Schema Hardening Audit ({report?.schemaIssues?.length ?? 0})
          </button>
        </div>

        <div style={{ padding: 16 }}>
          {subTab === 'owasp' && (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Control ID</th>
                  <th>Security Domain</th>
                  <th>Status</th>
                  <th>Findings</th>
                  <th>Mitigation Guidance</th>
                </tr>
              </thead>
              <tbody>
                {(report?.owaspControls ?? []).map((c) => (
                  <tr key={c.controlId}>
                    <td className="mono" style={{ whiteSpace: 'nowrap', color: '#38bdf8' }}>
                      {c.controlId}
                    </td>
                    <td style={{ fontWeight: 600 }}>{c.name}</td>
                    <td>
                      <span
                        className={`badge ${
                          c.status === 'PASS' ? 'badge-SAFE' : c.status === 'WARN' ? 'badge-MEDIUM' : 'badge-CRITICAL'
                        }`}
                      >
                        {c.status}
                      </span>
                    </td>
                    <td className="mono">{c.findingCount}</td>
                    <td style={{ color: '#94a3b8' }}>{c.mitigation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {subTab === 'benchmark' && (
            <table className="data-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Category</th>
                  <th>Defensive Control Check</th>
                  <th>Expected</th>
                  <th>Actual</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {(report?.policyBenchmarks ?? []).map((b) => (
                  <tr key={b.id}>
                    <td className="mono">{b.id}</td>
                    <td>
                      <span className="pill">{b.category}</span>
                    </td>
                    <td>
                      <div style={{ fontWeight: 600 }}>{b.name}</div>
                      <div style={{ fontSize: 11.5, color: '#64748b' }}>{b.notes}</div>
                    </td>
                    <td className="mono">{b.expected}</td>
                    <td className="mono">
                      {b.actual}{' '}
                      {b.matchedRule && (
                        <span style={{ color: '#64748b', fontSize: 10.5 }}>({b.matchedRule})</span>
                      )}
                    </td>
                    <td>
                      {b.passed ? (
                        <span className="badge badge-SAFE">
                          <CheckCircle2 size={11} /> PASS
                        </span>
                      ) : (
                        <span className="badge badge-CRITICAL">
                          <XCircle size={11} /> GAP
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {subTab === 'schema' && (
            <>
              {!report || report.schemaIssues.length === 0 ? (
                <div className="empty-state">
                  <CheckCircle2 size={28} color="#10b981" />
                  <h3>All Inspected Tool Schemas Hardened</h3>
                  <p>No missing input validation constraints detected across inspected MCP tools.</p>
                </div>
              ) : (
                report.schemaIssues.map((si) => (
                  <div key={si.id} className={`finding-card sev-${si.severity}`}>
                    <div className="finding-header">
                      <div className="finding-title">
                        <span className={`badge badge-${si.severity}`}>{si.severity}</span>
                        <span className="mono" style={{ color: '#94a3b8' }}>
                          {si.ruleId}
                        </span>
                        <span>{si.title}</span>
                      </div>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <span className="pill mono">
                          {si.serverName}/{si.toolName}
                        </span>
                        <span className="pill mono">param: {si.parameter}</span>
                      </div>
                    </div>
                    <p style={{ color: '#cbd5e1', fontSize: 12.5 }}>{si.description}</p>
                    <div className="remediation-box">
                      <strong>Hardening Recommendation:</strong> {si.recommendation}
                    </div>
                  </div>
                ))
              )}
            </>
          )}
        </div>
      </div>
    </>
  );
}
