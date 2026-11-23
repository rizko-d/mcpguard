import React from 'react';
import { FileCode2, RotateCcw, Save, ShieldCheck } from 'lucide-react';
import type { FirewallStatus } from '../types';

interface PolicyViewProps {
  yamlText: string;
  dirty: boolean;
  saving: boolean;
  errorText: string | null;
  status: FirewallStatus | null;
  onChange: (next: string) => void;
  onSave: () => void;
  onReset: () => void;
}

export default function PolicyView({
  yamlText,
  dirty,
  saving,
  errorText,
  status,
  onChange,
  onSave,
  onReset,
}: PolicyViewProps) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 310px', gap: 16 }}>
      <div className="card">
        <div className="section-header">
          <div className="section-title">
            <FileCode2 size={15} color="#38bdf8" /> Runtime Firewall Policy (YAML)
            {dirty && <span className="badge badge-MEDIUM">Unsaved</span>}
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-sm" onClick={onReset} disabled={saving}>
              <RotateCcw size={13} /> Reset Defaults
            </button>
            <button className="btn btn-sm btn-primary" onClick={onSave} disabled={saving || !dirty}>
              <Save size={13} /> {saving ? 'Validating...' : 'Save & Hot-Reload'}
            </button>
          </div>
        </div>

        {errorText && (
          <div className="banner banner-danger">
            <span>
              <strong>Policy Validation Error:</strong> {errorText}
            </span>
          </div>
        )}

        <textarea
          className="yaml-editor"
          spellCheck={false}
          value={yamlText}
          onChange={(e) => onChange(e.target.value)}
        />
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div className="card">
          <div className="section-title" style={{ marginBottom: 10 }}>
            <ShieldCheck size={15} color="#10b981" /> Active Enforcement Summary
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 12.5 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#94a3b8' }}>Enabled Rules</span>
              <strong>{status?.activeRulesCount ?? 0}</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#94a3b8' }}>DLP Secret Redaction</span>
              <span className={`pill ${status?.dlpEnabled ? 'pill-trusted' : ''}`}>
                {status?.dlpEnabled ? 'Enabled' : 'Disabled'}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#94a3b8' }}>Indirect Injection Guard</span>
              <span className={`pill ${status?.injectionGuard ? 'pill-trusted' : ''}`}>
                {status?.injectionGuard ? 'Enabled' : 'Disabled'}
              </span>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="section-title" style={{ marginBottom: 8 }}>
            Policy Reference
          </div>
          <div style={{ fontSize: 12, color: '#94a3b8', display: 'flex', flexDirection: 'column', gap: 8 }}>
            <p>
              Rules are evaluated <strong>top-to-bottom (first match wins)</strong> on every intercepted{' '}
              <span className="mono">tools/call</span> request.
            </p>
            <p>
              <strong>Actions:</strong>
              <br />• <span className="mono" style={{ color: '#6ee7b7' }}>ALLOW</span> — Forward immediately
              <br />• <span className="mono" style={{ color: '#fca5a5' }}>DENY</span> — Block with JSON-RPC error{' '}
              <span className="mono">-32001</span>
              <br />• <span className="mono" style={{ color: '#fde047' }}>ASK</span> — Pause execution &amp; prompt HITL
              approval modal (fail-closed on timeout)
            </p>
            <p>
              <strong>Matchers:</strong>
              <br />• <span className="mono">serverPattern</span> / <span className="mono">toolPattern</span>: comma-separated
              globs (e.g. <span className="mono">*exec*,run_command</span>)
              <br />• <span className="mono">argRegex</span>: Go RE2 regular expression matched against serialized JSON
              arguments
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
