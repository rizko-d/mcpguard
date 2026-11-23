import React, { useEffect, useState } from 'react';
import { AlertTriangle, Check, CheckCheck, ShieldAlert, X } from 'lucide-react';
import type { PendingApproval } from '../types';

interface ApprovalModalProps {
  approval: PendingApproval | null;
  queueCount: number;
  onResolve: (id: string, decision: 'APPROVE_ONCE' | 'APPROVE_SESSION' | 'DENY') => void;
}

function prettyJSON(raw: string): string {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw || '{}';
  }
}

export default function ApprovalModal({ approval, queueCount, onResolve }: ApprovalModalProps) {
  const [secondsLeft, setSecondsLeft] = useState<number>(60);

  useEffect(() => {
    if (!approval) return;
    const calc = () => {
      const diff = Math.max(0, Math.ceil((new Date(approval.expiresAt).getTime() - Date.now()) / 1000));
      setSecondsLeft(diff);
    };
    calc();
    const timer = window.setInterval(calc, 500);
    return () => window.clearInterval(timer);
  }, [approval]);

  if (!approval) return null;

  return (
    <div className="modal-backdrop">
      <div className="modal-card">
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <ShieldAlert size={20} color="#f97316" />
            <div>
              <div style={{ fontWeight: 700, fontSize: 15 }}>Human-in-the-Loop Approval Required</div>
              <div style={{ fontSize: 11.5, color: '#94a3b8' }}>
                MCPGuard intercepted a high-risk AI tool call before execution
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {queueCount > 1 && <span className="pill">+{queueCount - 1} queued</span>}
            <span className="badge badge-HIGH">{secondsLeft}s left</span>
          </div>
        </div>

        <div className="modal-body">
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: '1fr 1fr',
              gap: 10,
              background: 'rgba(11,15,23,0.6)',
              padding: 12,
              borderRadius: 8,
              border: '1px solid #1f2b42',
            }}
          >
            <div>
              <div style={{ fontSize: 10.5, color: '#64748b', textTransform: 'uppercase' }}>MCP Server</div>
              <div style={{ fontWeight: 700, marginTop: 2 }}>{approval.serverName}</div>
            </div>
            <div>
              <div style={{ fontSize: 10.5, color: '#64748b', textTransform: 'uppercase' }}>Tool Name</div>
              <div className="mono" style={{ fontWeight: 700, color: '#38bdf8', marginTop: 2 }}>
                {approval.toolName}
              </div>
            </div>
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '9px 12px',
              borderRadius: 8,
              background: 'rgba(249, 115, 22, 0.1)',
              border: '1px solid rgba(249, 115, 22, 0.3)',
              fontSize: 12.5,
              color: '#fed7aa',
            }}
          >
            <AlertTriangle size={15} />
            <span>
              <strong>{approval.ruleId}</strong> ({approval.ruleName}): {approval.reason}
            </span>
          </div>

          <div>
            <div style={{ fontSize: 11.5, color: '#94a3b8', marginBottom: 4 }}>
              Tool Arguments (DLP-scanned JSON payload)
            </div>
            <pre className="code-block" style={{ marginTop: 0, maxHeight: 210 }}>
              {prettyJSON(approval.argsJson)}
            </pre>
          </div>
        </div>

        <div className="modal-footer">
          <button className="btn btn-danger" onClick={() => onResolve(approval.id, 'DENY')}>
            <X size={14} /> Deny Call
          </button>
          <button className="btn btn-primary" onClick={() => onResolve(approval.id, 'APPROVE_ONCE')}>
            <Check size={14} /> Approve Once
          </button>
          <button className="btn btn-success" onClick={() => onResolve(approval.id, 'APPROVE_SESSION')}>
            <CheckCheck size={14} /> Approve for Session
          </button>
        </div>
      </div>
    </div>
  );
}
