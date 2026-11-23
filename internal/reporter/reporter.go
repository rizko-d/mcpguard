package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"
	"time"

	"mcpguard/internal/model"
)

// GenerateSARIF produces a SARIF 2.1.0 JSON report compatible with GitHub Code Scanning & CI/CD pipelines.
func GenerateSARIF(summary model.DashboardSummary) ([]byte, error) {
	ruleMap := make(map[string]map[string]interface{})
	results := []map[string]interface{}{}

	for _, srv := range summary.Servers {
		uri := srv.Server.ConfigPath
		if uri == "" {
			uri = srv.Server.ServerName
		}
		uri = strings.ReplaceAll(uri, "\\", "/")

		for _, f := range srv.Findings {
			if _, exists := ruleMap[f.RuleID]; !exists {
				ruleMap[f.RuleID] = map[string]interface{}{
					"id":               f.RuleID,
					"name":             f.Category,
					"shortDescription": map[string]string{"text": f.Title},
					"help": map[string]string{
						"text": f.Remediation,
					},
					"properties": map[string]interface{}{
						"tags": []string{"security", "mcp", "ai-security", f.OWASPRef},
					},
				}
			}

			msg := f.Description
			if f.Evidence != "" {
				msg += " | Evidence: " + f.Evidence
			}

			results = append(results, map[string]interface{}{
				"ruleId": f.RuleID,
				"level":  sarifLevel(f.Severity),
				"message": map[string]string{
					"text": msg,
				},
				"locations": []map[string]interface{}{
					{
						"physicalLocation": map[string]interface{}{
							"artifactLocation": map[string]string{
								"uri": uri,
							},
						},
						"logicalLocations": []map[string]string{
							{
								"fullyQualifiedName": f.Target,
								"kind":               "mcp-server",
							},
						},
					},
				},
				"properties": map[string]interface{}{
					"severity":    string(f.Severity),
					"category":    f.Category,
					"owaspRef":    f.OWASPRef,
					"remediation": f.Remediation,
				},
			})
		}
	}

	rules := make([]map[string]interface{}, 0, len(ruleMap))
	for _, r := range ruleMap {
		rules = append(rules, r)
	}

	sarif := map[string]interface{}{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "MCPGuard",
						"version":        "0.3.0",
						"informationUri": "https://modelcontextprotocol.io",
						"rules":          rules,
					},
				},
				"results": results,
			},
		},
	}

	return json.MarshalIndent(sarif, "", "  ")
}

// GenerateMarkdown produces a structured Markdown security report suitable for PRs, Jira, or Confluence.
func GenerateMarkdown(summary model.DashboardSummary, comp model.ComplianceReport) string {
	var sb strings.Builder
	sb.WriteString("# MCPGuard Security Audit Report\n\n")
	sb.WriteString(fmt.Sprintf("- **Generated At:** %s\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("- **Security Posture Score:** %d/100 (Compliance Grade: **%s**)\n", summary.PostureScore, comp.OverallGrade))
	sb.WriteString(fmt.Sprintf("- **Servers Audited:** %d | **Tools Inspected:** %d | **Total Findings:** %d\n", summary.TotalServers, summary.TotalTools, summary.TotalFindings))
	sb.WriteString(fmt.Sprintf("- **Severity Breakdown:** Critical: %d | High: %d | Medium: %d | Low: %d | Info: %d\n",
		summary.CriticalCount, summary.HighCount, summary.MediumCount, summary.LowCount, summary.InfoCount))
	sb.WriteString(fmt.Sprintf("- **Firewall Policy Coverage:** %d%% | **Schema Hardening Rate:** %d%%\n\n",
		comp.PolicyCoverageScore, comp.SchemaHardeningRate))

	sb.WriteString("## OWASP LLM & MCP Compliance Matrix\n\n")
	sb.WriteString("| Control | Category | Status | Findings | Mitigation |\n")
	sb.WriteString("|---|---|---|---|---|\n")
	for _, c := range comp.OWASPControls {
		sb.WriteString(fmt.Sprintf("| `%s` | %s | **%s** | %d | %s |\n",
			c.ControlID, c.Name, c.Status, c.FindingCount, c.Mitigation))
	}

	sb.WriteString("\n## Audited MCP Servers\n\n")
	sb.WriteString("| Server | Client | Transport | Tools | Baseline | Risk |\n")
	sb.WriteString("|---|---|---|---|---|---|\n")
	for _, s := range summary.Servers {
		sb.WriteString(fmt.Sprintf("| `%s` | %s | `%s` | %d | %s | **%s** (%d) |\n",
			s.Server.ServerName, s.Server.ClientName, s.Server.Transport, len(s.Tools), s.BaselineStatus, s.RiskLevel, s.RiskScore))
	}

	sb.WriteString("\n## Security Findings\n\n")
	if summary.TotalFindings == 0 {
		sb.WriteString("_No security findings detected._\n")
	} else {
		for _, s := range summary.Servers {
			for _, f := range s.Findings {
				sb.WriteString(fmt.Sprintf("### [%s] `%s` — %s\n", f.Severity, f.RuleID, f.Title))
				sb.WriteString(fmt.Sprintf("- **Target:** `%s` | **Category:** %s | **OWASP:** %s\n", f.Target, f.Category, f.OWASPRef))
				sb.WriteString(fmt.Sprintf("- **Description:** %s\n", f.Description))
				if f.Evidence != "" {
					sb.WriteString(fmt.Sprintf("- **Evidence:** `%s`\n", strings.ReplaceAll(f.Evidence, "`", "'")))
				}
				sb.WriteString(fmt.Sprintf("- **Remediation:** %s\n\n", f.Remediation))
			}
		}
	}

	return sb.String()
}

// GenerateHTML builds a self-contained, print-to-PDF-ready Executive Security Audit HTML document.
func GenerateHTML(summary model.DashboardSummary, comp model.ComplianceReport, recentTraffic []model.TrafficEvent) (string, error) {
	type htmlData struct {
		GeneratedAt string
		Summary     model.DashboardSummary
		Compliance  model.ComplianceReport
		Traffic     []model.TrafficEvent
		BlockedCnt  int
		DLPCnt      int
	}

	blocked := 0
	dlp := 0
	for _, t := range recentTraffic {
		if t.Decision == "DENY" || t.Decision == "DENIED_USER" || t.Decision == "TIMEOUT" || t.InjectionDetected {
			blocked++
		}
		if len(t.DLPHits) > 0 || t.Decision == "REDACTED" {
			dlp++
		}
	}

	trimmedTraffic := recentTraffic
	if len(trimmedTraffic) > 30 {
		trimmedTraffic = trimmedTraffic[:30]
	}

	data := htmlData{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05 MST"),
		Summary:     summary,
		Compliance:  comp,
		Traffic:     trimmedTraffic,
		BlockedCnt:  blocked,
		DLPCnt:      dlp,
	}

	tpl, err := template.New("report").Parse(executiveHTMLTemplate)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func sarifLevel(sev model.Severity) string {
	switch sev {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

const executiveHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>MCPGuard Executive Security Audit Report</title>
<style>
  :root { --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --muted: #94a3b8; --border: #334155; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 32px; background: #f8fafc; color: #0f172a; line-height: 1.5; }
  .container { max-width: 1020px; margin: 0 auto; }
  .header { background: #0f172a; color: #f8fafc; padding: 26px 30px; border-radius: 12px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
  .header h1 { margin: 0; font-size: 22px; }
  .header p { margin: 4px 0 0; color: #94a3b8; font-size: 13px; }
  .grade-box { text-align: center; background: #1e293b; border: 2px solid #38bdf8; border-radius: 10px; padding: 10px 22px; }
  .grade { font-size: 32px; font-weight: 800; color: #38bdf8; line-height: 1; }
  .kpi-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 22px; }
  .kpi { background: #ffffff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 16px; }
  .kpi .lbl { font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: 700; }
  .kpi .val { font-size: 26px; font-weight: 800; margin-top: 4px; }
  h2 { font-size: 16px; margin: 26px 0 10px; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; }
  table { width: 100%; border-collapse: collapse; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; font-size: 12.5px; }
  th { background: #f1f5f9; text-align: left; padding: 9px 12px; font-size: 11px; text-transform: uppercase; color: #475569; border-bottom: 1px solid #cbd5e1; }
  td { padding: 9px 12px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
  .badge { display: inline-block; padding: 2px 7px; border-radius: 4px; font-size: 10.5px; font-weight: 700; }
  .b-CRITICAL, .b-FAIL, .b-DENY { background: #fee2e2; color: #b91c1c; }
  .b-HIGH, .b-WARN { background: #ffedd5; color: #c2410c; }
  .b-MEDIUM { background: #fef9c3; color: #a16207; }
  .b-LOW, .b-INFO { background: #e0f2fe; color: #0369a1; }
  .b-SAFE, .b-PASS, .b-ALLOW { background: #dcfce7; color: #15803d; }
  .finding { background: #ffffff; border: 1px solid #e2e8f0; border-left: 4px solid #64748b; border-radius: 8px; padding: 12px 14px; margin-bottom: 10px; page-break-inside: avoid; }
  .finding.f-CRITICAL { border-left-color: #dc2626; }
  .finding.f-HIGH { border-left-color: #ea580c; }
  .finding.f-MEDIUM { border-left-color: #ca8a04; }
  .mono { font-family: Consolas, 'Courier New', monospace; font-size: 11.5px; background: #f1f5f9; padding: 1px 4px; border-radius: 3px; }
  .footer { margin-top: 32px; font-size: 11.5px; color: #64748b; text-align: center; }
  @media print { body { padding: 0; background: #ffffff; } .header { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1>MCPGuard — MCP &amp; AI Tool-Use Security Audit Report</h1>
      <p>Generated: {{.GeneratedAt}} · Print this page (Ctrl+P) to save as PDF</p>
    </div>
    <div class="grade-box">
      <div style="font-size:10px;color:#94a3b8;text-transform:uppercase;">Grade</div>
      <div class="grade">{{.Compliance.OverallGrade}}</div>
    </div>
  </div>

  <div class="kpi-row">
    <div class="kpi"><div class="lbl">Security Posture</div><div class="val">{{.Summary.PostureScore}} / 100</div></div>
    <div class="kpi"><div class="lbl">Policy Coverage</div><div class="val">{{.Compliance.PolicyCoverageScore}}%</div></div>
    <div class="kpi"><div class="lbl">Servers / Tools</div><div class="val">{{.Summary.TotalServers}} / {{.Summary.TotalTools}}</div></div>
    <div class="kpi"><div class="lbl">Critical &amp; High</div><div class="val">{{.Summary.CriticalCount}}C / {{.Summary.HighCount}}H</div></div>
  </div>

  <h2>1. OWASP LLM &amp; MCP Compliance Matrix</h2>
  <table>
    <thead><tr><th>Control</th><th>Security Domain</th><th>Status</th><th>Findings</th><th>Recommended Mitigation</th></tr></thead>
    <tbody>
    {{range .Compliance.OWASPControls}}
      <tr>
        <td><span class="mono">{{.ControlID}}</span></td>
        <td><strong>{{.Name}}</strong></td>
        <td><span class="badge b-{{.Status}}">{{.Status}}</span></td>
        <td>{{.FindingCount}}</td>
        <td>{{.Mitigation}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>

  <h2>2. Audited MCP Server Inventory</h2>
  <table>
    <thead><tr><th>Server</th><th>Client</th><th>Transport</th><th>Tools</th><th>Baseline Status</th><th>Risk</th></tr></thead>
    <tbody>
    {{range .Summary.Servers}}
      <tr>
        <td><strong>{{.Server.ServerName}}</strong></td>
        <td>{{.Server.ClientName}}</td>
        <td><span class="mono">{{.Server.Transport}}</span></td>
        <td>{{len .Tools}}</td>
        <td>{{.BaselineStatus}}</td>
        <td><span class="badge b-{{.RiskLevel}}">{{.RiskLevel}} ({{.RiskScore}})</span></td>
      </tr>
    {{end}}
    </tbody>
  </table>

  <h2>3. Detailed Security Findings ({{.Summary.TotalFindings}})</h2>
  {{if eq .Summary.TotalFindings 0}}
    <p>No static, poisoning, supply-chain, shadowing, or drift findings detected.</p>
  {{else}}
    {{range .Summary.Servers}}
      {{range .Findings}}
        <div class="finding f-{{.Severity}}">
          <div>
            <span class="badge b-{{.Severity}}">{{.Severity}}</span>
            <span class="mono">{{.RuleID}}</span>
            <strong>{{.Title}}</strong>
            <span style="float:right;font-size:11px;color:#64748b;">{{.Target}} · {{.OWASPRef}}</span>
          </div>
          <p style="margin:6px 0 4px;font-size:12.5px;">{{.Description}}</p>
          {{if .Evidence}}<div style="font-size:11.5px;margin:4px 0;"><strong>Evidence:</strong> <span class="mono">{{.Evidence}}</span></div>{{end}}
          <div style="font-size:12px;color:#065f46;margin-top:4px;"><strong>Remediation:</strong> {{.Remediation}}</div>
        </div>
      {{end}}
    {{end}}
  {{end}}

  <h2>4. Runtime Firewall Summary (Recent {{len .Traffic}} Events · {{.BlockedCnt}} Blocked · {{.DLPCnt}} DLP)</h2>
  {{if eq (len .Traffic) 0}}
    <p>No runtime firewall traffic captured in the current log.</p>
  {{else}}
    <table>
      <thead><tr><th>Timestamp</th><th>Server / Tool</th><th>Decision</th><th>Rule / Guard</th><th>Reason</th></tr></thead>
      <tbody>
      {{range .Traffic}}
        <tr>
          <td><span class="mono">{{.Timestamp}}</span></td>
          <td>{{.ServerName}} / <span class="mono">{{.ToolName}}</span></td>
          <td><span class="badge b-{{.Decision}}">{{.Decision}}</span></td>
          <td><span class="mono">{{.RuleID}}</span></td>
          <td>{{.Reason}}</td>
        </tr>
      {{end}}
      </tbody>
    </table>
  {{end}}

  <div class="footer">Generated by MCPGuard — Go + Wails MCP &amp; AI Tool-Use Security Auditor</div>
</div>
</body>
</html>
`
