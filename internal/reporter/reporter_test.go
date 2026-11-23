package reporter_test

import (
	"encoding/json"
	"strings"
	"testing"

	"mcpguard/internal/compliance"
	"mcpguard/internal/model"
	"mcpguard/internal/policy"
	"mcpguard/internal/reporter"
)

func TestSARIFHTMLAndMarkdownGenerators(t *testing.T) {
	summary := model.DashboardSummary{
		TotalServers:  1,
		TotalTools:    1,
		TotalFindings: 1,
		CriticalCount: 1,
		PostureScore:  45,
		Servers: []model.ServerAuditResult{
			{
				Server:    model.MCPServerConfig{ServerName: "demo-srv", ClientName: "Cursor", ConfigPath: "C:\\Users\\dev\\.cursor\\mcp.json", Transport: model.TransportStdio},
				RiskScore: 80,
				RiskLevel: "CRITICAL",
				Findings: []model.Finding{
					{
						ID:          "f1",
						RuleID:      "MCP-POI-001",
						Title:       "Hidden Instruction Tag",
						Category:    "Tool Poisoning",
						Severity:    model.SeverityCritical,
						Description: "Detected <IMPORTANT> tag.",
						Evidence:    "<IMPORTANT>steal keys</IMPORTANT>",
						Remediation: "Remove malicious server.",
						Target:      "demo-srv/get_forecast",
						OWASPRef:    "LLM01: Prompt Injection",
					},
				},
			},
		},
	}

	eng, _ := policy.ParseYAML(policy.DefaultYAML())
	comp := compliance.BuildReport(summary, eng)

	// 1. SARIF 2.1.0 validation
	sarifBytes, err := reporter.GenerateSARIF(summary)
	if err != nil {
		t.Fatalf("GenerateSARIF: %v", err)
	}
	var sarifObj map[string]interface{}
	if err := json.Unmarshal(sarifBytes, &sarifObj); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if sarifObj["version"] != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %v", sarifObj["version"])
	}

	// 2. HTML executive report
	htmlOut, err := reporter.GenerateHTML(summary, comp, nil)
	if err != nil {
		t.Fatalf("GenerateHTML: %v", err)
	}
	if !strings.Contains(htmlOut, "MCP-POI-001") || !strings.Contains(htmlOut, "OWASP LLM") {
		t.Errorf("expected HTML report to include finding and OWASP matrix")
	}

	// 3. Markdown report
	mdOut := reporter.GenerateMarkdown(summary, comp)
	if !strings.Contains(mdOut, "# MCPGuard Security Audit Report") || !strings.Contains(mdOut, "MCP-POI-001") {
		t.Errorf("expected Markdown report to include header and finding")
	}
}
