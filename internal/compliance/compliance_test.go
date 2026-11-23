package compliance_test

import (
	"testing"

	"mcpguard/internal/compliance"
	"mcpguard/internal/demolab"
	"mcpguard/internal/model"
	"mcpguard/internal/policy"
)

func TestComplianceReportAndPolicyBenchmark(t *testing.T) {
	eng, err := policy.ParseYAML(policy.DefaultYAML())
	if err != nil {
		t.Fatalf("ParseYAML: %v", err)
	}

	_, bundles := demolab.BuildDemoLab(false)
	servers := make([]model.ServerAuditResult, len(bundles))
	for i, b := range bundles {
		servers[i] = model.ServerAuditResult{
			Server: b.Server,
			Tools:  b.Tools,
		}
	}

	summary := model.DashboardSummary{
		TotalServers: len(servers),
		PostureScore: 70,
		Servers:      servers,
	}

	rep := compliance.BuildReport(summary, eng)
	if rep.PolicyCoverageScore != 100 {
		t.Errorf("expected default YAML policy to score 100%% benchmark coverage, got %d%%", rep.PolicyCoverageScore)
	}
	if len(rep.OWASPControls) < 7 {
		t.Errorf("expected at least 7 OWASP controls, got %d", len(rep.OWASPControls))
	}
	if len(rep.SchemaIssues) == 0 {
		t.Errorf("expected schema hardening issues on unconstrained demo tool parameters")
	}
}
