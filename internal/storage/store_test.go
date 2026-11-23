package storage_test

import (
	"testing"

	"mcpguard/internal/model"
	"mcpguard/internal/storage"
)

func TestSQLiteStoreRoundTrip(t *testing.T) {
	st, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("open memory sqlite: %v", err)
	}
	defer st.Close()

	rec := model.BaselineRecord{
		ServerID:      "srv-abc",
		ServerName:    "test-mcp",
		AggregateHash: "deadbeef1234",
		Tools: []model.MCPTool{
			{Name: "ping", Description: "Ping tool", SchemaHash: "hash1"},
		},
	}
	if err := st.SaveBaseline(rec); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	loaded, err := st.GetBaseline("srv-abc")
	if err != nil || loaded == nil {
		t.Fatalf("GetBaseline: err=%v loaded=%v", err, loaded)
	}
	if loaded.AggregateHash != "deadbeef1234" || len(loaded.Tools) != 1 {
		t.Errorf("unexpected baseline loaded: %+v", loaded)
	}

	if err := st.AddCustomConfig("My Custom", "/tmp/custom.json"); err != nil {
		t.Fatalf("AddCustomConfig: %v", err)
	}
	customs, err := st.ListCustomConfigs()
	if err != nil || len(customs) != 1 {
		t.Fatalf("ListCustomConfigs: err=%v len=%d", err, len(customs))
	}

	if err := st.RecordAuditSnapshot(model.ServerAuditResult{
		Server:      model.MCPServerConfig{ID: "srv-abc", ServerName: "test-mcp", ClientName: "Cursor"},
		RiskScore:   45,
		RiskLevel:   "HIGH",
		InspectedAt: "2026-11-23T15:00:00Z",
	}); err != nil {
		t.Fatalf("RecordAuditSnapshot: %v", err)
	}
	history, err := st.GetAuditHistory(10)
	if err != nil || len(history) != 1 || history[0].RiskScore != 45 {
		t.Fatalf("GetAuditHistory: err=%v history=%+v", err, history)
	}
}
