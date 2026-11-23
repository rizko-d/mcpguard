package firewall_test

import (
	"context"
	"testing"
	"time"

	"mcpguard/internal/firewall"
	"mcpguard/internal/model"
	"mcpguard/internal/storage"
)

func TestControlPlaneHITLSessionAndPersistence(t *testing.T) {
	st, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("open memory sqlite: %v", err)
	}
	defer st.Close()

	approvalCh := make(chan model.PendingApproval, 2)
	cp, err := firewall.NewControlPlane(st, firewall.Callbacks{
		OnApprovalNeeded: func(req model.PendingApproval) {
			approvalCh <- req
		},
	})
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}

	// 1. Immediate policy DENY on sensitive path
	denyResp := cp.EvaluateToolCall(context.Background(), firewall.EvaluateRequest{
		ServerName: "fs",
		ToolName:   "read_file",
		ArgsJSON:   `{"path": "/etc/passwd"}`,
	})
	if denyResp.Allowed || denyResp.Decision != "DENY" {
		t.Fatalf("expected DENY for /etc/passwd, got %+v", denyResp)
	}

	// 2. HITL ASK -> Approve for Session asynchronously
	done := make(chan firewall.EvaluateResponse, 1)
	go func() {
		done <- cp.EvaluateToolCall(context.Background(), firewall.EvaluateRequest{
			ServerName: "devops",
			ToolName:   "run_command",
			ArgsJSON:   `{"cmd": "go test ./..."}`,
		})
	}()

	select {
	case pending := <-approvalCh:
		if err := cp.ResolveApproval(pending.ID, "APPROVE_SESSION"); err != nil {
			t.Fatalf("ResolveApproval: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for HITL approval callback")
	}

	hitlResp := <-done
	if !hitlResp.Allowed || hitlResp.Decision != "APPROVED_SESSION" {
		t.Fatalf("expected APPROVED_SESSION, got %+v", hitlResp)
	}

	// 3. Second call to same server+tool should auto-approve via session cache without blocking
	secondResp := cp.EvaluateToolCall(context.Background(), firewall.EvaluateRequest{
		ServerName: "devops",
		ToolName:   "run_command",
		ArgsJSON:   `{"cmd": "git status"}`,
	})
	if !secondResp.Allowed || secondResp.Decision != "APPROVED_SESSION" {
		t.Fatalf("expected auto APPROVED_SESSION on second call, got %+v", secondResp)
	}

	// 4. Verify all 3 events persisted in SQLite traffic_logs
	logs, err := st.GetTrafficLogs(20)
	if err != nil || len(logs) != 3 {
		t.Fatalf("expected 3 traffic logs in SQLite, got err=%v len=%d", err, len(logs))
	}
}
