package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"mcpguard/internal/discovery"
	"mcpguard/internal/model"
)

// Store persists trusted MCP tool baselines, custom config paths, and audit history in SQLite.
type Store struct {
	db *sql.DB
}

// DefaultDBPath returns the OS-appropriate path for the MCPGuard SQLite database.
func DefaultDBPath() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		home, hErr := os.UserHomeDir()
		if hErr != nil {
			return "", hErr
		}
		cfgDir = filepath.Join(home, ".mcpguard")
	}
	dir := filepath.Join(cfgDir, "MCPGuard")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create app data dir: %w", err)
	}
	return filepath.Join(dir, "mcpguard.db"), nil
}

// Open initializes (or creates) the SQLite database at dbPath and runs schema migrations.
func Open(dbPath string) (*Store, error) {
	if dbPath != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
			return nil, fmt.Errorf("create db directory: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying SQLite database connection.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS baselines (
		server_id TEXT PRIMARY KEY,
		server_name TEXT NOT NULL,
		aggregate_hash TEXT NOT NULL,
		tools_json TEXT NOT NULL,
		approved_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS custom_configs (
		path TEXT PRIMARY KEY,
		label TEXT NOT NULL,
		added_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS audit_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		server_id TEXT NOT NULL,
		server_name TEXT NOT NULL,
		client_name TEXT NOT NULL,
		risk_score INTEGER NOT NULL,
		risk_level TEXT NOT NULL,
		findings_count INTEGER NOT NULL,
		tool_count INTEGER NOT NULL,
		scanned_at TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_audit_history_scanned_at ON audit_history(scanned_at DESC);

	CREATE TABLE IF NOT EXISTS policy_config (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		yaml_content TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS traffic_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		request_id TEXT NOT NULL,
		timestamp TEXT NOT NULL,
		server_name TEXT NOT NULL,
		direction TEXT NOT NULL,
		method TEXT NOT NULL,
		tool_name TEXT NOT NULL,
		args_preview TEXT NOT NULL,
		response_preview TEXT NOT NULL,
		decision TEXT NOT NULL,
		rule_id TEXT NOT NULL,
		rule_name TEXT NOT NULL,
		reason TEXT NOT NULL,
		severity TEXT NOT NULL,
		dlp_hits_json TEXT NOT NULL,
		injection_detected INTEGER NOT NULL,
		injection_evidence TEXT NOT NULL,
		latency_ms INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_traffic_logs_id ON traffic_logs(id DESC);

	CREATE TABLE IF NOT EXISTS http_proxy_routes (
		slug TEXT PRIMARY KEY,
		id TEXT NOT NULL,
		server_name TEXT NOT NULL,
		upstream_url TEXT NOT NULL,
		enabled INTEGER NOT NULL,
		created_at TEXT NOT NULL
	);
	`
	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("migrate sqlite schema: %w", err)
	}
	return nil
}

// SaveBaseline inserts or updates an approved tool-schema baseline for a server.
func (s *Store) SaveBaseline(rec model.BaselineRecord) error {
	toolsJSON, err := json.Marshal(rec.Tools)
	if err != nil {
		return fmt.Errorf("marshal tools: %w", err)
	}
	if rec.ApprovedAt == "" {
		rec.ApprovedAt = time.Now().UTC().Format(time.RFC3339)
	}
	_, err = s.db.Exec(`
		INSERT INTO baselines (server_id, server_name, aggregate_hash, tools_json, approved_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(server_id) DO UPDATE SET
			server_name = excluded.server_name,
			aggregate_hash = excluded.aggregate_hash,
			tools_json = excluded.tools_json,
			approved_at = excluded.approved_at
	`, rec.ServerID, rec.ServerName, rec.AggregateHash, string(toolsJSON), rec.ApprovedAt)
	return err
}

// GetBaseline retrieves a single baseline by server ID, or nil if none exists.
func (s *Store) GetBaseline(serverID string) (*model.BaselineRecord, error) {
	row := s.db.QueryRow(`
		SELECT server_id, server_name, aggregate_hash, tools_json, approved_at
		FROM baselines WHERE server_id = ?
	`, serverID)

	var rec model.BaselineRecord
	var toolsJSON string
	if err := row.Scan(&rec.ServerID, &rec.ServerName, &rec.AggregateHash, &toolsJSON, &rec.ApprovedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(toolsJSON), &rec.Tools); err != nil {
		return nil, fmt.Errorf("unmarshal baseline tools: %w", err)
	}
	return &rec, nil
}

// ListBaselines returns all stored baselines keyed by server ID.
func (s *Store) ListBaselines() (map[string]*model.BaselineRecord, error) {
	rows, err := s.db.Query(`
		SELECT server_id, server_name, aggregate_hash, tools_json, approved_at
		FROM baselines
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]*model.BaselineRecord)
	for rows.Next() {
		var rec model.BaselineRecord
		var toolsJSON string
		if err := rows.Scan(&rec.ServerID, &rec.ServerName, &rec.AggregateHash, &toolsJSON, &rec.ApprovedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(toolsJSON), &rec.Tools)
		copyRec := rec
		out[rec.ServerID] = &copyRec
	}
	return out, rows.Err()
}

// DeleteBaseline removes a trusted baseline record.
func (s *Store) DeleteBaseline(serverID string) error {
	_, err := s.db.Exec(`DELETE FROM baselines WHERE server_id = ?`, serverID)
	return err
}

// AddCustomConfig persists a user-specified MCP config file path.
func (s *Store) AddCustomConfig(label, path string) error {
	cleaned := filepath.Clean(path)
	_, err := s.db.Exec(`
		INSERT INTO custom_configs (path, label, added_at)
		VALUES (?, ?, ?)
		ON CONFLICT(path) DO UPDATE SET label = excluded.label
	`, cleaned, label, time.Now().UTC().Format(time.RFC3339))
	return err
}

// RemoveCustomConfig deletes a custom MCP config path.
func (s *Store) RemoveCustomConfig(path string) error {
	_, err := s.db.Exec(`DELETE FROM custom_configs WHERE path = ?`, filepath.Clean(path))
	return err
}

// ListCustomConfigs returns all user-added custom config paths.
func (s *Store) ListCustomConfigs() ([]discovery.CustomPath, error) {
	rows, err := s.db.Query(`SELECT label, path FROM custom_configs ORDER BY added_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []discovery.CustomPath
	for rows.Next() {
		var c discovery.CustomPath
		if err := rows.Scan(&c.Label, &c.Path); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RecordAuditSnapshot appends a summary record to audit_history.
func (s *Store) RecordAuditSnapshot(res model.ServerAuditResult) error {
	_, err := s.db.Exec(`
		INSERT INTO audit_history (server_id, server_name, client_name, risk_score, risk_level, findings_count, tool_count, scanned_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, res.Server.ID, res.Server.ServerName, res.Server.ClientName, res.RiskScore, res.RiskLevel, len(res.Findings), len(res.Tools), res.InspectedAt)
	return err
}

// GetAuditHistory returns the most recent audit history entries.
func (s *Store) GetAuditHistory(limit int) ([]model.AuditHistoryEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(`
		SELECT id, server_id, server_name, client_name, risk_score, risk_level, findings_count, tool_count, scanned_at
		FROM audit_history
		ORDER BY id DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.AuditHistoryEntry
	for rows.Next() {
		var e model.AuditHistoryEntry
		if err := rows.Scan(&e.ID, &e.ServerID, &e.ServerName, &e.ClientName, &e.RiskScore, &e.RiskLevel, &e.FindingsCount, &e.ToolCount, &e.ScannedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetPolicyYAML returns the persisted policy YAML, or empty string if none is saved yet.
func (s *Store) GetPolicyYAML() (string, error) {
	row := s.db.QueryRow(`SELECT yaml_content FROM policy_config WHERE id = 1`)
	var content string
	if err := row.Scan(&content); err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return content, nil
}

// SavePolicyYAML persists the user's policy YAML document.
func (s *Store) SavePolicyYAML(content string) error {
	_, err := s.db.Exec(`
		INSERT INTO policy_config (id, yaml_content, updated_at)
		VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			yaml_content = excluded.yaml_content,
			updated_at = excluded.updated_at
	`, content, time.Now().UTC().Format(time.RFC3339))
	return err
}

// RecordTrafficEvent persists a runtime firewall traffic event and returns its row ID.
func (s *Store) RecordTrafficEvent(ev model.TrafficEvent) (int64, error) {
	dlpJSON, _ := json.Marshal(ev.DLPHits)
	injInt := 0
	if ev.InjectionDetected {
		injInt = 1
	}
	res, err := s.db.Exec(`
		INSERT INTO traffic_logs (
			request_id, timestamp, server_name, direction, method, tool_name,
			args_preview, response_preview, decision, rule_id, rule_name, reason,
			severity, dlp_hits_json, injection_detected, injection_evidence, latency_ms
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		ev.RequestID, ev.Timestamp, ev.ServerName, ev.Direction, ev.Method, ev.ToolName,
		ev.ArgsPreview, ev.ResponsePreview, ev.Decision, ev.RuleID, ev.RuleName, ev.Reason,
		string(ev.Severity), string(dlpJSON), injInt, ev.InjectionEvidence, ev.LatencyMs,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetTrafficLogs returns the most recent runtime firewall traffic events.
func (s *Store) GetTrafficLogs(limit int) ([]model.TrafficEvent, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.Query(`
		SELECT id, request_id, timestamp, server_name, direction, method, tool_name,
		       args_preview, response_preview, decision, rule_id, rule_name, reason,
		       severity, dlp_hits_json, injection_detected, injection_evidence, latency_ms
		FROM traffic_logs
		ORDER BY id DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.TrafficEvent
	for rows.Next() {
		var ev model.TrafficEvent
		var sev, dlpJSON string
		var injInt int
		if err := rows.Scan(
			&ev.ID, &ev.RequestID, &ev.Timestamp, &ev.ServerName, &ev.Direction, &ev.Method, &ev.ToolName,
			&ev.ArgsPreview, &ev.ResponsePreview, &ev.Decision, &ev.RuleID, &ev.RuleName, &ev.Reason,
			&sev, &dlpJSON, &injInt, &ev.InjectionEvidence, &ev.LatencyMs,
		); err != nil {
			return nil, err
		}
		ev.Severity = model.Severity(sev)
		ev.InjectionDetected = injInt != 0
		_ = json.Unmarshal([]byte(dlpJSON), &ev.DLPHits)
		out = append(out, ev)
	}
	return out, rows.Err()
}

// ClearTrafficLogs deletes all recorded runtime traffic events.
func (s *Store) ClearTrafficLogs() error {
	_, err := s.db.Exec(`DELETE FROM traffic_logs`)
	return err
}

// SaveHTTPProxyRoute persists an HTTP/SSE reverse proxy route.
func (s *Store) SaveHTTPProxyRoute(r model.HTTPProxyRoute) error {
	en := 0
	if r.Enabled {
		en = 1
	}
	if r.CreatedAt == "" {
		r.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := s.db.Exec(`
		INSERT INTO http_proxy_routes (slug, id, server_name, upstream_url, enabled, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(slug) DO UPDATE SET
			server_name = excluded.server_name,
			upstream_url = excluded.upstream_url,
			enabled = excluded.enabled
	`, r.Slug, r.ID, r.ServerName, r.UpstreamURL, en, r.CreatedAt)
	return err
}

// ListHTTPProxyRoutes returns all configured HTTP/SSE reverse proxy routes.
func (s *Store) ListHTTPProxyRoutes() ([]model.HTTPProxyRoute, error) {
	rows, err := s.db.Query(`
		SELECT id, slug, server_name, upstream_url, enabled, created_at
		FROM http_proxy_routes
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.HTTPProxyRoute
	for rows.Next() {
		var r model.HTTPProxyRoute
		var en int
		if err := rows.Scan(&r.ID, &r.Slug, &r.ServerName, &r.UpstreamURL, &en, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.Enabled = en != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteHTTPProxyRoute removes a saved HTTP/SSE reverse proxy route by slug.
func (s *Store) DeleteHTTPProxyRoute(slug string) error {
	_, err := s.db.Exec(`DELETE FROM http_proxy_routes WHERE slug = ?`, slug)
	return err
}
