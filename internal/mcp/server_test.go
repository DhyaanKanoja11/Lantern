package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
	"github.com/DhyaanKanoja11/Lantern/internal/exposure"
	"github.com/DhyaanKanoja11/Lantern/internal/reclaim"
)

type mockAnalyzer struct {
	report *domain.ScanReport
	exp    *domain.Exposure
	err    error
}

func (m *mockAnalyzer) Scan(ctx context.Context) ([]domain.ExposureSummary, error) {
	if m.report == nil {
		return nil, m.err
	}
	return m.report.Summaries, m.err
}

func (m *mockAnalyzer) ScanReport(ctx context.Context) (*domain.ScanReport, error) {
	return m.report, m.err
}

func (m *mockAnalyzer) Why(ctx context.Context, port uint16, composePath string) (*domain.Exposure, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.exp == nil {
		return nil, exposure.ErrNoListener
	}
	return m.exp, nil
}

type mockReclaimer struct {
	plan   *reclaim.ReclaimPlan
	result *reclaim.ReclaimResult
	err    error
}

func (m *mockReclaimer) Plan(ctx context.Context, exp *domain.Exposure) (*reclaim.ReclaimPlan, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.plan, nil
}

func (m *mockReclaimer) Apply(ctx context.Context, plan *reclaim.ReclaimPlan, force bool, timeout time.Duration) (*reclaim.ReclaimResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

func TestServer_InitializeAndPing(t *testing.T) {
	srv := NewServer("0.2.3", nil, nil, nil)

	// Test Initialize
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`
	resp := srv.HandleMessage(context.Background(), []byte(initReq))
	if resp == nil {
		t.Fatal("expected response for initialize, got nil")
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error.Message)
	}

	resultMap, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("expected map result, got %T", resp.Result)
	}
	if resultMap["protocolVersion"] != ProtocolVersion {
		t.Errorf("expected protocol %s, got %v", ProtocolVersion, resultMap["protocolVersion"])
	}

	// Test Ping
	pingReq := `{"jsonrpc":"2.0","id":2,"method":"ping"}`
	resp = srv.HandleMessage(context.Background(), []byte(pingReq))
	if resp == nil || resp.Error != nil {
		t.Fatalf("expected successful ping, got error: %v", resp.Error)
	}

	// Test Notification (should return nil)
	notif := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	resp = srv.HandleMessage(context.Background(), []byte(notif))
	if resp != nil {
		t.Errorf("expected nil response for notification, got %v", resp)
	}
}

func TestServer_ToolsList(t *testing.T) {
	srv := NewServer("0.2.3", nil, nil, nil)
	req := `{"jsonrpc":"2.0","id":10,"method":"tools/list"}`
	resp := srv.HandleMessage(context.Background(), []byte(req))

	if resp == nil || resp.Error != nil {
		t.Fatalf("failed tools/list: %v", resp.Error)
	}

	res, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("expected result map, got %T", resp.Result)
	}
	tools, ok := res["tools"].([]map[string]any)
	if !ok || len(tools) < 4 {
		t.Fatalf("expected at least 4 tools, got %d", len(tools))
	}

	names := make(map[string]bool)
	for _, tool := range tools {
		names[tool["name"].(string)] = true
	}

	expected := []string{"lantern_scan", "lantern_why", "lantern_free", "lantern_doctor", "lantern_preflight"}
	for _, exp := range expected {
		if !names[exp] {
			t.Errorf("missing expected tool: %s", exp)
		}
	}
}

func TestServer_ToolsCall_Scan(t *testing.T) {
	mockAn := &mockAnalyzer{
		report: &domain.ScanReport{
			Summaries: []domain.ExposureSummary{
				{
					Port:        8080,
					Address:     "127.0.0.1",
					ProcessName: "web",
					PID:         1234,
				},
			},
		},
	}

	srv := NewServer("0.2.3", mockAn, nil, nil)
	req := `{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"lantern_scan","arguments":{}}}`
	resp := srv.HandleMessage(context.Background(), []byte(req))

	if resp == nil || resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(toolCallResult)
	if !ok {
		t.Fatalf("expected toolCallResult, got %T", resp.Result)
	}
	if result.IsError {
		t.Errorf("expected isError=false, got text: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "8080") {
		t.Errorf("expected port 8080 in scan output, got: %s", result.Content[0].Text)
	}
}

func TestServer_ToolsCall_Why(t *testing.T) {
	mockAn := &mockAnalyzer{
		exp: &domain.Exposure{
			Listener: domain.Listener{
				Port:    5432,
				Address: "0.0.0.0",
			},
			Process: &domain.Process{
				Name: "postgres",
				PID:  999,
			},
		},
	}

	srv := NewServer("0.2.3", mockAn, nil, nil)

	// Valid port
	req := `{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"lantern_why","arguments":{"port":5432}}}`
	resp := srv.HandleMessage(context.Background(), []byte(req))
	if resp == nil || resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	res := resp.Result.(toolCallResult)
	if res.IsError || !strings.Contains(res.Content[0].Text, "5432") {
		t.Errorf("unexpected why response: %s", res.Content[0].Text)
	}

	// Missing listener (free port)
	mockAn.exp = nil
	resp = srv.HandleMessage(context.Background(), []byte(req))
	res = resp.Result.(toolCallResult)
	if !strings.Contains(res.Content[0].Text, "No listening service found") {
		t.Errorf("expected 'No listening service found', got: %s", res.Content[0].Text)
	}

	// Invalid port
	badReq := `{"jsonrpc":"2.0","id":31,"method":"tools/call","params":{"name":"lantern_why","arguments":{"port":999999}}}`
	resp = srv.HandleMessage(context.Background(), []byte(badReq))
	res = resp.Result.(toolCallResult)
	if !res.IsError {
		t.Errorf("expected error for invalid port, got: %s", res.Content[0].Text)
	}
}

func TestServer_ToolsCall_Free(t *testing.T) {
	mockAn := &mockAnalyzer{
		exp: &domain.Exposure{
			Listener: domain.Listener{
				Port:    3000,
				Address: "127.0.0.1",
			},
		},
	}
	mockRec := &mockReclaimer{
		plan: &reclaim.ReclaimPlan{
			TargetType:  reclaim.TargetProcess,
			ProcessName: "node",
			PID:         555,
		},
		result: &reclaim.ReclaimResult{
			Port:        3000,
			TargetType:  reclaim.TargetProcess,
			Identifier:  "555",
			Description: "Terminated native process node (PID 555)",
		},
	}

	srv := NewServer("0.2.3", mockAn, mockRec, nil)
	req := `{"jsonrpc":"2.0","id":40,"method":"tools/call","params":{"name":"lantern_free","arguments":{"port":3000}}}`
	resp := srv.HandleMessage(context.Background(), []byte(req))

	if resp == nil || resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	res := resp.Result.(toolCallResult)
	if res.IsError || !strings.Contains(res.Content[0].Text, `"status": "freed"`) {
		t.Errorf("expected freed status, got: %s", res.Content[0].Text)
	}
}

func TestServer_ToolsCall_Doctor(t *testing.T) {
	doctorCalled := false
	mockDoctor := func(ctx context.Context) any {
		doctorCalled = true
		return []map[string]string{
			{"name": "OS", "status": "OK"},
		}
	}

	srv := NewServer("0.2.3", nil, nil, mockDoctor)
	req := `{"jsonrpc":"2.0","id":50,"method":"tools/call","params":{"name":"lantern_doctor","arguments":{}}}`
	resp := srv.HandleMessage(context.Background(), []byte(req))

	if !doctorCalled {
		t.Error("expected doctor function to be called")
	}
	res := resp.Result.(toolCallResult)
	if res.IsError || !strings.Contains(res.Content[0].Text, "OS") {
		t.Errorf("unexpected doctor output: %s", res.Content[0].Text)
	}
}

func TestServer_ToolsCall_Preflight(t *testing.T) {
	srv := NewServer("0.3.0", nil, nil, nil)
	tmpDir := t.TempDir()
	filePath := tmpDir + "/docker-compose.yml"
	content := `
services:
  web:
    image: nginx
    ports:
      - "127.0.0.1:8080:80"
`
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	req := fmt.Sprintf(`{"jsonrpc":"2.0","id":60,"method":"tools/call","params":{"name":"lantern_preflight","arguments":{"file_path":%q}}}`, filePath)
	resp := srv.HandleMessage(context.Background(), []byte(req))
	if resp == nil || resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	res := resp.Result.(toolCallResult)
	if res.IsError || !strings.Contains(res.Content[0].Text, `"passed": true`) {
		t.Errorf("expected passing preflight in MCP, got: %s", res.Content[0].Text)
	}
}

func TestServer_Errors(t *testing.T) {
	srv := NewServer("0.2.3", nil, nil, nil)

	// Malformed JSON
	resp := srv.HandleMessage(context.Background(), []byte(`{invalid`))
	if resp.Error == nil || resp.Error.Code != CodeParseError {
		t.Errorf("expected CodeParseError, got %v", resp.Error)
	}

	// Invalid JSONRPC version
	resp = srv.HandleMessage(context.Background(), []byte(`{"jsonrpc":"1.0","id":1,"method":"ping"}`))
	if resp.Error == nil || resp.Error.Code != CodeInvalidRequest {
		t.Errorf("expected CodeInvalidRequest, got %v", resp.Error)
	}

	// Unknown method
	resp = srv.HandleMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"foo_bar"}`))
	if resp.Error == nil || resp.Error.Code != CodeMethodNotFound {
		t.Errorf("expected CodeMethodNotFound, got %v", resp.Error)
	}

	// Unknown tool
	resp = srv.HandleMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unknown"}}`))
	if resp.Error == nil || resp.Error.Code != CodeMethodNotFound {
		t.Errorf("expected CodeMethodNotFound for unknown tool, got %v", resp.Error)
	}
}

func TestServer_ServeStream(t *testing.T) {
	srv := NewServer("0.2.3", nil, nil, nil)

	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		"",
	}, "\n")

	inBuf := bytes.NewBufferString(input)
	var outBuf bytes.Buffer

	err := srv.Serve(context.Background(), inBuf, &outBuf)
	if err != nil {
		t.Fatalf("Serve returned error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(outBuf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 responses (initialize and ping), got %d lines: %s", len(lines), outBuf.String())
	}

	var resp1, resp2 Response
	if err := json.Unmarshal([]byte(lines[0]), &resp1); err != nil {
		t.Fatalf("failed to parse resp1: %v", err)
	}
	if string(resp1.ID) != "1" {
		t.Errorf("expected ID 1, got %s", resp1.ID)
	}

	if err := json.Unmarshal([]byte(lines[1]), &resp2); err != nil {
		t.Fatalf("failed to parse resp2: %v", err)
	}
	if string(resp2.ID) != "2" {
		t.Errorf("expected ID 2, got %s", resp2.ID)
	}
}

// Requests without an id are notifications: JSON-RPC says the server must not
// reply. tools/call in particular must not run, since it can stop containers
// or kill processes and the caller would never see the result.
func TestServer_NotificationsGetNoResponse(t *testing.T) {
	srv := NewServer("0.2.3", nil, nil, nil)
	for _, msg := range []string{
		`{"jsonrpc":"2.0","method":"ping"}`,
		`{"jsonrpc":"2.0","method":"tools/list"}`,
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"lantern_free","arguments":{"port":5432}}}`,
		`{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"name":"lantern_scan"}}`,
	} {
		if resp := srv.HandleMessage(context.Background(), []byte(msg)); resp != nil {
			t.Errorf("%s: expected no response, got %+v", msg, resp)
		}
	}
}
