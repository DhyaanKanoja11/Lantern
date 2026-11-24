package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestMCPCommand_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"mcp", "--help"})

	err := rootCmd.Execute()
	_ = mcpCmd.Flags().Set("help", "false")
	rootCmd.SetArgs(nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Model Context Protocol") {
		t.Errorf("expected MCP help text, got: %s", out)
	}
}

func TestMCPCommand_ExecuteSession(t *testing.T) {
	inBuf := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n")
	outBuf := new(bytes.Buffer)

	rootCmd.SetIn(inBuf)
	rootCmd.SetOut(outBuf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"mcp"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error running mcp: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(outBuf.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 responses, got: %s", outBuf.String())
	}

	var initResp, listResp struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Result  any    `json:"result"`
	}

	if err := json.Unmarshal([]byte(lines[0]), &initResp); err != nil {
		t.Fatalf("failed to decode initResp (output was %q): %v", outBuf.String(), err)
	}
	if initResp.ID != 1 {
		t.Errorf("expected init ID 1, got %d", initResp.ID)
	}

	if err := json.Unmarshal([]byte(lines[1]), &listResp); err != nil {
		t.Fatalf("failed to decode listResp: %v", err)
	}
	if listResp.ID != 2 {
		t.Errorf("expected list ID 2, got %d", listResp.ID)
	}
}
