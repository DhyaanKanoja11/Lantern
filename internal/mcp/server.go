package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/DhyaanKanoja11/Lantern/internal/exposure"
	"github.com/DhyaanKanoja11/Lantern/internal/output"
	"github.com/DhyaanKanoja11/Lantern/internal/reclaim"
)

// MCP Protocol Version
const ProtocolVersion = "2024-11-05"

// JSON-RPC 2.0 Error Codes
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// Request represents a JSON-RPC 2.0 incoming request or notification.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response represents a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError represents a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Server implements a Model Context Protocol (MCP) stdio server.
type Server struct {
	version      string
	analyzer     exposure.Analyzer
	reclaimer    reclaim.Reclaimer
	doctorRunner func(context.Context) any

	mu          sync.Mutex
	initialized bool
}

// NewServer initializes a new MCP Server instance.
func NewServer(
	version string,
	analyzer exposure.Analyzer,
	reclaimer reclaim.Reclaimer,
	doctorRunner func(context.Context) any,
) *Server {
	return &Server{
		version:      version,
		analyzer:     analyzer,
		reclaimer:    reclaimer,
		doctorRunner: doctorRunner,
	}
}

// Serve reads JSON-RPC messages line-by-line from r and writes responses to w.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		resp := s.HandleMessage(ctx, line)
		if resp != nil {
			data, err := json.Marshal(resp)
			if err != nil {
				continue
			}
			data = append(data, '\n')
			if _, err := w.Write(data); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}

// HandleMessage parses and executes a single raw JSON-RPC message.
func (s *Server) HandleMessage(ctx context.Context, raw []byte) *Response {
	var req Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return &Response{
			JSONRPC: "2.0",
			ID:      json.RawMessage("null"),
			Error: &RPCError{
				Code:    CodeParseError,
				Message: fmt.Sprintf("Parse error: %v", err),
			},
		}
	}

	if req.JSONRPC != "2.0" {
		return &Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &RPCError{
				Code:    CodeInvalidRequest,
				Message: "Invalid Request: jsonrpc must be '2.0'",
			},
		}
	}

	// Notifications have no ID (or null ID)
	isNotification := len(req.ID) == 0 || string(req.ID) == "null"

	switch req.Method {
	case "initialize":
		res := map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    "lantern",
				"version": s.version,
			},
		}
		s.mu.Lock()
		s.initialized = true
		s.mu.Unlock()
		return &Response{JSONRPC: "2.0", ID: req.ID, Result: res}

	case "notifications/initialized":
		s.mu.Lock()
		s.initialized = true
		s.mu.Unlock()
		return nil

	case "ping":
		return &Response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}}

	case "tools/list":
		return &Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": s.listTools(),
			},
		}

	case "tools/call":
		return s.handleToolCall(ctx, req.ID, req.Params)

	default:
		if isNotification {
			return nil
		}
		return &Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &RPCError{
				Code:    CodeMethodNotFound,
				Message: fmt.Sprintf("Method %q not found", req.Method),
			},
		}
	}
}

func (s *Server) listTools() []map[string]any {
	return []map[string]any{
		{
			"name":        "lantern_scan",
			"description": "Discover active TCP listening services on the host machine, including process attribution, Docker container correlation, and network reachability classification (localhost, LAN, VPN).",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name":        "lantern_why",
			"description": "Explain why a specific network service or port is reachable. Traces the socket back to its process, Docker container, source docker-compose.yml file and line, and network interface reachability.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"port": map[string]any{
						"type":        "integer",
						"description": "TCP port number to inspect and explain (1-65535)",
					},
				},
				"required": []string{"port"},
			},
		},
		{
			"name":        "lantern_free",
			"description": "Safely reclaims an occupied TCP port. Checks whether the port is held by a Docker container or host process and terminates it cleanly without breaking Docker networking.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"port": map[string]any{
						"type":        "integer",
						"description": "TCP port number to free (1-65535)",
					},
					"force": map[string]any{
						"type":        "boolean",
						"description": "Force kill if graceful shutdown fails",
					},
				},
				"required": []string{"port"},
			},
		},
		{
			"name":        "lantern_doctor",
			"description": "Run diagnostic environment checks for socket collection, Docker access, and system tools.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
	}
}

type toolCallRequest struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type toolCallResult struct {
	Content []toolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

type toolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func (s *Server) handleToolCall(ctx context.Context, id json.RawMessage, paramsRaw json.RawMessage) *Response {
	var call toolCallRequest
	if err := json.Unmarshal(paramsRaw, &call); err != nil {
		return &Response{
			JSONRPC: "2.0",
			ID:      id,
			Error: &RPCError{
				Code:    CodeInvalidParams,
				Message: fmt.Sprintf("Invalid parameters: %v", err),
			},
		}
	}

	var text string
	var isError bool

	switch call.Name {
	case "lantern_scan":
		text, isError = s.executeScan(ctx)
	case "lantern_why":
		text, isError = s.executeWhy(ctx, call.Arguments)
	case "lantern_free":
		text, isError = s.executeFree(ctx, call.Arguments)
	case "lantern_doctor":
		text, isError = s.executeDoctor(ctx)
	default:
		return &Response{
			JSONRPC: "2.0",
			ID:      id,
			Error: &RPCError{
				Code:    CodeMethodNotFound,
				Message: fmt.Sprintf("Unknown tool %q", call.Name),
			},
		}
	}

	res := toolCallResult{
		Content: []toolContent{
			{
				Type: "text",
				Text: text,
			},
		},
		IsError: isError,
	}

	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  res,
	}
}

func (s *Server) executeScan(ctx context.Context) (string, bool) {
	if s.analyzer == nil {
		return "Analyzer not configured", true
	}

	report, err := s.analyzer.ScanReport(ctx)
	if err != nil {
		return fmt.Sprintf("Scan failed: %v", err), true
	}

	var buf bytes.Buffer
	formatter := output.NewJSONFormatter()
	if err := formatter.RenderScan(&buf, report.Summaries, report.Notices...); err != nil {
		return fmt.Sprintf("Render failed: %v", err), true
	}

	return buf.String(), false
}

func (s *Server) executeWhy(ctx context.Context, argsRaw json.RawMessage) (string, bool) {
	var args struct {
		Port int `json:"port"`
	}
	if err := json.Unmarshal(argsRaw, &args); err != nil || args.Port <= 0 || args.Port > 65535 {
		return "Invalid port: must provide an integer port between 1 and 65535", true
	}

	if s.analyzer == nil {
		return "Analyzer not configured", true
	}

	exp, err := s.analyzer.Why(ctx, uint16(args.Port), ".")
	if err != nil {
		if errors.Is(err, exposure.ErrNoListener) {
			return fmt.Sprintf("No listening service found on port %d", args.Port), false
		}
		return fmt.Sprintf("Error explaining port %d: %v", args.Port, err), true
	}

	var buf bytes.Buffer
	formatter := output.NewJSONFormatter()
	if err := formatter.RenderWhy(&buf, exp); err != nil {
		return fmt.Sprintf("Render failed: %v", err), true
	}

	return buf.String(), false
}

func (s *Server) executeFree(ctx context.Context, argsRaw json.RawMessage) (string, bool) {
	var args struct {
		Port  int  `json:"port"`
		Force bool `json:"force"`
	}
	if err := json.Unmarshal(argsRaw, &args); err != nil || args.Port <= 0 || args.Port > 65535 {
		return "Invalid port: must provide an integer port between 1 and 65535", true
	}

	if s.analyzer == nil || s.reclaimer == nil {
		return "Analyzer or Reclaimer not configured", true
	}

	port := uint16(args.Port)
	exp, err := s.analyzer.Why(ctx, port, ".")
	if err != nil {
		if errors.Is(err, exposure.ErrNoListener) {
			return fmt.Sprintf("Port %d is already free (no listening service found).", port), false
		}
		return fmt.Sprintf("Failed to inspect port %d: %v", port, err), true
	}

	plan, err := s.reclaimer.Plan(ctx, exp)
	if err != nil {
		return fmt.Sprintf("Failed to plan port release: %v", err), true
	}

	if plan.TargetType == reclaim.TargetUnknown {
		return fmt.Sprintf("Port %d is occupied, but the listener process/container is unknown or unprivileged.", port), true
	}

	result, err := s.reclaimer.Apply(ctx, plan, args.Force, 0)
	if err != nil {
		return fmt.Sprintf("Failed to free port %d: %v", port, err), true
	}

	targetName := plan.ProcessName
	if plan.TargetType == reclaim.TargetContainer {
		targetName = plan.ContainerName
	}

	outMap := map[string]any{
		"port":        port,
		"target_type": string(plan.TargetType),
		"target_name": targetName,
		"pid":         plan.PID,
		"container":   plan.ContainerID,
		"status":      "freed",
		"force":       args.Force,
		"description": result.Description,
	}

	outBytes, _ := json.MarshalIndent(outMap, "", "  ")
	return string(outBytes), false
}

func (s *Server) executeDoctor(ctx context.Context) (string, bool) {
	if s.doctorRunner == nil {
		return "Doctor diagnostics not configured", true
	}

	checks := s.doctorRunner(ctx)
	data, err := json.MarshalIndent(checks, "", "  ")
	if err != nil {
		return fmt.Sprintf("Failed to marshal doctor checks: %v", err), true
	}

	return string(data), false
}
