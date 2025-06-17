package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sourcegraph/jsonrpc2"
	"github.com/skapa-xyz/network-monitor-mcp/capture"
	"github.com/skapa-xyz/network-monitor-mcp/security"
)

type Server struct {
	conn     *jsonrpc2.Conn
	sniffer  *capture.Sniffer
	detector *security.Detector
}

func NewServer() *Server {
	return &Server{
		sniffer:  capture.NewSniffer(),
		detector: security.NewDetector(),
	}
}

func (s *Server) Start() error {
	stream := &stdioStream{
		stdin:  bufio.NewReader(os.Stdin),
		stdout: bufio.NewWriter(os.Stdout),
	}
	
	handler := jsonrpc2.HandlerWithError(s.handleRequest)
	s.conn = jsonrpc2.NewConn(context.Background(), stream, handler)
	
	if err := s.sendInitialize(); err != nil {
		return fmt.Errorf("failed to send initialize: %w", err)
	}
	
	<-s.conn.DisconnectNotify()
	return nil
}

func (s *Server) sendInitialize() error {
	initResp := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    "network-monitor-mcp",
			"version": "1.0.0",
		},
	}
	
	return s.conn.Reply(context.Background(), jsonrpc2.ID{}, initResp)
}

func (s *Server) handleRequest(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) (interface{}, error) {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(ctx, conn, req)
	case "tools/list":
		return s.handleToolsList(ctx, conn, req)
	case "tools/call":
		return s.handleToolsCall(ctx, conn, req)
	default:
		return nil, &jsonrpc2.Error{
			Code:    jsonrpc2.CodeMethodNotFound,
			Message: fmt.Sprintf("method not found: %s", req.Method),
		}
	}
}

func (s *Server) handleInitialize(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) (interface{}, error) {
	return map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    "network-monitor-mcp",
			"version": "1.0.0",
		},
	}, nil
}

func (s *Server) handleToolsList(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) (interface{}, error) {
	tools := []map[string]interface{}{
		{
			"name":        "capture_start",
			"description": "Start capturing network packets with optional filters",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"interface": map[string]interface{}{
						"type":        "string",
						"description": "Network interface to capture from (e.g., en0, wlan0)",
					},
					"filter": map[string]interface{}{
						"type":        "string",
						"description": "BPF filter expression (e.g., 'tcp port 80')",
					},
					"maxPackets": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum number of packets to capture (default: 10000)",
					},
				},
				"required": []string{"interface"},
			},
		},
		{
			"name":        "capture_stop",
			"description": "Stop the current packet capture session",
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			"name":        "get_packets",
			"description": "Retrieve captured packets with optional filtering",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"protocol": map[string]interface{}{
						"type":        "string",
						"description": "Filter by protocol (tcp, udp, icmp, dns, http)",
					},
					"srcIP": map[string]interface{}{
						"type":        "string",
						"description": "Filter by source IP address",
					},
					"dstIP": map[string]interface{}{
						"type":        "string",
						"description": "Filter by destination IP address",
					},
					"port": map[string]interface{}{
						"type":        "integer",
						"description": "Filter by port number",
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum number of packets to return (default: 100)",
					},
				},
			},
		},
		{
			"name":        "analyze_traffic",
			"description": "Get traffic statistics and analysis",
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			"name":        "get_suspicious",
			"description": "Get packets and connections flagged as suspicious",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"threatType": map[string]interface{}{
						"type":        "string",
						"description": "Filter by threat type (port_scan, data_exfil, malicious_dns, unusual_pattern)",
					},
				},
			},
		},
	}
	
	return map[string]interface{}{"tools": tools}, nil
}

type stdioStream struct {
	stdin  *bufio.Reader
	stdout *bufio.Writer
}

func (s *stdioStream) WriteObject(obj interface{}) error {
	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	
	if _, err := s.stdout.Write(data); err != nil {
		return err
	}
	if err := s.stdout.WriteByte('\n'); err != nil {
		return err
	}
	return s.stdout.Flush()
}

func (s *stdioStream) ReadObject(v interface{}) error {
	line, err := s.stdin.ReadBytes('\n')
	if err != nil {
		return err
	}
	return json.Unmarshal(line, v)
}

func (s *stdioStream) Close() error {
	return s.stdout.Flush()
}