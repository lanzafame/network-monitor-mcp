package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sourcegraph/jsonrpc2"
)

type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (s *Server) handleToolsCall(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) (interface{}, error) {
	var params ToolCallParams
	if err := json.Unmarshal(*req.Params, &params); err != nil {
		return nil, &jsonrpc2.Error{
			Code:    jsonrpc2.CodeInvalidParams,
			Message: "invalid parameters",
		}
	}
	
	var result interface{}
	var err error
	
	switch params.Name {
	case "capture_start":
		result, err = s.handleCaptureStart(params.Arguments)
	case "capture_stop":
		result, err = s.handleCaptureStop()
	case "get_packets":
		result, err = s.handleGetPackets(params.Arguments)
	case "analyze_traffic":
		result, err = s.handleAnalyzeTraffic()
	case "get_suspicious":
		result, err = s.handleGetSuspicious(params.Arguments)
	default:
		return nil, &jsonrpc2.Error{
			Code:    jsonrpc2.CodeMethodNotFound,
			Message: fmt.Sprintf("unknown tool: %s", params.Name),
		}
	}
	
	if err != nil {
		return nil, &jsonrpc2.Error{
			Code:    jsonrpc2.CodeInternalError,
			Message: err.Error(),
		}
	}
	
	response := map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": formatResult(result),
			},
		},
	}
	
	return response, nil
}

type CaptureStartParams struct {
	Interface   string `json:"interface"`
	Filter      string `json:"filter"`
	MaxPackets  int    `json:"maxPackets"`
}

func (s *Server) handleCaptureStart(args json.RawMessage) (interface{}, error) {
	var params CaptureStartParams
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}
	
	if params.MaxPackets == 0 {
		params.MaxPackets = 10000
	}
	
	err := s.sniffer.Start(params.Interface, params.Filter, params.MaxPackets)
	if err != nil {
		return nil, err
	}
	
	return map[string]interface{}{
		"status":    "started",
		"interface": params.Interface,
		"filter":    params.Filter,
		"maxPackets": params.MaxPackets,
	}, nil
}

func (s *Server) handleCaptureStop() (interface{}, error) {
	stats := s.sniffer.Stop()
	return stats, nil
}

type GetPacketsParams struct {
	Protocol string `json:"protocol"`
	SrcIP    string `json:"srcIP"`
	DstIP    string `json:"dstIP"`
	Port     int    `json:"port"`
	Limit    int    `json:"limit"`
}

func (s *Server) handleGetPackets(args json.RawMessage) (interface{}, error) {
	var params GetPacketsParams
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}
	
	if params.Limit == 0 {
		params.Limit = 100
	}
	
	packets := s.sniffer.GetPackets(params.Protocol, params.SrcIP, params.DstIP, params.Port, params.Limit)
	
	s.detector.AnalyzePackets(packets)
	
	return map[string]interface{}{
		"count":   len(packets),
		"packets": packets,
	}, nil
}

func (s *Server) handleAnalyzeTraffic() (interface{}, error) {
	packets := s.sniffer.GetAllPackets()
	analysis := s.detector.AnalyzeTraffic(packets)
	return analysis, nil
}

type GetSuspiciousParams struct {
	ThreatType string `json:"threatType"`
}

func (s *Server) handleGetSuspicious(args json.RawMessage) (interface{}, error) {
	var params GetSuspiciousParams
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}
	
	packets := s.sniffer.GetAllPackets()
	suspicious := s.detector.GetSuspiciousActivity(packets, params.ThreatType)
	
	return suspicious, nil
}

func formatResult(result interface{}) string {
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error formatting result: %v", err)
	}
	return string(b)
}