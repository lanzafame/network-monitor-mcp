package main

import (
	"log"
	"os"

	"github.com/skapa-xyz/network-monitor-mcp/mcp"
)

func main() {
	server := mcp.NewServer()
	
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start MCP server: %v", err)
		os.Exit(1)
	}
}