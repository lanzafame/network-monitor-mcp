# Network Monitor MCP Server

A Model Context Protocol (MCP) server for real-time network packet monitoring and security analysis. This tool enables Claude to inspect network traffic and identify potential security threats.

## Features

- Real-time packet capture from WiFi interfaces
- Protocol analysis (TCP, UDP, DNS, HTTP/HTTPS)
- Security threat detection:
  - Port scanning detection
  - Malicious DNS queries
  - Data exfiltration patterns
  - Anomaly detection
- MCP tools for Claude integration:
  - `capture_start` - Start packet capture
  - `capture_stop` - Stop capture
  - `get_packets` - Retrieve and filter packets
  - `analyze_traffic` - Traffic statistics
  - `get_suspicious` - Security threat analysis

## Prerequisites

- Go 1.21 or higher
- libpcap development files
- Root/sudo access for packet capture

### Installing libpcap

**macOS:**
```bash
brew install libpcap
```

**Linux:**
```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev

# RHEL/CentOS
sudo yum install libpcap-devel
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/skapa-xyz/network-monitor-mcp.git
cd network-monitor-mcp
```

2. Install dependencies:
```bash
go mod download
```

3. Build the server:
```bash
go build -o network-monitor-mcp
```

## Usage

### Running the MCP Server

The server requires root privileges for packet capture:

```bash
sudo ./network-monitor-mcp
```

### Configuring Claude Desktop

**⚠️ IMPORTANT SECURITY WARNING:**

Claude Desktop cannot directly execute commands with sudo. To use this MCP server with Claude Desktop, you have two options:

**Option 1: Sudoers Configuration (NOT RECOMMENDED for production)**

You can configure sudo to allow the network-monitor-mcp binary to run without a password prompt. This has **SIGNIFICANT SECURITY IMPLICATIONS** and should only be done in isolated development environments where security is not a concern.

1. Edit the sudoers file:
   ```bash
   sudo visudo
   ```

2. Add the following line (replace username and path):
   ```
   username ALL=(ALL) NOPASSWD: /path/to/network-monitor-mcp
   ```

3. Update Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):
   ```json
   {
     "mcpServers": {
       "network-monitor": {
         "command": "/path/to/network-monitor-mcp"
       }
     }
   }
   ```

**⚠️ SECURITY RISKS:**
- This grants passwordless root access to the binary
- If the binary is compromised, an attacker gains root access
- Network packet capture can expose sensitive data
- Only use this in isolated development/testing environments
- Never use this configuration on production systems or machines with sensitive data

**Option 2: Run Claude Desktop with elevated privileges (ALSO NOT RECOMMENDED)**

You could run Claude Desktop itself with sudo, but this gives the entire application root access, which poses even greater security risks.

### Recommended Approach

For production use, consider:
- Running the MCP server as a system service with proper permissions
- Using a dedicated monitoring system with appropriate access controls
- Implementing proper authentication and authorization mechanisms

### Example Claude Commands

1. **Start monitoring your WiFi interface:**
   ```
   Use the capture_start tool to monitor interface "en0" with a filter for TCP traffic
   ```

2. **Check for suspicious activity:**
   ```
   Use get_suspicious to show any detected security threats
   ```

3. **Analyze traffic patterns:**
   ```
   Use analyze_traffic to show network statistics and connection patterns
   ```

4. **Filter specific packets:**
   ```
   Use get_packets to show all DNS queries or traffic to port 443
   ```

## Security Considerations

- This tool requires root access to capture packets
- Only use on networks you own or have permission to monitor
- Captured data may contain sensitive information
- The tool is designed for legitimate security monitoring in enterprise environments

## Architecture

```
network-monitor-mcp/
├── main.go              # Entry point
├── mcp/                 # MCP protocol implementation
│   ├── server.go        # MCP server core
│   └── handlers.go      # Tool handlers
├── capture/             # Packet capture functionality
│   ├── sniffer.go       # Packet capture engine
│   └── analyzer.go      # Traffic analysis
└── security/            # Security detection
    └── detector.go      # Threat detection algorithms
```

## Troubleshooting

1. **Permission denied errors:**
   - Ensure you're running with sudo
   - Check libpcap installation

2. **Interface not found:**
   - List available interfaces: `ifconfig` or `ip link`
   - Common WiFi interfaces: `en0` (macOS), `wlan0` (Linux)

3. **No packets captured:**
   - Verify the interface is active
   - Check your BPF filter syntax
   - Ensure there's network traffic to capture

## Development

To contribute or modify:

1. Follow Go best practices
2. Add tests for new features
3. Update documentation
4. Test with Claude Desktop before submitting

## License

This project is for authorized security monitoring only. Use responsibly and in compliance with all applicable laws and regulations.