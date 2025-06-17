package capture

import (
	"net"
	"strings"
)

type TrafficStats struct {
	TotalPackets   int                       `json:"totalPackets"`
	TotalBytes     int64                     `json:"totalBytes"`
	ProtocolStats  map[string]int            `json:"protocolStats"`
	TopSrcIPs      map[string]int            `json:"topSrcIPs"`
	TopDstIPs      map[string]int            `json:"topDstIPs"`
	TopPorts       map[int]int               `json:"topPorts"`
	ConnectionMap  map[string]ConnectionInfo `json:"connections"`
}

type ConnectionInfo struct {
	PacketCount int   `json:"packetCount"`
	ByteCount   int64 `json:"byteCount"`
	FirstSeen   int64 `json:"firstSeen"`
	LastSeen    int64 `json:"lastSeen"`
}

func AnalyzePackets(packets []PacketInfo) TrafficStats {
	stats := TrafficStats{
		ProtocolStats: make(map[string]int),
		TopSrcIPs:     make(map[string]int),
		TopDstIPs:     make(map[string]int),
		TopPorts:      make(map[int]int),
		ConnectionMap: make(map[string]ConnectionInfo),
	}
	
	for _, packet := range packets {
		stats.TotalPackets++
		stats.TotalBytes += int64(packet.Length)
		
		// Protocol statistics
		stats.ProtocolStats[packet.Protocol]++
		
		// IP statistics
		if packet.SrcIP != "" {
			stats.TopSrcIPs[packet.SrcIP]++
		}
		if packet.DstIP != "" {
			stats.TopDstIPs[packet.DstIP]++
		}
		
		// Port statistics
		if packet.SrcPort > 0 {
			stats.TopPorts[packet.SrcPort]++
		}
		if packet.DstPort > 0 {
			stats.TopPorts[packet.DstPort]++
		}
		
		// Connection tracking
		connKey := formatConnection(packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort)
		conn := stats.ConnectionMap[connKey]
		conn.PacketCount++
		conn.ByteCount += int64(packet.Length)
		
		timestamp := packet.Timestamp.Unix()
		if conn.FirstSeen == 0 || timestamp < conn.FirstSeen {
			conn.FirstSeen = timestamp
		}
		if timestamp > conn.LastSeen {
			conn.LastSeen = timestamp
		}
		
		stats.ConnectionMap[connKey] = conn
	}
	
	return stats
}

func formatConnection(srcIP string, srcPort int, dstIP string, dstPort int) string {
	return strings.Join([]string{srcIP, string(srcPort), dstIP, string(dstPort)}, ":")
}

func IsPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsedIP) {
			return true
		}
	}
	
	return false
}

func GetServiceName(port int) string {
	commonPorts := map[int]string{
		20:    "FTP-DATA",
		21:    "FTP",
		22:    "SSH",
		23:    "TELNET",
		25:    "SMTP",
		53:    "DNS",
		67:    "DHCP",
		68:    "DHCP",
		80:    "HTTP",
		110:   "POP3",
		123:   "NTP",
		143:   "IMAP",
		161:   "SNMP",
		194:   "IRC",
		443:   "HTTPS",
		445:   "SMB",
		465:   "SMTPS",
		514:   "SYSLOG",
		587:   "SMTP",
		636:   "LDAPS",
		989:   "FTPS",
		990:   "FTPS",
		993:   "IMAPS",
		995:   "POP3S",
		1433:  "MSSQL",
		1521:  "ORACLE",
		3306:  "MYSQL",
		3389:  "RDP",
		5432:  "POSTGRESQL",
		5900:  "VNC",
		6379:  "REDIS",
		8080:  "HTTP-PROXY",
		8443:  "HTTPS-ALT",
		9200:  "ELASTICSEARCH",
		27017: "MONGODB",
	}
	
	if service, ok := commonPorts[port]; ok {
		return service
	}
	
	return "UNKNOWN"
}