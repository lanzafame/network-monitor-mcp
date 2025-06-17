package security

import (
	"fmt"
	"strings"
	"time"

	"github.com/skapa-xyz/network-monitor-mcp/capture"
)

type Detector struct {
	suspiciousIPs   map[string]ThreatInfo
	portScanners    map[string]*PortScanInfo
	dnsBlacklist    []string
	anomalyPatterns []AnomalyPattern
}

type ThreatInfo struct {
	IP         string    `json:"ip"`
	ThreatType string    `json:"threatType"`
	Severity   string    `json:"severity"`
	FirstSeen  time.Time `json:"firstSeen"`
	LastSeen   time.Time `json:"lastSeen"`
	Count      int       `json:"count"`
	Details    string    `json:"details"`
}

type PortScanInfo struct {
	SourceIP     string              `json:"sourceIP"`
	TargetPorts  map[int]bool        `json:"targetPorts"`
	TargetIPs    map[string]bool     `json:"targetIPs"`
	FirstSeen    time.Time           `json:"firstSeen"`
	LastSeen     time.Time           `json:"lastSeen"`
	PacketCount  int                 `json:"packetCount"`
	ScanType     string              `json:"scanType"`
}

type AnomalyPattern struct {
	Name        string
	Description string
	Detector    func(packet capture.PacketInfo) bool
}

type SuspiciousActivity struct {
	Threats      []ThreatInfo      `json:"threats"`
	PortScans    []PortScanInfo    `json:"portScans"`
	Anomalies    []AnomalyInfo     `json:"anomalies"`
	Summary      map[string]int    `json:"summary"`
}

type AnomalyInfo struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Packets     []string  `json:"packets"`
	FirstSeen   time.Time `json:"firstSeen"`
}

func NewDetector() *Detector {
	return &Detector{
		suspiciousIPs: make(map[string]ThreatInfo),
		portScanners:  make(map[string]*PortScanInfo),
		dnsBlacklist: []string{
			"malware.com",
			"c2server.net",
			"phishing.org",
			"cryptominer.io",
		},
		anomalyPatterns: []AnomalyPattern{
			{
				Name:        "large_data_transfer",
				Description: "Unusually large data transfer detected",
				Detector: func(p capture.PacketInfo) bool {
					return p.PayloadSize > 10000
				},
			},
			{
				Name:        "suspicious_port",
				Description: "Connection to suspicious port",
				Detector: func(p capture.PacketInfo) bool {
					suspiciousPorts := []int{1337, 31337, 4444, 5555, 6666, 6667, 12345}
					for _, port := range suspiciousPorts {
						if p.DstPort == port || p.SrcPort == port {
							return true
						}
					}
					return false
				},
			},
			{
				Name:        "unusual_protocol",
				Description: "Unusual protocol usage detected",
				Detector: func(p capture.PacketInfo) bool {
					return p.Protocol == "ICMP" && p.PayloadSize > 100
				},
			},
		},
	}
}

func (d *Detector) AnalyzePackets(packets []capture.PacketInfo) {
	for _, packet := range packets {
		d.detectPortScan(packet)
		d.detectMaliciousDNS(packet)
		d.detectAnomalies(packet)
		d.detectDataExfiltration(packet)
	}
}

func (d *Detector) detectPortScan(packet capture.PacketInfo) {
	if packet.Protocol != "TCP" {
		return
	}
	
	// Check for SYN scans
	if contains(packet.Flags, "SYN") && !contains(packet.Flags, "ACK") {
		scanner, exists := d.portScanners[packet.SrcIP]
		if !exists {
			scanner = &PortScanInfo{
				SourceIP:    packet.SrcIP,
				TargetPorts: make(map[int]bool),
				TargetIPs:   make(map[string]bool),
				FirstSeen:   packet.Timestamp,
				ScanType:    "SYN",
			}
			d.portScanners[packet.SrcIP] = scanner
		}
		
		scanner.TargetPorts[packet.DstPort] = true
		scanner.TargetIPs[packet.DstIP] = true
		scanner.LastSeen = packet.Timestamp
		scanner.PacketCount++
		
		// Detect port scan pattern
		if len(scanner.TargetPorts) > 10 || len(scanner.TargetIPs) > 5 {
			d.addThreat(packet.SrcIP, "port_scan", "high", 
				fmt.Sprintf("Port scanning detected: %d ports, %d hosts", 
					len(scanner.TargetPorts), len(scanner.TargetIPs)))
		}
	}
}

func (d *Detector) detectMaliciousDNS(packet capture.PacketInfo) {
	if packet.Protocol != "DNS" {
		return
	}
	
	if dnsInfo, ok := packet.Info["dns"].(map[string]interface{}); ok {
		if questions, ok := dnsInfo["questions"].([]string); ok {
			for _, domain := range questions {
				if d.isDomainBlacklisted(domain) {
					d.addThreat(packet.SrcIP, "malicious_dns", "critical",
						fmt.Sprintf("DNS query to blacklisted domain: %s", domain))
				}
				
				// Check for DGA (Domain Generation Algorithm) patterns
				if d.isDGA(domain) {
					d.addThreat(packet.SrcIP, "dga_domain", "high",
						fmt.Sprintf("Possible DGA domain detected: %s", domain))
				}
			}
		}
	}
}

func (d *Detector) detectAnomalies(packet capture.PacketInfo) {
	for _, pattern := range d.anomalyPatterns {
		if pattern.Detector(packet) {
			d.addThreat(packet.SrcIP, pattern.Name, "medium", pattern.Description)
		}
	}
}

func (d *Detector) detectDataExfiltration(packet capture.PacketInfo) {
	// Detect potential data exfiltration to external IPs
	if !capture.IsPrivateIP(packet.SrcIP) && capture.IsPrivateIP(packet.DstIP) {
		return
	}
	
	if packet.PayloadSize > 5000 && !capture.IsPrivateIP(packet.DstIP) {
		d.addThreat(packet.SrcIP, "data_exfiltration", "high",
			fmt.Sprintf("Large data transfer to external IP %s: %d bytes", 
				packet.DstIP, packet.PayloadSize))
	}
}

func (d *Detector) addThreat(ip, threatType, severity, details string) {
	key := fmt.Sprintf("%s:%s", ip, threatType)
	
	if threat, exists := d.suspiciousIPs[key]; exists {
		threat.Count++
		threat.LastSeen = time.Now()
		d.suspiciousIPs[key] = threat
	} else {
		d.suspiciousIPs[key] = ThreatInfo{
			IP:         ip,
			ThreatType: threatType,
			Severity:   severity,
			FirstSeen:  time.Now(),
			LastSeen:   time.Now(),
			Count:      1,
			Details:    details,
		}
	}
}

func (d *Detector) isDomainBlacklisted(domain string) bool {
	domain = strings.ToLower(domain)
	for _, blacklisted := range d.dnsBlacklist {
		if strings.Contains(domain, blacklisted) {
			return true
		}
	}
	return false
}

func (d *Detector) isDGA(domain string) bool {
	// Simple DGA detection based on entropy and patterns
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	
	subdomain := parts[0]
	
	// Check for high consonant ratio (common in DGA)
	consonants := 0
	for _, r := range subdomain {
		if !strings.ContainsRune("aeiou", r) {
			consonants++
		}
	}
	
	ratio := float64(consonants) / float64(len(subdomain))
	
	// DGA domains often have:
	// - High consonant ratio (> 0.75)
	// - Long random-looking strings (> 15 chars)
	// - No common words
	return ratio > 0.75 && len(subdomain) > 15
}

func (d *Detector) AnalyzeTraffic(packets []capture.PacketInfo) map[string]interface{} {
	stats := capture.AnalyzePackets(packets)
	
	// Identify suspicious patterns
	suspiciousConnections := 0
	externalConnections := 0
	
	for conn := range stats.ConnectionMap {
		parts := strings.Split(conn, ":")
		if len(parts) >= 4 {
			srcIP := parts[0]
			dstIP := parts[2]
			
			if !capture.IsPrivateIP(dstIP) {
				externalConnections++
			}
			
			if _, exists := d.suspiciousIPs[srcIP]; exists {
				suspiciousConnections++
			}
		}
	}
	
	return map[string]interface{}{
		"stats":                 stats,
		"suspiciousConnections": suspiciousConnections,
		"externalConnections":   externalConnections,
		"threatCount":           len(d.suspiciousIPs),
		"activeScanners":        len(d.portScanners),
	}
}

func (d *Detector) GetSuspiciousActivity(packets []capture.PacketInfo, threatType string) SuspiciousActivity {
	activity := SuspiciousActivity{
		Threats:   make([]ThreatInfo, 0),
		PortScans: make([]PortScanInfo, 0),
		Anomalies: make([]AnomalyInfo, 0),
		Summary:   make(map[string]int),
	}
	
	// Collect threats
	for _, threat := range d.suspiciousIPs {
		if threatType == "" || threat.ThreatType == threatType {
			activity.Threats = append(activity.Threats, threat)
			activity.Summary[threat.ThreatType]++
		}
	}
	
	// Collect port scans
	for _, scan := range d.portScanners {
		if len(scan.TargetPorts) > 5 {
			activity.PortScans = append(activity.PortScans, *scan)
		}
	}
	
	return activity
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
