package capture

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketInfo struct {
	Timestamp   time.Time              `json:"timestamp"`
	Protocol    string                 `json:"protocol"`
	SrcIP       string                 `json:"srcIP"`
	DstIP       string                 `json:"dstIP"`
	SrcPort     int                    `json:"srcPort"`
	DstPort     int                    `json:"dstPort"`
	Length      int                    `json:"length"`
	PayloadSize int                    `json:"payloadSize"`
	Flags       []string               `json:"flags,omitempty"`
	Info        map[string]interface{} `json:"info,omitempty"`
	Raw         []byte                 `json:"-"`
}

type CaptureStats struct {
	PacketsCaptured int       `json:"packetsCaptured"`
	BytesCaptured   int64     `json:"bytesCaptured"`
	StartTime       time.Time `json:"startTime"`
	EndTime         time.Time `json:"endTime"`
	Duration        string    `json:"duration"`
}

type Sniffer struct {
	handle      *pcap.Handle
	packets     []PacketInfo
	stats       CaptureStats
	isCapturing bool
	mu          sync.RWMutex
	stopChan    chan struct{}
	maxPackets  int
}

func NewSniffer() *Sniffer {
	return &Sniffer{
		packets:  make([]PacketInfo, 0),
		stopChan: make(chan struct{}),
	}
}

func (s *Sniffer) Start(iface, filter string, maxPackets int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.isCapturing {
		return fmt.Errorf("capture already in progress")
	}
	
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %w", iface, err)
	}
	
	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			handle.Close()
			return fmt.Errorf("failed to set BPF filter: %w", err)
		}
	}
	
	s.handle = handle
	s.packets = make([]PacketInfo, 0)
	s.maxPackets = maxPackets
	s.isCapturing = true
	s.stats = CaptureStats{
		StartTime: time.Now(),
	}
	s.stopChan = make(chan struct{})
	
	go s.capturePackets()
	
	return nil
}

func (s *Sniffer) Stop() CaptureStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if !s.isCapturing {
		return s.stats
	}
	
	close(s.stopChan)
	s.isCapturing = false
	
	if s.handle != nil {
		s.handle.Close()
	}
	
	s.stats.EndTime = time.Now()
	s.stats.Duration = s.stats.EndTime.Sub(s.stats.StartTime).String()
	
	return s.stats
}

func (s *Sniffer) capturePackets() {
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	
	for {
		select {
		case <-s.stopChan:
			return
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}
			
			s.mu.Lock()
			if len(s.packets) >= s.maxPackets {
				s.mu.Unlock()
				return
			}
			
			if info := s.parsePacket(packet); info != nil {
				s.packets = append(s.packets, *info)
				s.stats.PacketsCaptured++
				s.stats.BytesCaptured += int64(len(packet.Data()))
			}
			s.mu.Unlock()
		}
	}
}

func (s *Sniffer) parsePacket(packet gopacket.Packet) *PacketInfo {
	info := &PacketInfo{
		Timestamp: packet.Metadata().Timestamp,
		Length:    packet.Metadata().Length,
		Info:      make(map[string]interface{}),
		Raw:       packet.Data(),
	}
	
	// Parse network layer
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		switch net := netLayer.(type) {
		case *layers.IPv4:
			info.SrcIP = net.SrcIP.String()
			info.DstIP = net.DstIP.String()
			info.Protocol = net.NextLayerType().String()
		case *layers.IPv6:
			info.SrcIP = net.SrcIP.String()
			info.DstIP = net.DstIP.String()
			info.Protocol = net.NextLayerType().String()
		}
	}
	
	// Parse transport layer
	if transLayer := packet.TransportLayer(); transLayer != nil {
		switch trans := transLayer.(type) {
		case *layers.TCP:
			info.SrcPort = int(trans.SrcPort)
			info.DstPort = int(trans.DstPort)
			info.Protocol = "TCP"
			info.PayloadSize = len(trans.Payload)
			
			// Collect TCP flags
			flags := []string{}
			if trans.SYN {
				flags = append(flags, "SYN")
			}
			if trans.ACK {
				flags = append(flags, "ACK")
			}
			if trans.FIN {
				flags = append(flags, "FIN")
			}
			if trans.RST {
				flags = append(flags, "RST")
			}
			if trans.PSH {
				flags = append(flags, "PSH")
			}
			info.Flags = flags
			
		case *layers.UDP:
			info.SrcPort = int(trans.SrcPort)
			info.DstPort = int(trans.DstPort)
			info.Protocol = "UDP"
			info.PayloadSize = len(trans.Payload)
		}
	}
	
	// Parse application layer for common protocols
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		switch app := appLayer.(type) {
		case *layers.DNS:
			info.Protocol = "DNS"
			s.parseDNS(app, info)
		}
	}
	
	// Check for HTTP
	if info.DstPort == 80 || info.SrcPort == 80 {
		info.Info["possibleHTTP"] = true
	}
	
	// Check for HTTPS
	if info.DstPort == 443 || info.SrcPort == 443 {
		info.Info["possibleHTTPS"] = true
	}
	
	return info
}

func (s *Sniffer) parseDNS(dns *layers.DNS, info *PacketInfo) {
	dnsInfo := map[string]interface{}{
		"id":           dns.ID,
		"isResponse":   dns.QR,
		"opCode":       dns.OpCode.String(),
		"responseCode": dns.ResponseCode.String(),
	}
	
	if len(dns.Questions) > 0 {
		questions := make([]string, 0, len(dns.Questions))
		for _, q := range dns.Questions {
			questions = append(questions, string(q.Name))
		}
		dnsInfo["questions"] = questions
	}
	
	if len(dns.Answers) > 0 {
		answers := make([]map[string]interface{}, 0, len(dns.Answers))
		for _, a := range dns.Answers {
			answer := map[string]interface{}{
				"name": string(a.Name),
				"type": a.Type.String(),
				"ttl":  a.TTL,
			}
			
			switch a.Type {
			case layers.DNSTypeA:
				if ip, ok := a.IP.To4().MarshalText(); ok == nil {
					answer["ip"] = string(ip)
				}
			case layers.DNSTypeAAAA:
				if ip, ok := a.IP.MarshalText(); ok == nil {
					answer["ip"] = string(ip)
				}
			}
			
			answers = append(answers, answer)
		}
		dnsInfo["answers"] = answers
	}
	
	info.Info["dns"] = dnsInfo
}

func (s *Sniffer) GetPackets(protocol, srcIP, dstIP string, port, limit int) []PacketInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	filtered := make([]PacketInfo, 0)
	count := 0
	
	for i := len(s.packets) - 1; i >= 0 && count < limit; i-- {
		p := s.packets[i]
		
		if protocol != "" && p.Protocol != protocol {
			continue
		}
		if srcIP != "" && p.SrcIP != srcIP {
			continue
		}
		if dstIP != "" && p.DstIP != dstIP {
			continue
		}
		if port != 0 && p.SrcPort != port && p.DstPort != port {
			continue
		}
		
		filtered = append(filtered, p)
		count++
	}
	
	// Reverse to show oldest first
	for i, j := 0, len(filtered)-1; i < j; i, j = i+1, j-1 {
		filtered[i], filtered[j] = filtered[j], filtered[i]
	}
	
	return filtered
}

func (s *Sniffer) GetAllPackets() []PacketInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	packets := make([]PacketInfo, len(s.packets))
	copy(packets, s.packets)
	return packets
}

func GetAvailableInterfaces() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	
	var names []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			names = append(names, iface.Name)
		}
	}
	
	return names, nil
}
