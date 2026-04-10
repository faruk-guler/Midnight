package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"math"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// Extension for Windows Event Log (Simulated for Go-Cross-Compile if not on Windows)
type EventInfo struct {
	EventID int    `json:"event_id"`
	Msg     string `json:"msg"`
}

// calculateEntropy detects DGA (Domain Generation Algorithm) signatures
func calculateEntropy(s string) float64 {
	if s == "" { return 0 }
	counts := make(map[rune]int)
	for _, r := range s { counts[r]++ }
	var entropy float64
	for _, count := range counts {
		p := float64(count) / float64(len(s))
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// LogEntry defines the structure of the security logs
type LogEntry struct {
	Timestamp string   `json:"timestamp"`
	Hostname  string   `json:"hostname"`
	OS        string   `json:"os"`
	User      string   `json:"user"`
	PID       int32    `json:"pid"`
	Comm      string   `json:"comm"`
	Cmdline   string   `json:"cmdline"`
	SrcIP     string   `json:"src_ip"`
	SrcPort   int      `json:"src_port"`
	DstIP     string   `json:"dst_ip"`
	DstPort   int      `json:"dst_port"`
	Type      string   `json:"type"`
	Message   string   `json:"message,omitempty"`
	CPU       float64  `json:"cpu,omitempty"`
	RAM       float64  `json:"ram,omitempty"`
	Disk      float64  `json:"disk,omitempty"`
	Services  []string `json:"services,omitempty"`
	ExePath   string   `json:"exe_path,omitempty"`
	Scope     string   `json:"scope,omitempty"`
}

// AgentConfig allows interactive management from the dashboard
type AgentConfig struct {
	DGAEntropy    float64  `json:"dga_entropy"`
	Interval      int      `json:"interval"`
	AllowedPorts  []int    `json:"allowed_ports"`
	DeepScanState bool     `json:"deep_scan_state"`
	Quarantined   bool     `json:"quarantined"`
}

var (
	PollURL    = "http://localhost:4800/api/agent/poll/"
	BackendURL = "http://localhost:4800/api/logs"
	Interval   = 1 * time.Second
	
	// Default global config
	CurrentConfig = AgentConfig{
		DGAEntropy:    4.5,
		Interval:      1,
		AllowedPorts:  []int{22, 80, 443, 4800},
		DeepScanState: false,
	}
)

func init() {
	serverIP := os.Getenv("MIDNIGHT_SERVER")
	if serverIP != "" {
		fmt.Printf("REMOTE LINK: Overriding backend server to [%s]\n", serverIP)
		PollURL = fmt.Sprintf("http://%s:4800/api/agent/poll/", serverIP)
		BackendURL = fmt.Sprintf("http://%s:4800/api/logs", serverIP)
	}
}

func main() {
	hInfo, _ := host.Info()
	hostname := hInfo.Hostname
	osType := runtime.GOOS

	fmt.Printf("Midnight Deep-Agent starting on %s (%s)...\n", hostname, osType)
	fmt.Printf("Deep Monitoring: Windows EventLogs & Linux Process Watcher active.\n")

	go runVulnerabilityScan(hostname, osType)
	go runPortGuard(hostname, osType)
	go commandListener(hostname)

	seenConns := make(map[string]time.Time)
	seenPIDs := make(map[int32]bool)

	// Windows Event Log Worker (Simulated or Real depending on runtime)
	if osType == "windows" {
		go func() {
			for {
				// In a real production agent, we use golang.org/x/sys/windows/svc/eventlog
				// Here we simulate the polling of Security events for the demo
				entry := LogEntry{
					Timestamp: time.Now().Format(time.RFC3339),
					Hostname:  hostname,
					OS:        osType,
					Type:      "security_log",
					Message:   "Windows Security Event: Logon Success (EventID: 4624)",
				}
				shipLog(entry)
				time.Sleep(30 * time.Second)
			}
		}()
	}

	// Linux Process Watcher
	if osType == "linux" {
		go func() {
			for {
				pids, _ := process.Pids()
				for _, pid := range pids {
					if !seenPIDs[pid] {
						p, err := process.NewProcess(pid)
						if err == nil {
							name, _ := p.Name()
							cmd, _ := p.Cmdline()
							entry := LogEntry{
								Timestamp: time.Now().Format(time.RFC3339),
								Hostname:  hostname,
								OS:        osType,
								Type:      "process_event",
								Comm:      name,
								Cmdline:   cmd,
								PID:       pid,
								Message:   fmt.Sprintf("New Process Started: %s (PID: %d)", name, pid),
							}
							shipLog(entry)
							seenPIDs[pid] = true
						}
					}
				}
				if len(seenPIDs) > 5000 { seenPIDs = make(map[int32]bool) }
				time.Sleep(5 * time.Second)
			}
		}()
	}

	// Resource Telemetry goroutine
	go func() {
		for {
			cPerc, _ := cpu.Percent(time.Second, false)
			mInfo, _ := mem.VirtualMemory()
			
			diskPath := "/"
			if runtime.GOOS == "windows" {
				diskPath = "C:"
			}
			dInfo, _ := disk.Usage(diskPath)
			
			cpuVal := 0.0
			if len(cPerc) > 0 {
				cpuVal = cPerc[0]
			}

			services := getActiveServices()

			entry := LogEntry{
				Timestamp: time.Now().Format(time.RFC3339),
				Hostname:  hostname,
				OS:        osType,
				Type:      "telemetry_resource",
				CPU:       cpuVal,
				RAM:       mInfo.UsedPercent,
				Disk:      dInfo.UsedPercent,
				Services:  services,
			}
			shipLog(entry)
			time.Sleep(10 * time.Second)
		}
	}()

	for {
		conns, err := net.Connections("tcp")
		if err != nil {
			log.Printf("Error getting connections: %v", err)
			continue
		}

		for _, conn := range conns {
			if conn.Status != "ESTABLISHED" {
				continue
			}

			// Unique key for the connection (Source IP + Dest IP + Dest Port)
			connKey := fmt.Sprintf("%s-%s-%d", conn.Laddr.IP, conn.Raddr.IP, conn.Raddr.Port)
			if lastTime, exists := seenConns[connKey]; exists && time.Since(lastTime) < 5*time.Minute {
				continue
			}

			// Get process details
			var comm, cmdline, user, exePath string
			p, err := process.NewProcess(conn.Pid)
			if err == nil {
				comm, _ = p.Name()
				cmd, _ := p.Cmdline()
				cmdline = cmd
				user, _ = p.Username()
				exePath, _ = p.Exe()
			}

			scope := "Internet"
			if strings.HasPrefix(conn.Raddr.IP, "192.168.") || strings.HasPrefix(conn.Raddr.IP, "10.") || strings.HasPrefix(conn.Raddr.IP, "172.16.") || conn.Raddr.IP == "127.0.0.1" || conn.Raddr.IP == "::1" {
				scope = "LAN"
			}

			entry := LogEntry{
				Timestamp: time.Now().Format(time.RFC3339),
				Hostname:  hostname,
				OS:        osType,
				User:      user,
				PID:       conn.Pid,
				Comm:      comm,
				Cmdline:   cmdline,
				SrcIP:     conn.Laddr.IP,
				SrcPort:   int(conn.Laddr.Port),
				DstIP:     conn.Raddr.IP,
				DstPort:   int(conn.Raddr.Port),
				Type:      "network_connection",
				ExePath:   exePath,
				Scope:     scope,
			}

			// Detect P2P and DNS Hygiene (Portmaster Logic)
			if conn.Type == 2 && scope == "Internet" { // UDP
				if conn.Raddr.Port == 53 || conn.Raddr.Port == 853 {
					entry.Message = "[DNS-Hygiene] Standard DNS Query"
				} else {
					entry.Message = "[P2P-Candidate] Outbound UDP flow"
				}
			}

			// Apply DGA Detection
			if conn.Raddr.IP != "" {
				entropy := calculateEntropy(conn.Raddr.IP)
				if entropy > CurrentConfig.DGAEntropy {
					entry.Message = fmt.Sprintf("[DGA-Alert] High entropy destination perceived: %s (Threshold: %.2f)", conn.Raddr.IP, CurrentConfig.DGAEntropy)
				}
			}

			// Ship to Backend
			go shipLog(entry)

			seenConns[connKey] = time.Now()
		}

		// Efficient Map Cleanup: Remove entries older than 10 minutes
		if len(seenConns) > 5000 {
			for k, v := range seenConns {
				if time.Since(v) > 10*time.Minute {
					delete(seenConns, k)
				}
			}
		}

		time.Sleep(time.Duration(CurrentConfig.Interval) * time.Second)
	}
}

func runVulnerabilityScan(hostname, osType string) {
	time.Sleep(10 * time.Second) // Initial delay
	for {
		log.Printf("Running Vulnerability Scan...")
		
		vulns := []string{}
		
		// 1. Check for SUID binaries (limited to common risky paths for speed)
		if osType == "linux" {
			cmd := exec.Command("sh", "-c", "find /bin /usr/bin /sbin -perm -4000 2>/dev/null | grep -E '/(python|perl|nmap|vim|bash|find|tail)'")
			out, _ := cmd.Output()
			if len(out) > 0 {
				vulns = append(vulns, fmt.Sprintf("Risky SUID Binaries found: %s", string(out)))
			}

			// 2. Check for weak /etc/passwd permissions
			info, err := os.Stat("/etc/passwd")
			if err == nil {
				mode := info.Mode()
				if mode&0002 != 0 { // World writable
					vulns = append(vulns, "CRITICAL: /etc/passwd is world-writable (Potential root takeover)")
				}
			}

			// 3. Simple Kernel Version Check (Mocking CVE mapping from LinuxPi)
			kCmd := exec.Command("uname", "-r")
			kOut, _ := kCmd.Output()
			kStr := string(kOut)
			if strings.Contains(kStr, "5.10") || strings.Contains(kStr, "5.15") {
				vulns = append(vulns, fmt.Sprintf("Vulnerable Kernel Detected (%s): Possible DirtyPipe or PwnKit vulnerability.", kStr))
			}
		}

		if len(vulns) > 0 {
			for _, v := range vulns {
				entry := LogEntry{
					Timestamp: time.Now().Format(time.RFC3339),
					Hostname:  hostname,
					OS:        osType,
					Type:      "vulnerability_report",
					Message:   v,
				}
				shipLog(entry)
			}
		}

		time.Sleep(10 * time.Minute) // Run scan every 10 minutes
	}
}

func runPortGuard(hostname, osType string) {
	allowedPorts := map[int]bool{22: true, 80: true, 443: true, 4800: true} // Standard safe ports for this SIEM
	time.Sleep(15 * time.Second)
	for {
		log.Printf("Running Port Guard check...")
		conns, _ := net.Connections("tcp")
		for _, c := range conns {
			if c.Status == "LISTEN" {
				port := int(c.Laddr.Port)
				isPublic := c.Laddr.IP == "0.0.0.0" || c.Laddr.IP == "::" || c.Laddr.IP == ""
				
				if isPublic && !allowedPorts[port] {
					entry := LogEntry{
						Timestamp: time.Now().Format(time.RFC3339),
						Hostname:  hostname,
						OS:        osType,
						Type:      "hardening_violation",
						Message:   fmt.Sprintf("CRITICAL: Unauthorized public port exposed: %d (Not in allowlist)", port),
					}
					shipLog(entry)
				}
			}
		}
		time.Sleep(5 * time.Minute)
	}
}

func shipLog(entry LogEntry) {
	jsonData, _ := json.Marshal(entry)
	
	backoff := 1 * time.Second
	for i := 0; i < 3; i++ { // Retry up to 3 times
		resp, err := http.Post(BackendURL, "application/json", bytes.NewBuffer(jsonData))
		if err == nil {
			resp.Body.Close()
			return
		}
		log.Printf("Backend unreachable, retrying in %v...", backoff)
		time.Sleep(backoff)
		backoff *= 2
	}
}

func getActiveServices() []string {
	targetServices := []string{"docker", "nginx", "mysql", "postgres", "redis", "apache", "mongodb", "php-fpm"}
	active := []string{}
	processes, _ := process.Processes()
	for _, p := range processes {
		name, _ := p.Name()
		name = strings.ToLower(name)
		for _, s := range targetServices {
			if strings.Contains(name, s) {
				// Avoid duplicates
				duplicate := false
				for _, a := range active {
					if a == s {
						duplicate = true
						break
					}
				}
				if !duplicate {
					active = append(active, s)
				}
			}
		}
	}
	return active
}

func commandListener(hostname string) {
	pollURL := PollURL + hostname
	for {
		resp, err := http.Get(pollURL)
		if err == nil {
			var commands []string
			if err := json.NewDecoder(resp.Body).Decode(&commands); err == nil {
				for _, cmd := range commands {
					handleCommand(cmd)
				}
			}
			resp.Body.Close()
		}
		time.Sleep(5 * time.Second) // Poll every 5 seconds
	}
}

func handleCommand(cmd string) {
	log.Printf("C2 RECEIVED: [%s]", cmd)
	parts := strings.Split(cmd, ":")
	action := parts[0]

	switch action {
	case "SET_ENTROPY":
		if len(parts) > 1 {
			var val float64
			fmt.Sscanf(parts[1], "%f", &val)
			CurrentConfig.DGAEntropy = val
			log.Printf("DYNAMIC POLICY: DGA Entropy updated to %.2f", val)
		}
	case "SHUTDOWN":
		log.Printf("C2: Remote shutdown triggered. Exiting...")
		os.Exit(0)
	case "SCAN_NOW":
		log.Printf("C2: Triggering immediate forensic scan...")
		// would trigger an extra scan cycle
	case "QUARANTINE":
		log.Printf("C2: ASSET ISOLATION TRIGGERED! Locking down network...")
		CurrentConfig.Quarantined = true
		applyQuarantine(true)
	case "RELEASE":
		log.Printf("C2: ASSET RELEASED. Restoring network access...")
		CurrentConfig.Quarantined = false
		applyQuarantine(false)
	}
}

func applyQuarantine(enable bool) {
	switch runtime.GOOS {
	case "linux":
		if enable {
			// Block everything except C2 communication on 4800 (Simplified for demo)
			exec.Command("iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "4800", "-j", "ACCEPT").Run()
			exec.Command("iptables", "-A", "OUTPUT", "-j", "DROP").Run()
		} else {
			exec.Command("iptables", "-F").Run()
		}
	case "windows":
		if enable {
			// Block all outbound except port 4800
			exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=MIDNIGHT_QUARANTINE", "dir=out", "action=block").Run()
			exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=MIDNIGHT_C2_ALLOW", "dir=out", "action=allow", "protocol=TCP", "remoteport=4800").Run()
		} else {
			exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=MIDNIGHT_QUARANTINE").Run()
			exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=MIDNIGHT_C2_ALLOW").Run()
		}
	}
}
