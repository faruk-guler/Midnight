package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/websocket/v2"
)

// LogEntry defines the structure of the security logs
type LogEntry struct {
	Timestamp       string  `json:"timestamp"`
	ServerTimestamp string  `json:"server_timestamp"`
	Hostname        string  `json:"hostname"`
	OS              string  `json:"os"`
	User            string  `json:"user"`
	PID             int     `json:"pid"`
	Comm            string  `json:"comm"`
	Cmdline         string  `json:"cmdline"`
	SrcIP           string  `json:"src_ip"`
	SrcPort         int     `json:"src_port"`
	DstIP           string  `json:"dst_ip"`
	DstPort         int     `json:"dst_port"`
	Type            string  `json:"type"`
	CPU             float64 `json:"cpu,omitempty"`
	RAM             float64 `json:"ram,omitempty"`
	Disk            float64 `json:"disk,omitempty"`
	Message         string  `json:"message,omitempty"`
	Country         string  `json:"country,omitempty"`
	CountryCode     string  `json:"country_code,omitempty"`
	City            string  `json:"city,omitempty"`
	SentBytes       uint64  `json:"sent_bytes,omitempty"`
	RecvBytes       uint64  `json:"recv_bytes,omitempty"`
	ExePath         string  `json:"exe_path,omitempty"`
	Scope           string  `json:"scope,omitempty"`
}

// Agent represents a managed asset in the fleet
type Agent struct {
	Hostname   string   `json:"hostname"`
	IP         string   `json:"ip"`
	OS         string   `json:"os"`
	Status     string   `json:"status"` // ONLINE, OFFLINE, QUARANTINED
	RiskScore  int      `json:"risk_score"`
	LastSeen   time.Time `json:"last_seen"`
	Services   []string `json:"services"`
}

// Alert defines a security alert triggered by rules
type Alert struct {
	Timestamp string `json:"timestamp"`
	Severity  string `json:"severity"`
	Rule      string `json:"rule"`
	Category  string `json:"category"`
	Details   string `json:"details"`
	Hostname  string `json:"hostname"`
}

// AuditLog defines the structure for internal SIEM activity
type AuditLog struct {
	Timestamp string `json:"timestamp"`
	User      string `json:"user"`
	Action    string `json:"action"`
	Details   string `json:"details"`
}

var (
	auditLogs   []AuditLog
	auditMutex  sync.Mutex
	alertTrends = make(map[string]int) // Hourly trends

	// Agency Management
	agents      = make(map[string]*Agent)
	agentsMutex sync.Mutex

	// C2 Command Queue: hostname -> list of commands
	commandQueue = make(map[string][]string)
	commandMutex sync.Mutex
)

// LogAudit records an internal system action and persists it
func LogAudit(user, action, details string) {
	auditMutex.Lock()
	defer auditMutex.Unlock()
	entry := AuditLog{
		Timestamp: time.Now().Format(time.RFC3339),
		User:      user,
		Action:    action,
		Details:   details,
	}
	auditLogs = append(auditLogs, entry)
	
	// Atomic Save to JSON
	f, _ := os.OpenFile("logs/audit_history.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if f != nil {
		jb, _ := json.Marshal(entry)
		f.Write(append(jb, '\n'))
		f.Close()
	}
}

// StartAgentManager periodically checks for offline agents
func StartAgentManager(cm *ConnectionManager) {
	ticker := time.NewTicker(15 * time.Second)
	for range ticker.C {
		agentsMutex.Lock()
		changed := false
		for _, agent := range agents {
			if agent.Status != "OFFLINE" && time.Since(agent.LastSeen) > 40*time.Second {
				agent.Status = "OFFLINE"
				changed = true
				LogAudit("system", "agent_offline", fmt.Sprintf("Agent [%s] lost heartbeat", agent.Hostname))
			}
		}
		if changed {
			// Broadcast the state change
			msg, _ := json.Marshal(map[string]interface{}{
				"type": "fleet_update",
				"data": agents,
			})
			cm.broadcast <- msg
		}
		agentsMutex.Unlock()
	}
}

// ConnectionManager handles WebSocket clients
type ConnectionManager struct {
	clients   map[*websocket.Conn]bool
	broadcast chan []byte
	mutex     sync.Mutex
}

// Global log channel for thread-safe file writing
var (
	logChan  = make(chan LogEntry, 1000)
	geoCache sync.Map
)

func resolveGeoIP(ip string) (string, string, string) {
	if ip == "" || ip == "127.0.0.1" || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.16.") {
		return "Local Network", "LCL", ""
	}

	if val, ok := geoCache.Load(ip); ok {
		res := val.([]string)
		return res[0], res[1], res[2]
	}

	// Rate limited API usage
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,city", ip)
	resp, err := http.Get(url)
	if err != nil {
		return "Unknown", "", ""
	}
	defer resp.Body.Close()

	var data struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		City        string `json:"city"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err == nil && data.Status == "success" {
		geoCache.Store(ip, []string{data.Country, data.CountryCode, data.City})
		return data.Country, data.CountryCode, data.City
	}

	return "Unknown", "", ""
}

func resolveAppProtocol(port int) string {
	serviceMap := map[int]string{
		20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
		53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 443: "HTTPS", 
		543: "AppleTalk", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
		6379: "Redis", 8080: "HTTP-Proxy", 27017: "MongoDB",
	}
	if name, ok := serviceMap[port]; ok {
		return name
	}
	return "Unknown"
}

func StartFileLogger() {
	today := time.Now().Format("2006-01-02")
	filename := fmt.Sprintf("logs/midnight_logs_%s.json", today)
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Criticial: File Logger failed: %v", err)
		return
	}
	defer f.Close()

	for entry := range logChan {
		// Auto-rotate filename if day changes
		currentDay := time.Now().Format("2006-01-02")
		if currentDay != today {
			f.Close()
			today = currentDay
			filename = fmt.Sprintf("logs/midnight_logs_%s.json", today)
			f, _ = os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		}

		jsonBytes, _ := json.Marshal(entry)
		f.Write(append(jsonBytes, '\n'))
	}
}

func NewConnectionManager() *ConnectionManager {
	return &ConnectionManager{
		clients:   make(map[*websocket.Conn]bool),
		broadcast: make(chan []byte),
	}
}

func (cm *ConnectionManager) HandleBroadcast() {
	for {
		msg := <-cm.broadcast
		cm.mutex.Lock()
		for client := range cm.clients {
			err := client.WriteMessage(websocket.TextMessage, msg)
			if err != nil {
				log.Printf("WebSocket error: %v", err)
				client.Close()
				delete(cm.clients, client)
			}
		}
		cm.mutex.Unlock()
	}
}

// runRulesEngine categorizes alerts for modularity
func runRulesEngine(entry LogEntry, cm *ConnectionManager) {
	checkSystemRules(entry, cm)
	checkSecurityLogRules(entry, cm)
	checkIdentityRules(entry, cm)
	checkNetworkBehaviorRules(entry, cm)
	checkPhysicalRules(entry, cm)
}

func checkSystemRules(entry LogEntry, cm *ConnectionManager) {
	if entry.Type == "telemetry_resource" && (entry.CPU > 90 || entry.RAM > 90) {
		triggerAlert(Alert{
			Timestamp: time.Now().Format(time.RFC3339),
			Severity:  "HIGH",
			Rule:      "Resource Exhaustion",
			Category:  "System",
			Details:   fmt.Sprintf("CPU: %.2f%%, RAM: %.2f%%", entry.CPU, entry.RAM),
			Hostname:  entry.Hostname,
		}, cm)
	}
}

func checkSecurityLogRules(entry LogEntry, cm *ConnectionManager) {
	if entry.Type == "security_log" || entry.OS == "agentless_syslog" {
		msg := strings.ToLower(entry.Message)
		if strings.Contains(msg, "failed password") {
			triggerAlert(Alert{Timestamp: time.Now().Format(time.RFC3339), Severity: "HIGH", Rule: "Brute Force Attempt", Category: "Security", Details: "Unauthorized login attempt.", Hostname: entry.Hostname}, cm)
		}
		// ... more security log logic ...
	}
}

func checkIdentityRules(entry LogEntry, cm *ConnectionManager) {
	if strings.Contains(strings.ToUpper(entry.Message), "IAM") {
		msg := strings.ToLower(entry.Message)
		if strings.Contains(msg, "policy_id: 188") || strings.Contains(msg, "policy_id: 539") {
			triggerAlert(Alert{Timestamp: time.Now().Format(time.RFC3339), Severity: "HIGH", Rule: "MFA Policy Violation", Category: "Identity", Details: "Account missing MFA.", Hostname: entry.Hostname}, cm)
		}
	}
}

func checkNetworkBehaviorRules(entry LogEntry, cm *ConnectionManager) {
	if entry.Type == "network_connection" {
		if strings.Contains(entry.Message, "[DGA-Alert]") {
			triggerAlert(Alert{Timestamp: time.Now().Format(time.RFC3339), Severity: "HIGH", Rule: "DGA Detection", Category: "Network", Details: "Domain generation algorithm usage perceived.", Hostname: entry.Hostname}, cm)
		}
		if entry.SentBytes > 100*1024*1024 {
			triggerAlert(Alert{Timestamp: time.Now().Format(time.RFC3339), Severity: "CRITICAL", Rule: "Data Exfiltration", Category: "Network", Details: "Large outbound transfer detected.", Hostname: entry.Hostname}, cm)
		}
	}
}

func checkPhysicalRules(entry LogEntry, cm *ConnectionManager) {
	if entry.Type == "physical_event" || strings.Contains(strings.ToLower(entry.Message), "lock intrusion") {
		triggerAlert(Alert{Timestamp: time.Now().Format(time.RFC3339), Severity: "CRITICAL", Rule: "Physical Intrusion", Category: "Physical Access", Details: "Unauthorized lock attempt.", Hostname: entry.Hostname}, cm)
	}
}

func triggerAlert(alert Alert, cm *ConnectionManager) {
	// Night Bonus Logic
	hour := time.Now().Hour()
	if (hour >= 22 || hour < 6) && alert.Severity != "CRITICAL" {
		alert.Severity = "CRITICAL"
		alert.Rule += " (NIGHT BONUS)"
	}

	// Update Trends
	hourStr := time.Now().Format("15:00")
	commandMutex.Lock()
	alertTrends[hourStr]++
	commandMutex.Unlock()
	saveTrends()

	msg, _ := json.Marshal(map[string]interface{}{
		"type": "alert",
		"data": alert,
	})
	cm.broadcast <- msg
}

func saveTrends() {
	commandMutex.Lock()
	defer commandMutex.Unlock()
	jb, _ := json.Marshal(alertTrends)
	os.WriteFile("logs/alert_trends.json", jb, 0644)
}

func bootstrap() {
	log.Println("Midnight Bootstrap: Loading state from disk...")
	
	// Load Trends
	if data, err := os.ReadFile("logs/alert_trends.json"); err == nil {
		json.Unmarshal(data, &alertTrends)
		log.Printf("Loaded %d trend data points.", len(alertTrends))
	}

	// Load Last 100 Audit Logs for immediate UI view
	if data, err := os.ReadFile("logs/audit_history.json"); err == nil {
		lines := strings.Split(string(data), "\n")
		count := 0
		for i := len(lines) - 1; i >= 0 && count < 100; i-- {
			if lines[i] == "" { continue }
			var entry AuditLog
			if err := json.Unmarshal([]byte(lines[i]), &entry); err == nil {
				auditLogs = append(auditLogs, entry)
				count++
			}
		}
		log.Printf("Loaded %d recent audit logs.", count)
	}
}

// --- Agentless Workers ---

// StartSyslogServer listens for UDP syslog packets on port 5140
func StartSyslogServer(cm *ConnectionManager) {
	addr, _ := net.ResolveUDPAddr("udp", ":5140")
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("Syslog Listener Error: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("Syslog Server listening on UDP 5140")
	buf := make([]byte, 2048)
	for {
		n, addr, _ := conn.ReadFromUDP(buf)
		raw := string(buf[:n])
		
		// Basic RFC3164 Parser (Extracting tag and message)
		msg := raw
		if strings.Contains(raw, ">") {
			parts := strings.SplitN(raw, ">", 2)
			if len(parts) > 1 {
				msg = parts[1]
			}
		}

		entry := LogEntry{
			Timestamp:       time.Now().Format(time.RFC3339),
			ServerTimestamp: time.Now().Format(time.RFC3339),
			Hostname:        addr.IP.String(),
			Type:            "security_log",
			OS:              "agentless_syslog",
			Message:         strings.TrimSpace(msg),
		}

		// Log to file and broadcast
		logChan <- entry
		jsonBytes, _ := json.Marshal(entry)
		cm.broadcast <- jsonBytes
		go runRulesEngine(entry, cm)
	}
}

// StartSSHPoller demonstrates periodic SSH status checks
func StartSSHPoller(cm *ConnectionManager) {
	// For demo: We check an example "Asset" (localhost or a dummy target)
	ticker := time.NewTicker(60 * time.Second)
	for range ticker.C {
		// Mock logic: In a real scenario, this would come from a database of assets
		// We'll simulate a check to the backend's own OS for demo purposes
		output := "up 2 days, 14:12, 1 user, load average: 0.12, 0.08, 0.05"
		
		entry := LogEntry{
			Timestamp:       time.Now().Format(time.RFC3339),
			ServerTimestamp: time.Now().Format(time.RFC3339),
			Hostname:        "core-server-01",
			Type:            "telemetry_resource",
			OS:              "linux_agentless",
			Message:         fmt.Sprintf("SSH Connectivity OK. Uptime: %s", output),
		}

		logChan <- entry
		msg, _ := json.Marshal(entry)
		cm.broadcast <- msg
	}
}

// StartSNMPCollector demonstrates SNMP data gathering
func StartSNMPCollector() {
	ticker := time.NewTicker(60 * time.Second)
	for range ticker.C {
		log.Printf("SNMP Collector: Tick executed (Exploring network assets)")
		// Use gosnmp.Default.Get([]string{"1.3.6.1.2.1.1.1.0"})
	}
}

func main() {
	// Setup Fiber
	app := fiber.New(fiber.Config{
		AppName: "Midnight SIEM Backend (Go)",
	})

	// Middleware
	// Middleware: Multi-Origin SOC Support
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders: "Origin, Content-Type, Accept",
	}))

	// Data Management
	logDir := "logs"
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		os.Mkdir(logDir, 0755)
	}

	// Serve Static UI Files
	app.Static("/", "../midnight-ui/dist")

	cm := NewConnectionManager()
	go cm.HandleBroadcast()
	go StartFileLogger()
	
	// Reload Data from Disk
	bootstrap()

	// Launch Agentless Hub Workers
	go StartSyslogServer(cm)
	go StartSSHPoller(cm)
	go StartSNMPCollector()
	go StartAgentManager(cm)

	// Endpoints
	app.Get("/", func(c *fiber.Ctx) error {
		LogAudit("system", "access_dashboard", "Internal dashboard landing page accessed")
		return c.JSON(fiber.Map{
			"status": "Midnight Go-Backend is running",
			"engine": "Golang 1.26",
		})
	})

	// Forensic CSV Export
	app.Get("/api/export", func(c *fiber.Ctx) error {
		LogAudit("admin", "export_logs", "Full forensic CSV log export triggered")
		c.Set("Content-Type", "text/csv")
		c.Set("Content-Disposition", "attachment; filename=midnight_forensics_"+time.Now().Format("20060102_150405")+".csv")

		csv := "Timestamp,Hostname,OS,Type,Comm,ExePath,SrcIP,DstIP,DstPort,Message,Details\n"
		// Using a simplified fetch of last 1000 logs if they were in memory, for now we simulate or stream from file
		return c.SendString(csv + "2026-04-10T14:20:00Z,SOC-SRV,Linux,Network,ssh,/usr/sbin/sshd,10.0.0.5,8.8.8.8,53,DNS Security Check,Automated Forensics Preview\n")
	})

	// Internal Audit Log
	app.Get("/api/audit", func(c *fiber.Ctx) error {
		auditMutex.Lock()
		defer auditMutex.Unlock()
		return c.JSON(auditLogs)
	})

	// Threat Trends (Chart data)
	app.Get("/api/trends", func(c *fiber.Ctx) error {
		return c.JSON(alertTrends)
	})

	// Log ingestion from Agents
	app.Post("/api/logs", func(c *fiber.Ctx) error {
		var entry LogEntry
		if err := c.BodyParser(&entry); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid JSON"})
		}

		// Add server timestamp
		entry.ServerTimestamp = time.Now().Format(time.RFC3339)

		// 0. GeoIP Enrichment
		if entry.SrcIP != "" {
			entry.Country, entry.CountryCode, entry.City = resolveGeoIP(entry.SrcIP)
		} else if entry.DstIP != "" {
			entry.Country, entry.CountryCode, entry.City = resolveGeoIP(entry.DstIP)
		}

		// 1. Thread-safe Storage
		logChan <- entry

		// 1a. Update Agent Registry
		agentsMutex.Lock()
		if _, ok := agents[entry.Hostname]; !ok {
			agents[entry.Hostname] = &Agent{
				Hostname: entry.Hostname,
				OS:       entry.OS,
				Status:   "ONLINE",
			}
		}
		agent := agents[entry.Hostname]
		agent.Status = "ONLINE" // Restore to ONLINE whenever data is received
		agent.LastSeen = time.Now()
		
		// IP Detection Hardening
		if entry.SrcIP != "" {
			agent.IP = entry.SrcIP
		} else if agent.IP == "" || agent.IP == "N/A" {
			agent.IP = c.IP() // Fallback to connection IP
		}

		if len(entry.Message) > 0 && strings.Contains(entry.Message, "Services:") {
			parts := strings.Split(entry.Message, "Services:")
			if len(parts) > 1 {
				agent.Services = strings.Split(parts[1], ",")
			}
		}
		agentsMutex.Unlock()

		// 2. Real-time: Broadcast to Dashboard
		jsonBytes, _ := json.Marshal(entry)
		cm.broadcast <- jsonBytes

		// 3. Security: Run Rules Engine
		go runRulesEngine(entry, cm)

		return c.SendStatus(200)
	})

	// GET /api/agents: List all managed assets
	app.Get("/api/agents", func(c *fiber.Ctx) error {
		agentsMutex.Lock()
		defer agentsMutex.Unlock()
		return c.JSON(agents)
	})

	// --- INTERACTIVE C2 ENDPOINTS ---

	// POST /api/command: Dashboard sends a command to an agent
	app.Post("/api/command", func(c *fiber.Ctx) error {
		var req struct {
			Hostname string `json:"hostname"`
			Command  string `json:"command"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}

		commandMutex.Lock()
		commandQueue[req.Hostname] = append(commandQueue[req.Hostname], req.Command)
		commandMutex.Unlock()

		LogAudit("admin", "dispatch_command", fmt.Sprintf("Command [%s] dispatched to agent [%s]", req.Command, req.Hostname))
		
		// Persist Trends after update
		saveTrends()
		
		return c.JSON(fiber.Map{"status": "queued", "hostname": req.Hostname})
	})

	// GET /api/agent/poll/:hostname: Agent checks for pending commands
	app.Get("/api/agent/poll/:hostname", func(c *fiber.Ctx) error {
		hostname := c.Params("hostname")
		
		commandMutex.Lock()
		defer commandMutex.Unlock()

		commands := commandQueue[hostname]
		if len(commands) == 0 {
			return c.JSON([]string{})
		}

		// Clear queue after delivery
		commandQueue[hostname] = []string{}
		return c.JSON(commands)
	})

	// WebSocket for Dashboard
	app.Get("/ws", websocket.New(func(c *websocket.Conn) {
		cm.mutex.Lock()
		cm.clients[c] = true
		cm.mutex.Unlock()

		defer func() {
			cm.mutex.Lock()
			delete(cm.clients, c)
			cm.mutex.Unlock()
			c.Close()
		}()

		for {
			_, _, err := c.ReadMessage()
			if err != nil {
				break
			}
		}
	}))

	log.Fatal(app.Listen(":4800"))
}
