package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type DashboardFinder struct {
	client    *http.Client
	userAgent string
	timeout   time.Duration
	results   []Result
	mu        sync.Mutex
	resultFile *os.File
	fileMu     sync.Mutex
}

type Result struct {
	URL        string
	StatusCode int
	Title      string
	HasLogin   bool
	DashType   string
}

var dashboardPaths = []string{
	// Admin panels
	"/admin",
	"/admin/",
	"/admin/dashboard",
	"/admin/panel",
	"/admin/index",
	"/admin/home",
	"/administrator",
	"/administrator/",
	"/administration",
	"/control",
	"/control/",
	"/cp",
	"/cpanel",
	"/panel",
	"/dashboard",
	"/dashboard/",
	
	// Monitoring dashboards
	"/grafana",
	"/grafana/",
	"/kibana",
	"/kibana/",
	"/elasticsearch",
	"/prometheus",
	"/nagios",
	"/zabbix",
	"/cacti",
	"/munin",
	"/netdata",
	"/icinga",
	"/observium",
	"/prtg",
	"/zenoss",
	
	// Application dashboards
	"/phpmyadmin",
	"/phpmyadmin/",
	"/pma",
	"/mysql",
	"/adminer",
	"/wp-admin",
	"/wp-admin/",
	"/drupal",
	"/joomla/administrator",
	"/typo3",
	"/magento/admin",
	"/opencart/admin",
	
	// Server management
	"/webmin",
	"/cpanel",
	"/plesk",
	"/directadmin",
	"/ispconfig",
	"/virtualmin",
	"/usermin",
	"/ajenti",
	
	// Development tools
	"/jenkins",
	"/jenkins/",
	"/gitlab",
	"/gitea",
	"/bamboo",
	"/teamcity",
	"/travis",
	"/circleci",
	"/drone",
	"/concourse",
	
	// Database interfaces
	"/phppgadmin",
	"/phpldapadmin",
	"/rockmongo",
	"/mongoexpress",
	"/redis-commander",
	"/adminer",
	
	// File managers
	"/filemanager",
	"/fm",
	"/files",
	"/ftp",
	"/webftp",
	"/net2ftp",
	"/tinyfm",
	
	// System info
	"/info",
	"/info.php",
	"/phpinfo",
	"/phpinfo.php",
	"/server-info",
	"/server-status",
	"/status",
	"/health",
	"/metrics",
	"/stats",
	
	// Router/Network devices
	"/cgi-bin/luci",
	"/luci",
	"/pfsense",
	"/opnsense",
	"/ddwrt",
	"/tomato",
	"/merlin",
	
	// Cloud platforms
	"/rancher",
	"/portainer",
	"/kubernetes-dashboard",
	"/k8s",
	"/consul",
	"/vault",
	"/nomad",
	
	// Backup tools
	"/backup",
	"/backups",
	"/restore",
	"/duplicator",
	"/updraftplus",
	
	// Mail servers
	"/webmail",
	"/roundcube",
	"/squirrelmail",
	"/rainloop",
	"/mailcow",
	"/postfixadmin",
	
	// Common variations
	"/manage",
	"/manager",
	"/management",
	"/console",
	"/control-panel",
	"/admin-panel",
	"/adminpanel",
	"/login",
	"/signin",
	"/auth",
	"/secure",
	"/private",
	"/restricted",
	"/internal",
	"/staff",
	"/employee",
	"/member",
	"/user",
	"/account",
	"/profile",
	"/settings",
	"/config",
	"/configuration",
	"/setup",
	"/install",
	"/wizard",
}

var loginIndicators = []string{
	"login", "signin", "sign in", "log in", "password", "username",
	"email", "user", "auth", "authentication", "credentials",
	"form", "input type=\"password\"", "input type='password'",
	"type=\"text\"", "type='text'", "submit", "button",
}

var dashboardIndicators = []string{
	"dashboard", "admin panel", "control panel", "management",
	"administrator", "welcome", "overview", "statistics",
	"metrics", "monitoring", "analytics", "reports",
	"configuration", "settings", "users", "system",
	"server", "database", "files", "logs",
}

// Network blocks for random IP generation
var networkBlocks = []int{13, 18, 20, 34, 35, 40, 52, 54, 104, 134, 137, 139, 159}

// Ports to scan for dashboards
var targetPorts = []int{80, 81, 443, 8080, 8443, 8000, 8888, 8880, 7001, 9000}

// HTTPS ports
var httpsPort = map[int]bool{443: true, 8443: true, 7001: true}

func NewDashboardFinder() *DashboardFinder {
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          500,  // Increased connection pool
		MaxIdleConnsPerHost:   100,  // More connections per host
		IdleConnTimeout:       30 * time.Second,
		DisableKeepAlives:     false, // Keep connections alive
		TLSHandshakeTimeout:   2 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		Dial: (&net.Dialer{
			Timeout: 2 * time.Second,
		}).Dial,
	}
	
	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second, // Reduced from 10s to 5s
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 { // Reduced redirects from 3 to 2
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	
	// Create timestamped results file
	filename := fmt.Sprintf("dashboard_results_%s.txt", 
		time.Now().Format("2006-01-02_15-04-05"))
	
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Warning: Could not create results file: %v\n", err)
		file = nil
	} else {
		// Write file header
		header := fmt.Sprintf("Hidden Dashboard Finder Results - %s\n", time.Now().Format("2006-01-02 15:04:05"))
		header += "=======================================================\n\n"
		file.WriteString(header)
		file.Sync() // Ensure header is written immediately
		fmt.Printf("📄 Results will be saved to: %s\n\n", filename)
	}
	
	return &DashboardFinder{
		client:     client,
		userAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		timeout:    5 * time.Second,
		results:    make([]Result, 0),
		resultFile: file,
	}
}

// writeResultToFile writes a result to the file in real-time
func (df *DashboardFinder) writeResultToFile(result Result) {
	if df.resultFile == nil {
		return
	}
	
	df.fileMu.Lock()
	defer df.fileMu.Unlock()
	
	status := "ACCESSIBLE"
	if result.HasLogin {
		status = "LOGIN REQUIRED"
	}
	if result.StatusCode == 302 || result.StatusCode == 301 {
		status = "REDIRECT"
	}
	
	// Write with timestamp
	timestamp := time.Now().Format("15:04:05")
	line := fmt.Sprintf("[%s] [%s] %s - %s (%s)\n", 
		timestamp, status, result.URL, result.Title, result.DashType)
	
	df.resultFile.WriteString(line)
	df.resultFile.Sync() // Force write to disk immediately
}

func (df *DashboardFinder) checkURL(baseURL, path string) {
	fullURL := strings.TrimSuffix(baseURL, "/") + path
	
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return
	}
	
	req.Header.Set("User-Agent", df.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")
	
	resp, err := df.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	
	// Only process successful responses and redirects
	if resp.StatusCode == 200 || resp.StatusCode == 302 || resp.StatusCode == 301 {
		buf := make([]byte, 4096) // Read first 4KB for analysis
		n, _ := resp.Body.Read(buf)
		content := strings.ToLower(string(buf[:n]))
		
		// Extract title
		title := extractTitle(string(buf[:n]))
		
		// Check if it requires login
		hasLogin := containsAny(content, loginIndicators)
		
		// Determine dashboard type
		dashType := determineDashboardType(content, path)
		
		// Only add if it looks like a dashboard and doesn't require login
		if (resp.StatusCode == 200 && !hasLogin && dashType != "") || 
		   (resp.StatusCode == 302 || resp.StatusCode == 301) {
			
			result := Result{
				URL:        fullURL,
				StatusCode: resp.StatusCode,
				Title:      title,
				HasLogin:   hasLogin,
				DashType:   dashType,
			}
			
			df.mu.Lock()
			df.results = append(df.results, result)
			df.mu.Unlock()
			
			// Write to file immediately (real-time)
			df.writeResultToFile(result)
			
			// Print immediately for real-time feedback
			status := "✓ ACCESSIBLE"
			if hasLogin {
				status = "⚠ LOGIN REQUIRED"
			}
			if resp.StatusCode == 302 || resp.StatusCode == 301 {
				status = "↪ REDIRECT"
			}
			
			fmt.Printf("[%s] %s - %s (%s)\n", status, fullURL, title, dashType)
		}
	}
}

func extractTitle(content string) string {
	content = strings.ToLower(content)
	start := strings.Index(content, "<title>")
	if start == -1 {
		return "No Title"
	}
	start += 7
	end := strings.Index(content[start:], "</title>")
	if end == -1 {
		return "No Title"
	}
	title := content[start : start+end]
	if len(title) > 50 {
		title = title[:50] + "..."
	}
	return strings.TrimSpace(title)
}

func containsAny(content string, indicators []string) bool {
	for _, indicator := range indicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}
	return false
}

func determineDashboardType(content, path string) string {
	path = strings.ToLower(path)
	content = strings.ToLower(content)
	
	// Check path-based identification first
	if strings.Contains(path, "grafana") {
		return "Grafana"
	}
	if strings.Contains(path, "kibana") {
		return "Kibana"
	}
	if strings.Contains(path, "phpmyadmin") || strings.Contains(path, "pma") {
		return "phpMyAdmin"
	}
	if strings.Contains(path, "jenkins") {
		return "Jenkins"
	}
	if strings.Contains(path, "prometheus") {
		return "Prometheus"
	}
	if strings.Contains(path, "admin") {
		return "Admin Panel"
	}
	if strings.Contains(path, "dashboard") {
		return "Dashboard"
	}
	if strings.Contains(path, "webmin") {
		return "Webmin"
	}
	if strings.Contains(path, "cpanel") {
		return "cPanel"
	}
	if strings.Contains(path, "plesk") {
		return "Plesk"
	}
	
	// Check content-based identification
	if containsAny(content, []string{"grafana", "graph", "metric"}) {
		return "Monitoring"
	}
	if containsAny(content, []string{"phpmyadmin", "mysql", "database"}) {
		return "Database"
	}
	if containsAny(content, dashboardIndicators) {
		return "Dashboard"
	}
	
	return "Unknown"
}

// generateRandomIP creates a random IP from predefined network blocks
func generateRandomIP() string {
	block := networkBlocks[rand.Intn(len(networkBlocks))]
	octet2 := rand.Intn(256)
	octet3 := rand.Intn(256)
	octet4 := rand.Intn(254) + 1
	return fmt.Sprintf("%d.%d.%d.%d", block, octet2, octet3, octet4)
}

// scanPort checks if a specific port is open on the given IP
func scanPort(ip string, port int, timeout time.Duration) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// scanIP scans all target ports on an IP concurrently and returns open ports
func scanIP(ip string) []int {
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	timeout := 300 * time.Millisecond // Reduced from 500ms to 300ms

	for _, port := range targetPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			if scanPort(ip, p, timeout) {
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return openPorts
}

func (df *DashboardFinder) scanTarget(target string) {
	fmt.Printf("\n🔍 Scanning: %s\n", target)
	fmt.Println("=" + strings.Repeat("=", len(target)+11))
	
	// Test base URL first
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		// Try both HTTP and HTTPS
		df.checkURL("http://"+target, "/")
		df.checkURL("https://"+target, "/")
		target = "http://" + target // Default to HTTP for path scanning
	} else {
		df.checkURL(target, "/")
	}
	
	// Create worker pool
	semaphore := make(chan struct{}, 20) // Limit concurrent requests
	var wg sync.WaitGroup
	
	for _, path := range dashboardPaths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			semaphore <- struct{}{}
			df.checkURL(target, p)
			<-semaphore
		}(path)
	}
	
	wg.Wait()
}

// scanSingleIP processes a single IP address
func (df *DashboardFinder) scanSingleIP(ip string, ipNum, totalIPs int) {
	fmt.Printf("[%d/%d] Scanning IP: %s\n", ipNum, totalIPs, ip)
	
	// First, check if any ports are open
	openPorts := scanIP(ip)
	
	if len(openPorts) > 0 {
		fmt.Printf("  ⚡ Open ports found: %v\n", openPorts)
		
		// Check each open port for dashboards concurrently
		var portWg sync.WaitGroup
		for _, port := range openPorts {
			portWg.Add(1)
			go func(p int) {
				defer portWg.Done()
				
				protocol := "http"
				if httpsPort[p] {
					protocol = "https"
				}
				
				baseURL := fmt.Sprintf("%s://%s:%d", protocol, ip, p)
				
				// Test root path first
				df.checkURL(baseURL, "/")
				
				// Then test common dashboard paths with higher concurrency
				semaphore := make(chan struct{}, 20) // Increased from 10 to 20
				var wg sync.WaitGroup
				
				for _, path := range dashboardPaths {
					wg.Add(1)
					go func(p string) {
						defer wg.Done()
						semaphore <- struct{}{}
						df.checkURL(baseURL, p)
						<-semaphore
					}(path)
				}
				
				wg.Wait()
			}(port)
		}
		portWg.Wait()
	}
}

// scanRandomIPs performs random IP scanning for dashboards with parallel processing
func (df *DashboardFinder) scanRandomIPs(count int) {
	fmt.Printf("🎯 Starting random IP scan (%d IPs)\n", count)
	fmt.Println("======================================")
	
	rand.Seed(time.Now().UnixNano())
	
	// Create IP channel and worker pool
	ipChannel := make(chan struct{ip string; num int}, 100) // Buffered channel
	var mainWg sync.WaitGroup
	
	// Start multiple IP scanner workers
	numWorkers := 50 // Increased from sequential to 50 parallel workers
	for i := 0; i < numWorkers; i++ {
		mainWg.Add(1)
		go func() {
			defer mainWg.Done()
			for ipData := range ipChannel {
				df.scanSingleIP(ipData.ip, ipData.num, count)
				// Reduced delay significantly
				time.Sleep(10 * time.Millisecond) // Reduced from 100ms to 10ms
			}
		}()
	}
	
	// Generate IPs and send to workers
	go func() {
		defer close(ipChannel)
		for i := 1; i <= count; i++ {
			ip := generateRandomIP()
			ipChannel <- struct{ip string; num int}{ip: ip, num: i}
		}
	}()
	
	mainWg.Wait()
}

func main() {
	fmt.Println("🔍 Hidden Dashboard Finder v2.0")
	fmt.Println("Finding accessible dashboards and admin panels...")
	fmt.Println()
	
	finder := NewDashboardFinder()
	
	// Ensure file is closed on exit
	defer func() {
		if finder.resultFile != nil {
			finder.resultFile.Close()
		}
	}()
	
	// If no arguments provided (double-clicked), start random scan with 99999 IPs
	if len(os.Args) < 2 {
		fmt.Println("🎯 Auto-starting random IP scan (99,999 IPs)...")
		fmt.Println("Press Ctrl+C to stop the scan at any time.")
		fmt.Println()
		finder.scanRandomIPs(99999)
	} else {
		target := os.Args[1]
		
		// Check if random scanning is requested
		if target == "random" {
			count := 1000 // Default count
			if len(os.Args) > 2 {
				if c, err := strconv.Atoi(os.Args[2]); err == nil {
					count = c
				}
			}
			finder.scanRandomIPs(count)
		} else if _, err := os.Stat(target); err == nil {
			// Check if it's a file
			fmt.Printf("📁 Reading targets from file: %s\n", target)
			
			file, err := os.Open(target)
			if err != nil {
				fmt.Printf("Error opening file: %v\n", err)
				return
			}
			defer file.Close()
			
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				target := strings.TrimSpace(scanner.Text())
				if target != "" && !strings.HasPrefix(target, "#") {
					finder.scanTarget(target)
				}
			}
		} else {
			finder.scanTarget(target)
		}
	}
	
	// Summary
	fmt.Printf("\n📊 SCAN COMPLETE\n")
	fmt.Printf("=================\n")
	fmt.Printf("Total accessible dashboards found: %d\n", len(finder.results))
	
	if len(finder.results) > 0 {
		// Create results file
		filename := fmt.Sprintf("dashboard_results_%s.txt", 
			time.Now().Format("2006-01-02_15-04-05"))
		
		file, err := os.Create(filename)
		if err == nil {
			defer file.Close()
			
			file.WriteString("Hidden Dashboard Finder Results\n")
			file.WriteString("===============================\n\n")
			
			for _, result := range finder.results {
				status := "ACCESSIBLE"
				if result.HasLogin {
					status = "LOGIN REQUIRED"
				}
				if result.StatusCode == 302 || result.StatusCode == 301 {
					status = "REDIRECT"
				}
				
				line := fmt.Sprintf("[%s] %s - %s (%s)\n", 
					status, result.URL, result.Title, result.DashType)
				file.WriteString(line)
			}
			
			fmt.Printf("Results saved to: %s\n", filename)
		}
		
		fmt.Println("\n🎯 Found Dashboards:")
		noLoginCount := 0
		for _, result := range finder.results {
			status := "✓"
			if result.HasLogin {
				status = "⚠"
			} else {
				noLoginCount++
			}
			fmt.Printf("  %s %s (%s)\n", status, result.URL, result.DashType)
		}
		
		fmt.Printf("\n🔓 Dashboards without login required: %d\n", noLoginCount)
		if noLoginCount > 0 {
			fmt.Println("⚠️  WARNING: These dashboards appear to be accessible without authentication!")
		}
	} else {
		fmt.Println("No accessible dashboards found.")
	}
	
	// Keep console window open
	fmt.Println("\nPress Enter to exit...")
	fmt.Scanln()
}
