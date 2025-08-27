package main

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Network blocks from the original script
var networkBlocks = []int{13, 18, 20, 34, 35, 40, 52, 54, 104, 134, 137, 139, 159}

// Ports to scan
var targetPorts = []int{80, 81, 443, 8080, 8443, 8000, 8888, 8880, 7001, 9000}

// HTTPS ports
var httpsPort = map[int]bool{443: true, 8443: true, 7001: true}

// ASPX detection patterns
var aspxPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)aspx`),
	regexp.MustCompile(`(?i)ASP\.NET`),
	regexp.MustCompile(`(?i)ASPSESSIONID`),
	regexp.MustCompile(`(?i)X-AspNet-Version`),
}

// Login page detection patterns
var loginPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<input[^>]*type=["']password["']`),
	regexp.MustCompile(`(?i)<form[^>]*login`),
	regexp.MustCompile(`(?i)name=["']password["']`),
	regexp.MustCompile(`(?i)name=["']username["']`),
	regexp.MustCompile(`(?i)name=["']email["']`),
	regexp.MustCompile(`(?i)id=["']password["']`),
	regexp.MustCompile(`(?i)id=["']username["']`),
	regexp.MustCompile(`(?i)id=["']login["']`),
	regexp.MustCompile(`(?i)class=["'][^"']*login[^"']*["']`),
	regexp.MustCompile(`(?i)value=["']log\s*in["']`),
	regexp.MustCompile(`(?i)value=["']sign\s*in["']`),
	regexp.MustCompile(`(?i)>\s*log\s*in\s*<`),
	regexp.MustCompile(`(?i)>\s*sign\s*in\s*<`),
	regexp.MustCompile(`(?i)forgot.*password`),
	regexp.MustCompile(`(?i)remember.*me`),
}

// Common login page paths to check
var loginPaths = []string{
	"/",
	"/login.aspx",
	"/Login.aspx",
	"/admin/login.aspx",
	"/Admin/Login.aspx",
	"/account/login.aspx",
	"/Account/Login.aspx",
	"/signin.aspx",
	"/SignIn.aspx",
	"/logon.aspx",
	"/Logon.aspx",
	"/default.aspx",
	"/Default.aspx",
	"/admin/default.aspx",
	"/Admin/Default.aspx",
	"/admin/",
	"/Admin/",
	"/manager/",
	"/Manager/",
	"/console/",
	"/Console/",
	"/auth/",
	"/Auth/",
}

// generateRandomIP creates a random IP from predefined network blocks
func generateRandomIP() string {
	// Select random network block
	block := networkBlocks[rand.Intn(len(networkBlocks))]
	
	// Generate random octets
	octet2 := rand.Intn(256)
	octet3 := rand.Intn(256)
	octet4 := rand.Intn(254) + 1 // 1-254, avoiding 0
	
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
	timeout := 500 * time.Millisecond // Reduced from 1s to 500ms for speed
	
	// Scan all ports concurrently
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

// Global HTTP client for reuse (connection pooling) - follows redirects
var httpClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 200,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
		TLSHandshakeTimeout: 1 * time.Second,
		Dial: (&net.Dialer{
			Timeout: 500 * time.Millisecond,
		}).Dial,
	},
	Timeout: 3 * time.Second, // Increased to handle redirects
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		// Allow up to 5 redirects
		if len(via) >= 5 {
			return fmt.Errorf("stopped after 5 redirects")
		}
		return nil
	},
}

// LoginPageResult contains information about a found login page
type LoginPageResult struct {
	URL             string
	FinalURL        string  // URL after following redirects
	LoginIndicators []string
	Title           string
	Redirected      bool
	StatusCode      int
}

// checkASPX makes HTTP request and checks for ASPX indicators
func checkASPX(ip string, port int) bool {
	// Determine protocol
	protocol := "http"
	if httpsPort, exists := httpsPort[port]; exists && httpsPort {
		protocol = "https"
	}
	
	url := fmt.Sprintf("%s://%s:%d/", protocol, ip, port)
	
	// Make request using global client
	resp, err := httpClient.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	// Read response body (reduced buffer size for faster processing)
	buf := make([]byte, 2048) // Reduced from 4KB to 2KB
	n, err := resp.Body.Read(buf)
	if err != nil && n == 0 {
		return false
	}
	
	content := string(buf[:n])
	
	// Check headers for ASPX indicators first (faster than body)
	for key, values := range resp.Header {
		for _, value := range values {
			headerContent := fmt.Sprintf("%s: %s", key, value)
			for _, pattern := range aspxPatterns {
				if pattern.MatchString(headerContent) {
					return true
				}
			}
		}
	}
	
	// Check body content for ASPX indicators
	for _, pattern := range aspxPatterns {
		if pattern.MatchString(content) {
			return true
		}
	}
	
	return false
}

// checkLoginPage checks a specific URL for login page indicators
func checkLoginPage(baseURL, path string) *LoginPageResult {
	fullURL := baseURL + path
	
	resp, err := httpClient.Get(fullURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	// Process both successful responses and redirects
	if resp.StatusCode != 200 && resp.StatusCode != 302 && resp.StatusCode != 301 {
		return nil
	}
	
	// Check if we were redirected
	wasRedirected := resp.Request.URL.String() != fullURL
	finalURL := resp.Request.URL.String()
	
	// Read more content for login page detection
	buf := make([]byte, 8192) // Increased buffer for better detection
	n, err := resp.Body.Read(buf)
	if err != nil && n == 0 {
		return nil
	}
	
	content := string(buf[:n])
	var indicators []string
	
	// Check for login patterns
	for _, pattern := range loginPatterns {
		if pattern.MatchString(content) {
			indicators = append(indicators, pattern.String())
		}
	}
	
	// Also check URL for login keywords (helpful for redirects)
	if strings.Contains(strings.ToLower(finalURL), "login") ||
	   strings.Contains(strings.ToLower(finalURL), "signin") ||
	   strings.Contains(strings.ToLower(finalURL), "logon") ||
	   strings.Contains(strings.ToLower(finalURL), "auth") {
		indicators = append(indicators, "login-url-keyword")
	}
	
	// If we found login indicators, extract title
	if len(indicators) > 0 {
		title := extractTitle(content)
		return &LoginPageResult{
			URL:             fullURL,
			FinalURL:        finalURL,
			LoginIndicators: indicators,
			Title:           title,
			Redirected:      wasRedirected,
			StatusCode:      resp.StatusCode,
		}
	}
	
	return nil
}

// extractTitle extracts the page title from HTML content
func extractTitle(content string) string {
	titleRegex := regexp.MustCompile(`(?i)<title[^>]*>([^<]*)</title>`)
	matches := titleRegex.FindStringSubmatch(content)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return "No title"
}

// findLoginPages scans for login pages on an ASPX site
func findLoginPages(ip string, port int) []LoginPageResult {
	var loginPages []LoginPageResult
	
	// Determine protocol
	protocol := "http"
	if httpsPort, exists := httpsPort[port]; exists && httpsPort {
		protocol = "https"
	}
	
	baseURL := fmt.Sprintf("%s://%s:%d", protocol, ip, port)
	
	// Check each potential login path
	for _, path := range loginPaths {
		if result := checkLoginPage(baseURL, path); result != nil {
			loginPages = append(loginPages, *result)
		}
		// Small delay to avoid overwhelming the target
		time.Sleep(50 * time.Millisecond)
	}
	
	return loginPages
}

// worker processes IPs concurrently
func worker(jobs <-chan string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	
	for ip := range jobs {
		// Scan the IP for open ports
		openPorts := scanIP(ip)
		
		// Check each open port for ASPX
		for _, port := range openPorts {
			if checkASPX(ip, port) {
				protocol := "http"
				if httpsPort, exists := httpsPort[port]; exists && httpsPort {
					protocol = "https"
				}
				
				// Found ASPX site, now look for login pages
				loginPages := findLoginPages(ip, port)
				
				if len(loginPages) > 0 {
					// Report ASPX site with login pages
					for _, loginPage := range loginPages {
						var msg string
						if loginPage.Redirected {
							msg = fmt.Sprintf("[LOGIN PAGE FOUND - REDIRECT] %s -> %s - Title: %s - Indicators: %d - Status: %d",
								loginPage.URL, loginPage.FinalURL, loginPage.Title, len(loginPage.LoginIndicators), loginPage.StatusCode)
						} else {
							msg = fmt.Sprintf("[LOGIN PAGE FOUND] %s - Title: %s - Indicators: %d - Status: %d",
								loginPage.URL, loginPage.Title, len(loginPage.LoginIndicators), loginPage.StatusCode)
						}
						results <- msg
					}
				} else {
					// Report ASPX site without login pages
					results <- fmt.Sprintf("[ASPX FOUND - NO LOGIN] %s://%s:%d", protocol, ip, port)
				}
			}
		}
	}
}

func main() {
	// Seed random number generator
	rand.Seed(time.Now().UnixNano())
	
	// Configuration - optimized for speed
	const (
		totalScans     = 99999
		maxConcurrency = 100 // Increased from 20 to 100 for higher speed
	)
	
	// Create unique filename with timestamp
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("aspx_scan_results_%s.txt", timestamp)
	
	// Create/open results file
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating results file: %v\n", err)
		return
	}
	defer file.Close()
	
	// Write scan header to file
	header := fmt.Sprintf("ASPX Login Page Scanner Results - %s\nScanning %d random IPs with %d concurrent workers\nLooking for ASPX applications with login pages\n%s\n\n",
		time.Now().Format("2006-01-02 15:04:05"), totalScans, maxConcurrency, strings.Repeat("=", 60))
	file.WriteString(header)
	
	fmt.Printf("Starting ASPX login page scan...\nResults will be saved to: %s\n\n", filename)
	
	// Create channels
	jobs := make(chan string, maxConcurrency)
	results := make(chan string, maxConcurrency)
	
	// Track statistics
	var foundCount int64
	var scannedCount int64
	var statsMu sync.Mutex
	
	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < maxConcurrency; i++ {
		wg.Add(1)
		go worker(jobs, results, &wg)
	}
	
	// Start result printer and file writer goroutine
	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for result := range results {
			// Print to console
			fmt.Println(result)
			
			// Write to file
			file.WriteString(result + "\n")
			
			// Update statistics
			statsMu.Lock()
			foundCount++
			statsMu.Unlock()
		}
	}()
	
	// Progress tracking goroutine
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				statsMu.Lock()
				fmt.Printf("Progress: %d IPs scanned, %d ASPX sites with results found\n", scannedCount, foundCount)
				statsMu.Unlock()
			default:
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
	
	// Send jobs
	go func() {
		defer close(jobs)
		for i := 0; i < totalScans; i++ {
			ip := generateRandomIP()
			jobs <- ip
			
			// Update scanned count
			statsMu.Lock()
			scannedCount++
			statsMu.Unlock()
		}
	}()
	
	// Wait for all workers to complete
	wg.Wait()
	close(results)
	
	// Wait for result printer to finish
	resultWg.Wait()
	
	// Write final statistics to file
	footer := fmt.Sprintf("\n%s\nScan completed at: %s\nTotal IPs scanned: %d\nASPX sites with results: %d\n",
		strings.Repeat("=", 60), time.Now().Format("2006-01-02 15:04:05"), scannedCount, foundCount)
	file.WriteString(footer)
	
	fmt.Printf("\nScan completed!\nTotal IPs scanned: %d\nASPX sites with results: %d\nResults saved to: %s\n", scannedCount, foundCount, filename)
}
