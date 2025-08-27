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

// Ports to scan - reduced list for speed
var targetPorts = []int{80, 443, 8080, 8443}

// HTTPS ports
var httpsPort = map[int]bool{443: true, 8443: true}

// ASPX detection patterns - reduced for speed
var aspxPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)aspx`),
	regexp.MustCompile(`(?i)ASP\.NET`),
	regexp.MustCompile(`(?i)ASPSESSIONID`),
}

// Login page detection patterns - optimized for speed
var loginPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<input[^>]*type=["']password["']`),
	regexp.MustCompile(`(?i)name=["']password["']`),
	regexp.MustCompile(`(?i)name=["']username["']`),
	regexp.MustCompile(`(?i)id=["']password["']`),
	regexp.MustCompile(`(?i)>.*log.*in.*<`),
	regexp.MustCompile(`(?i)forgot.*password`),
}

// Reduced login paths for speed - only most common ones
var loginPaths = []string{
	"/",
	"/login.aspx",
	"/Login.aspx",
	"/admin/login.aspx",
	"/Admin/Login.aspx",
	"/default.aspx",
	"/Default.aspx",
	"/admin/",
	"/Admin/",
}

// generateRandomIP creates a random IP from predefined network blocks
func generateRandomIP() string {
	block := networkBlocks[rand.Intn(len(networkBlocks))]
	octet2 := rand.Intn(256)
	octet3 := rand.Intn(256)
	octet4 := rand.Intn(254) + 1
	return fmt.Sprintf("%d.%d.%d.%d", block, octet2, octet3, octet4)
}

// scanPort checks if a specific port is open - super fast version
func scanPort(ip string, port int, timeout time.Duration) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// scanIP scans ports with minimal timeout for maximum speed
func scanIP(ip string) []int {
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	timeout := 200 * time.Millisecond // Super aggressive timeout

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

// Ultra-fast HTTP client - aggressive settings
var httpClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        500,  // Increased
		MaxIdleConnsPerHost: 500,  // Increased
		IdleConnTimeout:     10 * time.Second, // Reduced
		DisableKeepAlives:   false,
		TLSHandshakeTimeout: 500 * time.Millisecond, // Reduced
		ResponseHeaderTimeout: 1 * time.Second, // Added timeout
		Dial: (&net.Dialer{
			Timeout: 300 * time.Millisecond, // Super fast
		}).Dial,
	},
	Timeout: 1500 * time.Millisecond, // Ultra fast timeout
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 2 { // Only allow 2 redirects for speed
			return fmt.Errorf("stopped after 2 redirects")
		}
		return nil
	},
}

// LoginPageResult - simplified for speed
type LoginPageResult struct {
	URL        string
	FinalURL   string
	Title      string
	Redirected bool
}

// Fast ASPX check - minimal processing
func checkASPX(ip string, port int) bool {
	protocol := "http"
	if httpsPort[port] {
		protocol = "https"
	}

	url := fmt.Sprintf("%s://%s:%d/", protocol, ip, port)
	resp, err := httpClient.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Quick header check first
	for key, values := range resp.Header {
		for _, value := range values {
			headerContent := strings.ToLower(fmt.Sprintf("%s: %s", key, value))
			if strings.Contains(headerContent, "aspx") || 
			   strings.Contains(headerContent, "asp.net") || 
			   strings.Contains(headerContent, "aspsessionid") {
				return true
			}
		}
	}

	// Quick body check - minimal read
	buf := make([]byte, 1024) // Reduced buffer for speed
	n, err := resp.Body.Read(buf)
	if err != nil && n == 0 {
		return false
	}

	content := strings.ToLower(string(buf[:n]))
	return strings.Contains(content, "aspx") || strings.Contains(content, "asp.net")
}

// Super fast login page check
func checkLoginPage(baseURL, path string) *LoginPageResult {
	fullURL := baseURL + path
	resp, err := httpClient.Get(fullURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 302 && resp.StatusCode != 301 {
		return nil
	}

	wasRedirected := resp.Request.URL.String() != fullURL
	finalURL := resp.Request.URL.String()

	// Fast read - smaller buffer
	buf := make([]byte, 4096)
	n, err := resp.Body.Read(buf)
	if err != nil && n == 0 {
		return nil
	}

	content := string(buf[:n])
	loginFound := false

	// Quick pattern check - break early when found
	for _, pattern := range loginPatterns {
		if pattern.MatchString(content) {
			loginFound = true
			break
		}
	}

	// Quick URL keyword check
	if !loginFound {
		lowerURL := strings.ToLower(finalURL)
		if strings.Contains(lowerURL, "login") || 
		   strings.Contains(lowerURL, "signin") || 
		   strings.Contains(lowerURL, "auth") {
			loginFound = true
		}
	}

	if loginFound {
		title := "Login Page"
		// Quick title extraction
		if titleStart := strings.Index(strings.ToLower(content), "<title"); titleStart != -1 {
			if titleContentStart := strings.Index(content[titleStart:], ">"); titleContentStart != -1 {
				titleStart += titleContentStart + 1
				if titleEnd := strings.Index(content[titleStart:], "</title>"); titleEnd != -1 {
					title = strings.TrimSpace(content[titleStart : titleStart+titleEnd])
					if len(title) > 50 {
						title = title[:50] + "..."
					}
				}
			}
		}

		return &LoginPageResult{
			URL:        fullURL,
			FinalURL:   finalURL,
			Title:      title,
			Redirected: wasRedirected,
		}
	}

	return nil
}

// Fast login page finder - reduced delays
func findLoginPages(ip string, port int) []LoginPageResult {
	var loginPages []LoginPageResult
	protocol := "http"
	if httpsPort[port] {
		protocol = "https"
	}

	baseURL := fmt.Sprintf("%s://%s:%d", protocol, ip, port)

	// Check paths with minimal delay
	for _, path := range loginPaths {
		if result := checkLoginPage(baseURL, path); result != nil {
			loginPages = append(loginPages, *result)
		}
		time.Sleep(10 * time.Millisecond) // Reduced delay
	}

	return loginPages
}

// Super fast worker
func worker(jobs <-chan string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	for ip := range jobs {
		openPorts := scanIP(ip)

		for _, port := range openPorts {
			if checkASPX(ip, port) {
				loginPages := findLoginPages(ip, port)

				if len(loginPages) > 0 {
					for _, loginPage := range loginPages {
						var msg string
						if loginPage.Redirected {
							msg = fmt.Sprintf("[FAST-LOGIN-REDIRECT] %s -> %s - %s",
								loginPage.URL, loginPage.FinalURL, loginPage.Title)
						} else {
							msg = fmt.Sprintf("[FAST-LOGIN-FOUND] %s - %s",
								loginPage.URL, loginPage.Title)
						}
						results <- msg
					}
				}
			}
		}
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())

	// Aggressive speed configuration
	const (
		totalScans     = 99999
		maxConcurrency = 200 // Doubled for maximum speed
	)

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("speedy_results_%s.txt", timestamp)

	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating results file: %v\n", err)
		return
	}
	defer file.Close()

	header := fmt.Sprintf("SPEEDY ASPX Login Scanner - %s\nULTRA FAST MODE: %d IPs with %d workers\n%s\n\n",
		time.Now().Format("2006-01-02 15:04:05"), totalScans, maxConcurrency, strings.Repeat("=", 60))
	file.WriteString(header)

	fmt.Printf("🚀 SPEEDY ASPX LOGIN SCANNER STARTING...\nResults: %s\n\n", filename)

	jobs := make(chan string, maxConcurrency*2) // Larger buffer
	results := make(chan string, maxConcurrency*2)

	var foundCount int64
	var scannedCount int64
	var statsMu sync.Mutex

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < maxConcurrency; i++ {
		wg.Add(1)
		go worker(jobs, results, &wg)
	}

	// Result handler
	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for result := range results {
			fmt.Println(result)
			file.WriteString(result + "\n")
			statsMu.Lock()
			foundCount++
			statsMu.Unlock()
		}
	}()

	// Progress tracker - faster updates
	go func() {
		ticker := time.NewTicker(5 * time.Second) // Faster updates
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				statsMu.Lock()
				fmt.Printf("🔥 SPEEDY: %d scanned, %d found (%.1f/sec)\n", 
					scannedCount, foundCount, float64(scannedCount)/time.Since(time.Now().Add(-5*time.Second)).Seconds())
				statsMu.Unlock()
			default:
				time.Sleep(50 * time.Millisecond)
			}
		}
	}()

	// Job generator
	go func() {
		defer close(jobs)
		for i := 0; i < totalScans; i++ {
			jobs <- generateRandomIP()
			statsMu.Lock()
			scannedCount++
			statsMu.Unlock()
		}
	}()

	wg.Wait()
	close(results)
	resultWg.Wait()

	footer := fmt.Sprintf("\n%s\n🚀 SPEEDY SCAN COMPLETE: %s\nScanned: %d | Found: %d\n",
		strings.Repeat("=", 60), time.Now().Format("2006-01-02 15:04:05"), scannedCount, foundCount)
	file.WriteString(footer)

	fmt.Printf("\n🎯 SPEEDY SCAN COMPLETE!\n📊 %d scanned | %d found\n💾 %s\n", scannedCount, foundCount, filename)
}
