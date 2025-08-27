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

// PHP detection patterns
var phpPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\.php`),
	regexp.MustCompile(`(?i)X-Powered-By.*PHP`),
	regexp.MustCompile(`(?i)PHPSESSID`),
	regexp.MustCompile(`(?i)Set-Cookie.*PHPSESSID`),
	regexp.MustCompile(`(?i)Server.*PHP`),
	regexp.MustCompile(`(?i)<?php`),
	regexp.MustCompile(`(?i)Laravel`),
	regexp.MustCompile(`(?i)WordPress`),
	regexp.MustCompile(`(?i)Drupal`),
	regexp.MustCompile(`(?i)CodeIgniter`),
	regexp.MustCompile(`(?i)CakePHP`),
	regexp.MustCompile(`(?i)Symfony`),
}

// Login page detection patterns
var loginPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<input[^>]*type=["']password["']`),
	regexp.MustCompile(`(?i)<form[^>]*login`),
	regexp.MustCompile(`(?i)name=["']password["']`),
	regexp.MustCompile(`(?i)name=["']username["']`),
	regexp.MustCompile(`(?i)name=["']email["']`),
	regexp.MustCompile(`(?i)name=["']user["']`),
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
	regexp.MustCompile(`(?i)wp-login`), // WordPress specific
	regexp.MustCompile(`(?i)user/login`), // Drupal specific
	regexp.MustCompile(`(?i)administrator`), // Joomla specific
	regexp.MustCompile(`(?i)phpmyadmin`), // phpMyAdmin
}

// Common PHP login page paths to check
var loginPaths = []string{
	"/",
	"/login.php",
	"/Login.php",
	"/admin/login.php",
	"/admin/Login.php",
	"/administrator/",
	"/admin/",
	"/admin/index.php",
	"/signin.php",
	"/auth.php",
	"/login/",
	"/user/login",
	"/account/login",
	"/members/login.php",
	"/wp-login.php", // WordPress
	"/wp-admin/", // WordPress admin
	"/user/login.php", // Drupal
	"/admin/admin.php",
	"/phpmyadmin/", // phpMyAdmin
	"/pma/", // phpMyAdmin alternative
	"/mysql/", // MySQL web interface
	"/cpanel/", // cPanel
	"/webmail/", // Webmail
	"/roundcube/", // RoundCube
	"/squirrelmail/", // SquirrelMail
	"/default.php",
	"/index.php",
	"/home.php",
	"/panel/",
	"/control/",
	"/manager/",
	"/console/",
	"/dashboard/",
	"/backend/",
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
	timeout := 500 * time.Millisecond

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
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   200,
		IdleConnTimeout:       30 * time.Second,
		DisableKeepAlives:     false,
		TLSHandshakeTimeout:   1 * time.Second,
		ResponseHeaderTimeout: 2 * time.Second,
		Dial: (&net.Dialer{
			Timeout: 500 * time.Millisecond,
		}).Dial,
	},
	Timeout: 3 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("stopped after 5 redirects")
		}
		return nil
	},
}

// LoginPageResult contains information about a found login page
type LoginPageResult struct {
	URL             string
	FinalURL        string
	LoginIndicators []string
	Title           string
	Redirected      bool
	StatusCode      int
	PHPFramework    string
}

// checkPHP makes HTTP request and checks for PHP indicators
func checkPHP(ip string, port int) (bool, string) {
	protocol := "http"
	if httpsPort[port] {
		protocol = "https"
	}

	url := fmt.Sprintf("%s://%s:%d/", protocol, ip, port)
	resp, err := httpClient.Get(url)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	framework := "Unknown"

	// Check headers for PHP indicators
	for key, values := range resp.Header {
		for _, value := range values {
			headerContent := fmt.Sprintf("%s: %s", key, value)
			for _, pattern := range phpPatterns {
				if pattern.MatchString(headerContent) {
					// Detect framework from headers
					if strings.Contains(strings.ToLower(headerContent), "laravel") {
						framework = "Laravel"
					} else if strings.Contains(strings.ToLower(headerContent), "wordpress") {
						framework = "WordPress"
					} else if strings.Contains(strings.ToLower(headerContent), "drupal") {
						framework = "Drupal"
					} else if strings.Contains(strings.ToLower(value), "php") {
						framework = "PHP"
					}
					return true, framework
				}
			}
		}
	}

	// Check body content for PHP indicators
	buf := make([]byte, 2048)
	n, err := resp.Body.Read(buf)
	if err != nil && n == 0 {
		return false, ""
	}

	content := string(buf[:n])
	for _, pattern := range phpPatterns {
		if pattern.MatchString(content) {
			// Detect framework from content
			contentLower := strings.ToLower(content)
			if strings.Contains(contentLower, "wordpress") || strings.Contains(contentLower, "wp-content") {
				framework = "WordPress"
			} else if strings.Contains(contentLower, "laravel") {
				framework = "Laravel"
			} else if strings.Contains(contentLower, "drupal") {
				framework = "Drupal"
			} else if strings.Contains(contentLower, "joomla") {
				framework = "Joomla"
			} else if strings.Contains(contentLower, "codeigniter") {
				framework = "CodeIgniter"
			} else if strings.Contains(contentLower, "cakephp") {
				framework = "CakePHP"
			} else if strings.Contains(contentLower, "symfony") {
				framework = "Symfony"
			} else if strings.Contains(contentLower, "phpmyadmin") {
				framework = "phpMyAdmin"
			} else {
				framework = "PHP"
			}
			return true, framework
		}
	}

	return false, ""
}

// checkLoginPage checks a specific URL for login page indicators
func checkLoginPage(baseURL, path string) *LoginPageResult {
	fullURL := baseURL + path
	resp, err := httpClient.Get(fullURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Process successful responses and redirects
	if resp.StatusCode != 200 && resp.StatusCode != 302 && resp.StatusCode != 301 {
		return nil
	}

	wasRedirected := resp.Request.URL.String() != fullURL
	finalURL := resp.Request.URL.String()

	// Read content for login page detection
	buf := make([]byte, 8192)
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

	// Check URL for login keywords
	lowerURL := strings.ToLower(finalURL)
	if strings.Contains(lowerURL, "login") ||
		strings.Contains(lowerURL, "signin") ||
		strings.Contains(lowerURL, "logon") ||
		strings.Contains(lowerURL, "auth") ||
		strings.Contains(lowerURL, "wp-login") ||
		strings.Contains(lowerURL, "admin") {
		indicators = append(indicators, "login-url-keyword")
	}

	if len(indicators) > 0 {
		title := extractTitle(content)
		framework := detectFrameworkFromContent(content)
		
		return &LoginPageResult{
			URL:             fullURL,
			FinalURL:        finalURL,
			LoginIndicators: indicators,
			Title:           title,
			Redirected:      wasRedirected,
			StatusCode:      resp.StatusCode,
			PHPFramework:    framework,
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

// detectFrameworkFromContent detects PHP framework from page content
func detectFrameworkFromContent(content string) string {
	contentLower := strings.ToLower(content)
	if strings.Contains(contentLower, "wordpress") || strings.Contains(contentLower, "wp-content") {
		return "WordPress"
	} else if strings.Contains(contentLower, "laravel") {
		return "Laravel"
	} else if strings.Contains(contentLower, "drupal") {
		return "Drupal"
	} else if strings.Contains(contentLower, "joomla") {
		return "Joomla"
	} else if strings.Contains(contentLower, "codeigniter") {
		return "CodeIgniter"
	} else if strings.Contains(contentLower, "cakephp") {
		return "CakePHP"
	} else if strings.Contains(contentLower, "symfony") {
		return "Symfony"
	} else if strings.Contains(contentLower, "phpmyadmin") {
		return "phpMyAdmin"
	} else if strings.Contains(contentLower, "magento") {
		return "Magento"
	} else if strings.Contains(contentLower, "prestashop") {
		return "PrestaShop"
	} else if strings.Contains(contentLower, "opencart") {
		return "OpenCart"
	}
	return "PHP"
}

// findLoginPages scans for login pages on a PHP site
func findLoginPages(ip string, port int) []LoginPageResult {
	var loginPages []LoginPageResult
	protocol := "http"
	if httpsPort[port] {
		protocol = "https"
	}

	baseURL := fmt.Sprintf("%s://%s:%d", protocol, ip, port)

	// Check each potential login path
	for _, path := range loginPaths {
		if result := checkLoginPage(baseURL, path); result != nil {
			loginPages = append(loginPages, *result)
		}
		time.Sleep(50 * time.Millisecond)
	}

	return loginPages
}

// worker processes IPs concurrently
func worker(jobs <-chan string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	for ip := range jobs {
		openPorts := scanIP(ip)

		for _, port := range openPorts {
			if isPHP, framework := checkPHP(ip, port); isPHP {
				protocol := "http"
				if httpsPort[port] {
					protocol = "https"
				}

				loginPages := findLoginPages(ip, port)

				if len(loginPages) > 0 {
					for _, loginPage := range loginPages {
						var msg string
						if loginPage.Redirected {
							msg = fmt.Sprintf("[PHP LOGIN REDIRECT] %s -> %s | %s | %s | Indicators: %d | Status: %d",
								loginPage.URL, loginPage.FinalURL, framework, loginPage.Title, 
								len(loginPage.LoginIndicators), loginPage.StatusCode)
						} else {
							msg = fmt.Sprintf("[PHP LOGIN FOUND] %s | %s | %s | Indicators: %d | Status: %d",
								loginPage.URL, framework, loginPage.Title, 
								len(loginPage.LoginIndicators), loginPage.StatusCode)
						}
						results <- msg
					}
				} else {
					// Report PHP site without login pages
					results <- fmt.Sprintf("[PHP FOUND - NO LOGIN] %s://%s:%d | %s", protocol, ip, port, framework)
				}
			}
		}
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())

	// Configuration
	const (
		totalScans     = 99999
		maxConcurrency = 100
	)

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("php_login_results_%s.txt", timestamp)

	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating results file: %v\n", err)
		return
	}
	defer file.Close()

	header := fmt.Sprintf("PHP Login Page Scanner Results - %s\nScanning %d random IPs with %d concurrent workers\nLooking for PHP applications with login pages\nSupported: WordPress, Laravel, Drupal, Joomla, CodeIgniter, CakePHP, Symfony, phpMyAdmin, Magento, PrestaShop, OpenCart\n%s\n\n",
		time.Now().Format("2006-01-02 15:04:05"), totalScans, maxConcurrency, strings.Repeat("=", 80))
	file.WriteString(header)

	fmt.Printf("🐘 PHP LOGIN PAGE SCANNER STARTING...\nResults will be saved to: %s\n\n", filename)

	jobs := make(chan string, maxConcurrency)
	results := make(chan string, maxConcurrency)

	var foundCount int64
	var scannedCount int64
	var statsMu sync.Mutex

	// Start worker goroutines
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

	// Progress tracking
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				statsMu.Lock()
				fmt.Printf("🐘 PHP Progress: %d IPs scanned, %d PHP sites with results found\n", scannedCount, foundCount)
				statsMu.Unlock()
			default:
				time.Sleep(100 * time.Millisecond)
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

	footer := fmt.Sprintf("\n%s\n🐘 PHP SCAN COMPLETE: %s\nTotal IPs scanned: %d\nPHP sites with results: %d\n",
		strings.Repeat("=", 80), time.Now().Format("2006-01-02 15:04:05"), scannedCount, foundCount)
	file.WriteString(footer)

	fmt.Printf("\n🎯 PHP SCAN COMPLETE!\n📊 Total IPs scanned: %d\n📊 PHP sites with results: %d\n💾 Results saved to: %s\n", 
		scannedCount, foundCount, filename)
}
