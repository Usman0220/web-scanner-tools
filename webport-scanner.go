package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Network blocks used for internet random IP generation (same as the other scanners)
var networkBlocks = []int{13, 18, 20, 34, 35, 40, 52, 54, 104, 134, 137, 139, 159}

// Local network class toggles (private Class A/B/C ranges, used with -local)
var scanClassA bool // 10.0.0.0/8
var scanClassB bool // 172.16.0.0/12
var scanClassC bool // 192.168.0.0/16

// defaultCloudPatterns are keywords matched against the banner Server/title
// to drop open ports owned by cloud/CDN providers.
var defaultCloudPatterns = []string{
	"microsoft", "azure", "azureedge", "amazon", "aws", "cloudfront",
	"google", "googleusercontent", "oracle", "digitalocean", "ovh",
	"linode", "hetzner", "scaleway", "vultr", "cloudflare", "akamai",
	"fastly", "incapsula", "imperva", "sucuri",
}

// cloudPatterns is the active filter list (overridable via -cloud-patterns)
var cloudPatterns = defaultCloudPatterns

// Default web ports to scan when no -ports is given
var defaultWebPorts = []int{80, 81, 443, 8080, 8443, 8000, 8888, 8880, 7001, 9000, 9443, 10000, 28017, 5000, 5001, 8001, 8081, 8090, 8888}

// Result holds one discovered open web port
type Result struct {
	Target     string
	Port       int
	Scheme     string // http or https when probing succeeds
	StatusCode int
	Server     string
	Title      string
}

// ANSI color helpers
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

func red(s string) string   { return colorRed + s + colorReset }
func green(s string) string { return colorGreen + s + colorReset }
func yellow(s string) string { return colorYellow + s + colorReset }
func cyan(s string) string  { return colorCyan + s + colorReset }
func bold(s string) string  { return colorBold + s + colorReset }

type scanner struct {
	ports    []int
	timeout  time.Duration
	workers  int
	probe    bool
	skipCloud bool
	client   *http.Client
	file     *os.File
	fileMu   sync.Mutex
	results  chan Result
	cancel   chan struct{}
	scanMu   sync.Mutex
	scanned  int64
	open     int64
	lastTick time.Time

	progressInterval time.Duration
}

func main() {
	var (
		portsFlag   = flag.String("ports", "", "web ports to scan, comma-separated (default: 80,81,443,8080,8443,8000,8888,8880,7001,9000,9443,10000,28017,5000,5001,8001,8081,8090)")
		fileFlag    = flag.String("file", "", "scan targets from file (one per line: IP, host, CIDR, or range)")
		timeoutF    = flag.Duration("timeout", 2*time.Second, "connection timeout per port")
		workersF    = flag.Int("workers", 200, "number of concurrent scan workers")
		probeF      = flag.Bool("banner", false, "probe open ports over HTTP(S) and report server/title")
		outName     = flag.String("out", "", "output file (default: webport_results_<timestamp>.txt)")
		countF      = flag.Int("count", -1, "number of random IPs to scan when no explicit target is given (default: 99,999)")
		blocksF     = flag.String("blocks", "", "network blocks for internet random IP generation, comma-separated (default: 13,18,20,34,35,40,52,54,104,134,137,139,159)")
		localF      = flag.Bool("local", false, "scan local/private ranges (Class A 10/8, B 172.16/12, C 192.168/16) instead of internet blocks")
		aF          = flag.Bool("a", true, "include Class A private range 10.0.0.0/8 (with -local)")
		bF          = flag.Bool("b", true, "include Class B private range 172.16.0.0/12 (with -local)")
		cF          = flag.Bool("c", true, "include Class C private range 192.168.0.0/16 (with -local)")
		exhaustF    = flag.Bool("exhaust", false, "enumerate every IP of the enabled ranges instead of random sampling")
		queueF      = flag.Int("queue", 1024, "job/result channel buffer size")
		progressF   = flag.Int("progress", 2, "progress report interval in seconds")
		maxIdleF    = flag.Int("max-idle", 500, "max idle connections for the banner HTTP client")
		headerTF    = flag.Duration("banner-timeout", 3*time.Second, "response header timeout for banner probing")
		httpxF      = flag.String("httpx", "auto", "pipe found URLs to projectdiscovery httpx ('auto' to detect, binary name/path, or 'off')")
		httpxOptsF  = flag.String("httpx-opts", "-status-code -title -tech-detect -web-server", "extra flags passed to projectdiscovery httpx")
		skipCloudF  = flag.Bool("skip-cloud", true, "drop open ports whose banner/title matches cloud/CDN providers (e.g. Microsoft-Azure-Application-Gateway)")
		cloudF      = flag.String("cloud-patterns", "", "comma-separated keywords treated as cloud/CDN (default: microsoft,azure,amazon,aws,cloudfront,google,oracle,digitalocean,ovh,linode,hetzner,scaleway,vultr,cloudflare,akamai,fastly,incapsula,imperva,sucuri)")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Web Port Scanner
Scans targets for open web (HTTP/HTTPS) ports.

With no target it scans random IPs from the internet network blocks.
With -local it scans local/private ranges instead:
  - Class A: 10.0.0.0/8        (10.x.y.z)
  - Class B: 172.16.0.0/12     (172.16-31.x.y)
  - Class C: 192.168.0.0/16    (192.168.x.y)

Usage:
  %s [options] <target> [target2 ...]   scan explicit targets
  %s [options] -local [options]         scan private class ranges
  %s [options] random [count]           internet random IP scan
  %s [options]                          random 99,999 IPs by default

Targets can be a single IP or hostname, CIDR block, IP range, or a
comma-separated list of any of the above.

All settings are changeable via flags (use -help to list them).
Found URLs are written to <out>.urls and piped to projectdiscovery
httpx by default (-httpx off to disable).

Options:
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	// Custom network blocks for internet random IP generation
	if *blocksF != "" {
		blocks, err := parseBlocks(*blocksF)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error in -blocks: %v\n", err)
			os.Exit(1)
		}
		networkBlocks = blocks
	}

	scanClassA = *aF
	scanClassB = *bF
	scanClassC = *cF
	if *localF && !scanClassA && !scanClassB && !scanClassC {
		fmt.Fprintln(os.Stderr, "Error: -local requires at least one class range (-a, -b, or -c).")
		os.Exit(1)
	}

	// Custom cloud/CDN filter keywords
	if *cloudF != "" {
		var pats []string
		for _, p := range strings.Split(*cloudF, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				pats = append(pats, strings.ToLower(p))
			}
		}
		if len(pats) == 0 {
			fmt.Fprintln(os.Stderr, "Error: -cloud-patterns is empty.")
			os.Exit(1)
		}
		cloudPatterns = pats
	}

	targets := flag.Args()
	if *fileFlag != "" {
		fromFile, err := readTargetsFile(*fileFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading targets file: %v\n", err)
			os.Exit(1)
		}
		targets = append(targets, fromFile...)
	}

	// Optional "random [count]" keyword
	randomCount := 0
	if len(targets) > 0 && targets[0] == "random" {
		if len(targets) > 1 {
			if c, err := strconv.Atoi(targets[1]); err == nil && *countF < 0 {
				randomCount = c
			}
		}
		targets = targets[1:]
	}

	// Decide scan mode: explicit targets win over random/local defaults
	var ips []string
	var err error
	switch {
	case len(targets) > 0:
		ips, err = expandTargets(targets)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error in targets: %v\n", err)
			os.Exit(1)
		}
	case *localF:
		if *exhaustF {
			fmt.Printf("%s\n", cyan("🔍 Exhaustive local scan: enumerating all IPs of the enabled class ranges"))
		} else {
			if randomCount == 0 {
				randomCount = *countF
				if randomCount < 0 {
					randomCount = 99999
				}
			}
			fmt.Printf("%s\n", green("🎯 Random local scan mode: "+strconv.Itoa(randomCount)+" IPs"))
		}
		fmt.Printf("📋 %s\n", cyan(fmt.Sprintf("Ranges: A(10/8)=%t B(172.16/12)=%t C(192.168/16)=%t", scanClassA, scanClassB, scanClassC)))
		fmt.Println(bold("======================================"))
		if *exhaustF {
			ips = enumerateLocalIPs()
		} else {
			ips = generateLocalIPs(randomCount)
		}
	default:
		if randomCount == 0 {
			randomCount = *countF
			if randomCount < 0 {
				randomCount = 99999
			}
		}
		fmt.Printf("%s\n", green("🎯 Random IP scan mode: "+strconv.Itoa(randomCount)+" IPs"))
		fmt.Println(bold("======================================"))
		ips = generateRandomIPs(randomCount)
	}
	if len(ips) == 0 {
		fmt.Fprintln(os.Stderr, "No targets to scan.")
		os.Exit(1)
	}

	// Parse ports
	ports := defaultWebPorts
	if *portsFlag != "" {
		ports, err = parsePorts(*portsFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error in -ports: %v\n", err)
			os.Exit(1)
		}
	}

	// Output file
	outPath := *outName
	if outPath == "" {
		outPath = fmt.Sprintf("webport_results_%s.txt", time.Now().Format("2006-01-02_15-04-05"))
	}
	file, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not create output file: %v\n", err)
	}

	s := &scanner{
		ports:            ports,
		timeout:          *timeoutF,
		workers:          *workersF,
		probe:            *probeF,
		skipCloud:        *skipCloudF,
		file:             file,
		results:          make(chan Result, *queueF),
		cancel:           make(chan struct{}),
		progressInterval: time.Duration(*progressF) * time.Second,
	}

	if file != nil {
		header := fmt.Sprintf("Web Port Scanner Results - %s\nTargets: %d IPs | Ports: %v\n%s\n\n",
			time.Now().Format("2006-01-02 15:04:05"), len(ips), ports, strings.Repeat("=", 60))
		file.WriteString(header)
		fmt.Printf("📄 %s\n\n", cyan("Results will be saved to: "+outPath))
	}

	// HTTP client for banner probing
	s.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:          *maxIdleF,
			MaxIdleConnsPerHost:   *maxIdleF / 10,
			IdleConnTimeout:       30 * time.Second,
			DisableKeepAlives:     false,
			TLSHandshakeTimeout:   *timeoutF,
			ResponseHeaderTimeout: *headerTF,
			Dial: (&net.Dialer{Timeout: *timeoutF}).Dial,
		},
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Streaming projectdiscovery httpx: pipe open ports as they are found
	var httpxIn io.WriteCloser
	var httpxCmd *exec.Cmd
	streamHTTPX := false
	httpxBin := strings.ToLower(*httpxF)
	if httpxBin != "off" && httpxBin != "false" {
		if httpxBin == "auto" || httpxBin == "true" {
			httpxBin = findPDHTTPX()
		}
		if httpxBin == "" {
			fmt.Println("⚠️  ProjectDiscovery httpx not found in PATH; URLs will still be saved to <out>.urls.")
		} else {
			cmd := exec.Command(httpxBin, strings.Fields(*httpxOptsF)...)
			var err error
			httpxIn, err = cmd.StdinPipe()
			if err == nil {
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if err := cmd.Start(); err != nil {
					fmt.Printf("⚠️  Could not start httpx: %v\n", err)
					httpxIn = nil
				} else {
					httpxCmd = cmd
					streamHTTPX = true
					fmt.Printf("%s\n", cyan(fmt.Sprintf("🔎 Streaming open ports to httpx (%s) as they are found...", httpxBin)))
				}
			}
		}
	}

	// Result writer + URL collector (streams to httpx immediately)
	var resultWg sync.WaitGroup
	var urls []string
	var urlsMu sync.Mutex
	var skipped int64
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for r := range s.results {
			if s.skipCloud && matchesCloud(r) {
				skipped++
				fmt.Printf("%s %s:%d server=%q\n", yellow("⛔ [SKIP cloud]"), r.Target, r.Port, r.Server)
				continue
			}
			line := r.String()
			fmt.Println(strings.Replace(line, "[OPEN]", green("[OPEN]"), 1))
			if s.file != nil {
				s.fileMu.Lock()
				s.file.WriteString(line + "\n")
				s.file.Sync()
				s.fileMu.Unlock()
			}
			for _, u := range r.URLs() {
				urlsMu.Lock()
				urls = append(urls, u)
				urlsMu.Unlock()
				if streamHTTPX {
					fmt.Fprintln(httpxIn, u)
				}
			}
		}
	}()

	fmt.Printf("%s\n", bold(cyan(fmt.Sprintf("🔍 Scanning %d IPs on %d web ports (%d workers)...", len(ips), len(ports), s.workers))))

	// Progress ticker
	progStop := make(chan struct{})
	go s.progress(progStop)

	// Kick off scanning
	var scanWg sync.WaitGroup
	jobCh := make(chan scanJob, s.workers)
	for i := 0; i < s.workers; i++ {
		scanWg.Add(1)
		go s.worker(jobCh, &scanWg)
	}
scanLoop:
	for _, ip := range ips {
		for _, p := range s.ports {
			select {
			case jobCh <- scanJob{ip: ip, port: p}:
			case <-s.cancel:
				break scanLoop
			}
		}
	}
	close(jobCh)
	scanWg.Wait()

	s.progressOnce()
	close(s.cancel)
	close(progStop)
	close(s.results)
	resultWg.Wait()

	// Close the httpx stream and wait for it to finish probing
	if streamHTTPX && httpxCmd != nil {
		if httpxIn != nil {
			httpxIn.Close()
		}
		httpxCmd.Wait()
	}

	if s.file != nil {
		footer := fmt.Sprintf("\n%s\nScan finished at: %s\nIPs scanned: %d\nOpen web ports found: %d\nCloud/CDN ports skipped: %d\n",
			strings.Repeat("=", 60), time.Now().Format("2006-01-02 15:04:05"), len(ips), s.open, skipped)
		s.file.WriteString(footer)
		s.file.Close()
	}
	fmt.Printf("\n%s\n", green(fmt.Sprintf("✅ Scan complete! %d open web ports found across %d IPs (%d skipped as cloud/CDN). Results in %s", s.open, len(ips), skipped, outPath)))

	// Write the collected URL list for later use
	if len(urls) > 0 {
		urlFile := outPath + ".urls"
		if err := os.WriteFile(urlFile, []byte(strings.Join(urls, "\n")+"\n"), 0644); err != nil {
			fmt.Printf("⚠️  Could not write URL list: %v\n", err)
		} else {
			fmt.Printf("%s\n", cyan(fmt.Sprintf("🌐 URL list saved: %s (%d URLs)", urlFile, len(urls))))
		}
	}
}

type scanJob struct {
	ip   string
	port int
}

func (s *scanner) worker(jobs <-chan scanJob, wg *sync.WaitGroup) {
	defer wg.Done()
	for j := range jobs {
		if s.scanPort(j.ip, j.port) {
			s.scanMu.Lock()
			s.open++
			s.scanMu.Unlock()
			found := Result{Target: j.ip, Port: j.port}
			// Probe banner when requested, or when cloud filtering needs the Server header
			if s.probe || s.skipCloud {
				found = s.probeBanner(j.ip, j.port)
			}
			s.results <- found
		}
		s.scanMu.Lock()
		s.scanned++
		s.scanMu.Unlock()
	}
}

// scanPort checks if a TCP port is open
func (s *scanner) scanPort(ip string, port int) bool {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, s.timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// probeBanner tries to determine scheme, status, server and title of an open port
func (s *scanner) probeBanner(ip string, port int) Result {
	r := Result{Target: ip, Port: port}

	// Try TLS first - server may be HTTPS-only
	scheme := "http"
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: s.timeout}, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)), &tls.Config{InsecureSkipVerify: true})
	if err == nil {
		scheme = "https"
		conn.Close()
	}

	url := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(ip, strconv.Itoa(port)))
	resp, err := s.client.Get(url)
	if err != nil {
		// Some servers only speak the other scheme; the raw port is still open
		r.Scheme = scheme
		return r
	}
	defer resp.Body.Close()

	r.Scheme = scheme
	r.StatusCode = resp.StatusCode
	r.Server = resp.Header.Get("Server")

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	r.Title = extractTitle(string(body))
	return r
}

// extractTitle pulls the <title> tag from HTML
func extractTitle(content string) string {
	body := content
	idx := strings.Index(strings.ToLower(body), "<title")
	if idx == -1 {
		return ""
	}
	start := strings.IndexByte(body[idx:], '>')
	if start == -1 {
		return ""
	}
	start = idx + start + 1
	end := strings.Index(body[start:], "</title>")
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(body[start : start+end])
}

// URLs returns the URL(s) to probe for this open port. If the scheme is
// unknown (no banner probe), both https and http variants are emitted so
// httpx can determine which one answers.
func (r Result) URLs() []string {
	host := net.JoinHostPort(r.Target, strconv.Itoa(r.Port))
	switch r.Scheme {
	case "https":
		return []string{fmt.Sprintf("https://%s", host)}
	case "http":
		return []string{fmt.Sprintf("http://%s", host)}
	default:
		return []string{
			fmt.Sprintf("https://%s", host),
			fmt.Sprintf("http://%s", host),
		}
	}
}

func (r Result) String() string {
	urls := r.URLs()
	var parts []string
	if len(urls) == 1 {
		parts = append(parts, fmt.Sprintf("[OPEN] %s", urls[0]))
	} else {
		parts = append(parts, fmt.Sprintf("[OPEN] %s", urls[0]), urls[1])
	}
	if r.StatusCode != 0 {
		parts = append(parts, fmt.Sprintf("status=%d", r.StatusCode))
	}
	if r.Server != "" {
		parts = append(parts, fmt.Sprintf("server=%s", r.Server))
	}
	if r.Title != "" {
		parts = append(parts, fmt.Sprintf("title=%q", r.Title))
	}
	return strings.Join(parts, " | ")
}

// findPDHTTPX locates the projectdiscovery httpx binary, skipping any
// Python HTTPX client that may shadow it in PATH.
func findPDHTTPX() string {
	candidates := []string{"httpx", "httpx-pd", "httpx-toolkit", "httpx2"}
	for _, c := range candidates {
		p, err := exec.LookPath(c)
		if err != nil {
			continue
		}
		if isPythonScript(p) {
			continue
		}
		return c
	}
	return ""
}

// isPythonScript reports whether the given executable is a python script
// (i.e. the httpx python client, which shadows projectdiscovery's httpx).
func isPythonScript(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 256)
	n, _ := f.Read(buf)
	return strings.Contains(strings.ToLower(string(buf[:n])), "python")
}

// matchesCloud reports whether a result's banner/title identifies it as a
// cloud/CDN provider endpoint (e.g. Microsoft-Azure-Application-Gateway).
func matchesCloud(r Result) bool {
	hay := strings.ToLower(r.Server + " " + r.Title)
	if hay == "" {
		return false
	}
	for _, p := range cloudPatterns {
		if strings.Contains(hay, p) {
			return true
		}
	}
	return false
}

func (s *scanner) progress(stop chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			s.progressOnce()
		}
	}
}

func (s *scanner) progressOnce() {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	if time.Since(s.lastTick) < 2*time.Second {
		return
	}
	s.lastTick = time.Now()
	if s.scanned > 0 {
		fmt.Printf("%s\n", yellow(fmt.Sprintf("⏳ Progress: %d connection attempts, %d open ports", s.scanned, s.open)))
	}
}

// parseBlocks parses a comma-separated list of network block first-octets for -blocks
func parseBlocks(s string) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		b, err := strconv.Atoi(part)
		if err != nil || b < 1 || b > 223 {
			return nil, fmt.Errorf("invalid network block %q (must be 1-223)", part)
		}
		if !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid network blocks specified")
	}
	return out, nil
}

// parsePorts parses a comma-separated port list, supporting ranges like 80-90
func parsePorts(s string) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil || lo < 1 || lo > hi || hi > 65535 {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			for p := lo; p <= hi; p++ {
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid ports specified")
	}
	return out, nil
}

// readTargetsFile reads newline-separated targets from a file
func readTargetsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

// generateRandomIP creates a random IP from predefined network blocks (same as the other scanners)
func generateRandomIP() string {
	block := networkBlocks[rand.Intn(len(networkBlocks))]
	octet2 := rand.Intn(256)
	octet3 := rand.Intn(256)
	octet4 := rand.Intn(254) + 1 // 1-254, avoiding 0
	return fmt.Sprintf("%d.%d.%d.%d", block, octet2, octet3, octet4)
}

// generateRandomIPs returns count random IPs
func generateRandomIPs(count int) []string {
	rand.Seed(time.Now().UnixNano())
	ips := make([]string, count)
	for i := 0; i < count; i++ {
		ips[i] = generateRandomIP()
	}
	return ips
}

// generateLocalIP creates a random IP from the enabled local class ranges
func generateLocalIP() string {
	// Collect enabled classes and pick one at random
	var classes []int
	if scanClassA {
		classes = append(classes, 1) // 10.0.0.0/8
	}
	if scanClassB {
		classes = append(classes, 2) // 172.16.0.0/12
	}
	if scanClassC {
		classes = append(classes, 3) // 192.168.0.0/16
	}
	switch classes[rand.Intn(len(classes))] {
	case 1:
		return fmt.Sprintf("10.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(254)+1)
	case 2:
		return fmt.Sprintf("172.%d.%d.%d", 16+rand.Intn(16), rand.Intn(256), rand.Intn(254)+1)
	default:
		return fmt.Sprintf("192.168.%d.%d", rand.Intn(256), rand.Intn(254)+1)
	}
}

// generateLocalIPs returns count random IPs from the enabled class ranges
func generateLocalIPs(count int) []string {
	rand.Seed(time.Now().UnixNano())
	ips := make([]string, count)
	for i := 0; i < count; i++ {
		ips[i] = generateLocalIP()
	}
	return ips
}

// enumerateLocalIPs returns every IP of the enabled class ranges
func enumerateLocalIPs() []string {
	var ips []string
	if scanClassA {
		for o2 := 0; o2 < 256; o2++ {
			for o3 := 0; o3 < 256; o3++ {
				for o4 := 1; o4 < 255; o4++ {
					ips = append(ips, fmt.Sprintf("10.%d.%d.%d", o2, o3, o4))
				}
			}
		}
	}
	if scanClassB {
		for o2 := 16; o2 <= 31; o2++ {
			for o3 := 0; o3 < 256; o3++ {
				for o4 := 1; o4 < 255; o4++ {
					ips = append(ips, fmt.Sprintf("172.%d.%d.%d", o2, o3, o4))
				}
			}
		}
	}
	if scanClassC {
		for o3 := 0; o3 < 256; o3++ {
			for o4 := 1; o4 < 255; o4++ {
				ips = append(ips, fmt.Sprintf("192.168.%d.%d", o3, o4))
			}
		}
	}
	return ips
}

// expandTargets expands hosts, CIDRs, and ranges into individual IPs
func expandTargets(targets []string) ([]string, error) {
	var ips []string
	seen := map[string]bool{}

	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		var resolved []string
		var err error

		if strings.Contains(t, "/") {
			_, ipnet, ipErr := net.ParseCIDR(t)
			if ipErr != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %v", t, ipErr)
			}
			resolved = expandCIDR(ipnet)
		} else if strings.HasPrefix(t, "http://") {
			host := strings.TrimPrefix(t, "http://")
			resolved, err = resolveHost(host)
		} else if strings.HasPrefix(t, "https://") {
			host := strings.TrimPrefix(t, "https://")
			resolved, err = resolveHost(host)
		} else if strings.Contains(t, "-") && !isHostname(t) {
			resolved, err = expandRange(t)
		} else {
			resolved, err = resolveHost(t)
		}
		if err != nil {
			return nil, err
		}
		for _, ip := range resolved {
			if !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
	}
	return ips, nil
}

func resolveHost(host string) ([]string, error) {
	host = strings.TrimSuffix(strings.TrimSpace(host), "/")
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}, nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil, fmt.Errorf("could not resolve %q: %v", host, err)
	}
	return addrs, nil
}

func expandCIDR(ipnet *net.IPNet) []string {
	var out []string
	ip := ipnet.IP.Mask(ipnet.Mask)
	ones, bits := ipnet.Mask.Size()
	if bits-ones > 22 {
		// Extremely large ranges (>/10) are almost always a mistake
		fmt.Fprintf(os.Stderr, "⚠️  Refusing to expand %s (too large).\n", ipnet.String())
		return out
	}
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		out = append(out, ip.String())
	}
	return out
}

func expandRange(spec string) ([]string, error) {
	parts := strings.SplitN(spec, "-", 2)
	lo := net.ParseIP(strings.TrimSpace(parts[0]))
	hi := net.ParseIP(strings.TrimSpace(parts[1]))
	if lo == nil || hi == nil || !strings.Contains(lo.String(), ".") {
		return nil, fmt.Errorf("invalid IP range %q", spec)
	}
	lo4 := lo.To4()
	hi4 := hi.To4()
	if lo4 == nil || hi4 == nil {
		return nil, fmt.Errorf("invalid IP range %q", spec)
	}
	start := ipToUint(lo4)
	end := ipToUint(hi4)
	if end < start || end-start > 1<<22 {
		return nil, fmt.Errorf("invalid or too large IP range %q", spec)
	}
	var out []string
	for v := start; v <= end; v++ {
		out = append(out, uintToIP(v))
	}
	return out, nil
}

func isHostname(s string) bool {
	// A hostname with a dash is not an IP range
	return strings.Contains(s, ".") || strings.ContainsAny(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

func ipToUint(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uintToIP(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", v>>24, (v>>16)&0xff, (v>>8)&0xff, v&0xff)
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}