package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

// commonServiceNames maps ports to well-known services for context in results
var commonServiceNames = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 81: "alt-http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
	143: "imap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
	587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s", 1080: "socks",
	1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker", 2376: "docker-tls",
	2379: "etcd", 3000: "grafana", 3306: "mysql", 3389: "rdp", 5000: "harbor/flask",
	5001: "web", 5432: "postgres", 5601: "kibana", 5900: "vnc", 5985: "winrm",
	5986: "winrm-https", 6379: "redis", 6443: "k8s-api", 7001: "weblogic",
	8000: "alt-http", 8001: "web", 8080: "alt-http", 8081: "web", 8088: "web",
	8181: "web", 8443: "alt-https", 8880: "alt-http", 8888: "web",
	9000: "php-fpm/payara", 9090: "prometheus", 9200: "elasticsearch",
	9443: "alt-https", 10000: "webmin", 11211: "memcached", 15672: "rabbitmq",
	27017: "mongod", 28017: "mongod-web", 49152: "web", 50000: "web",
}

func serviceName(port int) string {
	return commonServiceNames[port]
}

// jsonResult is one line of the optional JSONL export file
type jsonResult struct {
	IP         string   `json:"ip"`
	Port       int      `json:"port"`
	URL        string   `json:"url,omitempty"`
	Scheme     string   `json:"scheme,omitempty"`
	StatusCode int      `json:"status_code,omitempty"`
	Server     string   `json:"server,omitempty"`
	Title      string   `json:"title,omitempty"`
	Service    string   `json:"service,omitempty"`
	Juice      int      `json:"juice,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	PathHits   string   `json:"path_hits,omitempty"`
	Timestamp  string   `json:"timestamp"`
}

// pathCheck is one juicy path probed on confirmed web servers
type pathCheck struct {
	Path   string
	Admin  bool   // 401/403/302 also count as "exists"
	Secret bool   // anything but 200 is ignored (solid find only)
	Name   string // tag label
	Weight int    // juice points on a 200
}

// juicyPaths is the default set of paths probed on each confirmed web server
var juicyPaths = []pathCheck{
	{"/admin", true, false, "admin", 25},
	{"/admin/login", true, false, "admin-login", 25},
	{"/login", true, false, "login", 22},
	{"/login.php", true, false, "login", 22},
	{"/wp-admin/", true, false, "wp-admin", 22},
	{"/wp-admin/login.php", true, false, "wp-admin", 22},
	{"/phpmyadmin/", true, false, "phpmyadmin", 25},
	{"/phpmyadmin", true, false, "phpmyadmin", 22},
	{"/db/", true, false, "db-admin", 20},
	{"/upload/", true, false, "upload", 12},
	{"/config.php", false, true, "config", 40},
	{"/.env", false, true, ".env", 55},
	{"/.git/HEAD", false, true, ".git", 45},
	{"/.htaccess", false, true, ".htaccess", 20},
	{"/phpinfo.php", false, true, "phpinfo", 40},
	{"/backup/", false, true, "backup", 15},
	{"/robots.txt", false, true, "robots", 5},
}

// devPorts marks ports that are themselves interesting (dev/alt/admin panels/cameras)
var devPorts = map[int]string{
	81: "alt-http", 82: "alt-http", 83: "alt-http", 84: "alt-http", 85: "alt-http",
	88: "alt-http", 89: "alt-http", 800: "alt-http", 8000: "alt-http",
	8001: "alt-http", 8081: "alt-http", 8082: "alt-http", 8085: "alt-http",
	8086: "alt-http", 8087: "alt-http", 8088: "alt-http", 8089: "alt-http",
	8090: "alt-http", 8181: "alt-http", 8899: "alt-http", 9999: "alt-http",
	7001: "weblogic", 9000: "app-server", 9443: "alt-https", 10000: "webmin",
	5000: "dev-app", 5001: "dev-app", 3000: "dev-app", 5601: "kibana",
	9090: "metrics", 9200: "elasticsearch", 2375: "docker", 2376: "docker-tls",
	15672: "rabbitmq", 28017: "mongo-web", 27017: "mongo", 1433: "mssql", 5900: "vnc",
	554: "rtsp/camera", 7547: "tr-069(cwmp)", 34567: "hikv-rtsp/cam", 37200: "xiaomi-web",
	37777: "dahua-admin", 49152: "camera-web",
}

// Keyword sets used by the juice scorer
var iotSignals = []string{"dahua", "hikv", "tenda", "tp-link", "tplink", "netgear", "linksys", "zyxel", "mikrotik", "axis", "webcam", "ipcam", "camera", "dvr", "nvr", "iptv", "qnap", "synology", "bosch", "reolink", "amcrest", "foscam", "router", "wemo", "wifi-"}
var techSignals = []string{"wordpress", "laravel", "django", "spring", "tomcat", "jboss", "wildfly", "jenkins", "grafana", "kibana", "prometheus", "zabbix", "nagios", "netdata", "phpmyadmin", "nextcloud", "owncloud", "roundcube", "webmin", "hadoop", "harbor", "portainer", "minio", "sonarqube", "dokuwiki", "opencart", "moodle", "joomla", "drupal", "asp.net", "iis", "openresty", "caddy", "next.js", "nutanix", "sophos", "fortinet", "pfsense", "sabnzbd", "transmission", "radarr", "sonarr", "plex"}
var loginSignals = []string{"login", "sign in", "sign-in", "signin", "log in", "authentication", "access panel", "control panel", "web portal", "console", "admin panel", "管理", "登录", "控制台"}
var juicyRobotsDisallows = []string{"admin", "config", "backup", ".env", ".git", "sql", "db", "tmp", "login", "upload", "bak", "wp-", "cgi-bin", "debug", "app"}

// Default web ports to scan when no -ports is given
var defaultWebPorts = []int{80, 81, 82, 83, 84, 85, 88, 89, 443, 554, 800, 8000, 8001, 8080, 8081, 8082, 8085, 8086, 8087, 8088, 8089, 8090, 8181, 8443, 8880, 8888, 9000, 9443, 9999, 10000, 28017, 5000, 5001, 7547, 34567, 37200, 37777, 49152}

// Result holds one discovered open web port
type Result struct {
	Target     string
	Port       int
	Scheme     string // http or https when probing succeeds
	StatusCode int
	Server     string
	Title      string
	PoweredBy  string   // X-Powered-By / X-Generator header
	Score      int      // 0-100 juice ranking
	Tags       []string // interesting-finding tags
	PathHits   string   // compact list of juicy path hits e.g. /admin(200)
	RootOK     bool     // root probe answered real HTTP
	RealHits   int      // number of juicy paths that returned 200
	Protected  bool     // only protected (403/401/302) hits, no real content
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
	ports           []int
	timeout         time.Duration
	workers         int
	probe           bool
	skipCloud       bool
	forceProbe      bool
juice          bool
	minScore       int
	keepProtected  bool
	customPaths    []string
	statusMatch     func(int) bool
	client          *http.Client
	ctx             context.Context
	file            *os.File
	fileMu          sync.Mutex
	results         chan Result
	cancel          chan struct{}
	scanMu          sync.Mutex
	scanned         int64
	open            int64
	filtered        int64
	lastTick        time.Time
	progressInterval time.Duration
}

// parsePathsFlag parses the -paths extra-paths flag into absolute paths
func parsePathsFlag(s string) []string {
	var paths []string
	for _, p := range strings.Split(s, ",") {
		p = strings.Trim(strings.TrimSpace(p), "/")
		if p == "" {
			continue
		}
		paths = append(paths, "/"+p)
	}
	return paths
}

func main() {
	var (
		portsFlag   = flag.String("ports", "", "web ports to scan, comma-separated (default includes web UIs + IoT/camera ports: 80,81-85,88,89,443,554,800,8000-8001,8080-8089,8090,8181,8443,8880,8888,9000,9443,9999,10000,28017,5000,5001,7547,34567,37200,37777,49152)")
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
		seedF       = flag.Int64("seed", 0, "RNG seed for reproducible random IPs (0 = random seed)")
		skipF       = flag.Int("skip", 0, "skip the first N generated random IPs (resume support)")
		mcF         = flag.String("mc", "", "only report/stream ports whose probed status code is in this list (e.g. 200,301,302)")
		xmcF        = flag.String("xmc", "403", "exclude ports whose probed status code is in this list (e.g. 403,404); empty = keep all")
		jsonF       = flag.String("json", "", "also write results as JSONL to this file")
		juiceF      = flag.Bool("juice", true, "probe discovered web servers for juicy findings (admin panels, secrets, IoT devices, dir listings) and rank 0-100")
		minScoreF   = flag.Int("min-score", 0, "only report/stream hosts with juice score >= this value (0 = all)")
		pathsF      = flag.String("paths", "", "extra paths to probe (comma-separated) in addition to the default juicy paths")
		topJuicyF   = flag.Int("top", 15, "how many top juicy hosts to print in the final summary")
		openF       = flag.Int("open", 0, "auto-open juicy targets in a running browser IMMEDIATELY as they are found (max tabs; 0 = off)")
		openScoreF  = flag.Int("open-score", 30, "minimum juice score for a host to be auto-opened in the browser")
		keepProtF   = flag.Bool("keep-protected", false, "keep hosts whose ONLY signal is 403/401/302 protected hits (default: drop them as noise)")
		browserF    = flag.String("browser", "", "browser executable to open targets with (default: auto-detect a running browser: brave, chrome, chromium, edge, firefox...)")
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

	// Status-code match list
	var matchCodes []int
	matched := false
	if *mcF != "" {
		for _, c := range strings.Split(*mcF, ",") {
			code, err := strconv.Atoi(strings.TrimSpace(c))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error in -mc: invalid status code %q\n", c)
				os.Exit(1)
			}
			matchCodes = append(matchCodes, code)
		}
		matched = true
	}
	if len(matchCodes) == 0 {
		matched = false
	}
	// Excluded status codes (default: 403)
	excludeCodes := map[int]bool{}
	if *xmcF != "" {
		for _, c := range strings.Split(*xmcF, ",") {
			code, err := strconv.Atoi(strings.TrimSpace(c))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error in -xmc: invalid status code %q\n", c)
				os.Exit(1)
			}
			excludeCodes[code] = true
		}
	}

	statusMatch := func(code int) bool {
		if !matched {
			return true
		}
		for _, c := range matchCodes {
			if c == code {
				return true
			}
		}
		return false
	}

	// Deterministic seed for reproducible/resumable random scans
	seed := *seedF
	if seed == 0 {
		seed = time.Now().UnixNano()
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
			ips = generateLocalIPs(randomCount, seed)
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
		ips = generateRandomIPs(randomCount, seed)
	}
	// Resume support: drop the first N generated IPs
	if *skipF > 0 {
		if *skipF >= len(ips) {
			fmt.Fprintf(os.Stderr, "Error: -skip %d is >= number of targets (%d). Nothing left to scan.\n", *skipF, len(ips))
			os.Exit(1)
		}
		ips = ips[*skipF:]
	}
	if len(ips) == 0 {
		fmt.Fprintln(os.Stderr, "No targets to scan.")
		os.Exit(1)
	}
	fmt.Printf("%s\n", cyan(fmt.Sprintf("🎲 seed=%d targets=%d (resume with: -seed %d -skip %d)", seed, len(ips)+*skipF, seed, *skipF)))

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
		juice:            *juiceF,
		minScore:         *minScoreF,
		keepProtected:    *keepProtF,
		customPaths:      parsePathsFlag(*pathsF),
		statusMatch:      statusMatch,
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
	scanCtx, cancelScanCtx := context.WithCancel(context.Background())
	s.ctx = scanCtx
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
	var filtered int64
	var topMu sync.Mutex
	var topAll []Result

	// Optional JSONL export
	var jf *os.File
	if *jsonF != "" {
		jf, err = os.Create(*jsonF)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not create JSONL file: %v\n", err)
			jf = nil
		}
	}

	// Browser auto-open: detect the running browser once, stream-open as found
	var openBin string
	openLeft := *openF
	if openLeft > 0 {
		openBin = *browserF
		if openBin == "" {
			openBin = runningBrowser()
		}
		if openBin == "" {
			fmt.Printf("%s\n", yellow("No running browser detected (brave/chrome/chromium/edge/firefox) - start one, or set -browser <exe>."))
		} else {
			fmt.Printf("%s\n", cyan(fmt.Sprintf("🌐 Auto-opening juicy targets (J >= %d, max %d tabs) in %s as they are found...", *openScoreF, openLeft, openBin)))
		}
	}

	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for r := range s.results {
			if s.skipCloud && matchesCloud(r) {
				skipped++
				fmt.Printf("%s %s:%d server=%q\n", yellow("⛔ [SKIP cloud]"), r.Target, r.Port, r.Server)
				continue
			}
			// -mc status filter
			if !statusMatch(r.StatusCode) {
				filtered++
				continue
			}
			// -xmc excluded status filter (default 403)
			if excludeCodes[r.StatusCode] {
				filtered++
				continue
			}
			// Protected shells: no real content, every signal was 403/401/302
			if r.Protected && !s.keepProtected {
				filtered++
				continue
			}
			// -min-score juice floor
			if s.minScore > 0 && r.Score < s.minScore {
				filtered++
				continue
			}
			line := r.String()
			colored := strings.Replace(line, "[OPEN]", green("[OPEN]"), 1)
			if r.Score > 0 {
				colored = strings.Replace(colored, "🔸", bold(yellow("🔸")), 1)
			}
			fmt.Println(colored)
			if s.file != nil {
				s.fileMu.Lock()
				s.file.WriteString(line + "\n")
				s.file.Sync()
				s.fileMu.Unlock()
			}
			if jf != nil {
				rec := jsonResult{
					IP: r.Target, Port: r.Port, URL: r.URLs()[0], Scheme: r.Scheme,
					StatusCode: r.StatusCode, Server: r.Server, Title: r.Title,
					Service: serviceName(r.Port), Juice: r.Score, Tags: r.Tags,
					PathHits: r.PathHits, Timestamp: time.Now().UTC().Format(time.RFC3339),
				}
				if b, err := json.Marshal(rec); err == nil {
					jf.Write(append(b, '\n'))
				}
			}
			// Immediate browser open for juicy hosts
			if openBin != "" && openLeft > 0 && r.Score >= *openScoreF {
				u := r.URLs()[0]
				if r.Scheme == "" && len(r.URLs()) > 1 {
					u = r.URLs()[1]
				}
				if openInBrowser(openBin, u) {
					openLeft--
					fmt.Printf("%s\n", cyan(fmt.Sprintf("🌐 Opened J%d %s (%s)", r.Score, u, openBin)))
				} else if lastOpenErr != "" {
					fmt.Printf("%s\n", yellow(fmt.Sprintf("⚠️  Could not open %s: %s", u, lastOpenErr)))
				}
			}
			if r.Score > 0 {
				topMu.Lock()
				topAll = append(topAll, r)
				topMu.Unlock()
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

	// Graceful Ctrl-C / SIGTERM: stop cleanly, keep results, print resume hint
	stopOnce := sync.Once{}
	stop := func() { stopOnce.Do(func() { close(s.cancel) }) }
	sigCh := make(chan os.Signal, 1)
	interruptCh := make(chan struct{})
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		close(interruptCh)
		fmt.Printf("\n%s\n", yellow("🛑 Interrupt received - stopping scan and saving results..."))
		cancelScanCtx()
		stop()
	}()

	// Kick off scanning
	var scanWg sync.WaitGroup
	jobCh := make(chan scanJob, s.workers)
	for i := 0; i < s.workers; i++ {
		scanWg.Add(1)
		go s.worker(jobCh, &scanWg)
	}
	var dispatched int
scanLoop:
	for i, ip := range ips {
		for _, p := range s.ports {
			select {
			case jobCh <- scanJob{ip: ip, port: p}:
			case <-s.cancel:
				break scanLoop
			}
		}
		dispatched = i + 1
	}
	close(jobCh)
	scanWg.Wait()

	s.progressOnce()
	stop()
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
		footer := fmt.Sprintf("\n%s\nScan finished at: %s\nIPs scanned: %d\nOpen web ports found: %d\nCloud/CDN ports skipped: %d\nFiltered (mc/min-score): %d\n",
			strings.Repeat("=", 60), time.Now().Format("2006-01-02 15:04:05"), len(ips), s.open, skipped, filtered)
		s.file.WriteString(footer)
		s.file.Close()
	}
	if jf != nil {
		jf.Sync()
		jf.Close()
	}
	fmt.Printf("\n%s\n", green(fmt.Sprintf("✅ Scan complete! %d open web ports found across %d IPs (%d skipped as cloud/CDN, %d filtered). Results in %s", s.open, len(ips), skipped, filtered, outPath)))
	interrupted := false
	select {
	case <-interruptCh:
		interrupted = true
	default:
	}
	resumeSkip := *skipF + dispatched
	if interrupted {
		fmt.Printf("%s\n", yellow(fmt.Sprintf("⚠️  Scan interrupted after ~%d of %d IPs", dispatched, len(ips)+*skipF)))
	}
	fmt.Printf("%s\n", cyan(fmt.Sprintf("💾 Resume anytime with: -seed %d -skip %d", seed, resumeSkip)))

	// Top juicy targets
	if len(topAll) > 0 {
		sort.Slice(topAll, func(i, j int) bool { return topAll[i].Score > topAll[j].Score })
		n := *topJuicyF
		if n > len(topAll) {
			n = len(topAll)
		}
		fmt.Printf("\n%s\n", bold(yellow(fmt.Sprintf("🏆 Top %d juicy targets:", n))))
		for i, r := range topAll[:n] {
			u := r.URLs()[0]
			if r.Scheme == "" && len(r.URLs()) > 1 {
				u = r.URLs()[1]
			}
			fmt.Printf("  %d. J%02d  %s  %s\n", i+1, r.Score, u, strings.Join(r.Tags, ","))
		}
		fmt.Println()
	}

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
		// Abort early on interrupt: skip queued-but-unstarted jobs
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		if s.scanPort(j.ip, j.port) {
			s.scanMu.Lock()
			s.open++
			s.scanMu.Unlock()
			found := Result{Target: j.ip, Port: j.port}
			// Probe banner when requested, or when cloud filtering / juice needs headers
			if s.probe || s.skipCloud || s.juice {
				found = s.probeBanner(j.ip, j.port)
				if s.juice && found.Scheme != "" {
					s.assessJuice(&found)
				}
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
	select {
	case <-s.ctx.Done():
		return false
	default:
	}
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
	req, _ := http.NewRequestWithContext(s.ctx, http.MethodGet, url, nil)
	resp, err := s.client.Do(req)
	if err != nil {
		// Some servers only speak the other scheme; the raw port is still open
		r.Scheme = scheme
		return r
	}
	defer resp.Body.Close()
	r.RootOK = true

	r.Scheme = scheme
	r.StatusCode = resp.StatusCode
	r.Server = resp.Header.Get("Server")
	r.PoweredBy = resp.Header.Get("X-Powered-By")
	if r.PoweredBy == "" {
		r.PoweredBy = resp.Header.Get("X-Generator")
	}

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

// assessJuice ranks a probed host 0-100 based on juicy signals:
// panels/secrets found, IoT fingerprints, version disclosure, dir listings.
// Path probing only runs on hosts that actually answered HTTP(S).
func (s *scanner) assessJuice(r *Result) {
	low := strings.ToLower(r.Title + " " + r.Server + " " + r.PoweredBy)
	var tags []string
	score := 0
	add := func(n int, tag string) {
		score += n
		if tag != "" {
			tags = append(tags, tag)
		}
	}

	// Port itself is interesting (dev ports, admin panels, exposed services)
	if svc, ok := devPorts[r.Port]; ok {
		add(10, "dev-port:"+svc)
	}

	// Version disclosure in Server header
	if hasVersion(r.Server) {
		add(8, "version")
	}

	// X-Powered-By / X-Generator
	if r.PoweredBy != "" {
		add(5, "powered-by")
	}

	// Recognizable tech stack
	if t := firstMatch(low, techSignals); t != "" {
		add(8, t)
	}

	// IoT / camera / router fingerprint -> high value
	if t := firstMatch(low, iotSignals); t != "" {
		add(15, "iot:"+t)
	}

	// Login / admin wording on the front page
	if firstMatch(low, loginSignals) != "" {
		add(8, "login")
	}

	// Directory listing
	if strings.Contains(low, "index of") {
		add(18, "dirlisting")
	}

	// Path probing - only when we actually talked HTTP(S)
	realHits := 0
	if r.Scheme != "" {
		s.probeJuicyPaths(r, &score, &tags, &add, &realHits)
	}
	r.RealHits = realHits

	// Dedupe tags, cap at 100
	seen := make(map[string]bool)
	clean := tags[:0]
	for _, t := range tags {
		if !seen[t] {
			seen[t] = true
			clean = append(clean, t)
		}
	}
	tags = clean
	// Protected shell: nothing answered with real content, every hit was 403/401/302
	r.Protected = !r.RootOK && realHits == 0 && r.PathHits != ""
	if score > 100 {
		score = 100
	}
	r.Score = score
	r.Tags = tags
}

// probeJuicyPaths issues lightweight GETs against juicy paths
func (s *scanner) probeJuicyPaths(r *Result, score *int, tags *[]string, add *func(int, string), realHits *int) {
	base := fmt.Sprintf("%s://%s", r.Scheme, net.JoinHostPort(r.Target, strconv.Itoa(r.Port)))
	paths := juicyPaths
	for _, p := range s.customPaths {
		paths = append(paths, pathCheck{Path: p, Name: p, Weight: 8})
	}
	hits := ""
	for _, pc := range paths {
		status, body := s.pathStatus(base + pc.Path)
		if status == 0 {
			continue
		}
		// robots.txt: count disallowed paths
		if pc.Path == "/robots.txt" && status == 200 {
			n, hasJuicy := juicyRobots(body)
			if n > 0 {
				(*add)(minInt(n*3, 12), fmt.Sprintf("robots(%d)", n))
			} else if hasJuicy {
				(*add)(10, "robots")
			}
			continue
		}
		hit := false
		switch {
		case status == 200: // hard hit
			(*add)(pc.Weight, pc.Name)
			(*realHits)++
			hit = true
		case pc.Admin && !pc.Secret && (status == 401 || status == 403 || status == 302):
			(*add)(maxInt(pc.Weight-8, 5), pc.Name+":protected")
			hit = true
		}
		if hit {
			if hits != "" {
				hits += ","
			}
			hits += fmt.Sprintf("%s(%d)", pc.Path, status)
		}
	}
	if hits != "" {
		r.PathHits = hits
	}
}

// pathStatus GETs a path and returns (status, body-snippet). 0 means no HTTP response.
func (s *scanner) pathStatus(url string) (int, string) {
	req, _ := http.NewRequestWithContext(s.ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36")
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	return resp.StatusCode, string(body)
}

// juicyRobots parses a robots.txt body for Disallow entries; returns count and
// whether any entry looks interesting (admin/config/secret-ish).
func juicyRobots(body string) (int, bool) {
	count := 0
	anyInteresting := false
	for _, line := range strings.Split(body, "\n") {
		l := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(l, "disallow:") {
			count++
			for _, kw := range juicyRobotsDisallows {
				if strings.Contains(l, kw) {
					anyInteresting = true
					break
				}
			}
		}
	}
	return count, anyInteresting
}

// hasVersion reports whether s looks like a versioned server banner
func hasVersion(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i+1 < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' && s[i+1] == '.' {
			return true
		}
	}
	return false
}

// firstMatch returns the first needle found in hay, else ""
func firstMatch(hay string, needles []string) string {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return n
		}
	}
	return ""
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
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
	if r.Score > 0 {
		juiceStr := fmt.Sprintf("J%d", r.Score)
		if len(r.Tags) > 0 {
			juiceStr += ":" + strings.Join(r.Tags, ",")
		}
		parts = append(parts, fmt.Sprintf("🔸%s", juiceStr))
		if r.PathHits != "" {
			parts = append(parts, "paths="+r.PathHits)
		}
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
		case <-s.ctx.Done():
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

// browserExecs are preferred browsers in order (auto-detection)
var browserExecs = []string{
	"brave", "brave-browser", "google-chrome", "google-chrome-stable", "chromium",
	"chromium-browser", "microsoft-edge", "vivaldi", "opera", "zen-browser", "firefox",
}

// runningBrowser returns the executable of a browser that is currently running.
// Launching the same binary with a URL reuses the already-running window (and its
// flags, e.g. --ignore-certificate-errors) instead of starting a new instance.
func runningBrowser() string {
	out, err := exec.Command("ps", "-e", "-o", "comm=").Output()
	if err != nil {
		return ""
	}
	running := map[string]bool{}
	for _, name := range strings.Fields(string(out)) {
		running[name] = true
	}
	for _, name := range browserExecs {
		if running[name] {
			if p, err := exec.LookPath(name); err == nil {
				return p
			}
		}
	}
	return ""
}

var lastOpenErr string

// openInBrowser opens url in the given browser. For chrome-family browsers the
// launcher hands the URL to the running instance; xdg-open is a fallback.
func openInBrowser(bin, url string) bool {
	var args []string
	if strings.Contains(bin, "firefox") || strings.Contains(bin, "zen-browser") {
		args = []string{"--new-tab", url}
	} else {
		args = []string{url}
	}
	cmd := exec.Command(bin, args...)
	cmd.Stderr = nil
	cmd.Stdout = nil
	if err := cmd.Start(); err != nil {
		lastOpenErr = err.Error()
		return false
	}
	go cmd.Wait()
	return true
}

// generateRandomIPs returns count random internet-block IPs from a seeded RNG.
// With the same seed the sequence is identical, enabling -skip resume.
func generateRandomIPs(count int, seed int64) []string {
	rng := rand.New(rand.NewSource(seed))
	ips := make([]string, count)
	for i := 0; i < count; i++ {
		ips[i] = generateRandomIP(rng)
	}
	return ips
}

// generateRandomIP creates a random IP from the network blocks using the given RNG
func generateRandomIP(rng *rand.Rand) string {
	block := networkBlocks[rng.Intn(len(networkBlocks))]
	octet2 := rng.Intn(256)
	octet3 := rng.Intn(256)
	octet4 := rng.Intn(254) + 1 // 1-254, avoiding 0
	return fmt.Sprintf("%d.%d.%d.%d", block, octet2, octet3, octet4)
}

// generateLocalIP creates a random IP from the enabled local class ranges
func generateLocalIP(rng *rand.Rand) string {
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
	switch classes[rng.Intn(len(classes))] {
	case 1:
		return fmt.Sprintf("10.%d.%d.%d", rng.Intn(256), rng.Intn(256), rng.Intn(254)+1)
	case 2:
		return fmt.Sprintf("172.%d.%d.%d", 16+rng.Intn(16), rng.Intn(256), rng.Intn(254)+1)
	default:
		return fmt.Sprintf("192.168.%d.%d", rng.Intn(256), rng.Intn(254)+1)
	}
}

// generateLocalIPs returns count random IPs from the enabled class ranges (seeded)
func generateLocalIPs(count int, seed int64) []string {
	rng := rand.New(rand.NewSource(seed))
	ips := make([]string, count)
	for i := 0; i < count; i++ {
		ips[i] = generateLocalIP(rng)
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