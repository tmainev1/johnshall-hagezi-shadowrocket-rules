package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/idna"
)

const (
	srcJohnshall = "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_proxy_banad.conf"
	srcHagezi    = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/multi.txt"

	allowPath     = "allow.txt"
	extraPath     = "extra_block.txt"
	outDir        = "output"
	outDomains    = "output/domains.txt"
	outSR         = "output/shadowrocket.conf"
	cacheDir      = "cache"
	cacheOK       = "cache/ok.txt"
	cacheMetadata = "cache/metadata.json"
	dnsServerAddr = "119.29.29.29:53"

	qpsLimit      = 20              // DNS QPS limit
	resolveTO     = 2 * time.Second // Per query timeout
	fullMondayUTC = time.Monday

	// Performance tuning
	workerCount = 200  // Increased from 100 to 200 workers
	batchSize   = 1000 // Batch processing size
	maxRetries  = 3    // Maximum retries for failed requests
)

var (
	sectionHeaderRe = regexp.MustCompile(`^\s*\[(.+?)\]\s*$`)
	ipv4Re          = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}$`)

	domainLikeTypes = map[string]bool{
		"DOMAIN":        true,
		"DOMAIN-SUFFIX": true,
		"HOST":          true,
		"HOST-SUFFIX":   true,
	}

	defaultGeneral = []string{
		"[General]",
		"ipv6 = false",
		"bypass-system = true",
		"skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, fe80::/10, fc00::/7, localhost, *.local, *.lan, *.internal, e.crashlytics.com, captive.apple.com, sequoia.apple.com, seed-sequoia.siri.apple.com, *.ls.apple.com",
		"bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,233.252.0.0/24,224.0.0.0/4,255.255.255.255/32,::1/128,::ffff:0:0/96,::ffff:0:0:0/96,64:ff9b::/96,64:ff9b:1::/48,100::/64,2001::/32,2001:20::/28,2001:db8::/32,2002::/16,3fff::/20,5f00::/16,fc00::/7,fe80::/10,ff00::/8",
		"dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query",
		"",
	}

	tailRules = []string{
		"IP-CIDR,192.168.0.0/16,DIRECT",
		"IP-CIDR,10.0.0.0/8,DIRECT",
		"IP-CIDR,172.16.0.0/12,DIRECT",
		"IP-CIDR,127.0.0.0/8,DIRECT",
		"IP-CIDR,fe80::/10,DIRECT",
		"IP-CIDR,fc00::/7,DIRECT",
		"IP-CIDR,::1/128,DIRECT",
		"",
		"FINAL,proxy",
	}
)

// Performance metrics
type Metrics struct {
	StartTime        time.Time     `json:"start_time"`
	EndTime          time.Time     `json:"end_time"`
	DomainsProcessed int           `json:"domains_processed"`
	DNSQueries       int           `json:"dns_queries"`
	CacheHits        int           `json:"cache_hits"`
	NetworkRequests  int           `json:"network_requests"`
	Errors           int           `json:"errors"`
	Duration         time.Duration `json:"duration"`
}

func (m *Metrics) Save() error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cacheMetadata, data, 0644)
}

// ---------- HTTP Client with retry logic ----------

type HTTPClient struct {
	client  *http.Client
	retries int
}

func NewHTTPClient() *HTTPClient {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	return &HTTPClient{
		client:  &http.Client{Transport: tr, Timeout: 90 * time.Second},
		retries: maxRetries,
	}
}

func (h *HTTPClient) GetWithRetry(url string) (string, error) {
	var lastErr error
	for attempt := 0; attempt <= h.retries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt) * time.Second
			time.Sleep(backoff)
		}

		resp, err := h.client.Get(url)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			lastErr = fmt.Errorf("rate limited")
			continue
		}

		if resp.StatusCode/100 != 2 {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}

		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = err
			continue
		}

		s := string(bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF}))
		return s, nil
	}

	return "", fmt.Errorf("failed after %d attempts: %w", h.retries, lastErr)
}

// ---------- Utility functions ----------

func mustMkDirs() {
	_ = os.MkdirAll(outDir, 0o755)
	_ = os.MkdirAll(cacheDir, 0o755)
}

func isCommentOrBlank(line string) bool {
	t := strings.TrimSpace(line)
	return t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//")
}

func stripComments(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		if !isCommentOrBlank(ln) {
			out = append(out, ln)
		}
	}
	return out
}

func normalizeDomain(d string) (string, bool) {
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "" {
		return "", false
	}

	d = strings.Split(d, "/")[0]
	d = strings.TrimLeft(d, ".")

	if strings.Contains(d, " ") || ipv4Re.MatchString(d) {
		return "", false
	}

	d = strings.TrimLeft(d, "*.")
	if strings.Count(d, ".") == 0 {
		return "", false
	}

	puny, err := idna.ToASCII(d)
	if err != nil {
		return d, true
	}
	return strings.ToLower(puny), true
}

func readListFile(path string) (map[string]struct{}, error) {
	m := make(map[string]struct{})
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return m, nil
		}
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // 1MB max line size

	for scanner.Scan() {
		if d, ok := normalizeDomain(scanner.Text()); ok {
			m[d] = struct{}{}
		}
	}
	return m, scanner.Err()
}

func writeLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriterSize(f, 64*1024) // 64KB buffer
	defer w.Flush()

	for _, ln := range lines {
		if _, err := w.WriteString(ln + "\n"); err != nil {
			return err
		}
	}
	return nil
}

// ---------- Parallel processing with batching ----------

type BatchProcessor struct {
	workerCount int
	batchSize   int
}

func NewBatchProcessor() *BatchProcessor {
	return &BatchProcessor{
		workerCount: workerCount,
		batchSize:   batchSize,
	}
}

func (bp *BatchProcessor) Process(items []string, processFunc func([]string) error) error {
	if len(items) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	errCh := make(chan error, bp.workerCount)
	itemCh := make(chan []string, bp.workerCount)

	// Start workers
	for i := 0; i < bp.workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for batch := range itemCh {
				if err := processFunc(batch); err != nil {
					errCh <- err
					return
				}
			}
		}()
	}

	// Send batches
	go func() {
		defer close(itemCh)
		for i := 0; i < len(items); i += bp.batchSize {
			end := i + bp.batchSize
			if end > len(items) {
				end = len(items)
			}
			itemCh <- items[i:end]
		}
	}()

	wg.Wait()
	close(errCh)

	// Check for errors
	for err := range errCh {
		if err != nil {
			return err
		}
	}

	return nil
}

// ---------- Enhanced DNS checker with connection pooling ----------

type DNSChecker struct {
	resolver *net.Resolver
	tokens   chan struct{}
	cache    map[string]bool
	cacheMu  sync.RWMutex
	hits     atomic.Int64
	queries  atomic.Int64
}

func NewDNSChecker() *DNSChecker {
	dialer := &net.Dialer{
		Timeout:   resolveTO,
		KeepAlive: 30 * time.Second,
	}

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "udp", dnsServerAddr)
		},
	}

	tokens := make(chan struct{}, qpsLimit)
	go func() {
		tick := time.NewTicker(time.Second / time.Duration(qpsLimit))
		defer tick.Stop()
		for range tick.C {
			select {
			case tokens <- struct{}{}:
			default:
			}
		}
	}()

	return &DNSChecker{
		resolver: r,
		tokens:   tokens,
		cache:    make(map[string]bool),
	}
}

func (dc *DNSChecker) IsValid(ctx context.Context, domain string) bool {
	dc.cacheMu.RLock()
	if cached, ok := dc.cache[domain]; ok {
		dc.cacheMu.RUnlock()
		dc.hits.Add(1)
		return cached
	}
	dc.cacheMu.RUnlock()

	dc.queries.Add(1)

	select {
	case <-dc.tokens:
	case <-ctx.Done():
		return false
	}

	ctxTO, cancel := context.WithTimeout(ctx, resolveTO)
	defer cancel()

	result := dc.performLookup(ctxTO, domain)

	dc.cacheMu.Lock()
	dc.cache[domain] = result
	dc.cacheMu.Unlock()

	return result
}

func (dc *DNSChecker) performLookup(ctx context.Context, domain string) bool {
	// Try multiple lookup methods in parallel
	type lookupResult struct {
		success bool
		err     error
	}

	results := make(chan lookupResult, 3)

	// A record lookup
	go func() {
		addrs, err := dc.resolver.LookupHost(ctx, domain)
		results <- lookupResult{success: len(addrs) > 0, err: err}
	}()

	// AAAA record lookup
	go func() {
		ip6, err := dc.resolver.LookupIPAddr(ctx, domain)
		results <- lookupResult{success: len(ip6) > 0, err: err}
	}()

	// CNAME lookup
	go func() {
		cname, err := dc.resolver.LookupCNAME(ctx, domain)
		if err != nil {
			results <- lookupResult{success: false, err: err}
			return
		}

		cname = strings.TrimSuffix(cname, ".")
		if cname == domain {
			results <- lookupResult{success: false, err: nil}
			return
		}

		ctx2, cancel2 := context.WithTimeout(ctx, resolveTO)
		defer cancel2()

		addrs, err := dc.resolver.LookupHost(ctx2, cname)
		results <- lookupResult{success: len(addrs) > 0, err: err}
	}()

	// Wait for first successful result
	timeout := time.After(resolveTO)
	for i := 0; i < 3; i++ {
		select {
		case result := <-results:
			if result.success {
				return true
			}
		case <-timeout:
			return false
		case <-ctx.Done():
			return false
		}
	}

	return false
}

func (dc *DNSChecker) GetStats() (hits, queries int64) {
	return dc.hits.Load(), dc.queries.Load()
}

// ---------- Enhanced filtering with batch processing ----------

func filterByDNSOptimized(domains map[string]struct{}, fullRefresh bool) (map[string]struct{}, *Metrics, error) {
	all := keys(domains)
	sort.Strings(all)

	metrics := &Metrics{
		StartTime:        time.Now(),
		DomainsProcessed: len(all),
	}
	defer func() {
		metrics.EndTime = time.Now()
		metrics.Duration = metrics.EndTime.Sub(metrics.StartTime)
		metrics.Save()
	}()

	// Load cached results
	cached, _ := readListFile(cacheOK)
	if !fullRefresh {
		// Remove stale cache entries
		for k := range cached {
			if _, ok := domains[k]; !ok {
				delete(cached, k)
			}
		}
	}

	// Determine domains needing validation
	needValidation := make([]string, 0, len(all))
	if !fullRefresh {
		for _, d := range all {
			if _, ok := cached[d]; !ok {
				needValidation = append(needValidation, d)
			}
		}
	} else {
		needValidation = all
	}

	metrics.CacheHits = len(all) - len(needValidation)

	log.Printf("DNS validation: total=%d cached=%d to_validate=%d",
		len(all), len(cached), len(needValidation))

	if len(needValidation) == 0 && !fullRefresh {
		return cached, metrics, nil
	}

	// Initialize DNS checker
	dc := NewDNSChecker()
	ctx := context.Background()

	// Process domains in batches
	validated := make(map[string]struct{}, len(needValidation))
	var mu sync.Mutex

	processor := NewBatchProcessor()
	err := processor.Process(needValidation, func(batch []string) error {
		batchResults := make([]string, 0, len(batch))

		for _, domain := range batch {
			if dc.IsValid(ctx, domain) {
				batchResults = append(batchResults, domain)
			}
		}

		mu.Lock()
		for _, domain := range batchResults {
			validated[domain] = struct{}{}
		}
		mu.Unlock()

		return nil
	})

	if err != nil {
		return nil, metrics, fmt.Errorf("batch processing failed: %w", err)
	}

	// Merge results
	final := validated
	if !fullRefresh {
		final = unionSets(cached, validated)
	}

	// Save cache
	if err := writeLines(cacheOK, sortedKeys(final)); err != nil {
		return nil, metrics, fmt.Errorf("failed to write cache: %w", err)
	}

	hits, queries := dc.GetStats()
	metrics.DNSQueries = int(queries)

	log.Printf("DNS validation completed: validated=%d cache_hits=%d queries=%d",
		len(validated), hits, queries)

	return final, metrics, nil
}

// ---------- Configuration parsing ----------

type sections map[string][]string

func parseSections(text string) sections {
	ss := make(sections)
	var cur string

	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // 1MB max line size

	for scanner.Scan() {
		ln := scanner.Text()
		if m := sectionHeaderRe.FindStringSubmatch(ln); m != nil {
			cur = strings.TrimSpace(m[1])
			if _, ok := ss[cur]; !ok {
				ss[cur] = []string{}
			}
			continue
		}
		if cur == "" {
			ss["__top__"] = append(ss["__top__"], ln)
		} else {
			ss[cur] = append(ss[cur], ln)
		}
	}
	return ss
}

func extractRuleDomains(ruleLines []string) (nonDomainLines []string, domains map[string]struct{}) {
	nonDomainLines = []string{}
	domains = make(map[string]struct{})

	for _, raw := range ruleLines {
		trim := strings.TrimSpace(raw)
		parts := strings.Split(trim, ",")

		if len(parts) >= 2 {
			typ := strings.ToUpper(strings.TrimSpace(parts[0]))
			if domainLikeTypes[typ] {
				if d, ok := normalizeDomain(strings.TrimSpace(parts[1])); ok {
					domains[d] = struct{}{}
					continue
				}
			}
		}
		nonDomainLines = append(nonDomainLines, raw)
	}
	return
}

func parseHagezi(text string) map[string]struct{} {
	m := make(map[string]struct{})

	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // 1MB max line size

	for scanner.Scan() {
		ln := strings.TrimSpace(scanner.Text())
		if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, "!") {
			continue
		}
		if d, ok := normalizeDomain(ln); ok {
			m[d] = struct{}{}
		}
	}
	return m
}

// ---------- Configuration builder ----------

func buildShadowrocketConf(js sections, ruleNonDomain []string, mergedDomains []string) string {
	var out []string

	// Process top-level comments
	if top, ok := js["__top__"]; ok && len(top) > 0 {
		out = append(out, stripComments(top)...)
		if len(out) > 0 && out[len(out)-1] != "" {
			out = append(out, "")
		}
	}

	// General section
	if g, ok := js["General"]; ok && len(g) > 0 {
		out = append(out, "[General]")
		out = append(out, stripComments(g)...)
		out = append(out, "")
	} else {
		out = append(out, defaultGeneral...)
	}

	// Rule section
	out = append(out, "[Rule]")
	out = append(out, stripComments(ruleNonDomain)...)
	if len(out) == 0 || out[len(out)-1] != "" {
		out = append(out, "")
	}

	// Domain rules
	for _, d := range mergedDomains {
		out = append(out, fmt.Sprintf("DOMAIN-SUFFIX,%s,REJECT", d))
	}
	out = append(out, "")

	// Tail rules with deduplication
	seen := make(map[string]struct{})
	for _, ln := range out {
		t := strings.TrimSpace(ln)
		if t != "" {
			seen[t] = struct{}{}
		}
	}

	for _, ln := range tailRules {
		t := strings.TrimSpace(ln)
		if t == "" {
			if len(out) > 0 && out[len(out)-1] != "" {
				out = append(out, "")
			}
			continue
		}
		if _, ok := seen[t]; !ok {
			out = append(out, ln)
			seen[t] = struct{}{}
		}
	}
	out = append(out, "")

	// Other sections
	for name, lines := range js {
		if name == "__top__" || name == "General" || name == "Rule" {
			continue
		}
		out = append(out, "["+name+"]")
		out = append(out, stripComments(lines)...)
		out = append(out, "")
	}

	return strings.Join(out, "\n")
}

// ---------- Set operations ----------

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func sortedKeys(m map[string]struct{}) []string {
	kk := keys(m)
	sort.Slice(kk, func(i, j int) bool {
		if len(kk[i]) == len(kk[j]) {
			return kk[i] < kk[j]
		}
		return len(kk[i]) < len(kk[j])
	})
	return kk
}

func unionSets(a, b map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		out[k] = struct{}{}
	}
	for k := range b {
		out[k] = struct{}{}
	}
	return out
}

// ---------- Main application ----------

func main() {
	startTime := time.Now()

	// Initialize logging
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("Starting optimized build process (GOMAXPROCS=%d)", runtime.GOMAXPROCS(0))

	mustMkDirs()

	// Initialize HTTP client with retry logic
	httpClient := NewHTTPClient()

	log.Println("Fetching sources...")

	// Fetch sources concurrently
	type fetchResult struct {
		name string
		data string
		err  error
	}

	fetchCh := make(chan fetchResult, 2)

	go func() {
		data, err := httpClient.GetWithRetry(srcJohnshall)
		fetchCh <- fetchResult{name: "johnshall", data: data, err: err}
	}()

	go func() {
		data, err := httpClient.GetWithRetry(srcHagezi)
		fetchCh <- fetchResult{name: "hagezi", data: data, err: err}
	}()

	var johnText, hgText string
	for i := 0; i < 2; i++ {
		result := <-fetchCh
		if result.err != nil {
			log.Fatalf("Failed to fetch %s: %v", result.name, result.err)
		}

		switch result.name {
		case "johnshall":
			johnText = result.data
		case "hagezi":
			hgText = result.data
		}
	}

	log.Println("Parsing configurations...")

	// Parse configurations
	js := parseSections(johnText)
	ruleNonDomain, ruleDomains := extractRuleDomains(js["Rule"])
	hgDomains := parseHagezi(hgText)

	// Load allow/extra lists
	allow, _ := readListFile(allowPath)
	extra, _ := readListFile(extraPath)

	// Merge domains
	merged := make(map[string]struct{})
	for k := range ruleDomains {
		merged[k] = struct{}{}
	}
	for k := range hgDomains {
		merged[k] = struct{}{}
	}
	for k := range extra {
		merged[k] = struct{}{}
	}
	for k := range allow {
		delete(merged, k)
	}

	// Determine refresh strategy
	fullRefresh := time.Now().UTC().Weekday() == fullMondayUTC

	log.Printf("Merged domains: total=%d (johnshall=%d, hagezi=%d, extra=%d, allow=%d) full_refresh=%v",
		len(merged), len(ruleDomains), len(hgDomains), len(extra), len(allow), fullRefresh)

	// DNS validation with performance monitoring
	log.Println("Starting DNS validation...")
	okSet, metrics, err := filterByDNSOptimized(merged, fullRefresh)
	if err != nil {
		log.Fatalf("DNS validation failed: %v", err)
	}

	// Sort results
	okList := sortedKeys(okSet)

	// Write outputs
	log.Println("Writing output files...")
	if err := writeLines(outDomains, okList); err != nil {
		log.Fatalf("Failed to write domains.txt: %v", err)
	}

	// Generate configuration
	buildTime := time.Now().UTC().Format("2006-01-02 15:04:05 MST")
	header := []string{
		"# Auto-generated by cmd/merge-optimized (Go)",
		"# Sources:",
		"# - " + srcJohnshall,
		"# - " + srcHagezi,
		"# allow.txt was applied to subtract domains; extra_block.txt was added.",
		"# DNS validated via 119.29.29.29 at 20 QPS with connection pooling and batch processing",
		"# Cache in cache/ok.txt; Monday UTC full refresh",
		"# Build time (UTC): " + buildTime,
		"",
	}

	body := buildShadowrocketConf(js, ruleNonDomain, okList)
	if err := writeLines(outSR, append(header, body)); err != nil {
		log.Fatalf("Failed to write shadowrocket.conf: %v", err)
	}

	// Performance summary
	totalTime := time.Since(startTime)
	log.Printf("Build completed successfully in %v", totalTime)
	log.Printf("Results: domains=%d dns_validated=%d cache_hits=%d queries=%d",
		len(okList), len(okList), metrics.CacheHits, metrics.DNSQueries)
	log.Printf("Performance: %.2f domains/second", float64(len(okList))/totalTime.Seconds())
}

func init() {
	// Prevent compiler optimization of unused imports
	_ = base64.StdEncoding
}
