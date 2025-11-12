package main

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// DNSValidator performs DNS validation for domains
type DNSValidator struct {
	resolver     *net.Resolver
	tokens       chan struct{}
	cache        *DNSCache
	stats        *DNSStats
	maxRetries   int
	queryTimeout time.Duration
}

// DNSCache provides thread-safe caching for DNS results
type DNSCache struct {
	mu    sync.RWMutex
	cache map[string]bool
}

// NewDNSCache creates a new DNS cache
func NewDNSCache() *DNSCache {
	return &DNSCache{
		cache: make(map[string]bool),
	}
}

// DNSStats tracks DNS validation statistics
type DNSStats struct {
	TotalQueries  atomic.Int64
	CacheHits     atomic.Int64
	Successful    atomic.Int64
	Failed        atomic.Int64
	Timeouts      atomic.Int64
}

// NewDNSValidator creates a new DNS validator
func NewDNSValidator(serverAddr string, qpsLimit int) *DNSValidator {
	dialer := &net.Dialer{
		Timeout:   2 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "udp", serverAddr)
		},
	}
	
	// Token bucket for QPS limiting
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
	
	return &DNSValidator{
		resolver:     resolver,
		tokens:       tokens,
		cache:        &DNSCache{cache: make(map[string]bool)},
		stats:        &DNSStats{},
		maxRetries:   3,
		queryTimeout: 2 * time.Second,
	}
}

// Validate checks if a domain has valid DNS records
func (dv *DNSValidator) Validate(ctx context.Context, domain string) bool {
	dv.stats.TotalQueries.Add(1)
	
	// Check cache first
	if cached, found := dv.cache.Get(domain); found {
		dv.stats.CacheHits.Add(1)
		return cached
	}
	
	// Wait for rate limit token
	select {
	case <-dv.tokens:
	case <-ctx.Done():
		dv.stats.Timeouts.Add(1)
		return false
	}
	
	// Perform DNS validation with timeout
	ctxTO, cancel := context.WithTimeout(ctx, dv.queryTimeout)
	defer cancel()
	
	result := dv.performLookup(ctxTO, domain)
	
	// Cache result
	dv.cache.Set(domain, result)
	
	if result {
		dv.stats.Successful.Add(1)
	} else {
		dv.stats.Failed.Add(1)
	}
	
	return result
}

// performLookup performs actual DNS lookups
func (dv *DNSValidator) performLookup(ctx context.Context, domain string) bool {
	// Try multiple lookup methods concurrently
	type lookupResult struct {
		success bool
		err     error
	}
	
	results := make(chan lookupResult, 3)
	
	// A record lookup
	go func() {
		addrs, err := dv.resolver.LookupHost(ctx, domain)
		results <- lookupResult{success: len(addrs) > 0, err: err}
	}()
	
	// AAAA record lookup
	go func() {
		ip6, err := dv.resolver.LookupIPAddr(ctx, domain)
		results <- lookupResult{success: len(ip6) > 0, err: err}
	}()
	
	// CNAME lookup with fallback
	go func() {
		cname, err := dv.resolver.LookupCNAME(ctx, domain)
		if err != nil {
			results <- lookupResult{success: false, err: err}
			return
		}
		
		cname = trimTrailingDot(cname)
		if cname == domain {
			results <- lookupResult{success: false, err: nil}
			return
		}
		
		// Try to resolve CNAME target
		ctx2, cancel2 := context.WithTimeout(ctx, dv.queryTimeout)
		defer cancel2()
		
		addrs, err := dv.resolver.LookupHost(ctx2, cname)
		results <- lookupResult{success: len(addrs) > 0, err: err}
	}()
	
	// Wait for first successful result or timeout
	timeout := time.After(dv.queryTimeout)
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

// GetStats returns DNS validation statistics
func (dv *DNSValidator) GetStats() DNSStatsReport {
	return DNSStatsReport{
		TotalQueries: dv.stats.TotalQueries.Load(),
		CacheHits:    dv.stats.CacheHits.Load(),
		Successful:   dv.stats.Successful.Load(),
		Failed:       dv.stats.Failed.Load(),
		Timeouts:     dv.stats.Timeouts.Load(),
		CacheSize:    dv.cache.Size(),
	}
}

// DNSStatsReport provides a snapshot of DNS statistics
type DNSStatsReport struct {
	TotalQueries int64 `json:"total_queries"`
	CacheHits    int64 `json:"cache_hits"`
	Successful   int64 `json:"successful"`
	Failed       int64 `json:"failed"`
	Timeouts     int64 `json:"timeouts"`
	CacheSize    int   `json:"cache_size"`
}

// Cache methods
func (c *DNSCache) Get(domain string) (bool, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result, exists := c.cache[domain]
	return result, exists
}

func (c *DNSCache) Set(domain string, result bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[domain] = result
}

func (c *DNSCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

func (c *DNSCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]bool)
}

// BatchDNSValidator performs batch DNS validation
type BatchDNSValidator struct {
	validator *DNSValidator
	workers   int
	batchSize int
}

// NewBatchDNSValidator creates a new batch DNS validator
func NewBatchDNSValidator(serverAddr string, qpsLimit int, workers int) *BatchDNSValidator {
	if workers <= 0 {
		workers = runtime.NumCPU() * 2
	}
	
	return &BatchDNSValidator{
		validator: NewDNSValidator(serverAddr, qpsLimit/workers),
		workers:   workers,
		batchSize: 1000,
	}
}

// ValidateBatch validates a batch of domains
func (bdv *BatchDNSValidator) ValidateBatch(ctx context.Context, domains []string) (map[string]bool, error) {
	if len(domains) == 0 {
		return make(map[string]bool), nil
	}
	
	results := make(map[string]bool)
	var mu sync.Mutex
	
	// Create work channels
	domainCh := make(chan string, len(domains))
	resultCh := make(chan struct {
		domain string
		valid  bool
	}, len(domains))
	
	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < bdv.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range domainCh {
				if ctx.Err() != nil {
					return
				}
				valid := bdv.validator.Validate(ctx, domain)
				resultCh <- struct {
					domain string
					valid  bool
				}{domain: domain, valid: valid}
			}
		}()
	}
	
	// Send work
	go func() {
		defer close(domainCh)
		for _, domain := range domains {
			select {
			case domainCh <- domain:
			case <-ctx.Done():
				return
			}
		}
	}()
	
	// Close result channel when all workers are done
	go func() {
		wg.Wait()
		close(resultCh)
	}()
	
	// Collect results
	for result := range resultCh {
		mu.Lock()
		results[result.domain] = result.valid
		mu.Unlock()
	}
	
	return results, ctx.Err()
}

// GetStats returns batch validation statistics
func (bdv *BatchDNSValidator) GetStats() DNSStatsReport {
	return bdv.validator.GetStats()
}

// Helper function
func trimTrailingDot(s string) string {
	return strings.TrimSuffix(s, ".")
}