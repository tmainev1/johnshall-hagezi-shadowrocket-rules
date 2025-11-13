package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// BuildMetrics tracks build performance metrics
type BuildMetrics struct {
	StartTime          time.Time              `json:"start_time"`
	EndTime            time.Time              `json:"end_time"`
	Duration           time.Duration          `json:"duration"`
	
	// Source statistics
	JohnshallDomains   int                    `json:"johnshall_domains"`
	HageziDomains      int                    `json:"hagezi_domains"`
	AllowDomains       int                    `json:"allow_domains"`
	ExtraDomains       int                    `json:"extra_domains"`
	
	// Processing statistics
	TotalDomains       int                    `json:"total_domains"`
	ValidatedDomains   int                    `json:"validated_domains"`
	CacheHits          int                    `json:"cache_hits"`
	DNSQueries         int                    `json:"dns_queries"`
	
	// Performance metrics
	DomainsPerSecond   float64                `json:"domains_per_second"`
	MemoryUsage        uint64                 `json:"memory_usage_mb"`
	
	// Error tracking
	Errors             []string               `json:"errors"`
}

// BuildOrchestrator orchestrates the entire build process
type BuildOrchestrator struct {
	config        *BuildConfig
	metrics       *BuildMetrics
	httpClient    *HTTPClient
	domainProc    *DomainProcessor
	domainReader  *DomainListReader
	dnsValidator  *BatchDNSValidator
	configParser  *ConfigurationParser
	configBuilder *ConfigurationBuilder
	
	cache         *BuildCache
	logger        *log.Logger
}

// BuildConfig contains build configuration
type BuildConfig struct {
	JohnshallURL  string
	HageziURL     string
	AllowFile     string
	ExtraFile     string
	OutputDir     string
	CacheDir      string
	DNSQPSLimit   int
	Workers       int
	FullRefresh   bool
}

// BuildCache manages build caching
type BuildCache struct {
	mu       sync.RWMutex
	cacheDir string
	data     map[string]interface{}
}

// NewBuildOrchestrator creates a new build orchestrator
func NewBuildOrchestrator(config *BuildConfig) *BuildOrchestrator {
	return &BuildOrchestrator{
		config:        config,
		metrics:       &BuildMetrics{StartTime: time.Now(), Errors: []string{}},
		httpClient:    NewHTTPClient(),
		domainProc:    NewDomainProcessor(),
		domainReader:  NewDomainListReader(NewDomainProcessor()),
		dnsValidator:  NewBatchDNSValidator("119.29.29.29:53", config.DNSQPSLimit, config.Workers),
		configParser:  NewConfigurationParser(),
		configBuilder: NewConfigurationBuilder(),
		cache:         &BuildCache{cacheDir: config.CacheDir, data: make(map[string]interface{})},
		logger:        log.New(os.Stdout, "[BUILD] ", log.LstdFlags),
	}
}

// Execute runs the complete build process
func (bo *BuildOrchestrator) Execute(ctx context.Context) error {
	bo.logger.Printf("Starting build process with %d workers", bo.config.Workers)
	
	// Step 1: Fetch source data
	bo.logger.Println("Step 1: Fetching source data...")
	if err := bo.fetchSources(ctx); err != nil {
		return bo.recordError("failed to fetch sources: %w", err)
	}
	
	// Step 2: Parse configurations
	bo.logger.Println("Step 2: Parsing configurations...")
	if err := bo.parseConfigurations(ctx); err != nil {
		return bo.recordError("failed to parse configurations: %w", err)
	}
	
	// Step 3: Process domains
	bo.logger.Println("Step 3: Processing domains...")
	if err := bo.processDomains(ctx); err != nil {
		return bo.recordError("failed to process domains: %w", err)
	}
	
	// Step 4: Validate domains
	bo.logger.Println("Step 4: Validating domains...")
	if err := bo.validateDomains(ctx); err != nil {
		return bo.recordError("failed to validate domains: %w", err)
	}
	
	// Step 5: Generate output
	bo.logger.Println("Step 5: Generating output...")
	if err := bo.generateOutput(ctx); err != nil {
		return bo.recordError("failed to generate output: %w", err)
	}
	
	// Finalize metrics
	bo.finalizeMetrics()
	
	// Save cache
	if err := bo.saveCache(); err != nil {
		bo.logger.Printf("Warning: failed to save cache: %v", err)
	}
	
	bo.logger.Printf("Build completed successfully in %v", bo.metrics.Duration)
	bo.logger.Printf("Results: %d domains validated, %d cache hits, %.2f domains/second",
		bo.metrics.ValidatedDomains, bo.metrics.CacheHits, bo.metrics.DomainsPerSecond)
	
	return nil
}

func (bo *BuildOrchestrator) fetchSources(ctx context.Context) error {
	// Fetch sources concurrently
	type fetchTask struct {
		name string
		url  string
	}
	
	tasks := []fetchTask{
		{name: "johnshall", url: bo.config.JohnshallURL},
		{name: "hagezi", url: bo.config.HageziURL},
	}
	
	results := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	for _, task := range tasks {
		wg.Add(1)
		go func(t fetchTask) {
			defer wg.Done()
			
			bo.logger.Printf("Fetching %s from %s", t.name, t.url)
			data, err := bo.httpClient.GetWithRetry(t.url)
			if err != nil {
				bo.recordError("failed to fetch "+t.name+": %w", err)
				bo.logger.Printf("Error fetching %s: %v", t.name, err)
				return
			}
			
			mu.Lock()
			results[t.name] = data
			mu.Unlock()
			
			bo.logger.Printf("Fetched %s: %d bytes", t.name, len(data))
		}(task)
	}
	
	wg.Wait()
	
	// Store results in cache
	bo.cache.Set("sources", results)
	return nil
}

func (bo *BuildOrchestrator) parseConfigurations(ctx context.Context) error {
	sourcesVal := bo.cache.Get("sources")
	if sourcesVal == nil {
		return fmt.Errorf("sources not found in cache")
	}
	sources, ok := sourcesVal.(map[string]string)
	if !ok {
		return fmt.Errorf("invalid sources type in cache")
	}
	
	// Parse Johnshall configuration
	johnshallConfig, err := bo.configParser.Parse(sources["johnshall"])
	if err != nil {
		return fmt.Errorf("failed to parse johnshall config: %w", err)
	}
	
	// Parse Hagezi domains
	hageziSet, err := bo.domainReader.ReadFromString(sources["hagezi"], "hagezi")
	if err != nil {
		return fmt.Errorf("failed to parse hagezi domains: %w", err)
	}
	
	// Extract rules from Johnshall config
	extractor := NewRuleExtractor()
	domainRules, nonDomainRules, err := extractor.ExtractDomainRules(johnshallConfig)
	if err != nil {
		return fmt.Errorf("failed to extract rules: %w", err)
	}
	
	// Convert domain rules to DomainSet
	johnshallSet := NewDomainSet()
	for _, rule := range domainRules {
		if domain, valid := bo.domainProc.NormalizeDomain(rule.Pattern); valid {
			domain.Source = "johnshall"
			johnshallSet.Add(domain)
		}
	}
	
	// Store parsed data
	bo.cache.Set("johnshall_config", johnshallConfig)
	bo.cache.Set("johnshall_domains", johnshallSet)
	bo.cache.Set("hagezi_domains", hageziSet)
	bo.cache.Set("non_domain_rules", nonDomainRules)
	
	bo.logger.Printf("Parsed: johnshall=%d domains, hagezi=%d domains, non-domain rules=%d",
		johnshallSet.Size(), hageziSet.Size(), len(nonDomainRules))
	
	return nil
}

func (bo *BuildOrchestrator) processDomains(ctx context.Context) error {
	// Load allow/extra lists
	allowSet, err := bo.domainReader.ReadFromFile(bo.config.AllowFile)
	if err != nil {
		return fmt.Errorf("failed to read allow list: %w", err)
	}
	
	extraSet, err := bo.domainReader.ReadFromFile(bo.config.ExtraFile)
	if err != nil {
		return fmt.Errorf("failed to read extra list: %w", err)
	}
	
	// Get source domains
	johnshallSetVal := bo.cache.Get("johnshall_domains")
	if johnshallSetVal == nil {
		return fmt.Errorf("johnshall_domains not found in cache")
	}
	johnshallSet, ok := johnshallSetVal.(*DomainSet)
	if !ok {
		return fmt.Errorf("invalid johnshall_domains type in cache")
	}
	
	hageziSetVal := bo.cache.Get("hagezi_domains")
	if hageziSetVal == nil {
		return fmt.Errorf("hagezi_domains not found in cache")
	}
	hageziSet, ok := hageziSetVal.(*DomainSet)
	if !ok {
		return fmt.Errorf("invalid hagezi_domains type in cache")
	}
	
	// Merge all domains
	mergedSet := NewDomainSet()
	mergedSet.Merge(johnshallSet)
	mergedSet.Merge(hageziSet)
	mergedSet.Merge(extraSet)
	
	// Remove allowed domains
	for _, domain := range allowSet.GetAll() {
		mergedSet.Remove(domain.Normalized)
	}
	
	bo.metrics.JohnshallDomains = johnshallSet.Size()
	bo.metrics.HageziDomains = hageziSet.Size()
	bo.metrics.AllowDomains = allowSet.Size()
	bo.metrics.ExtraDomains = extraSet.Size()
	bo.metrics.TotalDomains = mergedSet.Size()
	
	bo.cache.Set("merged_domains", mergedSet)
	
	bo.logger.Printf("Merged domains: total=%d (johnshall=%d, hagezi=%d, allow=%d, extra=%d)",
		mergedSet.Size(), johnshallSet.Size(), hageziSet.Size(), allowSet.Size(), extraSet.Size())
	
	return nil
}

func (bo *BuildOrchestrator) validateDomains(ctx context.Context) error {
	mergedSetVal := bo.cache.Get("merged_domains")
	if mergedSetVal == nil {
		return fmt.Errorf("merged_domains not found in cache")
	}
	mergedSet, ok := mergedSetVal.(*DomainSet)
	if !ok {
		return fmt.Errorf("invalid merged_domains type in cache")
	}
	domains := mergedSet.GetNormalized()
	
	// Check cache first
	cache := NewDNSCache()
	if !bo.config.FullRefresh {
		if cached, err := bo.loadDNSCache(); err == nil {
			cache = cached
		}
	}
	
	// Filter out cached domains
	var toValidate []string
	var cachedCount int
	
	for _, domain := range domains {
		if cached, found := cache.Get(domain); found {
			if cached {
				cachedCount++
			}
		} else {
			toValidate = append(toValidate, domain)
		}
	}
	
	bo.metrics.CacheHits = cachedCount
	bo.logger.Printf("DNS validation: total=%d cached=%d to_validate=%d", len(domains), cachedCount, len(toValidate))
	
	if len(toValidate) > 0 {
		// Validate domains in batch
		results, err := bo.dnsValidator.ValidateBatch(ctx, toValidate)
		if err != nil {
			return fmt.Errorf("batch validation failed: %w", err)
		}
		
		// Update cache with results
		for domain, valid := range results {
			cache.Set(domain, valid)
		}
		
		// Save updated cache
		if err := bo.saveDNSCache(cache); err != nil {
			bo.logger.Printf("Warning: failed to save DNS cache: %v", err)
		}
	}
	
	// Collect validated domains
	var validated []string
	for _, domain := range domains {
		if cached, found := cache.Get(domain); found && cached {
			validated = append(validated, domain)
		}
	}
	
	bo.metrics.ValidatedDomains = len(validated)
	bo.cache.Set("validated_domains", validated)
	
	stats := bo.dnsValidator.GetStats()
	bo.metrics.DNSQueries = int(stats.TotalQueries)
	
	bo.logger.Printf("DNS validation completed: validated=%d cache_hits=%d queries=%d",
		len(validated), stats.CacheHits, stats.TotalQueries)
	
	return nil
}

func (bo *BuildOrchestrator) generateOutput(ctx context.Context) error {
	johnshallConfigVal := bo.cache.Get("johnshall_config")
	if johnshallConfigVal == nil {
		return fmt.Errorf("johnshall_config not found in cache")
	}
	johnshallConfig, ok := johnshallConfigVal.(*ParsedConfig)
	if !ok {
		return fmt.Errorf("invalid johnshall_config type in cache")
	}
	
	nonDomainRulesVal := bo.cache.Get("non_domain_rules")
	if nonDomainRulesVal == nil {
		return fmt.Errorf("non_domain_rules not found in cache")
	}
	nonDomainRules, ok := nonDomainRulesVal.([]*ShadowrocketRule)
	if !ok {
		return fmt.Errorf("invalid non_domain_rules type in cache")
	}
	
	validatedDomainsVal := bo.cache.Get("validated_domains")
	if validatedDomainsVal == nil {
		return fmt.Errorf("validated_domains not found in cache")
	}
	validatedDomains, ok := validatedDomainsVal.([]string)
	if !ok {
		return fmt.Errorf("invalid validated_domains type in cache")
	}
	
	// Sort domains for consistent output
	sort.Strings(validatedDomains)
	
	// Build configuration
	configContent := bo.configBuilder.BuildConfiguration(johnshallConfig, nonDomainRules, validatedDomains)
	
	// Write output files
	if err := os.WriteFile(bo.config.OutputDir+"/domains.txt", []byte(strings.Join(validatedDomains, "\n")+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write domains.txt: %w", err)
	}
	
	if err := os.WriteFile(bo.config.OutputDir+"/shadowrocket.conf", []byte(configContent), 0644); err != nil {
		return fmt.Errorf("failed to write shadowrocket.conf: %w", err)
	}
	
	bo.logger.Printf("Generated output files: domains.txt (%d domains), shadowrocket.conf (%d bytes)",
		len(validatedDomains), len(configContent))
	
	return nil
}

func (bo *BuildOrchestrator) finalizeMetrics() {
	bo.metrics.EndTime = time.Now()
	bo.metrics.Duration = bo.metrics.EndTime.Sub(bo.metrics.StartTime)
	
	if bo.metrics.Duration > 0 {
		bo.metrics.DomainsPerSecond = float64(bo.metrics.ValidatedDomains) / bo.metrics.Duration.Seconds()
	}
	
	// Get memory usage
	var m runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m)
	bo.metrics.MemoryUsage = m.Alloc / 1024 / 1024 // MB
}

func (bo *BuildOrchestrator) recordError(format string, err error) error {
	errMsg := fmt.Sprintf(format, err)
	bo.metrics.Errors = append(bo.metrics.Errors, errMsg)
	return fmt.Errorf(errMsg)
}

func (bo *BuildOrchestrator) loadDNSCache() (*DNSCache, error) {
	// Implementation for loading DNS cache from file
	return &DNSCache{cache: make(map[string]bool)}, nil
}

func (bo *BuildOrchestrator) saveDNSCache(cache *DNSCache) error {
	// Implementation for saving DNS cache to file
	return nil
}

func (bo *BuildOrchestrator) saveCache() error {
	// Save metrics
	metricsData, err := json.MarshalIndent(bo.metrics, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metrics: %w", err)
	}
	
	if err := os.WriteFile(bo.config.CacheDir+"/metrics.json", metricsData, 0644); err != nil {
		return fmt.Errorf("failed to write metrics: %w", err)
	}
	
	return nil
}

// Cache methods
func (c *BuildCache) Get(key string) interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data[key]
}

func (c *BuildCache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = value
}

func (c *BuildCache) Save() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	data, err := json.MarshalIndent(c.data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cache: %w", err)
	}
	
	if err := os.WriteFile(c.cacheDir+"/cache.json", data, 0644); err != nil {
		return fmt.Errorf("failed to write cache: %w", err)
	}
	
	return nil
}