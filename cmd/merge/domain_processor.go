package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/net/idna"
)

// Domain represents a normalized domain with validation status
type Domain struct {
	Name       string `json:"name"`
	Normalized string `json:"normalized"`
	Valid      bool   `json:"valid"`
	Source     string `json:"source"`
}

// DomainProcessor handles domain normalization and validation
type DomainProcessor struct {
	ipv4Re       *regexp.Regexp
	normalizer   *idna.Profile
	mu           sync.RWMutex
	cache        map[string]*Domain
}

// NewDomainProcessor creates a new domain processor
func NewDomainProcessor() *DomainProcessor {
	return &DomainProcessor{
		ipv4Re:     regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}$`),
		normalizer: idna.New(),
		cache:      make(map[string]*Domain),
	}
}

// NormalizeDomain normalizes a domain name
func (dp *DomainProcessor) NormalizeDomain(raw string) (*Domain, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, false
	}
	
	// Check cache first
	dp.mu.RLock()
	if cached, ok := dp.cache[raw]; ok {
		dp.mu.RUnlock()
		return cached, cached.Valid
	}
		dp.mu.RUnlock()
	
	// Normalize domain
	normalized := strings.ToLower(raw)
	normalized = strings.Split(normalized, "/")[0]
	normalized = strings.TrimLeft(normalized, ".")
	
	// Basic validation
	if strings.Contains(normalized, " ") || dp.ipv4Re.MatchString(normalized) {
		domain := &Domain{Name: raw, Normalized: "", Valid: false}
		dp.cacheDomain(raw, domain)
		return domain, false
	}
	
	// Remove wildcards
	normalized = strings.TrimLeft(normalized, "*.")
	
	// Check for minimum domain structure
	if strings.Count(normalized, ".") == 0 {
		domain := &Domain{Name: raw, Normalized: "", Valid: false}
		dp.cacheDomain(raw, domain)
		return domain, false
	}
	
	// Convert to ASCII (punycode)
	ascii, err := dp.normalizer.ToASCII(normalized)
	if err != nil {
		// Keep original if conversion fails
		ascii = normalized
	}
	
	domain := &Domain{
		Name:       raw,
		Normalized: strings.ToLower(ascii),
		Valid:      true,
	}
	
	dp.cacheDomain(raw, domain)
	return domain, true
}

func (dp *DomainProcessor) cacheDomain(key string, domain *Domain) {
	dp.mu.Lock()
	defer dp.mu.Unlock()
	dp.cache[key] = domain
}

// DomainSet represents a set of unique domains
type DomainSet struct {
	domains map[string]*Domain
	mu      sync.RWMutex
}

// NewDomainSet creates a new domain set
func NewDomainSet() *DomainSet {
	return &DomainSet{
		domains: make(map[string]*Domain),
	}
}

// Add adds a domain to the set
func (ds *DomainSet) Add(domain *Domain) {
	if domain == nil || !domain.Valid {
		return
	}
	
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.domains[domain.Normalized] = domain
}

// Remove removes a domain from the set
func (ds *DomainSet) Remove(normalized string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	delete(ds.domains, normalized)
}

// Contains checks if a domain exists in the set
func (ds *DomainSet) Contains(normalized string) bool {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	_, exists := ds.domains[normalized]
	return exists
}

// Size returns the number of domains in the set
func (ds *DomainSet) Size() int {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return len(ds.domains)
}

// GetAll returns all domains in the set
func (ds *DomainSet) GetAll() []*Domain {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	
	result := make([]*Domain, 0, len(ds.domains))
	for _, domain := range ds.domains {
		result = append(result, domain)
	}
	return result
}

// GetNormalized returns all normalized domain names
func (ds *DomainSet) GetNormalized() []string {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	
	result := make([]string, 0, len(ds.domains))
	for normalized := range ds.domains {
		result = append(result, normalized)
	}
	return result
}

// Merge merges another domain set into this one
func (ds *DomainSet) Merge(other *DomainSet) {
	if other == nil {
		return
	}
	
	ds.mu.Lock()
	other.mu.RLock()
	defer ds.mu.Unlock()
	defer other.mu.RUnlock()
	
	for normalized, domain := range other.domains {
		ds.domains[normalized] = domain
	}
}

// DomainListReader reads domain lists from various sources
type DomainListReader struct {
	processor *DomainProcessor
}

// NewDomainListReader creates a new domain list reader
func NewDomainListReader(processor *DomainProcessor) *DomainListReader {
	return &DomainListReader{processor: processor}
}

// ReadFromFile reads domains from a file
func (dlr *DomainListReader) ReadFromFile(path string) (*DomainSet, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return NewDomainSet(), nil
		}
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}
	defer file.Close()
	
	return dlr.ReadFromReader(file, path)
}

// ReadFromReader reads domains from an io.Reader
func (dlr *DomainListReader) ReadFromReader(reader io.Reader, source string) (*DomainSet, error) {
	set := NewDomainSet()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // 1MB max line size
	
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		
		// Skip comments and empty lines
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		
		domain, valid := dlr.processor.NormalizeDomain(line)
		if valid {
			domain.Source = source
			set.Add(domain)
		}
	}
	
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file at line %d: %w", lineNum, err)
	}
	
	return set, nil
}

// ReadFromString reads domains from a string
func (dlr *DomainListReader) ReadFromString(content string, source string) (*DomainSet, error) {
	return dlr.ReadFromReader(strings.NewReader(content), source)
}

// ReadFromHagezi reads domains from Hagezi format
func (dlr *DomainListReader) ReadFromHagezi(content string) (*DomainSet, error) {
	set := NewDomainSet()
	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // 1MB max line size
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		
		domain, valid := dlr.processor.NormalizeDomain(line)
		if valid {
			domain.Source = "hagezi"
			set.Add(domain)
		}
	}
	
	return set, scanner.Err()
}

// DomainListWriter writes domain lists to files
type DomainListWriter struct{}

// NewDomainListWriter creates a new domain list writer
func NewDomainListWriter() *DomainListWriter {
	return &DomainListWriter{}
}

// WriteDomains writes a list of domains to a file
func (dlw *DomainListWriter) WriteDomains(path string, domains []string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", path, err)
	}
	defer file.Close()
	
	writer := bufio.NewWriterSize(file, 64*1024) // 64KB buffer
	defer writer.Flush()
	
	for _, domain := range domains {
		if _, err := writer.WriteString(domain + "\n"); err != nil {
			return fmt.Errorf("failed to write to file %s: %w", path, err)
		}
	}
	
	return nil
}

// WriteDomainSet writes a DomainSet to a file
func (dlw *DomainListWriter) WriteDomainSet(path string, set *DomainSet) error {
	domains := set.GetNormalized()
	return dlw.WriteDomains(path, domains)
}