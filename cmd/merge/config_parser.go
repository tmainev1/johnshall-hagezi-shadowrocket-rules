package main

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// ConfigurationParser handles parsing of Shadowrocket configuration files
type ConfigurationParser struct {
	sectionRe *regexp.Regexp
}

// NewConfigurationParser creates a new configuration parser
func NewConfigurationParser() *ConfigurationParser {
	return &ConfigurationParser{
		sectionRe: regexp.MustCompile(`^\s*\[(.+?)\]\s*$`),
	}
}

// ParsedConfig represents a parsed Shadowrocket configuration
type ParsedConfig struct {
	Sections map[string][]string
	TopLevel []string
}

// NewParsedConfig creates a new parsed configuration
func NewParsedConfig() *ParsedConfig {
	return &ParsedConfig{
		Sections: make(map[string][]string),
		TopLevel: []string{},
	}
}

// Parse parses a configuration string
func (cp *ConfigurationParser) Parse(content string) (*ParsedConfig, error) {
	config := NewParsedConfig()
	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // 1MB max line size
	
	var currentSection string
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		
		// Check for section header
		if matches := cp.sectionRe.FindStringSubmatch(line); matches != nil {
			currentSection = strings.TrimSpace(matches[1])
			if _, exists := config.Sections[currentSection]; !exists {
				config.Sections[currentSection] = []string{}
			}
			continue
		}
		
		// Add line to appropriate section
		if currentSection == "" {
			config.TopLevel = append(config.TopLevel, line)
		} else {
			config.Sections[currentSection] = append(config.Sections[currentSection], line)
		}
	}
	
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error parsing configuration at line %d: %w", lineNum, err)
	}
	
	return config, nil
}

// GetSection returns the lines for a specific section
func (pc *ParsedConfig) GetSection(name string) []string {
	if lines, exists := pc.Sections[name]; exists {
		return lines
	}
	return []string{}
}

// HasSection checks if a section exists
func (pc *ParsedConfig) HasSection(name string) bool {
	_, exists := pc.Sections[name]
	return exists
}

// ShadowrocketRule represents a parsed Shadowrocket rule
type ShadowrocketRule struct {
	Type     string
	Pattern  string
	Action   string
	Options  []string
	Raw      string
}

// RuleParser handles parsing of individual rules
type RuleParser struct {
	domainTypes map[string]bool
}

// NewRuleParser creates a new rule parser
func NewRuleParser() *RuleParser {
	return &RuleParser{
		domainTypes: map[string]bool{
			"DOMAIN":        true,
			"DOMAIN-SUFFIX": true,
			"HOST":          true,
			"HOST-SUFFIX":   true,
		},
	}
}

// ParseRule parses a single rule
func (rp *RuleParser) ParseRule(line string) (*ShadowrocketRule, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return nil, nil // Comment or empty line
	}
	
	parts := strings.Split(line, ",")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid rule format: %s", line)
	}
	
	rule := &ShadowrocketRule{
		Type:    strings.ToUpper(strings.TrimSpace(parts[0])),
		Raw:     line,
		Options: []string{},
	}
	
	if len(parts) > 1 {
		rule.Pattern = strings.TrimSpace(parts[1])
	}
	
	if len(parts) > 2 {
		rule.Action = strings.TrimSpace(parts[2])
	}
	
	if len(parts) > 3 {
		rule.Options = parts[3:]
		for i, opt := range rule.Options {
			rule.Options[i] = strings.TrimSpace(opt)
		}
	}
	
	return rule, nil
}

// IsDomainRule checks if this is a domain-based rule
func (rp *RuleParser) IsDomainRule(rule *ShadowrocketRule) bool {
	if rule == nil {
		return false
	}
	return rp.domainTypes[rule.Type]
}

// RuleExtractor extracts rules from configuration sections
type RuleExtractor struct {
	parser *RuleParser
}

// NewRuleExtractor creates a new rule extractor
func NewRuleExtractor() *RuleExtractor {
	return &RuleExtractor{
		parser: NewRuleParser(),
	}
}

// ExtractRules extracts all rules from a configuration
func (re *RuleExtractor) ExtractRules(config *ParsedConfig) ([]*ShadowrocketRule, error) {
	var rules []*ShadowrocketRule
	
	// Extract from Rule section
	if ruleLines := config.GetSection("Rule"); len(ruleLines) > 0 {
		sectionRules, err := re.parseRuleLines(ruleLines)
		if err != nil {
			return nil, fmt.Errorf("error parsing Rule section: %w", err)
		}
		rules = append(rules, sectionRules...)
	}
	
	return rules, nil
}

// ExtractDomainRules extracts domain rules and returns (domainRules, nonDomainRules)
func (re *RuleExtractor) ExtractDomainRules(config *ParsedConfig) ([]*ShadowrocketRule, []*ShadowrocketRule, error) {
	allRules, err := re.ExtractRules(config)
	if err != nil {
		return nil, nil, err
	}
	
	var domainRules, nonDomainRules []*ShadowrocketRule
	
	for _, rule := range allRules {
		if re.parser.IsDomainRule(rule) {
			domainRules = append(domainRules, rule)
		} else {
			nonDomainRules = append(nonDomainRules, rule)
		}
	}
	
	return domainRules, nonDomainRules, nil
}

func (re *RuleExtractor) parseRuleLines(lines []string) ([]*ShadowrocketRule, error) {
	var rules []*ShadowrocketRule
	
	for lineNum, line := range lines {
		rule, err := re.parser.ParseRule(line)
		if err != nil {
			return nil, fmt.Errorf("error parsing rule at line %d: %w", lineNum+1, err)
		}
		if rule != nil {
			rules = append(rules, rule)
		}
	}
	
	return rules, nil
}

// ConfigurationBuilder builds Shadowrocket configuration files
type ConfigurationBuilder struct {
	defaultGeneral []string
	tailRules      []string
}

// NewConfigurationBuilder creates a new configuration builder
func NewConfigurationBuilder() *ConfigurationBuilder {
	return &ConfigurationBuilder{
		defaultGeneral: []string{
			"[General]",
			"ipv6 = false",
			"bypass-system = true",
			"skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, fe80::/10, fc00::/7, localhost, *.local, *.lan, *.internal, e.crashlytics.com, captive.apple.com, sequoia.apple.com, seed-sequoia.siri.apple.com, *.ls.apple.com",
			"bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,233.252.0.0/24,224.0.0.0/4,255.255.255.255/32,::1/128,::ffff:0:0/96,::ffff:0:0:0/96,64:ff9b::/96,64:ff9b:1::/48,100::/64,2001::/32,2001:20::/28,2001:db8::/32,2002::/16,3fff::/20,5f00::/16,fc00::/7,fe80::/10,ff00::/8",
			"dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query",
			"",
		},
		tailRules: []string{
			"IP-CIDR,192.168.0.0/16,DIRECT",
			"IP-CIDR,10.0.0.0/8,DIRECT",
			"IP-CIDR,172.16.0.0/12,DIRECT",
			"IP-CIDR,127.0.0.0/8,DIRECT",
			"IP-CIDR,fe80::/10,DIRECT",
			"IP-CIDR,fc00::/7,DIRECT",
			"IP-CIDR,::1/128,DIRECT",
			"",
			"FINAL,proxy",
		},
	}
}

// BuildConfiguration builds a complete configuration
func (cb *ConfigurationBuilder) BuildConfiguration(originalConfig *ParsedConfig, nonDomainRules []*ShadowrocketRule, validatedDomains []string) string {
	var sections []string
	
	// Add header comment
	sections = append(sections, cb.buildHeader()...)
	
	// Add top-level content
	if len(originalConfig.TopLevel) > 0 {
		sections = append(sections, cb.stripComments(originalConfig.TopLevel)...)
		sections = append(sections, "")
	}
	
	// Add General section
	sections = append(sections, cb.buildGeneralSection(originalConfig)...)
	
	// Add Rule section
	sections = append(sections, cb.buildRuleSection(nonDomainRules, validatedDomains)...)
	
	// Add other sections
	sections = append(sections, cb.buildOtherSections(originalConfig)...)
	
	return strings.Join(sections, "\n")
}

func (cb *ConfigurationBuilder) buildHeader() []string {
	buildTime := time.Now().UTC().Format("2006-01-02 15:04:05 MST")
	return []string{
		"# Auto-generated by Shadowrocket Rules Builder (Go)",
		"# Sources:",
		"# - https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_proxy_banad.conf",
		"# - https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/multi.txt",
		"# DNS validated domains with optimized batch processing",
		"# Build time (UTC): " + buildTime,
		"",
	}
}

func (cb *ConfigurationBuilder) buildGeneralSection(config *ParsedConfig) []string {
	var section []string
	
	if generalLines := config.GetSection("General"); len(generalLines) > 0 {
		section = append(section, "[General]")
		section = append(section, cb.stripComments(generalLines)...)
		section = append(section, "")
	} else {
		section = append(section, cb.defaultGeneral...)
	}
	
	return section
}

func (cb *ConfigurationBuilder) buildRuleSection(nonDomainRules []*ShadowrocketRule, validatedDomains []string) []string {
	var section []string
	
	section = append(section, "[Rule]")
	
	// Add non-domain rules
	for _, rule := range nonDomainRules {
		section = append(section, rule.Raw)
	}
	
	if len(nonDomainRules) > 0 {
		section = append(section, "")
	}
	
	// Add validated domain rules
	for _, domain := range validatedDomains {
		section = append(section, fmt.Sprintf("DOMAIN-SUFFIX,%s,REJECT", domain))
	}
	
	if len(validatedDomains) > 0 {
		section = append(section, "")
	}
	
	// Add tail rules with deduplication
	seen := make(map[string]bool)
	for _, rule := range nonDomainRules {
		seen[strings.TrimSpace(rule.Raw)] = true
	}
	
	for _, tailRule := range cb.tailRules {
		trimmed := strings.TrimSpace(tailRule)
		if trimmed != "" && !seen[trimmed] {
			section = append(section, tailRule)
			seen[trimmed] = true
		}
	}
	
	return section
}

func (cb *ConfigurationBuilder) buildOtherSections(config *ParsedConfig) []string {
	var sections []string
	
	// Skip already processed sections
	skipSections := map[string]bool{
		"__top__":  true,
		"General":  true,
		"Rule":     true,
	}
	
	for name, lines := range config.Sections {
		if skipSections[name] {
			continue
		}
		
		sections = append(sections, fmt.Sprintf("[%s]", name))
		sections = append(sections, cb.stripComments(lines)...)
		sections = append(sections, "")
	}
	
	return sections
}

func (cb *ConfigurationBuilder) stripComments(lines []string) []string {
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "//") {
			result = append(result, line)
		}
	}
	return result
}