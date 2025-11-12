package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
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
	dnsServerAddr = "119.29.29.29:53"

	qpsLimit      = 20               // 20 QPS
	resolveTO     = 2 * time.Second  // 每次查询超时
	fullMondayUTC = time.Monday
)

var (
	sectionHeaderRe = regexp.MustCompile(`^\s*\[(.+?)\]\s*$`)
	ipv4Re          = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}$`)
	// 允许 Unicode，先做 UTS46 归一到 ASCII punycode
	// DOMAIN/DOMAIN-SUFFIX/HOST/HOST-SUFFIX 类型
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

// ---------- 工具 ----------

func mustMkDirs() {
	_ = os.MkdirAll(outDir, 0o755)
	_ = os.MkdirAll(cacheDir, 0o755)
}

func httpGet(url string) (string, error) {
	// 简单、健壮的 GET；支持 HTTP/2
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
	}
	c := &http.Client{Transport: tr, Timeout: 90 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("http %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	// 处理可能的 UTF-8+BOM
	s := string(bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF}))
	return s, nil
}

func isCommentOrBlank(line string) bool {
	t := strings.TrimSpace(line)
	return t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//")
}

func stripComments(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		if isCommentOrBlank(ln) {
			continue
		}
		out = append(out, ln)
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
	// 允许 Unicode → punycode ASCII
	puny, err := idna.ToASCII(d)
	if err != nil {
		// 尝试原样
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
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if d, ok := normalizeDomain(sc.Text()); ok {
			m[d] = struct{}{}
		}
	}
	return m, sc.Err()
}

func writeLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, ln := range lines {
		if _, err := w.WriteString(ln + "\n"); err != nil {
			return err
		}
	}
	return w.Flush()
}

// ---------- 解析 johnshall 配置段 ----------

type sections map[string][]string

func parseSections(text string) sections {
	ss := make(sections)
	var cur string
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		ln := sc.Text()
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

// ---------- 解析 hagezi domains ----------

func parseHagezi(text string) map[string]struct{} {
	m := make(map[string]struct{})
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, "!") {
			continue
		}
		if d, ok := normalizeDomain(ln); ok {
			m[d] = struct{}{}
		}
	}
	return m
}

// ---------- 并行 DNS 校验（119.29.29.29, 20 QPS, worker pool） ----------

type dnsChecker struct {
	resolver *net.Resolver
	tokens   chan struct{}
}

func newDNSChecker() *dnsChecker {
	dialer := &net.Dialer{Timeout: resolveTO}
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
	return &dnsChecker{resolver: r, tokens: tokens}
}

func (dc *dnsChecker) ok(ctx context.Context, domain string) bool {
	select {
	case <-dc.tokens:
	case <-ctx.Done():
		return false
	}
	ctxTO, cancel := context.WithTimeout(ctx, resolveTO)
	defer cancel()

	if addrs, _ := dc.resolver.LookupHost(ctxTO, domain); len(addrs) > 0 {
		return true
	}
	if ip6, _ := dc.resolver.LookupIPAddr(ctxTO, domain); len(ip6) > 0 {
		return true
	}
	if cname, err := dc.resolver.LookupCNAME(ctxTO, domain); err == nil && cname != "" {
		cname = strings.TrimSuffix(cname, ".")
		ctx2, cancel2 := context.WithTimeout(ctx, resolveTO)
		defer cancel2()
		if addrs, _ := dc.resolver.LookupHost(ctx2, cname); len(addrs) > 0 {
			return true
		}
	}
	return false
}

func filterByDNS(domains map[string]struct{}, fullRefresh bool) (map[string]struct{}, error) {
	all := keys(domains)
	sort.Strings(all)
	cached, _ := readListFile(cacheOK)
	if !fullRefresh {
		for k := range cached {
			if _, ok := domains[k]; !ok {
				delete(cached, k)
			}
		}
	}

	need := make([]string, 0, len(all))
	if !fullRefresh {
		for _, d := range all {
			if _, ok := cached[d]; !ok {
				need = append(need, d)
			}
		}
	} else {
		need = all
	}

	fmt.Printf("DNS check: total=%d cached_ok=%d to_resolve=%d\n",
		len(all), len(cached), len(need))
	if len(need) == 0 && !fullRefresh {
		return cached, nil
	}

	dc := newDNSChecker()
	ctx := context.Background()
	okNew := make(map[string]struct{}, len(need))
	var mu sync.Mutex

	// worker pool
	workerN := 100
	jobs := make(chan string, workerN*2)
	wg := sync.WaitGroup{}

	for i := 0; i < workerN; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range jobs {
				if dc.ok(ctx, d) {
					mu.Lock()
					okNew[d] = struct{}{}
					mu.Unlock()
				}
			}
		}()
	}

	for _, d := range need {
		jobs <- d
	}
	close(jobs)
	wg.Wait()

	final := okNew
	if !fullRefresh {
		final = unionSets(cached, okNew)
	}

	if err := writeLines(cacheOK, sortedKeys(final)); err != nil {
		return nil, err
	}
	return final, nil
}


// ---------- 拼装输出 ----------

func buildShadowrocketConf(js sections, ruleNonDomain []string, mergedDomains []string) string {
	var out []string

	// 顶部散行（少见）去注释
	if top, ok := js["__top__"]; ok && len(top) > 0 {
		out = append(out, stripComments(top)...)
		if len(out) > 0 && out[len(out)-1] != "" {
			out = append(out, "")
		}
	}

	// [General]
	if g, ok := js["General"]; ok && len(g) > 0 {
		out = append(out, "[General]")
		out = append(out, stripComments(g)...)
		out = append(out, "")
	} else {
		out = append(out, defaultGeneral...)
	}

	// [Rule]
	out = append(out, "[Rule]")
	// 保留原非域名规则（去注释）
	out = append(out, stripComments(ruleNonDomain)...)
	if len(out) == 0 || out[len(out)-1] != "" {
		out = append(out, "")
	}
	// 域名规则
	for _, d := range mergedDomains {
		out = append(out, fmt.Sprintf("DOMAIN-SUFFIX,%s,REJECT", d))
	}
	out = append(out, "")

	// 追加 TAIL（去重）
	seen := make(map[string]struct{})
	for _, ln := range out {
		t := strings.TrimSpace(ln)
		if t != "" {
			seen[t] = struct{}{}
		}
	}
	for _, ln := range tailRules {
		if strings.TrimSpace(ln) == "" {
			if len(out) > 0 && out[len(out)-1] != "" {
				out = append(out, "")
			}
			continue
		}
		if _, ok := seen[strings.TrimSpace(ln)]; !ok {
			out = append(out, ln)
			seen[strings.TrimSpace(ln)] = struct{}{}
		}
	}
	out = append(out, "")

	// 其他段
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

// ---------- 小集合工具 ----------

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

// ---------- 主流程 ----------

func main() {
	mustMkDirs()

	fmt.Println("Fetching sources...")
	johnText, err := httpGet(srcJohnshall)
	chk(err)
	hgText, err := httpGet(srcHagezi)
	chk(err)

	// 解析 johnshall 段
	js := parseSections(johnText)
	ruleNonDomain, ruleDomains := extractRuleDomains(js["Rule"])

	// 解析 hagezi 域
	hgDomains := parseHagezi(hgText)

	// allow / extra
	allow, _ := readListFile(allowPath)
	extra, _ := readListFile(extraPath)

	// 合并
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

	// 每周一(UTC)全量刷新
	fullRefresh := time.Now().UTC().Weekday() == fullMondayUTC

	fmt.Printf("merged candidates=%d (john=%d, hagezi=%d, extra=%d, allow=%d) fullRefresh=%v\n",
		len(merged), len(ruleDomains), len(hgDomains), len(extra), len(allow), fullRefresh)

	// DNS 校验 + 缓存
	okSet, err := filterByDNS(merged, fullRefresh)
	chk(err)

	// 排序
	okList := sortedKeys(okSet)

	// 输出 domains.txt
	chk(writeLines(outDomains, okList))

	// 生成 shadowrocket.conf
	buildTime := time.Now().UTC().Format("2006-01-02 15:04:05 MST")
	header := []string{
		"# Auto-generated by cmd/merge (Go)",
		"# Sources:",
		"# - " + srcJohnshall,
		"# - " + srcHagezi,
		"# allow.txt was applied to subtract domains; extra_block.txt was added.",
		"# DNS validated via 119.29.29.29 at 20 QPS; cache in cache/ok.txt; Monday UTC full refresh.",
		"# build time (UTC): " + buildTime,
		"",
	}
	body := buildShadowrocketConf(js, ruleNonDomain, okList)
	chk(writeLines(outSR, append(header, body)))

	fmt.Printf("Done. dns-ok=%d -> %s, %s\n", len(okList), outDomains, outSR)
}

// 简洁报错
func chk(err error) {
	if err != nil {
		// 附带简单上下文，避免吞错
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
}

// 防止编译器优化未用导入（偶发）
var _ = base64.StdEncoding
