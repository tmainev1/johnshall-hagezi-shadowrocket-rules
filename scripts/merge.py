#!/usr/bin/env python3
# coding: utf-8
"""
merge.py
Merge Johnshall's Shadowrocket configuration with HaGeZi's domains/multi.txt
Retain non-domain settings such as [General], [URL Rewrite], [MITM] from Johnshall's configuration
Write merged/deduplicated domains into the [Rule] section as DOMAIN-SUFFIX,domain,REJECT

"""

import re
import sys
import os
import urllib.request
import idna

# Source Address
SRC_SHADOWROCKET = "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_proxy_banad.conf"
SRC_HAGEZI = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/multi.txt"

# Optional whitelist/custom blacklist
ALLOW_PATH = "allow.txt"
EXTRA_BLOCK_PATH = "extra_block.txt"

OUT_DIR = "output"
OUT_DOMAINS = os.path.join(OUT_DIR, "domains.txt")
OUT_SR = os.path.join(OUT_DIR, "shadowrocket.conf")

os.makedirs(OUT_DIR, exist_ok=True)

# Default template used when johnshall does not have [General] (you can modify it as needed)
DEFAULT_GENERAL = [
    "[General]",
    "ipv6 = false",
    "bypass-system = true",
    "skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, fe80::/10, fc00::/7, localhost, *.local, *.lan, *.internal, e.crashlytics.com, captive.apple.com, sequoia.apple.com, seed-sequoia.siri.apple.com, *.ls.apple.com",
    "bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,233.252.0.0/24,224.0.0.0/4,255.255.255.255/32,::1/128,::ffff:0:0/96,::ffff:0:0:0/96,64:ff9b::/96,64:ff9b:1::/48,100::/64,2001::/32,2001:20::/28,2001:db8::/32,2002::/16,3fff::/20,5f00::/16,fc00::/7,fe80::/10,ff00::/8",
    "dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query",
    ""
]

# Regular Expression
SECTION_HEADER_RE = re.compile(r'^\s*\[(.+?)\]\s*$')
DOMAIN_LINE_RE = re.compile(r'^[a-z0-9\-\.\*]+$', re.IGNORECASE)
IP_V4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=90) as r:
        return r.read().decode("utf-8", errors="ignore")

def normalize_domain(d: str) -> str:
    d = d.strip().lower()
    # remove protocol paths or extra parts
    d = d.split("/")[0]
    d = d.lstrip(".")
    if not d:
        return ""
    # filter out ips and things with spaces
    if " " in d or IP_V4_RE.match(d):
        return ""
    # strip common prefixes
    d = d.lstrip("*").lstrip(".")
    # if only one label (no dot) skip
    if d.count('.') == 0:
        return ""
    # reject if contains slashes or illegal chars
    if not re.match(r'^[a-z0-9\-\.\u0080-\uffff]+$', d, re.IGNORECASE):
        return ""
    # punycode normalize
    try:
        # idna encode -> ascii
        d_ascii = idna.encode(d, uts46=True).decode('ascii')
        # then normalize back to lower-ascii form for storage
        return d_ascii.lower()
    except Exception:
        return d.lower()

def load_list(path: str) -> set:
    s = set()
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                dom = normalize_domain(line.strip())
                if dom:
                    s.add(dom)
    return s

def parse_johnshall_conf(text: str):
    """
    Parses conf files in johnshall style, returning sections: dict[section_name] -> list(lines)
    Preserves original lines (including comments), but splits [Rule] sections into:
      - rule_non_domain_lines : **Non**-domain entries from the original [Rule] (e.g., IP-CIDR, GEOIP, FINAL, etc.)
      - rule_domain_set: Extract and normalize domain sets from [Rule] (DOMAIN, DOMAIN-SUFFIX, HOST)
    Other sections ([General], [URL Rewrite], [MITM]) returned as original lists
    """
    sections = {}
    cur = None
    lines = text.splitlines()
    for raw in lines:
        m = SECTION_HEADER_RE.match(raw)
        if m:
            cur = m.group(1).strip()
            sections.setdefault(cur, [])
            continue
        if cur is None:
            # headerless leading lines (rare) -> put into top
            sections.setdefault('__top__', []).append(raw)
        else:
            sections[cur].append(raw)
    # Split domain names / non-domain names from [Rule]
    rule_non_domain_lines = []
    rule_domain_set = set()
    if 'Rule' in sections:
        for line in sections['Rule']:
            s = line.strip()
            if not s or s.startswith("#") or s.startswith("//"):
                # preserve comments/blank
                rule_non_domain_lines.append(line)
                continue
            parts = [p.strip() for p in s.split(',')]
            if len(parts) >= 2:
                typ = parts[0].upper()
                dom = parts[1]
                if typ in ("DOMAIN", "DOMAIN-SUFFIX", "HOST", "HOST-SUFFIX"):
                    nd = normalize_domain(dom)
                    if nd:
                        rule_domain_set.add(nd)
                        continue
            # fallback: not a domain rule we care about — keep as non-domain
            rule_non_domain_lines.append(line)
    return sections, rule_domain_set, rule_non_domain_lines

def parse_hagezi_domains(text: str) -> set:
    domains = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        d = normalize_domain(line)
        if d:
            domains.add(d)
    return domains

def build_output_conf(j_sections, jr_non_domain_lines, merged_domains_sorted):
    """
    Generate the final shadowrocket.conf text:
      - Prioritize writing [General] (from johnshall; use DEFAULT_GENERAL if absent)
      - Then write [Rule]:
          * First write johnshall's rule_non_domain_lines (as-is)
          * Followed by the merged domain rules (DOMAIN-SUFFIX,domain,REJECT)
      - Finally append the remaining sections from johnshall (e.g., [URL Rewrite], [MITM]) unchanged (preserving original order except for consumed [Rule] sections)
    """
    out_lines = []

    # header/top if exists
    if '__top__' in j_sections and j_sections['__top__']:
        out_lines.extend(j_sections['__top__'])
        out_lines.append("")

    # General
    if 'General' in j_sections and j_sections['General']:
        out_lines.append("[General]")
        out_lines.extend(j_sections['General'])
        out_lines.append("")
    else:
        # fallback default general
        out_lines.extend(DEFAULT_GENERAL)

    # Rule
    out_lines.append("[Rule]")
    # first preserve johnshall's non-domain rule lines (if any)
    if jr_non_domain_lines:
        out_lines.extend(jr_non_domain_lines)
    else:
        # if none, keep a comment explaining
        out_lines.append("# non-domain rules from original [Rule] (none preserved)")
    out_lines.append("")  # blank line for readability

    # then produce domain rules
    for d in merged_domains_sorted:
        out_lines.append(f"DOMAIN-SUFFIX,{d},REJECT")
    out_lines.append("")

    # append other johnshall sections except General and Rule (respect original order)
    for sec_name, sec_lines in j_sections.items():
        if sec_name in ('General', 'Rule', '__top__'):
            continue
        out_lines.append(f"[{sec_name}]")
        out_lines.extend(sec_lines)
        out_lines.append("")

    return "\n".join(out_lines)

def main():
    print("Fetching sources...")
    try:
        sr_text = fetch(SRC_SHADOWROCKET)
    except Exception as e:
        print("Error fetching johnshall source:", e)
        return 2
    try:
        hg_text = fetch(SRC_HAGEZI)
    except Exception as e:
        print("Error fetching hagezi source:", e)
        return 3

    print("Parsing johnshall conf...")
    j_sections, j_rule_domains, j_rule_non_domain = parse_johnshall_conf(sr_text)

    print("Parsing hagezi domains...")
    h_domains = parse_hagezi_domains(hg_text)

    extra = load_list(EXTRA_BLOCK_PATH)
    allow = load_list(ALLOW_PATH)

    print(f"counts: johnshall domain rules={len(j_rule_domains)}, hagezi={len(h_domains)}, extra={len(extra)}, allow={len(allow)}")

    # Merge: domain names in johnshall + hagezi + extra, then remove allow
    merged = (j_rule_domains | h_domains | extra) - allow

    # Sorting (by domain name length, lexicographical order)
    merged_sorted = sorted(merged, key=lambda x: (len(x), x))

    # Output domains.txt
    with open(OUT_DOMAINS, "w", encoding="utf-8") as f:
        for d in merged_sorted:
            f.write(d + "\n")

    # Generate a complete shadowrocket.conf file
    out_conf_text = build_output_conf(j_sections, j_rule_non_domain, merged_sorted)
    with open(OUT_SR, "w", encoding="utf-8") as f:
        f.write("# Auto-generated by scripts/merge.py\n")
        f.write(f"# Sources:\n# - {SRC_SHADOWROCKET}\n# - {SRC_HAGEZI}\n")
        f.write("# allow.txt was applied to subtract domains; extra_block.txt was added.\n\n")
        f.write(out_conf_text)

    print(f"Done. total domains={len(merged_sorted)} -> {OUT_DOMAINS}, {OUT_SR}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
