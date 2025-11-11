#!/usr/bin/env python3
import re, sys, os, urllib.request, idna

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

def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=90) as r:
        return r.read().decode("utf-8", errors="ignore")

def normalize_domain(d: str) -> str:
    d = d.strip().lower()
    d = d.lstrip(".")
    # Filter IP / Empty / Contains spaces
    if not d or " " in d or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", d):
        return ""
    # Filter non-domain characters (preserve hyphens and periods)
    if not re.match(r"^[a-z0-9\-\.\*]+$", d):
        return ""
    # Remove the leading wildcard *
    d = d.lstrip("*").lstrip(".")
    if d.count(".") == 0:  # Single-segment fields (TLD/keywords) discarded to prevent false positives
        return ""
    # Punycode normalization
    try:
        d = idna.encode(d, uts46=True).decode("ascii")
        d = idna.decode(d).encode("idna").decode("ascii")  # Normalize to IDNA
    except Exception:
        pass
    return d

def load_list(path: str) -> set:
    items = set()
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                dom = normalize_domain(line)
                if dom:
                    items.add(dom)
    return items

def parse_shadowrocket_conf(text: str) -> set:
    """
    Resolve such as：
      DOMAIN-SUFFIX,example.com,REJECT
      DOMAIN,foo.bar,REJECT
      HOST,xxx       
    """
    domains = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        # Retrieve the second field (type, domain name[, policy])
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 2:
            typ, dom = parts[0].upper(), parts[1]
            if typ in ("DOMAIN", "DOMAIN-SUFFIX", "HOST", "HOST-SUFFIX"):
                d = normalize_domain(dom)
                if d:
                    domains.add(d)
    return domains

def parse_hagezi_domains(text: str) -> set:
    """
    multi.txt Each line contains one domain name, with comments/blank lines.
    """
    domains = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        d = normalize_domain(line)
        if d:
            domains.add(d)
    return domains

def main():
    print("Fetching sources...")
    sr_text = fetch(SRC_SHADOWROCKET)
    hg_text = fetch(SRC_HAGEZI)

    print("Parsing...")
    s1 = parse_shadowrocket_conf(sr_text)
    s2 = parse_hagezi_domains(hg_text)

    extra = load_list(EXTRA_BLOCK_PATH)
    allow = load_list(ALLOW_PATH)

    merged = (s1 | s2 | extra) - allow

    # Sorting (by length and lexicographical order for easy diffing)
    ordered = sorted(merged, key=lambda x: (len(x), x))

    # 输出纯域名
    with open(OUT_DOMAINS, "w", encoding="utf-8") as f:
        for d in ordered:
            f.write(d + "\n")

    # Output Shadowrocket Rules
    # Rule: Use DOMAIN-SUFFIX by default; use DOMAIN for clearly single-hostnames (rare)
    # Here we uniformly use DOMAIN-SUFFIX for simplicity and reliability
    with open(OUT_SR, "w", encoding="utf-8") as f:
        f.write("# Auto-generated. Sources:\n")
        f.write(f"# - {SRC_SHADOWROCKET}\n")
        f.write(f"# - {SRC_HAGEZI}\n")
        f.write("# Allowlist subtracted from allow.txt; extra from extra_block.txt\n\n")
        for d in ordered:
            f.write(f"DOMAIN-SUFFIX,{d},REJECT\n")

    print(f"Done. domains={len(ordered)}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
