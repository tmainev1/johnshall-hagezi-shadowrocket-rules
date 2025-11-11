#!/usr/bin/env python3
# coding: utf-8
"""
merge.py
合并 Johnshall 的 Shadowrocket 配置与 HaGezi 的 domains/multi.txt
保留非域名设置；[Rule] 中合并域名规则；末尾追加固定 IP-CIDR 与 FINAL
移除来源注释，仅保留脚本自带注释，并在注释最后写入 build time (UTC)

依赖: idna
"""

import re
import sys
import os
import urllib.request
import idna
from datetime import datetime, timezone

# === 源地址 ===
SRC_SHADOWROCKET = "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_proxy_banad.conf"
SRC_HAGEZI = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/multi.txt"

# === 可选白名单/自定义黑名单 ===
ALLOW_PATH = "allow.txt"
EXTRA_BLOCK_PATH = "extra_block.txt"

# === 输出路径 ===
OUT_DIR = "output"
OUT_DOMAINS = os.path.join(OUT_DIR, "domains.txt")
OUT_SR = os.path.join(OUT_DIR, "shadowrocket.conf")
os.makedirs(OUT_DIR, exist_ok=True)

# 当 johnshall 没有 [General] 时使用的默认模板（可自改）
DEFAULT_GENERAL = [
    "[General]",
    "ipv6 = false",
    "bypass-system = true",
    "skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, fe80::/10, fc00::/7, localhost, *.local, *.lan, *.internal, e.crashlytics.com, captive.apple.com, sequoia.apple.com, seed-sequoia.siri.apple.com, *.ls.apple.com",
    "bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,233.252.0.0/24,224.0.0.0/4,255.255.255.255/32,::1/128,::ffff:0:0/96,::ffff:0:0:0/96,64:ff9b::/96,64:ff9b:1::/48,100::/64,2001::/32,2001:20::/28,2001:db8::/32,2002::/16,3fff::/20,5f00::/16,fc00::/7,fe80::/10,ff00::/8",
    "dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query",
    ""
]

# 固定要追加到 [Rule] 末尾的规则
TAIL_RULES = [
    "IP-CIDR,192.168.0.0/16,DIRECT",
    "IP-CIDR,10.0.0.0/8,DIRECT",
    "IP-CIDR,172.16.0.0/12,DIRECT",
    "IP-CIDR,127.0.0.0/8,DIRECT",
    "IP-CIDR,fe80::/10,DIRECT",
    "IP-CIDR,fc00::/7,DIRECT",
    "IP-CIDR,::1/128,DIRECT",
    "",
    "FINAL,proxy"
]

# === 正则 ===
SECTION_HEADER_RE = re.compile(r'^\s*\[(.+?)\]\s*$')
IP_V4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=90) as r:
        return r.read().decode("utf-8", errors="ignore")

def normalize_domain(d: str) -> str:
    d = d.strip().lower()
    d = d.split("/")[0]  # 去除路径
    d = d.lstrip(".")
    if not d or " " in d or IP_V4_RE.match(d):
        return ""
    d = d.lstrip("*").lstrip(".")
    if d.count('.') == 0:
        return ""
    if not re.match(r'^[a-z0-9\-\.\u0080-\uffff]+$', d, re.IGNORECASE):
        return ""
    try:
        return idna.encode(d, uts46=True).decode('ascii').lower()
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

def strip_comments(lines):
    """移除来源中的注释行，只保留非注释内容"""
    out = []
    for line in lines:
        s = line.strip()
        if s.startswith("#") or s.startswith("//"):
            continue
        out.append(line)
    return out

def parse_johnshall_conf(text: str):
    """
    解析为 sections: dict[section_name] -> list(lines)
    并从 [Rule] 提取：
      - rule_non_domain_lines: 非域名条目（保留，稍后再统一去注释）
      - rule_domain_set: 域名集合（DOMAIN/DOMAIN-SUFFIX/HOST/HOST-SUFFIX）
    """
    sections = {}
    cur = None
    for raw in text.splitlines():
        m = SECTION_HEADER_RE.match(raw)
        if m:
            cur = m.group(1).strip()
            sections.setdefault(cur, [])
            continue
        if cur is None:
            sections.setdefault('__top__', []).append(raw)
        else:
            sections[cur].append(raw)

    rule_non_domain_lines = []
    rule_domain_set = set()
    if 'Rule' in sections:
        for line in sections['Rule']:
            s = line.strip()
            # 注释在这里先不丢，后续统一 strip
            parts = [p.strip() for p in s.split(',')]
            if len(parts) >= 2:
                typ = parts[0].upper()
                dom = parts[1]
                if typ in ("DOMAIN", "DOMAIN-SUFFIX", "HOST", "HOST-SUFFIX"):
                    nd = normalize_domain(dom)
                    if nd:
                        rule_domain_set.add(nd)
                        continue
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
    生成最终 shadowrocket.conf：
      - 去除来源注释（所有 section）
      - [General]：johnshall 或默认模板
      - [Rule]：先保留 johnshall 的非域名规则（去注释），再写域名规则，最后追加 TAIL_RULES
      - 其他段（如 [URL Rewrite], [MITM]）按原顺序写入（去注释）
    """
    out_lines = []

    # 顶部散行（极少见）去注释
    if '__top__' in j_sections and j_sections['__top__']:
        out_lines.extend(strip_comments(j_sections['__top__']))
        if out_lines and out_lines[-1] != "":
            out_lines.append("")

    # General
    if 'General' in j_sections and j_sections['General']:
        out_lines.append("[General]")
        out_lines.extend(strip_comments(j_sections['General']))
        out_lines.append("")
    else:
        out_lines.extend(DEFAULT_GENERAL)

    # Rule
    out_lines.append("[Rule]")
    # 先写入去注释后的非域名规则
    jr_clean = strip_comments(jr_non_domain_lines)
    out_lines.extend(jr_clean)
    if not (len(out_lines) > 0 and out_lines[-1] == ""):
        out_lines.append("")

    # 再写域名规则
    for d in merged_domains_sorted:
        out_lines.append(f"DOMAIN-SUFFIX,{d},REJECT")
    out_lines.append("")

    # 确保末尾追加固定规则（去重）
    existing = set(line.strip() for line in out_lines if line.strip())
    for line in TAIL_RULES:
        if not line:  # 空行
            if out_lines and out_lines[-1] != "":
                out_lines.append("")
            continue
        if line.strip() not in existing:
            out_lines.append(line)
            existing.add(line.strip())
    out_lines.append("")

    # 追加其他段（去注释）
    for sec_name, sec_lines in j_sections.items():
        if sec_name in ('General', 'Rule', '__top__'):
            continue
        out_lines.append(f"[{sec_name}]")
        out_lines.extend(strip_comments(sec_lines))
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

    merged = (j_rule_domains | h_domains | extra) - allow
    merged_sorted = sorted(merged, key=lambda x: (len(x), x))

    # 输出 domains.txt
    with open(OUT_DOMAINS, "w", encoding="utf-8") as f:
        for d in merged_sorted:
            f.write(d + "\n")

    # 生成完整 shadowrocket.conf（无来源注释）
    out_conf_text = build_output_conf(j_sections, j_rule_non_domain, merged_sorted)

    # 头部脚本注释（唯一保留的注释），在最后追加 build time
    build_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
    header = []
    header.append("# Auto-generated by scripts/merge.py")
    header.append(f"# Sources:")
    header.append(f"# - {SRC_SHADOWROCKET}")
    header.append(f"# - {SRC_HAGEZI}")
    header.append("# allow.txt was applied to subtract domains; extra_block.txt was added.")
    header.append(f"# build time (UTC): {build_time}")
    header.append("")  # 空行分隔

    with open(OUT_SR, "w", encoding="utf-8") as f:
        f.write("\n".join(header))
        f.write(out_conf_text)

    print(f"Done. total domains={len(merged_sorted)} -> {OUT_DOMAINS}, {OUT_SR}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
