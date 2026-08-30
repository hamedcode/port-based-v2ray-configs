#!/usr/bin/env python3
# categorize_all_protocols.py
# Safe updater: writes files into sub/ and detailed/, updates README between markers.
# No external formatting library required.

import os
import re
import requests
import base64
import json
from urllib.parse import urlparse
from collections import defaultdict
from datetime import datetime, timezone, timedelta # ADDED timedelta
import math
import shutil # For deleting directories
import sys # For exiting with an error code

from liveness.pipeline import run_tcp_stage, run_l3_and_build

# ---------------- Config ----------------
SOURCES = {
    "barry-far": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    "kobabi": "https://raw.githubusercontent.com/liketolivefree/kobabi/main/sub.txt",
    "yebekhe": "https://raw.githubusercontent.com/itsyebekhe/PSG/refs/heads/main/config.txt",
    "mahdibland": "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "Epodonios": "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "0xRadikal": "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
    "Rayan-Config": "https://raw.githubusercontent.com/Rayan-Config/C-Sub/refs/heads/main/configs/proxy.txt",
    "Hamedp-71": "https://raw.githubusercontent.com/hamedp-71/Sub_Checker_Creator/refs/heads/main/final.txt",
    "ConfigForge-V2Ray": "https://raw.githubusercontent.com/ShatakVPN/ConfigForge/main/configs/all.txt",
}

# GitHub repository details for raw links
GITHUB_USER = "hamedcode"
GITHUB_REPO = "port-based-v2ray-configs"
GITHUB_BRANCH = "main"
RAW_URL_BASE = f"https://raw.githubusercontent.com/{GITHUB_USER}/{GITHUB_REPO}/{GITHUB_BRANCH}"

COMMON_PORTS = [80, 443, 2053, 8880, 2087, 2096, 8443]
README_PATH = "README.md"
SUB_DIR = "sub"
DETAILED_DIR = "detailed"
RARE_PORTS_SUBDIR = "rare" # Name for the subdirectory for rare ports
RARE_PORT_THRESHOLD = 5 # Configs count threshold

PREFERRED = ["VLESS", "VMESS", "TROJAN", "SS", "OTHER"]

MARKERS = {
    "stats": ("<!-- START-STATS -->", "<!-- END-STATS -->"),
    "links": ("<!-- START-LINKS -->", "<!-- END-LINKS -->"),
    "sources": ("<!-- START-SOURCES -->", "<!-- END-SOURCES -->"),
    "liveness": ("<!-- START-LIVENESS -->", "<!-- END-LIVENESS -->"),
}

TOP100_FILENAME = "top100.txt"
CLASH_FILENAME = "clash.yaml"

# ---------------- Helpers ----------------
def safe_filename(s):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(s))

def parse_configs(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith(("vmess://", "vless://", "trojan://", "ss://")):
            out.append(line)
    return out

def extract_info(cfg):
    proto, port = None, None
    try:
        if cfg.startswith("vmess://"):
            proto = "VMESS"
            b64 = cfg[8:]
            dec = base64.b64decode(b64 + "=" * (-len(b64) % 4)).decode("utf-8", errors="ignore")
            data = json.loads(dec)
            port = str(data.get("port") or data.get("Port") or "")
        else:
            parsed = urlparse(cfg)
            scheme = (parsed.scheme or "").lower()
            if scheme in ["vless", "trojan", "ss"]:
                proto = scheme.upper()
            if parsed.port:
                port = str(parsed.port)
            elif "@" in parsed.netloc:
                host_part = parsed.netloc.rsplit("@", 1)[-1]
                if ":" in host_part:
                    p = host_part.rsplit(":", 1)[-1]
                    if p.isdigit():
                        port = p
    except Exception:
        return None, None
    return proto, port if port else None

def md_table_from_rows(header_cells, rows):
    header = "| " + " | ".join(header_cells) + " |"
    sep = "|" + "|".join(["---"] * len(header_cells)) + "|"
    body = "\n".join("| " + " | ".join(str(cell) for cell in row) + " |" for row in rows)
    return f"{header}\n{sep}\n{body}"

def html_table_from_rows(header_cells, rows):
    header_html = "<thead><tr>" + "".join(f"<th>{cell}</th>" for cell in header_cells) + "</tr></thead>"
    body_html = "<tbody>"
    for row in rows:
        body_html += "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
    body_html += "</tbody>"
    return f"<table>{header_html}{body_html}</table>"

def create_pp_sub_table(entries):
    if not entries:
        return ""
    
    table_body = "<tbody>"
    for i, item in enumerate(entries):
        style = ' style="border-top: 2px solid #d0d7de;"' if i > 0 and item["proto"] != entries[i-1]["proto"] else ''
        link = f'<a href="{item["url"]}">Sub</a>'
        table_body += f'<tr{style}><td>{item["proto"]}</td><td>{item["port"]}</td><td>{item["count"]}</td><td>{link}</td></tr>'
    table_body += "</tbody>"
    
    header = "<thead><tr><th>Protocol</th><th>Port</th><th>Count</th><th>Link</th></tr></thead>"
    return f"<table>{header}{table_body}</table>"

# ---------------- Main Logic ----------------
print("Fetching sources...")
all_items = []
source_counts = defaultdict(int)
for name, url in SOURCES.items():
    try:
        r = requests.get(url, timeout=25)
        r.raise_for_status()
        cfgs = parse_configs(r.text)
        for c in cfgs:
            all_items.append((c.strip(), name))
        source_counts[name] = len(cfgs)
        print(f"  Fetched {len(cfgs)} from {name}")
    except requests.RequestException as e:
        print(f"  Error fetching {name}: {e}")

total_fetched = len(all_items)
print(f"Total fetched: {total_fetched}")

if total_fetched == 0:
    print("\nERROR: No configs were fetched from any source. Aborting workflow.")
    sys.exit(1)

print("Deduplicating...")
seen = set()
for cfg, src in all_items:
    seen.add(cfg)
unique_count = len(seen)
print(f"Unique configs: {unique_count}, duplicates removed: {total_fetched - unique_count}")

# ---------------- Liveness — stage 1 (TCP, direct from runner) ----------------
# این عمداً *قبل* از نوشتنِ هر فایلی اجرا می‌شه: کانفیگ‌هایی که پورت‌شون
# اصلاً باز نیست اینجا حذف می‌شن و اصلاً وارد sub/ یا detailed/ نمی‌شن، نه
# اینکه فقط از top100 بیرون بمونن.
print("Running liveness stage 1 (TCP check, direct from runner)...")
alive_configs = run_tcp_stage(list(seen))
tcp_stable_count = len(alive_configs)
print(f"  {tcp_stable_count}/{unique_count} configs passed TCP; the rest are excluded from this repo entirely.")

print("Categorizing live configs...")
protocol_links = defaultdict(list)
port_links = defaultdict(list)
proto_port_links = defaultdict(lambda: defaultdict(list))
for cfg in alive_configs:
    proto, port = extract_info(cfg)
    key_proto = proto or "OTHER"
    key_port = port or "unknown"
    protocol_links[key_proto].append(cfg)
    port_links[key_port].append(cfg)
    proto_port_links[key_proto][key_port].append(cfg)

print("Cleaning up old directories...")
if os.path.exists(SUB_DIR):
    shutil.rmtree(SUB_DIR)
    print(f"  Removed directory: {SUB_DIR}")
if os.path.exists(DETAILED_DIR):
    shutil.rmtree(DETAILED_DIR)
    print(f"  Removed directory: {DETAILED_DIR}")

print("Writing subscription files...")
os.makedirs(SUB_DIR, exist_ok=True)
os.makedirs(os.path.join(SUB_DIR, RARE_PORTS_SUBDIR), exist_ok=True)
os.makedirs(DETAILED_DIR, exist_ok=True)

for group, links in protocol_links.items():
    with open(os.path.join(SUB_DIR, f"{safe_filename(group.lower())}.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(links))

for group, links in port_links.items():
    count = len(links)
    if count < RARE_PORT_THRESHOLD:
        target_dir = os.path.join(SUB_DIR, RARE_PORTS_SUBDIR)
    else:
        target_dir = SUB_DIR
    filepath = os.path.join(target_dir, f"port_{safe_filename(group)}.txt")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(links))

for proto, ports in proto_port_links.items():
    dirpath = os.path.join(DETAILED_DIR, safe_filename(proto.lower()))
    os.makedirs(dirpath, exist_ok=True)
    for port, links in ports.items():
        with open(os.path.join(dirpath, f"{safe_filename(port)}.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(links))

# ---------------- Liveness — stage 2+3 (WireGuard + xray-knife -> top100/clash) ----------------
print("Running liveness stage 2 (real test via WireGuard)...")
liveness_result = {}
try:
    liveness_result = run_l3_and_build(alive_configs)
except Exception as e:
    print(f"  WARNING: liveness L3 stage crashed, skipping top100/clash outputs: {e}")
    liveness_result = {
        "top_configs": [], "clash_yaml": "", "top100_txt": "",
        "l3_tested": False, "l3_alive_count": 0,
        "tunnel_used": None,
    }

if liveness_result.get("top100_txt"):
    with open(os.path.join(SUB_DIR, TOP100_FILENAME), "w", encoding="utf-8") as f:
        f.write(liveness_result["top100_txt"])
    print(f"  Wrote {SUB_DIR}/{TOP100_FILENAME} ({len(liveness_result['top_configs'])} configs)")

if liveness_result.get("clash_yaml"):
    with open(os.path.join(SUB_DIR, CLASH_FILENAME), "w", encoding="utf-8") as f:
        f.write(liveness_result["clash_yaml"])
    print(f"  Wrote {SUB_DIR}/{CLASH_FILENAME}")

print("Generating README content...")
protocols_all = sorted(protocol_links.keys(), key=lambda p: (PREFERRED.index(p) if p in PREFERRED else len(PREFERRED), p))
stats_table_md = md_table_from_rows(
    ["Protocol"] + [str(p) for p in COMMON_PORTS] + ["Total"],
    [[p] + [len(proto_port_links.get(p, {}).get(str(port), [])) for port in COMMON_PORTS] + [len(protocol_links.get(p, []))] for p in protocols_all]
)

port_table_rows = []
for p in COMMON_PORTS:
    count = len(port_links.get(str(p), []))
    if count > 0:
        if count < RARE_PORT_THRESHOLD:
            link_path = f"{SUB_DIR}/{RARE_PORTS_SUBDIR}/port_{p}.txt"
        else:
            link_path = f"{SUB_DIR}/port_{p}.txt"
        link = f"[Sub Link]({RAW_URL_BASE}/{link_path})"
        port_table_rows.append([p, count, link])

port_table_md = md_table_from_rows(
    ["Port", "Count", "Subscription Link"],
    port_table_rows
)

proto_table_md = md_table_from_rows(
    ["Protocol", "Count", "Subscription Link"],
    [[p, len(protocol_links.get(p, [])), f"[Sub Link]({RAW_URL_BASE}/{SUB_DIR}/{safe_filename(p.lower())}.txt)"] for p in protocols_all]
)

all_pp_entries = []
for proto in protocols_all:
    for p_int in COMMON_PORTS:
        p_str = str(p_int)
        count = len(proto_port_links.get(proto, {}).get(p_str, []))
        if count > 0:
            relative_path = f"{DETAILED_DIR}/{safe_filename(proto.lower())}/{safe_filename(p_str)}.txt"
            raw_url = f"{RAW_URL_BASE}/{relative_path}"
            all_pp_entries.append({"proto": proto, "port": p_str, "count": count, "url": raw_url})

pp_table_html = ""
if all_pp_entries:
    split_index = math.ceil(len(all_pp_entries) / 2.0)
    left_col = all_pp_entries[:split_index]
    right_col = all_pp_entries[split_index:]
    left_table_html = create_pp_sub_table(left_col)
    right_table_html = create_pp_sub_table(right_col)
    pp_table_html = f"""
<table width="100%" style="border: none; border-collapse: collapse;">
  <tr style="background-color: transparent;">
    <td width="50%" valign="top" style="border: none; padding-right: 10px;">
      {left_table_html}
    </td>
    <td width="50%" valign="top" style="border: none; padding-left: 10px;">
      {right_table_html}
    </td>
  </tr>
</table>
"""
else:
    pp_table_html = "_No specific protocol-port combinations found for common ports._"

sources_rows = sorted(source_counts.items())
summary_rows = [
    ["Total Fetched", total_fetched],
    ["Unique Configs", unique_count],
    ["Duplicates Removed", total_fetched - unique_count],
    ["Published (passed TCP check)", tcp_stable_count],
]
sources_table_html = html_table_from_rows(["Source", "Fetched Lines"], sources_rows)
summary_table_html = html_table_from_rows(["Metric", "Value"], summary_rows)
side_by_side_html = f"""
<table width="100%" style="border: none; border-collapse: collapse;">
  <tr style="background-color: transparent;">
    <td width="50%" valign="top" style="border: none; padding-right: 10px;">
      <h4>Sources</h4>
      {sources_table_html}
    </td>
    <td width="50%" valign="top" style="border: none; padding-left: 10px;">
      <h4>Summary</h4>
      {summary_table_html}
    </td>
  </tr>
</table>
"""

# --- CHANGED BLOCK START ---
# Create a timezone for GMT+3:30 (Iran Standard Time)
iran_tz = timezone(timedelta(hours=3, minutes=30))
# Get current time in UTC and convert it to Iran's timezone
now_ts = datetime.now(timezone.utc).astimezone(iran_tz).strftime("%Y-%m-%d %H:%M:%S GMT+3:30")
# --- CHANGED BLOCK END ---

stats_block = f"{MARKERS['stats'][0]}\n_Last update: {now_ts}_\n\n{stats_table_md}\n{MARKERS['stats'][1]}"
links_block = f"{MARKERS['links'][0]}\n### By Port\n{port_table_md}\n\n### By Protocol\n{proto_table_md}\n\n### By Protocol & Port (Common Ports)\n{pp_table_html}\n{MARKERS['links'][1]}"
sources_block = f"{MARKERS['sources'][0]}\n{side_by_side_html}\n{MARKERS['sources'][1]}"

# --- Liveness block ---
_unique_count = len(seen)
_tcp_stable = tcp_stable_count
_l3_tested = liveness_result.get("l3_tested", False)
_l3_alive = liveness_result.get("l3_alive_count", 0)
_tunnel = liveness_result.get("tunnel_used")

_tcp_pct = f"{(_tcp_stable / _unique_count * 100):.1f}%" if _unique_count else "0%"

if _l3_tested:
    _method_line = f"Real proxy test via WireGuard tunnel `{_tunnel}` (xray-knife)"
    _stage2_value = f"{_l3_alive} ({(_l3_alive / _tcp_stable * 100):.1f}% of stage 1)" if _tcp_stable else "0"
else:
    _method_line = "WireGuard tunnel unavailable this run — stage 2 did not run (fallback: TCP-only ranking used)"
    _stage2_value = "0 (did not run)"

_liveness_rows = [
    ["Unique configs checked", _unique_count],
    ["Stage 1 — TCP-stable (3 rounds)", f"{_tcp_stable} ({_tcp_pct})"],
    ["Stage 2 — Passed real test via WireGuard", _stage2_value],
]

liveness_table_md = md_table_from_rows(["Stage", "Result"], _liveness_rows)

_top100_link = f"[top100.txt]({RAW_URL_BASE}/{SUB_DIR}/{TOP100_FILENAME})"
_clash_link = f"[clash.yaml]({RAW_URL_BASE}/{SUB_DIR}/{CLASH_FILENAME})"

liveness_block = (
    f"{MARKERS['liveness'][0]}\n"
    f"**Method:** {_method_line}\n\n"
    f"{liveness_table_md}\n"
    f"\n- {_top100_link}\n"
    f"- {_clash_link}\n"
    f"{MARKERS['liveness'][1]}"
)

print("Updating README.md...")
try:
    with open(README_PATH, "r", encoding="utf-8") as f:
        readme_text = f.read()

    print("--- Checking for markers in README.md ---")
    for key, (start_marker, _) in MARKERS.items():
        if start_marker in readme_text:
            print(f"  [SUCCESS] Found '{start_marker}' for section '{key}'.")
        else:
            print(f"  [FAILURE] Could NOT find '{start_marker}' for section '{key}'.")
    print("-----------------------------------------")

    readme_text = re.sub(f"{re.escape(MARKERS['stats'][0])}.*?{re.escape(MARKERS['stats'][1])}", stats_block, readme_text, flags=re.S)
    readme_text = re.sub(f"{re.escape(MARKERS['links'][0])}.*?{re.escape(MARKERS['links'][1])}", links_block, readme_text, flags=re.S)
    readme_text = re.sub(f"{re.escape(MARKERS['sources'][0])}.*?{re.escape(MARKERS['sources'][1])}", sources_block, readme_text, flags=re.S)
    if MARKERS['liveness'][0] in readme_text:
        readme_text = re.sub(f"{re.escape(MARKERS['liveness'][0])}.*?{re.escape(MARKERS['liveness'][1])}", liveness_block, readme_text, flags=re.S)
    else:
        # اگه مارکرِ liveness توی README قدیمی نبود، بعد از بلوکِ sources اضافه‌اش می‌کنیم
        readme_text = readme_text.replace(
            MARKERS['sources'][1],
            f"{MARKERS['sources'][1]}\n\n## \U0001F7E2 Live Configs (Tested)\n{liveness_block}",
        )
    
    with open(README_PATH, "w", encoding="utf-8") as f:
        f.write(readme_text)
    
    print("README updated successfully.")

except FileNotFoundError:
    print(f"ERROR: {README_PATH} not found. Please create it using the provided template.")
    sys.exit(1)
except Exception as e:
    print(f"An error occurred while updating README: {e}")
    sys.exit(1)
