import requests
import base64
import json
import os
import re
import socket
import time
import concurrent.futures
from collections import defaultdict
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime, timezone, timedelta

# === منابع کانفیگ ===
SOURCES = {
    "barry-far": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    "mahdibland": "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "Epodonios": "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "soroushmirzaei": "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/mixed"
}

# === آدرس مخازن منابع برای لینک‌دهی ===
SOURCE_REPOS = {
    "barry-far": "https://github.com/barry-far/V2ray-Config",
    "mahdibland": "https://github.com/mahdibland/V2RayAggregator",
    "Epodonios": "https://github.com/Epodonios/v2ray-configs",
    "soroushmirzaei": "https://github.com/soroushmirzaei/telegram-configs-collector"
}

# === پارامترهای دسته‌بندی و تست ===
FAMOUS_PORTS = {'80', '443', '8080', '8088', '2052', '2053', '2082', '2083', '2086', '2087', '2095', '2096'}
GITHUB_REPO = os.environ.get('GITHUB_REPOSITORY', 'hamed1124/port-based-v2ray-configs')
MAX_WORKERS = 100
CONNECTION_TIMEOUT = 3


def fetch_all_configs_parallel(sources_dict):
    """کانفیگ‌ها را از تمام منابع به صورت موازی دریافت می‌کند."""
    raw_configs_list, source_stats = [], defaultdict(int)
    print("شروع دریافت موازی کانفیگ از تمام منابع...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_source = {executor.submit(requests.get, url, timeout=120): url for url in sources_dict.values()}
        
        for future in concurrent.futures.as_completed(future_to_source):
            try:
                response = future.result()
                if response.status_code == 200 and response.text:
                    name = [k for k, v in sources_dict.items() if v == response.url][0]
                    content = response.text.strip()
                    if len(content) > 1000 and "://" not in content:
                        content = base64.b64decode(content).decode('utf-8')
                    
                    configs = content.strip().split('\n')
                    valid_configs = [line.strip() for line in configs if line.strip() and '://' in line]
                    if valid_configs:
                        raw_configs_list.extend(valid_configs)
                        source_stats[name] = len(valid_configs)
                        print(f"  ✅ {len(valid_configs)} کانفیگ معتبر از {name} دریافت شد.")
            except Exception as e:
                print(f"- خطایی در هنگام دریافت یا پردازش یک منبع رخ داد: {e}")

    raw_total = len(raw_configs_list)
    unique_configs = list(set(raw_configs_list))
    print(f"\nتعداد کل کانفیگ‌های خام دریافت شده: {raw_total}. تعداد کانفیگ‌های منحصر به فرد: {len(unique_configs)}.")
    return unique_configs, source_stats, raw_total

def get_config_info(link):
    """اطلاعات کامل را از لینک کانفیگ استخراج می‌کند."""
    try:
        parsed_url = urlparse(link)
        protocol = parsed_url.scheme.lower()
        host = parsed_url.hostname
        port = str(parsed_url.port)
        name = unquote(parsed_url.fragment)

        return protocol, host, port, name
    except Exception:
        return None, None, None, None

def test_config_connection(config_link):
    """یک کانفیگ را با تست اتصال TCP پینگ می‌کند و زمان پاسخ را برمی‌گرداند."""
    _, host, port, _ = get_config_info(config_link)
    if not host or not port:
        return config_link, float('inf')
    
    try:
        start_time = time.time()
        with socket.create_connection((host, int(port)), timeout=CONNECTION_TIMEOUT):
            end_time = time.time()
            latency = (end_time - start_time) * 1000
            return config_link, latency
    except (socket.timeout, socket.error, OSError, ValueError):
        return config_link, float('inf')

def test_all_configs_parallel(configs):
    """تمام کانفیگ‌ها را به صورت موازی تست می‌کند و نتایج را برمی‌گرداند."""
    print(f"\nشروع تست {len(configs)} کانفیگ منحصر به فرد...")
    all_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_config = {executor.submit(test_config_connection, config): config for config in configs}
        
        for i, future in enumerate(concurrent.futures.as_completed(future_to_config), 1):
            try:
                result = future.result()
                all_results.append(result)
            except Exception as e:
                print(f"خطا در اجرای تست برای یک کانفیگ: {e}")

            print(f"\rتست شده: {i}/{len(configs)}", end="")

    all_results.sort(key=lambda x: x[1])
    live_results = [res for res in all_results if res[1] != float('inf')]
    dead_configs = [res[0] for res in all_results if res[1] == float('inf')]
    
    print(f"\n✅ تست کامل شد. {len(live_results)} کانفیگ فعال و {len(dead_configs)} کانفیگ غیرفعال پیدا شد.")
    return live_results, dead_configs

def get_tehran_time():
    tehran_tz = timezone(timedelta(hours=3, minutes=30))
    now_tehran = datetime.now(timezone.utc).astimezone(tehran_tz)
    return now_tehran.strftime("%Y-%m-%d %H:%M:%S Tehran Time")

def build_readme_content(stats):
    """محتوای کامل README را با آمار جدید می‌سازد."""
    print("\nBuilding README content...")
    
    detailed_stats = stats.get('detailed_stats', {})
    protocol_totals = {p: sum(len(cfgs) for cfgs in data.values()) for p, data in detailed_stats.items()}
    sorted_protocols = sorted(protocol_totals.keys(), key=lambda p: protocol_totals[p], reverse=True)
    port_totals = {port: sum(len(detailed_stats.get(p, {}).get(port, [])) for p in sorted_protocols) for port in FAMOUS_PORTS}
    sorted_ports = sorted(port_totals.keys(), key=lambda p: port_totals[p], reverse=True)
    
    stats_table_lines = []
    header = "| Protocol | " + " | ".join(sorted_ports) + " | Other Ports | Total |"
    separator = "|:---| " + " | ".join([":---:" for _ in sorted_ports]) + " |:---:|:---:|"
    stats_table_lines.extend([header, separator])
    total_other_ports = 0
    for proto in sorted_protocols:
        row = [f"| {proto.capitalize()}"]
        famous_ports_sum = 0
        for port in sorted_ports:
            count = len(detailed_stats.get(proto, {}).get(port, []))
            row.append(str(count))
            famous_ports_sum += count
        other_ports_count = protocol_totals[proto] - famous_ports_sum
        total_other_ports += other_ports_count
        row.append(str(other_ports_count))
        row.append(f"**{protocol_totals[proto]}**")
        stats_table_lines.append(" | ".join(row) + " |")
    footer = ["| **Total**", *[f"**{port_totals[port]}**" for port in sorted_ports], f"**{total_other_ports}**", f"**{sum(protocol_totals.values())}**"]
    stats_table_lines.append(" | ".join(footer) + " |")
    stats_table_string = "\n".join(stats_table_lines)
    
    protocol_links_string = "\n\n".join([f"- **{proto.capitalize()}:**\n  https://raw.githubusercontent.com/{GITHUB_REPO}/main/sub/protocols/{proto}.txt" for proto in sorted_protocols])
    port_links_string = "\n\n".join([f"- **Port {port}:**\n  https://raw.githubusercontent.com/{GITHUB_REPO}/main/sub/{port}.txt" for port in sorted_ports])

    source_stats_lines = []
    summary_lines = [
        f"**Total Fetched (Raw):** {stats['raw_total']}",
        f"**Duplicates Removed:** {stats['duplicates_removed']}",
        "---",
        f"**Unique Configs Tested:** {stats['tested_configs']}",
        f"**Working Configs Found:** {stats['live_configs']}",
    ]
    details_lines = [f"**[{name}]({SOURCE_REPOS.get(name, '#')}):** {count} configs" for name, count in sorted(stats['source_stats'].items(), key=lambda item: item[1], reverse=True)]
    source_stats_lines.extend(["| Summary | Source Details |", "|:---|:---|"])
    max_len = max(len(summary_lines), len(details_lines))
    for i in range(max_len):
        left_col = summary_lines[i] if i < len(summary_lines) else ""
        right_col = details_lines[i] if i < len(details_lines) else ""
        source_stats_lines.append(f"| {left_col} | {right_col} |")
    source_stats_string = "\n".join(source_stats_lines)
    
    test_results_links = f"""- **Top 200 (by Ping, US & NA excluded):** `https://raw.githubusercontent.com/{GITHUB_REPO}/main/test-results/top_200_ping.txt`
- **Dead Configs:** `https://raw.githubusercontent.com/{GITHUB_REPO}/main/test-results/dead_configs.txt`"""
    
    final_readme = f"""# Config Collector

[![Auto-Update Status](https://github.com/hamed1124/port-based-v2ray-configs/actions/workflows/main.yml/badge.svg)](https://github.com/hamed1124/port-based-v2ray-configs/actions/workflows/main.yml)

An automated repository that collects and categorizes free V2Ray/Clash configurations from reputable sources with advanced classification.

---

### 📊 Live Statistics

**Last Updated:** {stats['update_time']}

**Total Unique Configurations (Working):** {stats['total_configs']}

{stats_table_string}

---

### 🚀 Subscription Links

#### By Protocol

{protocol_links_string}

#### By Famous Ports

{port_links_string}

---

### 🧪 Test Results
*Note: The Top 200 list is sorted by the lowest ping and excludes US & NA-based servers for better performance in most regions.*

{test_results_links}

---

### 📚 Sources

{source_stats_string}
"""
    return final_readme


def main():
    unique_configs, source_stats, raw_total = fetch_all_configs_parallel(SOURCES)
    if not unique_configs:
        print("\nNo configs found. Exiting.")
        return

    live_results, dead_configs = test_all_configs_parallel(unique_configs)
    
    # --- *** منطق جدید برای فیلتر کردن US و NA *** ---
    print("\nFiltering out US & NA-based servers from the top list...")
    excluded_identifiers = [' us', '.us', '-us', '_us', 'united states', '🇺🇸', ' na', '.na', '-na', '_na', 'not available']
    
    filtered_live_configs = []
    for config, latency in live_results:
        # برای فیلتر کردن فقط به نام کانفیگ نیاز داریم
        _, _, _, name = get_config_info(config)
        
        is_excluded = False
        if name: # اطمینان از اینکه نام وجود دارد
            for identifier in excluded_identifiers:
                if identifier in name.lower():
                    is_excluded = True
                    break
        
        if not is_excluded:
            filtered_live_configs.append(config)
            
    # ساخت لیست ۲۰۰تای برتر از کانفیگ‌های فیلتر شده
    top_200_configs = filtered_live_configs[:200]
    print(f"Generated a top list of {len(top_200_configs)} configs (US & NA excluded).")

    # لیست کلی کانفیگ‌های فعال (شامل همه کشورها) برای بقیه فایل‌ها استفاده می‌شود
    live_configs = [res[0] for res in live_results]
    
    print("\nWriting test result files...")
    os.makedirs('test-results', exist_ok=True)
    with open('test-results/dead_configs.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(dead_configs))
    with open('test-results/top_200_ping.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(top_200_configs))
    print("✅ Test result files created successfully.")
    
    if not live_configs:
        print("\nNo working configs found after testing. Exiting.")
        stats = {
            "total_configs": 0, "raw_total": raw_total, "duplicates_removed": raw_total - len(unique_configs),
            "tested_configs": len(unique_configs), "live_configs": 0, "update_time": get_tehran_time(),
            "source_stats": source_stats, "detailed_stats": {}
        }
        final_readme_content = build_readme_content(stats)
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(final_readme_content)
        return

    print("\nCategorizing all working configurations...")
    categorized_by_protocol_and_port = defaultdict(lambda: defaultdict(list))
    for config_link in live_configs:
        protocol, _, port, _ = get_config_info(config_link)
        if protocol and port:
            categorized_by_protocol_and_port[protocol][port].append(config_link)

    print("\nWriting all subscription files based on working configs...")
    os.makedirs('sub/protocols', exist_ok=True)
    with open('sub/all.txt', 'w', encoding='utf-8') as f: f.write('\n'.join(live_configs))
    for protocol, ports_data in categorized_by_protocol_and_port.items():
        all_protocol_configs = [cfg for cfgs in ports_data.values() for cfg in cfgs]
        with open(f'sub/protocols/{protocol}.txt', 'w', encoding='utf-8') as f: f.write('\n'.join(all_protocol_configs))
    for port in FAMOUS_PORTS:
        port_configs = [cfg for p_data in categorized_by_protocol_and_port.values() for p, cfgs in p_data.items() if p == port for cfg in cfgs]
        if port_configs:
            with open(f'sub/{port}.txt', 'w', encoding='utf-8') as f: f.write('\n'.join(port_configs))
    detailed_folder = 'detailed'
    os.makedirs(detailed_folder, exist_ok=True)
    for protocol, ports_data in categorized_by_protocol_and_port.items():
        protocol_folder = os.path.join(detailed_folder, protocol)
        os.makedirs(protocol_folder, exist_ok=True)
        other_ports_folder = os.path.join(protocol_folder, 'other_ports')
        has_other_ports = False
        for port, configs in ports_data.items():
            file_path = os.path.join(protocol_folder, f'{port}.txt') if port in FAMOUS_PORTS else os.path.join(other_ports_folder, f'{port}.txt')
            if port not in FAMOUS_PORTS and not has_other_ports:
                os.makedirs(other_ports_folder, exist_ok=True)
                has_other_ports = True
            with open(file_path, 'w', encoding='utf-8') as f: f.write('\n'.join(configs))
    print("✅ All subscription files written successfully.")

    stats = {
        "total_configs": len(live_configs),
        "raw_total": raw_total,
        "duplicates_removed": raw_total - len(unique_configs),
        "tested_configs": len(unique_configs),
        "live_configs": len(live_configs),
        "update_time": get_tehran_time(),
        "source_stats": source_stats,
        "detailed_stats": categorized_by_protocol_and_port
    }
    
    final_readme_content = build_readme_content(stats)
    
    with open('README.md', 'w', encoding='utf-8') as f:
        f.write(final_readme_content)
    print("✅ README.md updated successfully with advanced filtering.")

    print("\n🎉 Project update finished successfully.")

if __name__ == "__main__":
    main()
