#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
liveness/clash_builder.py — انتخابِ top100 و ساختِ clash.yaml (فقط برای همون ۱۰۰ تا)

ورودی: dict {cfg: delay_ms} (خروجیِ xray_knife_test.run_real_test، یعنی
فقط کانفیگ‌هایی که واقعاً کار کردن). خروجی: لیستِ ۱۰۰ تای اول به‌ترتیبِ
تأخیر، و یه رشته‌ی YAML سازگار با Clash/Mihomo.
"""

import base64
import json
from urllib.parse import urlparse, parse_qs, unquote

try:
    import yaml
except ImportError:
    yaml = None


def get_top_n(delay_map: dict, n=100):
    """
    ورودی: dict {cfg: delay_ms}. خروجی: لیستِ (cfg, delay_ms) به ترتیبِ
    صعودیِ تأخیر، حداکثر n تا.
    """
    ordered = sorted(delay_map.items(), key=lambda kv: kv[1])
    return ordered[:n]


def _config_to_clash_proxy(cfg: str, name: str):
    """یه لینک vmess/vless/trojan/ss رو به dict فرمتِ Clash تبدیل می‌کنه."""
    try:
        if cfg.startswith("vmess://"):
            b64 = cfg[8:]
            dec = base64.b64decode(b64 + "=" * (-len(b64) % 4)).decode("utf-8", errors="ignore")
            d = json.loads(dec)
            net = d.get("net", "tcp")
            proxy = {
                "name": name,
                "type": "vmess",
                "server": d.get("add"),
                "port": int(d.get("port")),
                "uuid": d.get("id"),
                "alterId": int(d.get("aid", 0) or 0),
                "cipher": "auto",
                "tls": d.get("tls") == "tls",
                "network": net,
                "udp": True,
            }
            if net == "ws":
                proxy["ws-opts"] = {
                    "path": d.get("path", "/") or "/",
                    "headers": {"Host": d.get("host", "") or d.get("add", "")},
                }
            elif net == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": d.get("path", "") or ""}
            if proxy["tls"] and d.get("sni"):
                proxy["servername"] = d.get("sni")
            return proxy

        parsed = urlparse(cfg)
        qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            return None

        if cfg.startswith("vless://"):
            security = qs.get("security", "")
            net = qs.get("type", "tcp")
            proxy = {
                "name": name,
                "type": "vless",
                "server": host,
                "port": port,
                "uuid": parsed.username,
                "tls": security in ("tls", "reality"),
                "network": net,
                "udp": True,
            }
            if qs.get("sni"):
                proxy["servername"] = qs["sni"]
            if qs.get("fp"):
                proxy["client-fingerprint"] = qs["fp"]
            if security == "reality":
                proxy["reality-opts"] = {
                    "public-key": qs.get("pbk", ""),
                    "short-id": qs.get("sid", ""),
                }
            if net == "ws":
                proxy["ws-opts"] = {
                    "path": qs.get("path", "/"),
                    "headers": {"Host": qs.get("host", host)},
                }
            elif net == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": qs.get("serviceName", "")}
            return proxy

        if cfg.startswith("trojan://"):
            proxy = {
                "name": name,
                "type": "trojan",
                "server": host,
                "port": port,
                "password": parsed.username,
                "udp": True,
            }
            if qs.get("sni"):
                proxy["sni"] = qs["sni"]
            if qs.get("allowInsecure") == "1":
                proxy["skip-cert-verify"] = True
            net = qs.get("type", "tcp")
            if net == "ws":
                proxy["network"] = "ws"
                proxy["ws-opts"] = {
                    "path": qs.get("path", "/"),
                    "headers": {"Host": qs.get("host", host)},
                }
            return proxy

        if cfg.startswith("ss://"):
            userinfo = parsed.username
            password = parsed.password
            method = None
            if password is None and userinfo:
                try:
                    dec = base64.urlsafe_b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode()
                    method, password = dec.split(":", 1)
                except Exception:
                    return None
            else:
                method = userinfo
            if not method or password is None:
                return None
            return {
                "name": name,
                "type": "ss",
                "server": host,
                "port": port,
                "cipher": method,
                "password": password,
                "udp": True,
            }

    except Exception:
        return None
    return None


def build_clash_yaml(top_configs, header_comment=""):
    """
    top_configs: لیستِ (cfg, delay_ms) — خروجیِ get_top_n.
    برمی‌گردونه: رشته‌ی YAML آماده برای نوشتن توی sub/clash.yaml.
    """
    if yaml is None:
        raise RuntimeError("pyyaml نصب نیست؛ به requirements.txt اضافه کن: pyyaml")

    proxies = []
    names = []
    seen_names = set()

    for idx, (cfg, delay_ms) in enumerate(top_configs, start=1):
        base_name = f"cfg-{idx:03d}"
        name = base_name
        # جلوگیری از تکراری شدن اسم (Clash نیاز داره اسم‌ها یکتا باشن)
        suffix = 1
        while name in seen_names:
            suffix += 1
            name = f"{base_name}-{suffix}"
        seen_names.add(name)

        proxy = _config_to_clash_proxy(cfg, name)
        if proxy and proxy.get("server") and proxy.get("port"):
            proxies.append(proxy)
            names.append(name)

    doc = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["AUTO"] + names},
            {
                "name": "AUTO",
                "type": "url-test",
                "proxies": names,
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
            },
        ],
        "rules": ["MATCH,PROXY"],
    }

    body = yaml.dump(doc, allow_unicode=True, sort_keys=False)
    if header_comment:
        body = header_comment.rstrip() + "\n" + body
    return body


def build_top100_txt(top_configs):
    """فایلِ متنیِ ساده (یه لینک در هر خط) برای sub/top100.txt."""
    return "\n".join(cfg for cfg, _ in top_configs)
