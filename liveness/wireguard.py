#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
liveness/wireguard.py — مرحله ۲: تونل وایرگارد + network namespace + failover

چرا namespace: اگه wg0 رو مستقیم default route بکنیم، کل ترافیک runner
(از جمله git push و دانلود سورس‌ها) هم از تونل رد می‌شه که نه لازمه و نه
امنه (ممکنه سرعت/پایداری این کارها رو خراب کنه). به‌جاش یه network namespace
جدا می‌سازیم، wg0 رو فقط داخل همون namespace بالا می‌بریم و default route
namespace رو می‌ذاریم روی wg0. فقط دستوری که با `ip netns exec` اجرا بشه از
تونل رد می‌شه؛ بقیه‌ی runner دست‌نخورده می‌مونه.

فرمتِ سکرت WG_CONFIGS (چند کانفیگ، برای failover):

    ### NAME: proton-nl
    [Interface]
    PrivateKey = ...
    Address = 10.x.x.x/32
    DNS = 10.x.x.x

    [Peer]
    PublicKey = ...
    Endpoint = xx.xx.xx.xx:51820
    AllowedIPs = 0.0.0.0/0

    ### NAME: proton-us
    [Interface]
    ...

هر بلوک با `### NAME: <چیزی>` شروع می‌شه؛ خودِ اون خط جزوِ فایل .conf نیست،
فقط برای لاگ استفاده می‌شه.
"""

import os
import re
import subprocess
import tempfile
import time

NS_NAME = "wgtest"
WG_IFACE = "wg0"
HEALTH_URL = "https://cp.cloudflare.com/generate_204"


class WireGuardError(RuntimeError):
    pass


def parse_wg_configs_secret(secret_text: str):
    """
    سکرت WG_CONFIGS رو به لیستی از (name, conf_text) می‌شکنه.
    اگه هیچ `### NAME:` نبود، کل متن رو به‌عنوان یه کانفیگ تک (name="default")
    برمی‌گردونه (سازگاری با حالتی که کاربر فقط یه سرور داره).
    """
    secret_text = secret_text.strip()
    if not secret_text:
        return []

    blocks = re.split(r"^###\s*NAME:\s*(.+)$", secret_text, flags=re.M)
    # re.split با گروه، لیست رو به شکل [pre, name1, body1, name2, body2, ...] می‌ده
    if len(blocks) == 1:
        # هیچ مارکری پیدا نشد
        return [("default", secret_text)]

    configs = []
    # blocks[0] معمولاً متن خالی قبل از اولین مارکره؛ نادیده گرفته می‌شه.
    for i in range(1, len(blocks), 2):
        name = blocks[i].strip()
        body = blocks[i + 1].strip() if i + 1 < len(blocks) else ""
        if body:
            configs.append((name, body))
    return configs


def _run(cmd, check=True, capture=False, timeout=None):
    return subprocess.run(
        cmd,
        check=check,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        timeout=timeout,
        text=True,
    )


def netns_exists():
    r = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
    return NS_NAME in r.stdout


def teardown_namespace(verbose=True):
    """namespace و اینترفیس wg رو (اگه وجود داشت) پاک می‌کنه. بی‌خطر برای تکرار."""
    if netns_exists():
        subprocess.run(["sudo", "ip", "netns", "delete", NS_NAME], check=False)
        if verbose:
            print(f"[wireguard] namespace {NS_NAME} پاک شد")


def _write_conf(name, body):
    fd, path = tempfile.mkstemp(prefix=f"wg_{re.sub(r'[^A-Za-z0-9_-]', '_', name)}_", suffix=".conf")
    with os.fdopen(fd, "w") as f:
        f.write(body + "\n")
    os.chmod(path, 0o600)
    return path


def bring_up_one(name, conf_body, verbose=True, health_timeout=8):
    """
    یه namespace جدید می‌سازه، wg0 رو داخلش با این کانفیگ بالا می‌بره، و
    health-check می‌زنه. اگه موفق بود True برمی‌گردونه (namespace رو نگه
    می‌داره)؛ اگه شکست خورد، namespace رو پاک می‌کنه و False برمی‌گردونه.
    """
    teardown_namespace(verbose=False)
    conf_path = _write_conf(name, conf_body)

    try:
        if verbose:
            print(f"[wireguard] تلاش برای بالا آوردن تونل «{name}»...")

        _run(["sudo", "ip", "netns", "add", NS_NAME])
        # loopback داخل namespace لازمه وگرنه بعضی ابزارها گیر می‌کنن
        _run(["sudo", "ip", "netns", "exec", NS_NAME, "ip", "link", "set", "lo", "up"])

        # wg-quick از namespace فعلی می‌خونه نه از namespace هدف، پس دستی
        # اینترفیس رو می‌سازیم و بعد می‌بریمش داخل namespace.
        _run(["sudo", "ip", "link", "add", WG_IFACE, "type", "wireguard"])
        _run(["sudo", "ip", "link", "set", WG_IFACE, "netns", NS_NAME])

        # تنظیم کلید/پیر با wg syncconf داخل namespace
        # (wg-quick معادلِ دستیِ ساده: setconf + address + route + دی‌ان‌اس)
        address, dns = _extract_interface_fields(conf_body)
        stripped_conf = _strip_interface_extra_fields(conf_body)
        stripped_path = _write_conf(name + "_stripped", stripped_conf)

        _run(["sudo", "ip", "netns", "exec", NS_NAME,
              "wg", "setconf", WG_IFACE, stripped_path])

        if address:
            _run(["sudo", "ip", "netns", "exec", NS_NAME,
                  "ip", "address", "add", address, "dev", WG_IFACE])

        _run(["sudo", "ip", "netns", "exec", NS_NAME,
              "ip", "link", "set", WG_IFACE, "up"])
        _run(["sudo", "ip", "netns", "exec", NS_NAME,
              "ip", "route", "add", "default", "dev", WG_IFACE])

        os.remove(stripped_path)

        # health check: یه درخواست HTTP سریع از داخل namespace
        ok = health_check(timeout=health_timeout)
        if ok:
            if verbose:
                print(f"[wireguard] تونل «{name}» سالمه ✓")
            return True
        else:
            if verbose:
                print(f"[wireguard] تونل «{name}» health-check رو رد نشد ✗")
            teardown_namespace(verbose=verbose)
            return False

    except subprocess.CalledProcessError as e:
        if verbose:
            print(f"[wireguard] تونل «{name}» شکست خورد در راه‌اندازی: {e}")
        teardown_namespace(verbose=verbose)
        return False
    finally:
        try:
            os.remove(conf_path)
        except OSError:
            pass


def _extract_interface_fields(conf_body):
    address = None
    dns = None
    for line in conf_body.splitlines():
        line = line.strip()
        if line.lower().startswith("address"):
            address = line.split("=", 1)[1].strip()
        elif line.lower().startswith("dns"):
            dns = line.split("=", 1)[1].strip()
    return address, dns


def _strip_interface_extra_fields(conf_body):
    """
    `wg setconf` فقط بخش [Interface] با PrivateKey/ListenPort/FwMark و
    [Peer] رو می‌فهمه؛ Address/DNS رو نمی‌شناسه و باهاشون ارور می‌ده.
    این تابع اون خط‌ها رو حذف می‌کنه (چون جدا با `ip address add` تنظیم
    می‌شن).
    """
    out = []
    for line in conf_body.splitlines():
        stripped = line.strip().lower()
        if stripped.startswith("address") or stripped.startswith("dns"):
            continue
        out.append(line)
    return "\n".join(out)


def health_check(timeout=8):
    """از داخل namespace یه curl سریع به یه آدرس شناخته‌شده می‌زنه."""
    try:
        r = subprocess.run(
            ["sudo", "ip", "netns", "exec", NS_NAME,
             "curl", "-fsS", "--max-time", str(timeout), "-o", "/dev/null",
             "-w", "%{http_code}", HEALTH_URL],
            capture_output=True, text=True, timeout=timeout + 5,
        )
        return r.returncode == 0 and r.stdout.strip() in ("200", "204")
    except Exception:
        return False


def bring_up_with_failover(wg_configs_secret: str, verbose=True):
    """
    سکرت WG_CONFIGS رو پارس می‌کنه و به ترتیب کانفیگ‌ها رو امتحان می‌کنه تا
    یکی سالم بالا بیاد. اسم تونلِ موفق رو برمی‌گردونه، یا None اگه هیچ‌کدوم
    کار نکردن.
    """
    configs = parse_wg_configs_secret(wg_configs_secret)
    if not configs:
        if verbose:
            print("[wireguard] سکرت WG_CONFIGS خالیه یا پارس نشد")
        return None

    if verbose:
        print(f"[wireguard] {len(configs)} کانفیگ وایرگارد پیدا شد: {', '.join(n for n, _ in configs)}")

    for name, body in configs:
        if bring_up_one(name, body, verbose=verbose):
            return name

    if verbose:
        print("[wireguard] هیچ‌کدوم از تونل‌ها بالا نیومدن")
    return None


def ensure_alive_or_failover(wg_configs_secret: str, current_name: str, verbose=True):
    """
    اگه تونل فعلی هنوز سالمه، همون‌جوری برمی‌گردونه؛ وگرنه بقیه‌ی
    کانفیگ‌ها رو (به‌جز اونی که الان قطع شده) امتحان می‌کنه.
    برای صدا زدن بینِ batch های تست، وسط یه اجرای طولانی.
    """
    if health_check(timeout=6):
        return current_name

    if verbose:
        print(f"[wireguard] تونل «{current_name}» قطع شد، failover به کانفیگ بعدی...")

    configs = parse_wg_configs_secret(wg_configs_secret)
    remaining = [c for c in configs if c[0] != current_name]
    for name, body in remaining:
        if bring_up_one(name, body, verbose=verbose):
            return name

    return None


def teardown(verbose=True):
    teardown_namespace(verbose=verbose)


def netns_exec_prefix():
    """پیشوندِ دستور برای اجرای هر چیزی از داخل تونل (برای xray_knife_test.py)."""
    return ["sudo", "ip", "netns", "exec", NS_NAME]
