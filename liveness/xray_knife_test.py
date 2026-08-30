#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
liveness/xray_knife_test.py — مرحله ۳: تست واقعیِ پروکسی با xray-knife

این ماژول xray-knife رو *داخل* network namespace ای که wireguard.py ساخته
اجرا می‌کنه (با `ip netns exec`)، پس تمام ترافیکِ تستِ واقعی از IP پروتون
خارج می‌شه، نه IP ران‌ر گیت‌هاب.

xray-knife زیرفرمانِ `http` رو می‌گیره: یه فایلِ متنی از کانفیگ‌ها (هر خط
یه لینک)، به هرکدوم وصل می‌شه، از توش یه درخواستِ HTTP به یه URL تست می‌زنه،
و نتیجه (وضعیت + تأخیر) رو توی یه CSV می‌نویسه.

پارامترهای پیش‌فرض (threads/timeout/test-url) از تجربه‌ی سنجیده‌شده‌ی
پروژه‌ی مرجع اقتباس شدن (نه حدسی): timeout صریح چون پیش‌فرضِ ابزار بی‌مهلته
و روی CI خطرناکه، و URL تست هم صریح چون پیش‌فرضِ نسخه‌های مختلفِ ابزار
فرق می‌کنه.
"""

import csv
import io
import os
import shutil
import subprocess
import tempfile

DEFAULT_TEST_URL = "https://cp.cloudflare.com/generate_204"
DEFAULT_THREADS = 100
DEFAULT_TIMEOUT_MS = 5000
DEFAULT_HARD_TIMEOUT_S = 900

XK_BIN = os.environ.get("XK_BIN", "xray-knife")


class XrayKnifeMissing(RuntimeError):
    pass


class XrayKnifeFailed(RuntimeError):
    pass


def resolve_binary(binary=None):
    name = binary or XK_BIN
    path = shutil.which(name)
    if path:
        return path
    if os.path.isfile(name) and os.access(name, os.X_OK):
        return os.path.abspath(name)
    raise XrayKnifeMissing(
        f"xray-knife binary not found ({name!r}). Install it or set XK_BIN."
    )


def run_real_test(configs, netns_exec_prefix, *, test_url=None, threads=None,
                   timeout_ms=None, hard_timeout=None, verbose=True):
    """
    لیستِ کانفیگ‌ها رو با xray-knife از داخل namespace تست می‌کنه.

    netns_exec_prefix: لیستی مثل ["sudo", "ip", "netns", "exec", "wgtest"]
    که جلوی دستورِ xray-knife اضافه می‌شه تا از تونل رد بشه.

    برمی‌گردونه: dict {cfg: delay_ms} فقط برای کانفیگ‌هایی که واقعاً کار
    کردن (passed یا semi-passed).
    """
    if not configs:
        return {}

    binary = resolve_binary()

    in_fd, in_path = tempfile.mkstemp(prefix="xk_in_", suffix=".txt")
    with os.fdopen(in_fd, "w", encoding="utf-8") as f:
        f.write("\n".join(configs))

    out_fd, out_path = tempfile.mkstemp(prefix="xk_out_", suffix=".csv")
    os.close(out_fd)
    if os.path.exists(out_path):
        os.remove(out_path)

    argv = list(netns_exec_prefix) + [
        binary, "http",
        "-f", in_path,
        "-x", "csv",
        "-o", out_path,
        "-t", str(threads if threads is not None else DEFAULT_THREADS),
        "--timeout", str(timeout_ms if timeout_ms is not None else DEFAULT_TIMEOUT_MS),
        "-u", test_url if test_url is not None else DEFAULT_TEST_URL,
    ]

    if verbose:
        print(f"[xray_knife] تست واقعی روی {len(configs)} کانفیگ از پشتِ تونل...")

    try:
        limit = hard_timeout if hard_timeout is not None else DEFAULT_HARD_TIMEOUT_S
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=limit,
            check=False,
        )
        output = (proc.stdout or b"").decode("utf-8", errors="replace")

        if proc.returncode != 0:
            raise XrayKnifeFailed(
                f"xray-knife exited {proc.returncode}.\n--- output ---\n{output[-2000:]}"
            )

        if not os.path.isfile(out_path):
            raise XrayKnifeFailed(
                f"xray-knife exited 0 but wrote no output file.\n--- output ---\n{output[-2000:]}"
            )

        # بعضی کانفیگ‌های خراب/بدفرمت (مثلاً remark با کاراکترِ کنترلی) باعث
        # می‌شن xray-knife یه بایتِ NUL توی CSV بنویسه؛ اگه بدونِ پاک‌سازی به
        # csv.DictReader بدیم، همون یه ردیفِ خراب کلِ فایل رو fail می‌کنه و
        # نتیجه‌ی چند هزار کانفیگِ سالمِ دیگه هم دور ریخته می‌شه. پس اول
        # باینری می‌خونیم و NUL ها رو حذف می‌کنیم.
        with open(out_path, "rb") as handle:
            raw = handle.read()
        nul_count = raw.count(b"\x00")
        if nul_count and verbose:
            print(f"[xray_knife]   هشدار: {nul_count} بایتِ NUL توی خروجیِ CSV پاک شد (احتمالاً یه remark خراب)")
        text = raw.replace(b"\x00", b"").decode("utf-8", errors="replace")
        rows = list(csv.DictReader(io.StringIO(text)))

    finally:
        for p in (in_path, out_path):
            try:
                os.remove(p)
            except OSError:
                pass

    result = {}
    ok_count = 0
    for row in rows:
        status = (row.get("status") or "").strip().lower()
        link = row.get("link")
        delay_raw = row.get("delay")
        if status in ("passed", "semi-passed") and link:
            try:
                delay = float(delay_raw)
            except (TypeError, ValueError):
                delay = None
            if delay is not None and delay >= 0:
                result[link.strip()] = delay
                ok_count += 1

    if verbose:
        print(f"[xray_knife]   {ok_count}/{len(configs)} واقعاً کار کردن")

    return result
