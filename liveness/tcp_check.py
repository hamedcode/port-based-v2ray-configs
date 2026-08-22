#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
liveness/tcp_check.py — مرحله ۱: فیلتر ارزان TCP (مستقیم از IP ران‌ر گیت‌هاب)

هدف این مرحله فقط حذف کردنِ کانفیگ‌هایی هست که پورت‌شون اصلاً باز نیست، تا
مرحله‌ی گرون‌تر (تست واقعی با xray-knife از پشت وایرگارد) وقتش رو صرف
کانفیگ‌های مرده نکنه. این مرحله چون فقط یه TCP handshake ساده‌ست (نه تست
واقعیِ پروتکل)، از IP خودِ ران‌ر انجام می‌شه.

خروجی: مجموعه‌ای از کانفیگ‌هایی که در همه‌ی دورها (rounds) پورت‌شون باز بوده.
تست چند دوره‌ای برای حذف false-positive های گذرا (سرور موقتاً کند/شلوغ) هست.
"""

import asyncio
import base64
import json
import time
from urllib.parse import urlparse


def extract_host_port(cfg: str):
    """host و port رو از یه کانفیگ vmess/vless/trojan/ss استخراج می‌کنه."""
    try:
        if cfg.startswith("vmess://"):
            b64 = cfg[8:]
            dec = base64.b64decode(b64 + "=" * (-len(b64) % 4)).decode("utf-8", errors="ignore")
            data = json.loads(dec)
            host = data.get("add")
            port = data.get("port")
            if host and port:
                return str(host), int(port)
            return None, None
        parsed = urlparse(cfg)
        if parsed.hostname and parsed.port:
            return parsed.hostname, int(parsed.port)
        return None, None
    except Exception:
        return None, None


async def _test_one(host, port, timeout):
    try:
        t0 = time.monotonic()
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        delay_ms = (time.monotonic() - t0) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return delay_ms
    except Exception:
        return None


async def _test_batch(endpoints, concurrency, timeout):
    sem = asyncio.Semaphore(concurrency)

    async def bound(ep):
        host, port = ep
        async with sem:
            return await _test_one(host, port, timeout)

    return await asyncio.gather(*[bound(ep) for ep in endpoints])


def _run_one_round(configs, concurrency, timeout):
    """یه دورِ کامل تست روی همه‌ی کانفیگ‌ها. برمی‌گردونه: dict cfg -> delay_ms یا None."""
    valid_cfgs = []
    endpoints = []
    for cfg in configs:
        host, port = extract_host_port(cfg)
        if host and port:
            valid_cfgs.append(cfg)
            endpoints.append((host, port))

    if not endpoints:
        return {}

    delays = asyncio.run(_test_batch(endpoints, concurrency, timeout))
    return dict(zip(valid_cfgs, delays))


def check_liveness(configs, rounds=3, concurrency=300, timeout=3.0, verbose=True):
    """
    چند-دوره‌ای تست TCP روی لیست کانفیگ‌ها.

    برمی‌گردونه: dict {cfg: True} فقط برای کانفیگ‌هایی که در *همه‌ی* دورها
    پورت‌شون باز بوده (پایدار). کانفیگ‌هایی که host/port قابل استخراج نبود،
    اصلاً وارد نتیجه نمی‌شن.
    """
    configs = list(configs)
    if verbose:
        print(f"[tcp_check] شروع {rounds} دور تست روی {len(configs)} کانفیگ (concurrency={concurrency})")

    round_results = []
    for r in range(rounds):
        t0 = time.monotonic()
        res = _run_one_round(configs, concurrency, timeout)
        elapsed = time.monotonic() - t0
        alive = sum(1 for v in res.values() if v is not None)
        round_results.append(res)
        if verbose:
            print(f"[tcp_check]   دور {r + 1}/{rounds}: {alive}/{len(configs)} پورت باز ({elapsed:.1f}s)")

    stable = {}
    for cfg in configs:
        ok_in_all = True
        for res in round_results:
            if res.get(cfg) is None:
                ok_in_all = False
                break
        if ok_in_all:
            stable[cfg] = True

    if verbose:
        print(f"[tcp_check] پایدار در همه‌ی دورها: {len(stable)}/{len(configs)}")

    return stable
