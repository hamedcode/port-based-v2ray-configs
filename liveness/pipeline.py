#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
liveness/pipeline.py — رهبرِ کل فرایند: TCP → وایرگارد → xray-knife → top100/clash

این ماژول عمداً به دو تابعِ جدا شکسته شده (نه یه تابعِ یکپارچه)، چون
categorize_all_protocols.py باید *قبل از نوشتنِ هر فایلی* (sub/, detailed/)
بدونه کدوم کانفیگ‌ها از مرحله‌ی TCP رد شدن — تا کانفیگ‌های مرده اصلاً وارد
مخزن نشن، نه اینکه فقط از top100 حذف بشن.

  run_tcp_stage(configs)        → فقط مرحله‌ی ۱ (ارزون، همیشه اجرا می‌شه)
  run_l3_and_build(stable, ...) → مرحله‌ی ۲+۳ (وایرگارد + xray-knife) روی
                                    همون لیستِ فیلترشده‌ی مرحله‌ی ۱

هردو طوری نوشته شدن که اگه جایی شکست خورد، بقیه‌ی پایپ‌لاین خراب نشه:
  - اگه WG_CONFIGS ست نشده یا هیچ تونلی بالا نیومد → به‌جای fail کامل، از
    تأخیرِ TCP برای رتبه‌بندیِ top100 استفاده می‌شه و توی خروجی مشخص می‌شه
    که تستِ L3 انجام نشده.
  - namespace همیشه توی finally پاک می‌شه، حتی اگه وسط کار خطا بده.
"""

import os

from . import tcp_check
from . import wireguard
from . import xray_knife_test
from . import clash_builder


def run_tcp_stage(unique_configs, *, rounds=3, concurrency=300, verbose=True):
    """
    مرحله‌ی ۱: TCP سه‌دوره‌ای، مستقیم از IP ران‌ر.

    برمی‌گردونه: لیستِ کانفیگ‌هایی که در همه‌ی دورها پورت‌شون باز بوده
    (یعنی «زنده»‌های مرحله‌ی ۱؛ همینا هستن که وارد sub/detailed می‌شن).
    """
    stable_map = tcp_check.check_liveness(
        list(unique_configs), rounds=rounds, concurrency=concurrency, verbose=verbose
    )
    return list(stable_map.keys())


def run_l3_and_build(
    stable_configs,
    *,
    wg_configs_secret=None,
    top_n=100,
    verbose=True,
):
    """
    مرحله‌ی ۲+۳: تلاش برای بالا آوردنِ تونلِ وایرگارد + تستِ واقعی با
    xray-knife، روی کانفیگ‌هایی که از مرحله‌ی ۱ (run_tcp_stage) رد شدن.

    برمی‌گردونه dict شامل:
      top_configs: لیستِ (cfg, delay_ms) برای top100 نهایی
      clash_yaml / top100_txt: رشته‌های آماده برای نوشتن
      l3_tested: bool — آیا تستِ واقعی انجام شد
      l3_alive_count: تعدادِ کانفیگ‌هایی که واقعاً کار کردن
      tunnel_used: اسمِ تونلِ استفاده‌شده (یا None)
    """
    stable_configs = list(stable_configs)
    result = {
        "top_configs": [],
        "clash_yaml": "",
        "top100_txt": "",
        "l3_tested": False,
        "l3_alive_count": 0,
        "tunnel_used": None,
    }

    if not stable_configs:
        if verbose:
            print("[pipeline] هیچ کانفیگِ پایداری برای مرحله‌ی L3 نیست.")
        return result

    def _tcp_only_fallback(reason):
        if verbose:
            print(f"[pipeline] {reason} برمی‌گردیم به رتبه‌بندیِ TCP-only.")
        result["top_configs"] = [(cfg, 0.0) for cfg in stable_configs[:top_n]]
        result["top100_txt"] = clash_builder.build_top100_txt(result["top_configs"])
        try:
            result["clash_yaml"] = clash_builder.build_clash_yaml(
                result["top_configs"],
                header_comment=f"# هشدار: {reason} این خروجی فقط بر اساسِ TCP handshake است (بدونِ تستِ L3)\n",
            )
        except Exception as e:
            if verbose:
                print(f"[pipeline] ساختِ clash.yaml شکست خورد: {e}")
        return result

    wg_secret = wg_configs_secret if wg_configs_secret is not None else os.environ.get("WG_CONFIGS", "")
    if not wg_secret.strip():
        return _tcp_only_fallback("WG_CONFIGS ست نشده؛")

    # ── مرحله ۲: وایرگارد ────────────────────────────────────────────
    tunnel_name = None
    try:
        tunnel_name = wireguard.bring_up_with_failover(wg_secret, verbose=verbose)
    except Exception as e:
        if verbose:
            print(f"[pipeline] راه‌اندازیِ وایرگارد با خطا مواجه شد: {e}")

    if not tunnel_name:
        return _tcp_only_fallback("هیچ تونلِ وایرگاردی بالا نیومد؛")

    result["tunnel_used"] = tunnel_name

    # ── مرحله ۳: تستِ واقعی با xray-knife از پشتِ تونل ──────────────────
    try:
        alive_map = xray_knife_test.run_real_test(
            stable_configs,
            wireguard.netns_exec_prefix(),
            verbose=verbose,
        )
        result["l3_tested"] = True
        result["l3_alive_count"] = len(alive_map)
    except Exception as e:
        if verbose:
            print(f"[pipeline] تستِ xray-knife شکست خورد: {e}")
        alive_map = {}
    finally:
        wireguard.teardown(verbose=verbose)

    if not alive_map:
        return _tcp_only_fallback("تستِ L3 هیچ کانفیگِ زنده‌ای برنگردوند؛")

    top = clash_builder.get_top_n(alive_map, n=top_n)
    result["top_configs"] = top
    result["top100_txt"] = clash_builder.build_top100_txt(top)
    try:
        result["clash_yaml"] = clash_builder.build_clash_yaml(
            top,
            header_comment=f"# تست‌شده با xray-knife از پشتِ تونلِ «{tunnel_name}»\n",
        )
    except Exception as e:
        if verbose:
            print(f"[pipeline] ساختِ clash.yaml شکست خورد: {e}")

    return result


def run_liveness_pipeline(unique_configs, *, wg_configs_secret=None, tcp_rounds=3,
                           tcp_concurrency=300, top_n=100, verbose=True):
    """
    Wrapper راحت برای فراخوانیِ هر دو مرحله پشتِ‌سرِهم (وقتی نیازی به
    فیلترکردنِ خروجی‌های دیگه قبل از L3 نیست). categorize_all_protocols.py
    از این استفاده نمی‌کنه (چون باید بینِ دو مرحله فیلتر کنه)؛ این فقط برای
    استفاده‌ی مستقیم/تست نگه داشته شده.
    """
    stable_configs = run_tcp_stage(
        unique_configs, rounds=tcp_rounds, concurrency=tcp_concurrency, verbose=verbose
    )
    result = run_l3_and_build(
        stable_configs, wg_configs_secret=wg_configs_secret, top_n=top_n, verbose=verbose
    )
    result["tcp_stable_count"] = len(stable_configs)
    return result
