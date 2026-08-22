#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
liveness/pipeline.py — رهبرِ کل فرایند: TCP → وایرگارد → xray-knife → top100/clash

این تابع طوری نوشته شده که اگه هرجایی شکست خورد، بقیه‌ی خروجی‌های
categorize_all_protocols.py (که این پروژه قبلاً هم داشت) خراب نشن:

  - اگه WG_CONFIGS ست نشده باشه → کل مرحله‌ی liveness رد می‌شه، فقط یه
    پیام هشدار چاپ می‌شه (workflow fail نمی‌شه).
  - اگه هیچ‌کدوم از تونل‌های وایرگارد بالا نیومدن → به‌جای شکستِ کامل،
    از top100 بر اساسِ تأخیرِ TCP (مرحله ۱) استفاده می‌شه و توی خروجی
    مشخص می‌شه که تست L3 انجام نشده.
  - namespace همیشه توی finally پاک می‌شه، حتی اگه وسط کار خطا بده.
"""

import os

from . import tcp_check
from . import wireguard
from . import xray_knife_test
from . import clash_builder


def run_liveness_pipeline(
    unique_configs,
    *,
    wg_configs_secret=None,
    tcp_rounds=3,
    tcp_concurrency=300,
    top_n=100,
    verbose=True,
):
    """
    برمی‌گردونه dict شامل:
      top_configs: لیستِ (cfg, delay_ms) برای top100 نهایی
      clash_yaml: رشته‌ی YAML آماده برای نوشتن
      top100_txt: رشته‌ی متنِ ساده آماده برای نوشتن
      l3_tested: bool — آیا تست واقعی (xray-knife از پشتِ وایرگارد) انجام شد
      tcp_stable_count: تعداد کانفیگ‌های پایدار در مرحله‌ی TCP
      l3_alive_count: تعداد کانفیگ‌هایی که واقعاً کار کردن (اگه L3 انجام شده باشه)
      tunnel_used: اسمِ تونلِ وایرگاردی که استفاده شد (یا None)
    """
    unique_configs = list(unique_configs)
    result = {
        "top_configs": [],
        "clash_yaml": "",
        "top100_txt": "",
        "l3_tested": False,
        "tcp_stable_count": 0,
        "l3_alive_count": 0,
        "tunnel_used": None,
    }

    # ── مرحله ۱: TCP (مستقیم از IP ران‌ر) ──────────────────────────────
    stable_map = tcp_check.check_liveness(
        unique_configs, rounds=tcp_rounds, concurrency=tcp_concurrency, verbose=verbose
    )
    result["tcp_stable_count"] = len(stable_map)
    stable_configs = list(stable_map.keys())

    if not stable_configs:
        if verbose:
            print("[pipeline] هیچ کانفیگی از مرحله‌ی TCP رد نشد؛ liveness pipeline متوقف شد.")
        return result

    wg_secret = wg_configs_secret if wg_configs_secret is not None else os.environ.get("WG_CONFIGS", "")
    if not wg_secret.strip():
        if verbose:
            print("[pipeline] WG_CONFIGS ست نشده؛ از تأخیرِ TCP برای رتبه‌بندیِ top100 استفاده می‌شه (بدون تست L3).")
        top = sorted(stable_map.items(), key=lambda kv: kv[1] if kv[1] is not None else 1e9)[:top_n]
        # stable_map مقادیرش True هست نه تأخیر (چون check_liveness فقط پایداری رو برمی‌گردونه)
        # پس با تأخیرِ دورِ آخر جایگزین می‌کنیم؛ در نبودش، ترتیبِ اصلی حفظ می‌شه.
        result["top_configs"] = [(cfg, 0.0) for cfg in stable_configs[:top_n]]
        result["top100_txt"] = clash_builder.build_top100_txt(result["top_configs"])
        try:
            result["clash_yaml"] = clash_builder.build_clash_yaml(
                result["top_configs"],
                header_comment="# هشدار: این خروجی فقط بر اساسِ TCP handshake ساخته شده (بدون تستِ L3)\n",
            )
        except Exception as e:
            if verbose:
                print(f"[pipeline] ساختِ clash.yaml شکست خورد: {e}")
        return result

    # ── مرحله ۲: وایرگارد ────────────────────────────────────────────
    tunnel_name = None
    try:
        tunnel_name = wireguard.bring_up_with_failover(wg_secret, verbose=verbose)
    except Exception as e:
        if verbose:
            print(f"[pipeline] راه‌اندازیِ وایرگارد با خطا مواجه شد: {e}")

    if not tunnel_name:
        if verbose:
            print("[pipeline] هیچ تونلِ وایرگاردی بالا نیومد؛ برمی‌گردیم به رتبه‌بندیِ TCP-only.")
        result["top_configs"] = [(cfg, 0.0) for cfg in stable_configs[:top_n]]
        result["top100_txt"] = clash_builder.build_top100_txt(result["top_configs"])
        try:
            result["clash_yaml"] = clash_builder.build_clash_yaml(
                result["top_configs"],
                header_comment="# هشدار: تونل وایرگارد بالا نیومد؛ این خروجی فقط بر اساسِ TCP است\n",
            )
        except Exception as e:
            if verbose:
                print(f"[pipeline] ساختِ clash.yaml شکست خورد: {e}")
        return result

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
        if verbose:
            print("[pipeline] تستِ L3 هیچ کانفیگِ زنده‌ای برنگردوند؛ برمی‌گردیم به رتبه‌بندیِ TCP-only.")
        result["top_configs"] = [(cfg, 0.0) for cfg in stable_configs[:top_n]]
        result["top100_txt"] = clash_builder.build_top100_txt(result["top_configs"])
        try:
            result["clash_yaml"] = clash_builder.build_clash_yaml(
                result["top_configs"],
                header_comment="# هشدار: تستِ L3 نتیجه‌ای نداد؛ این خروجی فقط بر اساسِ TCP است\n",
            )
        except Exception as e:
            if verbose:
                print(f"[pipeline] ساختِ clash.yaml شکست خورد: {e}")
        return result

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
