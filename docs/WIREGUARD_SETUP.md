# راه‌اندازیِ WireGuard برای تستِ زنده‌بودنِ کانفیگ‌ها

این پروژه برای تستِ واقعیِ کانفیگ‌ها (نه فقط چک TCP)، ترافیکِ تست رو از پشتِ
یه تونلِ وایرگارد رد می‌کنه — تا سرورهایی که به IP رنجِ گیت‌هاب اکشن حساسن
دچار مشکل نشن، و درخواست‌های تکراری هم باعثِ بلاک‌شدنِ IP گیت‌هاب نشه.

## ۱. گرفتنِ کانفیگِ وایرگارد از پروتون

1. وارد [account.protonvpn.com](https://account.protonvpn.com) بشو.
2. برو به بخش **Downloads → WireGuard configuration**.
3. یه سرور (یا چند سرور، برای failover) انتخاب کن و فایل `.conf` رو دانلود کن.
4. این کار رو برای چند سرورِ مختلف (کشورهای متفاوت) تکرار کن، تا اگه یکی از
   کار افتاد، بقیه جایگزین بشن.

> از هر VPN دیگه‌ای هم که خروجیِ WireGuard بده (نه فقط پروتون) می‌شه استفاده کرد؛
> فقط باید فرمتِ استانداردِ `[Interface]` / `[Peer]` رو داشته باشه.

## ۲. فرمتِ سکرت `WG_CONFIGS`

همه‌ی کانفیگ‌هایی که دانلود کردی رو توی **یه سکرتِ واحد** به اسمِ
`WG_CONFIGS` بذار، هر کدوم با یه خطِ `### NAME: <اسمِ دلخواه>` قبلش:

```
### NAME: proton-nl
[Interface]
PrivateKey = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy=
Endpoint = 185.xxx.xxx.xxx:51820
AllowedIPs = 0.0.0.0/0

### NAME: proton-us
[Interface]
PrivateKey = ...
Address = 10.2.0.3/32
DNS = 10.2.0.1

[Peer]
PublicKey = ...
Endpoint = 64.xxx.xxx.xxx:51820
AllowedIPs = 0.0.0.0/0
```

نکات:
- اسمِ بعدِ `### NAME:` فقط برای لاگِ خروجیِ اکشن استفاده می‌شه (که بفهمی کدوم
  سرور استفاده شده)؛ هر اسمی می‌تونه باشه.
- ترتیب مهمه: پایپ‌لاین کانفیگ‌ها رو به همون ترتیبی که نوشتی امتحان می‌کنه.
- اگه فقط یه سرور داری، لازم نیست خطِ `### NAME:` رو بذاری؛ کلِ متن به‌عنوانِ
  یه کانفیگِ تک درنظر گرفته می‌شه.

## ۳. اضافه‌کردنِ سکرت به گیت‌هاب

1. توی مخزن برو به **Settings → Secrets and variables → Actions**.
2. **New repository secret** رو بزن.
3. Name: `WG_CONFIGS`
4. Value: کل متنِ بالا (همه‌ی کانفیگ‌ها با هم، هرکدوم با `### NAME:` خودش) رو
   پیست کن.
5. ذخیره کن.

## ۴. رفتار در نبودِ سکرت

اگه `WG_CONFIGS` ست نشده باشه، یا هیچ‌کدوم از تونل‌ها بالا نیان، پایپ‌لاین
**خطا نمی‌ده و اکشن fail نمی‌شه** — به‌جاش `top100.txt` و `clash.yaml` فقط
بر اساسِ نتیجه‌ی مرحله‌ی TCP ساخته می‌شن (بدون تستِ واقعیِ L3)، و این موضوع
توی خودِ README هم مشخص می‌شه.

## ۵. تستِ محلی (روی سیستمِ خودت)

اگه می‌خوای قبل از پوش کردن، محلی تست کنی:

```bash
# نصبِ وابستگی‌ها
sudo apt install wireguard-tools
pip install -r requirements.txt

# دانلودِ xray-knife (نسخه‌ی pin‌شده در .github/workflows/main.yml رو ببین)
# و قرار دادنش توی PATH با اسمِ xray-knife

export WG_CONFIGS="$(cat my_wireguard_configs.txt)"
sudo -E python3 categorize_all_protocols.py
```

توجه: چون اسکریپت network namespace و اینترفیسِ وایرگارد می‌سازه، نیازِ
`sudo` داره (هم محلی و هم روی ران‌رِ گیت‌هاب اکشن — که به‌صورتِ پیش‌فرض
دسترسیِ `sudo` بدونِ پسورد داره).
