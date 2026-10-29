# SV1 — قياس الاسترجاع على Firing Range (reflected)

- **التاريخ:** 2026-10-29
- **SV1:** 1.5.2 (هذا القياس) — الأساس 1.5.1 (`9e2dcc4`)
- **المنافس:** dalfox 3.2.4
- **الهدف:** `https://public-firing-range.appspot.com/reflected/`

dalfox archive SHA-256:
`28100d9355a1c767facd571a180d08b87d4de61167b3db99d56e4d8a6601d69a`.

## تصحيح الحساب

> الجدول السابق عرض **42/44** لأنه أدخل صفحة النموذج
> `/reflected/parameter/form` — وهي طلب **POST** — داخل مجموعة الـ47 صفحة
> **GET**. الفهرس 48 رابطاً = **47 GET + 1 POST**. اتحاد صفحات GET هو
> **43**، وليس 44. لذلك الأساس الصحيح لـSV1 1.5.1 هو **41/43**، وبعد
> إغلاق الفجوتين **43/43**. النموذج يُقاس منفصلاً.

**كل رقم في هذا الملف هو عدد مسارات صفحات فريدة، لا عدد findings.** يُحذف
الـquery والـfragment، ولو أنتجت الصفحة أكثر من نتيجة تُحسب مرة واحدة.

## المنهج

1. فتح فهرس `/reflected/` وعدّ الروابط: **48 صفحة** — 47 GET و1 POST
   (`parameter/form`).
2. تشغيل SV1 على القسم كامل: زحف، XSS فقط، 2 طلب/ثانية، `--pages 60`،
   مع Chromium. نفس الأمر على 1.5.1 و1.5.2.
3. تشغيل dalfox 3.2.4 على نفس الـmanifest: 47 طلب GET، وصفحة النموذج
   POST منفصلة. `--skip-mining` كي لا يخترع روابط أو باراميترات إضافية.
   المرحلة الأولى: سقف 30 بايلوداً لكل باراميتر. المرحلة الثانية: أي صفحة
   غابت عن الأولى أُعيد فحصها بسقف 200 بايلوداً. كل هدف في عملية منفصلة
   لأن مسار `-i file` توقف مع 47 هدفاً في 3.2.4.
4. توحيد هوية الصفحة: مسار URL بلا query ولا fragment. أي نتيجة على
   `/reflected/x?q=...` تُحسب صفحة `/reflected/x`.
5. فصل عمودين:
   - **شاف:** أي نتيجة من الأداة، حتى لو كانت انعكاساً فقط.
   - **أثبت:** SV1 `HIGH` + تنفيذ/إعادة تشغيل، وdalfox `type=V`.

## النتيجة

المقام الرئيسي: **43 صفحة GET** (اتحاد ما وجدته الأداتان بعد استبعاد أربع
صفحات خارج نطاق HTML الحديث). صفحة النموذج POST منفصلة.

| المقياس | SV1 1.5.1 | SV1 1.5.2 | dalfox 3.2.4 |
|---|---:|---:|---:|
| صفحات GET شافها | 41 | **43** | 43 |
| صفحات GET أثبتها | 39 | **41** | 39 `V` |
| شافها الاثنان | 41 | **43** | 43 |
| dalfox فقط | 2 | 0 | — |
| اتحاد GET | 43 | 43 | 43 |
| الاسترجاع مقابل الاتحاد | 41/43 = **95.3%** | **43/43 = 100.0%** | **43/43 = 100.0%** |
| من أصل 47 GET | 41/47 = 87.2% | **43/47 = 91.5%** | 43/47 = 91.5% |
| صفحات فاتته | 6 | 4 | 4 |
| POST `form` (منفصلة) | 1/1 `HIGH` | 1/1 `HIGH` | 1/1 `V` |

**الرقم الرئيسي: 43/43 = 100.0% بعد الإصلاح، مقابل 41/43 = 95.3% قبله.**
المقام واحد: 43 صفحة GET. الأربع الباقية قرارات نطاق، وليست فجوات كشف.
النموذج POST شوهد وأُثبت من الأداتين، لكنه لا يدخل مقام GET.

تفصيل 1.5.2: 49 صفحة زحف، 47 نقطة حقن، 514 طلباً، 0 أخطاء، 357.4 ثانية.
النتائج **44 = 43 GET + form**؛ منها **42 `HIGH`** و2 `MEDIUM` أعادتا
التشغيل عبر HTTP فقط (`css_import` و`object_data`). لذلك تأكيد GET هو
**41/43**، بينما الاسترجاع **43/43**.

dalfox شاف **43/43** صفحة GET، لكن **39 فقط `V`**. الأربع `R` هي
`script_src`، `iframe_attribute_value`، وفلترا `filteredcharsets`
(`body/SpaceDoubleQuoteSlashEquals` و`attribute_unquoted/DoubleQuoteSinglequote`)؛
لم تُحسب مثبتة. `V` عند dalfox موضع قابل للتنفيذ في DOM المُحلّل، وليس
تنفيذ Chromium.

## الفجوتان أُغلقتا

| الصفحة | البايلود الذي أثبت التنفيذ | النتيجة في 1.5.2 |
|---|---|---|
| `/reflected/url/script_src` | `data:text/javascript,alert('TOKEN')` | `HIGH`، تنفيذ Chromium، `xss-35.png` |
| `/reflected/filteredcharsets/attribute_unquoted/DoubleQuoteSinglequote` | `TOKEN onmouseover=alert(/TOKEN/) x=` | `HIGH`، تنفيذ Chromium، `xss-42.png` |

- فرع `<script src>` يجرّب `data:text/javascript` قبل الرجوع إلى إغلاق
  الوسم. الصيغة المقتبسة تستخدم اقتباس JS المعاكس، والصيغة العارية تستخدم
  `alert(/token/)` بلا اقتباسات.
- الـattribute العاري يجرّب `onmouseover` و`onfocus` بلا اقتباسات قبل
  النسخ المقتبسة، فينجو من فلتر يحذف `"` و`'`.
- القياس الجديد يؤكد النتيجتين `HIGH` بتنفيذ `alert` داخل Chromium، وليس
  انعكاساً فقط.

## قرارات النطاق (4)

مكتوبة مرة واحدة هنا. ليست أخطاء، ولا تُحسب فجوة HTML؛ الاثنان لم يجداها،
لذلك هي خارج اتحاد الـ43.

| الصفحة | نوع الرد | القرار |
|---|---|---|
| `/reflected/url/object_param` | `<param name="src">` لـFlash | خارج النطاق: Flash ميت في Chromium الحديث؛ السياق لا ينفّذ. |
| `/reflected/contentsniffing/json` | `application/json` | خارج النطاق الحالي: المتصفح الحديث لا يعيد sniffing إلى HTML. |
| `/reflected/contentsniffing/plaintext` | `text/plain` | خارج النطاق الحالي: سلوك IE قديم، لا HTML. |
| `/reflected/jsoncallback` | `application/json` (JSONP) | فئة منفصلة: ينفّذ عند تضمينه كـ`<script>src` وليس HTML XSS. |

dalfox لم يرَ هذه الأربع أيضاً؛ لم يفت أي صفحة HTML. الأربع `R` عنده
داخل الـ43 وليست من هذه القائمة.

## ما بعد القياس

- ✅ **P0 — `script_src`:** `data:text/javascript` في فرع `src`؛ نُفّذ في 1.5.2.
- ✅ **P0 — attribute بلا اقتباسات:** event handler بلا اقتباسات قبل النسخ
  المقتبسة؛ نُفّذ في 1.5.2.
- ✅ **P0 — JSONP:** قرار نطاق موثّق؛ لا يُخلط مع HTML XSS.
- ✅ **P1 — القياس:** 47 GET، الأساس 41/43، بعد الإصلاح 43/43؛ النموذج 1/1.
- **التالي — Juice Shop:** عينة ثانية بعد Firing Range، بنفس جدول الصفحات
  ودليل Chromium. Firing Range قسم اصطناعي واحد؛ لا تعمّم 100% على تطبيق
  حقيقي. تُقاس مسارات Juice Shop ومساحات الدخول والـAPI منفصلة، لا تُخلط
  مع هذا المقام.

## حدود القياس

- الاتحاد أقل تقدير. لو فاتت صفحة الاثنين، تختفي من المقام.
- dalfox شُغّل على مرحلتين: 30 بايلوداً لكل صفحة، ثم 200 للغائبة،
  `--scan-timeout 90`، 20 طلب/ثانية. هذا أقل من الـ3000 الافتراضية، لكنه
  لا يحاسب dalfox على سقف 30 وحده ويُبقي التشغيل ممكناً على هدف عام.
- dalfox `type=V` يعني «موضع قابل للتنفيذ في DOM المُحلّل»، وليس تنفيذ
  Chromium. لا تخلطه مع `HIGH` عند SV1.
- Firing Range صفحة اصطناعية، وليست تطبيقاً حقيقياً. النتيجة تقيس السياقات
  والبايلودات، لا منطق الأعمال.
- تشغيل واحد. لا يوجد قياس تذبذب أو تكرار بعد.

## إعادة التشغيل

```powershell
# SV1 — نفس الأمر للأساس 1.5.1 وللإصلاح 1.5.2
python sv1.py -u https://public-firing-range.appspot.com/reflected/ `
  --crawl --depth 1 --pages 60 --xss --rps 2 --threads 4 --timeout 20 `
  --browser --fail-on none --no-banner `
  -o docs/evidence/firing-range-reflected-1.5.2.json

# dalfox: المرحلة 1، كرر لكل URL GET في manifest.json
dalfox scan "<URL>" --skip-mining `
  --max-payloads-per-param 30 --scan-timeout 45 `
  --rate-limit 10 --workers 1 --timeout 20 `
  --silence --no-color --format json --output "<URL-output>.json"

# dalfox: المرحلة 2، فقط للصفحات التي غابت عن المرحلة 1
dalfox scan "<MISSED-URL>" --skip-mining `
  --max-payloads-per-param 200 --scan-timeout 90 `
  --rate-limit 20 --workers 1 --timeout 20 `
  --silence --no-color --format json --output "<MISSED-output>.json"

# dalfox: صفحة النموذج POST
dalfox scan "https://public-firing-range.appspot.com/reflected/parameter/form" `
  -X POST -d "q=a" --skip-mining `
  --max-payloads-per-param 30 --scan-timeout 45 `
  --rate-limit 10 --workers 1 --timeout 20 `
  --silence --no-color --format json --output "dalfox-reflected-form.json"
```

## الدليل

- [`firing-range-reflected-1.5.2.json`](evidence/firing-range-reflected-1.5.2.json)
- [`firing-range-reflected-1.5.1.json`](evidence/firing-range-reflected-1.5.1.json)
- [`firing-range-reflected-recall-1.5.2.json`](evidence/firing-range-reflected-recall-1.5.2.json)
- [`firing-range-reflected-manual-proof.txt`](evidence/firing-range-reflected-manual-proof.txt)
- [`dalfox-reflected-3.2.4.json`](evidence/dalfox-reflected-3.2.4.json)
