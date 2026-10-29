# SV1 — قياس الاسترجاع على Firing Range (reflected)

- **التاريخ:** 2026-10-28 (dalfox pass 2: 2026-10-29)
- **SV1:** 1.5.1 (`9e2dcc4`)
- **المنافس:** dalfox 3.2.4
- **الهدف:** `https://public-firing-range.appspot.com/reflected/`

dalfox archive SHA-256:
`28100d9355a1c767facd571a180d08b87d4de61167b3db99d56e4d8a6601d69a`.

`1.5.1` أثبتت أن النتائج أمينة: 40 تأكيد تنفيذ، 2 إعادة تشغيل، 0 أخطاء،
ولا نتيجة `HIGH` بلا دليل. هذا الملف يقيس سؤالاً ثانياً: **هل ترى الصفحات
الموجودة؟**

الرقم هنا ليس recall مطلقاً. Google لا تنشر عدد الصفحات القابلة للاستغلال في
هذا القسم، لذلك المقام هو **اتحاد ما وجده الأداتان**، وليس عدداً خارجياً.
هذا أقل تقدير للحقيقة: إذا فاتت صفحة الاثنين معاً، تختفي من المقام. لذلك
نُبقي قائمة الصفحات الـ48 من الفهرس كمرجع، ونعرض `neither` بشكل منفصل.

## المنهج

1. فتح فهرس `/reflected/` وعدّ الروابط: **48 صفحة**.
2. تشغيل SV1 على القسم كامل: زحف، XSS فقط، 2 طلب/ثانية،
   `--pages 60` (الافتراضي 25 كان سيقصّ القسم)، مع Chromium.
3. تشغيل dalfox 3.2.4 على نفس الـmanifest: 47 طلب GET، وصفحة النموذج
   `POST q` منفصلة. استُخدم `--skip-mining` كي لا يخترع dalfox روابط أو
   باراميترات إضافية خارج الـmanifest. المرحلة الأولى: سقف 30 بايلوداً
   للباراميتر على كل الصفحات. المرحلة الثانية: أي صفحة ما ظهرت في الأولى
   أُعيد فحصها بسقف 200 بايلوداً، حتى لا يكون السقف وحده هو سبب الغياب.
   شُغّل كل هدف في عملية منفصلة لأن مسار `-i file` توقف مع 47 هدفاً في 3.2.4.
4. توحيد هوية الصفحة: مسار URL بلا query ولا fragment. أي نتيجة على
   `/reflected/x?q=...` تُحسب صفحة `/reflected/x`.
5. فصل عمودين:
   - **شاف:** أي نتيجة من الأداة، حتى لو كانت انعكاساً فقط.
   - **أثبت:** SV1 `HIGH` + تنفيذ/إعادة تشغيل، وdalfox `type=V`.

## النتيجة

| المقياس | SV1 1.5.1 | dalfox 3.2.4 |
|---|---:|---:|
| صفحات شافها | **42** | 44 |
| صفحات أثبتها | **40** | 40 |
| شافها الاثنان | 42 | 42 |
| SV1 فقط | 0 | — |
| dalfox فقط | — | 2 |
| المجموع (اتحاد الأداتين) | 44 | 44 |
| الاسترجاع مقابل الاتحاد | **42/44 = 95.5%** | **44/44 = 100.0%** |
| من أصل 48 صفحة | 42/48 = **87.5%** | 44/48 = 91.7% |
| صفحات فاتته | 6 | 4 |

> الرقمان المطلوبان هما `الاسترجاع مقابل الاتحاد`: SV1 **42/44 = 95.5%**،
> dalfox **44/44 = 100.0%**. المقام واحد للأثنين: 44 صفحة.

بمعايير القراءة (85%+ strong، 60–80% medium، أقل من 60% narrow)، الرقمان
يقعان في **strong**. هذا لا يغيّر حقيقة أن ست صفحات فاتت SV1؛ قائمة الفوات
هي الـroadmap.

تفصيل SV1: **42 نتيجة** على 42 صفحة؛ 40 `HIGH` مؤكدة بتنفيذ Chromium،
و2 `MEDIUM` أعادت التشغيل عبر HTTP فقط (`css_import` و`object_data`).
49 صفحة زحف، 47 نقطة حقن، 512 طلباً، 0 أخطاء، 362.5 ثانية.

dalfox شاف 44 صفحة، لكن **40 فقط `V`**. الأربع `R` هي `script_src`،
`iframe_attribute_value`، وفلترا `filteredcharsets` (body وattribute_unquoted)؛
لم تُحسب مثبتة. `V` عند dalfox موضع قابل للتنفيذ في DOM المُحلّل، وليس تنفيذ
Chromium.

المرحلة الثانية أضافت ست صفحات كانت غائبة في الأولى: `title`، `textarea`،
`noscript`، `js_assignment`، وفلترَي `filteredcharsets`. الأربع الباقية هي
خارج نطاق HTML الحديث؛ لا تُحسب فجوة HTML، مع بقاء سقف 200 أقل من الافتراضي.

لو حذفنا أربع صفحات خارج نطاق HTML الحديث — `object_param` (Flash)،
`contentsniffing/json`، `contentsniffing/plaintext`، و`jsoncallback` (JSONP) —
يبقى **44 صفحة HTML**، وSV1 شاف **42/44 = 95.5%**. الفجوتان الحقيقيتان هناك
هما `script_src` و`filteredcharsets/attribute_unquoted`.

## اللي فات SV1

| الصفحة | نوع الرد | ليش فاتت | الحكم |
|---|---|---|---|
| `/reflected/url/script_src` | `text/html` | الانعكاس داخل `<script src="...">`؛ فرع `script` في SV1 لا يجرّب URL سكربت خارجي أو `data:text/javascript`. | **ثغرة سياق حقيقية** — بايلود `data:text/javascript,alert(...)` ينعكس وينفّذ في Chromium. |
| `/reflected/url/object_param` | `text/html` | `<param name="src">` لـ Flash. | **سياق ميت** — Chromium بلا Flash؛ لا تنفيذ. |
| `/reflected/contentsniffing/json` | `application/json` | SV1 لا يعتبر JSON مستند HTML. | **خارج النطاق الحالي** — المتصفح الحديث لا يعيد sniffing إلى HTML. |
| `/reflected/contentsniffing/plaintext` | `text/plain` | نفس السبب. | **خارج النطاق الحالي** — سلوك IE قديم. |
| `/reflected/jsoncallback` | `application/json` | جسم JSONP (`callback({...})`)؛ SV1 لا يفحص سياق `<script src>`. | **فئة منفصلة** — JSONP XSS حقيقية عند التضمين، لكنها ليست HTML XSS. |
| `/reflected/filteredcharsets/attribute_unquoted/DoubleQuoteSinglequote` | `text/html` | الفلتر يحذف `"` و`'`؛ كل بايلودات SV1 لهذا السياق تستخدم واحداً منهما. | **ثغرة بايلود حقيقية** — `x onmouseover=alert(/token/) x=` ينعكس وينفّذ بلا اقتباسات. |

الاثنان القابلان للتنفيذ الآن، وتحقّقا يدوياً في Chromium:

- `script_src`: `data:text/javascript,alert('sv1proof')` انعكس في
  `<script src="...">` ونفّذ `alert:sv1proof`. أضف هذا الشكل لفرع `src`، أو
  استعمل callback يستضيف سكربتاً.
- `attribute_unquoted` بعد فلتر الاقتباسات:
  `x onmouseover=alert(/sv1proof/) x=` انعكس ونفّذ `alert:/sv1proof/` بعد
  إرسال `mouseover`. أضف نسخة event handler بلا اقتباسات قبل النسخ المقتبسة.

## اللي فات dalfox

| الصفحة | السبب |
|---|---|
| `/reflected/contentsniffing/json` | `application/json`؛ المتصفح الحديث لا يعيد sniffing إلى HTML. |
| `/reflected/contentsniffing/plaintext` | `text/plain`؛ المتصفح الحديث لا يعيد sniffing إلى HTML. |
| `/reflected/jsoncallback` | JSONP؛ ينفّذ فقط عند تضمينه كـ`<script>`، وليس HTML XSS. |
| `/reflected/url/object_param` | Flash `<param name=src>`؛ سياق ميت في Chromium. |

كل ما فات dalfox هو نفس الصفحات الأربع خارج نطاق HTML الحديث؛ لم يفت أي
صفحة HTML.

## اللي فاتهما الاثنان

| الصفحة | السبب |
|---|---|
| `/reflected/contentsniffing/json` | `application/json`؛ المتصفح الحديث لا يعيد sniffing إلى HTML. |
| `/reflected/contentsniffing/plaintext` | `text/plain`؛ المتصفح الحديث لا يعيد sniffing إلى HTML. |
| `/reflected/jsoncallback` | JSONP؛ ينفّذ فقط عند تضمينه كـ`<script>`، وليس HTML XSS. |
| `/reflected/url/object_param` | Flash `<param name=src>`؛ سياق ميت في Chromium. |

هذه نفس الصفحات الأربع؛ لذلك الاتحاد 44 وليس 48. هي قرارات نطاق، وليست
فجوات كشف.

## شنو يعني هذا للـroadmap

| الصفحة الفائتة | مرشح الـroadmap | الأولوية |
|---|---|---|
| `/reflected/url/script_src` | أضف `data:text/javascript` و/أو callback خارجي إلى فرع `script src`. | P0 |
| `/reflected/filteredcharsets/attribute_unquoted/DoubleQuoteSinglequote` | أضف event handler بلا اقتباسات قبل النسخ المقتبسة. | P0 |
| `/reflected/jsoncallback` | فئة JSONP منفصلة بدليل `<script src>`، أو إعلان خارج النطاق. | P0 |
| `/reflected/url/object_param` | قرار نطاق: Flash ميت في Chromium. | P1 |
| `/reflected/contentsniffing/json` | قرار نطاق: لا sniffing إلى HTML. | P1 |
| `/reflected/contentsniffing/plaintext` | قرار نطاق: لا sniffing إلى HTML. | P1 |

- **P0 — إغلاق فجوتين HTML صغيرتين:** `data:` script src، وevent handler
  بلا اقتباسات. كلاهما يعيد استخدام proof الموجود، ولا يوسّع النطاق.
- **P0 — قرار JSONP:** إما فئة `JSONP XSS` منفصلة بدليل تضمين سكربت، أو
  إعلانها خارج النطاق. لا تُخلط مع HTML XSS.
- **P1 — إعادة القياس:** بعد الإصلاحين، أعد نفس الـ48. المتوقع 44/48 على
  الأقل، ثم راجع الـ4 الباقية (Flash/JSON/plaintext) كقرارات نطاق لا كأخطاء.
- **P1 — توسيع العينة:** Firing Range قسم واحد. لا تعمّم 95.5% (أو 87.5%
  من الفهرس) على تطبيق حقيقي؛ أضف Juice Shop/DVWA/WebGoat في `1.6.0`.

## حدود القياس

- الاتحاد أقل تقدير. لو فاتت صفحة الاثنين، يبقى الرقم مرتفعاً.
- dalfox شُغّل على مرحلتين: 30 بايلوداً لكل صفحة، ثم 200 بايلوداً لكل صفحة
  غابت عن المرحلة الأولى، `--scan-timeout 90`، 20 طلب/ثانية وعملية منفصلة
  لكل هدف. هذا أقل من الـ3000 الافتراضية، لكنه لا يحاسب dalfox على سقف 30
  وحده ويُبقي التشغيل ممكناً على هدف عام.
- dalfox `type=V` يعني «موضع قابل للتنفيذ في DOM المُحلّل»، وليس تنفيذ
  Chromium. لا تخلطه مع `HIGH` عند SV1.
- Firing Range صفحة اصطناعية، وليست تطبيقاً حقيقياً. النتيجة تقيس السياقات
  والبايلودات، لا منطق الأعمال.
- تشغيل واحد. لا يوجد قياس تذبذب أو تكرار بعد.

## إعادة التشغيل

```powershell
# SV1
python sv1.py -u https://public-firing-range.appspot.com/reflected/ `
  --crawl --depth 1 --pages 60 --xss --rps 2 --threads 4 --timeout 20 `
  --browser --fail-on none --no-banner `
  -o docs/evidence/firing-range-reflected-1.5.1.json

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

- [`firing-range-reflected-1.5.1.json`](evidence/firing-range-reflected-1.5.1.json)
- [`firing-range-reflected-manual-proof.txt`](evidence/firing-range-reflected-manual-proof.txt)
- [`dalfox-reflected-3.2.4.json`](evidence/dalfox-reflected-3.2.4.json)
