# SV1 — خارطة التطوير

بحث في الأدوات الحالية (dalfox v3، XSStrike، sqlmap) يوضح أن الفرق بين سكانر
«يعطي نتائج» وسكانر «يعطي نتائج حقيقية» ليس عدد البايلودات. الفرق في ثلاث:

1. **إثبات التنفيذ** — الانعكاس ليس ثغرة، التنفيذ هو الثغرة.
2. **فهم السياق** — البايلود الصحيح يبني على القواعد (tag/attribute/script/comment).
3. **ثبات النتيجة** — إذا ما تكررت، ما هي ثغرة.

---

## P0 — المحرك الدقيق  ✅ منجز

| البند | الحالة |
|---|---|
| Baseline مزدوج لكل نقطة + قياس ضجيج الصفحة | ✅ |
| مقارنة على مستوى التوكنز (`difflib`) بدل البايتات | ✅ |
| أرضية ضجيج (`floor = 3×noise`) وقرارات مبنية عليها | ✅ |
| إعادة الفرعين للتأكد من التكرار على الصفحات المتغيرة | ✅ |
| تحليل سياق الحقن وبناء بايلود مخصص (text/attr/script/comment) | ✅ |
| مرحلة replay لكل نتيجة + تخفيض ما لا يتكرر | ✅ |
| عمود `technique` في كل المخرجات | ✅ |

**قبل/بعد على المختبر** (صفحة تتغير كل طلب، فيها حقن منطقي حقيقي):

```
real injection on /account   old 0/5   sv1 5/5
false positives on /noisy    old 0/5   sv1 0/5
```

القديم كان **يفوّت** الحقن لأن ضجيج 2% يكسر مقارنة البايتات. الجديد يقيس الضجيج
ويقارن البنية.

---

## P1 — إثبات التنفيذ (المتصفح) ✅ منجز

| البند | الحالة |
|---|---|
| Playwright + Chromium headless، سكربت تهيئة قبل أي سكربت صفحة | ✅ |
| هوك على `alert/confirm/prompt` + تسجيل بالماركر | ✅ |
| إعادة الحقن كما أُرسل (GET + POST عبر نموذج) | ✅ |
| النتيجة ما تصير `CONFIRMED` إلا بتنفيذ حقيقي | ✅ |
| DOM XSS: مصدر→حوض ثابت + إثبات بالمتصفح | ✅ |
| Stored XSS: إرسال → زيارة → انتظار الماركر | ✅ |
| Screenshot لكل نتيجة مؤكدة + تقرير HTML | ✅ |

**قبول محقق:** `/search`, `/feedback` (حقلان), `/js`, `/attr` كلها `executed`;
`/safe` ما نفّذت فنزلت MEDIUM; `/dom` انكشفت عبر `location.hash → innerHTML`;
`/guestbook` انكشفت مخزّنة. 12 نتيجة، 8 صور إثبات، 0 إيجابية كاذبة.

---

## P2 — عمق SQLi ✅ منجز (النواة)

| البند | الحالة |
|---|---|
| UNION-based: `ORDER BY` بحث ثنائي + عمود مرتجع + استخراج | ✅ |
| بصمة DBMS من الخطأ ومن البانر المستخرج | ✅ |
| نقاط جديدة: هيدرات، كوكيز، JSON body | ✅ |
| Tamper: `/**/`, `%09`, حالة أحرف، ترميز مفرد ومزدوج | ✅ |
| كشف فلتر 403/406/429 + تراجع تلقائي | ✅ |
| replay يصمد أمام الفلتر بنفس الصياغات | ✅ |
| Second-order (تخزين ثم زيارة) | ✅ في P3 |
| multipart | ✅ في P3 |
| `--dump` لعمود واحد | ✅ في P3.1 |

**قبول محقق:** على `/union` استخرج `3 columns, column 1 echoes back;
version() -> 8.0.36-lab`، وعلى `/waf` تجاوز فلتر المسافات بـ `/**/` وأعاد
النتيجة مؤكدة. 17 نتيجة على المختبر، كلها أعادت التشغيل.

---

## P3 — التغطية ✅ منجز (P3 + P3.1)

| البند | الحالة |
|---|---|
| Second-order SQLi: تخزين نظيف → بايلود → زيارة → فرق الخطأ → replay | ✅ |
| multipart: قراءة `enctype` وإرسال الطلب multipart فعلاً | ✅ |
| باراميترات مخفية: قاموس 70 اسماً + تحكم عشوائي + بحث ثنائي + تأكيد مزدوج | ✅ |
| نقاط من JS: سكربت مضمّن + خارجي بنفس الأصل، أي URL فيه query | ✅ |
| `--dump`: هوية القاعدة + أسماء الجداول بعد UNION | ✅ P3.1 |
| زحف SPA عبر Playwright + التقاط XHR | ✅ P3.1 |
| استيراد OpenAPI/Swagger → نقاط جاهزة | ✅ P3.1 |
| Second-order متعدد البايلودات/النماذج | ⏳ لاحقاً |

**قبول P3:** الفحص الكامل على المختبر
(`--crawl --stored --js --second-order`): 20 نتيجة، 20 أعادت التشغيل،
0 unstable — CRITICAL 7، HIGH 11، MEDIUM 2.

- `/hidden --params` كشف `debug` و `export`، والاثنان XSS مؤكد بالتنفيذ.
- `/js-endpoints` خبّى `/api/fetch?id=&name=` داخل `fetch()`؛ `--js` استخرجه
  والفحص أثبت XSS (تنفيذ) و SQLi (خطأ).
- `/upload` نموذج multipart؛ حقل `comment` انكشف عبر طلب multipart حقيقي.
- `/profile` يخزّن الاسم ويعرضه لاحقاً؛ `--second-order` خزّن `sv1'`، أعاد
  الزيارة، وكشف خطأ MySQL جديداً. replay أكد بقاء الخطأ.

**قبول P3.1:** نفس الفحص مع `--dump --spa --openapi`:
**25 نتيجة، 25 أعادت التشغيل، 0 unstable** — CRITICAL 9، HIGH 14، MEDIUM 2.

- `--dump` أضاف للنتيجة: `user sv1@localhost`، `db sv1lab`،
  `tables users,notes,accounts` — كلها عبر العمود المرتجع بماركر.
- `--spa` حمّل 4 صفحات، التقط استدعاءين ورابطاً ديناميكياً واحداً، وبنى 6 نقاط.
  `/api/spa?id=&name=` يُبنى بـ `URLSearchParams` فلا يراه `--js`؛ التقطه SPA
  وأثبت XSS (تنفيذ) و SQLi (خطأ). ورابط `<a>` الديناميكي نحو
  `/dynamic?id=&name=` أعطى النتيجتين نفسهما.
- `--openapi` قرأ 4 نقاط من `/openapi.json`؛ أضاف `/api/item` JSON boolean.
  نقاط `/api/fetch` تكررت مع `--js` فتم دمجها بالمفتاح.
- النتائج الجديدة في المخرجات (JSON/HTML) تحمل قيم `data` للسحب.

---

## P4 — الأعمى (Blind) و OOB ✅ منجز

| البند | الحالة |
|---|---|
| سيرفر callback محلي + توكن فريد لكل حقنة | ✅ |
| Blind XSS: حقن `<script src=...>` في نماذج POST ثم مراقبة الاتصالات | ✅ |
| إثبات التنفيذ: `/t` = جلب السكربت، `/e` = نُفّذ في متصفح | ✅ |
| ربط الـ hit بالنتيجة: توكن + وقت + IP + UA + صفحة العرض (`p`/Referer) | ✅ |
| `--blind-visit`: فتح صفحة المشرف في Chromium + screenshot | ✅ |
| SSRF: باراميترات URL + callback + عدم اتباع redirects | ✅ |
| `--oob` / `--oob-bind` / `--oob-wait` للاستخدام المحلي والبعيد | ✅ |
| تفاعل interactsh (بديل) / DNS OOB / OOB SQLi (xp_dirtree/UTL_HTTP) | ⏳ لاحقاً |

**قبول P4:** الفحص الكامل مع `--blind --blind-visit ... --ssrf`:
**27 نتيجة، 27 أعادت التشغيل، 0 unstable** — CRITICAL 9، HIGH 16، MEDIUM 2،
19 صفحة، 25 نقطة.

- `/blind` نموذج POST مخزّن؛ `/blind-admin` غير مربوط بالفهرس. الحقن ثم
  `--blind-visit` شغّل السكربت: `/t` انجلب و`/e` نُفّذ، والـ `p` أثبت أن
  صفحة العرض هي `/blind-admin`. النتيجة `HIGH` + `CONFIRMED` مع screenshot.
- `/fetch?url=` نُقطته اسمها `url`؛ الحقنة طلبت الـ callback من داخل المختبر.
  الطلب وصل من `urllib` (server side)، والنتيجة `HIGH` + `CONFIRMED`.
- التكرار أُزيل بمفتاح `(action, field)` للـ blind، ولم تُعدّل نتائج P3/P3.1.

---

## P4.1 — ما بعد OOB (اختياري)

- DNS listener اختياري (UDP/53 أو عبر نفق) لالتقاط `xp_dirtree` و UNC.
- OOB SQLi لبصمات MSSQL/Oracle/PostgreSQL (HTTP egress) مع تأكيد مختبر.
- قناة interactsh بدل السيرفر المحلي (register/poll) لمن ما يقدر يفتح منفذ.
- بروتوكولات SSRF إضافية (`file/gopher/dict`) عبر محرك callback موسّع.

---

## P5 — التشغيل ✅ P5.0 (النسخة 1.1.0)

| البند | الحالة |
|---|---|
| SARIF 2.1.0 + بصمات + قواعد لكل نوع/تقنية | ✅ |
| `--fail-on` (any/none/low/medium/high/critical) + كود خروج واضح | ✅ |
| `--scope`: allowlist مضيف/مسار، فشل مغلق، فلترة الزحف والنقاط | ✅ |
| SQLite `--db` + `--diff` (جديد/مفتوح/مُصلح) + `--retest` | ✅ |
| تكيّف 429/503 + `Retry-After` + تعافي تدريجي | ✅ |
| اختبارات وحدة + CI على Windows/Linux | ✅ |
| محرك async (`httpx`) → سرعة أعلى | ⏳ P5.1 |
| `--resume` لاستكمال جلسة متوقفة | ⏳ P5.1 |
| curl repro وخط زمني أعمق في HTML | ✅ curl في 1.2.0 |

**قبول P5.0:** الفحص الكامل مع `--scope --db --diff --sarif --fail-on high`:
27 نتيجة، 27 أعادت التشغيل، 0 unstable — CRITICAL 9، HIGH 16، MEDIUM 2،
19 صفحة، 25 نقطة، 780 طلباً، 149.2s. SARIF صالح حسب schema الرسمي.
`--retest` من الجلسة: 21 open، 0 fixed، 6 skipped. `--fail-on none` = 0،
`high` = 1، وهدف نظيف مع `high` = 0.

P5.0 يضيف طبقة تشغيل حقيقية: تقرير SARIF للـ CI، بوابات خطورة، نطاق فحص
مغلق، وذاكرة SQLite تقارن الجلسات وتعيد فحص ما يمكن إعادة فحصه. المحرك
باقي متزامناً (threads)؛ الـ async مؤجل لـ P5.1 مع `--resume`.

---

## P5.0.1 — دقة 1.2.0 ✅

إصدار دقة وأمانة طلب قبل نقل المحرك إلى async. لا فئات ثغرات جديدة.

| البند | الحالة |
|---|---|
| ماسح HTML كامل: وسم/خاصية/اقتباس/تعليق/نص خام، بدون خدعة `<` داخل خاصية | ✅ |
| بايلودات: اسم الوسم، اسم الخاصية، قيمة بلا اقتباس، إغلاق `textarea/style` | ✅ |
| `iframe srcdoc` + حقن `srcdoc` + قراءة كل الإطارات في Chromium | ✅ |
| JavaScript: تعيين/استدعاء/تعبير نمطي/تعليق سطر أو بلوك | ✅ |
| معالج حدث بلا اقتباسات `alert(/TOKEN/)` ينجو من تهريب الاقتباسات | ✅ |
| بوّابة Content-Type: غير HTML/XML ليس مرشح XSS | ✅ |
| حتى 6 بايلودات في المتصفح + تفعيل `mouseover/focus/click` | ✅ |
| حفظ المعاملات المكررة + `param_index` كتكرار للاسم | ✅ |
| إصلاح المعامل الثاني (`?id=1&name=test`) + استعادة 3 نتائج XSS | ✅ |
| `curl` لكل نتيجة في الطرفية/HTML/JSON/CSV | ✅ |
| تعقيم ANSI/control/CSV/HTML + بديل ASCII للطرفية | ✅ |
| الحفاظ على method في OpenAPI واستيراد query لغير GET | ✅ |
| متجهات DOM: referrer، window.name، storage، postMessage، cookie | ✅ |

**قبول 1.2.0:**

- Firing Range منعكس: 49 صفحة، 47 نقطة، 508 طلبات، 0 أخطاء — 40 `HIGH`
  مثبتة في Chromium و2 `MEDIUM` (stylesheet link وFlash object).
- Firing Range DOM: 25 صفحة زحف، 20 معروضة، 15 `HIGH` مؤكدة.
- Altoro Mutual: معامل بحث واحد، `HIGH` مؤكد.
- المختبر: 27/27 أعادت التشغيل، 0 unstable — CRITICAL 9 / HIGH 16 / MEDIUM 2،
  19 صفحة، 25 نقطة، 853 طلباً، 164.4 ثانية.
- الاختبارات: 42 اختبار وحدة.

الأدلة: `docs/REALWORLD.md` و`docs/evidence/`.

---

## P5.0.2 — أمان 1.2.1 ✅

إصلاح أمان وصحة فوق 1.2.0. ما أضاف فئات ثغرات جديدة؛ نفس نطاق XSS وSQLi
وBlind XSS وSSRF.

| البند | الحالة |
|---|---|
| `-k/--insecure` يضبط `ignore_https_errors=True` بدل العكس | ✅ |
| إجراءات النماذج: نفس الأصل HTTP(S) قبل الزحف وstored/second-order والمتصفح | ✅ |
| `requests.Session` لكل خيط + cookie jar مشترك آمن للخيوط | ✅ |
| أساس SQLi يقرأ تكرار `param_index` المقصود لا أول قيمة بنفس الاسم | ✅ |
| إزالة صور الأدلة غير المنشورة والاعتماد على JSON النتيجة | ✅ |
| اختبارات انحدار للإصلاحات الأربعة | ✅ |

**قبول 1.2.1:**

- Firing Range منعكس بإعادة تشغيل مفعّلة: 49 صفحة، 47 نقطة، 512 طلباً،
  0 أخطاء — 42 نتيجة (40 `HIGH` مثبتة في Chromium و2 `MEDIUM`)،
  إعادة تشغيل 42/42، 0 unstable، 247 ثانية.
- المختبر: 27/27 أعادت التشغيل، 0 unstable — CRITICAL 9 / HIGH 16 / MEDIUM 2،
  19 صفحة، 25 نقطة، 853 طلباً، 163.4 ثانية.
- الاختبارات: 49 اختبار وحدة، و`compileall` نظيف.

الأدلة: `docs/REALWORLD.md` و`docs/evidence/`.

---

## P5.0.3 — تطبيقات حقيقية 1.3.0 ✅

النطاق لم يتغير: XSS وSQLi وBlind XSS وSSRF. أضيفت مدخلات التطبيقات الحقيقية
بدل الاعتماد على روابط وصفحات بسيطة فقط.

| البند | الحالة |
|---|---|
| استيراد HAR: كوكيز + هيدرات + نقاط query/form/JSON/raw | ✅ |
| استيراد طلب HTTP خام (method/path/headers/body) | ✅ |
| JSON متداخل: كل ورقة scalar تصبح نقطة، مع إعادة بناء القالب | ✅ |
| جسم خام عبر `--data` و`*` + `--method` و`--content-type` | ✅ |
| التقاط XHR/fetch POST من Chromium وتحويل JSON/form إلى نقاط | ✅ |
| تحليل سكربتات خارجية same-origin لمصادر/مصارف DOM وإثباتها | ✅ |
| OpenAPI JSON متداخل داخل requestBody | ✅ |
| اختبار Playwright في CI يثبت التقاط POST body | ✅ |
| عكس XSS يبدأ MEDIUM ولا يصبح HIGH إلا بتنفيذ Chromium | ✅ |

**قبول 1.3.0:**

- 72 اختباراً مكتشفاً: 71 ينجح و1 متصفح اختياري متخطى، و`compileall` نظيف.
- Chromium: `/xhr-post` التقط طلب POST JSON وأنتج نقطتي `user.name` و`q`.
- `/external --external-js`: نتيجة DOM XSS واحدة `HIGH` مؤكدة من
  `location.hash → innerHTML` داخل `/external.js`.
- `/xhr-post --spa`: 1 طلب XHR بجسم، 2 نقطتان، 1 `MEDIUM` (انعكاس JSON بلا
  مسار تنفيذ في المتصفح)، 14 طلباً.
- `/api/nested --json`: نقطتا `user.name` و`q`، 1 `MEDIUM`، 14 طلباً.
- HAR محلي: جلسة same-origin ونقاط JSON متداخلة، 1 `MEDIUM`، 14 طلباً.
- HAR عام على Firing Range: نقطة GET مستوردة، 1 `HIGH` + `CONFIRMED`،
  إعادة تشغيل 1/1، 12 طلباً، 17.9 ثانية.
- المختبر الكامل مع `--external-js`: 31 نتيجة، 31/31 أعادت التشغيل، 0 unstable،
  CRITICAL 10 / HIGH 18 / MEDIUM 3، 21 صفحة، 29 نقطة، 966 طلباً، 183.8 ثانية.

**حدود 1.3.0:** لا يوجد تسجيل دخول/تحديث CSRF تلقائي؛ HAR لقطة ثابتة. تحليل
السكربتات الخارجية same-origin فقط وبحد 4 ملفات/1.5MB. أجسام multipart من XHR
غير مدعومة. المحرك async و`--resume` مؤجلان إلى 1.4.0.

---

## ترتيب التنفيذ المقترح

```
P0   ✅  (المحرك الدقيق)
P1   ✅  (إثبات التنفيذ بالمتصفح)
P2   ✅  (عمق SQLi: UNION + استخراج + مواقع جديدة)
P3   ✅  (تغطية: second-order + باراميترات مخفية + JS + multipart)
P3.1 ✅  (dump + SPA crawl + OpenAPI)
P4   ✅  (الأعمى و OOB: blind xss + ssrf + callback)
P5.0 ✅  (CI: SARIF + fail-on + scope + SQLite diff/retest + 429)
P5.0.1 ✅ (1.2.0: دقة السياق + أمانة الطلب + تحقق ميداني)
P5.0.2 ✅ (1.2.1: TLS + same-origin forms + خيوط HTTP + تكرار SQLi)
P5.0.3 ✅ (1.3.0: HAR + JSON متداخل + XHR POST + سكربتات خارجية + CI متصفح)
P5.1 ←   (1.4.0: محرك async + resume)
```

P5.0 اكتمل: SV1 يصدّر SARIF صالحاً، يفرض نطاقاً، يحفظ الجلسات ويقارنها،
ويعيد فحص ما يمكن إعادة فحصه. 1.2.0 أضاف دقة السياق وأمانة الطلب وcurl.
1.2.1 شدّد TLS وإجراءات النماذج وجلسات الخيوط وأساس SQLi. 1.3.0 فتح مدخلات
التطبيقات الحقيقية: HAR وطلبات خام وJSON متداخل وXHR POST وسكربتات خارجية.
الخطوة القادمة P5.1: محرك async و`--resume`، أو P4.1 لـ DNS/OOB SQLi حسب الحاجة.

