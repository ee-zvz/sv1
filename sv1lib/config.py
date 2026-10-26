"""SV1 - tunables. Every magic number lives here."""

from __future__ import annotations

# --- version ---------------------------------------------------------------
TOOL_NAME = "SV1"
TOOL_AUTHOR = "ee.zvz"
TOOL_VERSION = "1.1.0"

# --- network ---------------------------------------------------------------
DEFAULT_TIMEOUT = 12.0          # seconds, per request
MAX_RETRIES = 2                 # attempts per request on transport failure
DEFAULT_RPS = 8.0               # requests per second cap, 0 = unlimited
MAX_BODY_BYTES = 4_000_000      # stop reading gigantic responses
MAX_REDIRECTS = 5

# --- adaptive throttling ---------------------------------------------------
RATE_PENALTY_FACTOR = 2.0       # multiply the interval on 429/503
RATE_MAX_MULTIPLIER = 8.0       # never slower than base * this
RATE_RECOVERY_AFTER = 20        # healthy responses before easing back
RATE_RECOVERY_FACTOR = 1.5      # divide the interval by this on recovery
RATE_MAX_DEFER = 30.0           # cap on Retry-After, seconds

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 SV1/1.1"
)

DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "close",
}

# --- crawler ---------------------------------------------------------------
DEFAULT_MAX_PAGES = 25
DEFAULT_MAX_DEPTH = 2
MAX_POINTS = 400                # hard cap on injection points
MAX_FORM_FIELDS = 30

SKIP_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp",
    ".css", ".js", ".map", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".avi", ".mov", ".webm", ".wav",
    ".pdf", ".zip", ".rar", ".7z", ".gz", ".tar", ".doc", ".docx",
    ".xls", ".xlsx", ".ppt", ".pptx", ".exe", ".msi", ".dll",
)

# --- xss -------------------------------------------------------------------
XSS_MAX_PAYLOADS = 10           # payloads tried per injection point
XSS_SAMPLE_CHARS = 160          # context window around a reflection

# --- sqli ------------------------------------------------------------------
SQLI_TIME_DELAY = 4             # seconds the DB is asked to sleep
SQLI_TIME_ATTEMPTS = 2          # confirm time-based twice

# --- page identity ---------------------------------------------------------
# Token-level comparison. Two fetches of the same URL must look like this to
# be trusted as a baseline; a payload branch must match the baseline and
# differ from its own opposite branch by the margins below.
TOKEN_LIMIT = 2000              # tokens kept per page, keeps difflib honest
BASELINE_SAMPLES = 2            # identical requests used to measure noise
BOOL_REPEATS = 2                # repeats per branch when the page is noisy
PAGE_STABLE = 0.995             # baseline copy vs baseline copy
PAGE_SAME = 0.970               # payload branch vs baseline
PAGE_DIFF = 0.950               # true branch vs false branch
PAGE_MIN_DIFF = 0.010           # smallest believable difference (1% of tokens)
PAGE_MAX_FLOOR = 0.100          # never trust a page that drifts more than this

# --- verification ----------------------------------------------------------
VERIFY_ROUNDS = 2               # every finding is replayed this many times

# --- browser / execution proof --------------------------------------------
BROWSER_TIMEOUT_MS = 20000      # navigation timeout
BROWSER_SETTLE_MS = 900         # quiet time after load, lets onload handlers run
BROWSER_VIEWPORT = (1366, 800)
BROWSER_MAX_PAGES = 20          # page budget for dom / stored passes
DOM_MAX_CANDIDATES = 6          # static source-to-sink pairs tested per page
DOM_PARAM_GUESSES = (
    "q", "s", "search", "query", "name", "id", "page", "view", "url", "redirect",
)
STORED_MAX_FORMS = 3            # forms used for the stored pass
STORED_MAX_FIELDS = 6           # fields filled per form
STORED_TEST_FIELDS = 2          # fields actually probed per form
STORED_MAX_PAGES = 8            # pages revisited looking for the payload
ARTIFACT_DIR = "sv1-artifacts"
HTML_REPORT = "sv1-report.html"

# --- coverage --------------------------------------------------------------
HIDDEN_CHUNK = 16               # parameter names per probe request
HIDDEN_MAX = 12                 # stop after this many hidden parameters
HIDDEN_VERIFY = 2               # individual confirmations per candidate
JS_MAX_PAGES = 8                # pages mined for endpoints
JS_MAX_SCRIPTS = 6              # external scripts fetched per page
JS_MAX_POINTS = 40              # endpoint points kept from javascript
SECOND_ORDER_FORMS = 6          # forms used for the second-order pass
SECOND_ORDER_FIELDS = 2         # fields probed per form
SECOND_ORDER_PAGES = 6          # pages revisited after storing

# --- dump ------------------------------------------------------------------
DUMP_MAX_VALUE = 200            # characters kept per dumped value
DUMP_TABLES_MAX = 12            # table names kept from the catalog

# --- spa -------------------------------------------------------------------
SPA_MAX_PAGES = 6               # crawled pages rendered in chromium
SPA_MAX_POINTS = 40             # endpoints captured from xhr/fetch
SPA_MAX_NEW_PAGES = 4           # anchors that only exist after rendering
SPA_WAIT_MS = 1800              # wait for late xhr after domcontentloaded

# --- openapi ---------------------------------------------------------------
OPENAPI_MAX_BYTES = 2_000_000   # spec read cap
OPENAPI_MAX_POINTS = 80         # points imported from one spec
OPENAPI_MAX_FIELDS = 6          # body properties probed per operation

# --- out of band -----------------------------------------------------------
OOB_PORT = 8777                 # default callback listener port
OOB_WAIT = 8.0                  # seconds to wait for external callbacks
OOB_POLL = 0.15                 # callback poll interval
OOB_MAX_HITS = 1000             # hard cap on recorded hits
BLIND_MAX_FORMS = 6             # forms seeded for blind xss
BLIND_TEST_FIELDS = 2           # fields probed per form
BLIND_VARIANTS = 2              # payload shapes per field
BLIND_VISIT_WAIT_MS = 1600      # wait after opening a simulated admin page
BLIND_VISIT_WAIT = 3.0          # callback wait when a local admin visit exists
BLIND_MAX_VISITS = 3            # admin pages opened after seeding
SSRF_MAX_POINTS = 15            # url-like points probed per run

# --- history / CI ----------------------------------------------------------
HISTORY_SCHEMA_VERSION = 1
FAIL_ON_CHOICES = ("any", "none", "low", "medium", "high", "critical")

# --- output ----------------------------------------------------------------
CSV_FIELDS = (
    "severity", "kind", "url", "method", "param",
    "payload", "confidence", "technique", "evidence",
)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# --- banner ----------------------------------------------------------------
BANNER_FRAME_DELAY = 0.035
BANNER_TAIL_DELAY = 0.9
SPINNER_INTERVAL = 0.09

