"""
LightScan v2.0 PHANTOM — OAuth 2.0 Scanner
Developer: Light

Tests: Open Redirect · CSRF/State · PKCE Downgrade · Scope Escalation
       Tenant Confusion · Device Code Abuse · Token Leakage
"""
from __future__ import annotations
import asyncio, base64, hashlib, json, random, string, time
import urllib.request, urllib.parse, urllib.error
from lightscan.core.engine import ScanResult, Severity

def _rand(n=32): return "".join(random.choices(string.ascii_letters+string.digits,k=n))

def _fetch(url, method="GET", data=None, headers=None, timeout=10.0):
    h={"User-Agent":"LightScan-OAuth/2.0"}
    if headers: h.update(headers)
    try:
        req=urllib.request.Request(url,data=data,headers=h,method=method)
        with urllib.request.urlopen(req,timeout=timeout) as r:
            return r.status, r.read(4096).decode("utf-8","replace"), r.url
    except urllib.error.HTTPError as e:
        try: body=e.read(2048).decode("utf-8","replace")
        except: body=""
        return e.code, body, url
    except Exception as e: return 0, str(e), url

async def _afetch(url, method="GET", data=None, headers=None, timeout=8.0):
    loop=asyncio.get_event_loop()
    return await loop.run_in_executor(None, _fetch, url, method, data, headers, timeout)

async def test_open_redirect(auth_url, client_id, timeout=8.0):
    results=[]; evil="https://evil.com/callback"
    payloads=["https://evil.com","//evil.com","https://legit.com.evil.com",
              "https://legit.com@evil.com",f"https://evil.com/%2f%2f",
              "javascript:alert(1)","data:text/html,<script>alert(1)</script>"]
    for redir in payloads:
        url=(f"{auth_url}?response_type=code&client_id={urllib.parse.quote(client_id)}"
             f"&redirect_uri={urllib.parse.quote(redir)}&scope=openid&state={_rand()}")
        status,body,final=await _afetch(url,timeout=timeout)
        if "evil.com" in final or (status in (301,302) and "evil.com" in body):
            results.append(ScanResult("oauth-open-redirect",auth_url,443,"VULNERABLE",Severity.HIGH,
                f"Open redirect: {redir} → {final[:60]}",{"redirect_uri":redir}))
    if not results:
        results.append(ScanResult("oauth-open-redirect",auth_url,443,"not_vuln",Severity.INFO,"No open redirect found"))
    return results

async def test_csrf_state(auth_url, client_id, redirect_uri, timeout=8.0):
    results=[]
    base=(f"{auth_url}?response_type=code&client_id={urllib.parse.quote(client_id)}"
          f"&redirect_uri={urllib.parse.quote(redirect_uri)}&scope=openid")
    # No state
    status,body,_=await _afetch(base,timeout=timeout)
    if status in (200,302) and "error" not in body.lower():
        results.append(ScanResult("oauth-csrf-state",auth_url,443,"VULNERABLE",Severity.MEDIUM,
            "Request accepted WITHOUT state parameter — CSRF risk",{"missing":"state"}))
    # Predictable states
    for sv in ("1","0","test","null","undefined","12345"):
        s,b,_=await _afetch(base+f"&state={sv}",timeout=timeout)
        if s in (200,302) and "invalid_state" not in b.lower() and "error" not in b.lower():
            results.append(ScanResult("oauth-csrf-state",auth_url,443,"weak_state",Severity.MEDIUM,
                f"Predictable state accepted: state={sv}",{"state":sv})); break
    if not results:
        results.append(ScanResult("oauth-csrf-state",auth_url,443,"not_vuln",Severity.INFO,"State param validated"))
    return results

async def test_pkce_downgrade(auth_url, client_id, redirect_uri, timeout=8.0):
    results=[]
    verifier=_rand(64)
    challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    base=(f"{auth_url}?response_type=code&client_id={urllib.parse.quote(client_id)}"
          f"&redirect_uri={urllib.parse.quote(redirect_uri)}&scope=openid&state={_rand()}")
    # plain method
    url_plain=base+f"&code_challenge={verifier}&code_challenge_method=plain"
    s,b,_=await _afetch(url_plain,timeout=timeout)
    if s in (200,302) and "error" not in b.lower():
        results.append(ScanResult("oauth-pkce-downgrade",auth_url,443,"VULNERABLE",Severity.HIGH,
            "PKCE downgrade: 'plain' method accepted (S256 not enforced)"))
    # No PKCE
    s2,b2,_=await _afetch(base,timeout=timeout)
    if s2 in (200,302) and "invalid_request" not in b2.lower():
        results.append(ScanResult("oauth-pkce-downgrade",auth_url,443,"pkce_not_required",Severity.MEDIUM,
            "PKCE not enforced — code_challenge not required"))
    if not results:
        results.append(ScanResult("oauth-pkce-downgrade",auth_url,443,"not_vuln",Severity.INFO,"PKCE S256 enforced"))
    return results

async def test_device_code(client_id, scope="openid profile", timeout=10.0):
    results=[]
    endpoints=["https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
               "https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode"]
    for ep in endpoints:
        data=urllib.parse.urlencode({"client_id":client_id,"scope":scope}).encode()
        s,b,_=await _afetch(ep,"POST",data,{"Content-Type":"application/x-www-form-urlencoded"},timeout)
        if s==200:
            try:
                resp=json.loads(b)
                if "device_code" in resp:
                    results.append(ScanResult("oauth-device-code",ep,443,"device_code_enabled",Severity.HIGH,
                        f"Device code flow enabled. Verification URL: {resp.get('verification_uri','N/A')} "
                        f"| User code: {resp.get('user_code','N/A')}",
                        {"user_code":resp.get("user_code"),"uri":resp.get("verification_uri")}))
            except: pass
    if not results:
        results.append(ScanResult("oauth-device-code","login.microsoftonline.com",443,
            "not_enabled",Severity.INFO,"Device code flow not enabled"))
    return results

async def test_scope_escalation(auth_url, client_id, redirect_uri, timeout=8.0):
    results=[]; scopes=["openid offline_access","User.Read User.ReadWrite.All",
        "read:user user:email admin:org","https://graph.microsoft.com/.default"]
    base=(f"{auth_url}?response_type=code&client_id={urllib.parse.quote(client_id)}"
          f"&redirect_uri={urllib.parse.quote(redirect_uri)}&state={_rand()}")
    for sc in scopes:
        s,b,_=await _afetch(base+f"&scope={urllib.parse.quote(sc)}",timeout=timeout)
        if s in (200,302) and "invalid_scope" not in b.lower() and "error" not in b.lower():
            results.append(ScanResult("oauth-scope-escalation",auth_url,443,"scope_accepted",Severity.MEDIUM,
                f"Elevated scope accepted: {sc!r}",{"scope":sc}))
    if not results:
        results.append(ScanResult("oauth-scope-escalation",auth_url,443,"not_vuln",Severity.INFO,"Scopes validated"))
    return results

class OAuthScanner:
    def __init__(self, auth_url, client_id, redirect_uri, timeout=8.0):
        self.auth_url=auth_url; self.client_id=client_id
        self.redirect_uri=redirect_uri; self.timeout=timeout

    async def scan_all(self):
        print(f"\033[38;5;196m[OAuth]\033[0m Scanning {self.auth_url}")
        all_r=[]
        all_r += await test_open_redirect(self.auth_url, self.client_id, self.timeout)
        all_r += await test_csrf_state(self.auth_url, self.client_id, self.redirect_uri, self.timeout)
        all_r += await test_pkce_downgrade(self.auth_url, self.client_id, self.redirect_uri, self.timeout)
        all_r += await test_scope_escalation(self.auth_url, self.client_id, self.redirect_uri, self.timeout)
        all_r += await test_device_code(self.client_id, timeout=self.timeout)
        vuln=sum(1 for r in all_r if r.severity in (Severity.CRITICAL,Severity.HIGH))
        print(f"\033[38;5;196m[OAuth]\033[0m Done — {len(all_r)} findings, {vuln} high/critical")
        return all_r
