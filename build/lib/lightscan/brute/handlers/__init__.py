"""
LightScan v2.0 PHANTOM — Protocol Handlers (12 protocols)
Developer: Light

SSH · FTP · SMTP · HTTP · MySQL · PostgreSQL · MSSQL
Telnet · VNC · SMB · RDP · LDAP

Pure stdlib fallbacks when optional libs absent.
Optional libs for full functionality:
  pip install paramiko pymysql psycopg2-binary ldap3 impacket
"""
from __future__ import annotations
import asyncio, ftplib, smtplib, socket, struct, time, base64, hashlib
import urllib.request, urllib.parse, urllib.error
from typing import Callable


def _wrap(fn) -> Callable:
    async def wrapper(user, passwd):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, fn, user, passwd)
    return wrapper


# ─── SSH ─────────────────────────────────────────────────────────────────────
def make_ssh_handler(host, port=22, timeout=8.0, **kw):
    try:
        import paramiko
        async def handler(user, passwd):
            def _try():
                c = paramiko.SSHClient()
                c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    c.connect(host, port=port, username=user, password=passwd,
                              timeout=timeout, banner_timeout=timeout,
                              auth_timeout=timeout, look_for_keys=False,
                              allow_agent=False)
                    c.close(); return True, "SUCCESS"
                except paramiko.AuthenticationException as e:
                    return False, str(e)
                except paramiko.SSHException as e:
                    return False, f"SSH_ERR:{e}"
                except Exception as e:
                    return False, f"ERR:{e}"
                finally:
                    try: c.close()
                    except: pass
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, _try)
        return handler
    except ImportError:
        async def fallback(user, passwd):
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
                banner = await asyncio.wait_for(r.read(256), timeout=2.0)
                w.close()
                return False, f"NOLIB:{banner[:40]}"
            except Exception as e:
                return False, str(e)
        print("\033[38;5;240m[!] pip install paramiko  (SSH brute needs it)\033[0m")
        return fallback


# ─── FTP ─────────────────────────────────────────────────────────────────────
def make_ftp_handler(host, port=21, timeout=8.0, **kw):
    def _try(user, passwd):
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=timeout)
            ftp.login(user, passwd)
            ftp.quit()
            return True, "SUCCESS"
        except ftplib.error_perm as e:
            return False, str(e)
        except Exception as e:
            return False, str(e)
    return _wrap(_try)


# ─── SMTP ────────────────────────────────────────────────────────────────────
def make_smtp_handler(host, port=587, timeout=8.0, **kw):
    def _try(user, passwd):
        try:
            if port == 465:
                srv = smtplib.SMTP_SSL(host, port, timeout=timeout)
            else:
                srv = smtplib.SMTP(host, port, timeout=timeout)
                try: srv.starttls()
                except Exception: pass
            srv.login(user, passwd)
            srv.quit()
            return True, "SUCCESS"
        except smtplib.SMTPAuthenticationError as e:
            return False, str(e)
        except Exception as e:
            return False, str(e)
    return _wrap(_try)


# ─── HTTP ────────────────────────────────────────────────────────────────────
def make_http_handler(host, port=80, url="", user_field="username",
                      pass_field="password", success_text="", failure_text="",
                      basic_auth=False, timeout=10.0, **kw):
    _url = url if url else (f"https://{host}:{port}/login" if port in (443,8443)
                            else f"http://{host}:{port}/login")
    _hdrs = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html,application/xhtml+xml,*/*",
    }
    async def handler(user, passwd):
        def _try():
            if basic_auth:
                creds = base64.b64encode(f"{user}:{passwd}".encode()).decode()
                hdrs = dict(_hdrs); hdrs["Authorization"] = f"Basic {creds}"
                req = urllib.request.Request(_url, headers=hdrs)
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as r:
                        return True, r.read(200).decode("utf-8","replace")
                except urllib.error.HTTPError as e:
                    return False, f"HTTP {e.code}"
                except Exception as e:
                    return False, str(e)
            else:
                data = urllib.parse.urlencode({user_field:user, pass_field:passwd}).encode()
                req  = urllib.request.Request(_url, data=data, headers=_hdrs, method="POST")
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as r:
                        body = r.read(4096).decode("utf-8","replace")
                        final = r.url
                    if success_text and success_text.lower() in body.lower():
                        return True, f"SUCCESS: {success_text}"
                    if failure_text and failure_text.lower() in body.lower():
                        return False, f"fail: {failure_text}"
                    if any(k in final.lower() for k in ("dashboard","home","welcome","panel","account")):
                        return True, f"Redirect: {final}"
                    return False, "200 no indicator"
                except urllib.error.HTTPError as e:
                    loc = e.headers.get("Location","")
                    if any(k in loc.lower() for k in ("dashboard","home","welcome","account")):
                        return True, f"Redirect: {loc}"
                    return False, f"HTTP {e.code}"
                except Exception as e:
                    return False, str(e)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _try)
    return handler


# ─── MySQL ───────────────────────────────────────────────────────────────────
def make_mysql_handler(host, port=3306, timeout=8.0, **kw):
    try:
        import pymysql
        def _try(user, passwd):
            try:
                conn = pymysql.connect(host=host, port=port, user=user, password=passwd,
                                       connect_timeout=int(timeout), read_timeout=int(timeout))
                conn.close(); return True, "SUCCESS"
            except pymysql.err.OperationalError as e:
                return False, str(e)
            except Exception as e:
                return False, str(e)
        return _wrap(_try)
    except ImportError:
        # Raw MySQL auth via handshake
        async def mysql_raw(user, passwd):
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
                hdr = await asyncio.wait_for(r.read(4), timeout=timeout)
                plen = struct.unpack("<I", hdr)[0] & 0xFFFFFF
                greeting = await asyncio.wait_for(r.read(plen), timeout=timeout)
                if not greeting or greeting[0] != 10: w.close(); return False, "Not MySQL"
                null = greeting.index(b"\x00", 1)
                challenge = greeting[null+1:null+9]
                if passwd:
                    s1 = hashlib.sha1(passwd.encode()).digest()
                    s2 = hashlib.sha1(s1).digest()
                    auth = bytes(a^b for a,b in zip(s1, hashlib.sha1(challenge+s2).digest()))
                else: auth = b""
                ub = user.encode()+b"\x00"; ab = struct.pack("B",len(auth))+auth
                payload = struct.pack("<I",0x0000A685)+b"\x00\x00\x00\x01!"+b"\x00"*23+ub+ab+b"\x00"
                pkt = struct.pack("<I",len(payload))[:3]+b"\x01"+payload
                w.write(pkt); await w.drain()
                rh = await asyncio.wait_for(r.read(4), timeout=timeout)
                rlen = struct.unpack("<I",rh)[0]&0xFFFFFF
                resp = await asyncio.wait_for(r.read(rlen), timeout=timeout)
                w.close()
                if resp and resp[0]==0x00: return True,"SUCCESS"
                if resp and resp[0]==0xFF:
                    return False, resp[3:].decode("utf-8","replace")
                return False,"unknown"
            except Exception as e:
                return False, str(e)
        print("\033[38;5;240m[!] pip install pymysql  (raw fallback active)\033[0m")
        return mysql_raw


# ─── PostgreSQL ──────────────────────────────────────────────────────────────
def make_postgres_handler(host, port=5432, timeout=8.0, **kw):
    try:
        import psycopg2
        def _try(user, passwd):
            try:
                conn = psycopg2.connect(host=host, port=port, user=user, password=passwd,
                                        dbname="postgres", connect_timeout=int(timeout))
                conn.close(); return True, "SUCCESS"
            except psycopg2.OperationalError as e:
                return False, str(e)
            except Exception as e:
                return False, str(e)
        return _wrap(_try)
    except ImportError:
        async def pg_raw(user, passwd):
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
                params = b"user\x00"+user.encode()+b"\x00database\x00postgres\x00\x00"
                mlen = 4+4+len(params)
                w.write(struct.pack("!II",mlen,196608)+params); await w.drain()
                resp = await asyncio.wait_for(r.read(1024), timeout=timeout)
                w.close()
                if resp and chr(resp[0])=="R": return False,"auth_required"
                if resp and chr(resp[0])=="E":
                    return False, resp[5:].decode("utf-8","replace")
                return False, f"type={chr(resp[0]) if resp else '?'}"
            except Exception as e: return False, str(e)
        print("\033[38;5;240m[!] pip install psycopg2-binary  (raw PG fallback active)\033[0m")
        return pg_raw


# ─── MSSQL ───────────────────────────────────────────────────────────────────
def make_mssql_handler(host, port=1433, timeout=8.0, **kw):
    try:
        import pymssql
        def _try(user, passwd):
            try:
                conn = pymssql.connect(server=host, port=str(port), user=user,
                                       password=passwd, login_timeout=int(timeout))
                conn.close(); return True, "SUCCESS"
            except Exception as e: return False, str(e)
        return _wrap(_try)
    except ImportError:
        async def tds_probe(user, passwd):
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
                prelogin = bytes([0x12,0x01,0x00,0x2F,0x00,0x00,0x01,0x00,
                                  0x00,0x00,0x1A,0x00,0x06,0x01,0x00,0x20,
                                  0x00,0x01,0x02,0x00,0x21,0x00,0x01,0x03,
                                  0x00,0x22,0x00,0x04,0x04,0x00,0x26,0x00,
                                  0x01,0xFF,0x09,0x00,0x00,0x00,0x00,0x00,
                                  0x01,0x00,0xB8,0x0D,0x00,0x00,0x01])
                w.write(prelogin); await w.drain()
                resp = await asyncio.wait_for(r.read(1024), timeout=timeout)
                w.close()
                return False, f"MSSQL_alive len={len(resp)}"
            except Exception as e: return False, str(e)
        print("\033[38;5;240m[!] pip install pymssql  (TDS probe only)\033[0m")
        return tds_probe


# ─── Telnet ──────────────────────────────────────────────────────────────────
def make_telnet_handler(host, port=23, timeout=8.0, **kw):
    async def handler(user, passwd):
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            async def read_until(patterns, tout=3.0):
                buf=b""; deadline=time.time()+tout
                while time.time()<deadline:
                    try:
                        chunk = await asyncio.wait_for(r.read(256), timeout=0.5)
                        if not chunk: break
                        # Strip IAC negotiation bytes
                        i=0; clean=b""
                        while i<len(chunk):
                            if chunk[i]==0xFF and i+2<len(chunk): i+=3
                            else: clean+=bytes([chunk[i]]); i+=1
                        buf+=clean
                        dec=buf.decode("utf-8","replace").lower()
                        if any(p.lower() in dec for p in patterns): return dec
                    except asyncio.TimeoutError: break
                return buf.decode("utf-8","replace")
            await read_until(["login:","username:","name:"])
            w.write((user+"\r\n").encode()); await w.drain()
            await read_until(["password:","passwd:"])
            w.write((passwd+"\r\n").encode()); await w.drain()
            result = await read_until(["$","#",">","last login","welcome","incorrect","failed","denied"])
            w.close()
            fail = any(f in result.lower() for f in ["incorrect","failed","denied","invalid"])
            ok   = any(s in result for s in ["$","#",">","last login","welcome"]) and not fail
            return ok, result[:100]
        except Exception as e: return False, str(e)
    return handler


# ─── VNC ─────────────────────────────────────────────────────────────────────
def make_vnc_handler(host, port=5900, timeout=8.0, **kw):
    async def handler(user, passwd):
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            version_b = await asyncio.wait_for(r.read(12), timeout=timeout)
            if b"RFB" not in version_b: w.close(); return False, "not VNC"
            w.write(b"RFB 003.003\n"); await w.drain()
            sec = await asyncio.wait_for(r.read(4), timeout=timeout)
            if len(sec)<4: w.close(); return False,"short"
            sec_type = struct.unpack("!I",sec)[0]
            if sec_type==1: w.close(); return True,"NO_AUTH"
            if sec_type==2:
                challenge = await asyncio.wait_for(r.read(16), timeout=timeout)
                if len(challenge)!=16: w.close(); return False,"bad challenge"
                key = (passwd[:8]+"\x00"*8)[:8].encode("latin-1","replace")
                rkey = bytes(int(f"{b:08b}"[::-1],2) for b in key)
                try:
                    from Crypto.Cipher import DES
                    resp = DES.new(rkey,DES.MODE_ECB).encrypt(challenge)
                except ImportError:
                    w.close(); return False,"pip install pycryptodome for VNC"
                w.write(resp); await w.drain()
                result = await asyncio.wait_for(r.read(4), timeout=timeout)
                w.close()
                if result and struct.unpack("!I",result)[0]==0: return True,"SUCCESS"
                return False,"auth_failed"
            w.close(); return False,f"sec_type:{sec_type}"
        except Exception as e: return False,str(e)
    return handler


# ─── SMB (Raw NTLMv2 — no impacket needed) ───────────────────────────────────
def make_smb_handler(host, port=445, timeout=8.0, domain='', **kw):
    """Raw NTLMv2 SMB brute — impacket optional fallback"""
    from lightscan.brute.handlers.smb_raw import make_smb_raw_handler
    raw = make_smb_raw_handler(host, port, timeout, domain)

    async def handler(user, passwd):
        ok, msg = await raw(user, passwd)
        if msg == "negotiate_failed":
            try:
                from impacket.smbconnection import SMBConnection
                import asyncio as _a
                def _imp():
                    try:
                        c = SMBConnection(host, host, timeout=int(timeout))
                        c.login(user, passwd, domain); c.logoff(); return True, "SUCCESS"
                    except Exception as e: return False, str(e).lower()
                return await _a.get_event_loop().run_in_executor(None, _imp)
            except ImportError: pass
        return ok, msg
    return handler


# ─── RDP (Raw CredSSP/NLA — no impacket needed) ───────────────────────────────
def make_rdp_handler(host, port=3389, timeout=10.0, domain='', **kw):
    """Full RDP brute: X.224 negotiate → TLS → CredSSP NTLMv2 (raw)"""
    from lightscan.brute.handlers.rdp_raw import make_rdp_handler as _raw
    return _raw(host, port, timeout, domain)


# ─── LDAP ────────────────────────────────────────────────────────────────────
def make_ldap_handler(host, port=389, base_dn="", timeout=8.0, **kw):
    try:
        import ldap3
        async def handler(user, passwd):
            def _try():
                try:
                    srv  = ldap3.Server(host, port=port, get_info=ldap3.NONE)
                    conn = ldap3.Connection(srv, user=user, password=passwd,
                                           authentication=ldap3.SIMPLE,
                                           read_only=True, receive_timeout=timeout)
                    if conn.bind(): conn.unbind(); return True,"SUCCESS"
                    return False, str(conn.result)
                except Exception as e: return False,str(e)
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, _try)
        return handler
    except ImportError:
        async def ldap_raw(user, passwd):
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
                ub=user.encode(); pb=passwd.encode()
                def alen(n): return bytes([n]) if n<128 else bytes([0x82,(n>>8)&0xFF,n&0xFF])
                pw_ctx = bytes([0x80,len(pb)])+pb
                bind_req = bytes([0x02,0x01,0x03])+bytes([0x04,len(ub)])+ub+pw_ctx
                bind_msg = bytes([0x60])+alen(len(bind_req))+bind_req
                pdu = bytes([0x30])+alen(len(bind_msg)+7)+bytes([0x02,0x01,0x01])+bind_msg
                w.write(pdu); await w.drain()
                resp = await asyncio.wait_for(r.read(1024), timeout=timeout)
                w.close()
                if resp and len(resp)>6 and resp[-3]==0x00: return True,"SUCCESS"
                return False,"auth_failed"
            except Exception as e: return False,str(e)
        print("\033[38;5;240m[!] pip install ldap3  (raw LDAP fallback active)\033[0m")
        return ldap_raw


# ─── Registry ────────────────────────────────────────────────────────────────
PROTOCOLS: dict = {
    "ssh":      (make_ssh_handler,      22),
    "ftp":      (make_ftp_handler,      21),
    "smtp":     (make_smtp_handler,     587),
    "http":     (make_http_handler,     80),
    "mysql":    (make_mysql_handler,    3306),
    "postgres": (make_postgres_handler, 5432),
    "mssql":    (make_mssql_handler,    1433),
    "telnet":   (make_telnet_handler,   23),
    "vnc":      (make_vnc_handler,      5900),
    "smb":      (make_smb_handler,      445),
    "rdp":      (make_rdp_handler,      3389),
    "ldap":     (make_ldap_handler,     389),
}

def get_handler(protocol: str, host: str, port: int = None, **kwargs):
    proto = protocol.lower()
    if proto not in PROTOCOLS:
        raise ValueError(f"Unknown protocol: {proto}. Available: {list(PROTOCOLS)}")
    factory, default_port = PROTOCOLS[proto]
    return factory(host, port or default_port, **kwargs)
