"""LightScan v2.0 PHANTOM — DNS Enumeration | Developer: Light"""
from __future__ import annotations
import asyncio, json, socket, struct, time, urllib.request, urllib.parse
from lightscan.core.engine import ScanResult, Severity

DEFAULT_SUBS = [
    "www","mail","smtp","pop","imap","ftp","ssh","vpn","remote","dev","staging","test",
    "uat","prod","api","admin","portal","login","auth","sso","cdn","static","media",
    "img","assets","git","gitlab","jenkins","jira","confluence","monitoring","grafana",
    "kibana","splunk","db","database","mysql","postgres","redis","mongo","ns1","ns2",
    "mx1","mx2","relay","gateway","proxy","internal","intranet","corp","exchange",
    "webmail","owa","autodiscover","backup","files","storage","s3","blob","app","apps",
    "mobile","m","secure","ssl","beta","alpha","sandbox","demo","preview","api2","v1",
    "v2","old","new","legacy","dev2","test2","stage","qa","uat2","admin2","panel",
]

def _build_query(qname, qtype=1):
    txid = int(time.time()) & 0xFFFF
    hdr  = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    labels = b""
    for part in qname.split("."):
        enc = part.encode(); labels += struct.pack("B", len(enc)) + enc
    return hdr + labels + b"\x00" + struct.pack("!HH", qtype, 1)

async def dns_query(host, qtype="A", ns="8.8.8.8", timeout=3.0):
    TYPES = {"A":1,"AAAA":28,"MX":15,"NS":2,"TXT":16,"CNAME":5,"SOA":6,"PTR":12}
    qt = TYPES.get(qtype.upper(), 1)

    class P(asyncio.DatagramProtocol):
        def __init__(self): self.r=None; self.e=asyncio.Event()
        def datagram_received(self,d,a): self.r=d; self.e.set()
        def error_received(self,ex): self.e.set()

    try:
        loop = asyncio.get_event_loop()
        t, p = await loop.create_datagram_endpoint(P, remote_addr=(ns,53))
        t.sendto(_build_query(host, qt))
        await asyncio.wait_for(p.e.wait(), timeout=timeout)
        t.close()
        if p.r: return _parse(p.r, qtype)
    except Exception: pass
    return []

def _parse(data, qtype):
    results = []
    try:
        ancount = struct.unpack("!H", data[6:8])[0]
        if not ancount: return []
        pos = 12
        # Skip question section
        while pos < len(data) and data[pos] != 0:
            if data[pos] & 0xC0 == 0xC0: pos += 2; break
            pos += data[pos] + 1
        else: pos += 1
        pos += 4
        for _ in range(min(ancount, 20)):
            if pos >= len(data): break
            if data[pos] & 0xC0 == 0xC0: pos += 2
            else:
                while pos < len(data) and data[pos] != 0: pos += data[pos] + 1
                pos += 1
            if pos + 10 > len(data): break
            rtype,_,_,rdlen = struct.unpack("!HHIH", data[pos:pos+10]); pos += 10
            rd = data[pos:pos+rdlen]; pos += rdlen
            if rtype == 1 and len(rd) == 4:
                results.append(socket.inet_ntoa(rd))
            elif rtype == 28 and len(rd) == 16:
                results.append(socket.inet_ntop(socket.AF_INET6, rd))
            elif rtype == 16:
                txts=[]; p2=0
                while p2<len(rd): l=rd[p2]; p2+=1; txts.append(rd[p2:p2+l].decode("utf-8","replace")); p2+=l
                results.append(" ".join(txts))
            elif rtype in (2,15):  # NS, MX
                try:
                    name=[]; p2=0
                    if rtype==15: p2=2  # skip preference
                    while p2<len(rd) and rd[p2]!=0:
                        if rd[p2]&0xC0==0xC0: break
                        l=rd[p2]; p2+=1; name.append(rd[p2:p2+l].decode("utf-8","replace")); p2+=l
                    results.append(".".join(name))
                except Exception: pass
    except Exception: pass
    return results

def crtsh(domain, timeout=10.0):
    subs = set()
    try:
        url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent":"LightScan/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            for e in json.loads(r.read()):
                for sub in e.get("name_value","").split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(domain) and sub != domain: subs.add(sub)
    except Exception: pass
    return sorted(subs)

async def brute_sub(domain, wordlist=None, ns="8.8.8.8", timeout=2.0, concurrency=60):
    wl  = wordlist or DEFAULT_SUBS
    sem = asyncio.Semaphore(concurrency)
    results = []
    async def check(sub):
        async with sem:
            fqdn = f"{sub}.{domain}"
            ips  = await dns_query(fqdn, "A", ns, timeout)
            if ips:
                results.append(ScanResult("dns-brute", fqdn, 53, "resolved",
                    Severity.INFO, f"A → {', '.join(ips[:3])}", {"fqdn":fqdn,"ips":ips}))
    await asyncio.gather(*[check(s) for s in wl])
    return results

async def full_dns_enum(domain, ns="8.8.8.8", axfr=True, brute=True, use_crtsh=True, wordlist=None):
    results=[]; ns_ips=[]
    for qtype in ("A","AAAA","MX","NS","TXT","SOA"):
        records = await dns_query(domain, qtype, ns)
        for rec in records:
            sev = Severity.INFO
            if qtype=="TXT" and any(x in rec.lower() for x in ("v=spf","v=dmarc")): sev=Severity.LOW
            results.append(ScanResult(f"dns-{qtype.lower()}", domain, 53, "found",
                sev, f"{qtype}: {rec}", {"type":qtype,"value":rec}))
            if qtype=="NS":
                try: ns_ips.append(socket.gethostbyname(rec.rstrip(".")))
                except: pass

    if axfr and ns_ips:
        for ns_ip in ns_ips[:3]:
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(ns_ip,53), timeout=5.0)
                q = _build_query(domain, 252)
                writer.write(struct.pack("!H",len(q))+q); await writer.drain()
                raw = await asyncio.wait_for(reader.read(65535), timeout=8.0)
                writer.close()
                import re
                for m in re.finditer(r"[a-zA-Z0-9_\-]+\."+re.escape(domain), raw.decode("utf-8","replace")):
                    results.append(ScanResult("dns-axfr", domain, 53, "zone-transfer",
                        Severity.CRITICAL, f"AXFR from {ns_ip}: {m.group()}"))
            except Exception: pass

    if use_crtsh:
        for sub in crtsh(domain):
            results.append(ScanResult("dns-crtsh", sub, 443, "cert-found",
                Severity.INFO, f"CT log: {sub}", {"subdomain":sub}))

    if brute:
        results.extend(await brute_sub(domain, wordlist, ns))

    print(f"\033[38;5;196m[DNS]\033[0m {domain}: {len(results)} records found")
    return results
