"""LightScan v2.0 PHANTOM — Async Port Scanner | Developer: Light"""
from __future__ import annotations
import asyncio, socket, struct
from lightscan.core.engine import ScanResult, Severity

SERVICE_MAP = {
    20:"FTP-DATA",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",69:"TFTP",
    79:"Finger",80:"HTTP",88:"Kerberos",110:"POP3",111:"RPC",119:"NNTP",
    123:"NTP",135:"MSRPC",137:"NetBIOS-NS",138:"NetBIOS-DGM",139:"NetBIOS",
    143:"IMAP",161:"SNMP",389:"LDAP",443:"HTTPS",445:"SMB",465:"SMTPS",
    514:"Syslog",548:"AFP",587:"SMTP-Sub",636:"LDAPS",873:"rsync",
    990:"FTPS",993:"IMAPS",995:"POP3S",1080:"SOCKS",1433:"MSSQL",
    1521:"Oracle",1723:"PPTP",2049:"NFS",2082:"cPanel",2083:"cPanel-SSL",
    3000:"Dev-HTTP",3128:"Squid",3306:"MySQL",3389:"RDP",4443:"HTTPS-Alt",
    5000:"Flask",5432:"PostgreSQL",5800:"VNC-HTTP",5900:"VNC",6379:"Redis",
    6443:"K8s-API",7001:"WebLogic",7443:"WebLogic-SSL",8000:"HTTP-Dev",
    8080:"HTTP-Proxy",8081:"HTTP-Alt",8443:"HTTPS-Alt",8888:"Jupyter",
    9000:"PHP-FPM",9090:"Prometheus",9200:"Elasticsearch",9300:"ES-Transport",
    9443:"HTTPS-Alt",10000:"Webmin",27017:"MongoDB",
}

PROBES = {
    80: b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n",
    6379: b"*1\r\n$4\r\nINFO\r\n",
    9200: b"GET / HTTP/1.0\r\nHost: x\r\n\r\n",
    9090: b"GET /metrics HTTP/1.0\r\nHost: x\r\n\r\n",
    8888: b"GET / HTTP/1.0\r\nHost: x\r\n\r\n",
}

CRIT_PORTS = {445, 3389, 23, 1433, 27017, 9200, 6379, 2049, 1521}
HIGH_PORTS = {21, 22, 3306, 5432, 5900, 389, 636, 8080, 8443, 9090, 10000, 7001}

async def tcp_scan(host, port, timeout=2.0, grab_banner=True):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None

    banner = ""; service = SERVICE_MAP.get(port, f"port/{port}")
    if grab_banner:
        try:
            probe = PROBES.get(port)
            if probe:
                writer.write(probe); await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            else:
                data = await asyncio.wait_for(reader.read(512), timeout=1.0)
            banner = data.decode("utf-8", errors="replace").strip()[:200]
        except Exception: pass
    try: writer.close(); await writer.wait_closed()
    except Exception: pass

    # auto-detect from banner
    if service.startswith("port/") and banner:
        bl = banner.lower()
        if "ssh"      in bl: service = "SSH"
        elif "ftp"    in bl: service = "FTP"
        elif "smtp"   in bl: service = "SMTP"
        elif "http"   in bl: service = "HTTP"
        elif "mysql"  in bl: service = "MySQL"
        elif "redis"  in bl: service = "Redis"
        elif "mongo"  in bl: service = "MongoDB"
        elif "rfb"    in bl: service = "VNC"

    sev = Severity.CRITICAL if port in CRIT_PORTS else Severity.HIGH if port in HIGH_PORTS else Severity.INFO
    detail = service + (f" | {banner[:80]}" if banner else "")
    return ScanResult("portscan", host, port, "open", sev, detail, {"service":service,"banner":banner})

async def udp_scan(host, port, timeout=2.0):
    UDP_PROBES = {
        53:  b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
        161: b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
        123: b"\x1b" + b"\x00" * 47,
    }
    probe = UDP_PROBES.get(port, b"\x00" * 8)
    loop  = asyncio.get_event_loop()
    class P(asyncio.DatagramProtocol):
        def __init__(self): self.r=None; self.e=asyncio.Event()
        def datagram_received(self,d,a): self.r=d; self.e.set()
        def error_received(self,ex): self.e.set()
    try:
        transport, proto = await loop.create_datagram_endpoint(P, remote_addr=(host,port))
        transport.sendto(probe)
        try: await asyncio.wait_for(proto.e.wait(), timeout=timeout)
        except asyncio.TimeoutError: transport.close(); return None
        transport.close()
        if proto.r:
            service = SERVICE_MAP.get(port, f"udp/{port}")
            return ScanResult("portscan-udp", host, port, "open|filtered", Severity.INFO, f"UDP {service} responded")
    except Exception: pass
    return None

def build_scan_tasks(hosts, ports, timeout=2.0, udp=False, banners=True):
    tasks = [(tcp_scan(h, p, timeout, banners), f"{h}:{p}") for h in hosts for p in ports]
    if udp:
        for h in hosts:
            for p in [53, 123, 161]:
                if p in ports: tasks.append((udp_scan(h, p, timeout), f"udp:{h}:{p}"))
    return tasks
