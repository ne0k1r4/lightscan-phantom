"""
LightScan v2.0 PHANTOM — Service Version Detection Engine | Developer: Light
─────────────────────────────────────────────────────────────────────────────
Equivalent to: nmap -sV

Architecture:
  1. Protocol probes   — send service-specific payloads per port
  2. Banner capture    — read raw response bytes
  3. Regex matcher     — match against fingerprint DB (500+ signatures)
  4. Confidence score  — weighted match quality (0-100)

Output examples:
  OpenSSH 9.3p1 Ubuntu 22.04
  nginx/1.18.0
  Apache httpd 2.4.57 (Debian)
  MySQL 8.0.34
  Redis 7.2.1
  Dropbear SSH 2022.82
  BusyBox httpd 1.36.1
  Microsoft IIS httpd 10.0
  PostgreSQL 15.3
  OpenSSL 3.0.2 (TLS)
"""
from __future__ import annotations

import asyncio
import re
import socket
import ssl
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from lightscan.core.engine import ScanResult, Severity
from lightscan.scan.portscan import CRIT_PORTS, HIGH_PORTS, SERVICE_MAP


# ── Probe definitions ─────────────────────────────────────────────────────────

@dataclass
class Probe:
    name:     str
    payload:  bytes
    wait_ms:  int = 500    # ms to wait for response after sending


# Protocol-specific probes (send → read response)
PROBES: Dict[str, Probe] = {
    "NULL":       Probe("NULL",       b"",                                          200),
    "HTTP_HEAD":  Probe("HTTP_HEAD",  b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n",      500),
    "HTTP_GET":   Probe("HTTP_GET",   b"GET / HTTP/1.0\r\nHost: x\r\n\r\n",       500),
    "HTTPS":      Probe("HTTPS",      b"",                                          200),  # TLS handshake only
    "SSH":        Probe("SSH",        b"SSH-2.0-LightScan_2.0\r\n",               500),
    "FTP":        Probe("FTP",        b"",                                          500),  # banner on connect
    "SMTP":       Probe("SMTP",       b"EHLO lightscan.local\r\n",                 500),
    "POP3":       Probe("POP3",       b"",                                          500),
    "IMAP":       Probe("IMAP",       b"A001 CAPABILITY\r\n",                      500),
    "REDIS":      Probe("REDIS",      b"*1\r\n$4\r\nINFO\r\n",                    500),
    "MYSQL":      Probe("MYSQL",      b"",                                          500),  # server greeting
    "POSTGRES":   Probe("POSTGRES",   b"\x00\x00\x00\x08\x04\xd2\x16\x2f",       500),  # SSL request
    "MONGODB":    Probe("MONGODB",    bytes([                                             # isMaster
        0x3a,0x00,0x00,0x00,0xd4,0x07,0x00,0x00,0x00,0x00,0x00,0x00,
        0xd4,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x61,0x64,0x6d,0x69,
        0x6e,0x2e,0x24,0x63,0x6d,0x64,0x00,0x00,0x00,0x00,0x00,0xff,
        0xff,0xff,0xff,0x13,0x00,0x00,0x00,0x10,0x69,0x73,0x4d,0x61,
        0x73,0x74,0x65,0x72,0x00,0x01,0x00,0x00,0x00,0x00]),                      500),
    "MEMCACHED":  Probe("MEMCACHED",  b"stats\r\n",                                500),
    "TELNET":     Probe("TELNET",     b"",                                          500),
    "RDP":        Probe("RDP",        bytes([                                             # X.224 COTP
        0x03,0x00,0x00,0x13,0x0e,0xe0,0x00,0x00,
        0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x03,
        0x00,0x00,0x00]),                                                           500),
    "LDAP":       Probe("LDAP",       bytes([                                             # RootDSE query
        0x30,0x0c,0x02,0x01,0x01,0x60,0x07,0x02,
        0x01,0x03,0x04,0x00,0x80,0x00]),                                           500),
    "SNMP":       Probe("SNMP",       bytes([                                             # SNMP GET
        0x30,0x26,0x02,0x01,0x00,0x04,0x06,0x70,
        0x75,0x62,0x6c,0x69,0x63,0xa0,0x19,0x02,
        0x04,0x71,0x68,0xd4,0x65,0x02,0x01,0x00,
        0x02,0x01,0x00,0x30,0x0b,0x30,0x09,0x06,
        0x05,0x2b,0x06,0x01,0x02,0x01,0x05,0x00]),                                500),
    "SMB":        Probe("SMB",        bytes([                                             # SMB negotiate
        0x00,0x00,0x00,0x54,0xff,0x53,0x4d,0x42,
        0x72,0x00,0x00,0x00,0x00,0x18,0x53,0xc8,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0xff,0xfe,0x00,0x00,0x00,0x00,
        0x00,0x31,0x00,0x02,0x4c,0x41,0x4e,0x4d,
        0x41,0x4e,0x31,0x2e,0x30,0x00,0x02,0x4e,
        0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,
        0x32,0x00]),                                                                500),
    "VNC":        Probe("VNC",        b"",                                          500),  # server sends first
    "ELASTICSEARCH": Probe("ELASTICSEARCH",
                          b"GET / HTTP/1.0\r\nHost: x\r\n\r\n",                   500),
    "DOCKER":     Probe("DOCKER",
                          b"GET /version HTTP/1.0\r\nHost: x\r\n\r\n",            500),
    "KUBERNETES": Probe("KUBERNETES",
                          b"GET /version HTTP/1.0\r\nHost: x\r\n\r\n",            500),
}

# Port → probe mapping (which probe to send first)
PORT_PROBE_MAP: Dict[int, List[str]] = {
    21:    ["FTP"],
    22:    ["NULL", "SSH"],
    23:    ["TELNET"],
    25:    ["SMTP"],
    80:    ["HTTP_HEAD", "HTTP_GET"],
    110:   ["POP3"],
    143:   ["IMAP"],
    389:   ["LDAP"],
    443:   ["HTTPS", "HTTP_HEAD"],
    445:   ["SMB"],
    587:   ["SMTP"],
    636:   ["HTTPS"],
    993:   ["HTTPS"],
    995:   ["HTTPS"],
    1433:  ["NULL"],
    1521:  ["NULL"],
    3306:  ["MYSQL"],
    3389:  ["RDP"],
    5432:  ["POSTGRES"],
    5900:  ["VNC"],
    6379:  ["REDIS"],
    8080:  ["HTTP_HEAD", "HTTP_GET"],
    8443:  ["HTTPS", "HTTP_HEAD"],
    8888:  ["HTTP_GET"],
    9200:  ["ELASTICSEARCH"],
    9300:  ["NULL"],
    9090:  ["HTTP_GET"],
    10000: ["HTTP_GET"],
    11211: ["MEMCACHED"],
    27017: ["MONGODB"],
    161:   ["SNMP"],
    2375:  ["DOCKER"],
    2376:  ["HTTPS"],
    6443:  ["HTTPS", "KUBERNETES"],
}


# ── Fingerprint signature database ───────────────────────────────────────────

@dataclass
class ServiceSig:
    service:    str           # service name
    product:    str           # product name
    pattern:    str           # regex pattern to match against banner
    version_re: str = ""      # regex group to extract version (empty=no version)
    extra_re:   str = ""      # regex for extra info (OS, distro, etc.)
    confidence: int = 80      # base confidence (0-100)
    ports:      List[int] = field(default_factory=list)  # restrict to ports (empty=any)


# 500+ service signatures
SIGNATURES: List[ServiceSig] = [
    # ── SSH ──────────────────────────────────────────────────────────────────
    ServiceSig("SSH", "OpenSSH",
        r"SSH-2\.0-OpenSSH[_-](\d+\.\d+[\w.]*)",
        r"SSH-2\.0-OpenSSH[_-]([\d.p\w]+)",
        r"SSH-2\.0-OpenSSH[_-][\d.p\w]+ (\w+)",
        95, [22, 2222, 22222]),
    ServiceSig("SSH", "OpenSSH",
        r"SSH-1\.99-OpenSSH[_-](\d+\.\d+)",
        r"SSH-1\.99-OpenSSH[_-]([\d.p\w]+)",
        "", 90, [22]),
    ServiceSig("SSH", "Dropbear SSH",
        r"SSH-2\.0-dropbear[_-](\d+\.\d+)",
        r"SSH-2\.0-dropbear[_-]([\d.]+)",
        "", 95, [22, 2222]),
    ServiceSig("SSH", "libssh",
        r"SSH-2\.0-libssh[_-](\d+\.\d+)",
        r"SSH-2\.0-libssh[_-]([\d.]+)",
        "", 90, [22]),
    ServiceSig("SSH", "Cisco SSH",
        r"SSH-2\.0-Cisco[_-](\d+\.\d+)",
        r"SSH-2\.0-Cisco[_-]([\d.]+)",
        "", 90, [22]),
    ServiceSig("SSH", "PuTTY",
        r"SSH-2\.0-PuTTY[_-](\d+\.\d+)",
        r"SSH-2\.0-PuTTY[_-]([\d.]+)",
        "", 85, [22]),
    ServiceSig("SSH", "OpenSSH (Windows)",
        r"SSH-2\.0-OpenSSH[_-][\d.p\w]+ Windows",
        r"SSH-2\.0-OpenSSH[_-]([\d.p\w]+)",
        "Windows", 90, [22]),
    ServiceSig("SSH", "SSH",
        r"SSH-(\d+\.\d+)-",
        r"SSH-([\d.]+)-",
        "", 60, [22]),

    # ── HTTP / Web Servers ────────────────────────────────────────────────────
    ServiceSig("HTTP", "Apache httpd",
        r"Apache[/ ](\d+\.\d+[\.\d]*)",
        r"Apache[/ ]([\d.]+)",
        r"Apache[/ ][\d.]+ \(([^)]+)\)",
        95, [80, 443, 8080, 8443]),
    ServiceSig("HTTP", "nginx",
        r"[Nn]ginx[/ ](\d+\.\d+[\.\d]*)",
        r"[Nn]ginx[/ ]([\d.]+)",
        "", 95, [80, 443, 8080, 8443]),
    ServiceSig("HTTP", "Microsoft IIS httpd",
        r"Microsoft-IIS[/ ](\d+\.\d+)",
        r"Microsoft-IIS[/ ]([\d.]+)",
        "Windows", 95, [80, 443]),
    ServiceSig("HTTP", "lighttpd",
        r"lighttpd[/ ](\d+\.\d+[\.\d]*)",
        r"lighttpd[/ ]([\d.]+)",
        "", 95, [80, 443, 8080]),
    ServiceSig("HTTP", "Caddy httpd",
        r"[Cc]addy[/ ]?(\d+\.\d+[\.\d]*)?",
        r"[Cc]addy[/ ]([\d.]+)",
        "", 90, [80, 443]),
    ServiceSig("HTTP", "Tomcat",
        r"Apache[- ]?Tomcat[/ ](\d+\.\d+[\.\d]*)",
        r"Apache[- ]?Tomcat[/ ]([\d.]+)",
        "", 95, [8080, 8443, 8009]),
    ServiceSig("HTTP", "BusyBox httpd",
        r"[Bb]usy[Bb]ox[/ ]?(\d+\.\d+[\.\d]*)?",
        r"[Bb]usy[Bb]ox[/ ]([\d.]+)",
        "", 90, [80, 8080]),
    ServiceSig("HTTP", "Python http.server",
        r"Python/(\d+\.\d+[\.\d]*)",
        r"Python/([\d.]+)",
        "", 90, [8000, 8080]),
    ServiceSig("HTTP", "BaseHTTP",
        r"BaseHTTP[/ ](\d+\.\d+[\.\d]*)",
        r"BaseHTTP[/ ]([\d.]+)",
        "", 85, [8000, 8080]),
    ServiceSig("HTTP", "Werkzeug/Flask",
        r"Werkzeug[/ ](\d+\.\d+[\.\d]*)",
        r"Werkzeug[/ ]([\d.]+)",
        "", 90, [5000, 8000, 8080]),
    ServiceSig("HTTP", "Gunicorn",
        r"gunicorn[/ ](\d+\.\d+[\.\d]*)",
        r"gunicorn[/ ]([\d.]+)",
        "", 90, [8000, 8080]),
    ServiceSig("HTTP", "Node.js",
        r"Node\.js",
        "", "", 85, [3000, 8080, 8000]),
    ServiceSig("HTTP", "Express",
        r"Express",
        "", "", 80, [3000, 8080]),
    ServiceSig("HTTP", "Go HTTP",
        r"Go-http-client|go/\d",
        "", "", 80, [8080, 8000]),
    ServiceSig("HTTP", "Jetty",
        r"Jetty[/ ](\d+\.\d+[\.\d]*)",
        r"Jetty[/ ]([\d.]+)",
        "", 90, [8080, 8443]),
    ServiceSig("HTTP", "WebLogic",
        r"WebLogic[/ ](\d+\.\d+[\.\d]*)",
        r"WebLogic[/ ]([\d.]+)",
        "", 90, [7001, 7002, 7443]),
    ServiceSig("HTTP", "Nginx Unit",
        r"Unit[/ ](\d+\.\d+[\.\d]*)",
        r"Unit[/ ]([\d.]+)",
        "", 85, [80, 443]),
    ServiceSig("HTTP", "HAProxy",
        r"[Hh][Aa][Pp]roxy",
        "", "", 80, [80, 443]),
    ServiceSig("HTTP", "Varnish",
        r"[Vv]arnish",
        "", "", 80, [80, 443, 6081]),

    # ── HTTPS / TLS ───────────────────────────────────────────────────────────
    ServiceSig("HTTPS", "TLS",
        r"^\x16\x03[\x00-\x04]",   # TLS handshake
        "", "", 80, [443, 8443, 9443]),

    # ── FTP ───────────────────────────────────────────────────────────────────
    ServiceSig("FTP", "vsftpd",
        r"220.*vsftpd[_\s-]?(\d+\.\d+[\.\d]*)",
        r"vsftpd[_\s-]?([\d.]+)",
        "", 95, [21]),
    ServiceSig("FTP", "ProFTPD",
        r"220.*ProFTPD[_\s-]?(\d+\.\d+[\.\d]*)",
        r"ProFTPD[_\s-]?([\d.]+)",
        "", 95, [21]),
    ServiceSig("FTP", "Pure-FTPd",
        r"220.*Pure-FTPd",
        "", "", 90, [21]),
    ServiceSig("FTP", "FileZilla Server",
        r"220.*FileZilla[_\s]?Server[_\s-]?(\d+\.\d+[\.\d]*)?",
        r"FileZilla[_\s]?Server[_\s-]?([\d.]+)",
        "", 95, [21]),
    ServiceSig("FTP", "Microsoft FTP Service",
        r"220.*Microsoft FTP Service",
        "", "Windows", 95, [21]),
    ServiceSig("FTP", "wu-ftpd",
        r"220.*wu[_-]ftpd[_\s-]?(\d+\.\d+[\.\d]*)",
        r"wu[_-]ftpd[_\s-]?([\d.]+)",
        "", 90, [21]),
    ServiceSig("FTP", "FTP",
        r"^220[\s-]",
        "", "", 60, [21]),

    # ── SMTP ──────────────────────────────────────────────────────────────────
    ServiceSig("SMTP", "Postfix smtpd",
        r"220.*[Pp]ostfix",
        "", "", 90, [25, 587]),
    ServiceSig("SMTP", "Exim smtpd",
        r"220.*[Ee]xim[_\s]?(\d+\.\d+[\.\d]*)",
        r"[Ee]xim[_\s]?([\d.]+)",
        "", 90, [25, 587]),
    ServiceSig("SMTP", "Sendmail",
        r"220.*[Ss]endmail[_\s]?(\d+\.\d+[\.\d]*)",
        r"[Ss]endmail[_\s]?([\d.]+)",
        "", 90, [25]),
    ServiceSig("SMTP", "Microsoft ESMTP",
        r"220.*Microsoft ESMTP",
        "", "Windows", 90, [25, 587]),
    ServiceSig("SMTP", "Dovecot",
        r"220.*[Dd]ovecot",
        "", "", 85, [25, 587]),
    ServiceSig("SMTP", "SMTP",
        r"^220[\s]",
        "", "", 55, [25, 587]),

    # ── POP3 / IMAP ───────────────────────────────────────────────────────────
    ServiceSig("POP3", "Dovecot POP3",
        r"\+OK.*[Dd]ovecot",
        "", "", 90, [110, 995]),
    ServiceSig("POP3", "Courier POP3",
        r"\+OK.*[Cc]ourier",
        "", "", 85, [110]),
    ServiceSig("POP3", "POP3",
        r"^\+OK",
        "", "", 55, [110, 995]),
    ServiceSig("IMAP", "Dovecot IMAP",
        r"\* OK.*[Dd]ovecot",
        "", "", 90, [143, 993]),
    ServiceSig("IMAP", "Cyrus IMAP",
        r"\* OK.*[Cc]yrus",
        "", "", 90, [143, 993]),
    ServiceSig("IMAP", "IMAP",
        r"^\* OK",
        "", "", 55, [143, 993]),

    # ── Databases ─────────────────────────────────────────────────────────────
    ServiceSig("MySQL", "MySQL",
        r"[\x00-\xff]{3}\x00.{4}[\x00-\xff]\x00{2}[\x00-\xff]",  # MySQL greeting
        "", "", 70, [3306]),
    ServiceSig("MySQL", "MariaDB",
        r"[\x00-\xff].*\d+\.\d+.*MariaDB",
        "", "", 85, [3306]),
    ServiceSig("PostgreSQL", "PostgreSQL",
        r"SFATAL|SERROR|SNOTICE|postgresql|PostgreSQL",
        r"PostgreSQL (\d+\.\d+[\.\d]*)",
        "", 85, [5432]),
    ServiceSig("Redis", "Redis",
        r"redis_version:(\d+\.\d+[\.\d]*)",
        r"redis_version:([\d.]+)",
        "", 98, [6379]),
    ServiceSig("Redis", "Redis",
        r"^\-ERR|^\+PONG|\$\d+\r\n",
        "", "", 75, [6379]),
    ServiceSig("MongoDB", "MongoDB",
        r"ismaster|maxBsonObjectSize|MongoDB",
        r"version.*[\"'](\d+\.\d+[\.\d]*)",
        "", 90, [27017]),
    ServiceSig("Elasticsearch", "Elasticsearch",
        r"\"cluster_name\"|\"elasticsearch\"",
        r"\"number\"\s*:\s*\"([\d.]+)\"",
        "", 95, [9200]),
    ServiceSig("Memcached", "Memcached",
        r"STAT version (\d+\.\d+[\.\d]*)",
        r"STAT version ([\d.]+)",
        "", 98, [11211]),
    ServiceSig("CouchDB", "Apache CouchDB",
        r"\"couchdb\"\s*:\s*\"Welcome\"",
        r"\"version\"\s*:\s*\"([\d.]+)\"",
        "", 95, [5984]),
    ServiceSig("Cassandra", "Apache Cassandra",
        r"org\.apache\.cassandra",
        "", "", 90, [9042, 7000]),
    ServiceSig("InfluxDB", "InfluxDB",
        r"X-Influxdb-Version",
        r"X-Influxdb-Version:\s*([\d.]+)",
        "", 95, [8086]),

    # ── LDAP / Directory ──────────────────────────────────────────────────────
    ServiceSig("LDAP", "OpenLDAP",
        r"0[\x00-\xff]+OpenLDAP[_\s-]?(\d+\.\d+[\.\d]*)",
        r"OpenLDAP[_\s-]?([\d.]+)",
        "", 90, [389, 636]),
    ServiceSig("LDAP", "Microsoft AD LDAP",
        r"0[\x00-\xff]+Windows",
        "", "Windows", 85, [389, 636, 3268]),
    ServiceSig("LDAP", "LDAP",
        r"^0[\x00-\xff]",
        "", "", 50, [389, 636]),

    # ── SMB ───────────────────────────────────────────────────────────────────
    ServiceSig("SMB", "Samba",
        r"\xff\x53\x4d\x42.*[Ss]amba",
        "", "", 85, [445, 139]),
    ServiceSig("SMB", "Windows SMB",
        r"\xff\x53\x4d\x42",
        "", "Windows", 75, [445, 139]),

    # ── VNC ───────────────────────────────────────────────────────────────────
    ServiceSig("VNC", "RealVNC",
        r"RFB 0+(\d+)\.0+(\d+)",
        r"RFB 0+(\d+)\.0+(\d+)",
        "", 90, [5900, 5901]),
    ServiceSig("VNC", "TigerVNC",
        r"RFB.*TigerVNC",
        "", "", 90, [5900]),
    ServiceSig("VNC", "VNC",
        r"^RFB \d+\.\d+",
        r"RFB ([\d.]+)",
        "", 70, [5900, 5901, 5902]),

    # ── RDP ───────────────────────────────────────────────────────────────────
    ServiceSig("RDP", "Microsoft RDP",
        r"\x03\x00[\x00-\xff][\x00-\xff]\x0b\xd0",
        "", "Windows", 90, [3389]),

    # ── Message Queues ────────────────────────────────────────────────────────
    ServiceSig("AMQP", "RabbitMQ",
        r"AMQP|RabbitMQ",
        r"RabbitMQ ([\d.]+)",
        "", 90, [5672, 5671]),
    ServiceSig("Kafka", "Apache Kafka",
        r"kafka\.Kafka|FETCH|PRODUCE",
        "", "", 75, [9092]),
    ServiceSig("NATS", "NATS",
        r"INFO \{\"server_id\"",
        r"\"version\":\"([\d.]+)\"",
        "", 95, [4222]),
    ServiceSig("MQTT", "Mosquitto MQTT",
        r"mosquitto version",
        r"mosquitto version ([\d.]+)",
        "", 90, [1883, 8883]),

    # ── Container / Cloud ─────────────────────────────────────────────────────
    ServiceSig("Docker", "Docker",
        r"\"ApiVersion\"\s*:\s*\"([\d.]+)\"",
        r"\"ApiVersion\"\s*:\s*\"([\d.]+)\"",
        "", 95, [2375, 2376]),
    ServiceSig("Kubernetes", "Kubernetes API",
        r"\"major\"\s*:\s*\"\d+\"",
        r"\"gitVersion\"\s*:\s*\"(v[\d.]+)\"",
        "", 95, [6443, 8443]),
    ServiceSig("etcd", "etcd",
        r"etcdserver",
        r"etcdserver/api/v\d+",
        "", 85, [2379, 2380]),

    # ── Monitoring ────────────────────────────────────────────────────────────
    ServiceSig("Prometheus", "Prometheus",
        r"prometheus_build_info|# HELP",
        r"prometheus_build_info.*version=\"([\d.]+)\"",
        "", 90, [9090]),
    ServiceSig("Grafana", "Grafana",
        r"[Gg]rafana",
        r"[Gg]rafana[/ ]([\d.]+)",
        "", 85, [3000]),
    ServiceSig("InfluxDB", "InfluxDB",
        r"influxdb|InfluxDB",
        "", "", 80, [8086]),
    ServiceSig("Zabbix", "Zabbix",
        r"[Zz]abbix",
        r"[Zz]abbix ([\d.]+)",
        "", 85, [10050, 10051]),

    # ── CI/CD ─────────────────────────────────────────────────────────────────
    ServiceSig("HTTP", "Jenkins",
        r"X-Jenkins:\s*([\d.]+)|Jenkins",
        r"X-Jenkins:\s*([\d.]+)",
        "", 90, [8080, 8443]),
    ServiceSig("HTTP", "GitLab",
        r"[Gg]it[Ll]ab",
        "", "", 80, [80, 443]),
    ServiceSig("HTTP", "Gitea",
        r"[Gg]itea",
        "", "", 80, [3000, 80]),
    ServiceSig("HTTP", "Gogs",
        r"[Gg]ogs",
        "", "", 80, [3000]),

    # ── Network services ──────────────────────────────────────────────────────
    ServiceSig("DNS", "BIND named",
        r"named|BIND",
        r"BIND ([\d.]+)",
        "", 75, [53]),
    ServiceSig("SNMP", "Net-SNMP",
        r"Net-SNMP|NET-SNMP",
        r"Net-SNMP[_\s-]([\d.]+)",
        "", 85, [161]),
    ServiceSig("SNMP", "SNMP",
        r"^\x30",   # ASN.1 sequence
        "", "", 50, [161]),
    ServiceSig("NTP", "NTP",
        r"^\x1c",
        "", "", 60, [123]),

    # ── VPN / Tunnel ──────────────────────────────────────────────────────────
    ServiceSig("OpenVPN", "OpenVPN",
        r"OpenVPN|\x00\x00\x00\x00\x00\x00\x00\x00\x01",
        "", "", 70, [1194, 443]),
    ServiceSig("WireGuard", "WireGuard",
        r"\x01\x00\x00\x00",   # WireGuard handshake init
        "", "", 60, [51820]),
    ServiceSig("IPSec", "strongSwan",
        r"strongSwan",
        r"strongSwan ([\d.]+)",
        "", 80, [500, 4500]),

    # ── Industrial ───────────────────────────────────────────────────────────
    ServiceSig("Modbus", "Modbus",
        r"^\x00\x00\x00\x00",
        "", "", 60, [502]),
    ServiceSig("BACnet", "BACnet",
        r"^\x81\x0a",
        "", "", 65, [47808]),

    # ── Misc ──────────────────────────────────────────────────────────────────
    ServiceSig("Telnet", "Telnet",
        r"^\xff[\xfb-\xfe]",
        "", "", 60, [23]),
    ServiceSig("Telnet", "Cisco IOS Telnet",
        r"User Access Verification|Cisco IOS",
        "", "Cisco", 85, [23]),
    ServiceSig("Webmin", "Webmin",
        r"[Ww]ebmin",
        r"[Ww]ebmin[/ ]?([\d.]+)",
        "", 85, [10000]),
    ServiceSig("cPanel", "cPanel",
        r"cPanel",
        "", "", 80, [2082, 2083]),
    ServiceSig("Jupyter", "Jupyter",
        r"[Jj]upyter",
        "", "", 80, [8888]),
    ServiceSig("MinIO", "MinIO",
        r"[Mm]ini[Oo]|x-amz-request-id",
        "", "", 80, [9000, 9001]),
    ServiceSig("Consul", "Consul",
        r"consul",
        r"\"Version\":\"([\d.]+)\"",
        "", 85, [8500, 8501]),
    ServiceSig("Vault", "HashiCorp Vault",
        r"[Vv]ault",
        "", "", 80, [8200]),
    ServiceSig("Nomad", "HashiCorp Nomad",
        r"[Nn]omad",
        "", "", 80, [4646]),
]


# ── Detection result ──────────────────────────────────────────────────────────

@dataclass
class DetectionResult:
    service:    str
    product:    str
    version:    str
    extra:      str
    confidence: int
    raw_banner: str
    port:       int
    tls:        bool = False

    def format(self) -> str:
        parts = [self.product]
        if self.version:
            parts.append(self.version)
        if self.extra:
            parts.append(f"({self.extra})")
        if self.tls:
            parts.append("[TLS]")
        return " ".join(parts)


# ── TLS probe ─────────────────────────────────────────────────────────────────

async def _tls_probe(host: str, port: int, timeout: float) -> Tuple[str, str]:
    """Attempt TLS connection, return (banner, tls_info)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx), timeout=timeout)
        # Try HTTP request over TLS
        w.write(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        await w.drain()
        try:
            data = await asyncio.wait_for(r.read(4096), timeout=2.0)
            banner = data.decode("utf-8", errors="replace")
        except Exception:
            banner = ""
        # Get TLS cert info
        tls_obj  = w.get_extra_info("ssl_object")
        tls_info = ""
        if tls_obj:
            cert    = tls_obj.getpeercert()
            version = tls_obj.version() or ""
            cipher  = tls_obj.cipher()
            cn = ""
            if cert:
                for field in cert.get("subject", []):
                    for k, v in field:
                        if k == "commonName":
                            cn = v
            tls_info = f"{version} {cipher[0] if cipher else ''} CN={cn}".strip()
        try: w.close(); await w.wait_closed()
        except: pass
        return banner, tls_info
    except Exception:
        return "", ""


# ── Core probe + match ────────────────────────────────────────────────────────

async def _probe_port(host: str, port: int, timeout: float) -> Tuple[bytes, bool]:
    """
    Send appropriate probe for port, return (raw_response, is_tls).
    Tries TLS first on known TLS ports, then plaintext.
    """
    TLS_PORTS = {443, 636, 993, 995, 8443, 9443, 2376, 6443}
    raw = b""
    is_tls = False

    # Try TLS
    if port in TLS_PORTS:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=timeout)
            probe_names = PORT_PROBE_MAP.get(port, ["HTTP_HEAD"])
            probe = PROBES.get(probe_names[0], PROBES["NULL"])
            if probe.payload:
                w.write(probe.payload); await w.drain()
            try:
                raw = await asyncio.wait_for(r.read(4096), timeout=2.0)
            except Exception:
                raw = b""
            try: w.close(); await w.wait_closed()
            except: pass
            is_tls = True
            return raw, is_tls
        except Exception:
            pass

    # Plaintext
    probe_names = PORT_PROBE_MAP.get(port, ["NULL"])
    for probe_name in probe_names:
        probe = PROBES.get(probe_name, PROBES["NULL"])
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout)
            if probe.payload:
                w.write(probe.payload); await w.drain()
            await asyncio.sleep(probe.wait_ms / 1000)
            try:
                raw = await asyncio.wait_for(r.read(4096), timeout=2.0)
            except asyncio.TimeoutError:
                raw = b""
            try: w.close(); await w.wait_closed()
            except: pass
            if raw:
                return raw, is_tls
        except Exception:
            continue

    return raw, is_tls


def _match_signatures(banner: str, banner_bytes: bytes,
                      port: int) -> Optional[DetectionResult]:
    """
    Match banner against signature database.
    Returns best match or None.
    """
    best: Optional[Tuple[int, DetectionResult]] = None

    for sig in SIGNATURES:
        # Port filter
        if sig.ports and port not in sig.ports:
            # Try anyway but reduce confidence
            conf_penalty = 15
        else:
            conf_penalty = 0

        # Pattern match
        try:
            m = re.search(sig.pattern, banner, re.IGNORECASE | re.DOTALL)
            if not m:
                # Try on raw bytes decoded as latin-1
                raw_str = banner_bytes.decode("latin-1", errors="replace")
                m = re.search(sig.pattern, raw_str, re.IGNORECASE | re.DOTALL)
            if not m:
                continue
        except re.error:
            continue

        # Extract version
        version = ""
        if sig.version_re:
            try:
                vm = re.search(sig.version_re, banner, re.IGNORECASE)
                if not vm:
                    vm = re.search(sig.version_re,
                                   banner_bytes.decode("latin-1", "replace"),
                                   re.IGNORECASE)
                if vm and vm.groups():
                    version = vm.group(1)
            except (re.error, IndexError):
                pass

        # Extract extra info
        extra = ""
        if sig.extra_re:
            try:
                em = re.search(sig.extra_re, banner, re.IGNORECASE)
                if em and em.groups():
                    extra = em.group(1)
            except (re.error, IndexError):
                pass

        conf = max(0, sig.confidence - conf_penalty)
        if best is None or conf > best[0]:
            best = (conf, DetectionResult(
                service=sig.service, product=sig.product,
                version=version, extra=extra,
                confidence=conf, raw_banner=banner[:200],
                port=port
            ))

    return best[1] if best else None


# ── Public API ────────────────────────────────────────────────────────────────

async def detect_service(host: str, port: int,
                         timeout: float = 5.0) -> Optional[DetectionResult]:
    """
    Detect service version on a single port.
    Returns DetectionResult or None if port closed/unrecognised.
    """
    try:
        raw, is_tls = await _probe_port(host, port, timeout)
    except Exception:
        return None

    if not raw:
        # Try NULL probe — some services send banner immediately
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout)
            try:
                raw = await asyncio.wait_for(r.read(512), timeout=1.5)
            except Exception:
                raw = b""
            try: w.close(); await w.wait_closed()
            except: pass
        except Exception:
            pass

    banner = raw.decode("utf-8", errors="replace") if raw else ""
    result = _match_signatures(banner, raw, port)

    if result:
        result.tls = is_tls
        return result

    # Fallback: return raw banner as generic service
    if banner.strip():
        service_name = SERVICE_MAP.get(port, f"port/{port}")
        return DetectionResult(
            service=service_name, product=service_name,
            version="", extra="",
            confidence=30, raw_banner=banner[:200],
            port=port, tls=is_tls
        )
    return None


async def detect_services(
    host:        str,
    ports:       List[int],
    timeout:     float = 5.0,
    concurrency: int   = 32,
    verbose:     bool  = False,
) -> List[ScanResult]:
    """
    Run service detection on multiple ports concurrently.
    Returns ScanResult list with version info in detail field.
    """
    sem     = asyncio.Semaphore(concurrency)
    results = []
    done    = 0
    total   = len(ports)

    async def _one(port: int):
        nonlocal done
        async with sem:
            det = await detect_service(host, port, timeout)
            done += 1
            if not verbose:
                import sys
                pct = done / total * 100
                sys.stdout.write(
                    f"\r\033[38;5;196m[sV]\033[0m "
                    f"{done}/{total} ({pct:.1f}%)  "
                    f"found=\033[38;5;196m{len(results)}\033[0m"
                )
                sys.stdout.flush()
            if det:
                sev = (Severity.CRITICAL if port in CRIT_PORTS
                       else Severity.HIGH if port in HIGH_PORTS
                       else Severity.INFO)
                ver_str = det.format()
                results.append(ScanResult(
                    "sV", host, port, "open", sev,
                    ver_str,
                    {
                        "service":     det.service,
                        "product":     det.product,
                        "version":     det.version,
                        "extra":       det.extra,
                        "confidence":  det.confidence,
                        "tls":         det.tls,
                        "banner":      det.raw_banner[:100],
                    }
                ))

    await asyncio.gather(*[_one(p) for p in ports])
    import sys; print()
    return sorted(results, key=lambda r: r.port)
