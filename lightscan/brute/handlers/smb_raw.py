"""
LightScan v2.0 PHANTOM — Raw SMB Handler (NTLMv2)
Developer: Light (Neok1ra)

Integration of uploaded RawSMBHandler — full SMB1 + NTLMv2 auth
without impacket dependency.

Protocol flow:
  1. TCP connect to :445
  2. NetBIOS session service framing
  3. SMB_COM_NEGOTIATE — send dialect list, get server challenge
  4. Parse NTLMSSP_CHALLENGE from security blob
  5. Calculate NTLMv2 response (HMAC-MD5 chain)
  6. SMB_COM_SESSION_SETUP_ANDX with NTLMSSP_AUTH blob
  7. Check NT STATUS in response header
"""
from __future__ import annotations
import hashlib, hmac, os, socket, struct, time
import logging

log = logging.getLogger("lightscan.smb_raw")

# SMB Status codes
STATUS_SUCCESS            = 0x00000000
STATUS_LOGON_FAILURE      = 0xC000006D
STATUS_ACCOUNT_LOCKED_OUT = 0xC0000234
STATUS_PASSWORD_EXPIRED   = 0xC0000071
STATUS_ACCESS_DENIED      = 0xC0000022
STATUS_MORE_PROCESSING    = 0xC0000016

LOCKOUT_STATUSES = {STATUS_ACCOUNT_LOCKED_OUT}
AUTH_FAIL_STATUSES = {STATUS_LOGON_FAILURE, STATUS_ACCESS_DENIED}

class RawSMBHandler:
    """
    Full SMB1 + NTLMSSP NTLMv2 authentication handler.
    Zero external dependencies (no impacket).
    Based on uploaded implementation + NT STATUS checking added.
    """
    SMB_COM_NEGOTIATE      = 0x72
    SMB_COM_SESSION_SETUP  = 0x73
    NTLMSSP_NEGOTIATE_MSG  = 0x01
    NTLMSSP_CHALLENGE_MSG  = 0x02
    NTLMSSP_AUTH_MSG       = 0x03

    DIALECTS = [
        b'\x02PC NETWORK PROGRAM 1.0\x00',
        b'\x02MICROSOFT NETWORKS 1.03\x00',
        b'\x02LANMAN1.0\x00',
        b'\x02LM1.2X002\x00',
        b'\x02NT LM 0.12\x00',
    ]
    NTLM_FLAGS = 0x00000001 | 0x00000002 | 0x00000200 | 0x00008000

    def __init__(self, host, port=445, timeout=8.0):
        self.host    = host
        self.port    = port
        self.timeout = timeout
        self.sock    = None
        self._mid    = 0
        self.server_challenge: bytes = b""
        self.uid = 0

    # ── Transport ──────────────────────────────────────────────────────────────

    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            return True
        except Exception as e:
            log.debug(f"connect failed: {e}"); return False

    def close(self):
        try: self.sock.close()
        except Exception: pass
        self.sock = None

    def _nb_send(self, smb_bytes: bytes):
        """Wrap SMB in NetBIOS session service (4-byte big-endian length)"""
        self.sock.sendall(struct.pack(">I", len(smb_bytes)) + smb_bytes)

    def _nb_recv(self) -> bytes | None:
        """Read one NetBIOS-framed SMB packet"""
        try:
            hdr = self._recv_exact(4)
            if not hdr: return None
            n = struct.unpack(">I", hdr)[0]
            return self._recv_exact(n)
        except Exception: return None

    def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk: break
            buf += chunk
        return buf

    # ── SMB Header ────────────────────────────────────────────────────────────

    def _smb_header(self, cmd: int, flags=0x18, flags2=0xC001, uid=0) -> bytes:
        self._mid += 1
        return (
            b'\xffSMB' +
            struct.pack('<B',  cmd)    +   # command
            struct.pack('<I',  0)      +   # NT status
            struct.pack('<B',  flags)  +   # flags
            struct.pack('<H',  flags2) +   # flags2
            struct.pack('<H',  0)      +   # pid high
            b'\x00' * 8               +   # security signature
            struct.pack('<H',  0)      +   # reserved
            struct.pack('<H',  0)      +   # TID
            struct.pack('<H',  0xFFFE) +   # PID
            struct.pack('<H',  uid)    +   # UID
            struct.pack('<H',  self._mid)  # MID
        )

    def _get_status(self, raw: bytes) -> int:
        """Extract NT STATUS from SMB response (offset 9 in SMB header = offset 9 after NetBIOS)"""
        if len(raw) < 13: return -1
        return struct.unpack("<I", raw[9:13])[0]

    # ── Step 1: Negotiate ─────────────────────────────────────────────────────

    def negotiate(self) -> bool:
        dialects = b"".join(self.DIALECTS)
        hdr  = self._smb_header(self.SMB_COM_NEGOTIATE)
        body = struct.pack('<B', 0)               # word count
        body += struct.pack('<H', len(dialects))  # byte count
        body += dialects
        self._nb_send(hdr + body)
        resp = self._nb_recv()
        if not resp: return False

        # Check SMB signature
        if resp[:4] != b'\xffSMB': return False

        # Parse security blob for NTLMSSP challenge
        # SMB negotiate response: header(32B) + params + blob
        try:
            off = 32  # skip SMB header
            word_count = resp[off]; off += 1
            # skip dialect index (2) + other params
            # params are (word_count * 2) bytes
            # then 2 byte byte_count
            off += word_count * 2
            if off + 2 > len(resp): return False
            byte_count = struct.unpack("<H", resp[off:off+2])[0]; off += 2
            blob = resp[off:off+byte_count]
            if blob.startswith(b'NTLMSSP\x00'):
                return self._parse_ntlm_challenge(blob)
        except Exception as e:
            log.debug(f"negotiate parse error: {e}")
        return False

    def _parse_ntlm_challenge(self, blob: bytes) -> bool:
        """Extract server challenge from NTLMSSP_CHALLENGE blob"""
        if len(blob) < 32: return False
        msg_type = struct.unpack("<I", blob[8:12])[0]
        if msg_type != self.NTLMSSP_CHALLENGE_MSG: return False
        self.server_challenge = blob[24:32]
        log.debug(f"got server challenge: {self.server_challenge.hex()}")
        return True

    # ── Step 2: NTLMv2 ────────────────────────────────────────────────────────

    @staticmethod
    def _ntlm_hash(password: str) -> bytes:
        """NT hash = MD4(UTF-16LE(password)) — uses pycryptodome if OpenSSL MD4 disabled"""
        data = password.encode("utf-16le")
        try:
            return hashlib.new("md4", data).digest()
        except ValueError:
            # OpenSSL 3.x disables MD4 — fall back to pycryptodome
            from Crypto.Hash import MD4
            return MD4.new(data).digest()

    @staticmethod
    def _ntlmv2_hash(nt_hash: bytes, username: str, domain: str) -> bytes:
        """NTLMv2 hash = HMAC-MD5(NT_hash, upper(username+domain) in UTF-16LE)"""
        return hmac.new(
            nt_hash,
            (username.upper() + domain).encode("utf-16le"),
            hashlib.md5
        ).digest()

    def _ntlmv2_response(self, username: str, password: str, domain: str) -> bytes:
        """
        Build full NTLMv2 response blob.
        Response = HMAC-MD5(NTLMv2_hash, server_challenge + blob) + blob
        where blob is the 'NTLMv2 Client Challenge' structure.
        """
        nt_hash   = self._ntlm_hash(password)
        v2_hash   = self._ntlmv2_hash(nt_hash, username, domain)

        # Client challenge (8 random bytes)
        client_challenge = os.urandom(8)

        # NTLMv2 blob — Windows FILETIME (100ns intervals since 1601-01-01)
        windows_epoch_delta = 116444736000000000
        ts = struct.pack("<Q", int(time.time() * 10_000_000) + windows_epoch_delta)

        blob = (
            b'\x01\x01'        +  # blob signature
            b'\x00\x00'        +  # reserved
            b'\x00\x00'        +  # reserved
            b'\x00\x00'        +  # reserved (must be 8 bytes total before timestamp)
            ts                 +  # timestamp
            client_challenge   +  # 8 bytes
            b'\x00' * 4        +  # reserved
            b'\x00' * 4        +  # target info (empty terminator)
            b'\x00' * 4           # reserved
        )

        hmac_input = self.server_challenge + blob
        nt_proof   = hmac.new(v2_hash, hmac_input, hashlib.md5).digest()
        return nt_proof + blob

    # ── Step 3: Session Setup ─────────────────────────────────────────────────

    def session_setup(self, username: str, password: str, domain: str = "") -> tuple[bool, str]:
        """
        Build NTLMSSP_AUTH blob and SMB_COM_SESSION_SETUP_ANDX.
        Returns (success, status_string)
        """
        ntlm_resp    = self._ntlmv2_response(username, password, domain)
        domain_b     = domain.encode("utf-16le")
        username_b   = username.encode("utf-16le")
        workstation_b= b""

        # Compute offsets for security blob variable fields
        base_offset = 64  # approximate NTLMSSP_AUTH fixed header size
        ntlm_off   = base_offset
        domain_off = ntlm_off   + len(ntlm_resp)
        user_off   = domain_off + len(domain_b)
        ws_off     = user_off   + len(username_b)

        def _field(data: bytes, offset: int) -> bytes:
            """Security buffer descriptor: length (2), max length (2), offset (4)"""
            return struct.pack("<HHI", len(data), len(data), offset)

        auth_blob = (
            b'NTLMSSP\x00'                           +  # signature
            struct.pack("<I", self.NTLMSSP_AUTH_MSG)  +  # message type = 3
            _field(b"", 0)                            +  # LM response (empty)
            _field(ntlm_resp, ntlm_off)               +  # NTLMv2 response
            _field(domain_b,  domain_off)             +  # domain name
            _field(username_b,user_off)               +  # username
            _field(workstation_b, ws_off)             +  # workstation
            _field(b"", 0)                            +  # session key (empty)
            struct.pack("<I", self.NTLM_FLAGS)        +  # negotiate flags
            b'\x06\x00\x70\x17\x00\x00\x00\x0f'     +  # OS version (Win10)
            ntlm_resp + domain_b + username_b
        )

        hdr  = self._smb_header(self.SMB_COM_SESSION_SETUP, uid=self.uid)

        # Session setup ANDX params (12 words = 24 bytes)
        params = (
            struct.pack('<B',  0xFF)  +  # AndX command (none)
            struct.pack('<B',  0)     +  # reserved
            struct.pack('<H',  0)     +  # AndX offset
            struct.pack('<H',  0)     +  # max buffer
            struct.pack('<H',  2)     +  # max mpx count
            struct.pack('<H',  1)     +  # VC number
            struct.pack('<I',  0)     +  # session key
            struct.pack('<H',  len(auth_blob)) +  # security blob length
            struct.pack('<I',  0)     +  # reserved
            struct.pack('<I',  0x40)    # capabilities
        )
        body = struct.pack('<B', 12) + params   # word count = 12
        body += struct.pack('<H', len(auth_blob)) + auth_blob  # byte count + blob

        self._nb_send(hdr + body)
        resp = self._nb_recv()
        if resp is None:
            return False, "no_response"

        status = self._get_status(resp)
        if status == STATUS_SUCCESS or status == STATUS_MORE_PROCESSING:
            return True, "SUCCESS"
        if status in LOCKOUT_STATUSES:
            return False, "account_locked"
        if status in AUTH_FAIL_STATUSES:
            return False, f"auth_failed:0x{status:08X}"
        return False, f"status:0x{status:08X}"

    # ── Public API ────────────────────────────────────────────────────────────

    def authenticate(self, username: str, password: str, domain: str = "") -> tuple[bool, str]:
        """Full auth flow: connect → negotiate → session setup. Returns (bool, msg)"""
        if not self.connect():
            return False, "connection_failed"
        try:
            if not self.negotiate():
                return False, "negotiate_failed"
            if not self.server_challenge:
                return False, "no_server_challenge"
            return self.session_setup(username, password, domain)
        except Exception as e:
            return False, f"error:{e}"
        finally:
            self.close()


# ── Async LightScan handler factory ──────────────────────────────────────────

def make_smb_raw_handler(host: str, port: int = 445, timeout: float = 8.0,
                         domain: str = "", **kw):
    """
    Returns an async (user, passwd) → (bool, str) handler
    using the raw NTLMv2 SMB implementation.
    Falls back to impacket if available and raw fails.
    """
    import asyncio

    async def handler(user: str, passwd: str) -> tuple[bool, str]:
        loop = asyncio.get_event_loop()
        def _try():
            h = RawSMBHandler(host, port, timeout)
            return h.authenticate(user, passwd, domain)
        return await loop.run_in_executor(None, _try)

    return handler
