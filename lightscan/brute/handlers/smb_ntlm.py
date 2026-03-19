"""
LightScan v2.0 PHANTOM — Raw SMB/NTLMv2 Handler
Developer: Light

Direct integration of full SMB1 NTLM authentication:
  1. TCP connect to port 445
  2. SMB Negotiate (multi-dialect, extended security)
  3. Parse server's NTLMSSP challenge (8-byte nonce)
  4. Calculate NTLMv2 response (HMAC-MD5)
  5. SMB Session Setup with auth blob
  6. Parse response → success/failure/locked

Requires pycryptodome for HMAC-MD4 (pip install pycryptodome).
Falls back to Python stdlib hmac+hashlib if MD4 is available.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import socket
import struct
import time

log = logging.getLogger("lightscan.smb")

# ─── SMB constants ────────────────────────────────────────────────────────────
_SMB_NEG_CMD     = 0x72
_SMB_SESS_CMD    = 0x73
_NTLMSSP_NEG     = 0x01
_NTLMSSP_CHAL    = 0x02
_NTLMSSP_AUTH    = 0x03
_NTLM_FLAGS      = 0x00000001 | 0x00000002 | 0x00000200   # Unicode + OEM + NTLM

_DIALECTS = (
    b'\x02PC NETWORK PROGRAM 1.0\x00'
    b'\x02MICROSOFT NETWORKS 1.03\x00'
    b'\x02MICROSOFT NETWORKS 3.0\x00'
    b'\x02LANMAN1.0\x00'
    b'\x02LM1.2X002\x00'
    b'\x02NT LM 0.12\x00'
    b'\x02SMB 2.002\x00'
)


# ─── Core SMB class (from Doc 3, refactored) ──────────────────────────────────
class RawSMBAuth:
    def __init__(self, host: str, port: int = 445, timeout: float = 8.0):
        self.host    = host
        self.port    = port
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.server_challenge: bytes | None = None
        self.uid = 0
        self._mid = 0

    # ── Transport ─────────────────────────────────────────────────────────────
    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            return True
        except Exception as e:
            log.debug(f"SMB connect failed: {e}"); return False

    def close(self):
        if self.sock:
            try: self.sock.close()
            except: pass
            self.sock = None

    def _send(self, smb_payload: bytes):
        netbios = struct.pack(">I", len(smb_payload))
        self.sock.sendall(netbios + smb_payload)

    def _recv(self) -> bytes | None:
        try:
            nb = self.sock.recv(4)
            if len(nb) < 4: return None
            plen = struct.unpack(">I", nb)[0]
            data = b""
            while len(data) < plen:
                chunk = self.sock.recv(min(4096, plen - len(data)))
                if not chunk: break
                data += chunk
            return data
        except (socket.timeout, OSError):
            return None

    # ── SMB header builder ────────────────────────────────────────────────────
    def _smb_header(self, cmd: int, flags: int = 0x18, flags2: int = 0xC801,
                    tid: int = 0, uid: int = 0) -> bytes:
        self._mid += 1
        return (
            b'\xffSMB'
            + struct.pack('<B', cmd)       # command
            + struct.pack('<I', 0)         # NTSTATUS
            + struct.pack('<B', flags)
            + struct.pack('<H', flags2)
            + b'\x00' * 12                 # PID high, sig, reserved, TID, PID
            + struct.pack('<H', uid)
            + struct.pack('<H', self._mid)
        )

    # ── Step 1: Negotiate ──────────────────────────────────────────────────────
    def negotiate(self) -> bool:
        body  = struct.pack('<B', 0)                       # word count
        body += struct.pack('<H', len(_DIALECTS))          # byte count
        body += _DIALECTS
        self._send(self._smb_header(_SMB_NEG_CMD) + body)
        resp = self._recv()
        if not resp or len(resp) < 36: return False
        if resp[:4] != b'\xffSMB': return False

        # Try to extract NTLMSSP challenge from security blob
        try:
            # word count tells us parameter size
            wc   = resp[32]
            blob_off = 32 + 1 + wc * 2 + 2
            if blob_off + 2 <= len(resp):
                blob_len = struct.unpack('<H', resp[blob_off:blob_off+2])[0]
                blob = resp[blob_off+2 : blob_off+2+blob_len]
                if blob.startswith(b'NTLMSSP\x00'):
                    self._parse_ntlm_challenge(blob)
        except Exception: pass

        return True

    # ── Step 1b: Parse NTLMSSP challenge ─────────────────────────────────────
    def _parse_ntlm_challenge(self, blob: bytes):
        if len(blob) < 32: return
        msg_type = struct.unpack('<I', blob[8:12])[0]
        if msg_type == _NTLMSSP_CHAL:
            self.server_challenge = blob[24:32]
            log.debug(f"NTLM challenge: {self.server_challenge.hex()}")

    # ── Step 2: NTLMv2 response calculation ───────────────────────────────────
    @staticmethod
    def _md4(data: bytes) -> bytes:
        try:
            return hashlib.new('md4', data).digest()
        except ValueError:
            # MD4 not in stdlib — try pycryptodome
            try:
                from Crypto.Hash import MD4
                return MD4.new(data).digest()
            except ImportError:
                raise RuntimeError("MD4 unavailable: pip install pycryptodome")

    @staticmethod
    def _hmac_md5(key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.md5).digest()

    def _ntlmv2_response(self, username: str, password: str,
                         domain: str, server_challenge: bytes) -> bytes:
        # NTLM hash = MD4(password UTF-16LE)
        nt_hash = self._md4(password.encode('utf-16-le'))

        # NTLMv2 hash = HMAC-MD5(NT hash, uppercase(user+domain) UTF-16LE)
        ntv2_hash = self._hmac_md5(
            nt_hash,
            (username.upper() + domain).encode('utf-16-le')
        )

        # Client challenge (8 random bytes)
        client_challenge = os.urandom(8)

        # Timestamp: Windows FILETIME (100ns since 1601-01-01)
        ts = int((time.time() + 11644473600) * 10_000_000)
        timestamp = struct.pack('<Q', ts)

        # NTLMv2 blob
        blob = (
            b'\x01\x01\x00\x00'        # signature + reserved
            + b'\x00\x00\x00\x00'
            + timestamp
            + client_challenge
            + b'\x00\x00\x00\x00'      # reserved
            # TargetInfo (empty) — real impl would include domain/server name
            + b'\x00\x00\x00\x00'
        )

        # Response = HMAC-MD5(NTLMv2 hash, server_challenge + blob) + blob
        ntv2_response = self._hmac_md5(ntv2_hash, server_challenge + blob) + blob
        return ntv2_response

    # ── Step 3: Session Setup with NTLM auth ─────────────────────────────────
    def session_setup(self, username: str, password: str, domain: str = '') -> str:
        """
        Returns: 'success' | 'failure' | 'locked' | 'error:<msg>'
        """
        if not self.server_challenge:
            return 'error:no_challenge'

        try:
            ntlm_resp = self._ntlmv2_response(username, password, domain, self.server_challenge)
        except Exception as e:
            return f'error:{e}'

        # Build NTLMSSP AUTH blob
        def sec_buf(data: bytes, base_offset: int) -> tuple[bytes, int]:
            hdr = struct.pack('<HHI', len(data), len(data), base_offset)
            return hdr, base_offset + len(data)

        domain_bytes = domain.encode('utf-16-le')
        user_bytes   = username.encode('utf-16-le')
        ws_bytes     = b''
        lm_bytes     = b'\x00' * 24   # LMv2 placeholder

        # Fixed header = 8 (sig+type) + 8 (LM) + 8 (NTLM) + 8 (domain) +
        #                8 (user) + 8 (ws) + 8 (sesskey) + 4 (flags) + 8 (ver) = 72
        base = 72
        lm_hdr,   base = sec_buf(lm_bytes,     base)
        ntlm_hdr, base = sec_buf(ntlm_resp,    base)
        dom_hdr,  base = sec_buf(domain_bytes, base)
        usr_hdr,  base = sec_buf(user_bytes,   base)
        ws_hdr,   base = sec_buf(ws_bytes,     base)

        auth_blob = (
            b'NTLMSSP\x00'
            + struct.pack('<I', _NTLMSSP_AUTH)
            + lm_hdr + ntlm_hdr + dom_hdr + usr_hdr + ws_hdr
            + struct.pack('<HHI', 0, 0, 0)            # session key (empty)
            + struct.pack('<I', _NTLM_FLAGS)
            + b'\x06\x01\x00\x00\x00\x00\x00\x0f'   # OS version (Win10)
            # variable data
            + lm_bytes + ntlm_resp + domain_bytes + user_bytes + ws_bytes
        )

        # SMB session setup parameters
        params = (
            struct.pack('<B', 0xFF)           # no AndX
            + struct.pack('<B', 0)
            + struct.pack('<H', 0)
            + struct.pack('<H', 0xFFFF)       # max buffer
            + struct.pack('<H', 2)            # max mpx
            + struct.pack('<H', 1)            # vc number
            + struct.pack('<I', 0)            # session key
            + struct.pack('<H', len(auth_blob))
            + struct.pack('<I', 0)            # reserved
            + struct.pack('<I', 0x80000054)   # capabilities
        )

        body  = struct.pack('<B', len(params) // 2)  # word count
        body += params
        body += struct.pack('<H', len(auth_blob) + 2)
        body += auth_blob
        body += b'\x00\x00'                          # native OS, native LM

        hdr = self._smb_header(_SMB_SESS_CMD, uid=self.uid)
        self._send(hdr + body)
        resp = self._recv()

        if not resp: return 'error:no_response'

        # NTSTATUS is bytes 4–8 of the SMB header
        if len(resp) < 9: return 'error:short_response'
        ntstatus = struct.unpack('<I', resp[4:8])[0]

        if ntstatus == 0x00000000:   return 'success'
        if ntstatus == 0xC000006D:   return 'failure'          # STATUS_LOGON_FAILURE
        if ntstatus == 0xC0000064:   return 'failure'          # STATUS_NO_SUCH_USER
        if ntstatus == 0xC0000072:   return 'locked'           # STATUS_ACCOUNT_DISABLED
        if ntstatus == 0xC0000234:   return 'locked'           # STATUS_ACCOUNT_LOCKED_OUT
        if ntstatus == 0xC000006E:   return 'locked'           # STATUS_ACCOUNT_RESTRICTION
        return f'error:ntstatus=0x{ntstatus:08x}'

    # ── Full auth flow ────────────────────────────────────────────────────────
    def authenticate(self, username: str, password: str, domain: str = '') -> tuple[bool, str]:
        """Returns (success, message)"""
        if not self.connect():
            return False, 'connection_failed'
        try:
            # Some SMB servers skip negotiate challenge and require a separate
            # NTLMSSP_NEGOTIATE packet to receive the challenge. Handle both.
            if not self.negotiate():
                return False, 'negotiate_failed'

            # If no challenge from negotiate, send explicit NTLMSSP_NEGOTIATE
            if not self.server_challenge:
                neg_blob = (
                    b'NTLMSSP\x00'
                    + struct.pack('<I', _NTLMSSP_NEG)
                    + struct.pack('<I', _NTLM_FLAGS)
                    + b'\x00' * 16   # domain + workstation (empty)
                    + b'\x06\x01\x00\x00\x00\x00\x00\x0f'  # version
                )
                params = (
                    struct.pack('<B', 0xFF) + struct.pack('<B',0) + struct.pack('<H',0)
                    + struct.pack('<H', 0xFFFF) + struct.pack('<H',2)
                    + struct.pack('<H',1) + struct.pack('<I',0)
                    + struct.pack('<H', len(neg_blob))
                    + struct.pack('<I',0) + struct.pack('<I',0)
                )
                body  = struct.pack('<B', len(params)//2) + params
                body += struct.pack('<H', len(neg_blob)+2) + neg_blob + b'\x00\x00'
                hdr   = self._smb_header(_SMB_SESS_CMD, uid=0)
                self._send(hdr + body)
                resp  = self._recv()
                if resp and len(resp) > 36:
                    # Parse the challenge from this response
                    try:
                        wc2 = resp[32]; boff = 32+1+wc2*2+2
                        blen = struct.unpack('<H', resp[boff:boff+2])[0]
                        blob = resp[boff+2:boff+2+blen]
                        if blob.startswith(b'NTLMSSP\x00'):
                            self._parse_ntlm_challenge(blob)
                    except: pass

            if not self.server_challenge:
                return False, 'no_challenge_received'

            result = self.session_setup(username, password, domain)
            if result == 'success':   return True,  'SUCCESS'
            if result == 'locked':    return False, 'ACCOUNT_LOCKED'
            if result == 'failure':   return False, 'auth_failed'
            return False, result
        except Exception as e:
            return False, f'exception:{e}'
        finally:
            self.close()


# ─── LightScan async handler factory ─────────────────────────────────────────
def make_smb_ntlm_handler(host: str, port: int = 445, timeout: float = 8.0,
                          domain: str = '', **kw):
    """
    Returns an async (user, passwd) → (bool, str) handler for BruteEngine.
    Tries impacket first (most reliable), then falls back to RawSMBAuth.
    """
    # ── Prefer impacket ───────────────────────────────────────────────────────
    try:
        from impacket.smbconnection import SMBConnection

        async def impacket_handler(user: str, passwd: str) -> tuple[bool, str]:
            def _try():
                try:
                    conn = SMBConnection(host, host, timeout=int(timeout))
                    conn.login(user, passwd, domain=domain)
                    conn.logoff()
                    return True, 'SUCCESS'
                except Exception as e:
                    msg = str(e).lower()
                    if 'locked' in msg:      return False, 'ACCOUNT_LOCKED'
                    if 'logon_failure' in msg or 'wrong' in msg: return False, 'auth_failed'
                    return False, str(e)
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, _try)

        return impacket_handler

    except ImportError:
        pass

    # ── Fall back to RawSMBAuth (Doc 3) ───────────────────────────────────────
    async def raw_handler(user: str, passwd: str) -> tuple[bool, str]:
        def _try():
            auth = RawSMBAuth(host, port, timeout)
            return auth.authenticate(user, passwd, domain)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _try)

    return raw_handler
