"""
LightScan v2.0 PHANTOM — TCP Flag Parser & ICMP Classification | Developer: Light
──────────────────────────────────────────────────────────────────────────────────
Core fix: replaces naive bitmask comparisons across the scan layer with a
proper flag parser and a full ICMP type-3 code table.

Used by: packetscan.py, syn.py, syn_scanner.py
"""
from __future__ import annotations
from typing import Optional, Tuple

# ── TCP flag bit positions (RFC 793 + RFC 3168) ───────────────────────────────
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40   # RFC 3168 – ECN-Echo
TCP_CWR = 0x80   # RFC 3168 – Congestion Window Reduced

_FLAG_MAP = (
    (TCP_CWR, 'CWR'), (TCP_ECE, 'ECE'), (TCP_URG, 'URG'), (TCP_ACK, 'ACK'),
    (TCP_PSH, 'PSH'), (TCP_RST, 'RST'), (TCP_SYN, 'SYN'), (TCP_FIN, 'FIN'),
)


def parse_tcp_flags(flags: int) -> dict:
    """Return {flag_name: bool} for all 8 TCP flags."""
    return {name: bool(flags & bit) for bit, name in _FLAG_MAP}


def flags_str(flags: int) -> str:
    """Human-readable flag string, e.g. 'SYN|ACK'."""
    active = [name for bit, name in _FLAG_MAP if flags & bit]
    return '|'.join(active) if active else 'NONE'


def classify_tcp(flags: int) -> Optional[str]:
    """
    Classify port state from TCP response flags.
    Returns 'open' | 'closed' | None (unrecognised / not our response).

    More accurate than raw bitmasks:
      SYN+ACK (strict)          → 'open'
      RST (any combination)     → 'closed'   (RST-ACK, pure RST, RST+SYN)
      FIN+ACK (no RST, no SYN)  → 'closed'   (firewall teardown)

    The old check `flags & 0x12 == 0x12` correctly caught SYN+ACK but also
    matched RST+SYN+ACK (0x16) as open. Fixed here.
    """
    f = parse_tcp_flags(flags)
    if f['SYN'] and f['ACK'] and not f['RST'] and not f['FIN']:
        return 'open'
    if f['RST']:
        return 'closed'
    if f['FIN'] and f['ACK'] and not f['SYN'] and not f['RST']:
        return 'closed'
    return None


def is_firewall_rst(flags: int) -> bool:
    """
    Heuristic: RST with no ACK and window=0 often indicates a firewall-generated
    RST (injected inline reset) rather than a genuine host RST-ACK.
    Call with the flags byte; check window separately.
    """
    f = parse_tcp_flags(flags)
    return f['RST'] and not f['ACK']


# ── ICMP Type 3 (Destination Unreachable) classification ─────────────────────
# state: 'filtered' | 'closed' | 'firewall'
# reason: short label for ScanResult.data and verbose output

ICMP3_TABLE: dict = {
    0:  ('filtered', 'net-unreachable'),
    1:  ('filtered', 'host-unreachable'),
    2:  ('filtered', 'proto-unreachable'),
    3:  ('closed',   'port-unreachable'),
    4:  ('filtered', 'fragmentation-needed'),
    5:  ('filtered', 'src-route-failed'),
    6:  ('filtered', 'dst-net-unknown'),
    7:  ('filtered', 'dst-host-unknown'),
    8:  ('filtered', 'src-host-isolated'),
    9:  ('firewall', 'net-admin-prohibited'),
    10: ('firewall', 'host-admin-prohibited'),
    11: ('filtered', 'net-tos-unreachable'),
    12: ('filtered', 'host-tos-unreachable'),
    13: ('firewall', 'comm-admin-prohibited'),
    14: ('firewall', 'host-precedence-violation'),
    15: ('firewall', 'precedence-cutoff'),
}

ICMP_TTL_EXCEEDED    = 11   # type 11 → filtered (TTL hop limit reached)
ICMP_DEST_UNREACHABLE = 3   # type 3 → use ICMP3_TABLE


def classify_icmp3(code: int) -> Tuple[str, str]:
    """
    Map ICMP type-3 code → (state, reason).
    Unknown codes default to filtered.
    """
    return ICMP3_TABLE.get(code, ('filtered', f'icmp3-code{code}'))
