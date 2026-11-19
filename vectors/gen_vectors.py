#!/usr/bin/env python3
"""
ShieldNet v1 golden-vector generator.

Computes the reference byte values for spec/transport.md — the key schedule,
the four admission messages, the envelope and sequence reconstruction (Appendix
A), and the worked admission (Appendix C) — from an implementation independent of
any other: Python stdlib HMAC/HKDF plus the `cryptography` library's X25519 and
ChaCha20-Poly1305. Emits the vector file vectors/shieldnet-v1-vectors.json.

The vectors are derived from the formulas in the specification, not dumped from an
implementation, so an error that an implementation shares with itself is caught.
The generator is checked in beside the JSON so its provenance is reviewable, and
an implementation's tests assert the JSON; they do not originate it.

Run:  python3 vectors/gen_vectors.py > vectors/shieldnet-v1-vectors.json
"""
import hashlib, hmac, json, sys
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

def L(s): return bytes([len(s)]) + s.encode()
def extract(salt, ikm):
    if salt == b"": salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()
def expand(prk, info, n):
    out, t, c = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([c]), hashlib.sha256).digest()
        out += t; c += 1
    return out[:n]
def h128(k, m): return hmac.new(k, m, hashlib.sha256).digest()[:16]
def hx(b): return b.hex()

# Fixed nominal inputs, published with the suite.
PSK       = bytes(range(32))
DEV       = bytes([0x11] * 8)
NONCE     = bytes([0x22] * 24)
ETAG      = bytes([0x33] * 8)
COOKIE    = bytes([0x44] * 16)
AEPOCH    = bytes([0x55] * 8)
CS        = bytes([0x88] * 32)          # cookie_secret
CEPOCH    = bytes([0, 0, 0, 7])         # cookie_epoch = 7, BE uint32
CANON     = bytes([0x99] * 18)          # canonical_source
OBS       = bytes([0xaa] * 18)          # observed_source
EC_PRIV   = bytes([0x66] * 32)
ES_PRIV   = bytes([0x77] * 32)
SEQ_FULL  = 0x0102030405060708
KCP_MSG   = b"hello kcp"

EC = X25519PrivateKey.from_private_bytes(EC_PRIV).public_key().public_bytes_raw()
ES = X25519PrivateKey.from_private_bytes(ES_PRIV).public_key().public_bytes_raw()

prk_psk   = extract(b"", PSK)
k_dev     = expand(prk_psk, L("shieldled/v1/device") + DEV, 32)
prk_st    = extract(b"", k_dev)
k_req     = expand(prk_st, L("shieldled/v1/req"), 32)
k_resp    = expand(prk_st, L("shieldled/v1/resp"), 32)

epoch_tag = hmac.new(CS, L("shieldled/v1/epoch") + CEPOCH, hashlib.sha256).digest()[:8]
cookie    = h128(CS, L("shieldled/v1/cookie") + ETAG + CANON + NONCE)
init_mac  = h128(k_req, L("shieldled/v1/init") + bytes([1, 1]) + NONCE + DEV)
retry_mac = h128(k_resp, L("shieldled/v1/retry") + bytes([2, 1]) + NONCE + ETAG + COOKIE + AEPOCH + DEV + OBS)

context   = bytes([1]) + NONCE + ETAG + COOKIE + AEPOCH + DEV
context2  = context + EC + ES
client_tag = h128(k_req, L("shieldled/v1/finish") + bytes([5, 1]) + context + EC)
admit_pre  = h128(k_resp, L("shieldled/v1/admit-pre") + bytes([6, 1]) + context2)

dh        = X25519PrivateKey.from_private_bytes(EC_PRIV).exchange(
                X25519PrivateKey.from_private_bytes(ES_PRIV).public_key())
master    = extract(L("shieldled/v1/master") + context2, k_dev + dh)
k_c2s     = expand(master, L("shieldled/v1/c2s"), 32)
k_s2c     = expand(master, L("shieldled/v1/s2c"), 32)
k_kcp_c2s = expand(master, L("shieldled/v1/kcp-c2s"), 32)
k_kcp_s2c = expand(master, L("shieldled/v1/kcp-s2c"), 32)
admit_tag = expand(master, L("shieldled/v1/admit"), 16)

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
sw = (SEQ_FULL & 0xFFFFFFFF).to_bytes(4, "big")
ct_tag = ChaCha20Poly1305(k_kcp_c2s).encrypt(b"C2S\x00" + SEQ_FULL.to_bytes(8, "big"), KCP_MSG, sw)
envelope = ct_tag[:-16] + sw + ct_tag[-16:]

# spec/transport.md Appendix A: the S2C direction, so an implementation that used one direction label for
# both — the single likeliest wiring error in the envelope — cannot pass.
ct_tag_s2c = ChaCha20Poly1305(k_kcp_s2c).encrypt(b"S2C\x00" + SEQ_FULL.to_bytes(8, "big"), KCP_MSG, sw)
envelope_s2c = ct_tag_s2c[:-16] + sw + ct_tag_s2c[-16:]

# The two envelopes above seal a 9-octet plaintext: they pin the sealing, but at 29
# octets they are below spec/transport.md 5.7's 44-octet minimum and a receiver discards them. This
# one is a datagram a device accepts: the promoting datagram of a session — one KCP
# PUSH segment, sn = 0, carrying KCP_MSG — sealed client-to-device at seq_full = 1.
# The KCP header is little-endian (spec/transport.md §13).
import struct
KCP_CONV = 0x11223344
kcp_push = struct.pack("<IBBHIIII", KCP_CONV, 81, 0, 32, 0, 0, 0, len(KCP_MSG)) + KCP_MSG
ct_tag_push = ChaCha20Poly1305(k_kcp_c2s).encrypt(b"C2S\x00" + (1).to_bytes(8, "big"),
                                                  kcp_push, (1).to_bytes(4, "big"))
envelope_push = ct_tag_push[:-16] + (1).to_bytes(4, "big") + ct_tag_push[-16:]

# spec/transport.md 11.5, computed rather than typed, so the table cannot disagree with the rule.
REPLAY_WINDOW = 256
def reconstruct(seq_wire, hwm):
    d32 = (seq_wire - (hwm & 0xFFFFFFFF)) & 0xFFFFFFFF
    return hwm + (d32 if d32 < 0x80000000 else d32 - 0x100000000)
def in_range(candidate, hwm):
    return candidate >= 1 and hwm - candidate <= REPLAY_WINDOW
def rc(seq_wire, hwm):
    return {"seq_wire": seq_wire, "hwm": hwm, "candidate": reconstruct(seq_wire, hwm)}
def rr(why, seq_wire, hwm):
    c = reconstruct(seq_wire, hwm)
    return {"why": why, "seq_wire": seq_wire, "hwm": hwm, "candidate": c,
            "in_range": in_range(c, hwm)}

# spec/transport.md Appendix A: a second PSK, to pin that neither device key is derivable from the other.
PSK2 = bytes([0xA0 + (i % 16) for i in range(32)])
k_dev2 = expand(extract(b"", PSK2), L("shieldled/v1/device") + DEV, 32)

# spec/transport.md Appendix A: a second device_id under the same PSK, to pin that siblings' device keys
# differ.
DEV2 = bytes([0x22] * 8)
k_dev_dev2 = expand(extract(b"", PSK), L("shieldled/v1/device") + DEV2, 32)

# spec/transport.md Appendix A: X25519 against a low-order point. Section 6.4 item 1
# rejects iff the 32-octet output is all zero, and implementations must agree —
# so the expected output is pinned here rather than left to each library.
LOW_ORDER = bytes([0xe0,0xeb,0x7a,0x7c,0x3b,0x41,0xb8,0xae,0x16,0x56,0xe3,0xfa,0xf1,0x9f,
                   0xc4,0x6a,0xda,0x09,0x8d,0xeb,0x9c,0x32,0xb1,0xfd,0x86,0x62,0x05,0x16,
                   0x5f,0x49,0xb8,0x00])
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    _lo = X25519PrivateKey.from_private_bytes(EC_PRIV).exchange(
        X25519PublicKey.from_public_bytes(LOW_ORDER))
except Exception:
    _lo = bytes(32)  # the library refused it, which is the same verdict
dh_low_order = _lo

MAGIC = b"SLD1Z001"
def hdr(t): return MAGIC + bytes([t, 1])
init_msg  = hdr(1) + NONCE + DEV + init_mac + bytes(198)
retry_msg = hdr(2) + ETAG + COOKIE + AEPOCH + DEV + OBS + retry_mac
finish_msg = hdr(5) + NONCE + ETAG + COOKIE + AEPOCH + EC + client_tag + bytes(142)
admit_msg = hdr(6) + AEPOCH + ES + admit_pre + admit_tag
assert len(init_msg)==256 and len(retry_msg)==84 and len(finish_msg)==256 and len(admit_msg)==82

# ------------------------------------------- spec/transport.md 7.2 table
# The cases Appendix A asks for: "this is where two conforming implementations most
# plausibly diverge." A v4 address is carried in mapped form (a16[12..15]) with
# is_v4 set, matching sn_source_rejected's (is_v4, a16[16]) signature.
def a16_v4(s_):
    o = [int(x) for x in s_.split(".")]
    return bytes(10) + b"\xff\xff" + bytes(o)

def a16_v6(hextets):
    return bytes.fromhex(hextets.replace(":", ""))

# The receiving interface: 192.168.4.1/24 and fe80::1/64.
SRC_LOCAL = [
    {"addr": hx(a16_v4("192.168.4.1")), "is_v4": True, "bits": 24},
    {"addr": hx(a16_v6("fe800000000000000000000000000001")), "is_v4": False, "bits": 64},
]

def sc(name, addr, is_v4, rejected):
    return {"name": name, "addr": hx(addr), "is_v4": is_v4, "rejected": rejected}

SRC_CASES = [
    # v4 rejects
    sc("v4 multicast",         a16_v4("224.0.0.1"),     True,  True),
    sc("v4 multicast high",    a16_v4("239.255.255.250"), True, True),
    sc("v4 limited broadcast", a16_v4("255.255.255.255"), True, True),
    sc("v4 subnet broadcast",  a16_v4("192.168.4.255"), True,  True),
    sc("v4 this-network",      a16_v4("0.0.0.0"),       True,  True),
    sc("v4 this-network high", a16_v4("0.255.255.255"), True,  True),
    sc("v4 loopback",          a16_v4("127.0.0.1"),     True,  True),
    sc("v4 own address",       a16_v4("192.168.4.1"),   True,  True),
    # v4 accepts — these are what the deployment actually uses
    sc("v4 rfc1918 peer",      a16_v4("192.168.4.2"),   True,  False),
    sc("v4 rfc1918 other",     a16_v4("10.0.0.7"),      True,  False),
    sc("v4 link-local",        a16_v4("169.254.1.1"),   True,  False),
    sc("v4 cgnat",             a16_v4("100.64.0.1"),    True,  False),
    sc("v4 subnet host",       a16_v4("192.168.4.254"), True,  False),
    # v6 rejects
    sc("v6 multicast",         a16_v6("ff020000000000000000000000000001"), False, True),
    sc("v6 unspecified",       a16_v6("00000000000000000000000000000000"), False, True),
    sc("v6 loopback",          a16_v6("00000000000000000000000000000001"), False, True),
    sc("v6 mapped v4",         a16_v4("192.168.4.2"),   False, True),
    sc("v6 ipv4-compatible",   a16_v6("00000000000000000000000001020304"), False, True),
    sc("v6 own address",       a16_v6("fe800000000000000000000000000001"), False, True),
    # v6 accepts
    sc("v6 link-local peer",   a16_v6("fe800000000000000000000000000002"), False, False),
    sc("v6 ula",               a16_v6("fd000000000000000000000000000001"), False, False),
    sc("v6 global unicast",    a16_v6("20010db8000000000000000000000001"), False, False),
]

# canonical_source for a v4 and a v6 peer: pins RFC 4291 §2.5.5.2 and the port.
CANON_V4 = a16_v4("192.168.4.2") + (5000).to_bytes(2, "big")
CANON_V6 = a16_v6("fe800000000000000000000000000002") + (5000).to_bytes(2, "big")

# ------------------------------------------------------------- replay script
# Applied in order to ONE fresh window. Covers first-accept, duplicate-reject,
# forward jump, in-window backfill, and both edges of the 256-bit window.
REPLAY = [
    {"seq": 1,    "accept": True,  "why": "first"},
    {"seq": 1,    "accept": False, "why": "duplicate"},
    {"seq": 2,    "accept": True,  "why": "next"},
    {"seq": 1000, "accept": True,  "why": "forward jump sets hwm"},
    {"seq": 999,  "accept": True,  "why": "in-window backfill"},
    {"seq": 999,  "accept": False, "why": "duplicate backfill"},
    {"seq": 745,  "accept": True,  "why": "offset 255, the last in-window value"},
    {"seq": 744,  "accept": False, "why": "offset 256, one past the window"},
    {"seq": 1,    "accept": False, "why": "far below the window"},
    {"seq": 1001, "accept": True,  "why": "forward again"},
]

# ------------------------------------------- spec/transport.md §5 / §8 wire table
# Classification and decode acceptance for malformed and hostile datagrams.
# role: 0 = device, 1 = client. cls: 0 drop, 1 envelope, 2 INIT, 3 RETRY,
# 4 FINISH, 5 ADMIT — the same numbering on both sides. "decodes" is whether the
# type-specific decoder accepts it; a datagram that classifies as a control type
# and then fails length or padding validation is the case 5.6 says these exist
# to pin, because it is where an out-of-bounds read would show up.
ROLE_DEV, ROLE_CLI = 0, 1  # NB: DEV is already the device_id above

def wc(name, role, dgram, cls, decodes):
    return {"name": name, "role": role, "datagram": hx(dgram), "cls": cls,
            "decodes": decodes}

WIRE_CASES = [
    # Valid, for contrast — a table of only rejects proves nothing.
    wc("valid INIT",   ROLE_DEV, init_msg,   2, True),
    wc("valid RETRY",  ROLE_CLI, retry_msg,  3, True),
    wc("valid FINISH", ROLE_DEV, finish_msg, 4, True),
    wc("valid ADMIT",  ROLE_CLI, admit_msg,  5, True),

    # 5.6: a 10-octet datagram carrying only magic+type+version. It classifies
    # by type and is refused on length — reading a field here is the OOB.
    wc("10-octet INIT",   ROLE_DEV, hdr(1), 2, False),
    wc("10-octet RETRY",  ROLE_CLI, hdr(2), 3, False),
    wc("10-octet FINISH", ROLE_DEV, hdr(5), 4, False),
    wc("10-octet ADMIT",  ROLE_CLI, hdr(6), 5, False),

    # Wrong lengths either side of each fixed size.
    wc("INIT one short",  ROLE_DEV, init_msg[:-1],       2, False),
    wc("INIT one long",   ROLE_DEV, init_msg + b"\x00", 2, False),
    wc("ADMIT one short", ROLE_CLI, admit_msg[:-1],      5, False),
    wc("ADMIT one long",  ROLE_CLI, admit_msg + b"\x00", 5, False),
    wc("RETRY one short",  ROLE_CLI, retry_msg[:-1],        3, False),
    wc("RETRY one long",   ROLE_CLI, retry_msg + b"\x00",   3, False),
    wc("FINISH one short", ROLE_DEV, finish_msg[:-1],       4, False),
    wc("FINISH one long",  ROLE_DEV, finish_msg + b"\x00",  4, False),

    # 5.6: padding is zero. Only INIT and FINISH carry padding.
    wc("INIT nonzero padding",   ROLE_DEV, init_msg[:-1] + b"\x01",   2, False),
    wc("FINISH nonzero padding", ROLE_DEV, finish_msg[:-1] + b"\x01", 4, False),

    # spec/transport.md §15: one version exists, and the version is NOT a demultiplexing input.
    # A wrong version still classifies by type — spec/transport.md §8 routes on magic, type and
    # direction — and is refused by the decoder before any field is read.
    wc("wrong version", ROLE_DEV, MAGIC + bytes([1, 2]) + init_msg[10:], 2, False),

    # spec/transport.md §8: reserved types are rejected, not passed to the envelope path.
    wc("reserved type 0x03", ROLE_DEV, MAGIC + bytes([3, 1]) + bytes(246), 0, False),
    wc("reserved type 0x04", ROLE_DEV, MAGIC + bytes([4, 1]) + bytes(246), 0, False),

    # spec/transport.md §8: direction. A device never accepts RETRY/ADMIT; a client never accepts
    # INIT/FINISH. These drop, not fall through to the envelope.
    wc("RETRY at device",  ROLE_DEV, retry_msg,  0, False),
    wc("ADMIT at device",  ROLE_DEV, admit_msg,  0, False),
    wc("INIT at client",   ROLE_CLI, init_msg,   0, False),
    wc("FINISH at client", ROLE_CLI, finish_msg, 0, False),

    # No magic: the envelope path, whatever the first octets say.
    wc("no magic is envelope", ROLE_DEV, bytes(64), 1, False),
    wc("near-magic is envelope", ROLE_DEV, b"SLD1Z00" + bytes(57), 1, False),
]

vectors = {
    "_comment": "Generated by vectors/gen_vectors.py from the formulas in "
                "spec/transport.md; independent of any implementation. "
                "Do not hand-edit.",
    "inputs": {
        "psk": hx(PSK), "device_id": hx(DEV), "client_nonce": hx(NONCE),
        "epoch_tag": hx(ETAG), "cookie": hx(COOKIE), "admission_epoch": hx(AEPOCH),
        "cookie_secret": hx(CS), "cookie_epoch_be": hx(CEPOCH),
        "canonical_source": hx(CANON), "observed_source": hx(OBS),
        "e_c_priv": hx(EC_PRIV), "e_s_priv": hx(ES_PRIV),
        "seq_full": SEQ_FULL, "kcp_msg": hx(KCP_MSG),
        "kcp_conv": KCP_CONV, "kcp_push": hx(kcp_push),
        "psk2": hx(PSK2), "low_order_point": hx(LOW_ORDER),
        "device_id2": hx(DEV2),
    },
    "schedule": {
        "k_dev": hx(k_dev), "k_req": hx(k_req), "k_resp": hx(k_resp),
        "e_c": hx(EC), "e_s": hx(ES),
        "epoch_tag_out": hx(epoch_tag), "cookie_out": hx(cookie),
        "init_mac": hx(init_mac), "retry_mac": hx(retry_mac),
        "client_tag": hx(client_tag), "admit_pre": hx(admit_pre),
        "context": hx(context), "context2": hx(context2),
        "dh": hx(dh), "master": hx(master),
        "k_c2s": hx(k_c2s), "k_s2c": hx(k_s2c),
        "k_kcp_c2s": hx(k_kcp_c2s), "k_kcp_s2c": hx(k_kcp_s2c),
        "admit_tag": hx(admit_tag),
        "envelope": hx(envelope),
        # Additions per Appendix A. prk_psk/prk_static pin the Extract stage, which an
        # error at could otherwise be compensated for by the following Expand.
        "prk_psk": hx(prk_psk), "prk_static": hx(prk_st),
        "envelope_s2c": hx(envelope_s2c),
        "k_dev_psk2": hx(k_dev2),
        "k_dev_dev2": hx(k_dev_dev2),
        "dh_low_order": hx(dh_low_order),
        "envelope_push": hx(envelope_push),
    },
    "messages": {
        "init": hx(init_msg), "retry": hx(retry_msg),
        "finish": hx(finish_msg), "admit": hx(admit_msg),
    },
    "wire_cases": WIRE_CASES,
    "source_local": SRC_LOCAL,
    "source_cases": SRC_CASES,
    "canonical_source": {"v4": hx(CANON_V4), "v6": hx(CANON_V6)},
    "replay_script": REPLAY,
    "reconstruct": [
        rc(0x80000000, 0),
        rc(0x7FFFFFFF, 0),
        rc(1001, 1000),
        rc(999, 1000),
        rc(2, 4294967295),
        rc(0xFFFFFFFE, 0x100000005),      # backward across 2^32
        rc(0, 10),                        # reconstructs to exactly 0
        rc(700, 1000),                    # below the window
        rc(744, 1000),                    # exactly REPLAY_WINDOW below
    ],
    # 11.5's range check on the reconstructed value. A candidate exactly
    # REPLAY_WINDOW below the mark is in range here and is then refused by the
    # replay window (11.4); see replay_script.
    "reconstruct_range": [
        rr("first datagram of a session", 1, 0),
        rr("d32 = 2^31 on an empty window: negative", 0x80000000, 0),
        rr("reconstructs to 0", 0, 10),
        rr("backward across 2^32, inside the window", 0xFFFFFFFE, 0x100000005),
        rr("exactly REPLAY_WINDOW below the mark", 744, 1000),
        rr("one more than REPLAY_WINDOW below", 743, 1000),
        rr("far below the window", 700, 1000),
        rr("above the mark", 1001, 1000),
    ],
    # 5.7's size bounds on an envelope datagram, at the default WIRE_MTU.
    "envelope_size": {
        "wire_mtu": 1400,
        "cases": [
            {"len": 43, "accept": False}, {"len": 44, "accept": True},
            {"len": 1400, "accept": True}, {"len": 1401, "accept": False},
        ],
    },
}
assert [c["candidate"] for c in vectors["reconstruct"][:5]] == \
    [-2147483648, 2147483647, 1001, 999, 4294967298]
json.dump(vectors, sys.stdout, indent=2)
sys.stdout.write("\n")
