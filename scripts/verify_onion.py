#!/usr/bin/env python3
"""
Derives the Ed25519 public key from hs_ed25519_secret_key and compares it
against hs_ed25519_public_key. Pure Python 3, no external dependencies.

Usage:
    python3 verify_onion_keys.py /path/to/hidden-service/
    python3 verify_onion_keys.py   # defaults to current directory
"""

import sys
import os
import hashlib
import base64

# ── Ed25519 curve parameters (RFC 8032) ──────────────────────────────────────

P = 2**255 - 19                                      # field prime
D = (-121665 * pow(121666, P - 2, P)) % P            # curve constant d
SQRT_M1 = pow(2, (P - 1) // 4, P)                   # sqrt(-1) mod P


def _recover_x(y, sign):
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    return (P - x) if (x & 1) != sign else x


# Base point G in extended coordinates (X, Y, Z, T)
_gy = 4 * pow(5, P - 2, P) % P
_gx = _recover_x(_gy, 0)
G = (_gx, _gy, 1, _gx * _gy % P)


def _point_add(pt1, pt2):
    x1, y1, z1, t1 = pt1
    x2, y2, z2, t2 = pt2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % P, h * g % P, f * g % P, e * h % P


def _scalar_mul(scalar, point):
    result = (0, 1, 1, 0)          # neutral element
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _compress(point):
    zinv = pow(point[2], P - 2, P)
    x = point[0] * zinv % P
    y = point[1] * zinv % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def pubkey_from_expanded(expanded_64: bytes) -> bytes:
    """Derive the 32-byte Ed25519 public key from a 64-byte expanded private key."""
    scalar = int.from_bytes(expanded_64[:32], "little")
    return _compress(_scalar_mul(scalar, G))


def onion_from_pubkey(pubkey_32: bytes) -> str:
    """Compute the v3 .onion address from a 32-byte Ed25519 public key."""
    checksum_input = b".onion checksum" + pubkey_32 + b"\x03"
    checksum = hashlib.sha3_256(checksum_input).digest()[:2]
    addr_bytes = pubkey_32 + checksum + b"\x03"
    return base64.b32encode(addr_bytes).decode().lower() + ".onion"


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    directory = sys.argv[1] if len(sys.argv) > 1 else "."

    sec_path = os.path.join(directory, "hs_ed25519_secret_key")
    pub_path = os.path.join(directory, "hs_ed25519_public_key")
    hostname_path = os.path.join(directory, "hostname")

    with open(sec_path, "rb") as f:
        sec_data = f.read()
    with open(pub_path, "rb") as f:
        pub_data = f.read()
    with open(hostname_path) as f:
        stored_hostname = f.read().strip()

    if len(sec_data) != 96:
        sys.exit(f"ERROR: {sec_path} is {len(sec_data)} bytes, expected 96")
    if len(pub_data) != 64:
        sys.exit(f"ERROR: {pub_path} is {len(pub_data)} bytes, expected 64")

    expanded_key = sec_data[32:]      # 64-byte expanded private key
    stored_pubkey = pub_data[32:]     # 32-byte public key

    derived_pubkey = pubkey_from_expanded(expanded_key)
    derived_hostname = onion_from_pubkey(stored_pubkey)

    print(f"secret key → derived public key : {derived_pubkey.hex()}")
    print(f"stored public key               : {stored_pubkey.hex()}")
    print(f"secret key matches public key   : {derived_pubkey == stored_pubkey}")
    print()
    print(f"public key → derived onion addr : {derived_hostname}")
    print(f"stored hostname                 : {stored_hostname}")
    print(f"public key matches hostname     : {derived_hostname == stored_hostname}")
    print()
    all_ok = (derived_pubkey == stored_pubkey) and (derived_hostname == stored_hostname)
    print(f"ALL FILES CONSISTENT: {all_ok}")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()