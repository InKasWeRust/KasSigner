#!/usr/bin/env python3
"""
KasSigner — Offline Signing Key Verification

Derives the secp256k1 x-only public key from a 32-byte private key
and compares it against the embedded DEV_PUBKEY.

Usage: python3 verify_key.py /path/to/dev_signing_key.bin

No network. No dependencies. Pure Python.
"""

import sys

# secp256k1 curve parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# DEV_PUBKEY from fw_update.rs
DEV_PUBKEY = bytes([
    0xf5, 0x7f, 0x09, 0xaf, 0xf8, 0xd0, 0x6b, 0x3f,
    0x24, 0xc8, 0xb3, 0xf9, 0xc0, 0xc9, 0x91, 0xca,
    0x6b, 0x43, 0xe9, 0xa6, 0x8e, 0xf8, 0xbe, 0x3a,
    0x91, 0x7b, 0x62, 0x88, 0x30, 0x80, 0xf7, 0xf3
])

def modinv(a, m):
    """Modular inverse using extended Euclidean algorithm."""
    if a < 0:
        a = a % m
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def point_add(px, py, qx, qy):
    """Add two points on secp256k1."""
    if px is None:
        return qx, qy
    if qx is None:
        return px, py
    if px == qx and py == qy:
        # Point doubling
        lam = (3 * px * px) * modinv(2 * py, P) % P
    elif px == qx:
        return None, None  # Point at infinity
    else:
        lam = (qy - py) * modinv(qx - px, P) % P
    rx = (lam * lam - px - qx) % P
    ry = (lam * (px - rx) - py) % P
    return rx, ry

def scalar_mult(k, px, py):
    """Scalar multiplication using double-and-add."""
    rx, ry = None, None
    while k > 0:
        if k & 1:
            rx, ry = point_add(rx, ry, px, py)
        px, py = point_add(px, py, px, py)
        k >>= 1
    return rx, ry

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 verify_key.py /path/to/dev_signing_key.bin")
        sys.exit(1)

    key_path = sys.argv[1]
    with open(key_path, "rb") as f:
        key_bytes = f.read()

    if len(key_bytes) != 32:
        print(f"ERROR: Key file must be exactly 32 bytes, got {len(key_bytes)}")
        sys.exit(1)

    print("╔════════════════════════════════════════════════╗")
    print("║  KasSigner — Offline Key Verification          ║")
    print("╚════════════════════════════════════════════════╝")
    print()

    # Derive public key: privkey × G
    privkey = int.from_bytes(key_bytes, "big")
    if privkey == 0 or privkey >= N:
        print("ERROR: Invalid private key (out of range)")
        sys.exit(1)

    pub_x, pub_y = scalar_mult(privkey, Gx, Gy)
    derived = pub_x.to_bytes(32, "big")

    derived_hex = derived.hex()
    expected_hex = DEV_PUBKEY.hex()

    print(f"  Key file:     {key_path}")
    print(f"  Derived pub:  {derived_hex}")
    print(f"  Expected pub: {expected_hex}")
    print()

    if derived == DEV_PUBKEY:
        print("  ✅ MATCH — Private key corresponds to DEV_PUBKEY")
        print("  Safe to proceed with eFuse burning.")
    else:
        print("  ❌ MISMATCH — Private key does NOT match DEV_PUBKEY!")
        print("  DO NOT burn eFuses with this key.")
        sys.exit(1)

if __name__ == "__main__":
    main()
