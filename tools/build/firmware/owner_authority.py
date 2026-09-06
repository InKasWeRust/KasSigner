#!/usr/bin/env python3
"""Create owner-authority enrollment media for KasSigner CoreS3.

OWNERKEY.KAS contains only the SHA-256 digest of an RSA-3072 Secure Boot v2
public key plus an integrity checksum. The private key never belongs on the
device or removable media.
"""
from __future__ import annotations
import argparse, hashlib, subprocess, tempfile
from pathlib import Path

MAGIC=b"KSOWNR01"
FORMAT_VERSION=1
RECORD_SIZE=76

def secure_boot_digest(key: Path, espsecure: str='espsecure') -> bytes:
    with tempfile.TemporaryDirectory() as td:
        out=Path(td)/'digest.bin'
        subprocess.run([espsecure,'digest-sbv2-public-key','--keyfile',str(key),'--output',str(out)],check=True)
        data=out.read_bytes()
    if len(data)!=32: raise SystemExit(f'expected 32-byte Secure Boot digest, got {len(data)}')
    return data

def encode(digest: bytes) -> bytes:
    if len(digest)!=32 or digest in (b'\x00'*32,b'\xff'*32): raise ValueError('invalid owner key digest')
    prefix=MAGIC+bytes([FORMAT_VERSION,0,0,0])+digest
    assert len(prefix)==44
    return prefix+hashlib.sha256(prefix).digest()

def decode(data: bytes) -> bytes:
    if len(data)!=RECORD_SIZE or data[:8]!=MAGIC or data[8]!=FORMAT_VERSION or data[9:12]!=b'\0\0\0':
        raise ValueError('invalid OWNERKEY.KAS header')
    if hashlib.sha256(data[:44]).digest()!=data[44:]: raise ValueError('OWNERKEY.KAS checksum mismatch')
    digest=data[12:44]
    if digest in (b'\x00'*32,b'\xff'*32): raise ValueError('invalid owner key digest')
    return digest

def main() -> None:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--key',type=Path,required=True,help='owner RSA-3072 private key')
    ap.add_argument('--output',type=Path,default=Path('OWNERKEY.KAS'))
    ap.add_argument('--espsecure',default='espsecure')
    args=ap.parse_args()
    digest=secure_boot_digest(args.key,args.espsecure)
    args.output.write_bytes(encode(digest))
    print(f'Wrote {args.output} (owner digest {digest.hex()})')
if __name__=='__main__': main()
