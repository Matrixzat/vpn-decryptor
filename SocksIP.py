#!/usr/bin/env python3
"""
socksip_decrypt.py - Decrypt SocksTunnel / SocksIP .sip config files to readable JSON.

Usage:
    python socksip_decrypt.py 1.sip output.json
    python socksip_decrypt.py 1.sip                (defaults to 1.sip.json)

Requires: pycryptodome  (pip install pycryptodome)

Supports VER2 / VER5 / VER7 / VER8 formats (auto-detected).
VER2/5/7 use the legacy multi-layer onion:
    base64 -> AES/ECB -> CFB(AES-256) -> Salsa20 -> CFB(CAST5)
    -> PBKDF2-XOR -> CFB(AES-256) -> Java serialization -> OpenSSL blob (Fpassword)
VER8 uses an authenticated replacement after the outer AES layer:
    AES-256-GCM(nonce || ciphertext || tag) -> Java serialization.
"""

import argparse
import base64
import datetime
import hashlib
import json
import struct
import sys

from Crypto.Cipher import AES, CAST, Salsa20
from Crypto.Util.Padding import unpad

# ----------------------------------------------------------------------------
# constants recovered from libgojni.so
# ----------------------------------------------------------------------------
XYZ_KEY = bytes([0x19, 0x2E, 0x04, 0x08, 0x08, 0x04, 0x04, 0x09,
                 0x05, 0x59, 0x29, 0x59, 0x38, 0x5F, 0x54, 0x17])  # nativo.xyz JNI AES key
COMMON_IV = bytes.fromhex("a7734f9c12ac1b01a415f2c1fc78e66b")    # kcp initialVector
SALTXOR = b"sH3CIVoF#rWLtJo6"                                     # kcp saltxor
FPASSWORD_PW = b"$%23489/**"                                      # aes256 passphrase (trickvpn.Es)
VER8_KEY_A = bytes.fromhex("4e67b09c9aba0aefad92a5e1e9ad765b17eda8779064975ac8979a48e7474220")
VER8_KEY_B = bytes.fromhex("2d06ddfef3db558adee6cabe99c204046398f71bfc05e13f97f3ff17d4751d42")
VER8_KEY = bytes(a ^ b for a, b in zip(VER8_KEY_A, VER8_KEY_B))


class SipDecryptError(Exception):
    pass


# ----------------------------------------------------------------------------
# crypto layer helpers
# ----------------------------------------------------------------------------
def cfb_decrypt(data: bytes, block) -> bytes:
    """kcp-style CFB: keystream = E(prev ciphertext block), E(IV) for the first."""
    bs = block.block_size
    buf = bytearray(COMMON_IV[:bs])
    out = bytearray(len(data))
    for i in range(0, len(data), bs):
        n = min(bs, len(data) - i)
        ks = block.encrypt(bytes(buf))
        for j in range(n):
            out[i + j] = data[i + j] ^ ks[j]
        if n == bs:
            buf = bytearray(data[i:i + bs])
    return bytes(out)


def evp_bytes_to_key(passphrase: bytes, salt: bytes, key_len=32, iv_len=16):
    """OpenSSL EVP_BytesToKey with MD5 (matches the app's aes256 package)."""
    d = b""
    prev = b""
    while len(d) < key_len + iv_len:
        prev = hashlib.md5(prev + passphrase + salt).digest()
        d += prev
    return d[:key_len], d[key_len:key_len + iv_len]


def decrypt_fpassword(value: str):
    """Best-effort decrypt of an OpenSSL 'Salted__' blob field."""
    if not value:
        return value, False
    try:
        blob = base64.b64decode(value)
    except Exception:
        return value, False
    if len(blob) < 16 or blob[:8] != b"Salted__":
        return value, False
    salt, ct = blob[8:16], blob[16:]
    key, iv = evp_bytes_to_key(FPASSWORD_PW, salt)
    try:
        pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
        return pt.decode("utf-8", "replace"), True
    except Exception:
        return value, False


# ----------------------------------------------------------------------------
# versioned decryptors
# ----------------------------------------------------------------------------
def decrypt_ver8(payload: bytes) -> bytes:
    """Decrypt the VER8 nonce || ciphertext || tag AES-256-GCM payload."""
    nonce_size = 12
    tag_size = 16
    if len(payload) < nonce_size + tag_size:
        raise SipDecryptError("VER8 payload too short")
    nonce = payload[:nonce_size]
    ciphertext = payload[nonce_size:-tag_size]
    tag = payload[-tag_size:]
    try:
        out = AES.new(VER8_KEY, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise SipDecryptError("VER8 AES-GCM authentication failed") from exc
    if out[:4] != b"\xac\xed\x00\x05":
        raise SipDecryptError("VER8 plaintext has no Java serialization magic")
    return out


def decrypt_sip(data: bytes, tail_size: int = 0) -> bytes:
    """Decrypt .sip bytes -> Java serialized SerSocksIP stream.

    tail_size: version-specific key-tail length (32=VER2, 47=VER7, 52=VER5).
    Zero = auto-detect by magic, then by brute force over tail sizes.
    """
    try:
        raw = base64.b64decode(b"".join(data.split()))
    except Exception:
        raise SipDecryptError("not valid base64 data")

    # layer 1: AES/ECB/PKCS5 (nativo.xyz -> javax.crypto.Cipher "AES")
    try:
        pt = AES.new(XYZ_KEY, AES.MODE_ECB).decrypt(raw)
        pt = pt[:-pt[-1]]
    except Exception:
        raise SipDecryptError("layer 1 (AES/ECB) failed - wrong file?")

    magic = pt[:4]
    payload = pt[4:]
    L = len(payload)

    if magic == b"VER8":
        return decrypt_ver8(payload)

    # legacy version -> tail size
    if tail_size == 0:
        tail_size = {"VER7": 47, "VER5": 52, "VER2": 32}.get(magic.decode("latin1"))
        if tail_size is None and magic[:3] == b"VER":
            raise SipDecryptError(f"unsupported version {magic.decode('latin1')}")
        if tail_size is None:
            raise SipDecryptError(f"unknown sip magic {magic!r}")

    if L < tail_size + 32 + 64:
        raise SipDecryptError("payload too short")

    # layer 2: aes key from the last T bytes ([16:T] reversed, take [0:32])
    tail = bytearray(payload[L - tail_size:L])
    tail[16:tail_size] = tail[tail_size - 1:15:-1]
    aes_key1 = bytes(tail[0:32])

    # layer 3: CFB over the payload
    p = bytearray(cfb_decrypt(payload, AES.new(aes_key1, AES.MODE_ECB)))

    # layer 4: Salsa20
    salsa_key = bytes(p[0:32])
    S = bytearray(reversed(p[32:L - tail_size - 32]))
    S[8:] = Salsa20.new(key=salsa_key, nonce=bytes(S[0:8])).encrypt(bytes(S[8:]))

    # layer 5: CAST5 CFB (8-byte blocks)
    N = int.from_bytes(S[8:12], "big")
    if not (60 <= N <= len(S) - 12):
        raise SipDecryptError(f"bad length field N={N} (wrong version key?)")
    c5_key = bytes(S[12 + N + (N - 16): 12 + N + (N - 16) + 16])
    region = bytearray(S[12 + N: 12 + N + (N - 16)])
    c5out = cfb_decrypt(region, CAST.new(c5_key, CAST.MODE_ECB))
    S[12 + N: 12 + N + (N - 16)] = c5out

    # layer 6: flag byte selects the R layout
    flag = c5out[0]
    h = (N - 17) >> 1
    SLEN = len(S)
    if flag == 1:
        R = bytearray(reversed(c5out[1 + h:N - 16])) + bytearray(c5out[1:1 + h])
    else:
        R = bytearray(S[12 + N + 1: 12 + N + 1 + (SLEN - N - 13)])

    # layer 7: XOR with PBKDF2-SHA1(password=R[0:16], salt=saltxor, 32, 1500)
    salt = bytes(R[0:16])
    xkey = hashlib.pbkdf2_hmac("sha1", salt, SALTXOR, 32, 1500)
    for i in range(min(1500, len(R) - 16)):
        R[16 + i] ^= xkey[i]

    # layer 8: final AES CFB over the reassembled buffer
    v186 = N - 17
    aes_key2 = bytearray(R[v186 - 32:v186])
    aes_key2[0], aes_key2[31] = aes_key2[31], aes_key2[0]
    buf = bytes(R[v186 - 42:v186 - 32]) + bytes(reversed(R[16:v186 - 42]))

    # layer 9: the Java serialized object
    out = cfb_decrypt(buf, AES.new(bytes(aes_key2), AES.MODE_ECB))
    if out[:4] != b"\xac\xed\x00\x05":
        raise SipDecryptError("decrypted stream has no Java serialization magic")
    return out


# ----------------------------------------------------------------------------
# Java serialization parser (with handle tracking)
# ----------------------------------------------------------------------------
HANDLE_BASE = 0x7E0000


class SerialParser:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.objects = []   # handle table: classDescs (None) and strings (str), in write order

    # -- low level readers ------------------------------------------------
    def _rd(self, n):
        b = self.data[self.pos:self.pos + n]
        if len(b) != n:
            raise SipDecryptError(f"stream truncated at offset {self.pos}")
        self.pos += n
        return b

    def u1(self):
        return self._rd(1)[0]

    def u2(self):
        return struct.unpack(">H", self._rd(2))[0]

    def u4(self):
        return struct.unpack(">I", self._rd(4))[0]

    def u8(self):
        return struct.unpack(">Q", self._rd(8))[0]

    def utf(self):
        return self._rd(self.u2()).decode("utf-8", "replace")

    # -- handle helpers ---------------------------------------------------
    def _store_string(self, s: str):
        self.objects.append(s)

    def _resolve(self, handle: int) -> str:
        idx = handle - HANDLE_BASE
        if 0 <= idx < len(self.objects) and isinstance(self.objects[idx], str):
            return self.objects[idx]
        return f"<ref {handle}>"

    # -- structure readers ------------------------------------------------
    def classdesc(self, names, types):
        """Read one classDesc (0x72). Returns class name or None for TC_NULL."""
        tag = self.u1()
        if tag == 0x70:          # TC_NULL
            return None
        if tag == 0x71:          # TC_REFERENCE
            self.u4()
            return "<ref>"
        if tag != 0x72:
            raise SipDecryptError(f"unexpected classDesc tag {tag:#x} at {self.pos - 1}")
        self.objects.append(None)  # classDesc gets a handle
        cname = self.utf()
        self._rd(8)              # serialVersionUID
        self.u1()                # flags
        nf = self.u2()
        for _ in range(nf):
            tc = self.u1()
            fname = self.utf()
            if tc in (ord('L'), ord('[')):
                t = self.u1()
                if t == 0x71:
                    self.u4()
                elif t == 0x74:
                    self._store_string(self.utf())
                else:
                    self.pos -= 1
                    self.utf()
            names.append(fname)
            types.append(chr(tc))
        if self.u1() != 0x78:    # TC_ENDBLOCKDATA
            raise SipDecryptError("missing TC_ENDBLOCKDATA")
        self.classdesc(names, types)  # superclass
        return cname

    def value(self, tc: str):
        if tc == 'B':
            return self.u1()
        if tc == 'Z':
            return self.u1() != 0
        if tc == 'C':
            return chr(self.u1())
        if tc == 'I':
            return struct.unpack(">i", self._rd(4))[0]
        if tc == 'J':
            return struct.unpack(">q", self._rd(8))[0]
        if tc == 'S':
            return struct.unpack(">h", self._rd(2))[0]
        if tc == 'F':
            return struct.unpack(">f", self._rd(4))[0]
        if tc == 'D':
            return struct.unpack(">d", self._rd(8))[0]
        if tc == 'L':
            tag = self.u1()
            if tag == 0x70:      # TC_NULL
                return ""
            if tag == 0x71:      # TC_REFERENCE
                return self._resolve(self.u4())
            if tag == 0x74:      # TC_STRING
                s = self.utf()
                self._store_string(s)
                return s
            if tag in (0x72, 0x73):  # boxed object (TC_OBJECT + classDesc)
                self.pos -= 1
                if tag == 0x73:
                    self.u1()
                    self.objects.append(None)  # TC_OBJECT handle
                names, types = [], []
                self.classdesc(names, types)
                vals = [self.value(t) for t in types]
                return vals[0] if len(vals) == 1 else vals
            raise SipDecryptError(f"unexpected object tag {tag:#x} at {self.pos}")
        raise SipDecryptError(f"unsupported field type {tc!r}")

    def parse(self):
        if self._rd(4) != b"\xac\xed\x00\x05":
            raise SipDecryptError("missing Java serialization magic")
        if self.u1() != 0x73:
            raise SipDecryptError("expected TC_OBJECT")
        names, types = [], []
        cname = self.classdesc(names, types)
        config = {}
        for n, t in zip(names, types):
            config[n] = self.value(t)
        # second pass: resolve any forward references using the complete string table
        for n, v in config.items():
            if isinstance(v, str) and v.startswith("<ref "):
                try:
                    h = int(v[5:-1])
                    config[n] = self._resolve(h)
                except ValueError:
                    pass
        return cname, config


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        prog="SocksIP.py",
        description="Decrypt SocksTunnel/SocksIP .sip config files into readable JSON.")
    ap.add_argument("input", help="path to the .sip file")
    ap.add_argument("output", nargs="?", default=None,
                    help="output JSON path (default: <input>.json)")
    args = ap.parse_args()

    out_path = args.output or (args.input.rsplit(".", 1)[0] + ".json")

    try:
        data = open(args.input, "rb").read()
        if not data.strip():
            raise SipDecryptError("empty input file")

        stream = decrypt_sip(data)

        parser = SerialParser(stream)
        cname, config = parser.parse()

        # detect the version for reporting
        try:
            raw = base64.b64decode(b"".join(data.split()))
            pt = AES.new(XYZ_KEY, AES.MODE_ECB).decrypt(raw)
            version = pt[:4].decode("latin1")
        except Exception:
            version = "VER?"

        # post-processing: Fpassword blob + expiration date
        extra = {}
        fpw, fpw_ok = decrypt_fpassword(config.get("Fpassword", ""))
        if fpw_ok:
            extra["FpasswordRaw"] = config["Fpassword"]
            config["Fpassword"] = fpw
            extra["FpasswordDecrypted"] = True

        for fld in ("expiration", "expireFile"):
            v = config.get(fld)
            if isinstance(v, int) and v > 1000000000:
                try:
                    extra[fld + "Date"] = datetime.datetime.fromtimestamp(
                        v, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                except Exception:
                    pass

        result = {
            "input": args.input,
            "format": "socksip-" + version.lower(),
            "class": cname,
            "serialVersionUID": "0x68034118b5395142",
            **extra,
            "config": config,
        }

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

        print(f"[+] decrypted '{args.input}' ({version} format)")
        print(f"[+] class: {cname}")
        n_fields = len(config)
        print(f"[+] fields: {n_fields}")
        for k in ("Server", "Fserver", "CDNTargetADDR", "FTunnelDomain",
                  "Fpassword", "Payload", "Protocol", "Location", "ProxyHostPort"):
            if config.get(k):
                print(f"    {k:16s} = {config[k]}")
        if "expirationDate" in extra:
            print(f"    expiration     = {extra['expirationDate']}")
        print(f"[+] written to '{out_path}'")

    except SipDecryptError as e:
        print(f"[!] error: {e}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"[!] file error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
