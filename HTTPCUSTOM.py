import json
import base64
import re
import contextlib
from typing import Optional, Dict, Any, List, Union
from Crypto.Cipher import ChaCha20, AES
from Crypto.Util.Padding import unpad


class HCConstants:
    """Cryptographic constants, keys, and mappings for HTTP Custom."""
    
    CHACHA_KEYS: List[bytes] = [
        bytes.fromhex("2be4342943c6f91ff58987f41a1aafd179eeb4e053f5cea55b11d6a7db58bd7d"),
        bytes.fromhex("3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372"),
        bytes.fromhex("cea9305c95168b162a335b137c61983b8df54e6375da01136547890f14c5fac3"),
        bytes.fromhex("4beeace0e42bae8f29470cf40cf2dfacd5f4e1f751912bf52e803c8c85792193"),
        bytes.fromhex("f8e5f6ebea90558eb32229da24fd0fb7d813091dafe89bb2954fda33b4c60f63"),
        bytes.fromhex("81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c"),
        bytes.fromhex("45635e6fc70486e2fd10d3c2b4780f02d0b4c5f4aa929fc54f86bb8fa4417944"),
        bytes.fromhex("3d632a251c9820f2baf83e15498d27548fc67921cb437f8ce48505989378adea")
    ]
    
    RST_KEYS: List[bytes] = [
        b"JN1k3YHc2.6_v235", b"JN1k3YHc_2.7_v71", b"JN1k3YHc2.7.ps69",
        b"JN1k3YHc2.7.6950", b"Jn1K3yHc2.8.ps08", b"Jn1K3yHc2.9.ps6c",
        b"Zk:L7>WKaiK*s9>D", b"!<f!&WIlM**R.B0X", b"b4a5opinx2uloec6"
    ]

    JKL_KEY_OLD: bytes = bytes([
        0xd5, 0xd4, 0xd3, 0xd2, 0xd1, 0xd0, 0xcf, 0xce, 0xcd, 0xcc, 
        0xbd, 0xbc, 0xbb, 0xba, 0xb9, 0xb8, 0xb7, 0xb6, 0xb5, 0xb4
    ])

    JKL_KEY_NEW: bytes = bytes([
        8, 9, 10, 11, 12, 13, 14, 15, 17, 17, 
        5, 4, 3, 2, 1, 0, 255, 254, 253, 252
    ])

    TOKEN_MAP: Dict[int, str] = {
        0: "payload", 1: "proxy", 2: "lockAllConfig", 3: "blockedByRoot",
        4: "expiryTime", 5: "noteEnabled", 6: "notes", 7: "sshField", 
        8: "mobileDataAndLockProvider", 9: "unlockUserAndPass", 10: "ovpnConfig", 
        11: "ovpnUserAndPass", 12: "sni", 13: "unlockUserAndPass2", 
        14: "unknown14", 15: "blockedByHwid", 16: "cloudconfig", 
        17: "psiphon", 18: "name", 19: "blockArea", 
        20: "connectionMode", 21: "blockedByPassword", 22: "unknown22", 
        23: "extraSniffer", 24: "psiphon2", 25: "v2rayEnabled", 
        26: "v2rayConfig", 27: "version", 28: "slowdnsEnabled", 
        29: "slowdnsServer", 30: "slowdnsPublickey", 31: "dnsResolver"
    }

    BRAILLE_ALPHABET: str = "⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚⠅⠇⠍⠝⠕⠏⠟⠗⠎⠞⠥⠧⠺⠭⠽⠵⠼⠁⠼⠃⠼⠉⠼⠙⠼⠑⠼⠋⠼⠛⠼⠓⠼⠊⠼⠚"
    STATIC_NONCE: bytes = b'\xdb' * 8
    RST_XOR_KEY: bytes = bytes(range(2, 22))


class HCDecryptor:
    """Core decryption engine for HTTP Custom profiles."""

    @staticmethod
    def _clean_hex(raw_str: str) -> str:
        if not raw_str: 
            return ""
        clean = re.sub(r'[^0-9a-fA-F]', '', raw_str)
        return f"0{clean}" if len(clean) % 2 != 0 else clean

    @staticmethod
    def _is_hex(s: str) -> bool:
        return bool(s and len(s) >= 16 and re.fullmatch(r'^[0-9a-fA-F]+$', s))

    @staticmethod
    def _is_mostly_printable(s: str, strict: bool = False) -> bool:
        if not s: 
            return False
        if len(s) < 4: 
            return True
        printable_count = sum(1 for c in s if c.isprintable() or c in '\t\n\r')
        return (printable_count / len(s)) > (0.90 if strict else 0.80)

    @staticmethod
    def _extract_z3a(data: str, iv: int) -> str:
        if not data: 
            return ""
        new_data = bytearray()
        for m in re.finditer(r'(-?\d+)\.(-?\d+)', data):
            val11, val22 = int(m.group(1)) - iv, int(m.group(2)) - iv
            with contextlib.suppress(Exception):
                if (divisor := 1 << val22) != 0:
                    new_data.append((val11 // divisor) % 256)
        return new_data.decode('utf-8', errors='ignore')

    @staticmethod
    def _decrypt_braille(ciphertext: str) -> str:
        try:
            return bytes(
                (HCConstants.BRAILLE_ALPHABET.index(ciphertext[i]) * 16 + 
                 HCConstants.BRAILLE_ALPHABET.index(ciphertext[i + 1])) & 255
                for i in range(0, len(ciphertext) - 1, 2)
            ).decode('utf-8')
        except ValueError:
            return ciphertext

    @classmethod
    def _process_credentials(cls, raw_val: str, is_ssh: bool = False) -> str:
        if not raw_val: 
            return raw_val
        
        if is_ssh and raw_val[0] in HCConstants.BRAILLE_ALPHABET:
            raw_val = cls._decrypt_braille(raw_val)
            
        pattern = r'^([\w\.-]+):([\d\-]+)@(.+):(.+)$' if is_ssh else r'^([^:]+):(.+)$'
        if match := re.match(pattern, raw_val):
            groups = match.groups()
            u_enc, p_enc = groups[-2:]
            
            u_dec = cls._extract_z3a(u_enc, len(re.findall(r'(-?\d+)\.(-?\d+)', u_enc)))
            p_dec = cls._extract_z3a(p_enc, len(re.findall(r'(-?\d+)\.(-?\d+)', p_enc)))
            
            final_user, final_pass = u_dec or u_enc, p_dec or p_enc
            return f"{groups[0]}:{groups[1]}@{final_user}:{final_pass}" if is_ssh else f"{final_user}:{final_pass}"
        
        return raw_val

    @classmethod
    def _abc_decrypt(cls, raw_input: str, key: bytes, nonce: bytes = HCConstants.STATIC_NONCE) -> str:
        if not raw_input: 
            return ""
        with contextlib.suppress(Exception):
            data = bytes.fromhex(cls._clean_hex(raw_input))
            if len(data) > 16:
                cipher = ChaCha20.new(key=key, nonce=nonce)
                cipher.seek(64)
                decrypted = cipher.decrypt(data[:-16])
                return decrypted.decode('utf-8', errors='ignore')
        return ""

    @classmethod
    def _rst_decrypt(cls, encrypted_str: str) -> Optional[str]:
        with contextlib.suppress(Exception):
            b64_string = bytes(b ^ HCConstants.RST_XOR_KEY[i % 20] for i, b in enumerate(encrypted_str.encode('utf-8')))
            aes_ciphertext = base64.b64decode(b64_string)
            
            for aes_key in HCConstants.RST_KEYS:
                with contextlib.suppress(Exception):
                    decrypted = unpad(AES.new(aes_key, AES.MODE_ECB).decrypt(aes_ciphertext), AES.block_size)
                    dec_str = decrypted.decode('utf-8', errors='ignore')
                    if "[splitConfig]" in dec_str:
                        return dec_str
        return None

    @classmethod
    def _jkl_decrypt(cls, input_str: str, is_new: bool = False) -> str:
        if not input_str: 
            return input_str
        
        active_key = HCConstants.JKL_KEY_NEW if is_new else HCConstants.JKL_KEY_OLD
        with contextlib.suppress(Exception):
            pad = len(input_str) % 4
            padded_str = input_str + "=" * (4 - pad) if pad else input_str
            data = bytearray(base64.b64decode(padded_str, validate=True))
            
            for i, d in enumerate(data):
                k = active_key[i % 20]
                data[i] = (((d ^ 0xff) & 0xca) | (d & 0x35)) ^ (((k ^ 0xff) & 0xca) | (k & 0x35))
                
            return base64.b64decode(data.decode('utf-8'), validate=True).decode('utf-8')
        return input_str

    @classmethod
    def _decrypt_field(cls, token: str, dynamic_nonce: bytes) -> str:
        if not token or token in {"true", "false", "lifeTime", "[splitPsiphon][splitPsiphon]"} or token.startswith("<"):
            return token
            
        candidates: List[bytes] = []
        if cls._is_hex(clean_h := cls._clean_hex(token)) and len(clean_h) >= 32:
            with contextlib.suppress(Exception): candidates.append(bytes.fromhex(clean_h))
            
        if len(token) > 16:
            with contextlib.suppress(Exception): candidates.append(token.encode('latin-1'))
            with contextlib.suppress(Exception): candidates.append(token.encode('utf-8'))

        unique_cands = list(dict.fromkeys(candidates))
        
        for data_bytes in (c for c in unique_cands if len(c) > 16):
            ciphertext = data_bytes[:-16]
            for chacha_key in HCConstants.CHACHA_KEYS:
                with contextlib.suppress(Exception):
                    cipher = ChaCha20.new(key=chacha_key, nonce=dynamic_nonce)
                    cipher.seek(64)
                    dec_str = cipher.decrypt(ciphertext).decode('utf-8', errors='ignore')

                    for is_new in (True, False):
                        if (out := cls._jkl_decrypt(dec_str, is_new)) and out != dec_str and cls._is_mostly_printable(out):
                            return out
                            
                    if cls._is_mostly_printable(dec_str, strict=True) and any(x in dec_str for x in ("HTTP", "@", ":", "{")) or dec_str.isalnum():
                        return dec_str

        for is_new in (True, False):
            if (out := cls._jkl_decrypt(token, is_new)) != token and cls._is_mostly_printable(out):
                return out

        return token

    @staticmethod
    def _extract_initial_payload(file_bytes: bytes, hex_key: str) -> Optional[str]:
        with contextlib.suppress(Exception):
            key_bytes = bytes.fromhex(hex_key)
            k_len = len(key_bytes)
            
            try: encrypted_data = file_bytes.decode('utf-8', errors='ignore').encode('latin-1', errors='ignore')
            except Exception: encrypted_data = file_bytes 
                
            return bytes(b ^ key_bytes[i % k_len] for i, b in enumerate(encrypted_data)).decode('utf-8')
        return None

    @classmethod
    def execute(cls, file_bytes: bytes) -> Optional[str]:
        if not file_bytes or not (hex_payload := cls._extract_initial_payload(file_bytes, "e382e4b8adc386f09f9293")):
            return None

        with contextlib.suppress(Exception):
            if not (outer := cls._abc_decrypt(hex_payload, HCConstants.CHACHA_KEYS[5])) or not outer.startswith("{"):
                return None

            json_obj = json.loads(outer)
            if not isinstance(json_obj, dict):
                return None

            cfg_obj = json_obj.get("cfg", {})
            is_new_format = isinstance(cfg_obj, dict) and "content" in cfg_obj

            meta_values, protections = {}, {}
            
            if is_new_format:
                for k, name in {'b': 'hwid', 'f': 'area'}.items():
                    if val := str(json_obj.get(k) or cfg_obj.get(k) or ""):
                        meta_values[name] = protections[name] = val
                target_cipher, split_delim = cfg_obj.get('content'), "[splitConfig]"
            else:
                obj_a = json_obj.get('a') if isinstance(json_obj.get('a'), dict) else {}
                for k, name in {'bb': 'hwid', 'e': 'password', 'fe': 'area', 'ed': 'provider'}.items():
                    if val := (json_obj.get(k) if k == 'e' else obj_a.get(k)):
                        if dec_val := cls._abc_decrypt(str(val), HCConstants.CHACHA_KEYS[7]):
                            meta_values[name] = protections[name] = dec_val
                target_cipher, split_delim = json_obj.get('xy') or obj_a.get('xy'), json_obj.get('uv') or obj_a.get('uv')

            if not target_cipher or not split_delim:
                return None

            # Nonce derivation
            to_hex = lambda s: s.encode().hex() if s else ""
            h, p, pr, a = meta_values.get('hwid'), meta_values.get('password'), meta_values.get('provider'), meta_values.get('area')
            derived_hex = (to_hex(h) * 2) if h and not any((p, pr, a)) else (to_hex(p) + to_hex(h) + to_hex(pr) + to_hex(a))
            
            dynamic_nonce = bytearray(HCConstants.STATIC_NONCE)
            if derived_hex:
                with contextlib.suppress(Exception):
                    for i, b in enumerate(bytes.fromhex(derived_hex)[:8]):
                        dynamic_nonce[i] = b

            # Ciphertext decryption
            xy_dec = None
            if is_new_format:
                xy_dec = cls._rst_decrypt(str(target_cipher))
                if not xy_dec:
                    for key in HCConstants.CHACHA_KEYS:
                        if (temp := cls._abc_decrypt(str(target_cipher), key)) and split_delim in temp:
                            xy_dec = temp
                            break
            else:
                xy_dec = cls._abc_decrypt(str(target_cipher), HCConstants.CHACHA_KEYS[1])
                
            if not xy_dec: 
                return None
            
            config_data = {}
            for i, token in enumerate(xy_dec.split(str(split_delim))):
                if i in {22, 24}: 
                    continue

                label = HCConstants.TOKEN_MAP.get(i, f"field_{i}")
                final_out = token

                if is_new_format:
                    final_out = cls._decrypt_field(token, dynamic_nonce)
                else:
                    if cls._is_hex(token):
                        final_out = cls._abc_decrypt(token, HCConstants.CHACHA_KEYS[7], dynamic_nonce)
                    final_out = cls._jkl_decrypt(final_out, is_new=False)

                if i == 7: final_out = cls._process_credentials(final_out, is_ssh=True)
                elif i == 11: final_out = cls._process_credentials(final_out, is_ssh=False)

                if final_out:
                    if isinstance(final_out, str):
                        final_out = final_out.replace("88a05e8772eac3e5703e0cd26c6e6f23de72fb09f7ee5a43283d1681f19d", "")
                        with contextlib.suppress(Exception):
                            if final_out.startswith(("{", "[")): final_out = json.loads(final_out)
                    
                    if not (isinstance(final_out, str) and cls._is_hex(final_out)):
                        config_data[label] = final_out
                    
            result_dict = {"Protections": protections, "Config": config_data}

            return (
                f"HABIBI HTTP CUSTOM SCRIPT\n"
                f"{'='*30}\n\n"
                f"{json.dumps(result_dict, indent=4, ensure_ascii=False)}\n\n"
                f"{'='*30}\n"
                f"code : @HABIBI_1ST"
            )
        return None


def run(file_bytes: bytes) -> Optional[str]:
    """Entry point for seamless integration."""
    return HCDecryptor.execute(file_bytes)
    