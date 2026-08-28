import json
import re
import struct
import contextlib
from typing import Optional, Dict, Any, List
from Crypto.Cipher import ChaCha20


class SSCConstants:
    """Cryptographic artifacts and configuration mappings for SSC."""
    
    FIXED_NONCE: bytes = struct.pack('<Q', 0xf7479d9f87f3d074)
    L1_KEY: bytes = bytes.fromhex("c8a6a8ea102d5a0baf8fdb1b39cd615c0d07c1edcbde4e82cfdd309bc4587f6b")
    L2_KEY: bytes = bytes.fromhex("7f9db48ffde449ad19f9ed44b8b27eee334ab4a85b972dca8ff20e4e8ed44e4e")
    L3_KEY: bytes = bytes.fromhex("d39394517a48971f6e8555e994bee5bd835e5ab2f85fbd76bbd99800f32b967e")

    KEY_MAP: Dict[str, str] = {
        "a": "CONFIGS", "b": "NOTE", "c": "EXPIRY DATE", "e": "CONFIGNAME",
        "f": "PAYLOAD ENABLED", "g": "PAYLOAD", "h": "PROXY", "i": "PROXY PORT",
        "j": "TYPE", "k": "PROXY ENABLED", "l": "ADDRESS", "m": "PORT",
        "n": "IS PREMIUM", "o": "USERNAME", "p": "PASSWORD", "q": "TIMEOUT",
        "r": "PROTOCOL", "s": "VERSION", "t": "ENCRYPTION", "u": "COMPRESSIONLEVEL",
        "v": "DNS", "w": "NSSERVER", "x": "PUBKEY", "y": "ISDEFAULT",
        "z": "LOCALPORT"
    }
    
    ENCRYPTED_FIELDS = {"g", "h", "l", "o", "p", "v", "x", "i", "w"}


class SSCDecryptor:
    """Core decryption engine for SSC profiles."""

    @staticmethod
    def _chacha20_decrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
        """Standard ChaCha20 decryption, offsetting the block counter to 1."""
        cipher = ChaCha20.new(key=key, nonce=nonce)
        cipher.seek(64) # Block size is 64 bytes; seeking 64 sets counter = 1
        return cipher.decrypt(data)

    @staticmethod
    def _decode_cstring(b: bytes) -> str:
        if not b: 
            return ""
        b = b.split(b"\x00")[0]
        try: 
            return b.decode("utf-8")
        except UnicodeDecodeError as e: 
            return b[:e.start].decode("utf-8", errors="ignore")

    @classmethod
    def _sanitize_field(cls, key: str, value: Any) -> Any:
        if not isinstance(value, str): 
            return value
            
        value = "".join(c for c in value if ord(c) >= 32)

        if key in {"ADDRESS", "DNS", "H", "NSSERVER"}:
            if match := re.search(r'(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?', value):
                return match.group(0)
            return "".join(c for c in value if c.isalnum() or c in ".-_")

        if key in {"USERNAME", "PASSWORD"}:
            if value.isalnum(): return value
            if match := re.match(r'^[a-zA-Z0-9!@#$%^&*()._-]+', value):
                return match.group(0)

        if key == "PAYLOAD":
            return value.split("\x00")[0] if "[crlf]" in value else value.strip()

        return value.strip()

    @staticmethod
    def _derive_inner_nonce(user_key: str) -> Optional[bytes]:
        if not user_key or len(user_key) != 32: 
            return None
        return bytes.fromhex(f"{user_key[16:32][::-1]}68{user_key[0:16]}")[:8]

    @staticmethod
    def _clean_json(text_bytes: bytes) -> Optional[Dict]:
        if not text_bytes: 
            return None
            
        with contextlib.suppress(Exception):
            text = text_bytes.decode('utf-8', errors='ignore').split('\x00')[0]
            if (start := text.find('{')) != -1 and (end := text.rfind('}')) != -1:
                candidate = text[start:end+1]
                try: 
                    return json.loads(candidate)
                except json.JSONDecodeError as e:
                    if e.msg.startswith("Extra data"):
                        return json.loads(candidate[:e.pos])
        return None

    @classmethod
    def _process_configs(cls, json_obj: Dict) -> Dict:
        if isinstance(configs := json_obj.get("a"), list):
            processed = []
            for item in configs:
                if user_key := item.get("b"):
                    if inner_nonce := cls._derive_inner_nonce(user_key):
                        for field in SSCConstants.ENCRYPTED_FIELDS.intersection(item.keys()):
                            enc_val = item[field]
                            if isinstance(enc_val, str) and len(enc_val) > 16:
                                with contextlib.suppress(Exception):
                                    dec_bytes = cls._chacha20_decrypt(
                                        SSCConstants.L3_KEY, 
                                        inner_nonce, 
                                        bytes.fromhex(enc_val)
                                    )
                                    plain = cls._decode_cstring(dec_bytes)
                                    item[field] = "".join(c for c in plain if c.isalnum() or c in ".-:_") if field in {"l", "v", "w", "h"} else plain

                new_item = {}
                for k, v in item.items():
                    new_key = SSCConstants.KEY_MAP.get(k, k)
                    new_val = cls._sanitize_field(new_key, v)
                    if new_val == "" and k in SSCConstants.ENCRYPTED_FIELDS:
                        continue
                    new_item[new_key] = new_val
                    
                processed.append(new_item)
            json_obj["a"] = processed
        return json_obj

    @classmethod
    def execute(cls, file_bytes: bytes) -> Optional[str]:
        with contextlib.suppress(Exception):
            content = file_bytes.decode('utf-8-sig', errors='ignore').strip()
            
            if content.startswith("ssc://"):
                content = content[6:][::-1]
                
            if len(cipher_hex := "".join(content.split())) % 2 != 0: 
                return None
                
            l1_data = cls._chacha20_decrypt(SSCConstants.L1_KEY, SSCConstants.FIXED_NONCE, bytes.fromhex(cipher_hex))
            if not (l1_json := cls._clean_json(l1_data)): 
                return None

            target_json = None
            
            if "c" in l1_json and isinstance(l1_json.get("a"), str):
                l2_nonce = bytes.fromhex(l1_json["a"][:16])
                l2_data = cls._chacha20_decrypt(SSCConstants.L2_KEY, l2_nonce, bytes.fromhex(l1_json["c"]))
                if l2_json := cls._clean_json(l2_data):
                    target_json = {SSCConstants.KEY_MAP.get(k, k): cls._sanitize_field(SSCConstants.KEY_MAP.get(k, k), v) if k != "a" else v for k, v in l2_json.items()}
                    
            elif "a" in l1_json and isinstance(l1_json["a"], list):
                target_json = l1_json

            if target_json:
                final_struct = cls._process_configs(target_json)
                final_obj = {
                    SSCConstants.KEY_MAP.get(k, k): v if k in {"a", "CONFIGS"} and isinstance(v, list) else cls._sanitize_field(SSCConstants.KEY_MAP.get(k, k), v) 
                    for k, v in final_struct.items()
                }

                return (
                    f"HABIBI SSC SCRIPT\n"
                    f"{'='*30}\n\n"
                    f"{json.dumps(final_obj, indent=4, ensure_ascii=False)}\n\n"
                    f"{'='*30}\n"
                    f"code : @HABIBI_1ST"
                )
        return None


def run(file_bytes: bytes) -> Optional[str]:
    """Entry point for seamless integration."""
    return SSCDecryptor.execute(file_bytes)
    