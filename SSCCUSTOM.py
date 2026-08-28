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

    TOP_LEVEL_KEY_MAP: Dict[str, str] = {
        "a": "CONFIGS",
        "b": "NOTE",
        "c": "EXPIRY DATE",
        "d": "VERSION",
        "e": "CONFIG NAME",
    }

    CONFIG_KEY_MAP: Dict[str, str] = {
        "a": "ID",
        "e": "PROFILE NAME",
        "f": "PAYLOAD ENABLED",
        "g": "PAYLOAD",
        "h": "PROXY",
        "i": "PROXY BACKUP",
        "j": "TYPE",
        "k": "PROXY ENABLED",
        "l": "HOST",
        "m": "PORT",
        "n": "IS PREMIUM",
        "o": "USERNAME",
        "p": "PASSWORD",
        "q": "TIMEOUT",
        "r": "PROTOCOL",
        "s": "VERSION",
        "t": "ENCRYPTION",
        "u": "COMPRESSION LEVEL",
        "v": "DNS",
        "w": "NAMESERVER",
        "x": "PUBLIC KEY",
        "y": "IS DEFAULT",
        "z": "LOCAL PORT",
    }

    CONFIG_OUTPUT_ORDER = (
        "ID",
        "PROFILE NAME",
        "PAYLOAD ENABLED",
        "PAYLOAD",
        "PROXY",
        "PROXY BACKUP",
        "TYPE",
        "PROXY ENABLED",
        "HOST",
        "PORT",
        "IS PREMIUM",
        "USERNAME",
        "PASSWORD",
        "TIMEOUT",
        "PROTOCOL",
        "VERSION",
        "ENCRYPTION",
        "COMPRESSION LEVEL",
        "DNS",
        "NAMESERVER",
        "PUBLIC KEY",
        "IS DEFAULT",
        "LOCAL PORT",
    )

    ENCRYPTED_FIELDS = {"g", "l", "o", "p"}


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

        if key in {"HOST", "DNS", "NAMESERVER"}:
            if match := re.search(r'(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?', value):
                return match.group(0)
            return "".join(c for c in value if c.isalnum() or c in ".-_:")

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
                                    encrypted = bytes.fromhex(enc_val)
                                    if len(encrypted) <= 16:
                                        continue
                                    dec_bytes = cls._chacha20_decrypt(
                                        SSCConstants.L3_KEY, 
                                        inner_nonce, 
                                        encrypted[:-16],
                                    )
                                    plain = cls._decode_cstring(dec_bytes)
                                    item[field] = plain

                new_item = {}
                for k, v in item.items():
                    new_key = SSCConstants.CONFIG_KEY_MAP.get(k)
                    if not new_key:
                        continue
                    new_val = cls._sanitize_field(new_key, v)
                    if new_val == "" and k in SSCConstants.ENCRYPTED_FIELDS:
                        continue
                    new_item[new_key] = new_val
                    
                processed.append(new_item)
            json_obj["a"] = processed
        return json_obj

    @staticmethod
    def _format_value(value: Any) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)

    @classmethod
    def _format_output(cls, decoded: Dict[str, Any]) -> str:
        configs = decoded.get("CONFIGS")
        if not isinstance(configs, list):
            configs = []

        lines = ["[SSC]"]
        for label in ("VERSION", "CONFIG ID", "EXPIRY DATE", "NOTE"):
            value = decoded.get(label)
            if value not in (None, "", False):
                lines.append(f"{label.title()}: {cls._format_value(value)}")
        lines.append(f"Total Configs: {len(configs)}")

        for index, config in enumerate(configs, 1):
            if not isinstance(config, dict):
                continue
            lines.extend(("", f"[Config {index}]"))
            for label in SSCConstants.CONFIG_OUTPUT_ORDER:
                if label in config:
                    lines.append(
                        f"{label.title()}: {cls._format_value(config[label])}"
                    )

        return "\n".join(lines) + "\n"

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
            config_id = None
            
            if "c" in l1_json and isinstance(l1_json.get("a"), str):
                config_id = l1_json["a"]
                l2_nonce = bytes.fromhex(l1_json["a"][:16])
                l2_data = cls._chacha20_decrypt(SSCConstants.L2_KEY, l2_nonce, bytes.fromhex(l1_json["c"]))
                if l2_json := cls._clean_json(l2_data):
                    target_json = l2_json
                    
            elif "a" in l1_json and isinstance(l1_json["a"], list):
                target_json = l1_json

            if target_json:
                final_struct = cls._process_configs(target_json)
                final_obj = {
                    SSCConstants.TOP_LEVEL_KEY_MAP.get(k, k): (
                        v
                        if k == "a" and isinstance(v, list)
                        else cls._sanitize_field(
                            SSCConstants.TOP_LEVEL_KEY_MAP.get(k, k), v
                        )
                    )
                    for k, v in final_struct.items()
                }
                if config_id:
                    final_obj["CONFIG ID"] = config_id

                return cls._format_output(final_obj)
        return None


def run(file_bytes: bytes) -> Optional[str]:
    """Entry point for seamless integration."""
    return SSCDecryptor.execute(file_bytes)
    