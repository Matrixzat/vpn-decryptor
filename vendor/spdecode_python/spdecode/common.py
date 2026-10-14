"""Shared binary/crypto helpers, translated from M1.I, M1.j0, M1.C0345c."""
import base64
import gzip
import hashlib
import hmac
import html
import json
from pathlib import Path
import re
import struct
import zlib
import xml.etree.ElementTree as ET
from Crypto.Cipher import AES, DES, Blowfish, ChaCha20_Poly1305
from Crypto.Util.Padding import unpad

DATA = Path(__file__).resolve().parent/'data'
LIMIT=16*1024*1024
class DecodeError(ValueError): pass

def asset(name):return json.loads((DATA/name).read_text())
def raw_asset(name):return (DATA/name).read_bytes()
def text(data):return data.decode('utf-8') if isinstance(data,bytes) else data
def b64(data):
    s=re.sub(r'\s','',text(data))
    if not s or not re.fullmatch(r'[A-Za-z0-9+/]*={0,2}',s) or len(s.rstrip('='))%4==1:
        raise DecodeError('Invalid Base64')
    return base64.b64decode(s+'='*((-len(s))%4),validate=True)
def b64url(data):return b64(text(data).replace('-','+').replace('_','/'))
def strip_uri(data):
    s=text(data).strip()
    return s.split('://',1)[-1]
def pbkdf(password,salt,iterations=1000,size=16):
    if isinstance(password,str):password=password.encode()
    return hashlib.pbkdf2_hmac('sha256',password,salt,iterations,size)
def md5(data):return hashlib.md5(data).digest()
def sha(data):return hashlib.sha256(data).digest()
def mac(key,data):return hmac.new(key,data,'sha256').digest()
def gcm(key,nonce,data,aad=b''):
    if len(data)<16:raise DecodeError('Missing GCM authentication tag')
    c=AES.new(key,AES.MODE_GCM,nonce=nonce,mac_len=16);c.update(aad)
    return c.decrypt_and_verify(data[:-16],data[-16:])
def cbc(key,iv,data,padded=True):
    plain=AES.new(key,AES.MODE_CBC,iv).decrypt(data)
    return unpad(plain,16) if padded else plain
def ecb(key,data,padded=True):
    plain=AES.new(key,AES.MODE_ECB).decrypt(data)
    return unpad(plain,16) if padded else plain
def des(key,data):return DES.new(key[:8].ljust(8,b'\0'),DES.MODE_ECB).decrypt(data)
def cfb(key,iv,data):return AES.new(key,AES.MODE_CFB,iv,segment_size=128).decrypt(data)
def ctr(key,iv,data):return AES.new(key,AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(iv,'big')).decrypt(data)
def chacha(key,nonce,data,aad=b''):
    c=ChaCha20_Poly1305.new(key=key,nonce=nonce)
    c.update(aad)
    return c.decrypt_and_verify(data[:-16],data[-16:])
def decompress(data):
    if data[:2]==b'\x1f\x8b':
        d=zlib.decompressobj(31)
    else:d=zlib.decompressobj()
    plain=d.decompress(data,LIMIT+1)
    if len(plain)>LIMIT or not d.eof or d.unconsumed_tail:raise DecodeError('Invalid or oversized compressed stream')
    return plain+d.flush()
def maybe_decompress(data):
    try:return decompress(data)
    except (ValueError,zlib.error):return data
def parse(data):
    s=text(data).strip('\0\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10 ')
    try:return json.loads(s)
    except (ValueError,TypeError):
        if s.startswith('<?xml') or s.startswith('<properties'):
            def surrogate_pair(match):
                high=int(match.group(1) or match.group(2),16 if match.group(1) else 10)
                low=int(match.group(3) or match.group(4),16 if match.group(3) else 10)
                if 0xd800<=high<=0xdbff and 0xdc00<=low<=0xdfff:
                    return chr(0x10000+((high-0xd800)<<10)+low-0xdc00)
                return match.group(0)
            xml=re.sub(r'&#(?:x([0-9A-Fa-f]+)|([0-9]+));&#(?:x([0-9A-Fa-f]+)|([0-9]+));',surrogate_pair,s)
            try:root=ET.fromstring(xml)
            except ET.ParseError as error:raise DecodeError('Malformed properties XML') from error
            if root.tag!='properties':raise DecodeError('Unexpected properties XML root')
            entries={}
            for entry in root.findall('entry'):
                if entry.get('key') is None:raise DecodeError('Properties XML entry has no key')
                entries[entry.get('key')]=entry.text or ''
            if not entries:raise DecodeError('Properties XML has no configuration entries')
            return entries
        entries=re.findall(r'<entry\s+key\s*=\s*[\"\x27]([^\"\x27]+)[\"\x27]\s*(?:>(.*?)</entry\s*>|/>)',s,re.S)
        if entries:return {html.unescape(k):html.unescape(v) for k,v in entries}
        return s
def require_config(data):
    result=parse(data)
    if not isinstance(result,(dict,list)):raise DecodeError('Decrypted data is not a configuration object')
    return result
def triplet(data,password,iterations=1000,size=16):
    parts=text(data).strip().split('.')
    if len(parts)!=3:raise DecodeError('Expected salt.nonce.ciphertext')
    salt,nonce,encrypted=map(b64,parts)
    return gcm(pbkdf(password,salt,iterations,size),nonce,encrypted)
def walk(obj,fn,depth=0):
    if depth>32:raise DecodeError('Configuration nesting exceeds limit')
    if isinstance(obj,dict):return {k:walk(v,fn,depth+1) for k,v in obj.items()}
    if isinstance(obj,list):return [walk(v,fn,depth+1) for v in obj]
    if isinstance(obj,str):
        try:return fn(obj)
        except (ValueError,KeyError,UnicodeError,TypeError):return obj
    return obj
def first(attempts):
    errors=[]
    for fn in attempts:
        try:
            value=fn()
            if value is not None and value!='':return value
        except (ValueError,KeyError,UnicodeError,IndexError,TypeError,struct.error) as e:errors.append(type(e).__name__)
    raise DecodeError('No recovered key/format matched'+(' ('+', '.join(sorted(set(errors)))+')' if errors else ''))
def xxtea(data,key,delta=0x9e3779b9,include_length=False):
    if len(data)<8:raise DecodeError('XXTEA input too short')
    n=(len(data)+3)//4
    v=list(struct.unpack('<'+'I'*n,data.ljust(n*4,b'\0')))
    k=struct.unpack('<4I',key[:16].ljust(16,b'\0'))
    total=((6+52//n)*delta)&0xffffffff
    y=v[0]
    while total:
        e=(total>>2)&3
        for p in range(n-1,-1,-1):
            z=v[p-1 if p else n-1]
            mx=((((z>>5)^(y<<2))+((y>>3)^(z<<4)))^((total^y)+(k[(p&3)^e]^z)))&0xffffffff
            y=v[p]=(v[p]-mx)&0xffffffff
        total=(total-delta)&0xffffffff
    plain=struct.pack('<'+'I'*n,*v)
    if include_length:
        length=v[-1]
        if not n*4-7<=length<=n*4-4:raise DecodeError('Invalid XXTEA embedded length')
        return plain[:length]
    return plain.rstrip(b'\0')
