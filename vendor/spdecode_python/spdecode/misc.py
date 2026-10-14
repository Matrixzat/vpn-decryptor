"""Remaining legacy profile helpers: SSC, JEZ/HRT, and NUR solid."""
from .common import *
from Crypto.Cipher import ChaCha20

def ssc(data):
    def decrypt(key,nonce,record):
        c=ChaCha20.new(key=bytes.fromhex(key),nonce=nonce);c.seek(64)
        s=text(c.decrypt(record)).split('\0',1)[0];return json.loads(s[s.find('{'):s.rfind('}')+1])
    key1='c8a6a8ea102d5a0baf8fdb1b39cd615c0d07c1edcbde4e82cfdd309bc4587f6b'
    key2='7f9db48ffde449ad19f9ed44b8b27eee334ab4a85b972dca8ff20e4e8ed44e4e'
    key3='d39394517a48971f6e8555e994bee5bd835e5ab2f85fbd76bbd99800f32b967e'
    encoded=''.join(strip_uri(data).split())
    candidates=[encoded[::-1],encoded] if text(data).strip().lower().startswith('ssc://') else [encoded]
    def outer(candidate):
        result=decrypt(key1,bytes.fromhex('74d0f3879f9d47f7'),bytes.fromhex(candidate))
        if not isinstance(result,dict):raise DecodeError('Invalid SSC object')
        return result
    obj=first([lambda candidate=candidate:outer(candidate) for candidate in candidates])
    if isinstance(obj.get('a'),str) and 'c' in obj:obj=decrypt(key2,bytes.fromhex(obj['a'][:16]),bytes.fromhex(obj['c']))
    configs=obj.get('a')
    if not isinstance(configs,list):raise DecodeError('Invalid SSC configuration list')
    for config in configs:
        s=config.get('b','')
        if len(s)!=32:continue
        nonces=list(dict.fromkeys([
            bytes.fromhex(s[16:][::-1]+'68'+s[:16])[:8],
            bytes.fromhex(s[16:]+'68'+s[:16])[:8]
        ]))
        for field in ['g','h','l','o','p','v','x','i','w']:
            if isinstance(config.get(field),str) and len(config[field])>16:
                try:
                    record=bytes.fromhex(config[field])
                    def attempt(nonce,record):
                        c=ChaCha20.new(key=bytes.fromhex(key3),nonce=nonce);c.seek(64)
                        value=text(c.decrypt(record).split(b'\0',1)[0])
                        if not value or not all(x.isprintable() or x in '\r\n\t' for x in value):
                            raise DecodeError('Invalid SSC field text')
                        return value
                    records=[record]+([record[:-16]] if len(record)>16 else [])
                    value=first([lambda nonce=nonce,record=record:attempt(nonce,record) for nonce in nonces for record in records])
                    if field in {'l','v','w','h'}:value=''.join(ch for ch in value if ch.isalnum() or ch in '.-:_')
                    config[field]=value
                except (ValueError,UnicodeError):pass
    return obj

def solid(data):
    from argon2.low_level import hash_secret_raw,Type
    p=asset('embedded_kotlin_profiles.json')['nurTunnel']
    def decrypt(s):
        if len(s)<60 or len(s)%4 not in {0,1}:raise DecodeError('Unsupported NUR envelope')
        if len(s)%4==1 and len(s)>=61:s=s[:3]+s[4:];name='exportSecretB64'
        else:name='internalSecretB64'
        r=b64(s);salt=r[:16];nonce=r[16:28]
        if len(r)<44:raise DecodeError('Truncated NUR record')
        key=hash_secret_raw(b64(p[name]),salt,3,8192,1,32,Type.ID,19)
        return text(gcm(key,nonce,r[28:],salt))
    return walk(json.loads(decrypt(text(data).strip().replace('\r','').replace('\n',''))),decrypt)

def misc(data,suffix):
    if suffix=='ssc':return ssc(data)
    if suffix=='solid':return solid(data)
    if suffix in {'hrt','jez'}:
        return walk(require_config(cbc(sha(b'Radz_11_2021'),bytes(16),b64(data))),lambda v:text(b64(v)))
    if suffix=='maya':
        key=bytes.fromhex('360b82639d6fb4642dc69a1e7b9c720644f9227c7c2f1cc6da14ba9a7dcfead0')
        def decrypt(v):
            r=b64(v);return parse(cbc(key,r[:16],r[16:]))
        return walk(require_config(decrypt(text(data))),decrypt)
    raise DecodeError('Miscellaneous format not mapped: '+suffix)
