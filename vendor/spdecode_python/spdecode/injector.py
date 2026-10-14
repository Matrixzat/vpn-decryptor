"""EHI/EHIL container and field ports from M1.C0353k and helpers."""
from .common import *
STANDARD='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
EHI_ALPHABET='RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs'
EHIL_ALPHABET='t6uxKcTwhBn3UvRkLC2QaVM1o5A4f7Hr0Zp8OyjqzDb9e+dSFXsEIimPYgGJW/lN'
def container(data):
    pos=0
    def string():
        nonlocal pos
        n=int.from_bytes(data[pos:pos+2],'big');pos+=2
        if n>len(data)-pos:raise DecodeError('Truncated Injector string')
        s=text(data[pos:pos+n]);pos+=n;return s
    format=string();pos+=8;string();pos+=8
    n=int.from_bytes(data[pos:pos+4],'big');pos+=12
    if not 1<=n<=1048576 or n>len(data)-pos:raise DecodeError('Invalid Injector payload length')
    return format,data[pos:pos+n]
def field_decrypt(v,salt,alphabet):
    v=v.strip().replace('?','');key=salt.encode()
    if not key:raise DecodeError('Empty Injector field salt')
    def attempt(candidate):
        encoded=text(b64(candidate.translate(str.maketrans(alphabet,STANDARD))))
        encoded=encoded if len(encoded)%2==0 else '0'+encoded
        record=bytes.fromhex(encoded)
        plain=text(bytes(x^key[i%len(key)] for i,x in enumerate(record)).replace(b'\0',b''))
        if not plain or not all(c.isprintable() or c in '\r\n\t' for c in plain):
            raise DecodeError('Invalid Injector field text')
        return plain
    return first([lambda:attempt(v),lambda:attempt(v[::-1])])

def protected_config(obj,salt):
    from argon2.low_level import hash_secret_raw,Type
    encoded=field_decrypt(obj['configData'],salt,EHI_ALPHABET)
    record=b64(encoded)
    if len(record)<66:raise DecodeError('Truncated EHI protected config')
    iterations,memory=struct.unpack('<II',record[1:9]);lanes=record[9]
    if not 1<=iterations<=16 or not 8<=memory<=262144 or not 1<=lanes<=16 or memory<8*lanes:
        raise DecodeError('Unsupported EHI Argon2 resource profile')
    names=['configAesKey','configIdentifier','configSalt','configTimestamp','configExpiryTimestamp',
           'lockModes','lockModesHash','configHwid','configLockMobileOperatorId']
    values=[str(obj.get(name,0 if name in {'configTimestamp','configExpiryTimestamp'} else '')) for name in names]
    master=sha(''.join(values).encode())
    key=hash_secret_raw(master,record[10:26],iterations,memory,lanes,32,Type.ID)
    return json.loads(text(chacha(key,record[26:50],record[50:],record[:26])))
def injector(data,suffix):
    format,record=container(data)
    profiles=asset('embedded_kotlin_profiles.json')
    if suffix=='ehi':
        p=profiles['ehi'];key=bytes.fromhex(p['firstKeyHex']);innerkey=bytes.fromhex(p['secondKeyHex'])
        def attempt(iv):
            first_layer=text(cbc(key,iv,record)).split(':')
            if len(first_layer)<3:raise DecodeError('Invalid EHI inner record')
            encrypted_inner=cbc(innerkey,b64(first_layer[0]),b64(first_layer[2]))
            try:decoded=xxtea(encrypted_inner,p['xxteaKeyText'].encode(),include_length=True)
            except ValueError:decoded=xxtea(encrypted_inner,p['xxteaKeyText'].encode())
            s=text(decoded);obj=json.loads(s[s.find('{'):s.rfind('}')+1]);salt=obj.get('configSalt') or 'EVZJNI'
            if iv.hex() not in p['bypassIvHex'] and obj.get('configData'):
                obj=protected_config(obj,salt)
            def visit(value,key=''):
                if isinstance(value,dict):return {k:visit(v,k) for k,v in value.items()}
                if isinstance(value,list):return [visit(v) for v in value]
                if isinstance(value,str):
                    try:
                        if key=='configMessage':
                            raw=text(b64(value)).encode('utf-16-be')
                            chars=struct.unpack('>'+'H'*(len(raw)//2),raw)
                            return struct.pack('>'+'H'*len(chars),*(c^ord('EHIMSG'[i%6]) for i,c in enumerate(chars))).decode('utf-16-be')
                        decoded=field_decrypt(value,salt,EHI_ALPHABET)
                        if key in {'v2rRawJson','overwriteServerData'}:
                            start,end=decoded.find('{'),decoded.rfind('}')
                            if start>=0 and end>=start:
                                try:return json.loads(decoded[start:end+1],strict=False)
                                except ValueError:pass
                        return decoded
                    except (ValueError,UnicodeError):pass
                return value
            return visit(obj)
        return first([lambda iv=iv:attempt(bytes.fromhex(iv)) for iv in p['bypassIvHex']+p['standardIvHex']])
    if format.lower()!='ehil':raise DecodeError('Invalid EHIL header')
    p=profiles['ehil'];attempts=[]
    def attempt(key,iv,key2,iv2):
        outer=text(cbc(key,iv,record));enc=b64(outer.split(':')[-1]);s=text(cbc(key2,iv2,enc))
        candidates=[s]
        if len(s)>17:candidates += ['{"a'+s[17:],'{'+'"a":"'+s[17:]]
        for fragment,prefix in [('estamp":','{"a'),('configIdentifier"','{"aestamp":0,"')]:
            start=s.find(fragment)
            if start>=0:candidates.append(prefix+s[start:])
        def parsed(candidate):
            obj=json.loads(candidate)
            if 'configSalt' not in obj:raise DecodeError('Invalid EHIL inner JSON')
            return obj
        obj=first([lambda c=c:parsed(c) for c in candidates]);salt=obj.get('configSalt') or 'EVZJNI'
        return walk(obj,lambda v:field_decrypt(v,salt,EHIL_ALPHABET))
    for key in p['firstLayerKeyHex']:
        for iv in p['ivAscii']:
            for key2 in p['secondLayerKeyHex']:
                for iv2 in p['ivAscii']:attempts.append(lambda key=key,iv=iv,key2=key2,iv2=iv2:attempt(bytes.fromhex(key),iv.encode('ascii'),bytes.fromhex(key2),iv2.encode('ascii')))
    return first(attempts)
