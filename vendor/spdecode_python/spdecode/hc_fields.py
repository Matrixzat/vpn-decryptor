"""Historical HTTP Custom field encodings merged into the shared decoder."""
from .common import *
from Crypto.Cipher import ChaCha20

JKL_OLD=bytes.fromhex('d5d4d3d2d1d0cfcecdccbdbcbbbab9b8b7b6b5b4')
JKL_NEW=bytes.fromhex('08090a0b0c0d0e0f1111050403020100fffefdfc')
BRAILLE='⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚⠅⠇⠍⠝⠕⠏⠟⠗⠎⠞⠥⠧⠺⠭⠽⠵⠼⠁⠼⠃⠼⠉⠼⠙⠼⠑⠼⠋⠼⠛⠼⠓⠼⠊⠼⠚'

def readable(value):
    return bool(value) and sum(c.isprintable() or c in '\r\n\t' for c in value)/len(value)>=0.95

def jkl(value,new=False):
    try:
        record=b64(value);key=JKL_NEW if new else JKL_OLD
        decoded=text(b64(bytes(v^key[i%len(key)] for i,v in enumerate(record))))
        return decoded if readable(decoded) else value
    except (ValueError,UnicodeError):return value

def credentials(value,ssh=False):
    if not isinstance(value,str) or not value:return value
    if ssh and value[0] in BRAILLE:
        try:value=bytes((BRAILLE.index(value[i])*16+BRAILLE.index(value[i+1]))&255 for i in range(0,len(value),2)).decode()
        except (ValueError,UnicodeError,IndexError):return value
    pattern=r'^(.+):([\d-]+)@(.+):(.+)$' if ssh else r'^([^:]+):(.+)$'
    match=re.match(pattern,value)
    if not match:return value
    parts=list(match.groups())
    for i in [-2,-1]:
        pairs=re.findall(r'(-?\d+)\.(-?\d+)',parts[i]);offset=len(pairs)
        try:
            if pairs and all(0<=int(shift)-offset<=63 for _,shift in pairs):
                candidate=bytes(((int(n)-offset)//(1<<(int(shift)-offset)))%256 for n,shift in pairs).decode()
                if readable(candidate):parts[i]=candidate
        except (ValueError,UnicodeError,OverflowError):pass
    return f'{parts[0]}:{parts[1]}@{parts[2]}:{parts[3]}' if ssh else ':'.join(parts)

def field(value,nonce,keys,new=False):
    if not value or value in {'true','false','lifeTime','[splitPsiphon][splitPsiphon]'}:
        return value
    candidates=[]
    try:
        if len(value)%2==0:candidates.append(bytes.fromhex(value))
    except ValueError:pass
    if new:
        for encoding in ['latin1','utf-8']:
            try:candidates.append(value.encode(encoding))
            except UnicodeError:pass
    for record in dict.fromkeys(candidates):
        if len(record)<=16:continue
        for key in (keys if new else [keys[7]]):
            try:
                cipher=ChaCha20.new(key=key,nonce=nonce);cipher.seek(64)
                decoded=text(cipher.decrypt(record[:-16]))
                for version in ([True,False] if new else [False]):
                    transformed=jkl(decoded,version)
                    if transformed!=decoded:return transformed
                if readable(decoded) and (any(x in decoded for x in ['HTTP','@',':','{']) or decoded.isalnum()):
                    return decoded
            except (ValueError,UnicodeError):pass
    for version in ([True,False] if new else [False]):
        transformed=jkl(value,version)
        if transformed!=value:return transformed
    return value
