"""Renz AES/custom XXTEA/Threefish-256, translated from M1.C0342a0."""
from .common import *

MODIFIED_DELTA=2052510689
ROTATIONS=[(14,16),(52,57),(23,40),(5,37),(25,33),(46,12),(58,22),(32,32)]
MASK64=(1<<64)-1
SEED=bytes.fromhex('deb72221be4652c347f930e85adc29970ccd499cf42e361b3d6b14918912bf3b')
SALT=bytes.fromhex('70ed508428ff7b5bcde0bcdd3b9474932ab1cabc5ff6870e6e584b4fa7925f55')
IV=bytes.fromhex('2d2f3112a271edbba9a41ad58a3a99bf')

def hkdf(seed,salt,size=32):
    key=mac(salt,seed);out=b'';last=b'';i=1
    while len(out)<size:last=mac(key,last+bytes([i]));out+=last;i+=1
    return out[:size]
def renz_xxtea(data,key,standard=False):
    key=key[:16].ljust(16,b'\0')
    if b'\0' in key:key=key.split(b'\0',1)[0].ljust(16,b'\0')
    return xxtea(data,key,delta=0x9e3779b9 if standard else MODIFIED_DELTA,include_length=True)
def threefish(data,key,tweak_fn,permutation_after=False):
    if len(key)<32 or not data or len(data)%32:raise DecodeError('Invalid Threefish dimensions')
    k=list(struct.unpack('<4Q',key[:32]));k.append(0x1bd11bdaa9fc1a22^k[0]^k[1]^k[2]^k[3])
    output=bytearray()
    def ror(x,n):return ((x>>n)|(x<<(64-n)))&MASK64
    for index,pos in enumerate(range(0,len(data),32)):
        words=list(struct.unpack('<4Q',data[pos:pos+32]));t0,t1=tweak_fn(index,words);t=[t0&MASK64,t1&MASK64,(t0^t1)&MASK64]
        subkeys=[(k[s%5],(k[(s+1)%5]+t[s%3])&MASK64,(k[(s+2)%5]+t[(s+1)%3])&MASK64,(k[(s+3)%5]+s)&MASK64) for s in range(19)]
        for group in range(17,-1,-1):
            words=[(x-y)&MASK64 for x,y in zip(words,subkeys[group+1])]
            for step in range(3,-1,-1):
                if not permutation_after:words=[words[i] for i in [0,3,2,1]]
                rotations=ROTATIONS[(group*4+step)%8]
                for pair in range(2):
                    p=pair*2;y=ror(words[p]^words[p+1],rotations[pair]);words[p]=(words[p]-y)&MASK64;words[p+1]=y
                if permutation_after:words=[words[i] for i in [0,3,2,1]]
        words=[(x-y)&MASK64 for x,y in zip(words,subkeys[0])]
        output.extend(struct.pack('<4Q',*words))
    return bytes(output)

def typed(record,kind):
    if kind==0:
        key=sha(SEED)[:16];plain=xxtea(cbc(key,IV,record),key,delta=MODIFIED_DELTA,include_length=True)
        return bytes((x-2)&255 for x in plain)
    if kind==1:
        plain=threefish(b64(record),hkdf(SEED,SALT),lambda i,w:(i,0)).rstrip(b'\0')
        return cbc(hkdf(SEED,SALT[:16],16),IV,plain)
    if kind==2:
        key=pbkdf(SEED,SALT,100000,32);r=xxtea(b64(record),key[:16],delta=MODIFIED_DELTA,include_length=True)
        return cbc(key,r[:16],r[16:])
    if kind==3:
        return cbc(hkdf(SEED,SALT),record[:16],record[16:])
    raise DecodeError('Unregistered Renz type')

def renz(data,suffix):
    catalog=asset('renz_d_profiles.json')
    alias=next(a for a in catalog['aliases'] if a['suffix']==suffix)
    p=next(p for p in catalog['profiles'] if p['key']==alias['profile'])
    seed,iv,salt=map(bytes.fromhex,[p['seed'],p['iv'],p['salt']]);name=p['key']
    s=strip_uri(data)
    def outer(v):
        if name=='tcxtunnel':
            key=bytes.fromhex('6103102f3dfa7cac1aa5b8ff4ba12022')
            return cbc(key,bytes(16),renz_xxtea(b64(v),key,True))
        key=sha(seed)[:16];plain=renz_xxtea(cbc(key,iv,b64(v)),key)
        return plain if name in {'xhypher','safetunnel','mhrtunnel','letsvpngo'} else bytes((x-2)&255 for x in plain)
    def secret(v):
        if name=='tcxtunnel':return text(outer(v))
        size=16 if name=='cranetunnel' else 32;key=pbkdf(seed,salt or b'0'*size,100000,size)
        plain=cbc(key,iv,renz_xxtea(b64(v),key),False)
        if len(plain)<16:raise DecodeError('Invalid Renz password field')
        pad=plain[-1];plain=plain[16:len(plain)-pad if 1<=pad<=len(plain) else len(plain)]
        if name!='cranetunnel':
            for _ in range(16):
                if plain and plain[-1]<=31:
                    pad=plain[-1];plain=plain[:-pad] if pad else b''
        return text(plain)
    def field(v):
        if name=='tcxtunnel':return text(outer(v))
        salt2=salt or b'0'*32;key16=hkdf(seed,salt2[:16],16)
        if name=='cranetunnel':return text(cbc(key16,iv,renz_xxtea(b64(v),key16)))
        def tweak(index,words):
            t0=0 if name=='vipsnipherpro' else index;t1=64*index
            if name in {'7net','actunnelvpn','vipsnipherpro','deshtunnelvpn','hamotunnelplus','aloplusvpn'}:t1=0
            elif name in {'xhypher','safetunnel','mhrtunnel','letsvpngo'}:t1=192*index
            if name=='aloplusvpn':
                for j,w in enumerate(words):t1^=(w+j)&MASK64
                t1^=index*160
            return t0,t1
        plain=threefish(b64(v),hkdf(seed,salt2),tweak).rstrip(b'\0')
        plain=cbc(key16,iv,plain,False)
        if plain and 1<=plain[-1]<=16 and plain.endswith(bytes([plain[-1]])*plain[-1]):plain=plain[:-plain[-1]]
        return text(plain)
    def visit(obj):
        if isinstance(obj,list):return [visit(v) for v in obj]
        if isinstance(obj,dict):
            out={}
            for key,value in obj.items():
                if isinstance(value,str) and len(value)>20:
                    try:
                        value=secret(value) if 'password' in key.lower() else field(value) if any(v in key.lower() for v in ['host','path','username']) else first([lambda:text(outer(value)),lambda:field(value)])
                    except (ValueError,UnicodeError):pass
                out[key]=visit(value)
            return out
        return obj
    attempts=[lambda:visit(require_config(outer(s)))]
    if name=='7net':
        records=[data]
        try:records.append(b64(s))
        except ValueError:pass
        for kind in range(4):
            for r in records:attempts.append(lambda kind=kind,r=r:require_config(typed(r,kind)))
    return {'application':alias['name'],'extension':'.'+suffix,'config':first(attempts)}
