"""SocksIP's direct Java stream and VER2/5/7/8 containers in one engine."""
from .common import *
from Crypto.Cipher import CAST,Salsa20

IV=bytes.fromhex('a7734f9c12ac1b01a415f2c1fc78e66b')
SALT=b'sH3CIVoF#rWLtJo6'
JAVA=b'\xac\xed\0\5'

def feedback(data,block):
    size=block.block_size;previous=IV[:size];out=bytearray()
    for pos in range(0,len(data),size):
        part=data[pos:pos+size];stream=block.encrypt(previous)
        out.extend(a^b for a,b in zip(part,stream))
        if len(part)==size:previous=part
    return bytes(out)

def layered(payload,tail_size):
    length=len(payload)
    if length<tail_size+96:raise DecodeError('Truncated SocksIP layered record')
    tail=bytearray(payload[-tail_size:]);tail[16:]=tail[16:][::-1]
    decrypted=feedback(payload,AES.new(bytes(tail[:32]),AES.MODE_ECB))
    salsa_key=decrypted[:32]
    record=bytearray(decrypted[32:length-tail_size-32][::-1])
    if len(record)<12:raise DecodeError('Truncated SocksIP Salsa record')
    record[8:]=Salsa20.new(key=salsa_key,nonce=bytes(record[:8])).decrypt(bytes(record[8:]))
    n=struct.unpack('>I',record[8:12])[0]
    end=12+n+n-16
    if n<60 or end+16>len(record):raise DecodeError('Invalid SocksIP CAST record length')
    cast_key=bytes(record[end:end+16])
    cast=feedback(bytes(record[12+n:end]),CAST.new(cast_key,CAST.MODE_ECB))
    half=(n-17)//2
    if cast[0]==1:
        rebuilt=bytearray(cast[1+half:n-16][::-1]+cast[1:1+half])
    else:
        rebuilt=bytearray(cast[1:]+bytes(record[end:]))
    v=n-17
    if len(rebuilt)<v or v<58:raise DecodeError('Truncated SocksIP reconstructed record')
    key=hashlib.pbkdf2_hmac('sha1',bytes(rebuilt[:16]),SALT,32,1500)
    for i in range(min(1500,len(rebuilt)-16)):rebuilt[16+i]^=key[i]
    aes_key=bytearray(rebuilt[v-32:v]);aes_key[0],aes_key[31]=aes_key[31],aes_key[0]
    encrypted=bytes(rebuilt[v-42:v-32])+bytes(rebuilt[16:v-42][::-1])
    stream=feedback(encrypted,AES.new(bytes(aes_key),AES.MODE_ECB))
    if not stream.startswith(JAVA):raise DecodeError('Invalid SocksIP Java stream')
    return stream

def openssl_field(value):
    if not isinstance(value,str):return value
    try:
        record=b64(value)
        if record[:8]!=b'Salted__' or len(record)<32:return value
        material=b'';last=b''
        while len(material)<48:
            last=md5(last+b'$%23489/**'+record[8:16]);material+=last
        return text(cbc(material[:32],material[32:48],record[16:]))
    except (ValueError,UnicodeError):return value

def java_config(stream):
    import javaobj.v2 as javaobj
    obj=javaobj.loads(stream)
    active=set()
    def normalize(value,depth=0):
        if depth>32:raise DecodeError('SocksIP Java nesting exceeds limit')
        if value is None or isinstance(value,(str,int,float,bool)):return value
        if isinstance(value,bytes):return {'binary_base64':base64.b64encode(value).decode()}
        if id(value) in active:raise DecodeError('Cyclic SocksIP object')
        active.add(id(value))
        try:
            if hasattr(value,'field_data'):
                result={}
                for fields in value.field_data.values():
                    result.update({field.name:normalize(item,depth+1) for field,item in fields.items()})
                for name,item in list(result.items()):
                    if name.lower()=='fpassword':result[name]=openssl_field(item)
                return result
            if hasattr(value,'value'):return normalize(value.value,depth+1)
            if isinstance(value,dict):return {str(k):normalize(v,depth+1) for k,v in value.items()}
            if isinstance(value,(list,tuple)):return [normalize(v,depth+1) for v in value]
            raise DecodeError('Unsupported SocksIP Java object')
        finally:active.remove(id(value))
    return normalize(obj)

def socksip(data):
    p=asset('embedded_kotlin_profiles.json')['legacyBatch2']['sip']
    plain=ecb(bytes.fromhex(p['outerAesHex']),b64url(strip_uri(data)))
    magic=plain[:4]
    if magic==b'VER8':
        if len(plain)<32:raise DecodeError('Truncated SocksIP VER8 record')
        plain=gcm(p['ver8Key'].encode('ascii'),plain[4:16],plain[16:])
    elif magic in {b'VER2',b'VER5',b'VER7'}:
        plain=layered(plain[4:],{b'VER2':32,b'VER5':52,b'VER7':47}[magic])
    elif magic!=JAVA:
        raise DecodeError('Unsupported SocksIP container version')
    if not plain.startswith(JAVA):raise DecodeError('Invalid SocksIP Java stream')
    return java_config(plain)
