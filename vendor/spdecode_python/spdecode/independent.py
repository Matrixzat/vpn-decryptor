"""Independent phase F and IZPH ports: M1.C, M1.D, M1.F."""
from .common import *
from .renz import hkdf,threefish,MODIFIED_DELTA

def flex(data):
    if data[:6]!=b'FLXCFG':raise DecodeError('Invalid Flex header')
    pos=6;version=data[pos];pos+=1
    if not 1<=version<=4:raise DecodeError('Invalid Flex version')
    build=struct.unpack('>I',data[pos:pos+4])[0] if version>=3 else 0
    if version>=3:pos+=4
    iterations=struct.unpack('>I',data[pos:pos+4])[0];pos+=4
    if not 10000<=iterations<=500000:raise DecodeError('Invalid Flex KDF cost')
    initial=pos
    if version==4:
        try:
            n=data[pos+1]
            if 1<=n<=64 and len(data)>=pos+2+n:pos+=2+n
        except IndexError:pass
    n=data[pos];pos+=1
    if not 32<=n<=64 and version==4 and pos-1!=initial:pos=initial;n=data[pos];pos+=1
    if not 32<=n<=64:raise DecodeError('Invalid Flex salt')
    salt=data[pos:pos+n];pos+=n
    n=data[pos];pos+=1
    if n!=12:raise DecodeError('Invalid Flex nonce')
    nonce=data[pos:pos+n];pos+=n
    n=struct.unpack('>I',data[pos:pos+4])[0];pos+=4
    if not 17<=n<=4194304 or n>len(data)-pos:raise DecodeError('Invalid Flex ciphertext length')
    materials=asset('flex_f_profiles.json')['materials'];keyname=f'{version},{build}'
    if keyname not in materials:
        choices=[s for s in materials if s.startswith(f'{version},')]
        if not choices:raise DecodeError('Unknown Flex material')
        keyname=min(choices,key=lambda s:abs(int(s.split(',')[1])-build))
    material=b64(materials[keyname]).decode('latin1').encode('utf-8')
    aad=b'FLXCFG'+bytes([version])+struct.pack('>I',build) if version>=3 else b''
    plain=gcm(hashlib.pbkdf2_hmac('sha512',material,salt,iterations,32),nonce,data[pos:pos+n],aad)
    return {'app':'FlexNet','rawProperties':require_config(decompress(plain))}

def izph(data):
    seed=bytes.fromhex('8968cb6e895105be625839ad9b9ba6ace8dcd4413d7c5ecfaa1069413ffeb044')
    iv=bytes.fromhex('49e59fdf67eb479ce8b96c24d2495bd1');salt=bytes.fromhex('c27fd7bee17196d650530886cf4c24f52cac5abb8bff6ad3a48ebb10f4b1f632')
    key0=sha(seed)[:16];key1=hkdf(seed,salt);key2=pbkdf(seed,salt,100000,32)
    def decrypt(v,kind):
        def record_attempt(record):
            if kind==0:return bytes((x-2)&255 for x in xxtea(cbc(key0,iv,record),key0,delta=MODIFIED_DELTA,include_length=True))
            if kind==1:return cbc(hkdf(seed,salt[:16],16),iv,threefish(b64(record),key1,lambda i,w:(i,64*i),True).rstrip(b'\0'))
            if kind==2:
                r=xxtea(b64(record),key2[:16],delta=MODIFIED_DELTA,include_length=True);return cbc(key2,r[:16],r[16:])
            return cbc(key1,record[:16],record[16:])
        attempts=[lambda:record_attempt(text(v).encode())]
        try:decoded=b64(v);attempts.insert(0,lambda:record_attempt(decoded))
        except (ValueError,UnicodeError):pass
        return text(first(attempts))
    s=strip_uri(data)
    try:obj=require_config(s)
    except ValueError:obj=first([lambda i=i:require_config(decrypt(s,i)) for i in range(4)])
    def field(v):
        result=first([lambda i=i:decrypt(v,i) for i in range(4)])
        return parse(maybe_decompress(result.encode()))
    return walk(obj,field)

def independent(data,suffix):
    profiles=asset('embedded_kotlin_profiles.json')
    f1=profiles['independentF1'];f2=profiles['specialKeyFamilies']['f2']
    if suffix in {'flex','flexnet'}:return flex(data)
    if suffix in {'ltm','lt'}:return require_config(triplet(strip_uri(data),bytes.fromhex(f1['ltmPasswordHex'])))
    if suffix=='vn7':return first([lambda p=p:parse(triplet(data,p)) for p in f1['vn7Passwords']])
    if suffix=='izph':return izph(data)
    if suffix in {'crev','cerv','cer'}:
        def attempt(p):
            def decrypt(v):return text(xxtea(b64(v),p.encode(),delta=0x9a7393b4,include_length=True))
            return walk(require_config(decrypt(strip_uri(data))),decrypt)
        return first([lambda p=p:attempt(p) for p in f2['crevPasswords']])
    if suffix=='dev':
        obj=require_config(xxtea(b64(data),f2['devSeed'].encode(),delta=0x9a7393b4,include_length=True))
        password=f2['devPassword'].encode().hex().upper().encode();key=sha(password);alphabet=f2['devAlphabet']
        def decrypt(v):
            if len(v)%2==0:
                try:v=bytes((alphabet.index(v[i])<<4)|alphabet.index(v[i+1]) for i in range(0,len(v),2)).decode()
                except ValueError:pass
            plain=cbc(key,bytes(16),b64(v),False)
            n=plain[-1];return text(plain[:-n] if n else b'')
        return walk(obj,decrypt)
    if suffix=='zoba':
        try:record=b64(data)
        except (ValueError,UnicodeError):record=data
        return parse(xxtea(record,f2['zobaPassword'].encode(),delta=(-1704280)&0xffffffff,include_length=True))
    if suffix=='ktr':
        if data[:4]!=b'\xac\xed\0\5':raise DecodeError('KTR requires Java serialization')
        # Match APK string extraction before its AES field pass.
        strings=[];i=4
        while i<len(data):
            header=3 if data[i]==0x74 else 9 if data[i]==0x7c else 0
            if header and i+header<=len(data):
                n=int.from_bytes(data[i+1:i+header],'big')
                if 0<n<=len(data)-i-header:
                    try:strings.append(text(data[i+header:i+header+n]));i+=header+n;continue
                    except UnicodeError:pass
            i+=1
        key=bytes.fromhex(f2['ktrAesHex']);iv=bytes.fromhex(f2['ktrIvHex'])
        values=[]
        for value in strings:
            try:value=text(cbc(key,iv,b64(value)))
            except (ValueError,UnicodeError):pass
            if value in {'key','value','next','hash','this$0','serialVersionUID'} or value.startswith(('java.','com.','org.','sun.','javax.','Ljava.','[L','Lsc.','Lcom/')):continue
            values.append(value)
        result={};pending=None
        for value in values:
            if re.fullmatch(r'[A-Z][A-Z0-9_]{1,60}',value):
                if pending:result[pending]=None
                pending=value
            elif pending:result[pending]=value;pending=None
        if pending:result[pending]=None
        if not result:raise DecodeError('No KTR configuration fields')
        return {'mode':'java','count':len(result),'data':result}
    if suffix=='n4':
        obj=require_config(ecb(sha(f2['n4Seed'].encode()),b64(data)))
        key=sha(f2['n4Password'].encode().hex().upper().encode())
        alphabets=[f2[k] for k in ['n4Table2','n4Table3','n4Table4']]
        def decrypt(v):
            def attempt(alphabet):
                encoded=bytes((alphabet.index(v[i])<<4)|alphabet.index(v[i+1]) for i in range(0,len(v),2))
                return text(cbc(key,bytes(16),b64(encoded)))
            return first([lambda a=a:attempt(a) for a in alphabets])
        obj=walk(obj,decrypt)
        morse=dict(zip(['.-','-...','-.-.','-..','.','..-.','--.','....','..','.---','-.-','.-..','--','-.','---','.--.','--.-','.-.','...','-','..-','...-','.--','-..-','-.--','--..','-----','.----','..---','...--','....-','.....','-....','--...','---..','----.'],'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'))
        def visit(value):
            if isinstance(value,dict):
                result={k:visit(v) for k,v in value.items()}
                if isinstance(result.get('ServerPort'),str):result['ServerPort']=' '.join(''.join(morse.get(c,'') for c in word.split()) for word in result['ServerPort'].split(' / ')).strip()
                return result
            if isinstance(value,list):return [visit(v) for v in value]
            return value
        return visit(obj)
    raise DecodeError('Independent format not mapped: '+suffix)
