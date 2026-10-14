"""HTTP Custom legacy and HCCFG ports, including supplied-password/HWID flow."""
from .common import *
from Crypto.Cipher import ChaCha20
from .hc_fields import field as decode_field, credentials

SECRET=bytes.fromhex('95dd433d7e4a0be02d55cc62553edcfc8f077fe780be5a7da7f861c2558dc18138cabb40b2f81a5a30b11a97cbcf0fed755aa8c2b5495e9bc0c1902077a4cd92')
APP=b'xyz.easypro.httpcustom'
def stream(key,nonce,data):
    c=ChaCha20.new(key=key,nonce=nonce);c.seek(64);return c.decrypt(data)
def hkdf(ikm,salt,info):return mac(mac(salt,ikm),info+b'\1')
def ascii8(v):
    record=bytes.fromhex(re.sub('[^0-9a-fA-F]','',v))
    if len(record)<=16:raise DecodeError('Truncated legacy HC field')
    return record[:-16]
def legacy(data):
    p=asset('embedded_kotlin_profiles.json');keys=asset('hc_source_keys.json');cha=[bytes.fromhex(k) for k in keys['chaChaKeys']]
    xor=bytes.fromhex(p['httpCustom']['outerXorKeyHex'])
    try:record=text(data).encode('latin1')
    except (UnicodeError,ValueError):record=data
    decoded=bytes(x^xor[i%len(xor)] for i,x in enumerate(record))
    def decrypt(v,key):return text(stream(key,b'\xdb'*8,ascii8(v)))
    obj=json.loads(decrypt(text(decoded),cha[5]));protections={}
    if isinstance(obj.get('cfg'),dict) and 'content' in obj['cfg']:
        cfg=obj['cfg'];encrypted=cfg['content'];delimiter='[splitConfig]'
        for source,target in [('b','hwid'),('f','area')]:
            value=obj.get(source) or cfg.get(source)
            if value:
                try:protections[target]=decrypt(value,cha[7])
                except (ValueError,UnicodeError):protections[target]=str(value)
        def aes_try(key):
            transformed=bytes(v^((i%20)+2) for i,v in enumerate(encrypted.encode()))
            s=text(ecb(key.encode('ascii'),b64(transformed)))
            if delimiter not in s:raise DecodeError('Invalid HC split marker')
            return s
        attempts=[lambda key=key:aes_try(key) for key in keys['rstKeys']]
        attempts += [lambda key=key:decrypt(encrypted,key) for key in cha]
        plain=first(attempts)
    else:
        cfg=obj.get('a',{});encrypted=obj.get('xy') or cfg.get('xy');delimiter=obj.get('uv') or cfg.get('uv')
        if not encrypted or not delimiter:raise DecodeError('Invalid HC content/delimiter')
        for source,target in [('bb','hwid'),('e','password'),('fe','area'),('ed','provider')]:
            v=obj.get(source) if source=='e' else cfg.get(source)
            if v:
                try:protections[target]=decrypt(v,cha[7])
                except (ValueError,UnicodeError):pass
        plain=decrypt(encrypted,cha[1])
    names=['payload','proxy','lockAllConfig','blockedByRoot','expiryTime','noteEnabled','notes','sshField','mobileDataAndLockProvider','unlockUserAndPass','ovpnConfig','ovpnUserAndPass','sni','unlockUserAndPass2','unknown14','blockedByHwid','cloudconfig','psiphon','name','blockArea','connectionMode','blockedByPassword','unknown22','extraSniffer','psiphon2','v2rayEnabled','v2rayConfig','version','slowdnsEnabled','slowdnsServer','slowdnsPublickey','dnsResolver']
    hwid=protections.get('hwid','');password=protections.get('password','')
    provider=protections.get('provider','');area=protections.get('area','')
    material=(hwid*2 if hwid and not any([password,provider,area]) else password+hwid+provider+area).encode()
    nonce=bytearray(b'\xdb'*8);nonce[:min(8,len(material))]=material[:8]
    is_new=isinstance(obj.get('cfg'),dict) and 'content' in obj['cfg']
    config={}
    for i,token in enumerate(plain.split(delimiter)):
        if not token:continue
        value=decode_field(token,bytes(nonce),cha,is_new)
        if i in {7,11}:value=credentials(value,i==7)
        try:value=json.loads(value) if value.startswith(('{','[')) else value
        except ValueError:pass
        config[names[i] if i<len(names) else f'field_{i}']=value
    return {'Protections':protections,'Config':config}

def unseal(data):
    key=hkdf(sha(SECRET+b'hc-envelope-seal-v1 xyz.easypro.httpcustom'),b'hc-envelope-seal-salt-v1',b'hc-envelope-seal-info-v1')
    for _ in range(6):
        if len(data)>=40:
            try:return json.loads(text(chacha(key,data[:24],data[24:],b'HCX1|xyz.easypro.httpcustom|1')))
            except (ValueError,UnicodeError):pass
            # The original APK also accepts this historical unauthenticated outer envelope.
            try:
                oldkey=bytes.fromhex('88702df6ae8c089c9478b8cd2bd3f30961b3574a58063d024bdc50f6b779e26f')
                obj=json.loads(text(stream(oldkey,data[:24],data[24:-16])))
                if obj.get('a')=='HCCFG':return obj
            except (ValueError,UnicodeError):pass
        try:converted=text(data).encode('latin1')
        except UnicodeError:break
        if converted==data:break
        data=converted
    raise DecodeError('Unsupported HCCFG envelope')
def modern(data,password=None,hwid=None):
    from argon2.low_level import hash_secret_raw,Type
    obj=unseal(data)
    if obj.get('a')!='HCCFG' or obj.get('b') not in {1,2,5,7}:raise DecodeError('Invalid HCCFG header')
    mode=obj['e'];version=obj['b']
    if mode not in {'n1','n2','n7','n8'}:raise DecodeError('Unregistered HCCFG mode')
    if obj['c']!=('XCHACHA20P1305' if version==1 else 's1') or obj['d']!=('NATIVE-HKDF-SHA256' if version==1 else 'h1'):raise DecodeError('Invalid HCCFG crypto profile')
    flags=','.join(obj['f']).encode();salt=bytes.fromhex(obj['g'])
    if len(salt)!=32:raise DecodeError('Invalid HCCFG salt')
    build=str(obj['n']).encode() if obj.get('n') is not None else None
    hwidbytes=None
    if mode in {'n2','n8'}:
        if hwid is None:raise DecodeError('HWID_REQUIRED')
        hwid=hwid.strip().upper()
        if len(hwid)!=32 or any(c not in '0123456789ABCDEFH' for c in hwid):raise DecodeError('Invalid HWID')
        hwidbytes=hwid.encode()
    pieces=[b'HCCFG',APP,b'1',flags]
    if build is not None:pieces.append(build)
    if hwidbytes is not None:pieces += [b'hwid',hwidbytes]
    context=b'\0'.join(pieces)+b'\0'+salt
    key=mac(bytes.fromhex('9ba7ff3baf33db7aad807a86574b7ca55bef2f048ead51f3a1fe0cff389db3b3'),b'\xd3'+SECRET[:32]+context) if mode in {'n7','n8'} else sha(SECRET+context)
    protection=b'|0'
    if obj.get('h'):
        if not password:raise DecodeError('PASSWORD_REQUIRED')
        cost,memory=obj['l'],obj['m']
        if not 1<=cost<=16 or not 8388608<=memory<=268435456 or memory%1024:raise DecodeError('Invalid HCCFG Argon2 parameters')
        if obj['k'] not in {'ARGON2ID13','a1'}:raise DecodeError('Unregistered HCCFG password KDF')
        key += hash_secret_raw(password.encode() if isinstance(password,str) else password,salt[:16],cost,memory//1024,1,32,Type.ID,19)
        protection=f'|1|ARGON2ID13|{cost}|{memory}'.encode()
    info=b'app-config|'+mode.encode()+b'|'+APP+b'|1|'+flags
    if build is not None:info+=b'|'+build
    if hwidbytes is not None:info+=b'|hwid|'+hwidbytes
    key=hkdf(key,salt,info)
    aad=f'HCCFG|{version}|XCHACHA20P1305|NATIVE-HKDF-SHA256|{mode}|'.encode()+APP+b'|1|'+flags+protection
    if build is not None:aad+=b'|'+build
    if hwidbytes is not None:
        def unwrap(slot):return chacha(key,bytes.fromhex(slot['a']),bytes.fromhex(slot['b']),aad+b'\0w')
        key=first([lambda s=s:unwrap(s) for s in obj['o']])
    def section(record):return chacha(key,bytes.fromhex(record['b']),bytes.fromhex(record['c']),aad+b'\0'+record['a'].encode())
    main=json.loads(text(section(obj['i'])))
    configs=[];other=[];sections=obj.get('j',[])
    if isinstance(sections,dict):sections=[sections[k] for k in sorted(sections)]
    for record in sections:
        plain=section(record);label=record['a'];sidecar=None
        if plain[:4]==b'HPR1':plain=chacha(key,plain[4:28],plain[28:],aad+b'\0'+(label+':r').encode())
        if record.get('d'):
            r=record['d'];sidecar=chacha(key,bytes.fromhex(r['a']),bytes.fromhex(r['b']),aad+b'\0'+label.encode()+b':x')
        if plain[:4]!=b'HPC1':other.append({'label':label,'content':parse(plain)});continue
        pos=4
        def integer():
            nonlocal pos
            value=struct.unpack('>i',plain[pos:pos+4])[0];pos+=4;return value
        def string():
            nonlocal pos
            n=integer()
            if n<0 or n>len(plain)-pos:raise DecodeError('Invalid HPC1 string length')
            s=text(plain[pos:pos+n]);pos+=n;return s
        if integer()!=11:raise DecodeError('Unregistered HPC1 version')
        conf={k:string() for k in ['name','protocol','host']};conf['port']=integer()
        conf.update({k:string() for k in ['username','password','payload']});conf['options']=parse(string());conf['flags']=integer()&0xffffffff
        conf['updated_at_ms']=struct.unpack('>q',plain[pos:pos+8])[0];pos+=8;conf['mode']=string();conf['label']=label
        if pos!=len(plain):raise DecodeError('Trailing HPC1 data')
        if sidecar is not None:conf['custom_payload_sidecar']=parse(sidecar)
        configs.append(conf)
    return {'app_version':obj.get('n'),'config':configs,'main_config':main,'other_sections':other,'requirements':{'password_required':bool(obj.get('h')),'hwid_required':hwidbytes is not None}}
def httpcustom(data,password=None,hwid=None):
    try:return modern(data,password,hwid)
    except DecodeError as e:
        if str(e) in {'PASSWORD_REQUIRED','HWID_REQUIRED'}:raise
        return legacy(data)
