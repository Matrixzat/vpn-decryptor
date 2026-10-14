"""Recovered legacy AES/DES/XXTEA formats. Raw configurations replace app banners."""
from .common import *

PASSWORDS={'fnnetwork':'Ed\x01','mij':'Ed\x01','mrc':'Ed\x01','mtl':'Ed\x01','uwu':'Ed','nt':'0x0','pb':'Cw1G6s0K8fJVKZmhSLZLw3L1R3ncNJ2e','pcx':'cinbdf665$4','sksrv.png':'6pq8YieK$8D2kT4a6Pizv3i56nWi'}
def legacy(data,suffix):
    if suffix in PASSWORDS:return parse(triplet(data,PASSWORDS[suffix]))
    if suffix in {'agn','cly','fɴ','jvc','jvi','v2i'}:
        keys=[b'cinbdf66',b64('4pyF2Y5PU1Q='),b'letsmake',b'agstgfoh']
        return first([lambda k=k:require_config(des(k,data)) for k in keys])
    if suffix in {'sbr','ost'}:
        key=b'cinbdf66' if suffix=='sbr' else b64('4pyF2Y5PU1Q=')
        try:return require_config(des(key,data))
        except (ValueError,UnicodeError):
            if suffix=='ost':
                from .families import ultra
                return ultra(data,suffix)
            raise
    if suffix in {'stk','rez','rezl','tvt','ipt'}:
        key=b64('QEFkZWRheW8ncyBXZVR1bm5lbA==')[:16] if suffix=='ipt' else (b'Bgw34Nmk' if suffix=='stk' else b'@technore24 2022')
        plain=xxtea(b64(data),key,delta=0x9a7393b4)
        s=(plain.decode('latin1') if suffix=='ipt' else text(plain)).rstrip('\0N')
        if suffix=='stk':s=s.replace('\\','').removeprefix('{"config":"').removesuffix('}"')
        return json.loads(s[s.find('{'):s.rfind('}')+1])
    if suffix=='at':
        def decrypt(v):
            record=b64(v);salt=record[:16]
            first_layer=gcm(salt+b'AF4nnvvn10XpsrrR',record[16:28],record[28:])
            return text(gcm(salt,first_layer[:12],first_layer[12:]))
        return walk(require_config(decrypt(text(data).strip())),decrypt)
    if suffix=='aro':
        plain=bytes((v+18)&255 for v in b64(data))
        obj=require_config(plain)
        def decrypt(v):return b64(b64(v)).decode('latin1') if v else 'enzo pro'
        return walk(obj,decrypt)
    if suffix=='nm':
        record=b64url(strip_uri(data));raw=None
        if not record or len(record)%16:raise DecodeError('Invalid NetMod AES record')
        for key in [b'<n3t5yn4^n3tm0d>',b'_netsyna_netmod_',b'nicetrybuddygoon']:
            plain=ecb(key,record,padded=False)
            try:plain=unpad(plain,16)
            except ValueError:plain=plain.rstrip(b'\0')
            try:s=text(plain)
            except UnicodeError:continue
            try:return json.loads(s)
            except ValueError:
                if raw is None and s and all(c.isprintable() or c in '\r\n\t' for c in s):raw=s
        if raw is not None:return raw
        raise DecodeError('No NetMod key produced a readable configuration')
    if suffix=='mina':return require_config(cbc(sha(b'AndroidV'),bytes(16),b64(data)))
    if suffix=='vpnlite':
        record=b64(data);return parse(cbc(sha('Wasjdeijs@/ÇPãoOf231#$%¨&*()_qqu&iJo>ç'.encode()),record[:16],record[16:]))
    if suffix in {'xtp','roy','sut'}:
        alphabet="¹²³⁴⁵⁶⁷⁸⁹⁰·,‽:'′"
        s=text(data).strip()
        if len(s)%2:raise DecodeError('Invalid symbol encoding')
        enc=bytes((alphabet.index(s[i])<<4)|alphabet.index(s[i+1]) for i in range(0,len(s),2))
        password='SimeliFamilyForLifeTime' if suffix=='sut' else 'tekidoer'
        obj=require_config(cbc(sha(password.encode().hex().upper().encode()),bytes(16),b64(enc)))
        if suffix=='sut':
            p=sha(b'new#Pa$$wd#4#Maky,sim?2024tech&(.);#@980well*..smk.now')
            for k in ['UDPServerIP','ServerIP','Payload','Bug','SNI','ServerUser','UDPServerUser','UDPServerPass','chaveKey','serverNameKey','dnsKey']:
                if isinstance(obj.get(k),str):
                    try:obj[k]=text(cbc(p,bytes(16),b64(obj[k])))
                    except (ValueError,UnicodeError):pass
        return obj
    if suffix=='sksplus':
        obj=json.loads(text(data))['payload']
        return require_config(cbc(bytes.fromhex('6237376365303534616164623839653963313064633430656265393735323631'),bytes(v&255 for v in obj['iv']),bytes(v&255 for v in obj['encoded'])))
    if suffix=='xscks':
        # The APK uses an ASCII binary-digit string as the password, not its decoded letters.
        password=asset('ported_constants.json')['xscksPassword'].encode()
        return require_config(cbc(sha(password),bytes(16),b64(data)))
    if suffix=='xui':
        key=bytes.fromhex('721d60cba2999a7e0f90e848d1ea31b7d06aa6be3654821fc4a5b388e70fc51c')
        def decrypt(v):
            r=b64(v);return parse(cbc(key,r[:16],r[16:]))
        return walk(require_config(decrypt(text(data))),decrypt)
    if suffix=='v2':
        s=data.decode('utf-8',errors='replace').strip()
        variant=-1
        if '[eV2ray]' not in s:
            encoded=bytes(v^((i%20)+2) for i,v in enumerate(data.rstrip(b'\t\n\r ')))
            enc=b64(encoded)
            s=first([lambda key=key:text(ecb(key,enc)) for key in [b'#%*7K!iuFem%M6BB',b'ah@`6js^E5,.esEK',b'3gp268y3i9nwd4ut']])
        parts=s.split('[eV2ray]')
        if len(parts)!=3 or parts[2]!='true':raise DecodeError('Invalid eV2Ray export')
        return {'profile_name':text(b64(parts[0])).strip(),'config':json.loads(text(b64(parts[1]))),'enabled':True}
    raise DecodeError('Legacy format not yet translated: '+suffix)
