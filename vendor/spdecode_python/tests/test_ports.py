"""Synthetic compatibility checks. No real exporter files are represented here."""
import base64
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest
import zlib
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from Crypto.Cipher import AES,DES,ChaCha20_Poly1305
from Crypto.Util.Padding import pad
from argon2.low_level import hash_secret_raw,Type
from spdecode.api import decode,formats,CATALOG
from spdecode.common import *
from spdecode.whitebox import npvs_block,canonical

def encode64(b):return base64.b64encode(b).decode()
def encrypt_gcm(key,nonce,data,aad=b''):
    c=AES.new(key,AES.MODE_GCM,nonce=nonce);c.update(aad);enc,tag=c.encrypt_and_digest(data);return enc+tag
def encrypt_chacha(key,nonce,data,aad=b''):
    c=ChaCha20_Poly1305.new(key=key,nonce=nonce);c.update(aad);enc,tag=c.encrypt_and_digest(data);return enc+tag
def encode_triplet(password,plain):
    salt=bytes(range(16));nonce=bytes(range(12));key=hashlib.pbkdf2_hmac('sha256',password if isinstance(password,bytes) else password.encode(),salt,1000,16)
    return '.'.join(map(encode64,[salt,nonce,encrypt_gcm(key,nonce,plain)] )).encode()
def xxtea_encrypt(plain,key,delta=0x9e3779b9,include_length=True):
    n=(len(plain)+3)//4
    v=list(struct.unpack('<'+'I'*n,plain.ljust(n*4,b'\0')))
    if include_length:v.append(len(plain))
    n=len(v);k=struct.unpack('<4I',key[:16].ljust(16,b'\0'));z=v[-1];total=0
    for _ in range(6+52//n):
        total=(total+delta)&0xffffffff;e=(total>>2)&3
        for p in range(n):
            y=v[p+1 if p+1<n else 0]
            mx=((((z>>5)^(y<<2))+((y>>3)^(z<<4)))^((total^y)+(k[(p&3)^e]^z)))&0xffffffff
            z=v[p]=(v[p]+mx)&0xffffffff
    return struct.pack('<'+'I'*n,*v)

class PortTests(unittest.TestCase):
    def test_generic_all_profiles(self):
        plain=b'{"host":"test.invalid","port":443}'
        for p in asset('generic_b_profiles.json')['profiles']:
            if p['aesKeys']:
                with self.subTest(suffix=p['suffix'],algorithm='AES'):
                    self.assertEqual(decode(encode_triplet(b64(p['aesKeys'][0]),plain),p['suffix']),json.loads(plain))
            if p.get('desKey'):
                with self.subTest(suffix=p['suffix'],algorithm='DES'):
                    data=plain+b' '*((-len(plain))%8)
                    encrypted=DES.new(b64(p['desKey'])[:8].ljust(8,b'\0'),DES.MODE_ECB).encrypt(data)
                    self.assertEqual(decode(encrypted,p['suffix']),json.loads(plain))
    def test_ultra_all_profiles_and_nested_fields(self):
        catalog=asset('ultra_c_profiles.json')
        for p in catalog['profiles']:
            aliases=[a for a in catalog['aliases'] if a['profile']==p['key']]
            if not aliases:continue
            with self.subTest(profile=p['key']):
                salt=bytes(range(16));nonce=bytes(range(12))
                def key(password):return hash_secret_raw(b64(p[password]),salt,3,p['memoryKiB'],1,32,Type.ID,19)
                field=catalog['encryptedFields'][0]
                nested=encode64(salt+nonce+encrypt_gcm(key('password2'),nonce,b'inner value',salt))
                obj={'host':'test.invalid',field:nested};encrypted=salt+nonce+encrypt_gcm(key('password'),nonce,json.dumps(obj).encode(),salt)
                result=decode(encode64(encrypted).encode(),aliases[0]['suffix'])
                self.assertEqual(result['config'][field],'inner value')
    def test_renz_all_aliases_outer_container(self):
        c=asset('renz_d_profiles.json');profiles={p['key']:p for p in c['profiles']}
        plain=b'{"host":"test.invalid","port":443}'
        for alias in c['aliases']:
            with self.subTest(suffix=alias['suffix']):
                p=profiles[alias['profile']]
                if p['key']=='tcxtunnel':
                    key=bytes.fromhex('6103102f3dfa7cac1aa5b8ff4ba12022')
                    encrypted=xxtea_encrypt(AES.new(key,AES.MODE_CBC,bytes(16)).encrypt(pad(plain,16)),key)
                else:
                    key=hashlib.sha256(bytes.fromhex(p['seed'])).digest()[:16]
                    key=key.split(b'\0',1)[0].ljust(16,b'\0')
                    data=plain if p['key'] in {'xhypher','safetunnel','mhrtunnel','letsvpngo'} else bytes((v+2)&255 for v in plain)
                    inner=xxtea_encrypt(data,key,2052510689)
                    # The CBC key uses the original digest; XXTEA truncates after the first zero.
                    aeskey=hashlib.sha256(bytes.fromhex(p['seed'])).digest()[:16]
                    encrypted=AES.new(aeskey,AES.MODE_CBC,bytes.fromhex(p['iv'])).encrypt(pad(inner,16))
                result=decode(encode64(encrypted).encode(),alias['suffix'])
                self.assertEqual(result['config'],json.loads(plain))
    def test_tls_six_key_profiles(self):
        p=asset('embedded_kotlin_profiles.json')['tls']['hexProfiles']
        for number,key in enumerate(p,1):
            with self.subTest(profile=number):
                nonce=bytes(range(36));values=['']*28
                values[0]='1';values[1]='2';values[2]='443';values[4]=encode64(b'user');values[6]=encode64(b'test.invalid');values[12]=encode64(b'GET / HTTP/1.1');values[27]=encode64(b'hello')
                enc=encrypt_gcm(bytes.fromhex(key),nonce,':'.join(values).encode());half=len(enc)//2
                record=bytes(12)+enc[:half][::-1]+nonce[:18][::-1]+enc[half:][::-1]+nonce[18:][::-1]+bytes(84)
                result=decode(('tls://'+encode64(record)[::-1]).encode(),'tls')
                self.assertEqual(result['sshuser'],'user');self.assertEqual(result['_tls']['key_profile'],number)
    def test_legacy_triplet_families(self):
        from spdecode.legacy import PASSWORDS
        plain=b'{"host":"test.invalid"}'
        for suffix,password in PASSWORDS.items():
            with self.subTest(suffix=suffix):self.assertEqual(decode(encode_triplet(password,plain),suffix),json.loads(plain))
    def test_independent_triplets(self):
        p=asset('embedded_kotlin_profiles.json')['independentF1'];plain=b'{"host":"test.invalid"}'
        for suffix,password in [('ltm',bytes.fromhex(p['ltmPasswordHex'])),('vn7',p['vn7Passwords'][0]),('phc',p['vn7Passwords'][1]),('ziv',p['vn7Passwords'][0])]:
            with self.subTest(suffix=suffix):self.assertEqual(decode(encode_triplet(password,plain),suffix),json.loads(plain))
    def test_xor_family_hex_and_nested(self):
        key=b'4%PdXch>fkP]'
        enc=lambda s:bytes(v^key[i%len(key)] for i,v in enumerate(s.encode())).hex()
        plain=json.dumps({'host':enc('test.invalid')})
        for suffix in ['apnalite','apnatnl','omanova','4ulite','bdnet','hsome','ursa','fnf','hxt']:
            self.assertEqual(decode((suffix+'://'+enc(plain)).encode(),suffix),{'host':'test.invalid'})
    def test_ipt_and_rez_custom_delta(self):
        obj={'PSInstall':True,'host':'test.invalid'};plain=json.dumps(obj).encode()
        for suffix,password in [('ipt',b64('QEFkZWRheW8ncyBXZVR1bm5lbA==')[:16]),('rez',b'@technore24 2022')]:
            with self.subTest(suffix=suffix):
                record=xxtea_encrypt(plain,password,0x9a7393b4,False)
                self.assertEqual(decode(encode64(record).encode(),suffix),obj)
    def test_ec_standard_xxtea(self):
        p=asset('embedded_kotlin_profiles.json')['specialKeyFamilies']['e2'];obj={'host':'test.invalid'}
        record=xxtea_encrypt(json.dumps(obj).encode(),p['ecPassword'].encode())
        self.assertEqual(decode(encode64(record).encode(),'ec'),obj)
    def test_flex_versions(self):
        materials=asset('flex_f_profiles.json')['materials']
        for version in [1,2,3,4]:
            entries=[k for k in materials if k.startswith(str(version)+',')];selected=entries[0];build=int(selected.split(',')[1])
            salt=bytes(range(32));nonce=bytes(range(12));iterations=10000
            password=b64(materials[selected]).decode('latin1').encode()
            key=hashlib.pbkdf2_hmac('sha512',password,salt,iterations,32)
            plain=zlib.compress(b'<properties><entry key="sshServer">test.invalid</entry></properties>')
            aad=b'FLXCFG'+bytes([version])+struct.pack('>I',build) if version>=3 else b''
            encrypted=encrypt_gcm(key,nonce,plain,aad)
            record=b'FLXCFG'+bytes([version])+(struct.pack('>I',build) if version>=3 else b'')+struct.pack('>I',iterations)+bytes([len(salt)])+salt+bytes([12])+nonce+struct.pack('>I',len(encrypted))+encrypted
            with self.subTest(version=version):self.assertEqual(decode(record,'flex')['rawProperties']['sshServer'],'test.invalid')
    def test_legacy_cbc_and_symbol_formats(self):
        obj={'host':'test.invalid'};plain=json.dumps(obj).encode()
        for suffix,password in [('mina',b'AndroidV'),('xscks',asset('ported_constants.json')['xscksPassword'].encode())]:
            c=AES.new(hashlib.sha256(password).digest(),AES.MODE_CBC,bytes(16));r=encode64(c.encrypt(pad(plain,16)))
            with self.subTest(suffix=suffix):self.assertEqual(decode(r.encode(),suffix),obj)
        alphabet="¹²³⁴⁵⁶⁷⁸⁹⁰·,‽:'′";password='tekidoer'.encode().hex().upper().encode()
        enc=encode64(AES.new(hashlib.sha256(password).digest(),AES.MODE_CBC,bytes(16)).encrypt(pad(plain,16))).encode()
        record=''.join(alphabet[v>>4]+alphabet[v&15] for v in enc).encode()
        self.assertEqual(decode(record,'roy'),obj)
    def test_authenticated_cipher_tampering_is_rejected(self):
        valid=encode_triplet(b'Ed\1',b'{"host":"test.invalid"}').split(b'.')
        last=bytearray(b64(valid[2]));last[-1]^=1;valid[2]=encode64(last).encode()
        with self.assertRaises(ValueError):decode(b'.'.join(valid),'fnnetwork')
    def test_reference_java_vectors(self):
        from spdecode.whitebox import npv_block,npvs_block
        from spdecode.renz import threefish
        vectors=dict(line.split() for line in (Path(__file__).parent/'reference_vectors.txt').read_text().splitlines())
        block=bytes((i*13+7)&255 for i in range(16));r=bytes((i*7+11)&255 for i in range(64));k=bytes((i*19+3)&255 for i in range(32))
        self.assertEqual(npv_block(block).hex(),vectors['npv']);self.assertEqual(npvs_block(block).hex(),vectors['npvs'])
        self.assertEqual(threefish(r,k,lambda i,w:(i,64*i)).hex(),vectors['threefishBefore'])
        self.assertEqual(threefish(r,k,lambda i,w:(i,64*i),True).hex(),vectors['threefishAfter'])
    def test_ehi_container(self):
        p=asset('embedded_kotlin_profiles.json')['ehi'];obj={'host':'test.invalid','configSalt':'EVZJNI'}
        iv=bytes.fromhex(p['bypassIvHex'][0]);iv2=bytes(range(16))
        raw=xxtea_encrypt(json.dumps(obj).encode(),p['xxteaKeyText'].encode())
        inner=AES.new(bytes.fromhex(p['secondKeyHex']),AES.MODE_CBC,iv2).encrypt(pad(raw,16))
        outer=(encode64(iv2)+':unused:'+encode64(inner)).encode()
        encrypted=AES.new(bytes.fromhex(p['firstKeyHex']),AES.MODE_CBC,iv).encrypt(pad(outer,16))
        def string(s):return struct.pack('>H',len(s))+s
        record=string(b'EHI')+bytes(8)+string(b'version')+bytes(8)+struct.pack('>I',len(encrypted))+bytes(8)+encrypted
        self.assertEqual(decode(record,'ehi'),obj)
    def test_npvs_complete_container_and_signature(self):
        from cryptography.hazmat.primitives.asymmetric import ec,utils
        from cryptography.hazmat.primitives import hashes,serialization
        private=ec.derive_private_key(19,ec.SECP256R1());public=private.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.CompressedPoint)
        config_id=bytes(range(16));nonce=bytes(range(12));block=bytes((i*13+7)&255 for i in range(16));wrapped_nonce=bytes(range(12,24));doc_key=bytes(range(32))
        metadata={'policy':{'displayMessage':'test'},'issuedAt':1700000000}
        info=lambda ikm,salt,info:mac(mac(salt,ikm),info+b'\1')
        wrap_key=hashlib.sha256(b'npvtunnel/appkey/v2 '+npvs_block(block)+config_id).digest()
        wrapped=wrapped_nonce+encrypt_chacha(wrap_key,wrapped_nonce,doc_key,block)
        prefix=b'\1'+config_id+public+b'\2'+struct.pack('>H',0)+b'\0\2'+block+wrapped
        length=len(json.dumps(metadata).encode())+16;prefix+=struct.pack('>I',length)
        encrypted_metadata=encrypt_chacha(info(doc_key,nonce,b'NPVS-v5/metadata'),nonce,json.dumps(metadata).encode(),prefix[:-4])
        aux=prefix+encrypted_metadata
        url=lambda b:base64.urlsafe_b64encode(b).decode().rstrip('=')
        normalized={'onlyMobileNetwork':False,'attestationLevel':'','expiresAt':None,'displayMessage':'test','customServerMessage':''}
        source={'v':5,'configId':url(config_id),'issuedAt':1700000000,'creator':{'fp':url(hashlib.sha256(public).digest()),'pk':url(public)},'policy':normalized,'recipients':None}
        fingerprint=hashlib.sha256(b'NPVS-v5/source-fields-v1/'+canonical(source)+nonce).digest()
        fieldkey=lambda label,id:info(doc_key,fingerprint,b'NPV-fields-v1/'+label+b'/'+struct.pack('>H',id))
        fields=b'NPF\1'+fingerprint+struct.pack('>H',2)
        for id,obj in [(1,'test.invalid'),(65535,{'configs':[{'host':1}]})]:
            plain=json.dumps(obj).encode();aad=b'NPV-fields-v1/record/'+fingerprint+struct.pack('>HI',id,len(plain))
            enc=encrypt_chacha(fieldkey(b'field',id),bytes(12),plain,aad);fields+=struct.pack('>HI',id,len(enc))+enc
        fields+=mac(fieldkey(b'inventory',0),fields)
        body=b'NPVS\5'+struct.pack('>I',len(aux))+aux+nonce+struct.pack('>I',len(fields))+fields
        der=private.sign(body,ec.ECDSA(hashes.SHA256()));r,s=utils.decode_dss_signature(der);record=body+r.to_bytes(32,'big')+s.to_bytes(32,'big')
        result=decode(record,'npvs');self.assertEqual(result['document']['configs'][0]['host'],'test.invalid')
        altered=bytearray(record);altered[9]^=1
        with self.assertRaises(Exception):decode(bytes(altered),'npvs')
    def test_httpcustom_modern_sealed(self):
        from spdecode.httpcustom import SECRET,hkdf
        app=b'xyz.easypro.httpcustom';flags=b'test';salt=bytes(range(32));nonce=bytes(range(24))
        context=b'\0'.join([b'HCCFG',app,b'1',flags])+b'\0'+salt
        base=hashlib.sha256(SECRET+context).digest();key=hkdf(base,salt,b'app-config|n1|'+app+b'|1|test')
        aad=b'HCCFG|1|XCHACHA20P1305|NATIVE-HKDF-SHA256|n1|'+app+b'|1|test|0'
        main={'g':{'v':'test note'}};enc=encrypt_chacha(key,nonce,json.dumps(main).encode(),aad+b'\0main')
        envelope={'a':'HCCFG','b':1,'c':'XCHACHA20P1305','d':'NATIVE-HKDF-SHA256','e':'n1','f':['test'],'g':salt.hex(),'h':0,'i':{'a':'main','b':nonce.hex(),'c':enc.hex()},'j':[]}
        sealkey=hkdf(hashlib.sha256(SECRET+b'hc-envelope-seal-v1 xyz.easypro.httpcustom').digest(),b'hc-envelope-seal-salt-v1',b'hc-envelope-seal-info-v1')
        record=nonce+encrypt_chacha(sealkey,nonce,json.dumps(envelope).encode(),b'HCX1|xyz.easypro.httpcustom|1')
        result=decode(record,'hc');self.assertEqual(result['main_config'],main)
    def test_routes_cover_entire_catalog(self):
        self.assertEqual(len(formats()),239)
        for e in formats():
            with self.subTest(suffix=e['suffix']):
                try:decode(b'invalid',e['suffix'])
                except Exception as error:self.assertNotIn('not mapped',str(error));self.assertNotIn('not yet translated',str(error));self.assertNotIn('routing missing',str(error))
    def test_individual_script_cli_from_another_directory(self):
        import subprocess,tempfile
        script=Path(__file__).resolve().parents[1]/'decoders/fnnetwork.py'
        with tempfile.TemporaryDirectory() as work:
            input=Path(work)/'fixture.fnnetwork';output=Path(work)/'decoded.json'
            input.write_bytes(encode_triplet('Ed\1',b'{"host":"test.invalid"}'))
            completed=subprocess.run([sys.executable,str(script),str(input),'-o',str(output)],cwd=work,capture_output=True,text=True)
            self.assertEqual(completed.returncode,0,completed.stderr)
            self.assertEqual(json.loads(output.read_text()),{'host':'test.invalid'})
    def test_nur_solid_internal_and_export_marker(self):
        p=asset('embedded_kotlin_profiles.json')['nurTunnel'];obj={'Name':'test','TunnelType':'SSH'}
        for name,export in [('internalSecretB64',False),('exportSecretB64',True)]:
            salt=bytes(range(16));nonce=bytes(range(12));key=hash_secret_raw(b64(p[name]),salt,3,8192,1,32,Type.ID,19)
            encoded=encode64(salt+nonce+encrypt_gcm(key,nonce,json.dumps(obj).encode(),salt))
            if export:encoded=encoded[:3]+'x'+encoded[3:]
            self.assertEqual(decode(encoded.encode(),'solid'),obj)
    def test_linklayer_complete_container(self):
        from Crypto.Cipher import Salsa20,CAST,Blowfish
        from spdecode.linklayer import STATIC_IV
        def uint(n):
            if n<128:return bytes([n])
            b=n.to_bytes((n.bit_length()+7)//8,'big');return bytes([256-len(b)])+b
        def sint(n):return uint((~n<<1)|1 if n<0 else n<<1)
        def string(s):return uint(len(s))+s
        descriptor=sint(-65)+uint(3)+uint(1)+uint(1)+string(b'NativeConfig')+uint(1)+sint(65)+uint(0)+uint(1)+uint(1)+uint(1)+string(b'Host')+uint(1)+sint(6)+uint(0)+uint(0)+uint(0)
        value=sint(65)+uint(1)+string(b'test.invalid')+uint(0)
        gob=uint(len(descriptor))+descriptor+uint(len(value))+value
        def enc(algorithm,key,data):return algorithm.new(key,algorithm.MODE_CFB,STATIC_IV[:algorithm.block_size],segment_size=algorithm.block_size*8).encrypt(data)
        final_key=bytes(range(32));cipher=enc(AES,final_key,gob);key_swapped=bytearray(final_key);key_swapped[0],key_swapped[-1]=key_swapped[-1],key_swapped[0]
        inner=cipher[10:][::-1]+cipher[:10]+key_swapped
        pbkdf_key=bytes(range(16));stream=hashlib.pbkdf2_hmac('sha1',pbkdf_key,b'sH3CIVoF#rWLtJo6',32,1500)
        mixed=bytes(c^stream[i] if i<1500 else c for i,c in enumerate(inner))
        cast_key=bytes(range(16,32));segment=enc(CAST,cast_key,b'\0'+pbkdf_key+mixed)+cast_key
        length=len(segment);packet=struct.pack('>I',length)+bytes(length)+segment+bytes(length)
        salsa_key=bytes(range(32));nonce=bytes(range(8));packet=nonce+Salsa20.new(key=salsa_key,nonce=nonce).encrypt(packet)
        salsa_container=salsa_key+packet[::-1]+bytes(32)
        aes_key=bytes(range(32));trailer=aes_key[:16]+bytes(40)+aes_key[16:][::-1]
        record=b'VER6'+enc(Blowfish,b'12345678',enc(AES,aes_key,salsa_container)+trailer)+b'12345678'
        self.assertEqual(decode(record,'lnk')['Host'],'test.invalid')

if __name__=='__main__':unittest.main(verbosity=2)
