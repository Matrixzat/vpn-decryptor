"""Checks for one engine, merged historical variants, and every uploaded vector."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'vendor/spdecode_python'))
from Crypto.Cipher import AES,CAST,Salsa20
from Crypto.Util.Padding import pad
from scripts.decoder_job import DecoderJobError,run_decoder
from scripts.unified_cli import run_bytes
from scripts import ported_engine
from spdecode.common import asset,b64
from spdecode.socksip import IV,SALT

def encode64(data):return base64.b64encode(data).decode()
def decode(data,suffix,**kwargs):
    rendered=run_bytes(data,suffix,**kwargs)
    try:return json.loads(rendered)
    except ValueError:return rendered.rstrip('\n')
def gcm(key,nonce,data,aad=b''):
    cipher=AES.new(key,AES.MODE_GCM,nonce=nonce);cipher.update(aad)
    encrypted,tag=cipher.encrypt_and_digest(data)
    return encrypted+tag
def java_fixture():
    def utf(s):
        raw=s.encode();return struct.pack('>H',len(raw))+raw
    # A valid serialized object with one primitive field; no external Java needed.
    return b'\xac\xed\0\5\x73\x72'+utf('SerSocksIP')+bytes(8)+b'\x02\0\x01I'+utf('port')+b'\x78\x70'+struct.pack('>i',443)
def sip_fixture(version):
    profiles=asset('embedded_kotlin_profiles.json')['legacyBatch2']['sip']
    stream=java_fixture()
    if version==8:
        nonce=bytes(range(12))
        inner=b'VER8'+nonce+gcm(profiles['ver8Key'].encode(),nonce,stream)
    else:
        # Reverse all nine native layers to exercise VER2/5/7, not mocked routing.
        n=len(stream)+65;v=n-17
        key=bytes(range(32));stored=bytearray(key);stored[0],stored[-1]=stored[-1],stored[0]
        encrypted=AES.new(key,AES.MODE_CFB,iv=IV,segment_size=128).encrypt(stream)
        rebuilt=bytearray(bytes(range(16))+encrypted[10:][::-1]+encrypted[:10]+stored)
        xor=hashlib.pbkdf2_hmac('sha1',bytes(rebuilt[:16]),SALT,32,1500)
        for i in range(min(1500,len(rebuilt)-16)):rebuilt[16+i]^=xor[i]
        half=(n-17)//2
        cast_plain=b'\x01'+bytes(rebuilt[-half:])+bytes(rebuilt[:-half][::-1])
        cast_key=bytes(range(16))
        cast_enc=CAST.new(cast_key,CAST.MODE_CFB,iv=IV[:8],segment_size=64).encrypt(cast_plain)
        nonce=bytes(range(8));record=nonce+struct.pack('>I',n)+bytes(n)+cast_enc+cast_key
        salsa_key=bytes(range(32))
        record=nonce+Salsa20.new(key=salsa_key,nonce=nonce).encrypt(record[8:])
        prefix=salsa_key+record[::-1]+bytes(32)
        tail_size={2:32,5:52,7:47}[version]
        tail=bytes(range(16))+bytes(tail_size-32)+bytes(range(16,32))[::-1]
        outer_key=bytes(range(32))
        encrypted=AES.new(outer_key,AES.MODE_CFB,iv=IV,segment_size=128).encrypt(prefix)
        inner=f'VER{version}'.encode()+encrypted+tail
    return base64.b64encode(AES.new(bytes.fromhex(profiles['outerAesHex']),AES.MODE_ECB).encrypt(pad(inner,16)))

class MergeTests(unittest.TestCase):
    def test_source_inventory_and_approved_merge_bytes(self):
        from scripts.verify_import import verify
        self.assertEqual(verify()['files'],123)
    def test_httpcustom_full_historical_envelope(self):
        from Crypto.Cipher import ChaCha20
        from spdecode.hc_fields import JKL_OLD
        keys=[bytes.fromhex(v) for v in asset('hc_source_keys.json')['chaChaKeys']]
        def encrypt(key,data):
            cipher=ChaCha20.new(key=key,nonce=b'\xdb'*8);cipher.seek(64)
            return (cipher.encrypt(data)+bytes(16)).hex()
        encoded=base64.b64encode(b'HTTP payload')
        encoded=encode64(bytes(v^JKL_OLD[i%len(JKL_OLD)] for i,v in enumerate(encoded)))
        tokens=[encoded]+['']*31
        tokens[7]='host:443@user:pass'
        obj={'xy':encrypt(keys[1],'[splitConfig]'.join(tokens).encode()),'uv':'[splitConfig]'}
        outer=encrypt(keys[5],json.dumps(obj).encode()).encode()
        xor=bytes.fromhex(asset('embedded_kotlin_profiles.json')['httpCustom']['outerXorKeyHex'])
        data=bytes(v^xor[i%len(xor)] for i,v in enumerate(outer))
        result=decode(data,'hc')['Config']
        self.assertEqual(result['payload'],'HTTP payload')
        self.assertEqual(result['sshField'],'host:443@user:pass')
    def test_ehi_protected_configdata_and_reversed_fields(self):
        from argon2.low_level import hash_secret_raw,Type
        from Crypto.Cipher import ChaCha20_Poly1305
        from spdecode.injector import EHI_ALPHABET,STANDARD
        from unified_reference_vectors import xxtea_encrypt
        p=asset('embedded_kotlin_profiles.json')['ehi']
        salt='EVZJNI'
        def encode_field(value):
            value=value.encode()
            encrypted=bytes(v^ord(salt[i%len(salt)]) for i,v in enumerate(value)).hex().encode()
            return encode64(encrypted).translate(str.maketrans(STANDARD,EHI_ALPHABET))[::-1]
        meta={'configSalt':salt,'configIdentifier':'synthetic','configAesKey':'synthetic',
              'configTimestamp':0,'configExpiryTimestamp':0}
        names=['configAesKey','configIdentifier','configSalt','configTimestamp','configExpiryTimestamp',
               'lockModes','lockModesHash','configHwid','configLockMobileOperatorId']
        master=hashlib.sha256(''.join(str(meta.get(n,0 if 'Timestamp' in n else '')) for n in names).encode()).digest()
        raw_salt=bytes(range(16));nonce=bytes(range(24))
        header=b'\1'+struct.pack('<II',1,8)+b'\1'+raw_salt
        key=hash_secret_raw(master,raw_salt,1,8,1,32,Type.ID)
        cipher=ChaCha20_Poly1305.new(key=key,nonce=nonce);cipher.update(header)
        enc,tag=cipher.encrypt_and_digest(json.dumps({'host':encode_field('test.invalid'),'unknown':123}).encode())
        raw=header+nonce+enc+tag
        def container(record):
            config=dict(meta,configData=encode_field(encode64(record)))
            tea=xxtea_encrypt(json.dumps(config).encode(),p['xxteaKeyText'].encode())
            iv=bytes(range(16))
            inner=AES.new(bytes.fromhex(p['secondKeyHex']),AES.MODE_CBC,iv).encrypt(pad(tea,16))
            outer=(encode64(iv)+':ignored:'+encode64(inner)).encode()
            encrypted=AES.new(bytes.fromhex(p['firstKeyHex']),AES.MODE_CBC,bytes.fromhex(p['standardIvHex'][0])).encrypt(pad(outer,16))
            def utf(s):
                s=s.encode();return struct.pack('>H',len(s))+s
            return utf('ehi')+bytes(8)+utf('synthetic')+bytes(8)+struct.pack('>I',len(encrypted))+bytes(8)+encrypted
        self.assertEqual(decode(container(raw),'ehi'),{'host':'test.invalid','unknown':123})
        with self.assertRaises(DecoderJobError):decode(container(raw[:-1]+bytes([raw[-1]^1])),'ehi')
    def test_ssc_reversed_uri_and_inner_fields(self):
        import ast,inspect
        from Crypto.Cipher import ChaCha20
        from spdecode.misc import ssc
        tree=ast.parse(inspect.getsource(ssc));keys={}
        for node in ast.walk(tree):
            if isinstance(node,ast.Assign) and isinstance(node.value,ast.Constant):
                for target in node.targets:
                    if isinstance(target,ast.Name) and target.id in {'key1','key2','key3'}:
                        keys[target.id]=bytes.fromhex(node.value.value)
        identifier='0123456789abcdef1122334455667788'
        nonce=bytes.fromhex(identifier[16:][::-1]+'68'+identifier[:16])[:8]
        cipher=ChaCha20.new(key=keys['key3'],nonce=nonce);cipher.seek(64)
        field=cipher.encrypt(b'test.invalid\0'+bytes(16)).hex()
        obj={'a':[{'b':identifier,'g':field,'unknown':123}]}
        cipher=ChaCha20.new(key=keys['key1'],nonce=bytes.fromhex('74d0f3879f9d47f7'));cipher.seek(64)
        encoded=cipher.encrypt(json.dumps(obj).encode()).hex()
        result=decode(('ssc://'+encoded[::-1]).encode(),'ssc')
        self.assertEqual(result['a'][0]['g'],'test.invalid')
        self.assertEqual(result['a'][0]['unknown'],123)
    def test_socksip_all_four_versions(self):
        for version in [2,5,7,8]:
            with self.subTest(version=version):
                self.assertEqual(decode(sip_fixture(version),'sip'),{'port':443})
    def test_sockshttp_all_key_generations(self):
        seeds={1:b'662ede816988e58fb6d057d9d85605e0',5:b'962exe865948e37ws6d057d4d85604e0'}
        for version in [1,5,6,13]:
            keys=[hashlib.md5((prefix+str(version)).encode()).hexdigest().encode()
                  for prefix in ['162exe235948e37ws6d057d9d85324e2 ','962exe865948e37ws6d057d4d85604e0 ']]
            if version in seeds:keys.append(seeds[version])
            for key in keys:
                iv=bytes(range(16));enc=AES.new(key,AES.MODE_CBC,iv).encrypt(pad(b'{"host":"test.invalid"}',16))
                record=json.dumps({'v':version,'d':encode64(enc)+'.'+encode64(iv)}).encode()
                self.assertEqual(decode(record,'sks'),{'host':'test.invalid'})
    def test_password_v2box_and_authentication(self):
        password='synthetic-password';nonce=bytes(range(12))
        encrypted=gcm(hashlib.sha256(password.encode()).digest(),nonce,b'{"host":"test.invalid"}')
        record={'magic':'v2box_export','version':1,'isPasswordProtected':True,
                'nonce':encode64(nonce),'ciphertext':encode64(encrypted[:-16]),'tag':encode64(encrypted[-16:])}
        data=json.dumps(record).encode()
        self.assertEqual(decode(data,'v2box',password=password),{'host':'test.invalid'})
        for options in [{},{'password':'wrong'}]:
            with self.assertRaises(DecoderJobError):decode(data,'v2box',**options)
    def test_netmod_urlsafe_zero_padding_and_text(self):
        key=b'<n3t5yn4^n3tm0d>';plain=b'{"host":"test.invalid"}'
        for raw in [plain,b'host=test.invalid']:
            payload=AES.new(key,AES.MODE_ECB).encrypt(raw.ljust((len(raw)+15)//16*16,b'\0'))
            data=b'nm-vless://'+base64.urlsafe_b64encode(payload).rstrip(b'=')
            expected=json.loads(raw) if raw.startswith(b'{') else raw.decode()
            self.assertEqual(decode(data,'nm'),expected)
    def test_hat_text_and_hc_encoded_fields(self):
        key=b64(asset('embedded_kotlin_profiles.json')['hat']['aesKeyB64'])
        data=base64.b64encode(AES.new(key,AES.MODE_ECB).encrypt(pad(b'plain profile',16)))
        self.assertEqual(decode(data,'hat'),'plain profile')
        from spdecode.hc_fields import JKL_OLD,jkl,credentials,BRAILLE
        plain='test.invalid';inner=base64.b64encode(plain.encode())
        encrypted=bytes(v^JKL_OLD[i%len(JKL_OLD)] for i,v in enumerate(inner))
        self.assertEqual(jkl(encode64(encrypted)),plain)
        raw='host:443@user:pass'
        braille=''.join(BRAILLE[b>>4]+BRAILLE[b&15] for b in raw.encode())
        self.assertEqual(credentials(braille,True),raw)
    def test_opentunnel_xml_and_trailing_data(self):
        p=asset('embedded_kotlin_profiles.json')['legacyBatch2']['tnl']
        salt=bytes(range(32));nonce=bytes(range(12))
        key=hashlib.pbkdf2_hmac('sha256',p['oplSecret'].encode(),salt,100000,32)
        xml=b'<?xml version="1.0"?><properties><entry key="host"><![CDATA[test.invalid]]></entry><entry key="emoji">&#xD83D;&#xDE00;</entry></properties>'
        envelope='.'.join(map(encode64,[salt,nonce,gcm(key,nonce,xml)] )).encode()
        encoded=bytes(value^((((195<<(i%8))|(195>>(8-i%8)))&255))^(i&255) for i,value in enumerate(envelope))
        record=b'OPL\2'+struct.pack('<II',len(envelope)^((-1481390639)&0xffffffff),zlib.crc32(envelope))+encoded
        self.assertEqual(decode(record,'tnl'),{'host':'test.invalid','emoji':'😀'})
        with self.assertRaises(DecoderJobError):decode(record+b'extra','tnl')
    def test_one_engine_failure_cannot_call_original_code(self):
        with patch('scripts.ported_engine.decode',side_effect=ValueError('Rejected')),tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'config.npvt';path.write_bytes(b'bad')
            with self.assertRaises(DecoderJobError):run_decoder(ROOT,path,Path(temp)/'output')
        for path in ROOT.glob('*.py'):
            if path.name!='decode.py':self.assertLess(len(path.read_text().splitlines()),10,path.name)
    def test_cli_catalog_and_no_legacy_switch(self):
        result=subprocess.run([sys.executable,str(ROOT/'decode.py'),'--list'],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(len(result.stdout.splitlines()),240)
        result=subprocess.run([sys.executable,str(ROOT/'decode.py'),'--engine','legacy'],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
    def test_compound_suffix(self):
        self.assertEqual(ported_engine.infer_suffix('example.SKSRV.PNG'),'sksrv.png')

def load_tests(loader,_tests,_pattern):
    path=ROOT/'vendor/spdecode_python/tests/test_ports.py'
    spec=importlib.util.spec_from_file_location('unified_reference_vectors',path)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    def bridge(data,suffix,password=None,hwid=None):
        try:return decode(data,suffix,password=password,hwid=hwid)
        except DecoderJobError as error:raise ValueError(str(error)) from None
    module.decode=bridge
    suite=loader.loadTestsFromTestCase(MergeTests)
    suite.addTests(loader.loadTestsFromTestCase(module.PortTests))
    return suite

if __name__=='__main__':unittest.main(verbosity=2)
