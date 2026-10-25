"""Synthetic, non-sensitive tests. Run: python -m unittest discover -s tests -v"""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from withings_pklg_analyzer import WPPStream,parse_wpp,tlvs,scrub_json,reconstruct_configuration_transfers


def frame(cmd,fields):
    body=b''.join(struct.pack('>HH',t,len(v))+v for t,v in fields)
    return b'\x01'+struct.pack('>HH',cmd,len(body))+body


def packetlogger_record(typ,data):
    return struct.pack('<III',9+len(data),1000,0)+bytes([typ])+data


def acl_att(val,handle=0x40,typ=3,attr=0x25):
    att=bytes([0x1b])+struct.pack('<H',attr)+val
    l2=struct.pack('<HH',len(att),4)+att
    acl=struct.pack('<HH',handle|0x2000,len(l2))+l2
    return packetlogger_record(typ,acl)


class DecoderTests(unittest.TestCase):
    def test_reassemble_two_notifications(self):
        msg=frame(0x0147,[(0x0116,b'\x00'*23),(0x0144,b'\x03abc'),(0x0100,b'')])
        s=WPPStream()
        self.assertEqual(s.feed(msg[:12],5),[])
        out=s.feed(msg[12:],6)
        self.assertEqual(len(out),1)
        self.assertEqual(out[0]['command'],'0x0147')
        self.assertEqual(out[0]['start_record'],5)
        self.assertEqual(out[0]['end_record'],6)
        self.assertNotIn('payload_hex',out[0])

    def test_multiple_frames_one_notification(self):
        s=WPPStream()
        out=s.feed(frame(0x0101,[])+frame(0x0148,[(0x0145,b'\x00'*4)]),2)
        self.assertEqual([m['command'] for m in out],['0x0101','0x0148'])

    def test_private_bytes(self):
        s=WPPStream(private=True)
        out=s.feed(frame(0x0148,[(0x0145,b'\x01\x02\x03\x04')]),1)
        self.assertEqual(out[0]['tlvs'][0]['value_hex'],'01020304')

    def test_redaction(self):
        obj={'sp':{'users':[{'name':'Secret Name','id':123,'email':'secret@example.org'}]},'ind':{'ft':[12,27], 'mcr':1}}
        text=json.dumps(scrub_json(obj))
        self.assertNotIn('Secret Name',text)
        self.assertNotIn('secret@example.org',text)
        self.assertNotIn('123',text)
        self.assertIn('27',text)

    def test_configuration_chunk_reassembly_and_ack(self):
        source=b'{"ind":{"ft":[12,27]},"sp":{"users":[]}}'
        frames=[]
        for offset in range(0,len(source),10):
            chunk=source[offset:offset+10]
            frames.append(frame(0x010D,[(0x0112,bytes([len(chunk)])+chunk)]))
        frames.append(frame(0x010D,[(0x0100,b'')]))
        frames.append(frame(0x010D,[]))
        timeline=[]
        for idx,raw in enumerate(frames):
            direction='device_to_host' if idx==len(frames)-1 else 'host_to_device'
            decoded=parse_wpp(raw,private=True)
            decoded['start_record']=idx+10
            decoded['end_record']=idx+10
            timeline.append({'record':idx+10,'handle':'0x0058',
                             'direction':direction,'wpp_messages':[decoded]})
        transfers=reconstruct_configuration_transfers(timeline,private=True)
        self.assertEqual(len(transfers),1)
        self.assertEqual(transfers[0]['assembled_length'],len(source))
        self.assertEqual(transfers[0]['json']['ind']['ft'],[12,27])
        self.assertTrue(transfers[0]['json_valid'])
        self.assertTrue(transfers[0]['terminated'])
        self.assertTrue(transfers[0]['acknowledged'])
        self.assertEqual(transfers[0]['chunks'],len(frames)-2)
        public=[]
        for e in timeline:
            m=parse_wpp(frames[e['record']-10],private=False)
            m['start_record']=m['end_record']=e['record']
            public.append({**e,'wpp_messages':[m]})
        redacted=reconstruct_configuration_transfers(public,private=False)[0]
        self.assertNotIn('assembled_hex',redacted)
        self.assertNotIn('json',redacted)
        self.assertEqual(redacted['assembled_length'],len(source))

    def test_cli_synthetic_capture(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d)
            secret=b'privatepayloadEXAMPLE'
            msg=frame(0x0147,[(0x0144,bytes([len(secret)])+secret)])
            capture=d/'private-capture.pklg';output=d/'public.json'
            capture.write_bytes(acl_att(msg[:10])+acl_att(msg[10:]))
            result=subprocess.run([sys.executable,str(ROOT/'withings_pklg_analyzer.py'),str(capture),'--out',str(output)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            j=json.loads(output.read_text())
            self.assertEqual(j['capture'],'<redacted>')
            self.assertEqual(j['timeline'][-1]['wpp_messages'][0]['command'],'0x0147')
            self.assertNotIn('privatepayload',output.read_text())
            self.assertNotIn('private-capture',output.read_text())
            self.assertEqual(output.stat().st_mode & 0o777,0o600)

if __name__=='__main__':unittest.main()
