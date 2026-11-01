from __future__ import annotations
import base64,datetime,json,os,plistlib,struct,tempfile,unittest
from pathlib import Path
import collect_rekey104 as c
import collect_rekey100 as b
from test_collect_rekey104 import make_hcmd_service,auth_blob,FakeClock,BUILD,UUID

def group2(stage=12):
    raw=bytearray(b.GROUP2_SIZE)
    raw[:b.GROUP2_HEADER.size]=b.GROUP2_HEADER.pack(b.GROUP2_MAGIC,1,b.GROUP2_HEADER.size,b.GROUP2_EVENT.size,32,2,2,0,1,1,1,1,0)
    event=(1,1234567,501,3,2,1,7,9,7,12,6,17,128,8,4656,15,0,0,stage,1)
    raw[b.GROUP2_HEADER.size:b.GROUP2_HEADER.size+b.GROUP2_EVENT.size]=b.GROUP2_EVENT.pack(*event)
    return bytes(raw)

def point(raw=None):
    service=make_hcmd_service();service[c.AUTH_PROPERTY]=auth_blob()
    if raw is not None:service[b.GROUP2_PROPERTY]=raw
    service['NativeStaCompletionSequence']=31
    service['NativeStaCompletionLiveCount']=17
    service['NativeStaCompletionIgnoredNonNumeric']='not-retained'
    service['UnexpectedPrivateField']='private-not-retained'
    def ioreg(*args,**kwargs):return plistlib.dumps([service],fmt=plistlib.FMT_BINARY)
    def ifconfig(*args,**kwargs):return b'en1: flags=8863<UP,RUNNING> mtu 1500\n status: active\n'
    return c.sample_once(BUILD,{'boot_epoch':1700000000,'os_build':'25G332','loaded_kext_uuid':UUID},ioreg_fn=ioreg,ifconfig_fn=ifconfig,
        monotonic_ns=lambda:1,wall_now=lambda:datetime.datetime.fromisoformat('2026-01-01T00:00:00+00:00'))
class Group2RetentionTests(unittest.TestCase):
    def test_existing_metadata_preserved_in_same_sample_and_log(self):
        raw=group2();p=point(raw)
        event=p['group2_tx_trace']['events'][0]
        self.assertEqual((event['stage'],event['index'],event['origin_generation'],event['cookie']),(12,17,7,501))
        self.assertFalse(p['group2_tx_trace']['peer_ack_proven'])
        self.assertEqual(base64.b64decode(p['raw_osdata'][b.GROUP2_PROPERTY]['base64']),raw)
        self.assertEqual(p['completion_scalars']['NativeStaCompletionSequence'],31)
        self.assertEqual(p['completion_live_counters']['NativeStaCompletionLiveCount'],17)
        self.assertNotIn('IgnoredNonNumeric',json.dumps(p));self.assertNotIn('private-not-retained',json.dumps(p))
        clock=FakeClock()
        with tempfile.TemporaryDirectory() as temp:
            os.chmod(temp,0o700);path=Path(temp)/'fake.jsonl'
            c.capture(path,boot_epoch=1700000000,expected_uuid=UUID,expected_build=BUILD,duration=1,interval=.25,
                identity_reader=lambda *args:{'boot_epoch':1700000000,'os_build':'25G332','loaded_kext_uuid':UUID},
                sample_reader=lambda *args:p,monotonic=clock.monotonic,sleep=clock.sleep)
            samples=[d for d in map(json.loads,path.read_text().splitlines()) if d['record_type']=='sample']
            self.assertTrue(samples)
            for d in samples:
                self.assertEqual(d['group2_tx_trace'],p['group2_tx_trace'])
                self.assertEqual(d['completion_scalars'],p['completion_scalars'])
                self.assertEqual(d['completion_live_counters'],p['completion_live_counters'])
                self.assertEqual(d['completion_host_origin'],p['completion_host_origin'])
                self.assertTrue(d['raw_osdata'][b.GROUP2_PROPERTY]['retained'])
    def test_missing_is_unknown(self):
        p=point();self.assertEqual(p['group2_tx_trace']['snapshot_status'],'not_published');self.assertFalse(p['raw_osdata'][b.GROUP2_PROPERTY]['retained'])
    def test_short_rejected_and_not_saved_as_valid_raw(self):
        p=point(group2()[:-1]);self.assertEqual(p['group2_tx_trace']['snapshot_status'],'invalid');self.assertFalse(p['raw_osdata'][b.GROUP2_PROPERTY]['retained'])
    def test_oversize_rejected_and_bounded(self):
        p=point(group2()+b'\0');self.assertEqual(p['group2_tx_trace']['events'],[]);self.assertEqual(p['raw_osdata'][b.GROUP2_PROPERTY]['status'],'over_size_limit')
    def test_bad_magic_rejected(self):
        raw=bytearray(group2());raw[0]^=1;self.assertEqual(c._decode_group2_trace(bytes(raw))['events'],[])
    def test_unstable_cut_rejected(self):
        raw=bytearray(group2());struct.pack_into('<Q',raw,16,3);self.assertEqual(c._decode_group2_trace(bytes(raw))['events'],[])
    def test_unused_bytes_rejected(self):
        raw=bytearray(group2());raw[-1]=1;self.assertEqual(c._decode_group2_trace(bytes(raw))['events'],[])
    def test_local_completion_never_becomes_peer_ack(self):
        p=point(group2(13));self.assertEqual(p['group2_tx_trace']['events'][0]['status'],1);self.assertFalse(p['group2_tx_trace']['peer_ack_proven'])
if __name__=='__main__':unittest.main()
