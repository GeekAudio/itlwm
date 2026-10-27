#!/usr/bin/env python3
"""Real production submit/completion code with host DMA/KPI shims, not RF."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('action_hal',Path(__file__).with_name('test_iwx_p2p_action_hal.py'))
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
extra=r'''
#include "native/awdl_data_frame.hpp"
namespace NativeAwdlBSD {
static unsigned finished=0;static uint64_t lastToken=0;static bool succeeded=false;
void completed(uint64_t token,bool ok){++finished;lastToken=token;succeeded=ok;}
void submitted(uint64_t,int){}
}
'''
cases=r'''
    {
        Fixture f;uint8_t ipv6[40]{};ipv6[0]=0x60;
        NativeAwdlData::EncodeInput in{};
        memcpy(in.sourceAddress,kSource,6);in.destinationAddress[0]=0x33;in.destinationAddress[1]=0x33;in.destinationAddress[5]=1;
        in.wifiSequenceNumber=1;in.ipv6Packet=ipv6;in.ipv6Length=40;
        uint8_t raw[200];size_t n=0;
        assert(NativeAwdlData::encodeIpv6DataMpdu(&in,raw,sizeof(raw),&n)==NativeAwdlData::Status::Ok);
        auto frame=new mbuf(raw,n);const unsigned id=frame->id;
        assert(iwx_tahoe_p2p_action_tx_submit(&f.owner,&f.owner.com,&f.lease,&f.context,55,true,false,frame,4242)==0);
        assert(f.context.nativeDataToken==4242&&f.ring()->data[0].type==IEEE80211_FC0_TYPE_DATA);
        assert(f.ring()->queued==1&&gFreedById[id]==0);
        iwx_rx_packet packet{};packet.rawIndex=0;
        makeResponse(packet,12,0x10,1,uint16_t(n),0x0008);
        assert(dispatch(f,packet));assert(gFreedById[id]==1&&f.ring()->queued==0);
        assert(NativeAwdlBSD::finished==1&&NativeAwdlBSD::lastToken==4242&&NativeAwdlBSD::succeeded);
        assert(!f.context.nativeDataToken);
        const auto prior=NativeAwdlBSD::finished;
        dispatch(f,packet);assert(NativeAwdlBSD::finished==prior);
    }
    {
        Fixture f;auto frame=makeFrame();const auto before=gDoorbells;
        // An Action frame cannot masquerade as an IPv6 data token.
        assert(iwx_tahoe_p2p_action_tx_submit(&f.owner,&f.owner.com,&f.lease,&f.context,55,true,false,frame,4243)==EINVAL);
        assert(gDoorbells==before&&!f.ring()->queued);
    }
'''
def main():
    with tempfile.TemporaryDirectory(prefix='native052-tx-hal-') as temp:
        d=Path(temp);cpp=d/'test.cpp';binary=d/'test'
        cpp.write_text(base.SHIM+'\n'+extra+'\n'+base.production_helpers+'\n'+base.production_generic_helpers+
            '\n'+base.production_functions+'\n'+base.BODY.replace('int main() {','int main() {\n'+cases,1))
        subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror','-Wno-unused-function',
            '-fsanitize=address,undefined','-fno-omit-frame-pointer','-DITL_NATIVE_AWDL_RESIDENT_25G332=1',
            '-I',str(ROOT),str(cpp),*map(lambda n:str(ROOT/'native'/n),
            ['p2p_action_tx.cpp','awdl_action_frame.cpp','awdl_action_encode.cpp','awdl_mif_encode.cpp','awdl_data_frame.cpp']),
            '-o',str(binary)],check=True)
        subprocess.run([str(binary)],check=True)
        report={'production_hal_under_host_shims_passed':True,'native_data_submit_completion_and_duplicate_rejection':True,
            'action_frame_cannot_claim_data_token':True,'asan_ubsan_passed':True,'firmware_runtime_tested':False,'rf_tested':False}
        p=ROOT.parent/'IntelWirelessNative/research/test052-data-hal-host-private.json';p.write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report))
if __name__=='__main__':main()
