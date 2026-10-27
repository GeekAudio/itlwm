#!/usr/bin/env python3
"""Production BSD bridge under host KPI shims; not a kernel/RF test."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
ART=ROOT.parent/'IntelWirelessNative/research'
def run(args):
    p=subprocess.run(args,cwd=ROOT,text=True,capture_output=True)
    if p.returncode:raise RuntimeError(p.stdout+p.stderr)
    return p.stdout

def main():
    with tempfile.TemporaryDirectory(prefix='native-data052-') as temp:
        d=Path(temp)
        for header in ('IOKit/IOLib.h','IOKit/IOLocks.h','kern/clock.h','net/kpi_interfacefilter.h',
                       'net/if.h','sys/socket.h','sys/mbuf.h','net/kpi_interface.h','sys/kpi_socket.h','netinet/in.h','netinet6/in6_var.h'):
            p=d/header;p.parent.mkdir(parents=True,exist_ok=True)
            p.write_text('#include "awdl_bsd_bridge_shim.hpp"\n')
        flags=['xcrun','clang++','-std=c++14','-O1','-g','-Wall','-Wextra','-Werror',
            '-fsanitize=address,undefined','-fno-omit-frame-pointer','-DITL_NATIVE_AWDL_RESIDENT_25G332=1',
            '-I'+str(d),'-Inative/tests','-Inative']
        run(flags+['native/awdl_native_bsd_data_25G332.cpp','native/awdl_data_frame.cpp',
            'native/tests/awdl_bsd_bridge_shim_test.cpp','-o',str(d/'test')])
        for case in range(1,15):run([str(d/'test'),str(case)])
        report={'host_production_bridge_cases':14,'asan_ubsan_passed':True,
            'packet_ownership_balanced':True,'stale_generation_fenced':True,
            'pending_completion_or_filter_detach_prevents_release':True,
            'native_kernel_tested':False,'firmware_tested':False,'rf_tested':False,
            'scope':'Production BSD bridge under host KPI shims; real macOS/firmware/peer delivery untested.'}
        (ART/'test052-bsd-data-host-private.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report))
if __name__=='__main__':main()
