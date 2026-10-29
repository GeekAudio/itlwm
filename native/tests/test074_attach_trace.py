#!/usr/bin/env python3
"""Compile and exercise the exact Test074 production BSD attach function.

The harness extracts attach() from awdl_native_bsd_data_25G332.cpp and supplies
small KPI stubs. It does not reimplement the attach control flow.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "native/awdl_native_bsd_data_25G332.cpp"


def function_body(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0:
        raise RuntimeError(f"missing production function: {signature}")
    opening = source.find("{", start + len(signature))
    if opening < 0:
        raise RuntimeError("missing production function body")
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise RuntimeError("unterminated production function")


HARNESS = r'''#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include "native/awdl_bsd_attach_trace.hpp"

namespace NativeAwdlBSD {
struct FakeIf { uint8_t lladdr[6]{}; unsigned refs=0; };
using ifnet_t=FakeIf *;
struct IOSimpleLock {};
using IOInterruptState=unsigned;
struct iff_filter {
    const char *iff_name=nullptr;
    unsigned iff_protocol=0;
    int (*iff_output)(void *,ifnet_t,unsigned,void **)=nullptr;
    void (*iff_detached)(void *,ifnet_t)=nullptr;
};
using interface_filter_t=iff_filter *;
enum Counter { Attached, Ipv6ConfigResult, Ipv6Configured, OffloadCapabilities };
enum { IFF_UP=1, IFF_RUNNING=0x40, IFCAP_HWCSUM=1, IFCAP_TSO=2,
       IFCAP_CSUM_PARTIAL=4, IFCAP_CSUM_ZERO_INVERT=8 };

static AttachTraceLedger attachTrace;
static IOSimpleLock lockStorage;
static IOSimpleLock *lock=nullptr;
static uint32_t attachClaimed=0, closingRequested=0;
static FakeIf fakeIf{};
static ifnet_t interface=nullptr;
static uint8_t own[6]{};
static bool closing=false,detached=false;
static uint64_t counters[4]{};
static iff_filter installed{};
static interface_filter_t filter=nullptr;
static int lladdrResult=0,referenceResult=0,filterResult=0;
static int offloadResult=0,mtuResult=0,flagsResult=0,ipv6Result=0;
static bool allocationFails=false,hasLinkLocalResult=false,detachDuringFilter=false;
static unsigned lladdrCalls=0,referenceCalls=0,filterCalls=0;
static unsigned offloadCalls=0,mtuCalls=0,flagsCalls=0,ipv6Calls=0,linkLocalCalls=0;
static unsigned releaseCalls=0;

static IOSimpleLock *bridgeLock(){return __atomic_load_n(&lock,__ATOMIC_ACQUIRE);}
static IOInterruptState IOSimpleLockLockDisableInterrupt(IOSimpleLock *){return 0;}
static void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock *,IOInterruptState){}
static IOSimpleLock *IOSimpleLockAlloc(){return allocationFails?nullptr:&lockStorage;}
static int ifnet_lladdr_copy_bytes(ifnet_t dev,void *out,size_t length){
    ++lladdrCalls;if(lladdrResult)return lladdrResult;
    if(!dev||length!=sizeof(dev->lladdr))return EINVAL;
    memcpy(out,dev->lladdr,length);return 0;
}
static int ifnet_reference(ifnet_t dev){
    ++referenceCalls;if(referenceResult)return referenceResult;
    ++dev->refs;return 0;
}
static void ifnet_release(ifnet_t dev){assert(dev->refs);--dev->refs;++releaseCalls;}
static int output(void *,ifnet_t,unsigned,void **){return 0;}
static void detachedCallback(void *,ifnet_t){}
static int iflt_attach(ifnet_t,const iff_filter *spec,interface_filter_t *out){
    ++filterCalls;installed=*spec;
    if(filterResult)return filterResult;
    filter=&installed;*out=filter;
    if(detachDuringFilter)detached=true;
    return 0;
}
static int ifnet_set_offload(ifnet_t,unsigned){++offloadCalls;return offloadResult;}
static int ifnet_set_mtu(ifnet_t,unsigned){++mtuCalls;return mtuResult;}
static int ifnet_set_flags(ifnet_t,unsigned,unsigned){++flagsCalls;return flagsResult;}
static int ifnet_set_capabilities_enabled(ifnet_t,unsigned,unsigned){return 0;}
static int ifnet_set_capabilities_supported(ifnet_t,unsigned,unsigned){return 0;}
static unsigned ifnet_capabilities_enabled(ifnet_t){return 0x400;}
static bool hasLinkLocal(ifnet_t){++linkLocalCalls;return hasLinkLocalResult;}
static int configureLinkLocal(ifnet_t,const uint8_t[6]){++ipv6Calls;return ipv6Result;}
static void set(Counter counter,uint64_t value){counters[counter]=value;}

// PRODUCTION_ATTACH_INSERTION_POINT

} // namespace NativeAwdlBSD

int main(int argc,char **argv){
    using namespace NativeAwdlBSD;
    assert(argc==2);
    const char *scenario=argv[1];
    if(!strcmp(scenario,"lookup-fail")){
        attachTrace.noteResidentLookupResult(ENOENT);
        const auto s=attachTrace.snapshot();
        assert(s.complete&&s.attempted&&s.attemptSerial==1);
        assert(s.lookupResultPresent&&s.lookupResultDomain==AttachResultDomainRawKPI);
        assert(static_cast<int64_t>(s.lookupResultValue)==ENOENT);
        assert(s.done&&s.failed&&!s.producerActive&&!s.bridgeEntered);
        assert(s.failurePresent&&s.failureStage==AttachStageResidentLookup);
        assert(s.failureResultPresent&&s.failureResultDomain==AttachResultDomainRawKPI);
        return 0;
    }

    attachTrace.noteResidentLookupResult(0);
    const uint8_t expectedMac[6]={0x02,0,0,0,0,0x42};
    memcpy(fakeIf.lladdr,expectedMac,sizeof(expectedMac));
    bool invoke=true;
    if(!strcmp(scenario,"null-ifnet")) invoke=false;
    else if(!strcmp(scenario,"read-error")) lladdrResult=EIO;
    else if(!strcmp(scenario,"address-mismatch")) fakeIf.lladdr[5]=0x43;
    else if(!strcmp(scenario,"claim-fail")) attachClaimed=1;
    else if(!strcmp(scenario,"alloc-fail")) allocationFails=true;
    else if(!strcmp(scenario,"reference-error")) referenceResult=EBUSY;
    else if(!strcmp(scenario,"can-attach-fail")) closing=true;
    else if(!strcmp(scenario,"filter-error")) filterResult=EIO;
    else if(!strcmp(scenario,"offload-error")) offloadResult=EIO;
    else if(!strcmp(scenario,"mtu-error")) mtuResult=EINVAL;
    else if(!strcmp(scenario,"flags-error")) flagsResult=EIO;
    else if(!strcmp(scenario,"ipv6-error")) ipv6Result=EADDRNOTAVAIL;
    else if(!strcmp(scenario,"final-ready-fail")) detachDuringFilter=true;
    else if(strcmp(scenario,"success")) assert(!"unknown scenario");

    const bool result=attach(invoke?&fakeIf:nullptr,expectedMac);
    const auto s=attachTrace.snapshot();
    assert(s.complete&&s.versionBegin==s.versionEnd&&!(s.versionEnd&1));
    assert(s.attempted&&s.attemptSerial==1&&s.lookupResultPresent);
    assert(s.lookupResultDomain==AttachResultDomainRawKPI);
    assert(static_cast<int64_t>(s.lookupResultValue)==0);
    assert(s.done&&!s.producerActive);

    AttachTraceLedger stickyTrace;
    stickyTrace.noteResidentLookupResult(0);
    stickyTrace.beginAttempt();
    stickyTrace.recordSetOffload(EIO);
    stickyTrace.recordSetMtu(EPERM);
    stickyTrace.finishFailure();
    const auto sticky=stickyTrace.snapshot();
    assert(sticky.complete&&sticky.done&&sticky.failed);
    assert(sticky.setOffloadResultPresent&&sticky.setMtuResultPresent);
    assert(static_cast<int64_t>(sticky.setOffloadResultValue)==EIO);
    assert(static_cast<int64_t>(sticky.setMtuResultValue)==EPERM);
    assert(sticky.failureStage==AttachStageSetOffload);
    assert(sticky.failureResultPresent&&
           static_cast<int64_t>(sticky.failureResultValue)==EIO);

    if(!strcmp(scenario,"success")){
        assert(result&&!s.failed&&!s.failurePresent&&s.bridgeEntered);
        assert(s.stage==AttachStageTerminal&&s.finalReadyResultPresent&&s.finalReadyResultValue==1);
        assert(s.liveAddressReadResultPresent&&s.liveAddressReadResultDomain==AttachResultDomainRawKPI);
        assert(s.liveAddressMatchPresent&&s.liveAddressMatch);
        assert(s.claimAttempted&&s.claimSucceeded&&s.lockAllocationPresent&&s.lockAllocated);
        assert(s.ifnetReferenceResultPresent&&s.ifnetReferenceResultValue==0);
        assert(s.canAttachResultPresent&&s.canAttachResultDomain==AttachResultDomainBoolean&&s.interfaceBound);
        assert(s.ifFilterAttachResultPresent&&s.ifFilterAttachResultValue==0);
        assert(s.setOffloadResultPresent&&s.setMtuResultPresent&&s.setFlagsResultPresent);
        assert(s.ipv6ResultPresent&&s.ipv6HasLinkLocalPresent);
        assert(lladdrCalls==1&&referenceCalls==1&&filterCalls==1);
        assert(offloadCalls==1&&mtuCalls==1&&flagsCalls==1&&ipv6Calls==1&&linkLocalCalls==1);
        assert(counters[Attached]==1);
    }else{
        assert(!result&&s.failed&&s.failurePresent);
        assert(s.stage==AttachStageTerminal);
        if(!strcmp(scenario,"null-ifnet")){
            assert(!s.bridgeEntered&&s.inputGuardPresent&&s.inputGuardCode==AttachInputGuardNullIfnet);
            assert(s.failureStage==AttachStageEntryGuard&&s.failureResultPresent&&
                   s.failureResultDomain==AttachResultDomainBoolean&&
                   s.failureResultValue==0&&lladdrCalls==0);
        }else if(!strcmp(scenario,"read-error")){
            assert(s.failureStage==AttachStageLiveAddressRead&&s.liveAddressReadResultPresent);
            assert(static_cast<int64_t>(s.liveAddressReadResultValue)==EIO);
            assert(s.failureResultPresent&&static_cast<int64_t>(s.failureResultValue)==EIO);
            assert(!s.liveAddressMatchPresent&&lladdrCalls==1);
        }else if(!strcmp(scenario,"address-mismatch")){
            assert(s.failureStage==AttachStageLiveAddressMatch&&s.liveAddressMatchPresent&&!s.liveAddressMatch);
            assert(s.failureResultPresent&&s.failureResultDomain==AttachResultDomainBoolean);
            assert(!s.claimAttempted);
        }else if(!strcmp(scenario,"claim-fail")){
            assert(s.failureStage==AttachStageClaim&&s.claimAttempted&&!s.claimSucceeded);
            assert(s.failureResultDomain==AttachResultDomainBoolean&&!s.lockAllocationPresent);
        }else if(!strcmp(scenario,"alloc-fail")){
            assert(s.failureStage==AttachStageLockAllocation&&s.lockAllocationPresent&&!s.lockAllocated);
            assert(!s.ifnetReferenceResultPresent);
        }else if(!strcmp(scenario,"reference-error")){
            assert(s.failureStage==AttachStageIfnetReference&&s.ifnetReferenceResultPresent);
            assert(static_cast<int64_t>(s.ifnetReferenceResultValue)==EBUSY);
        }else if(!strcmp(scenario,"can-attach-fail")){
            assert(s.failureStage==AttachStageCanAttach&&s.canAttachResultPresent&&!s.canAttachResultValue);
            assert(s.canAttachResultDomain==AttachResultDomainBoolean&&!s.interfaceBound&&releaseCalls==1);
        }else if(!strcmp(scenario,"filter-error")){
            assert(s.failureStage==AttachStageFilterAttach&&s.ifFilterAttachResultPresent);
            assert(static_cast<int64_t>(s.ifFilterAttachResultValue)==EIO);
            assert(!interface&&releaseCalls==1);
        }else if(!strcmp(scenario,"offload-error")){
            assert(s.failureStage==AttachStageSetOffload&&s.setOffloadResultPresent);
            assert(static_cast<int64_t>(s.setOffloadResultValue)==EIO);
            assert(mtuCalls==0&&flagsCalls==0);
        }else if(!strcmp(scenario,"mtu-error")){
            assert(s.failureStage==AttachStageSetMtu&&s.setMtuResultPresent);
            assert(static_cast<int64_t>(s.setMtuResultValue)==EINVAL&&flagsCalls==0);
        }else if(!strcmp(scenario,"flags-error")){
            assert(s.failureStage==AttachStageSetFlags&&s.setFlagsResultPresent);
            assert(static_cast<int64_t>(s.setFlagsResultValue)==EIO&&ipv6Calls==0);
        }else if(!strcmp(scenario,"ipv6-error")){
            assert(s.failureStage==AttachStageIPv6&&s.ipv6ResultPresent&&s.ipv6HasLinkLocalPresent);
            assert(static_cast<int64_t>(s.ipv6ResultValue)==EADDRNOTAVAIL);
        }else if(!strcmp(scenario,"final-ready-fail")){
            assert(s.failureStage==AttachStageFinalReady&&s.finalReadyResultPresent&&!s.finalReadyResultValue);
            assert(s.failureResultDomain==AttachResultDomainBoolean);
        }
    }

    return 0;
}
'''


def main() -> int:
    source = SOURCE.read_text()
    production = function_body(source, "bool attach(ifnet_t dev,const uint8_t mac[6])")
    insertion = "// PRODUCTION_ATTACH_INSERTION_POINT\n"
    if insertion not in HARNESS:
        raise RuntimeError("harness insertion marker missing")
    harness = HARNESS.replace(insertion, production + "\n", 1)
    compiler = os.environ.get("CXX", "clang++")
    scenarios = (
        "lookup-fail", "success", "null-ifnet", "read-error", "address-mismatch",
        "claim-fail", "alloc-fail", "reference-error", "can-attach-fail",
        "filter-error", "offload-error", "mtu-error", "flags-error",
        "ipv6-error", "final-ready-fail",
    )
    with tempfile.TemporaryDirectory(prefix="test074-attach-trace-") as temp:
        temp_dir = pathlib.Path(temp)
        cpp = temp_dir / "test074_attach_trace_harness.cpp"
        binary = temp_dir / "test074_attach_trace_harness"
        cpp.write_text(harness)
        subprocess.run([
            compiler, "-std=c++14", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            "-I", str(ROOT), str(cpp), "-o", str(binary),
        ], check=True)
        for scenario in scenarios:
            subprocess.run([str(binary), scenario], check=True)
    print(f"PASS: extracted production attach() and lookup trace across {len(scenarios)} scenarios")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
