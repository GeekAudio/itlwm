// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_unpublished_cleanup.hpp"
#include <assert.h>
#include <string.h>
using namespace NativeAwdlInit;

struct Fixture {
    bool quiesced = true, open = true, closeWorks = true;
    bool foreignClientOpen = true, lockOwned = true, listOwned = true;
    unsigned bpfCalls = 0;
    char trace[32]{};
    void record(char c) { const auto n = strlen(trace); assert(n+1<sizeof(trace));trace[n]=c; }
    bool quiesceInterest() { record('Q');return quiesced; }
    bool isOpen() { record('I');return open; }
    void close() { record('C');if(closeWorks)open=false; }
    void freeBpfResources() {
        record('B');assert(!open && quiesced && bpfCalls==0);
        lockOwned=false;listOwned=false;++bpfCalls;
    }
};

int main() {
    { // Successful init, not attached/started. Foreign clients remain open.
        Fixture f;CleanupFacts s{true,true,false};
        assert(prepareUnpublished(s,f)==Disposal::VirtualInterfaceBase);
        assert(strcmp(f.trace,"QICIB")==0 && s.bpfCleaned);
        assert(!f.lockOwned && !f.listOwned && f.foreignClientOpen);
        assert(prepareUnpublished(s,f)==Disposal::VirtualInterfaceBase);
        assert(f.bpfCalls==1); // Native helper leaves the freed lock pointer set.
    }
    { // Failed superclass init; no native private state may be freed.
        Fixture f;f.open=false;CleanupFacts s{false,false,false};
        assert(prepareUnpublished(s,f)==Disposal::ServiceBase);
        assert(strcmp(f.trace,"I")==0 && f.bpfCalls==0);
    }
    { // Parent ready, child allocation failed. PM cleanup is harmless/absent.
        Fixture f;f.open=false;CleanupFacts s{true,false,false};
        assert(prepareUnpublished(s,f)==Disposal::VirtualInterfaceBase);
        assert(strcmp(f.trace,"QI")==0 && f.bpfCalls==0);
    }
    { // Never pass an impossible child-without-parent state to native free.
        Fixture f;CleanupFacts s{false,true,false};
        assert(prepareUnpublished(s,f)==Disposal::Quarantine);
        assert(strlen(f.trace)==0 && f.open && f.bpfCalls==0);
    }
    { // PM callback quiescence failure preserves the owner and resources.
        Fixture f;f.quiesced=false;CleanupFacts s{true,true,false};
        assert(prepareUnpublished(s,f)==Disposal::Quarantine);
        assert(strcmp(f.trace,"Q")==0 && f.open && f.lockOwned);
    }
    { // A controller that still owns this open cannot outlive its client.
        Fixture f;f.closeWorks=false;CleanupFacts s{true,true,false};
        assert(prepareUnpublished(s,f)==Disposal::Quarantine);
        assert(strcmp(f.trace,"QICI")==0 && !s.bpfCleaned);
        assert(f.lockOwned && f.listOwned);
        f.closeWorks=true;
        assert(prepareUnpublished(s,f)==Disposal::VirtualInterfaceBase);
        assert(f.bpfCalls==1);
    }
    { // Previously cleaned state must not invoke the native lock free again.
        Fixture f;f.open=false;f.lockOwned=false;f.listOwned=false;
        CleanupFacts s{true,true,true};
        assert(prepareUnpublished(s,f)==Disposal::VirtualInterfaceBase);
        assert(f.bpfCalls==0 && strcmp(f.trace,"QI")==0);
    }
    return 0;
}
