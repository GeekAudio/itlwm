// SPDX-License-Identifier: GPL-2.0-only
// Exercise the production bridge, with fixture-only access to its private
// state. No diagnostic-only state mutation API is added to the driver.
#define main rx149ExistingRegressionMain
#include "awdl_native_rx149_data_input_test.cpp"
#undef main
#if defined(RX149_CAPTURE_BASELINE_SOURCE)
#include RX149_CAPTURE_BASELINE_SOURCE
#else
#include "../awdl_native_bsd_data_25G332.cpp"
#endif
#include <stdio.h>
#include <thread>

namespace D = NativeAwdlBSD::Rx149CaptureDiagnostics;

int ledgerConcurrency() {
    D::Ledger ledger;
    std::atomic<bool> go{false}, done{false};
    std::thread writers[D::kCapacity];
    for (unsigned i=0;i<D::kCapacity;++i) writers[i]=std::thread([&,i] {
        while (!go.load(std::memory_order_acquire)) {}
        D::Record record;
        for (auto &word:record.value) word=i+100;
        ledger.append(record);
    });
    std::thread reader([&] {
        do {
            D::Wire wire;
            ledger.copy(&wire);
            assert(wire.header[D::ReservedBegin]<=D::kCapacity);
            for (unsigned i=0;i<D::kCapacity;++i) {
                if (!(wire.header[D::CommittedMask]&(uint64_t{1}<<i))) continue;
                const auto marker=wire.records[i].value[0];
                assert(marker>=100&&marker<100+D::kCapacity);
                for (const auto word:wire.records[i].value) assert(word==marker);
            }
        } while (!done.load(std::memory_order_acquire));
    });
    go.store(true,std::memory_order_release);
    for (auto &writer:writers) writer.join();
    done.store(true,std::memory_order_release);reader.join();
    D::Wire first;ledger.copy(&first);
    assert(first.header[D::CompleteCut]==1);
    assert(first.header[D::CommittedMask]==255);
    for (unsigned i=0;i<4;++i) ledger.append(D::Record{});
    D::Wire full;ledger.copy(&full);
    assert(full.header[D::OverflowObserved]==1);
    assert(!memcmp(first.records,full.records,sizeof(first.records)));
    puts("ledger concurrency/immutable release publication/overflow passed");
    return 0;
}

int main(int argc,char **argv) {
    assert(argc>=2);
    if (!strcmp(argv[1],"ledger")) return ledgerConcurrency();
    const unsigned scenario=unsigned(atoi(argv[1]));
    FakeIf dev;
    if(scenario!=1) prepare(dev);
    auto lease=validLease();
    if(scenario!=1) publishRx149DataInputLease(lease);
    NativeP2PRx149DataInput::Permit permit{};
    assert(makePermit(lease,validDescriptor(),&permit));
    uint8_t bytes[4096]{};size_t length=0;
    makeFrame(bytes,sizeof(bytes),&length);
    bool protectedFrame=false;
    uint32_t generation=lease.epochs.power;
    unsigned expected=0;
    using namespace NativeAwdlBSD;
    switch(scenario) {
        case 0:break;
        case 1:expected=D::BridgeLock;break;
        case 2:protectedFrame=true;expected=D::Unprotected;break;
        case 3:length=2049;expected=D::LengthWithinLimit;break;
        case 4:permit.valid=false;expected=D::PermitValid;break;
        case 5:++generation;expected=D::PowerGenerationMatches;break;
        case 6:invalidateRx149DataInputFast();expected=D::FirstGateClear;break;
        case 7:fakeTime=101000;expected=D::PermitCurrent;break;
        case 8:NativeAwdlBSD::activeRx149LeaseValid=false;expected=D::ActiveLeaseValid;break;
        case 9:NativeAwdlBSD::activeRx149Version=0;expected=D::ActiveVersionNonzero;break;
        case 10:++NativeAwdlBSD::activeRx149Lease.ownerSerial;expected=D::LeaseIdentityMatches;break;
        case 11:++permit.ownerSerial;expected=D::PermitCurrent;break;
        case 12:NativeAwdlBSD::activeRx149Lease.runtimeEnabled=false;expected=D::ActiveLeaseCurrent;break;
        case 13:NativeAwdlBSD::interfaceIncarnation=0;expected=D::InterfaceIncarnationNonzero;break;
        case 14:NativeAwdlBSD::interface=nullptr;expected=D::InterfacePresent;break;
        case 15:NativeAwdlBSD::closing=true;expected=D::NotClosing;break;
        case 16:NativeAwdlBSD::detached=true;expected=D::NotDetached;break;
        case 17:NativeAwdlBSD::radio=false;expected=D::RadioReady;break;
        case 18:NativeAwdlBSD::closingRequested=1;expected=D::ClosingNotRequested;break;
        case 19:++NativeAwdlBSD::radioGeneration;expected=D::RadioGenerationMatches;break;
        case 20:NativeAwdlBSD::counters[Attached]=0;expected=D::Attached;break;
        case 21:NativeAwdlBSD::rx149ReceiptSequence=UINT64_MAX;expected=D::SequenceAvailable;break;
        case 22:NativeAwdlBSD::rx149ReceiptContentRevision=UINT64_MAX;expected=D::RevisionAvailable;break;
        case 23:NativeAwdlBSD::rx.count=QueueDepth;expected=D::QueueSpaceAvailable;break;
        case 24:break; // capture first, then independently model terminal fault
        case 25:bytes[0]=0x80;break; // a non-candidate produces no row
        case 26:protectedFrame=true;permit.valid=false;expected=D::Unprotected;break;
        case 27:invalidateRx149DataInputFast();fakeTime=101000;expected=D::FirstGateClear;break;
        case 28:break; // ledger saturation cannot change queue/return behavior
        default:return 2;
    }
    const unsigned attempts=scenario==28?12:1;
    std::vector<unsigned> results;
    for(unsigned i=0;i<attempts;++i) {
        results.push_back(unsigned(captureRx149Data(
            bytes,length,protectedFrame,lease,permit,generation)));
    }
    if(scenario==24) {
        invalidateRx149DataInputFast();
        revokeRx149DataInput();
        assert(rx149DataInputBlocked());
    }
#if !defined(RX149_CAPTURE_BASELINE_SOURCE)
    D::Wire wire;captureRx149Diagnostics(&wire);
    const unsigned retained=scenario==25?0:(attempts>D::kCapacity?D::kCapacity:attempts);
    assert(wire.header[D::ReservedEnd]==retained&&wire.header[D::CompleteCut]==1);
    assert(wire.header[D::OverflowObserved]==(attempts>D::kCapacity));
    if(retained) {
        const auto &v=wire.records[0].value;
        assert(v[D::FailureCheck]==expected);
        assert(v[D::Outcome]==results[0]);
        assert(v[D::SequenceControl]==(17u<<4)&&v[D::HeaderPresentMask]==3);
        assert(v[D::PermitOwner]==lease.ownerSerial||scenario==11);
        if(expected) {
            const auto bit=uint64_t{1}<<(expected-1u);
            assert(v[D::EvaluatedMask]&bit);
            assert(!(v[D::PassedMask]&bit));
        }
        if(scenario==6||scenario==27) {
            assert(Rx149InputGateState::blocked(v[D::FirstGateWord]));
            assert(!(v[D::EvaluatedMask]&(uint64_t{1}<<(D::PermitCurrent-1u))));
            assert(!(v[D::EvaluatedMask]&(uint64_t{1}<<(D::AuthorityGateClear-1u))));
        }
        if(scenario==24) {
            assert(!v[D::FailureCheck]);
            assert(!Rx149InputGateState::blocked(v[D::FirstGateWord]));
            assert(!Rx149InputGateState::blocked(v[D::AuthorityGateWord]));
            assert(v[D::ActiveOwner]==lease.ownerSerial);
            assert(v[D::AssignedReceiptSequence]==1);
        }
    }
    if(argc==3) {
        FILE *file=fopen(argv[2],"wb");assert(file);
        assert(fwrite(&wire,1,sizeof(wire),file)==sizeof(wire));fclose(file);
    }
#else
    (void)expected;
#endif
    // The exact same output is compared against the original production
    // function: return values, every legacy counter, receipt, and queue state.
    const auto state=snapshot();
    for(auto result:results) printf("%u,",result);
    printf("|");
    for(auto counter:state.value) printf("%llu,",(unsigned long long)counter);
    const auto &receipt=state.rx149Input;
    const uint64_t receiptValues[]={receipt.schemaVersion,receipt.disposition,
        receipt.sequence,receipt.contentRevision,receipt.ownerSerial,
        receipt.interfaceIncarnation,receipt.contextGeneration,
        receipt.powerGeneration,receipt.stationGeneration,receipt.rocGeneration,
        receipt.captureUs,receipt.inputUs,receipt.deadlineUs,receipt.ieeeChannel,
        receipt.macIndexPresent,receipt.macIndex,receipt.macPhyDecodeMode,
        receipt.originalRxStatus,receipt.mpduLength,receipt.decodedIpv6Count,
        receipt.ifnetInputResultPresent,uint64_t(int64_t(receipt.ifnetInputResult))};
    printf("|");
    for(auto value:receiptValues)printf("%llu,",(unsigned long long)value);
    printf("|%zu,%zu,%zu\n",NativeAwdlBSD::rx.head,
           NativeAwdlBSD::rx.tail,NativeAwdlBSD::rx.count);
    return 0;
}
