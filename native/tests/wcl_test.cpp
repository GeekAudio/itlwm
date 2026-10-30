// SPDX-License-Identifier: GPL-2.0-only
#include "../wcl_backend.hpp"
#include <assert.h>
#include <string.h>
#include <vector>

using namespace NativeWifi;
namespace {
struct Emitted { uint32_t kind; std::vector<uint8_t> body; };
struct Fixture {
    Backend backend;
    unsigned scans {}, joins {}, leaves {}, cancels {};
    unsigned busyJoinResponses {};
    unsigned busyScanResponses {};
    uint32_t generation {};
    bool privateReady {true};
    Status joinStatus {Status::Ok};
    Status scanStatus {Status::Ok};
    uint8_t lastScanChannels[32] {}, lastScanSsid[32] {}, lastScanSsidLength {};
    uint8_t lastJoinBssid[6] {}, lastJoinSsid[32] {}, lastJoinPmk[32] {};
    uint8_t lastJoinSsidLength {}, lastJoinPasswordLength {};
    std::vector<Emitted> messages;
    static Status scan(void *x, const ScanPlan &p) {
        auto f=static_cast<Fixture *>(x); ++f->scans; f->generation=p.identifier;
        memcpy(f->lastScanChannels,p.channels,sizeof(f->lastScanChannels));
        memcpy(f->lastScanSsid,p.ssid,sizeof(f->lastScanSsid));
        f->lastScanSsidLength=p.ssidLength;
        if (f->busyScanResponses) { --f->busyScanResponses; return Status::Busy; }
        return f->scanStatus;
    }
    static Status join(void *x, const JoinPlan &p) {
        auto f=static_cast<Fixture *>(x); ++f->joins;
        memcpy(f->lastJoinBssid,p.bssid,sizeof(f->lastJoinBssid));
        memcpy(f->lastJoinSsid,p.ssid,sizeof(f->lastJoinSsid));
        memcpy(f->lastJoinPmk,p.pmk,sizeof(f->lastJoinPmk));
        f->lastJoinSsidLength=p.ssidLength;
        f->lastJoinPasswordLength=p.passwordLength;
        if (f->busyJoinResponses) { --f->busyJoinResponses; return Status::Busy; }
        return f->joinStatus;
    }
    static Status cancel(void *x) { ++static_cast<Fixture *>(x)->cancels; return Status::Ok; }
    static void leave(void *x) { ++static_cast<Fixture *>(x)->leaves; }
    static bool privacy(void *x) { return static_cast<Fixture *>(x)->privateReady; }
    static void emit(void *x, uint32_t k, const void *p, size_t n) {
        auto f = static_cast<Fixture *>(x);
        if (k == Link) {
            assert(p && n == 16);
            auto bytes = static_cast<const uint8_t *>(p);
            assert(bytes[6] <= 1 && bytes[7] == 0);
            if (bytes[6]) {
                // The native link-up consumer immediately asks for GET433.
                uint8_t bss[BeaconPrefixSize + MaximumIEBytes] {};
                assert(f->backend.copyBss(bss, sizeof(bss)) == Status::Ok);
                assert(!memcmp(bss + 0x29, bytes, 6));
            }
        }
        Emitted e { k, {} };
        if (n) e.body.assign(static_cast<const uint8_t *>(p), static_cast<const uint8_t *>(p) + n);
        f->messages.push_back(e);
    }
    Fixture() { backend.initialize({this, scan, join, leave, emit, privacy, cancel}); backend.driverState(true); messages.clear(); }
    unsigned count(uint32_t k) const { unsigned n = 0; for (auto &e : messages) if (e.kind == k) ++n; return n; }
};
std::vector<uint8_t> scanWire() {
    std::vector<uint8_t> p(ScanWireSize);
    write32(p.data(), 17); p[4] = 1; write32(p.data() + 0x40, 1);
    write32(p.data() + 0x54, 1); write32(p.data() + 0x58, 1);
    write32(p.data() + 0x5c, 6); write32(p.data() + 0x60, 0xa);
    return p;
}
std::vector<uint8_t> joinWire() {
    std::vector<uint8_t> p(JoinWireSize);
    write16(p.data() + 0xc, 2); write32(p.data() + 0x10, 1);
    write32(p.data() + 0x1c, 1); p[0x20] = 'x';
    write32(p.data() + 0x214, 1); p[0x21c] = 2; p[0x221] = 1;
    return p;
}
}
int main() {
    ScanPlan s {};
    auto scan = scanWire();
    assert(decodeScan(scan.data(), scan.size(), s) == DecodeResult::Ok);
    assert(s.privateAddressRequired && selectedChannel(s, 6) && !selectedChannel(s, 7));
    for (size_t n = 0; n < scan.size(); ++n)
        assert(decodeScan(scan.data(), n, s) == DecodeResult::Malformed);
    for (auto home : {0U,40U,110U}) for (auto active : {0U,20U,40U}) {
        auto canonical=scan;
        write32(canonical.data()+8,home);write32(canonical.data()+0x48,active);
        write32(canonical.data()+0x4c,110);write32(canonical.data()+0x50,45);
        assert(decodeScan(canonical.data(),canonical.size(),s)==DecodeResult::Ok);
        Fixture f; assert(f.backend.scanRequest(canonical.data(),canonical.size())==Status::Ok && f.scans==1);
    }
    for (auto offset : {8U,0x48U,0x4cU,0x50U}) {
        auto custom=scan;write32(custom.data()+offset,37);
        uint32_t field=0;
        assert(decodeScan(custom.data(),custom.size(),s,&field)==DecodeResult::Unsupported && field==offset);
        Fixture f;assert(f.backend.scanRequest(custom.data(),custom.size())==Status::Unsupported && !f.scans);
    }
    auto altered = scan;
    write32(altered.data() + 0x54, 401);
    assert(decodeScan(altered.data(), altered.size(), s) == DecodeResult::Malformed);
    altered = scan; write32(altered.data() + 0x48, 0xffffffffU);
    assert(decodeScan(altered.data(), altered.size(), s) == DecodeResult::Unsupported);
    altered = scan; write32(altered.data() + 0x60, 0x2002);
    assert(decodeScan(altered.data(), altered.size(), s) == DecodeResult::Unsupported);
    auto join = joinWire(); JoinPlan j {};
    assert(decodeJoin(join.data(), join.size(), j) == DecodeResult::Ok && !j.secured);
    for (size_t n = 0; n < join.size(); ++n)
        assert(decodeJoin(join.data(), n, j) == DecodeResult::Malformed);
    altered = join; write32(altered.data() + 0x14, 0x1000);
    assert(decodeJoin(altered.data(), altered.size(), j) == DecodeResult::Unsupported);
    altered = join; altered[0x50] = 1;
    assert(decodeJoin(altered.data(), altered.size(), j) == DecodeResult::Unsupported);
    static const uint8_t rsn[] = {48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,2,0,0};
    auto secured = join; write32(secured.data() + 0x14, 8);
    write32(secured.data() + 0x44, 32); write32(secured.data() + 0x48, 6);
    write16(secured.data() + 0xd4, sizeof(rsn)); memcpy(secured.data() + 0xd6, rsn, sizeof(rsn));
    assert(decodeJoin(secured.data(), secured.size(), j) == DecodeResult::Ok && j.secured);
    auto pwd = secured; write32(pwd.data()+0x48,10); write32(pwd.data()+0x44,8);
    memset(pwd.data()+0x50,'a',8);
    assert(decodeJoin(pwd.data(),pwd.size(),j)==DecodeResult::Ok && j.derivePmk && j.passwordLength==8);
    pwd[0x52]=0; assert(decodeJoin(pwd.data(),pwd.size(),j)==DecodeResult::Unsupported);
    pwd=secured;write32(pwd.data()+0x48,10);write32(pwd.data()+0x44,64);memset(pwd.data()+0x50,'a',64);
    assert(decodeJoin(pwd.data(),pwd.size(),j)==DecodeResult::Ok && j.passwordLength==64);
    pwd[0x6f]='x'; assert(decodeJoin(pwd.data(),pwd.size(),j)==DecodeResult::Unsupported);
    auto flags=secured;write32(flags.data()+0x1e4,2);
    assert(decodeJoin(flags.data(),flags.size(),j)==DecodeResult::Ok);
    for (auto offset : {0x18U,0x1e0U,0x1e4U,0x1e8U,0x1ecU}) {
        flags=secured;write32(flags.data()+offset,1);uint32_t rejected=0;
        assert(decodeJoin(flags.data(),flags.size(),j,&rejected)==DecodeResult::Unsupported && rejected==offset);
    }
    secured[0xd6 + 20] = 0x40;
    assert(decodeJoin(secured.data(), secured.size(), j) == DecodeResult::Unsupported);
    uint8_t malformed[] = {0,2,1}; assert(!validateIEs(malformed, sizeof(malformed)));
    {
        Fixture f;
        uint8_t bssid[6] = {2,0,0,0,0,1};
        uint8_t frame[38] = {0x80}, ies[2] = {0,0}, ssid[1] = {'x'};
        Beacon b {ssid,bssid,ies,frame,1,2,sizeof(frame),0x1006,100,0,6,-45,-95,50};
        assert(f.backend.last237Status() == 0xffffffffU);
        f.backend.observeBeacon(b); // Real idle RX is not a scan-result emit.
        assert(f.backend.realBeacons()==1 && !f.backend.pendingScanBeacons());
        assert(!f.backend.event201EmitCalls() && !f.backend.event237EmitCalls());
        assert(f.backend.scanRequest(scan.data(),scan.size())==Status::Ok);
        f.backend.observeBeacon(b);
        assert(f.backend.realBeacons()==2 && f.backend.pendingScanBeacons()==1);
        assert(f.backend.event201EmitCalls()==1 && f.count(ScanBeacon)==1);
        const auto payload=f.messages.back().body;
        assert(payload.size()==BeaconPrefixSize+sizeof(ies) && read32(payload.data())==sizeof(ies));
        assert(!memcmp(payload.data()+BeaconPrefixSize,ies,sizeof(ies)));
        Beacon invalid=b;invalid.ieLength=MaximumIEBytes+1;
        f.backend.observeBeacon(invalid);
        assert(f.backend.realBeacons()==2 && f.backend.pendingScanBeacons()==1 && f.backend.event201EmitCalls()==1);
        f.backend.observeScanComplete(f.generation,1);
        assert(f.backend.event237EmitCalls()==1 && f.backend.last237Status()==0);
        f.backend.observeScanComplete(f.generation,1); // No duplicate completion.
        assert(f.backend.event237EmitCalls()==1);
        f.backend.stop();f.backend.observeBeacon(b);f.backend.observeScanComplete(f.generation,1);
        assert(f.backend.realBeacons()==2 && f.backend.event201EmitCalls()==1 && f.backend.event237EmitCalls()==1);
    }
    {
        Fixture f;
        // An absent callback does not count as an emitted201/237 notification.
        f.backend.initialize({&f,Fixture::scan,Fixture::join,Fixture::leave,nullptr,Fixture::privacy,Fixture::cancel});
        assert(f.backend.scanRequest(scan.data(),scan.size())==Status::Ok);
        uint8_t bssid[6]={2,0,0,0,0,1},ssid[1]={'x'},ies[2]={0,0},frame[38]={0x80};
        Beacon b {ssid,bssid,ies,frame,1,2,sizeof(frame),0x1006,100,0,6,-45,-95,50};
        f.backend.observeBeacon(b);f.backend.observeScanComplete(f.generation,2);
        assert(f.backend.pendingScanBeacons()==1 && !f.backend.event201EmitCalls() && !f.backend.event237EmitCalls());
        assert(f.backend.last237Status()==0xffffffffU);
    }
    {
        Fixture f;
        assert(f.backend.scanRequest(scan.data(),scan.size())==Status::Ok);
        assert(f.backend.abortScan()==Status::Ok && !f.backend.event237EmitCalls());
        f.backend.observeScanComplete(f.generation,2);
        assert(f.backend.event237EmitCalls()==1 && f.backend.last237Status()==0xe00002eb);
        assert(f.backend.scanRequest(scan.data(),scan.size())==Status::Ok);
        f.backend.tick(20000);
        assert(f.backend.event237EmitCalls()==2 && f.backend.last237Status()==0xe00002d6);
    }
    {
        Fixture f;
        f.privateReady = false;
        assert(f.backend.scanRequest(scan.data(), scan.size()) == Status::Unsupported && !f.scans);
        f.privateReady = true;
        assert(f.backend.scanRequest(scan.data(), scan.size()) == Status::Ok && f.scans == 1);
        f.backend.tick(1000); assert(!f.count(ScanFinished));
        f.backend.observeScanComplete(0, 1); f.backend.observeScanComplete(18, 1);
        assert(!f.count(ScanFinished));
        f.backend.observeScanComplete(f.generation, 1); assert(f.count(ScanFinished) == 1);
        f.backend.observeScanComplete(f.generation, 1); assert(f.count(ScanFinished) == 1);
        f.backend.stop(); f.backend.observeScanComplete(f.generation, 1); assert(f.count(ScanFinished) == 1);
    }
    {
        Fixture f;
        assert(f.backend.scanRequest(scan.data(), scan.size()) == Status::Ok);
        const auto old = f.generation;
        assert(f.backend.abortScan() == Status::Ok && f.backend.scanDraining());
        assert(f.count(ScanFinished)==0);
        f.backend.driverState(true);
        assert(f.backend.scanDraining());
        assert(f.backend.scanRequest(scan.data(), scan.size()) == Status::Busy);
        f.backend.observeScanComplete(0, 1);
        assert(f.backend.scanDraining());
        f.backend.observeScanComplete(old, 1);
        assert(!f.backend.scanDraining() && f.count(ScanFinished) == 1);
        assert(f.backend.scanRequest(scan.data(), scan.size()) == Status::Ok && f.generation != old);
        f.backend.observeScanComplete(old, 1);
        assert(f.backend.scanning() && f.count(ScanFinished) == 1);
        f.backend.observeScanComplete(f.generation, 0);
        assert(f.backend.scanning());
        f.backend.observeScanComplete(f.generation, 2);
        assert(!f.backend.scanning() && f.count(ScanFinished) == 2);
        assert(read32(f.messages.back().body.data()) == 0xe00002eb);
        assert(f.backend.scanRequest(scan.data(), scan.size()) == Status::Ok);
        f.backend.tick(20000);
        assert(f.backend.scanDraining() && f.count(ScanFinished) == 3);
        assert(f.backend.joinRequest(join.data(), join.size()) == Status::Busy);
        f.backend.observeScanComplete(f.generation, 1);
        assert(!f.backend.scanDraining());
    }
    {
        Fixture f;assert(f.backend.scanRequest(scan.data(),scan.size())==Status::Ok);
        auto old=f.generation;f.backend.driverState(false);
        assert(f.backend.scanDraining());
        f.backend.observeScanReset(old+1);assert(f.backend.scanDraining());
        f.backend.observeScanReset(0);assert(f.backend.scanDraining());
        f.backend.observeScanReset(old);assert(!f.backend.scanDraining()&&!f.backend.scanning());
        auto calls=f.count(ScanFinished);f.backend.observeScanComplete(old,1);
        f.backend.observeScanReset(old);assert(f.count(ScanFinished)==calls);
        f.backend.driverState(true);
        assert(f.backend.scanRequest(scan.data(),scan.size())==Status::Ok && f.generation!=old);
        f.backend.observeScanReset(old);assert(f.backend.scanning());
        f.backend.observeScanComplete(f.generation,1);assert(!f.backend.scanning());
    }
    {
        Fixture f;assert(f.backend.scanRequest(scan.data(),scan.size())==Status::Ok);
        assert(f.backend.abortScan()==Status::Ok && f.backend.scanDraining());
        auto calls=f.count(ScanFinished);f.backend.observeScanReset(f.generation);
        assert(!f.backend.scanDraining() && f.count(ScanFinished)==calls+1);
        auto last=f.count(ScanFinished);f.backend.observeScanReset(f.generation);
        assert(f.count(ScanFinished)==last);
    }
    {
        Fixture f;assert(f.backend.scanRequest(scan.data(),scan.size())==Status::Ok);
        f.backend.addressHardwareStopped(); // No address transaction, no drain claim.
        assert(f.backend.scanning());
        f.backend.beginAddressChange();
        f.backend.addressHardwareStopped(); // Actual quiesce can retire a not-yet-issued HAL request.
        assert(!f.backend.scanning() && !f.backend.scanDraining());
        f.backend.driverState(true);
        assert(f.backend.scanRequest(scan.data(),scan.size())==Status::Ok);
    }
    {
        // Busy from an occupied init-scan lease is accepted as one owned WCL
        // request. Generation zero releases it, but does not complete it; only
        // its own matching firmware terminal event emits native 237.
        Fixture f; f.busyScanResponses=2;
        auto request=scanWire();
        assert(f.backend.scanRequest(request.data(),request.size())==Status::Ok);
        const uint32_t generation=f.generation;
        uint8_t expectedChannels[32] {};
        memcpy(expectedChannels,f.lastScanChannels,sizeof(expectedChannels));
        assert(generation && f.backend.scanning() && f.backend.scanDraining()==false);
        assert(f.backend.joinRequest(join.data(),join.size())==Status::Busy);
        memset(request.data(),0,request.size()); // Retry owns the decoded plan, not caller storage.
        f.backend.tick(1000);
        assert(f.scans==2 && f.generation==generation && f.backend.scanning());
        f.backend.observeScanComplete(0,1);
        assert(f.scans==3 && f.generation==generation && f.backend.scanning());
        assert(!memcmp(f.lastScanChannels,expectedChannels,sizeof(expectedChannels)));
        assert(f.backend.event237EmitCalls()==0 && f.count(ScanFinished)==0);
        f.backend.observeScanComplete(generation,1);
        assert(!f.backend.scanning() && f.backend.event237EmitCalls()==1);
        assert(f.count(ScanFinished)==1 && read32(f.messages.back().body.data())==0);
    }
    {
        // A newer valid scan replaces a queued-only request exactly once. A
        // stale old-generation terminal cannot submit or complete the new one.
        Fixture f; f.busyScanResponses=5;
        auto first=scanWire(), second=scanWire();
        assert(f.backend.scanRequest(first.data(),first.size())==Status::Ok);
        const uint32_t oldGeneration=f.generation;
        assert(f.backend.scanRequest(second.data(),second.size())==Status::Ok);
        const uint32_t newGeneration=f.generation;
        assert(newGeneration && newGeneration!=oldGeneration);
        assert(f.backend.scanning() && f.count(ScanFinished)==1);
        assert(read32(f.messages.back().body.data())==0xe00002eb);
        f.backend.observeScanComplete(oldGeneration,1);
        assert(f.scans==2 && f.backend.scanning() && f.count(ScanFinished)==1);
        f.busyScanResponses=0;
        f.backend.tick(1000);
        assert(f.scans==3 && f.generation==newGeneration && f.backend.scanning());
        assert(f.count(ScanFinished)==1);
        f.backend.observeScanComplete(newGeneration,1);
        assert(!f.backend.scanning() && f.count(ScanFinished)==2);
        assert(read32(f.messages.back().body.data())==0);
    }
    {
        // A queued scan was never submitted, so abort/off complete it locally
        // without invoking the HAL cancel path or waiting for firmware drain.
        Fixture f; f.busyScanResponses=1;
        assert(f.backend.scanRequest(scan.data(),scan.size())==Status::Ok);
        assert(f.backend.scanning() && !f.backend.scanDraining());
        assert(f.backend.abortScan()==Status::Ok);
        assert(!f.backend.scanning() && !f.backend.scanDraining());
        assert(f.cancels==0 && f.count(ScanFinished)==1);
        assert(read32(f.messages.back().body.data())==0xe00002eb);
        f.backend.observeScanComplete(0,1);
        assert(f.cancels==0 && f.count(ScanFinished)==1);

        Fixture down; down.busyScanResponses=1;
        assert(down.backend.scanRequest(scan.data(),scan.size())==Status::Ok);
        down.backend.driverState(false);
        assert(!down.backend.scanning() && !down.backend.scanDraining());
        assert(down.count(ScanFinished)==1);
        assert(read32(down.messages.back().body.data())==0xe00002d7);
        down.backend.driverState(true);
        down.backend.observeScanComplete(0,1);
        down.backend.tick(1000);
        assert(down.scans==1 && down.count(ScanFinished)==1);
    }
    {
        // Queued Busy retries are one-at-a-time and bounded by the original
        // 20 s deadline. NotReady and hard failure remain synchronous errors.
        Fixture f; f.busyScanResponses=100;
        assert(f.backend.scanRequest(scan.data(),scan.size())==Status::Ok);
        for (unsigned i=0;i<20;++i) f.backend.tick(1000);
        assert(!f.backend.scanning() && !f.backend.scanDraining());
        assert(f.count(ScanFinished)==1 && f.backend.event237EmitCalls()==1);
        assert(read32(f.messages.back().body.data())==0xe00002d6);
        const unsigned calls=f.scans;
        f.backend.tick(1000);
        assert(f.scans==calls && f.count(ScanFinished)==1);
        for (auto status : {Status::NotReady, Status::Failed}) {
            Fixture rejected; rejected.scanStatus=status;
            assert(rejected.backend.scanRequest(scan.data(),scan.size())==status);
            assert(!rejected.backend.scanning() && !rejected.backend.scanDraining());
            assert(!rejected.count(ScanFinished));
            rejected.backend.tick(20000);
            assert(!rejected.count(ScanFinished));
        }
    }
    {
        Fixture f;
        assert(f.backend.joinRequest(join.data(), join.size()) == Status::Ok && f.joins == 1);
        f.backend.observeAuthorization(true); assert(!f.count(Connection) && !f.count(Link));
        uint8_t wrong[6] = {2,0,0,0,0,2}; f.backend.observeAssociation(0, wrong);
        assert(!f.count(Association));
        f.backend.observeAssociation(0, join.data() + 0x21c);
        assert(f.count(Association) == 1 && !f.count(Connection) && !f.count(Link));
        uint8_t frame[38] = {0x80}; uint8_t ies[2] = {0,0}; uint8_t ssid[1] = {'x'};
        Beacon b {ssid,join.data()+0x21c,ies,frame,1,2,sizeof(frame),0x1006,100,0,6,-45,-95,50};
        f.backend.observeBeacon(b);
        assert(f.count(FirstBeacon) == 1 && f.count(Connection) == 1);
        assert(f.count(Link) == 1);
        const auto &link = f.messages[f.messages.size()-2];
        assert(link.kind == Link && link.body.size() == 16 && link.body[6] == 1);
        assert(!memcmp(link.body.data(), join.data()+0x21c, 6));
        assert(read32(link.body.data()+8) == 255 && read32(link.body.data()+12) == 0);
        assert(f.messages.back().body[0] == 0);
        f.backend.observeBeacon(b); f.backend.observeAuthorization(true);
        assert(f.count(Connection) == 1 && f.count(Link) == 1);
        assert(f.backend.associatedBeacons()==2);
        f.backend.tick(1000); // Establish the first real association snapshot.
        assert(f.count(BeaconLqm)==0);
        f.backend.observeBeacon(b);
        auto other=b;other.bssid=wrong;f.backend.observeBeacon(other);
        f.backend.tick(1000);
        assert(f.messages.back().kind==BeaconLqm);
        assert(f.messages.back().body.size()==0x1dc);
        const auto &lqm=f.messages.back().body;
        assert(read32(lqm.data()+0x28)==1 && lqm[0x30]==1);
        assert(lqm[0x1d8]==1 && lqm[0x1d9]==1);
        for(unsigned i=0;i<lqm.size();++i)
            if(i!=0x28 && i!=0x30 && i!=0x1d8 && i!=0x1d9)assert(lqm[i]==0);
        f.backend.tick(1000);
        assert(read32(f.messages.back().body.data()+0x28)==0); // No real beacon, no liveness progress.
        // Request acceptance is not proof of physical disconnection. Preserve
        // the active BSSID until the real down callback, even after leave().
        f.backend.leave(false); assert(f.count(Link) == 1);
        f.backend.observeAuthorization(false); assert(f.count(Link) == 2);
        auto reports=f.count(BeaconLqm);f.backend.tick(1000);
        assert(f.count(BeaconLqm)==reports);
        assert(f.messages.back().body[6] == 0);
        assert(!memcmp(f.messages.back().body.data(), join.data()+0x21c, 6));
        f.backend.observeAuthorization(false); assert(f.count(Link) == 2);
    }
    {
        Fixture f;
        assert(f.backend.joinRequest(join.data(),join.size())==Status::Ok);
        f.backend.observeAssociation(0,join.data()+0x21c);
        uint8_t frame[38]={0x80}, ies[2]={0,0}, ssid[1]={'x'};
        Beacon b {ssid,join.data()+0x21c,ies,frame,1,2,sizeof(frame),0x1006,100,0,6,-45,-95,50};
        f.backend.observeBeacon(b);
        assert(!f.count(Link) && !f.count(Connection)); // No key authorization.
        f.backend.observeAuthorization(true);
        assert(f.count(Link)==1 && f.count(Connection)==1);
        assert(f.messages[f.messages.size()-2].kind==Link);
        f.backend.driverState(false);
        assert(f.count(Link)==2);
        f.backend.driverState(false);f.backend.observeAuthorization(false);
        assert(f.count(Link)==2); // Repeated reset/down callbacks are not edges.
        f.backend.driverState(true);f.backend.observeBeacon(b);
        f.backend.observeAuthorization(true);
        assert(f.count(Link)==2 && f.count(Connection)==1); // No new join.
    }
    {
        Fixture f;
        assert(f.backend.joinRequest(join.data(),join.size())==Status::Ok);
        f.backend.observeAssociation(1,join.data()+0x21c);
        f.backend.observeAuthorization(true);
        assert(!f.count(Link) && f.count(Connection)==1);
        assert(f.messages.back().body[0] != 0);
    }
    {
        Fixture f; f.backend.beginAddressChange(); f.joinStatus=Status::Busy;
        assert(f.backend.joinRequest(join.data(),join.size())==Status::Ok);
        f.backend.driverState(true);
        assert(f.backend.joining() && f.joins==1 && !f.count(Connection) && !f.count(Link));
        f.backend.tick(1000); assert(f.backend.joining() && !f.count(Connection));
        f.joinStatus=Status::Ok; f.backend.observeScanComplete(0,1);
        assert(f.backend.joining() && f.joins==3 && !f.count(Connection));
        f.backend.observeAssociation(0,join.data()+0x21c);
        assert(f.count(Association)==1);
        f.backend.stop();
    }
    {
        // A lower radio Busy (for example while Tahoe's generation-zero init
        // scan owns the HAL lease) is accepted as a bounded deferred Join. The
        // exact decoded request survives caller-buffer mutation and retries on
        // the init scan's generation-zero terminal event.
        Fixture f; f.busyJoinResponses=2;
        auto request=joinWire();
        uint8_t expectedBssid[6] {};
        memcpy(expectedBssid,request.data()+0x21c,sizeof(expectedBssid));
        assert(f.backend.joinRequest(request.data(),request.size())==Status::Ok);
        assert(f.joins==1 && f.backend.joining() && !f.count(Connection));
        assert(!memcmp(f.lastJoinBssid,expectedBssid,sizeof(expectedBssid)));
        f.backend.observeAuthorization(true);
        f.backend.observeAssociation(0,expectedBssid);
        assert(!f.count(Association) && !f.count(Connection) && !f.count(Link));
        assert(f.backend.scanRequest(scan.data(),scan.size())==Status::Busy);
        f.backend.tick(1000); // One bounded retry per tick; no busy-wait loop.
        assert(f.joins==2 && f.backend.joining() && !f.count(Connection));
        auto replacement=joinWire(); replacement[0x21c]=2; replacement[0x21d]=7;
        request[0x21c]=2; request[0x21d]=9; // Caller storage is no longer authoritative.
        f.joinStatus=Status::Ok; f.busyJoinResponses=0;
        f.backend.observeScanComplete(0,1);
        assert(f.joins==3 && f.backend.joining() && !f.count(Connection));
        assert(!memcmp(f.lastJoinBssid,expectedBssid,sizeof(expectedBssid)));
        f.backend.observeAuthorization(true);
        f.backend.observeAssociation(0,expectedBssid);
        uint8_t frame[38]={0x80}, ies[2]={0,0}, ssid[1]={'x'};
        Beacon b {ssid,expectedBssid,ies,frame,1,2,sizeof(frame),0x1006,100,0,6,-45,-95,50};
        f.backend.observeBeacon(b);
        assert(f.count(Link)==1 && f.count(Connection)==1);
        f.backend.stop();
    }
    {
        // A newer request replaces a queued Busy retry, signals cancellation
        // for the old WCL request, and owns the only plan retried/completed.
        Fixture f; f.busyJoinResponses=1;
        auto oldRequest=joinWire();
        uint8_t oldBssid[6] {};
        memcpy(oldBssid,oldRequest.data()+0x21c,sizeof(oldBssid));
        assert(f.backend.joinRequest(oldRequest.data(),oldRequest.size())==Status::Ok);
        assert(f.joins==1 && f.backend.joining());
        auto newRequest=joinWire(); newRequest[0x21c]=2; newRequest[0x21d]=4;
        uint8_t newBssid[6] {};
        memcpy(newBssid,newRequest.data()+0x21c,sizeof(newBssid));
        assert(f.backend.joinRequest(newRequest.data(),newRequest.size())==Status::Ok);
        assert(f.joins==2 && f.backend.joining() && f.count(JoinAborted)==1);
        assert(!memcmp(f.lastJoinBssid,newBssid,sizeof(newBssid)));
        f.backend.observeScanComplete(0,1); // Stale initial-scan terminal cannot revive the old plan.
        assert(f.joins==2 && f.count(JoinAborted)==1);
        f.backend.observeAuthorization(true);
        f.backend.observeAssociation(0,oldBssid);
        assert(!f.count(Association));
        f.backend.observeAssociation(0,newBssid);
        uint8_t frame[38]={0x80}, ies[2]={0,0}, ssid[1]={'x'};
        Beacon b {ssid,newBssid,ies,frame,1,2,sizeof(frame),0x1006,100,0,6,-45,-95,50};
        f.backend.observeBeacon(b);
        assert(f.count(Association)==1 && f.count(Link)==1 && f.count(Connection)==1);
    }
    {
        // Power-off fails the accepted-but-unsubmitted request once and clears
        // its plan; a later READY or stale scan completion cannot revive it.
        Fixture f; f.busyJoinResponses=3;
        assert(f.backend.joinRequest(join.data(),join.size())==Status::Ok);
        assert(f.joins==1 && f.backend.joining());
        f.backend.driverState(false);
        assert(!f.backend.joining() && f.count(Connection)==1);
        assert(read32(f.messages.back().body.data()+12)==0xe00002d7);
        f.backend.driverState(true);
        f.backend.observeScanComplete(0,1);
        f.backend.tick(1000);
        assert(f.joins==1 && !f.backend.joining() && f.count(Connection)==1);
    }
    {
        // Repeated Busy admission retries are bounded by the original 30 s
        // deadline and produce a terminal timeout instead of waiting forever.
        Fixture f; f.busyJoinResponses=100;
        assert(f.backend.joinRequest(join.data(),join.size())==Status::Ok);
        assert(f.backend.joining() && f.joins==1);
        for (unsigned i=0;i<30;++i) f.backend.tick(1000);
        assert(!f.backend.joining() && f.joins==30 && f.count(Connection)==1);
        assert(read32(f.messages.back().body.data()+12)==0xe00002d6 && f.leaves==1);
        f.backend.tick(1000);
        assert(f.joins==30 && f.count(Connection)==1);
    }
    {
        // Only Busy is converted into an accepted deferred request. Preserve
        // existing NotReady and hard-failure return behavior.
        for (auto status : {Status::NotReady, Status::Failed}) {
            Fixture f; f.joinStatus=status;
            assert(f.backend.joinRequest(join.data(),join.size())==status);
            assert(f.joins==1 && !f.backend.joining() && !f.count(Connection));
            f.backend.tick(30000);
            assert(f.joins==1 && !f.backend.joining() && !f.count(Connection));
        }
    }
    {
        Fixture f; f.backend.beginAddressChange();
        assert(f.backend.joinRequest(join.data(), join.size()) == Status::Ok && !f.joins);
        f.backend.driverState(false); assert(!f.joins);
        f.backend.driverState(true); assert(f.joins == 1 && !f.count(Connection));
        f.backend.tick(30000); assert(f.count(Connection) == 1);
        assert(f.messages.back().body[0] == 1 && f.leaves == 1);
        assert(!f.count(Link));
    }
}
