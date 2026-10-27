// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_data_roc_gate.hpp"
#include "../p2p_hal_probe.hpp"
#include <assert.h>
int main(){
    NativeP2PProbe::Revalidation old{};
    old.generationMatches=old.p2pGenerationMatches=old.radioAvailable=old.firmwareHealthy=true;
    old.driverRunning=old.associated=old.portAuthorized=old.scanIdle=old.commandQueueIdle=true;
    old.stateQueuePaused=old.noPendingNewstate=old.p2pContextInitialized=old.addAcknowledged=old.p2pMacActive=true;
    old.p2pBindingAbsent=false;
    assert(NativeP2PProbe::revalidationBlockReason(old,true)==NativeP2PProbe::kFirmwareOutcomeUnknown);
    using namespace NativeAwdlDataGate;
    const State good{true,true,true,true,true,true,true,true,true};
    assert(blockers(good)==0);
    State s=good;s.bindingActive=false;assert(blockers(s)==BindingInactive);
    s=good;s.owner=false;assert(blockers(s)==WrongOwner);
    s=good;s.epochs=false;assert(blockers(s)==EpochChanged);
    s=good;s.station=false;assert(blockers(s)==StationUnavailable);
    s=good;s.commands=false;assert(blockers(s)==CommandOrStateBusy);
    s=good;s.macActive=false;assert(blockers(s)==MacInactive);
    s=good;s.phyLeased=false;assert(blockers(s)==PhyNotLeased);
    s=good;s.session=false;assert(blockers(s)==SessionInactive);
    s=good;s.queueIdle=false;assert(blockers(s)==QueueBusy);
    return 0;
}
