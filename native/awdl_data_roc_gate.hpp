// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <stdint.h>
namespace NativeAwdlDataGate {
enum Block : uint32_t {
    WrongOwner=1u<<0, EpochChanged=1u<<1, StationUnavailable=1u<<2,
    CommandOrStateBusy=1u<<3, MacInactive=1u<<4, BindingInactive=1u<<5,
    PhyNotLeased=1u<<6, SessionInactive=1u<<7, QueueBusy=1u<<8
};
struct State {
    bool owner,epochs,station,commands,macActive,bindingActive,phyLeased,session,queueIdle;
};
// This is the active-ROC phase. The pre-binding MAC-add revalidation function
// deliberately requires binding ABSENT and must never be used here.
inline uint32_t blockers(const State &s) {
    return (s.owner?0:WrongOwner)|(s.epochs?0:EpochChanged)|
        (s.station?0:StationUnavailable)|(s.commands?0:CommandOrStateBusy)|
        (s.macActive?0:MacInactive)|(s.bindingActive?0:BindingInactive)|
        (s.phyLeased?0:PhyNotLeased)|(s.session?0:SessionInactive)|(s.queueIdle?0:QueueBusy);
}
}
