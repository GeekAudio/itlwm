// SPDX-License-Identifier: GPL-2.0-only
#pragma once

namespace NativeAwdlInit {
enum class Disposal { Quarantine, ServiceBase, VirtualInterfaceBase };
struct CleanupFacts {
    bool parentPrivate;
    bool childPrivate;
    bool bpfCleaned;
};
// Only for unpublished objects that never attached or started. The binding
// must make PM callbacks independent of native state. Quiescing callbacks
// does not imply all asynchronous references have already been removed.
template <typename Operations>
Disposal prepareUnpublished(CleanupFacts &facts, Operations &ops)
{
    if (facts.childPrivate && !facts.parentPrivate)
        return Disposal::Quarantine;
    if (facts.parentPrivate && !ops.quiesceInterest())
        return Disposal::Quarantine;
    if (ops.isOpen()) {
        ops.close();
        if (ops.isOpen())
            return Disposal::Quarantine;
    }
    if (facts.childPrivate && !facts.bpfCleaned) {
        ops.freeBpfResources();
        facts.bpfCleaned = true;
    }
    return facts.parentPrivate ? Disposal::VirtualInterfaceBase :
                                 Disposal::ServiceBase;
}
} // namespace NativeAwdlInit
