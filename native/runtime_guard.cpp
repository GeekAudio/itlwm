// SPDX-License-Identifier: GPL-2.0-only
#include "runtime_guard.hpp"
#include <IOKit/IORegistryEntry.h>
#include <libkern/c++/OSString.h>
#include <libkern/libkern.h>

namespace NativeWifi {
namespace {
bool verifyRuntime(bool requireOSBuild, bool requireAwdlProfile)
{
    IORegistryEntry *root = IORegistryEntry::getRegistryRoot();
    if (!root)
        return false;

    // These are public registry properties, not private kernel globals. Use
    // retained snapshots so the check does not borrow a property lifetime.
    OSObject *buildObject = root->copyProperty("OS Build Version");
    OSObject *kernelObject = root->copyProperty("IOKitBuildVersion");
    OSString *build = OSDynamicCast(OSString, buildObject);
    OSString *kernel = OSDynamicCast(OSString, kernelObject);
    struct RuntimeProfile {
        const char *build;
        const char *kernel;
        bool awdlCandidate;
    };
    // Each profile requires a separate Apple wireless/Skywalk ABI review
    // before deployment. Matching this list alone is not runtime proof.
    static const RuntimeProfile supportedProfiles[] = {
        {
            "25G241",
            "Darwin Kernel Version 25.6.0: Tue Aug 18 17:46:40 PDT 2026; "
            "root:xnu-12377.161.15.700.19~2/RELEASE_X86_64", false
        },
        {
            "25G332",
            "Darwin Kernel Version 25.6.0: Mon Oct 12 00:33:09 PDT 2026; "
            "root:xnu-12377.161.15.701.48~2/RELEASE_X86_64", true
        },
        {
            "25G416",
            "Darwin Kernel Version 25.6.0: Fri Oct 30 17:30:02 PDT 2026; "
            "root:xnu-12377.161.15.702.13~1/RELEASE_X86_64", true
        }
    };
    // A missing early property is expected. A present property of the wrong
    // type or value must still fail; build/kernel values must be an exact pair.
    bool matches = false;
    if (kernel) {
        for (const RuntimeProfile &profile : supportedProfiles) {
            if (!kernel->isEqualTo(profile.kernel))
                continue;
            if (requireAwdlProfile && !profile.awdlCandidate)
                break;
            if (buildObject)
                matches = build && build->isEqualTo(profile.build);
            else
                matches = !requireOSBuild;
            break;
        }
    }
    if (kernelObject)
        kernelObject->release();
    if (buildObject)
        buildObject->release();
    return matches;
}
}

bool verifyTahoeRuntime(bool requireOSBuild)
{
    return verifyRuntime(requireOSBuild, false);
}

bool verifyTahoeAwdlRuntime()
{
    // The private AWDL lifecycle never uses early, kernel-only admission.
    return verifyRuntime(true, true);
}
}
