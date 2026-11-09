// Run the actual ../runtime_guard.cpp with isolated host-only IOKit shims.
// No copy of the runtime guard implementation exists in this test.
#include "../runtime_guard.hpp"
#include <IOKit/IORegistryEntry.h>
#include <cassert>
#include <cstdio>
#include <string>

unsigned OSObject::liveObjects = 0;
unsigned OSObject::retains = 0;
unsigned OSObject::releases = 0;
IORegistryEntry *IORegistryEntry::root = nullptr;

namespace {
struct RuntimeProfile {
    const char *build;
    const char *kernel;
    bool awdl;
};
const RuntimeProfile Profiles[] = {
    {"25G241", "Darwin Kernel Version 25.6.0: Tue Aug 18 17:46:40 PDT 2026; root:xnu-12377.161.15.700.19~2/RELEASE_X86_64", false},
    {"25G332", "Darwin Kernel Version 25.6.0: Mon Oct 12 00:33:09 PDT 2026; root:xnu-12377.161.15.701.48~2/RELEASE_X86_64", true},
    {"25G416", "Darwin Kernel Version 25.6.0: Fri Oct 30 17:30:02 PDT 2026; root:xnu-12377.161.15.702.13~1/RELEASE_X86_64", true}
};
unsigned checks = 0;
class WrongType final : public OSObject {};

void put(IORegistryEntry &root, const char *key, const char *value) {
    if (!value) { root.setProperty(key, nullptr); return; }
    auto text = new OSString(value);
    root.setProperty(key, text);
    text->release();
}
void wrong(IORegistryEntry &root, const char *key) {
    auto value = new WrongType;
    root.setProperty(key, value);
    value->release();
}
void expect(bool required, bool result, bool awdlResult = false) {
    const auto retains = OSObject::retains;
    const auto releases = OSObject::releases;
    assert(NativeWifi::verifyTahoeRuntime(required) == result);
    assert(NativeWifi::verifyTahoeAwdlRuntime() == awdlResult);
    assert(OSObject::retains - retains == OSObject::releases - releases);
    if (IORegistryEntry::root) assert(IORegistryEntry::root->propertyReferencesBalanced());
    checks += 2;
}
}

int main() {
    // Missing root and missing kernel are never accepted.
    expect(false, false); expect(true, false);
    auto root = new IORegistryEntry;
    IORegistryEntry::root = root;
    expect(false, false); expect(true, false);
    put(*root, "OS Build Version", "25G241");
    expect(false, false); expect(true, false);

    // Ordinary Wi-Fi admits all three exact profiles. AWDL admits only its
    // narrower explicit set, never a missing build property.
    for (size_t i = 0; i < sizeof(Profiles) / sizeof(Profiles[0]); ++i) {
        const RuntimeProfile &profile = Profiles[i];
        put(*root, "IOKitBuildVersion", profile.kernel);
        put(*root, "OS Build Version", nullptr);
        expect(false, true);
        expect(true, false);
        assert(NativeWifi::verifyTahoeRuntime()); ++checks;
        assert(root->propertyReferencesBalanced());

        put(*root, "OS Build Version", profile.build);
        expect(false, true, profile.awdl);
        expect(true, true, profile.awdl);

        // Test every wrong pairing, not only one neighboring profile.
        for (size_t j = 0; j < sizeof(Profiles) / sizeof(Profiles[0]); ++j) {
            if (j == i) continue;
            put(*root, "OS Build Version", profile.build);
            put(*root, "IOKitBuildVersion", Profiles[j].kernel);
            expect(false, false);
            expect(true, false);
        }

        for (const char *value : {"25G240", "25G241 ", "25g241", "25G332 ", "25G333", "25G416 ", "25g416", "25G417", ""}) {
            put(*root, "OS Build Version", value);
            put(*root, "IOKitBuildVersion", profile.kernel);
            expect(false, false);
            expect(true, false);
        }

        // A present but wrong-typed build value fails even in early mode.
        wrong(*root, "OS Build Version");
        expect(false, false);
        expect(true, false);

        put(*root, "OS Build Version", profile.build);
        wrong(*root, "IOKitBuildVersion");
        expect(false, false);
        expect(true, false);

        // Exact full kernel equality is required; truncation and suffix drift
        // must not match either profile.
        put(*root, "IOKitBuildVersion", (std::string(profile.kernel) + " ").c_str());
        expect(false, false);
        expect(true, false);
        const std::string truncated(profile.kernel);
        put(*root, "IOKitBuildVersion",
            truncated.substr(0, truncated.size() - 1).c_str());
        expect(false, false);
        expect(true, false);

        // Missing build is allowed only with a full, known kernel; missing or
        // unknown kernel properties always fail.
        put(*root, "OS Build Version", nullptr);
        put(*root, "IOKitBuildVersion", "Darwin Kernel Version 25.6.0:");
        expect(false, false);
        expect(true, false);
        put(*root, "IOKitBuildVersion", profile.kernel);
        expect(false, true);
        expect(true, false);
        put(*root, "IOKitBuildVersion", nullptr);
        expect(false, false);
        expect(true, false);
    }

    // Repeated real calls must balance every copyProperty ownership operation.
    put(*root, "OS Build Version", Profiles[0].build);
    put(*root, "IOKitBuildVersion", Profiles[0].kernel);
    for (unsigned i = 0; i < 100; ++i) expect(i & 1, true);
    IORegistryEntry::root = nullptr;
    root->release();
    assert(OSObject::liveObjects == 0);
    std::printf("runtime_guard: %u real-implementation checks passed; all property references released\n", checks);
}
