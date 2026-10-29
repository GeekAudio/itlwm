#!/usr/bin/env python3
"""Extract and fault-inject the production MCC numeric snapshot publisher."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
DRIVER = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()


def function_body(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    index = opening
    state = "code"
    while index < len(source):
        char = source[index]
        nxt = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and nxt == "/":
                state = "line"
                index += 2
                continue
            if char == "/" and nxt == "*":
                state = "block"
                index += 2
                continue
            if char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return source[start : index + 1]
        elif state == "line":
            if char == "\n":
                state = "code"
        elif state == "block":
            if char == "*" and nxt == "/":
                state = "code"
                index += 2
                continue
        elif state in ("string", "char"):
            if char == "\\":
                index += 2
                continue
            if (state == "string" and char == '"') or (
                state == "char" and char == "'"
            ):
                state = "code"
        index += 1
    raise AssertionError("unterminated production publisher")


PUBLISHER = function_body(
    DRIVER, "void ItlIwx::tahoePublishMccSnapshot(IOEthernetController *controller)"
)

HARNESS = r"""
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <unordered_map>

struct IOEthernetController {
    std::unordered_map<std::string, uint64_t> properties;
    unsigned writes = 0;
    std::string failKey;
    bool failOnce = false;

    bool setProperty(const char *key, uint64_t value, unsigned)
    {
        ++writes;
        if (failOnce && failKey == key) {
            failOnce = false;
            return false;
        }
        properties[key] = value;
        return true;
    }
};
struct iwx_softc {
    uint32_t sc_generation = 25;
    uint32_t sc_native_mcc_notice_generation = 0;
    uint32_t sc_native_mcc_notice_code = 0;
    uint32_t sc_native_mcc_notice_source = 0;
    uint32_t sc_native_mcc_notice_valid = 0;
    uint32_t sc_native_mcc_pending = 0;
    uint32_t sc_native_mcc_request_sequence = 0;
    uint32_t sc_native_mcc_request_mcc = 0;
    uint32_t sc_native_mcc_request_notice_generation = 0;
    uint32_t sc_native_mcc_request_firmware_generation = 0;
    uint32_t sc_native_mcc_request_source = 0;
    uint32_t sc_native_mcc_request_origin = 0;
    uint32_t sc_native_mcc_command_version = 0;
    uint32_t sc_native_mcc_command_version_present = 0;
    uint32_t sc_native_mcc_notification_version = 0;
    uint32_t sc_native_mcc_notification_version_present = 0;
    uint32_t sc_native_mcc_response_format = 0;
    uint32_t sc_native_mcc_11ax_capability = 0;
    uint32_t sc_native_mcc_11ax_capability_present = 0;
    uint32_t sc_native_mcc_response_present = 0;
    uint32_t sc_native_mcc_response_notice_generation = 0;
    uint32_t sc_native_mcc_response_firmware_generation = 0;
    uint32_t sc_native_mcc_response_mcc = 0;
    uint32_t sc_native_mcc_response_source = 0;
    uint32_t sc_native_mcc_response_status = 0;
    uint32_t sc_native_mcc_response_capabilities = 0;
    uint32_t sc_native_mcc_response_time = 0;
    uint32_t sc_native_mcc_response_geo_info = 0;
    uint32_t sc_native_mcc_response_channel_count = 0;
    uint32_t sc_native_mcc_response_profile149_flags = 0;
    uint32_t sc_native_mcc_response_profile149_flags_present = 0;
    uint32_t sc_native_mcc_applied_notice_generation = 0;
    uint32_t sc_native_mcc_applied_firmware_generation = 0;
    uint32_t sc_native_mcc_applied_channel149_flags = 0;
    uint32_t sc_native_mcc_applied_channel149_flags_present = 0;
    uint32_t sc_native_mcc_applied_channel149_frequency = 0;
    uint32_t sc_native_mcc_applied_channel149_frequency_present = 0;
    uint32_t sc_native_mcc_nvm_firmware_generation = 0;
    uint32_t sc_native_mcc_nvm_profile149_flags = 0;
    uint32_t sc_native_mcc_nvm_profile149_flags_present = 0;
    uint32_t sc_native_mcc_nvm_channel149_flags = 0;
    uint32_t sc_native_mcc_nvm_channel149_flags_present = 0;
    uint32_t sc_native_mcc_nvm_channel149_frequency = 0;
    uint32_t sc_native_mcc_nvm_channel149_frequency_present = 0;
    uint32_t sc_native_mcc_profile149_index = 0;
    uint32_t sc_native_mcc_last_error = 0;
    uint32_t sc_native_mcc_failed_notice_generation = 0;
    uint32_t sc_native_mcc_failed_firmware_generation = 0;
    uint32_t sc_native_mcc_failed_request_sequence = 0;
    uint32_t sc_native_mcc_last_gate = 0;
    uint32_t sc_native_mcc_snapshot_revision = 0;
    uint64_t sc_native_mcc_published_fingerprint = 0;
    uint32_t sc_native_mcc_published_fingerprint_valid = 0;
};
struct ItlIwx {
    iwx_softc com;
    IOEthernetController controller;
    bool mainGate = true;
    bool lifecycleAvailable = true;
    unsigned releases = 0, lifecycleDepth = 0;

    bool tahoeP2pOnMainGate() const { return mainGate; }
    bool tahoeTryLifecycleFence()
    {
        if (!lifecycleAvailable) return false;
        ++lifecycleDepth; // model IORecursiveLock try-lock on the same thread
        return true;
    }
    bool tahoeReleaseLifecycleFence(bool)
    {
        assert(lifecycleDepth > 0);
        const bool outermost = (--lifecycleDepth == 0);
        ++releases;
        return outermost;
    }
    void tahoePublishMccSnapshot(IOEthernetController *);
};

""" + PUBLISHER + r"""

static uint64_t value(const ItlIwx &owner, const char *name)
{
    auto found = owner.controller.properties.find(name);
    assert(found != owner.controller.properties.end());
    return found->second;
}

static void testInitialZeroGenerationSnapshotAndDeduplication()
{
    ItlIwx owner {};
    owner.com.sc_native_mcc_response_present = 1; // init GET_CURRENT can precede CHUB
    assert(owner.tahoeTryLifecycleFence());
    assert(owner.lifecycleDepth == 1);
    owner.tahoePublishMccSnapshot(&owner.controller);
    assert(owner.lifecycleDepth == 1); // nested publisher fence released only its recursion
    assert(owner.tahoeReleaseLifecycleFence(false));
    assert(owner.lifecycleDepth == 0);
    assert(owner.com.sc_native_mcc_snapshot_revision == 2);
    assert(owner.com.sc_native_mcc_published_fingerprint_valid == 1);
    assert(value(owner, "NativeMCCSnapshotValid") == 1);
    assert(value(owner, "NativeMCCNoticeGeneration") == 0);
    assert(value(owner, "NativeMCCNoticeMCCPresent") == 0);
    assert(value(owner, "NativeMCCNoticeSourcePresent") == 0);
    assert(value(owner, "NativeMCCResponsePresent") == 1);
    const unsigned writesAfterFirst = owner.controller.writes;

    owner.tahoePublishMccSnapshot(&owner.controller);
    assert(owner.controller.writes == writesAfterFirst);
    assert(owner.com.sc_native_mcc_snapshot_revision == 2);
    assert(owner.releases == 3);
}

static void testChangedContentPublishesAndFailureRetries()
{
    ItlIwx owner {};
    owner.tahoePublishMccSnapshot(&owner.controller);
    const unsigned initialWrites = owner.controller.writes;
    const uint64_t initialFingerprint =
        owner.com.sc_native_mcc_published_fingerprint;

    owner.com.sc_native_mcc_last_error = 17;
    owner.tahoePublishMccSnapshot(&owner.controller);
    assert(owner.com.sc_native_mcc_snapshot_revision == 4);
    assert(owner.controller.writes > initialWrites);
    assert(value(owner, "NativeMCCLastError") == 17);
    const unsigned writesAfterChange = owner.controller.writes;
    const uint64_t committedFingerprint =
        owner.com.sc_native_mcc_published_fingerprint;
    assert(committedFingerprint != initialFingerprint);

    owner.com.sc_native_mcc_last_error = 18;
    owner.controller.failKey = "NativeMCCLastError";
    owner.controller.failOnce = true;
    owner.tahoePublishMccSnapshot(&owner.controller);
    assert(owner.com.sc_native_mcc_snapshot_revision == 4);
    assert(owner.com.sc_native_mcc_published_fingerprint == committedFingerprint);
    assert(owner.com.sc_native_mcc_published_fingerprint_valid == 1);
    assert(value(owner, "NativeMCCSnapshotValid") == 0);
    assert(value(owner, "NativeMCCLastError") == 17);
    assert(owner.controller.writes > writesAfterChange);

    owner.tahoePublishMccSnapshot(&owner.controller);
    assert(owner.com.sc_native_mcc_snapshot_revision == 6);
    assert(owner.com.sc_native_mcc_published_fingerprint != committedFingerprint);
    assert(value(owner, "NativeMCCSnapshotValid") == 1);
    assert(value(owner, "NativeMCCLastError") == 18);
}

int main()
{
    testInitialZeroGenerationSnapshotAndDeduplication();
    testChangedContentPublishesAndFailureRetries();
    return 0;
}
"""

def main() -> None:
    source = HARNESS
    with tempfile.TemporaryDirectory(prefix="test082-mcc-publisher-") as temp:
        cpp, binary = Path(temp) / "publisher.cpp", Path(temp) / "publisher"
        cpp.write_text(source)
        result = subprocess.run(
            ["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
             "-I", str(ROOT), str(cpp), "-o", str(binary)],
            text=True,
            capture_output=True,
        )
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        result = subprocess.run([str(binary)], text=True, capture_output=True)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
    print("PASS: production MCC publisher deduplicates unchanged content, emits generation-zero no-notice snapshot, and retries failed property batches without committing fingerprint/revision")

if __name__ == "__main__":
    main()

