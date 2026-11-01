// SPDX-License-Identifier: GPL-2.0-only
#include "../iwx_add_sta_key_status.hpp"
#include "../iwx_fw_diagnostics.hpp"

#include <assert.h>

int main()
{
    constexpr uint32_t kAddStaKeyCommandId = 0x17;
    const uint8_t successBytes[] = {0x01, 0x00, 0x00, 0x00};
    constexpr uint32_t kTestCommandQueueId = 0;
    auto observation = IwxAddStaKeyStatus::decode(
        kAddStaKeyCommandId, kAddStaKeyCommandId, kTestCommandQueueId,
        kTestCommandQueueId, false,
        successBytes, sizeof(successBytes), sizeof(successBytes));
    assert(observation.outcome == IwxAddStaKeyStatus::Outcome::StatusPresent);
    assert(observation.status == 1);
    assert(!observation.commandResponseFailed);

    const uint8_t nonzeroBytes[] = {0x04, 0x03, 0x02, 0x01};
    observation = IwxAddStaKeyStatus::decode(
        kAddStaKeyCommandId, kAddStaKeyCommandId, kTestCommandQueueId,
        kTestCommandQueueId, true,
        nonzeroBytes, sizeof(nonzeroBytes), sizeof(nonzeroBytes));
    assert(observation.outcome == IwxAddStaKeyStatus::Outcome::StatusPresent);
    assert(observation.status == 0x01020304U);
    assert(observation.commandResponseFailed);

    observation = IwxAddStaKeyStatus::decode(
        kAddStaKeyCommandId, kAddStaKeyCommandId, kTestCommandQueueId,
        kTestCommandQueueId, false,
        nonzeroBytes, 3, sizeof(nonzeroBytes));
    assert(observation.outcome ==
           IwxAddStaKeyStatus::Outcome::StatusUnavailable);

    observation = IwxAddStaKeyStatus::decode(
        kAddStaKeyCommandId, kAddStaKeyCommandId, kTestCommandQueueId,
        kTestCommandQueueId, false,
        nullptr, sizeof(nonzeroBytes), sizeof(nonzeroBytes));
    assert(observation.outcome ==
           IwxAddStaKeyStatus::Outcome::StatusUnavailable);

    observation = IwxAddStaKeyStatus::decode(
        kAddStaKeyCommandId, kAddStaKeyCommandId, kTestCommandQueueId,
        kTestCommandQueueId, false,
        nonzeroBytes, sizeof(nonzeroBytes), 3);
    assert(observation.outcome ==
           IwxAddStaKeyStatus::Outcome::StatusUnavailable);

    observation = IwxAddStaKeyStatus::decode(
        kAddStaKeyCommandId, kAddStaKeyCommandId, kTestCommandQueueId,
        kTestCommandQueueId, false,
        nonzeroBytes, 5, sizeof(nonzeroBytes));
    assert(observation.outcome ==
           IwxAddStaKeyStatus::Outcome::StatusUnavailable);

    observation = IwxAddStaKeyStatus::decode(
        0x18, kAddStaKeyCommandId, kTestCommandQueueId,
        kTestCommandQueueId, false, nonzeroBytes,
        sizeof(nonzeroBytes), sizeof(nonzeroBytes));
    assert(observation.outcome == IwxAddStaKeyStatus::Outcome::NotApplicable);

    observation = IwxAddStaKeyStatus::decode(
        kAddStaKeyCommandId, kAddStaKeyCommandId, 1,
        kTestCommandQueueId, false,
        nonzeroBytes, sizeof(nonzeroBytes), sizeof(nonzeroBytes));
    assert(observation.outcome == IwxAddStaKeyStatus::Outcome::NotApplicable);

    observation = IwxAddStaKeyStatus::decode(
        kAddStaKeyCommandId, kAddStaKeyCommandId, 0x80,
        kTestCommandQueueId, false,
        nonzeroBytes, sizeof(nonzeroBytes), sizeof(nonzeroBytes));
    assert(observation.outcome == IwxAddStaKeyStatus::Outcome::NotApplicable);

    observation = IwxAddStaKeyStatus::decode(
        kAddStaKeyCommandId, kAddStaKeyCommandId, kTestCommandQueueId,
        kTestCommandQueueId, false, nonzeroBytes, 5, 5);
    assert(observation.outcome ==
           IwxAddStaKeyStatus::Outcome::StatusUnavailable);

    assert(IwxAddStaKeyStatus::isPendingCommandQueueIndex(8, 2, 3, 7));
    assert(IwxAddStaKeyStatus::isPendingCommandQueueIndex(8, 2, 3, 0));
    assert(IwxAddStaKeyStatus::isPendingCommandQueueIndex(8, 2, 3, 1));
    assert(!IwxAddStaKeyStatus::isPendingCommandQueueIndex(8, 2, 3, 2));
    assert(IwxAddStaKeyStatus::isPendingCommandQueueIndex(8, 1, 1, 0));
    assert(!IwxAddStaKeyStatus::isPendingCommandQueueIndex(8, 1, 0, 0));
    assert(!IwxAddStaKeyStatus::isPendingCommandQueueIndex(8, 1, 8, 0));
    assert(!IwxAddStaKeyStatus::isPendingCommandQueueIndex(7, 1, 1, 0));
    assert(!IwxAddStaKeyStatus::isPendingCommandQueueIndex(8, 8, 1, 0));
    assert(!IwxAddStaKeyStatus::isPendingCommandQueueIndex(8, 1, 1, 8));

    IwxFirmwareDiagnostics::TraceRing trace{};
    IwxFirmwareDiagnostics::initialize(&trace);
    IwxFirmwareDiagnostics::Entry keyResponse{};
    keyResponse.phase = static_cast<uint32_t>(
        IwxFirmwareDiagnostics::Phase::RxResponseNoBuffer);
    keyResponse.source = static_cast<uint32_t>(
        IwxFirmwareDiagnostics::Source::CommandResponseQueue);
    keyResponse.command_id = 0x17;
    keyResponse.qid = 0;
    keyResponse.flags = IwxFirmwareDiagnostics::kFirmwareStatusPresent;
    keyResponse.result = 0x01020304U;
    assert(IwxFirmwareDiagnostics::record(&trace, keyResponse) == 1);
    for (uint32_t index = 0; index < 70; ++index) {
        IwxFirmwareDiagnostics::Entry other{};
        other.phase = static_cast<uint32_t>(
            IwxFirmwareDiagnostics::Phase::CommandSubmitted);
        assert(IwxFirmwareDiagnostics::record(&trace, other) != 0);
    }
    IwxFirmwareDiagnostics::TraceSnapshot traceSnapshot{};
    assert(IwxFirmwareDiagnostics::snapshot(&trace, &traceSnapshot));
    assert(traceSnapshot.complete == 1);
    assert(traceSnapshot.row_count == IwxFirmwareDiagnostics::kTraceCapacity);
    assert(traceSnapshot.latest_add_sta_key_present == 1);
    assert(traceSnapshot.latest_add_sta_key_stable == 1);
    assert(traceSnapshot.latest_add_sta_key_response.serial == 1);
    assert(traceSnapshot.latest_add_sta_key_response.result == 0x01020304U);
    IwxFirmwareDiagnostics::TraceWireBuffer wire{};
    assert(IwxFirmwareDiagnostics::encodeWire(traceSnapshot, &wire));
    assert(wire.length == IwxFirmwareDiagnostics::kTraceWireBlobBytes);

    IwxFirmwareDiagnostics::TraceRing droppedTrace{};
    IwxFirmwareDiagnostics::initialize(&droppedTrace);
    __atomic_store_n(&droppedTrace.latest_add_sta_key_response.writer, 1U,
                     __ATOMIC_RELEASE);
    assert(IwxFirmwareDiagnostics::record(&droppedTrace, keyResponse) == 1);
    __atomic_store_n(&droppedTrace.latest_add_sta_key_response.writer, 0U,
                     __ATOMIC_RELEASE);
    IwxFirmwareDiagnostics::TraceSnapshot droppedSnapshot{};
    assert(IwxFirmwareDiagnostics::snapshot(&droppedTrace, &droppedSnapshot));
    assert(droppedSnapshot.latest_add_sta_key_present == 0);
    assert(droppedSnapshot.latest_add_sta_key_stable == 1);
    assert(droppedSnapshot.latest_add_sta_key_dropped_count == 1);
    assert(droppedSnapshot.latest_add_sta_key_dropped_serial == 1);
    return 0;
}
