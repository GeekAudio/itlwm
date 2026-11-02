// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_IWX_LIVE_KEY_PUBLISH_HPP
#define GEEK_IWX_LIVE_KEY_PUBLISH_HPP
#include "iwx_fw_diagnostics.hpp"

// Independent of the sealed HCTX cut. These are two observations, NOT a
// transaction match, firmware ACK, installation result, or peer receipt.
namespace IwxLiveKey {
using IwxFirmwareDiagnostics::Entry;
using IwxFirmwareDiagnostics::Slot;
struct Observation {
    Entry entry{};
    uint32_t present{0}, stable{0}, dropped{0};
    uint64_t droppedSerial{0};
    uint64_t originSubmitSerial{0};
};
struct Snapshot {
    Observation submit{}, response{};
    Observation rxSequence{}, txSequence{}, sequenceUnavailable{};
};

inline bool readSlot(const Slot &slot, const uint32_t &drops,
                     const uint64_t &missedSerial, Observation &out)
{
    out = {};
    out.dropped = __atomic_load_n(&drops, __ATOMIC_ACQUIRE);
    out.droppedSerial = __atomic_load_n(&missedSerial, __ATOMIC_ACQUIRE);
    if (__atomic_load_n(&slot.writer, __ATOMIC_ACQUIRE)) return false;
    const uint64_t before = __atomic_load_n(&slot.entry.serial, __ATOMIC_ACQUIRE);
    IwxFirmwareDiagnostics::copyEntry(&out.entry, slot.entry);
    __atomic_thread_fence(__ATOMIC_ACQ_REL);
    const uint64_t after = __atomic_load_n(&slot.entry.serial, __ATOMIC_ACQUIRE);
    out.stable = before == after && before == out.entry.serial &&
        !__atomic_load_n(&slot.writer, __ATOMIC_ACQUIRE) &&
        out.dropped == __atomic_load_n(&drops, __ATOMIC_ACQUIRE) &&
        out.droppedSerial == __atomic_load_n(&missedSerial, __ATOMIC_ACQUIRE);
    out.present = out.stable && before != 0;
    out.originSubmitSerial = out.present &&
        (out.entry.flags & IwxFirmwareDiagnostics::kOriginSubmitSerialPresent)
            ? (uint64_t(out.entry.packet_length) << 32) |
                out.entry.payload_length
            : 0U;
    if (!out.present) out.entry = {};
    if (!out.present) out.originSubmitSerial = 0U;
    return out.stable != 0;
}

inline Snapshot snapshot(const IwxFirmwareDiagnostics::TraceRing &ring)
{
    Snapshot result{};
    readSlot(ring.latest_add_sta_key_submit,
             ring.latest_add_sta_key_submit_dropped_count,
             ring.latest_add_sta_key_submit_dropped_serial, result.submit);
    readSlot(ring.latest_add_sta_key_response,
             ring.latest_add_sta_key_dropped_count,
             ring.latest_add_sta_key_dropped_serial, result.response);
    readSlot(ring.latest_key_rx_sequence,
             ring.latest_key_rx_sequence_dropped_count,
             ring.latest_key_rx_sequence_dropped_serial, result.rxSequence);
    readSlot(ring.latest_key_tx_sequence,
             ring.latest_key_tx_sequence_dropped_count,
             ring.latest_key_tx_sequence_dropped_serial, result.txSequence);
    readSlot(ring.latest_key_sequence_unavailable,
             ring.latest_key_sequence_unavailable_dropped_count,
             ring.latest_key_sequence_unavailable_dropped_serial,
             result.sequenceUnavailable);
    // Recheck both observations after copying the second. No dependence on
    // unrelated RX ring churn; no assertion that these entries form a pair.
    __atomic_thread_fence(__ATOMIC_ACQ_REL);
    const auto current = [](const Slot &slot, const uint32_t &drops,
                            const uint64_t &missed, const Observation &o) {
        return o.stable && !__atomic_load_n(&slot.writer, __ATOMIC_ACQUIRE) &&
            __atomic_load_n(&slot.entry.serial, __ATOMIC_ACQUIRE) == o.entry.serial &&
            __atomic_load_n(&drops, __ATOMIC_ACQUIRE) == o.dropped &&
            __atomic_load_n(&missed, __ATOMIC_ACQUIRE) == o.droppedSerial;
    };
    if (!current(ring.latest_add_sta_key_submit,
                 ring.latest_add_sta_key_submit_dropped_count,
                 ring.latest_add_sta_key_submit_dropped_serial, result.submit)) {
        result.submit.stable = result.submit.present = 0;
        result.submit.entry = {};
    }
    if (!current(ring.latest_add_sta_key_response,
                 ring.latest_add_sta_key_dropped_count,
                 ring.latest_add_sta_key_dropped_serial, result.response)) {
        result.response.stable = result.response.present = 0;
        result.response.entry = {};
    }
    if (!current(ring.latest_key_rx_sequence,
                 ring.latest_key_rx_sequence_dropped_count,
                 ring.latest_key_rx_sequence_dropped_serial,
                 result.rxSequence)) {
        result.rxSequence.stable = result.rxSequence.present = 0;
        result.rxSequence.entry = {};
        result.rxSequence.originSubmitSerial = 0;
    }
    if (!current(ring.latest_key_tx_sequence,
                 ring.latest_key_tx_sequence_dropped_count,
                 ring.latest_key_tx_sequence_dropped_serial,
                 result.txSequence)) {
        result.txSequence.stable = result.txSequence.present = 0;
        result.txSequence.entry = {};
        result.txSequence.originSubmitSerial = 0;
    }
    if (!current(ring.latest_key_sequence_unavailable,
                 ring.latest_key_sequence_unavailable_dropped_count,
                 ring.latest_key_sequence_unavailable_dropped_serial,
                 result.sequenceUnavailable)) {
        result.sequenceUnavailable.stable =
            result.sequenceUnavailable.present = 0;
        result.sequenceUnavailable.entry = {};
        result.sequenceUnavailable.originSubmitSerial = 0;
    }
    return result;
}

// Owner/main-gate only. A partial property write leaves an odd revision and
// is never accepted as a stable observation. No payload/SSID/MAC/key material.
template<class Controller>
bool publish(Controller *controller, const Snapshot &sample, uint64_t now,
             uint32_t generation, uint32_t outputEpoch, bool contextStable,
             bool hctxFrozen, bool hctxManualLatched,
             uint32_t &revision)
{
    if (!controller || revision > UINT32_MAX - 2U) return false;
    const uint32_t odd = revision + 1U;
    const uint32_t even = revision + 2U;
    bool okay = controller->setProperty("NativeKeyLiveRevisionBegin", odd, 32) &&
        controller->setProperty("NativeKeyLiveRevisionEnd", odd, 32) &&
        controller->setProperty("NativeKeyLiveSchema", 2U, 32) &&
        controller->setProperty("NativeKeyLiveSampleMonotonicNs", now, 64) &&
        controller->setProperty("NativeKeyLiveOwnerGeneration", generation, 32) &&
        controller->setProperty("NativeKeyLiveOwnerOutputEpoch", outputEpoch, 32) &&
        controller->setProperty("NativeKeyLiveOwnerContextStable", contextStable, 32) &&
        controller->setProperty("NativeKeyLiveHctxFrozen", hctxFrozen, 32) &&
        controller->setProperty("NativeKeyLiveHctxManualLatched", hctxManualLatched, 32);
#define LIVE_KEY_FIELD(prefix, value, name, field, bits) \
    okay = okay && controller->setProperty("NativeKeyLive" prefix name, value.field, bits)
#define LIVE_KEY_OBSERVATION(prefix, value) \
    LIVE_KEY_FIELD(prefix, value, "Present", present, 32); \
    LIVE_KEY_FIELD(prefix, value, "Stable", stable, 32); \
    LIVE_KEY_FIELD(prefix, value, "DroppedCount", dropped, 32); \
    LIVE_KEY_FIELD(prefix, value, "DroppedSerial", droppedSerial, 64); \
    LIVE_KEY_FIELD(prefix, value, "OriginSubmitSerial", originSubmitSerial, 64); \
    LIVE_KEY_FIELD(prefix, value.entry, "Serial", serial, 64); \
    LIVE_KEY_FIELD(prefix, value.entry, "MonotonicNs", monotonic_ns, 64); \
    LIVE_KEY_FIELD(prefix, value.entry, "DriverGeneration", driver_generation, 32); \
    LIVE_KEY_FIELD(prefix, value.entry, "FirmwareGeneration", firmware_generation, 32); \
    LIVE_KEY_FIELD(prefix, value.entry, "Phase", phase, 32); \
    LIVE_KEY_FIELD(prefix, value.entry, "Source", source, 32); \
    LIVE_KEY_FIELD(prefix, value.entry, "CommandId", command_id, 32); \
    LIVE_KEY_FIELD(prefix, value.entry, "GroupId", group_id, 32); \
    LIVE_KEY_FIELD(prefix, value.entry, "Version", version, 32); \
    LIVE_KEY_FIELD(prefix, value.entry, "Qid", qid, 32); \
    LIVE_KEY_FIELD(prefix, value.entry, "Index", index, 32); \
    LIVE_KEY_FIELD(prefix, value.entry, "HeaderSequence", header_sequence, 32); \
    LIVE_KEY_FIELD(prefix, value.entry, "Flags", flags, 32); \
    LIVE_KEY_FIELD(prefix, value.entry, "Result", result, 32); \
    LIVE_KEY_FIELD(prefix, value.entry, "ResultDetail", result_detail, 32); \
    LIVE_KEY_FIELD(prefix, value.entry, "PacketLength", packet_length, 32); \
    LIVE_KEY_FIELD(prefix, value.entry, "PayloadLength", payload_length, 32)
    LIVE_KEY_OBSERVATION("Submit", sample.submit);
    LIVE_KEY_OBSERVATION("Response", sample.response);
    LIVE_KEY_OBSERVATION("RxSequence", sample.rxSequence);
    LIVE_KEY_OBSERVATION("TxSequence", sample.txSequence);
    LIVE_KEY_OBSERVATION("SequenceUnavailable", sample.sequenceUnavailable);
#undef LIVE_KEY_OBSERVATION
#undef LIVE_KEY_FIELD
    if (okay) okay = controller->setProperty("NativeKeyLiveRevisionEnd", even, 32) &&
        controller->setProperty("NativeKeyLiveRevisionBegin", even, 32);
    if (okay) revision = even;
    return okay;
}
} // namespace IwxLiveKey
#endif
