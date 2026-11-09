// SPDX-License-Identifier: GPL-2.0-only
// Offline format fixture built from the production QWR1/facts/status encoders,
// TX trace ledger, and completion result enum. This is not runtime evidence.

#include "awdl_data_tx_trace.hpp"
#include "awdl_qm_wire_snapshot.hpp"
#include "p2p_action_tx.hpp"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>

namespace {

using NativeAwdlDataTxTrace::RecordSnapshot;

void emit(const char *key, uint64_t value)
{
    std::cout << key << '=' << value << '\n';
}

void emitHex(const char *key, const uint8_t *bytes, size_t length)
{
    static const char digits[] = "0123456789abcdef";
    std::cout << key << '=';
    for (size_t i = 0; i < length; ++i) {
        std::cout << digits[bytes[i] >> 4] << digits[bytes[i] & 0x0f];
    }
    std::cout << '\n';
}

bool ready(NativeAwdlDataTxTrace::Status status)
{
    return status == NativeAwdlDataTxTrace::Status::Ready;
}

void emitRecord(uint32_t slot, const RecordSnapshot &record)
{
#define EMIT_RECORD(field, expression) \
    emit((std::string("record.") + std::to_string(slot) + "." #field).c_str(), \
         record.present ? static_cast<uint64_t>(expression) : 0)
    EMIT_RECORD(RecordPresent, 1);
    EMIT_RECORD(Used, 1);
    EMIT_RECORD(RecordSerial, record.recordSerial);
    EMIT_RECORD(Token, record.identity.token);
    EMIT_RECORD(DiagnosticGeneration, record.identity.diagnosticGeneration);
    EMIT_RECORD(ContextGeneration, record.identity.contextGeneration);
    EMIT_RECORD(PowerGeneration, record.identity.powerGeneration);
    EMIT_RECORD(StationGeneration, record.identity.stationGeneration);
    EMIT_RECORD(RocGeneration, record.identity.rocGeneration);
    EMIT_RECORD(StagePresenceFlags, record.stageMask);
    EMIT_RECORD(QueueMetadataPresent, record.queueMetadataPresent ? 1 : 0);
    EMIT_RECORD(QueryClass, record.queryClass);
    EMIT_RECORD(Eligible, record.queueEligible ? 1 : 0);
    EMIT_RECORD(QueueBornUs, record.queueBornUs);
    EMIT_RECORD(DequeuedUs, record.dequeuedUs);
    EMIT_RECORD(SubmitCallStartUs, record.submitCallStartUs);
    EMIT_RECORD(FinalWireUs, record.finalWireUs);
    EMIT_RECORD(RingReservedUs, record.ringReservedUs);
    EMIT_RECORD(DescriptorReadyUs, record.descriptorReadyUs);
    EMIT_RECORD(DoorbellMarkedUs, record.doorbellMarkedUs);
    EMIT_RECORD(DoorbellIssuedUs, record.doorbellIssuedUs);
    EMIT_RECORD(TxRspTapUs, record.txRspTapUs);
    EMIT_RECORD(CompletionUs, record.completionUs);
    EMIT_RECORD(CancelUs, record.cancelUs);
    EMIT_RECORD(UnknownUs, record.unknownUs);
    EMIT_RECORD(EncodeFailureUs, record.encodeFailureUs);
    EMIT_RECORD(StopUs, record.stopUs);
    EMIT_RECORD(SubmitCallEndUs, record.submitCallEndUs);
    EMIT_RECORD(FrameControl, record.frameControl);
    EMIT_RECORD(SequenceControl, record.sequenceControl);
    EMIT_RECORD(MpduLength, record.mpduLength);
    EMIT_RECORD(PacketCount, record.packetCount);
    EMIT_RECORD(IPv6Length, record.ipv6Length);
    EMIT_RECORD(QueueId, record.queueId);
    EMIT_RECORD(RingSize, record.ringSize);
    EMIT_RECORD(DescriptorIndex, record.descriptorIndex);
    EMIT_RECORD(TxRspQueueId, record.txRspQueueId);
    EMIT_RECORD(TxRspRxHeaderIndex, record.txRspRxHeaderIndex);
    EMIT_RECORD(TxRspSequenceControl, record.txRspSequenceControl);
    EMIT_RECORD(TxRspByteCount, record.txRspByteCount);
    EMIT_RECORD(TxRspFrameControl, record.txRspFrameControl);
    EMIT_RECORD(TxRspStatus, record.txRspStatus);
    EMIT_RECORD(TxRspRaTid, record.txRspRaTid);
    EMIT_RECORD(TxRspScdSsn, record.txRspScdSsn);
    EMIT_RECORD(TxRspValidFields, record.txRspValidFields);
    EMIT_RECORD(SubmitCallResult, record.submitCallResult);
    EMIT_RECORD(CompletionResult, record.completionResult);
    EMIT_RECORD(CancellationReason, record.cancellationReason);
    EMIT_RECORD(UnknownReason, record.unknownReason);
    EMIT_RECORD(EncodeFailureResult, record.encodeFailureResult);
    EMIT_RECORD(StopNewGeneration, record.stopNewGeneration);
    EMIT_RECORD(StopReason, record.stopReason);
    EMIT_RECORD(StopProvenDrain, record.stopProvenDrain ? 1 : 0);
    EMIT_RECORD(ResponseMismatchMask, record.responseMismatchMask);
    EMIT_RECORD(ResponseScalarMatchMask, record.responseScalarMatchMask);
    EMIT_RECORD(AssociationStrength, record.associationStrength);
    EMIT_RECORD(TxRspHandlerDisposition, record.txRspHandlerDisposition);
    EMIT_RECORD(FirmwareEchoesFullIdentity,
                record.firmwareEchoesFullIdentity ? 1 : 0);
    EMIT_RECORD(AmbiguousLateQueueUnknown,
                record.ambiguousLateQueueUnknown ? 1 : 0);
    EMIT_RECORD(ResponseCandidateSeen, record.responseCandidateSeen ? 1 : 0);
#undef EMIT_RECORD
}

} // namespace

int main()
{
    constexpr uint64_t token = 101;
    constexpr uint64_t context = 4;
    constexpr uint64_t power = 7;
    constexpr uint64_t station = 18;
    constexpr uint64_t roc = 4;
    constexpr uint64_t hostPre = 270000;
    constexpr uint64_t rawDoorbell = 270100;
    constexpr uint64_t rawFinish = 270200;

    NativeAwdlQmWireSnapshot::Raw::Record raw{};
    raw.identity = {token, context, power, station, roc};
    raw.stationId = 9;
    raw.queueId = 4;
    raw.ringSize = 256;
    raw.descriptorIndex = 0;
    raw.sequenceControl = 0x20;
    raw.frameControl = 0x0808;

    uint8_t command[56];
    uint8_t mpduHeader[24];
    uint8_t payload[72];
    memset(command, 'C', sizeof(command));
    memset(mpduHeader, 'H', sizeof(mpduHeader));
    memset(payload, 'P', sizeof(payload));
    if (!NativeAwdlQmWireSnapshot::Raw::captureBytes(
            &raw, command, sizeof(command), mpduHeader, sizeof(mpduHeader),
            payload, sizeof(payload), 0))
        return 2;
    raw.flags |= NativeAwdlQmWireSnapshot::Raw::kStageAccepted;
    raw.stage = NativeAwdlQmWireSnapshot::Raw::Stage::kStagedAwaitingPublish;
    raw.doorbellUs = rawDoorbell;
    raw.finishUs = rawFinish;

    NativeAwdlQmWireSnapshot::Record facts{};
    facts.header = {0x0808, 0x20, 96, 0, 24,
                    NativeAwdlQmWireSnapshot::kHeaderValid |
                        NativeAwdlQmWireSnapshot::kNoDs |
                        NativeAwdlQmWireSnapshot::kAddress2MatchesLocal,
                    true};
    facts.token = token;
    facts.contextGeneration = context;
    facts.powerGeneration = power;
    facts.stationGeneration = station;
    facts.rocToken = roc;
    facts.stationId = 9;
    facts.queueId = 4;
    facts.ringSize = 256;
    facts.descriptorIndex = 0;
    facts.hostPreDoorbellUs = hostPre;

    const NativeAwdlQmWireSnapshot::Raw::EncodedSnapshot rawEncoded =
        NativeAwdlQmWireSnapshot::Raw::encode(raw);
    const NativeAwdlQmWireSnapshot::EncodedSnapshot factsEncoded =
        NativeAwdlQmWireSnapshot::encode(facts);
    const NativeAwdlQmWireSnapshot::Raw::EncodedStatus statusEncoded =
        NativeAwdlQmWireSnapshot::Raw::encodeStatus({
            NativeAwdlQmWireSnapshot::Raw::Stage::kPublished, raw.identity});
    emitHex("raw_hex", rawEncoded.bytes, sizeof(rawEncoded.bytes));
    emitHex("facts_hex", factsEncoded.bytes, sizeof(factsEncoded.bytes));
    emitHex("status_hex", statusEncoded.bytes, sizeof(statusEncoded.bytes));

    NativeAwdlDataTxTrace::Identity traceIdentity{
        token, 4, context, power, station, roc};
    NativeAwdlDataTxTrace::Ledger ledger;
    const uint32_t completionResult = static_cast<uint32_t>(
        IntelP2PActionTx::Result::kCompletion);
    if (!ready(ledger.beginToken(traceIdentity, 269000, 1, true)) ||
        !ready(ledger.markDequeued(traceIdentity, 269100)) ||
        !ready(ledger.markSubmitCallStart(token, 269200)) ||
        !ready(ledger.markFinalWire(token, context, power, roc, 0x0808,
                                   0x20, 96, 1, 72, 269300)) ||
        !ready(ledger.markRing(token, context, power, roc, 4, 256, 0, 269400)) ||
        !ready(ledger.markDescriptorReady(token, 269500)) ||
        !ready(ledger.markDoorbellMarked(token, 269900)) ||
        !ready(ledger.markDoorbellIssued(token, 270150)))
        return 3;

    const uint32_t responseFields =
        NativeAwdlDataTxTrace::kResponseQueueValid |
        NativeAwdlDataTxTrace::kResponseSequenceValid |
        NativeAwdlDataTxTrace::kResponseByteCountValid |
        NativeAwdlDataTxTrace::kResponseFrameControlValid |
        NativeAwdlDataTxTrace::kResponseStatusValid |
        NativeAwdlDataTxTrace::kResponseRaTidValid |
        NativeAwdlDataTxTrace::kResponseScdSsnValid;
    if (!ledger.captureTxResponseTap(token, 270300, responseFields, 4, 0,
                                     0x20, 96, 0x0808, 1, 48, 1))
        return 4;
    const NativeAwdlDataTxTrace::Status responseMerge =
        ledger.mergeTxResponseTap();
    if (!ready(responseMerge) ||
        !ready(ledger.markTxResponseHandlerDisposition(token, 1)) ||
        !ready(ledger.markCompletion(token, completionResult, 270500)) ||
        !ready(ledger.markSubmitCallEnd(token, 0, 270600)))
        return 5;

    emit("completion_enum_ready", static_cast<uint32_t>(
        IntelP2PActionTx::Result::kReady));
    emit("completion_enum_frame_failed", static_cast<uint32_t>(
        IntelP2PActionTx::Result::kFrameFailed));
    emit("completion_enum_completion", completionResult);

    NativeAwdlDataTxTrace::PublicationSnapshot publication{};
    const NativeAwdlDataTxTrace::Status stopMerge = ledger.mergeStopTap();
    ledger.publicationSnapshot(&publication);
    const uint64_t version = ledger.snapshotVersion();
    if (!publication.revisionStable || (version & 1u) ||
        !ledger.markPublishedSnapshotVersion(version))
        return 6;
    const uint64_t publishedVersion = version ? version : 2;
    emit("header.SnapshotVersionBegin", publishedVersion);
    emit("header.SnapshotVersionEnd", publishedVersion);
    emit("header.SnapshotComplete", publication.coverageUnknown ? 0 : 1);
    emit("header.SchemaVersion", 1);
    emit("header.Revision", publication.revision);
    emit("header.OwnerPresent", publication.ownerPresent ? 1 : 0);
    emit("header.OwnerSerial", publication.owner.diagnosticGeneration);
    emit("header.OwnerDiagnosticGeneration",
         publication.owner.diagnosticGeneration);
    emit("header.OwnerContextGeneration", publication.owner.contextGeneration);
    emit("header.OwnerPowerGeneration", publication.owner.powerGeneration);
    emit("header.OwnerStationGeneration", publication.owner.stationGeneration);
    emit("header.OwnerRocGeneration", publication.owner.rocGeneration);
    emit("header.Count", ledger.count());
    emit("header.DroppedCount", ledger.droppedCount());
    emit("header.CoverageUnknown", publication.coverageUnknown ? 1 : 0);
    emit("header.ResponseTapMergeStatus", static_cast<uint32_t>(responseMerge));
    emit("header.StopTapMergeStatus", static_cast<uint32_t>(stopMerge));
    ledger.publicationSnapshot(&publication);
    const auto emitTap = [](const char *prefix,
                            const NativeAwdlDataTxTrace::TapPublicationSnapshot &tap) {
        const std::string base = std::string("header.") + prefix;
        emit((base + "State").c_str(), static_cast<uint32_t>(tap.state));
        emit((base + "Sequence").c_str(), tap.sequence);
        emit((base + "ConsumedSequence").c_str(), tap.consumedSequence);
        emit((base + "DroppedCount").c_str(), tap.droppedCount);
        emit((base + "ActivePublicationSequence").c_str(),
             tap.activePublicationSequence);
        emit((base + "ActiveToken").c_str(), tap.activeToken);
    };
    emitTap("TxRspTap", publication.txResponse);
    emitTap("StopTap", publication.stop);
    emit("header.FirmwareEchoesFullIdentity", 0);
    emit("header.AssociationStrengthCandidateOnly",
         static_cast<uint32_t>(NativeAwdlDataTxTrace::AssociationStrength::CandidateOnly));
    emit("header.AssociationStrengthLocalScalarMatch",
         static_cast<uint32_t>(NativeAwdlDataTxTrace::AssociationStrength::LocalScalarFieldsMatch));
    emit("header.AssociationStrengthExistingHandlerAccepted",
         static_cast<uint32_t>(NativeAwdlDataTxTrace::AssociationStrength::ExistingHandlerAccepted));

    for (uint32_t slot = 0; slot < NativeAwdlDataTxTrace::kRecordCapacity; ++slot) {
        RecordSnapshot record{};
        if (!ledger.snapshot(slot, &record))
            return 7;
        emitRecord(slot, record);
    }
    return 0;
}
