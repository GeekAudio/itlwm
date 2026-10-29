#!/usr/bin/env python3
"""Source-contract checks for Test072 Probe-side native DATA TX telemetry."""
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"
TRACE = ROOT / "native/awdl_data_tx_trace.hpp"
ACTION = ROOT / "itlwm/hal_iwx/ItlIwxP2PAction.hpp"
DATA_OBSERVATION = ROOT / "native/awdl_data_tx_observation.hpp"


def slice_between(source, start, end):
    begin = source.index(start)
    finish = source.index(end, begin + len(start))
    return source[begin:finish]


def consumption_body(source, function_name, end_marker):
    body = slice_between(source, function_name, end_marker)
    begin = body.index("if (consumed) {")
    return body[begin:body.index("\n    }", begin) + 6]


def main():
    probe = PROBE.read_text()
    trace = TRACE.read_text()
    action = ACTION.read_text()
    data_observation = DATA_OBSERVATION.read_text()

    recorder = slice_between(
        probe,
        "static void recordNativeDataTxConsumption(",
        "static mbuf_t takeDiscoveryPacketPsfNextSlot(",
    )
    assert "owner->tahoeP2pOnMainGate()" in recorder
    assert "identity.token = head.token;" in recorder
    assert "identity.powerGeneration = head.generation;" in recorder
    assert "identity.diagnosticGeneration = run->contextGeneration;" in recorder
    assert "trace.beginToken(identity, head.bornUs, head.queryClass," in recorder
    assert "head.eligible)" in recorder
    assert "trace.markDequeued(identity, dequeuedAtUs)" in recorder
    assert "trace.markEncodeFailure(head.token, EINVAL, failedAtUs)" in recorder
    assert "setProperty(" not in recorder
    assert "mbuf_copydata" not in recorder
    assert "return" not in recorder.split("trace.beginToken", 1)[1].split(
        "const uint64_t dequeuedAtUs", 1)[1]

    psf = consumption_body(
        probe,
        "static mbuf_t takeDiscoveryPacketPsfNextSlot(",
        "static mbuf_t takeDiscoveryPacketMifCurrent(",
    )
    mif = consumption_body(
        probe,
        "static mbuf_t takeDiscoveryPacketMifCurrent(",
        "static mbuf_t takeDiscoveryPacket(",
    )
    for consume in (psf, mif):
        assert "recordNativeDataTxConsumption(run, head, packet != nullptr);" in consume
        assert "run->discoveryPacketToken = head.token;" in consume
    psf_function = slice_between(
        probe,
        "static mbuf_t takeDiscoveryPacketPsfNextSlot(",
        "static mbuf_t takeDiscoveryPacketMifCurrent(",
    )
    mif_function = slice_between(
        probe,
        "static mbuf_t takeDiscoveryPacketMifCurrent(",
        "static mbuf_t takeDiscoveryPacket(",
    )
    assert "NativeAwdlBSD::nextDiscoveryTx" in psf_function
    assert "NativeAwdlBSD::nextDiscoveryTx" in mif_function

    submit_at = probe.index("const int result=iwx_tahoe_p2p_action_tx_submit(")
    start_at = probe.rfind("markSubmitCallStart(token, submitStartUs)", 0, submit_at)
    end_at = probe.index("markSubmitCallEnd(token, result, submitEndUs)", submit_at)
    assert start_at >= 0 and start_at < submit_at < end_at
    submit_call = probe[submit_at:probe.index("// Quarantine alone", submit_at)]
    assert "packet,token" in submit_call
    assert ", nullptr," in submit_call  # Existing control TimeEvidence stays separate.
    assert "markCancelled(token, EIO, cancelledAtUs)" in probe[submit_at:end_at + 5000]
    assert probe.rfind("if (discoveryPacket)", 0, start_at) >= 0
    assert "if (discoveryPacket)" in probe[submit_at:end_at]
    assert "if (discoveryPacket && !doorbellIssued && result == 0)" in probe[end_at:end_at + 3000]

    publisher = slice_between(
        probe,
        "static void publishNativeP2PDataTxTraceOnMainGate(",
        "static IOReturn publishNativeP2PDataTxTraceAction(",
    )
    gate_at = publisher.index("tahoeP2pOnMainGate()")
    early_probe_snapshot_at = publisher.index(
        "captureNativeP2PPublicationProbeSnapshot(owner, &probeBefore)")
    allowed_probe_state_at = publisher.index(
        "nativeP2PPublicationProbeStateAllowed(", early_probe_snapshot_at)
    controller_at = publisher.index("tahoeP2pController()")
    assert gate_at < early_probe_snapshot_at < allowed_probe_state_at < controller_at
    assert "nativeP2PPublicationBusy(owner)" in publisher
    assert "captureNativeP2PPublicationTxResources(owner, &txResources)" in publisher
    assert publisher.index("shouldDeferBulkProperties(") < publisher.index(
        "trace.mergeStopTap()")
    assert publisher.index("trace.mergeStopTap()") < publisher.index(
        "trace.mergeTxResponseTap()")
    assert "nativeP2PPublicationStateStillStable(" in publisher
    assert "sc_p2p_roc" not in publisher
    assert "nativeP2pActionTx_.state" not in publisher
    assert "nativeP2pTxQueue_.submissionBusy" not in publisher
    assert "captureP2PTxSnapshot" not in publisher
    assert "nativeP2pProbeGeneration_" not in publisher
    assert "sc_generation" not in publisher
    assert "sc_tx_output_epoch" not in publisher  # sampled by the bounded helper
    assert "sc_tx_rate_generation" not in publisher  # sampled by the bounded helper
    tx_resource_snapshot = slice_between(
        probe,
        "static bool captureNativeP2PPublicationTxResources(",
        "static bool sameNativeP2PPublicationTxResources(",
    )
    assert "IORecursiveLockHaveLock(lifecycleLock)" in tx_resource_snapshot
    assert "IORecursiveLockTryLock(lifecycleLock)" in tx_resource_snapshot
    assert "IOSimpleLockTryLock(txLock)" in tx_resource_snapshot
    assert "IOSimpleLockLockDisableInterrupt" not in tx_resource_snapshot
    assert tx_resource_snapshot.index("IORecursiveLockTryLock(lifecycleLock)") < tx_resource_snapshot.index(
        "IOSimpleLockTryLock(txLock)")
    assert "queue.stateLock == txLock" in tx_resource_snapshot
    assert "queue.pendingRing" in tx_resource_snapshot
    assert "queue.retainedRing" in tx_resource_snapshot
    assert "queue.submissionBusy" in tx_resource_snapshot
    assert "queue.lifecycle.snapshot()" in tx_resource_snapshot
    probe_snapshot_helper = slice_between(
        probe,
        "static bool captureNativeP2PPublicationProbeSnapshot(",
        "static bool sameNativeP2PPublicationProbeSnapshot(",
    )
    assert "owner->nativeResetTrace_.read(&reset)" in probe_snapshot_helper
    assert "owner->nativeP2pProbe_.snapshot()" in probe_snapshot_helper
    assert "sc_tx_output_epoch" in probe_snapshot_helper
    assert "sc_tx_rate_generation" in probe_snapshot_helper
    stop_merge_at = publisher.index("trace.mergeStopTap()")
    response_merge_at = publisher.index("trace.mergeTxResponseTap()")
    bulk_gate_at = publisher.index("shouldDeferBulkProperties(")
    assert publisher.index("if (!captureNativeP2PPublicationProbeSnapshot(") < bulk_gate_at
    assert "return;" in publisher[publisher.index(
        "if (!captureNativeP2PPublicationProbeSnapshot("):controller_at]
    assert publisher.index("setNativeP2PDataTxTraceProperty(") > bulk_gate_at
    assert gate_at < early_probe_snapshot_at < bulk_gate_at < stop_merge_at < response_merge_at
    assert response_merge_at < publisher.index(
        "trace.publicationSnapshot(&publicationBefore)")
    assert publisher.index("trace.publicationSnapshot(&publicationBefore)") < publisher.index(
        "sourceVersion = trace.snapshotVersion()")
    assert "trace.publicationSnapshot(&publicationBefore)" in publisher
    assert "Ledger::canClosePublication(" in publisher
    assert "NativeP2PDataTxTraceSnapshotComplete" in publisher
    assert "NativeP2PDataTxTraceCoverageUnknown" in publisher
    assert "NativeP2PDataTxTraceResponseTapMergeStatus" in publisher
    assert "NativeP2PDataTxTraceStopTapMergeStatus" in publisher
    assert "NativeP2PDataTxTraceTxRspTapActivePublicationSequence" in publisher
    assert "NativeP2PDataTxTraceTxRspTapActiveToken" in publisher
    assert "NativeP2PDataTxTraceStopTapActivePublicationSequence" in publisher
    assert "NativeP2PDataTxTraceStopTapActiveToken" in publisher
    transient_at = publisher.index("if (tapsTransient)")
    assert bulk_gate_at < transient_at
    assert "sourceVersion + 1u" in publisher[transient_at:]
    assert "txResources.unsettled" in publisher
    assert "sessionCleanupAllowed = session.cleanupAllowed" in publisher
    assert "rxTrace.ownerPresent != 0" in publisher
    assert "rxTrace.active != 0" in publisher
    assert "rxTrace.producerClosed != 0" in publisher
    gate_header = ROOT / "native/awdl_data_tx_publish_gate.hpp"
    assert gate_header.exists()
    assert "trace.hasPublishedSnapshot()" in publisher
    assert "sourceVersion = trace.snapshotVersion()" in publisher
    assert "sourceRevision = publicationBefore.revision" in publisher
    assert publisher.index("SnapshotVersionBegin\", writingVersion") < publisher.index(
        "setHeader(\"NativeP2PDataTxTraceSchemaVersion")
    assert "NativeP2PDataTxTraceRevision" in publisher
    assert "NativeP2PDataTxTraceOwnerPresent" in publisher
    assert "NativeP2PDataTxTraceOwnerSerial" in publisher
    assert "NativeP2PDataTxTraceFirmwareEchoesFullIdentity\", 0" in publisher
    assert "trace.snapshot(index, &record)" in publisher
    assert 'setRecord("RecordPresent"' in publisher
    assert 'setRecord("Used"' in publisher
    assert 'setRecord("StagePresenceFlags"' in publisher
    assert 'setRecord("Token"' in publisher
    for field in (
        "DiagnosticGeneration", "ContextGeneration", "PowerGeneration",
        "StationGeneration", "RocGeneration", "QueueBornUs", "DequeuedUs",
        "SubmitCallStartUs", "SubmitCallEndUs", "FinalWireUs",
        "RingReservedUs", "DescriptorReadyUs", "DoorbellMarkedUs",
        "DoorbellIssuedUs", "TxRspTapUs", "CompletionUs", "CancelUs",
        "UnknownUs", "EncodeFailureUs", "StopUs", "SequenceControl", "MpduLength",
        "QueueId", "DescriptorIndex", "QueueMetadataPresent",
        "QueryClass", "Eligible", "TxRspRxHeaderIndex",
        "TxRspValidFields", "ResponseScalarMatchMask",
        "SubmitCallResult",
        "AssociationStrength", "FirmwareEchoesFullIdentity",
        "AmbiguousLateQueueUnknown", "StopNewGeneration", "StopReason",
        "StopProvenDrain",
    ):
        assert f'setRecord("{field}"' in publisher, field
    assert "trace.snapshotVersion() != sourceVersion" in publisher
    assert "trace.revision() != sourceRevision" in publisher
    end_at = publisher.index('"NativeP2PDataTxTraceSnapshotVersionEnd"')
    final_begin_at = publisher.index('"NativeP2PDataTxTraceSnapshotVersionBegin", publishedVersion')
    mark_at = publisher.index("trace.markPublishedSnapshotVersion(sourceVersion)")
    invalid_if_at = publisher.index("if (!writesOk ||")
    assert invalid_if_at < end_at
    assert end_at < final_begin_at < mark_at
    assert publisher.rfind("return;", 0, mark_at) > final_begin_at
    for secret in ("SourceAddress", "DestinationAddress", "SSID", "Payload"):
        assert secret not in publisher

    state_publisher = slice_between(
        probe,
        "void ItlIwx::tahoeP2pPublishProbeState()",
        "#endif // AIRPORT_TAHOE",
    )
    assert state_publisher.index("nativeP2PPublicationBusy(this)") < state_publisher.index(
        "tahoeP2pPublishRocState()")
    assert state_publisher.index("nativeP2PPublicationBusy(this)") < state_publisher.index(
        "requestNativeP2PDataTxTracePublish(this)")
    assert "requestNativeP2PDataTxTracePublish(this);" in state_publisher
    assert "#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)" in state_publisher
    assert "ITL_NATIVE_AWDL_TX_EVIDENCE_25G332" in state_publisher
    request_publisher = slice_between(
        probe,
        "static void requestNativeP2PDataTxTracePublish(ItlIwx *owner)",
        "#endif",
    )
    assert "gate->attemptAction(publishNativeP2PDataTxTraceAction, owner)" in request_publisher
    assert "gate->runAction(" not in request_publisher
    assert "next periodic tick retries publication" in request_publisher
    assert "kEncodeFailure = 1u << 13" in trace
    assert "struct RecordSnapshot" in trace
    assert "uint8_t queryClass;" in trace
    assert "bool queueEligible;" in trace
    assert "bool queueMetadataPresent;" in trace
    assert "uint64_t queueBornUs" in trace
    assert "uint64_t finalWireUs" in trace
    assert "uint64_t submitCallStartUs" in trace
    assert "uint64_t submitCallEndUs" in trace
    assert "bool firmwareEchoesFullIdentity" in trace
    assert "NativeAwdlDataTxTrace::Ledger dataTxTrace;" in action
    for name, value in (
        ("Unknown", 0), ("LegacyUnicastReply", 1),
        ("QuUnicastPreferred", 2), ("QmMulticast", 3), ("Other", 4),
    ):
        assert f"{name} = {value}" in data_observation

    # These markers are deliberately observational, never control-flow inputs.
    assert not re.search(r"if\s*\([^)]*dataTxTrace", probe)
    assert "windowEvidence" not in recorder

    # The source uses the same standalone decision exercised by the C++ fixture.
    assert "NativeAwdlDataTxPublication::shouldDeferBulkProperties(" in publisher


if __name__ == "__main__":
    main()
