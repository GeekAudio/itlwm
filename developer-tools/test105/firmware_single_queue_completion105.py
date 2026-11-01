"""Offline, independent queue-completion evidence; never changes exact SC match.

The caller must bind this saved scalar cut and the supplied generation/epoch to
the same boot/kext. True means firmware-reported single-queue status SUCCESS,
following the pinned Linux API6/7 queue/SSN contract. It is not proof of peer
CCMP/MIC/replay acceptance, application processing, or AirDrop delivery.
firmware_reported_ack names the Linux SUCCESS-to-TX_STAT_ACK mapping only;
without the address/ACK-policy witness it does not prove a unicast radio ACK.
Generation and epoch are host lifecycle guards, not firmware incarnation echoes.
"""
from __future__ import annotations

PREFIX = "NativeStaCompletion"
REQUIRED_PRESENCE = ((1 << 17) - 1) | sum(1 << bit for bit in (25, 26, 27, 28, 30, 31))


def evaluate(scalars: dict, *, expected_generation: int,
             expected_output_epoch: int) -> dict:
    result = {
        "schema": "firmware-single-queue-completion/v1",
        "firmware_single_queue_completion_success": None,
        "status": "unknown",
        "peer_receipt_proven": False,
        "peer_key_validation_proven": False,
        "airdrop_proven": False,
        "on_air_sequence_proven": False,
        "radio_ack_proven": False,
        "firmware_incarnation_echo_proven": False,
        "original_exact_sc_match_modified": False,
    }

    def unknown(reason):
        return dict(result, reason=reason)

    if (type(expected_generation) is not int or
            not 0 < expected_generation < 0xffffffff or
            type(expected_output_epoch) is not int or
            not 0 < expected_output_epoch < 0xffffffff):
        return unknown("authoritative_context_unavailable")
    if type(scalars) is not dict:
        return unknown("scalar_cut_unavailable")

    def get(name):
        return scalars.get(PREFIX + name)

    # No coercion: bool, strings, missing and negative values are not scalar proof.
    top = ("Schema", "SnapshotVersionBegin", "SnapshotVersionEnd",
           "SnapshotAvailable", "SnapshotComplete", "DroppedCount",
           "RelatedRecordDroppedCount", "RelatedCutLostCount", "OwnerGeneration",
           "PublicationGeneration", "PublicationSource", "PublicationSequence",
           "NextSerial", "TxRspPrefixExtensionSchema", "TxRspVersionLookupGroup",
           "TxRspVersionLookupCommand")
    if any(type(get(name)) is not int or not 0 <= get(name) <= 0xffffffffffffffff
           for name in top):
        return unknown("snapshot_metadata_missing_or_invalid")
    if get("Schema") != 5 or get("TxRspPrefixExtensionSchema") != 1:
        return unknown("unsupported_schema_or_extension")
    revision = get("SnapshotVersionBegin")
    if (not 0 < revision <= 0xffffffff or revision & 1 or
            revision != get("SnapshotVersionEnd") or
            revision != get("PublicationSequence")):
        return unknown("unstable_publication")
    if get("SnapshotAvailable") != 1 or get("SnapshotComplete") != 1:
        return unknown("snapshot_unavailable_or_incomplete")
    if any(get(name) != 0 for name in (
            "DroppedCount", "RelatedRecordDroppedCount", "RelatedCutLostCount")):
        return unknown("observer_or_related_cut_loss")
    if (get("OwnerGeneration") != expected_generation or
            get("PublicationGeneration") != expected_generation or
            get("PublicationSource") != 1):
        return unknown("not_current_ordinary_generation_cut")
    if (get("TxRspVersionLookupGroup") != 1 or
            get("TxRspVersionLookupCommand") != 0x1c):
        return unknown("notification_version_namespace_mismatch")

    names = ("Present", "Kind", "Stage", "TerminalReason", "Serial", "Count",
             "MonotonicNs", "DriverGeneration", "OutputEpoch", "PresenceFlags",
             "RxGroup", "RxCommand", "RxHeaderQid", "RxHeaderIndex",
             "RxPacketLength", "PayloadLength", "FirmwareQid", "QueueIndex",
             "RingCount", "Queued", "Cur", "Tail", "FrameCount", "Ssn",
             "RaTid", "Status", "ResponseFrameControl", "ResponseSequenceControl",
             "TxCommandScanStatus", "TxCommandExpectedCount", "TxCommandScannedCount",
             "TxCommandCandidateCount", "TxCommandCandidateIndex",
             "TxCommandApiGeneration", "TxCommandVersion", "TxCommandFlags",
             "TxCommandOffloadAssist", "SingleSlotTxCommandHeader", "HostOriginState",
             "HostOriginCookie", "HostOriginSlotGeneration", "HostOriginContextGeneration",
             "HostOriginOutputEpoch", "HostOriginIdentityEpoch", "HostOriginAttemptId",
             "HostOriginSource", "HostOriginIndex", "HostOriginFrameControl",
             "HostOriginSequenceControl", "HostOriginTid",
             "TxRspPrefixObservationVersion", "TxRspNotificationVersion")
    e = {name: get("Event0" + name) for name in names}
    if any(type(value) is not int or not 0 <= value <= 0xffffffffffffffff
           for value in e.values()):
        return unknown("event_fields_missing_or_invalid")
    wide = {"Serial", "Count", "MonotonicNs", "HostOriginCookie", "HostOriginSlotGeneration"}
    if any(value > 0xffffffff for name, value in e.items() if name not in wide):
        return unknown("event_field_width_invalid")
    if (e["Present"], e["Kind"], e["Stage"], e["TerminalReason"]) != (1, 0, 1, 8):
        return unknown("not_single_reclaim_completed")
    if (e["Serial"] == 0 or e["Count"] == 0 or e["MonotonicNs"] == 0 or
            e["Serial"] > get("NextSerial")):
        return unknown("event_identity_unavailable")
    presence = e["PresenceFlags"]
    if ((presence & REQUIRED_PRESENCE) != REQUIRED_PRESENCE or
            presence & sum(1 << bit for bit in range(17, 25))):
        return unknown("required_presence_missing_or_conflicting")
    if (e["DriverGeneration"] != expected_generation or
            e["HostOriginContextGeneration"] != expected_generation or
            e["OutputEpoch"] != expected_output_epoch or
            e["HostOriginOutputEpoch"] != expected_output_epoch or
            e["HostOriginIdentityEpoch"] == 0xffffffff):
        return unknown("generation_epoch_or_identity_ambiguous")
    if (e["TxRspPrefixObservationVersion"] != 1 or
            e["TxRspNotificationVersion"] != 7 or
            e["TxCommandApiGeneration"] != 3 or e["TxCommandVersion"] != 10):
        return unknown("gen3_command10_response7_not_proven")
    if (e["RxGroup"] != 0 or e["RxCommand"] != 0x1c or
            e["FrameCount"] != 1 or e["PayloadLength"] < 48 or
            e["RxPacketLength"] != e["PayloadLength"] + 4):
        return unknown("response_header_or_payload_layout_invalid")
    n, tail, boundary = e["RingCount"], e["Tail"], e["QueueIndex"]
    if (not 2 <= n <= 1024 or n & (n - 1) or
            not 0 <= tail < n or not 0 <= boundary < n or
            e["Queued"] != 1 or e["Cur"] != boundary or
            (boundary + n - tail) % n != 1 or e["Ssn"] > 0xfff or
            (e["Ssn"] & (n - 1)) != boundary):
        return unknown("not_unique_one_outstanding_exclusive_interval")
    if (not 0 <= e["FirmwareQid"] <= 0xff or
            e["RxHeaderQid"] != e["FirmwareQid"] or
            e["RxHeaderIndex"] != (tail & 0xff)):
        return unknown("raw_response_header_not_bound_to_single_slot")
    if (e["HostOriginState"] != 2 or e["HostOriginIndex"] != tail or
            e["TxCommandCandidateIndex"] != tail or
            e["TxCommandScanStatus"] != 1 or e["TxCommandExpectedCount"] != 1 or
            e["TxCommandScannedCount"] != 1 or
            e["HostOriginCookie"] == 0 or e["HostOriginSlotGeneration"] == 0 or
            e["HostOriginAttemptId"] == 0 or e["HostOriginSource"] not in (1, 2) or
            e["HostOriginTid"] > 15):
        return unknown("unique_current_host_origin_not_proven")
    for field in ("HostOriginFrameControl", "HostOriginSequenceControl",
                  "ResponseFrameControl", "ResponseSequenceControl"):
        if e[field] > 0xffff:
            return unknown("frame_header_width_invalid")
    if (e["RaTid"] > 0xff or e["TxCommandFlags"] > 0xffff or
            (e["RaTid"] & 0xf) != e["HostOriginTid"]):
        return unknown("command_or_response_scalar_width_invalid")
    packed = (e["HostOriginFrameControl"] << 16) | e["HostOriginSequenceControl"]
    if packed != e["SingleSlotTxCommandHeader"]:
        return unknown("raw_command_header_conflicts_with_host_origin")
    exact = (e["HostOriginFrameControl"] == e["ResponseFrameControl"] and
             e["HostOriginSequenceControl"] == e["ResponseSequenceControl"])
    count = e["TxCommandCandidateCount"]
    if (count not in (0, 1) or bool(count) != bool(presence & (1 << 29)) or
            bool(count) != exact):
        return unknown("original_exact_tuple_evidence_inconsistent")
    if e["Status"] != 1:
        return unknown("firmware_raw_status_not_success1")

    return dict(result, status="proven", reason="api7_single_queue_status_success",
                firmware_single_queue_completion_success=True,
                firmware_reported_ack=True, exact_response_tuple_match_observed=exact,
                exact_sequence_control_equal_observed=(
                    e["HostOriginSequenceControl"] == e["ResponseSequenceControl"]),
                event_serial=e["Serial"], queue_id=e["FirmwareQid"],
                host_slot=tail, exclusive_boundary=boundary,
                host_cookie=e["HostOriginCookie"], host_attempt=e["HostOriginAttemptId"],
                host_slot_generation=e["HostOriginSlotGeneration"],
                host_sequence_control=e["HostOriginSequenceControl"],
                response_sequence_control=e["ResponseSequenceControl"],
                generation=expected_generation, output_epoch=expected_output_epoch)
