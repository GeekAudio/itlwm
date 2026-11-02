"""Decode the independent, numeric NativeKeyLive publication. No ACK join."""
PREFIX = "NativeKeyLive"
HEADER = {
    "Schema": 32, "RevisionBegin": 32, "RevisionEnd": 32,
    "SampleMonotonicNs": 64, "OwnerGeneration": 32,
    "HctxFrozen": 32, "HctxManualLatched": 32,
    "OwnerOutputEpoch": 32, "OwnerContextStable": 32,
}
ENTRY = {
    "Serial": 64, "MonotonicNs": 64, "DriverGeneration": 32,
    "FirmwareGeneration": 32, "Phase": 32, "Source": 32,
    "CommandId": 32, "GroupId": 32, "Version": 32,
    "Qid": 32, "Index": 32, "HeaderSequence": 32,
    "Flags": 32, "Result": 32, "ResultDetail": 32,
    "PacketLength": 32, "PayloadLength": 32,
}
OBSERVATION = {"Present": 32, "Stable": 32,
               "DroppedCount": 32, "DroppedSerial": 64,
               "OriginSubmitSerial": 64, **ENTRY}
OBSERVATION_V1 = {key: value for key, value in OBSERVATION.items()
                  if key != "OriginSubmitSerial"}
SEQUENCE_ROLES = ("RxSequence", "TxSequence", "SequenceUnavailable")
ROLES_V1 = ("Submit", "Response")
ROLES_V2 = ROLES_V1 + SEQUENCE_ROLES
FIELDS_V1 = {**HEADER, **{role + key: bits for role in ROLES_V1
                          for key, bits in OBSERVATION_V1.items()}}
FIELDS_V2 = {**HEADER, **{role + key: bits for role in ROLES_V2
                          for key, bits in OBSERVATION.items()}}
FIELDS = FIELDS_V2

FLAG_KEY_SEQUENCE_VALUE_PRESENT = 1 << 13
FLAG_KEY_SEQUENCE_API_VERSION_PRESENT = 1 << 14
FLAG_KEY_SEQUENCE_MAX_TID_PRESENT = 1 << 15
FLAG_KEY_SEQUENCE_MAX_TID_SHIFT = 20
FLAG_KEY_SEQUENCE_MAX_TID_MASK = 0x0f << FLAG_KEY_SEQUENCE_MAX_TID_SHIFT
FLAG_ORIGIN_GENERATION_PRESENT = 1 << 17
FLAG_ORIGIN_GENERATION_CHANGED = 1 << 18
FLAG_ORIGIN_SUBMIT_SERIAL_PRESENT = 1 << 19

# Submit.Version is the command-header version. Sequence-row Version carries
# the ADD_STA_KEY CMD_VERSIONS API version, so compare it only between sequence
# rows, not between a Submit row and its sequence observation.
SUBMIT_SEQUENCE_COMMAND_FIELDS = (
    "CommandId", "GroupId", "Qid", "Index", "HeaderSequence")
SUBMIT_SEQUENCE_IDENTITY_FIELDS = (
    "DriverGeneration", *SUBMIT_SEQUENCE_COMMAND_FIELDS)
SEQUENCE_PAIR_IDENTITY_FIELDS = SUBMIT_SEQUENCE_IDENTITY_FIELDS + ("Version",)


def parse_live_key(service: dict) -> dict:
    schema = service.get(PREFIX + "Schema")
    result = {"status": "not_published", "scalars": {},
              "command_response_match": "unknown",
              "key_install_result": "unknown",
              "key_install_success_proven": False,
              "peer_ack_proven": False}
    if schema is None:
        return result
    if type(schema) is not int or schema not in (1, 2):
        result["status"] = "unsupported_schema"
        return result

    fields = FIELDS_V1 if schema == 1 else FIELDS_V2
    roles = ROLES_V1 if schema == 1 else ROLES_V2
    observation_fields = OBSERVATION_V1 if schema == 1 else OBSERVATION
    raw = {key: service.get(PREFIX + key) for key in fields}
    # Retain only fixed-width numeric allowlisted fields. No arbitrary strings,
    # properties, addresses, secrets, or firmware packet bodies are exported.
    scalars = {key: value for key, value in raw.items()
               if type(value) is int and 0 <= value < 1 << fields[key]}
    result["scalars"] = scalars
    if len(scalars) != len(fields):
        result["status"] = "missing_or_invalid_fields"
        return result
    if raw["Schema"] != schema:
        result["status"] = "missing_or_invalid_fields"
        return result
    begin, end = raw["RevisionBegin"], raw["RevisionEnd"]
    if begin == 0 or begin != end or begin & 1:
        result["status"] = "unstable_publication"
        return result
    if (raw["SampleMonotonicNs"] == 0 or raw["OwnerGeneration"] == 0 or
            raw["HctxFrozen"] not in (0, 1) or raw["HctxManualLatched"] not in (0, 1) or
            raw["OwnerContextStable"] not in (0, 1)):
        result["status"] = "invalid_header"
        return result
    observations = {}
    for role in roles:
        o = {key: raw[role + key] for key in observation_fields}
        if o["Present"] not in (0, 1) or o["Stable"] not in (0, 1):
            result["status"] = "invalid_observation_flags"
            return result
        if not o["Present"]:
            if any(o[key] != 0 for key in ENTRY):
                result["status"] = "absent_observation_has_payload"
                return result
            if o.get("OriginSubmitSerial", 0) != 0:
                result["status"] = "absent_observation_has_origin_serial"
                return result
            observations[role.lower()] = {
                "status": "absent" if o["Stable"] else "unstable_slot"}
            continue
        valid_identity = (o["Stable"] == 1 and o["Serial"] > 0 and
                          0 < o["MonotonicNs"] <= raw["SampleMonotonicNs"] and
                          o["DriverGeneration"] > 0 and o["CommandId"] == 0x17 and
                          o["Qid"] == 0 and o["Index"] <= 255)
        if role == "Submit":
            valid_identity = (valid_identity and o["Source"] == 1 and
                              o["Phase"] == 1 and o["GroupId"] in (0, 1) and
                              o["HeaderSequence"] == o["Index"] and bool(o["Flags"] & (1 << 4)))
        elif role == "Response":
            valid_identity = (valid_identity and o["Source"] == 2 and
                              o["Phase"] in (7, 8) and bool(o["Flags"] & (7 << 10)))
        else:
            expected_phase = {
                "RxSequence": 14,
                "TxSequence": 15,
                "SequenceUnavailable": 16,
            }[role]
            flags = o["Flags"]
            valid_identity = (valid_identity and o["Source"] == 1 and
                              o["Phase"] == expected_phase and
                              o["GroupId"] == 1 and
                              o["HeaderSequence"] == o["Index"] and
                              bool(flags & (1 << 4)) and
                              bool(flags & FLAG_KEY_SEQUENCE_API_VERSION_PRESENT))
            if role in ("RxSequence", "TxSequence"):
                valid_identity = (valid_identity and
                    bool(flags & FLAG_KEY_SEQUENCE_VALUE_PRESENT) and
                    o["Version"] in (2, 3))
                if role == "RxSequence":
                    valid_identity = valid_identity and bool(
                        flags & FLAG_KEY_SEQUENCE_MAX_TID_PRESENT)
                    valid_identity = valid_identity and (
                        (flags & FLAG_KEY_SEQUENCE_MAX_TID_MASK) >>
                        FLAG_KEY_SEQUENCE_MAX_TID_SHIFT) <= 15
                    if valid_identity:
                        o["MaximumTid"] = (
                            (flags & FLAG_KEY_SEQUENCE_MAX_TID_MASK) >>
                            FLAG_KEY_SEQUENCE_MAX_TID_SHIFT)
                else:
                    valid_identity = valid_identity and not bool(
                        flags & FLAG_KEY_SEQUENCE_MAX_TID_PRESENT)
                    valid_identity = valid_identity and not bool(
                        flags & FLAG_KEY_SEQUENCE_MAX_TID_MASK)
            elif flags & FLAG_KEY_SEQUENCE_VALUE_PRESENT:
                valid_identity = False
            elif flags & (FLAG_KEY_SEQUENCE_MAX_TID_PRESENT |
                          FLAG_KEY_SEQUENCE_MAX_TID_MASK):
                valid_identity = False
            origin_serial = o["OriginSubmitSerial"]
            encoded_serial = ((o["PacketLength"] << 32) |
                              o["PayloadLength"])
            serial_present = bool(flags & FLAG_ORIGIN_SUBMIT_SERIAL_PRESENT)
            if serial_present:
                valid_identity = valid_identity and origin_serial > 0 and \
                    origin_serial == encoded_serial
            else:
                valid_identity = valid_identity and origin_serial == 0 and \
                    encoded_serial == 0
        if not valid_identity:
            result["status"] = "invalid_observation_identity"
            return result
        status = "retained_observation"
        bundle_id = o.get("OriginSubmitSerial", 0)
        if role in SEQUENCE_ROLES and (o["Flags"] & FLAG_ORIGIN_GENERATION_CHANGED):
            status = "retained_origin_generation_changed"
        elif role in SEQUENCE_ROLES and not (o["Flags"] & FLAG_ORIGIN_GENERATION_PRESENT):
            status = "retained_origin_generation_unknown"
        elif role in SEQUENCE_ROLES and not bundle_id:
            status = "retained_origin_submit_serial_unknown"
        elif not raw["OwnerContextStable"]:
            status = "retained_context_unstable"
        elif o["DriverGeneration"] != raw["OwnerGeneration"]:
            status = "retained_older_generation"
        if o["DroppedSerial"] > o["Serial"]:
            status = "retained_with_newer_event_lost"
        observed = {
            "status": status, "age_ns": raw["SampleMonotonicNs"] - o["MonotonicNs"],
            "entry": o,
        }
        if role in SEQUENCE_ROLES:
            observed["origin_submit_serial"] = bundle_id or None
            observed["origin_generation_present"] = bool(
                o["Flags"] & FLAG_ORIGIN_GENERATION_PRESENT)
            observed["origin_generation_changed_before_record"] = bool(
                o["Flags"] & FLAG_ORIGIN_GENERATION_CHANGED)
            observed["key_install_success_proven"] = False
            observed["peer_ack_proven"] = False
        observations[role.lower()] = observed

    bundle = {"schema": "test110-key-sequence-bundle/v1",
              "status": "not_assessed",
              "same_origin_submit_serial": False,
              "origin_submit_serial_matches_current_submit": False,
              "sequence_observation_matches_current_submit": False,
              "current_submit_serial": None,
              "current_sequence_unavailable": False,
              "key_install_success_proven": False,
              "peer_ack_proven": False}
    if schema == 2:
        rx = observations.get("rxsequence", {})
        tx = observations.get("txsequence", {})
        unavailable = observations.get("sequenceunavailable", {})
        rx_id = rx.get("origin_submit_serial")
        tx_id = tx.get("origin_submit_serial")
        submit = observations.get("submit", {})
        submit_entry = submit.get("entry", {})
        submit_id = submit_entry.get("Serial") if submit_entry else None
        unavailable_id = unavailable.get("origin_submit_serial")
        bundle["current_submit_serial"] = submit_id
        bundle["origin_submit_serial_matches_current_submit"] = bool(
            submit_id and rx_id and tx_id and rx_id == tx_id == submit_id)
        bundle["sequence_observation_matches_current_submit"] = bool(
            submit_id and submit_id in (rx_id, tx_id, unavailable_id))
        bundle["current_sequence_unavailable"] = bool(
            submit_id and unavailable_id and submit_id == unavailable_id)
        if bundle["current_sequence_unavailable"]:
            unavailable_entry = unavailable.get("entry", {})
            fields_match = all(
                submit_entry.get(key) == unavailable_entry.get(key)
                for key in SUBMIT_SEQUENCE_COMMAND_FIELDS)
            if unavailable.get("origin_generation_present"):
                fields_match = fields_match and (
                    submit_entry.get("DriverGeneration") ==
                    unavailable_entry.get("DriverGeneration"))
            current_sequence_rows_conflict = submit_id in (rx_id, tx_id)
            bundle["status"] = (
                "current_submit_sequence_conflict" if current_sequence_rows_conflict
                else "current_submit_sequence_unavailable" if fields_match
                else "current_submit_identity_conflict")
            bundle["origin_submit_serial"] = submit_id
        elif rx_id and tx_id:
            if rx_id != tx_id:
                bundle["status"] = "different_submit_serials_not_joined"
            else:
                bundle["same_origin_submit_serial"] = True
                bundle["origin_submit_serial"] = rx_id
                rx_entry = rx.get("entry", {})
                tx_entry = tx.get("entry", {})
                same_identity = all(
                    rx_entry.get(key) == tx_entry.get(key)
                    for key in SEQUENCE_PAIR_IDENTITY_FIELDS)
                same_generation = (
                    rx_entry.get("DriverGeneration") ==
                    tx_entry.get("DriverGeneration"))
                changed = (rx.get("origin_generation_changed_before_record") or
                           tx.get("origin_generation_changed_before_record") or
                           not rx.get("origin_generation_present") or
                           not tx.get("origin_generation_present") or
                           rx.get("status") != "retained_observation" or
                           tx.get("status") != "retained_observation")
                if not same_identity:
                    bundle["status"] = "same_submit_serial_identity_conflict"
                elif not submit_id or rx_id != submit_id:
                    bundle["status"] = "stale_sequence_pair_not_current"
                elif changed or not same_generation:
                    bundle["status"] = "same_submit_serial_generation_unverified"
                else:
                    submit_fields_match = all(
                        submit_entry.get(key) == rx_entry.get(key)
                        for key in SUBMIT_SEQUENCE_IDENTITY_FIELDS)
                    bundle["status"] = ("same_submit_serial" if submit_fields_match
                        else "same_submit_serial_identity_conflict")
        elif unavailable.get("entry"):
            bundle["origin_submit_serial"] = unavailable_id
            if not submit_id:
                bundle["status"] = "sequence_unavailable_current_submit_unknown"
            elif unavailable_id != submit_id:
                bundle["status"] = "stale_sequence_unavailable_not_current"
            else:
                unavailable_entry = unavailable.get("entry", {})
                fields_match = all(
                    submit_entry.get(key) == unavailable_entry.get(key)
                    for key in SUBMIT_SEQUENCE_COMMAND_FIELDS)
                if unavailable.get("origin_generation_present"):
                    fields_match = fields_match and (
                        submit_entry.get("DriverGeneration") ==
                        unavailable_entry.get("DriverGeneration"))
                bundle["status"] = ("sequence_unavailable" if fields_match else
                                    "current_submit_identity_conflict")
        elif rx.get("entry") or tx.get("entry"):
            event = rx if rx.get("entry") else tx
            event_id = event.get("origin_submit_serial")
            bundle["origin_submit_serial"] = event_id
            event_entry = event.get("entry", {})
            if not submit_id:
                bundle["status"] = "partial_sequence_current_submit_unknown"
            elif event_id != submit_id:
                bundle["status"] = "stale_partial_sequence_not_current"
            else:
                fields_match = all(
                    submit_entry.get(key) == event_entry.get(key)
                    for key in SUBMIT_SEQUENCE_COMMAND_FIELDS)
                if event.get("origin_generation_present"):
                    fields_match = fields_match and (
                        submit_entry.get("DriverGeneration") ==
                        event_entry.get("DriverGeneration"))
                if not fields_match:
                    bundle["status"] = "current_submit_identity_conflict"
                elif event.get("status") != "retained_observation":
                    bundle["status"] = "partial_sequence_generation_unverified"
                else:
                    bundle["status"] = "partial_sequence_observation"
        else:
            bundle["status"] = "no_sequence_observation"
    result["key_sequence_bundle"] = bundle
    result.update(status="stable_publication", observations=observations)
    return result


def completion_with_live_authority(completion_scalars: dict, live: dict) -> dict:
    """Use independent sampled owner context, never Event0 as its own authority.

    The collector supplies both publications from the same registry read and
    enforces its boot/build/loaded-kext identity contract separately.
    """
    from firmware_single_queue_completion105 import evaluate
    unknown = evaluate({}, expected_generation=None, expected_output_epoch=None)
    # The collector returns an empty mapping when no NativeStaCompletion
    # scalar was published in this IORegistry cut. Keep that distinct from a
    # present-but-incomplete completion record, whose missing fields should
    # still flow through the existing authority/time/schema checks below.
    if completion_scalars == {}:
        return dict(unknown, reason="completion_observation_not_published")
    if live.get("status") != "stable_publication":
        return unknown
    raw = live.get("scalars", {})
    if raw.get("OwnerContextStable") != 1:
        return unknown
    sampled = raw.get("SampleMonotonicNs")
    event = completion_scalars.get("NativeStaCompletionEvent0MonotonicNs")
    if (type(sampled) is not int or type(event) is not int or
            not 0 < event <= sampled):
        return dict(unknown, reason="owner_sample_does_not_cover_event_clock")
    return evaluate(completion_scalars,
                    expected_generation=raw.get("OwnerGeneration"),
                    expected_output_epoch=raw.get("OwnerOutputEpoch"))
