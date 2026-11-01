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
               "DroppedCount": 32, "DroppedSerial": 64, **ENTRY}
FIELDS = {**HEADER, **{role + key: bits for role in ("Submit", "Response")
                       for key, bits in OBSERVATION.items()}}


def parse_live_key(service: dict) -> dict:
    raw = {key: service.get(PREFIX + key) for key in FIELDS}
    # Retain only fixed-width numeric allowlisted fields. No arbitrary strings,
    # properties, addresses, secrets, or firmware packet bodies are exported.
    scalars = {key: value for key, value in raw.items()
               if type(value) is int and 0 <= value < 1 << FIELDS[key]}
    result = {"status": "not_published", "scalars": scalars,
              "command_response_match": "unknown",
              "key_install_result": "unknown"}
    if raw["Schema"] is None:
        return result
    if raw["Schema"] != 1 or type(raw["Schema"]) is not int:
        result["status"] = "unsupported_schema"
        return result
    if len(scalars) != len(FIELDS):
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
    for role in ("Submit", "Response"):
        o = {key: raw[role + key] for key in OBSERVATION}
        if o["Present"] not in (0, 1) or o["Stable"] not in (0, 1):
            result["status"] = "invalid_observation_flags"
            return result
        if not o["Present"]:
            if any(o[key] != 0 for key in ENTRY):
                result["status"] = "absent_observation_has_payload"
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
        else:
            valid_identity = (valid_identity and o["Source"] == 2 and
                              o["Phase"] in (7, 8) and bool(o["Flags"] & (7 << 10)))
        if not valid_identity:
            result["status"] = "invalid_observation_identity"
            return result
        status = "retained_observation"
        if not raw["OwnerContextStable"]:
            status = "retained_context_unstable"
        elif o["DriverGeneration"] != raw["OwnerGeneration"]:
            status = "retained_older_generation"
        if o["DroppedSerial"] > o["Serial"]:
            status = "retained_with_newer_event_lost"
        observations[role.lower()] = {
            "status": status, "age_ns": raw["SampleMonotonicNs"] - o["MonotonicNs"],
            "entry": o,
        }
    result.update(status="stable_publication", observations=observations)
    return result


def completion_with_live_authority(completion_scalars: dict, live: dict) -> dict:
    """Use independent sampled owner context, never Event0 as its own authority.

    The collector supplies both publications from the same registry read and
    enforces its boot/build/loaded-kext identity contract separately.
    """
    from firmware_single_queue_completion105 import evaluate
    unknown = evaluate({}, expected_generation=None, expected_output_epoch=None)
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
