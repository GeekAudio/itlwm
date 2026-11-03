"""Per-run RX tool contracts. Pure validation; no device access or ARM policy.

Construction metadata and a decoded wire contract are deliberately distinct.
Every consumer receives a fresh copy of the same validated bytes, rather than
reading a mutable coordinator module's latest manifest.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Callable


class RuntimeContractError(ValueError):
    pass


@dataclass(frozen=True)
class ValidatedPacketSet:
    _canonical: str
    sha256: str
    wire_nonce_hex: str

    @classmethod
    def from_bytes(cls, raw: bytes, construction_manifest: dict,
                   decode: Callable) -> "ValidatedPacketSet":
        if type(raw) is not bytes or not isinstance(construction_manifest, dict):
            raise RuntimeContractError("packetset_input_type_invalid")
        digest = hashlib.sha256(raw).hexdigest()
        if construction_manifest.get("packet_set_sha256") != digest:
            raise RuntimeContractError("packetset_construction_hash_mismatch")
        # Decode and verify actual bytes. Never promote a construction manifest
        # by setting its valid flag, and never trust its validation child.
        checked = decode(raw)
        if (not isinstance(checked, dict) or checked.get("valid") is not True or
                checked.get("packet_set_sha256") != digest):
            raise RuntimeContractError("packetset_wire_validation_failed")
        for key in ("schema", "frame_count", "interval_ms", "send_budget_ms",
                    "wire_nonce_hex", "wifi_sequence_base", "awdl_sequence_base",
                    "frames"):
            # JSON comparison preserves bool/int distinctions in nested rows.
            if json.dumps(checked.get(key), sort_keys=True) != json.dumps(
                    construction_manifest.get(key), sort_keys=True):
                raise RuntimeContractError("packetset_construction_mismatch:" + key)
        identities = construction_manifest.get("identities")
        if not isinstance(identities, dict):
            raise RuntimeContractError("packetset_construction_identities_missing")
        for key in ("source", "destination_awdl0"):
            wire_identity = checked.get(key)
            supplied_identity = identities.get(key)
            if (not isinstance(wire_identity, dict) or
                    not isinstance(supplied_identity, dict) or
                    any(wire_identity.get(field) != supplied_identity.get(field)
                        for field in ("mac", "ipv6_link_local"))):
                raise RuntimeContractError("packetset_identity_mismatch:" + key)
        nonce = checked.get("wire_nonce_hex")
        if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{16}", nonce):
            raise RuntimeContractError("packetset_wire_nonce_invalid")
        return cls(json.dumps(checked, sort_keys=True, separators=(",", ":")),
                   digest, nonce)

    def manifest(self) -> dict:
        return json.loads(self._canonical)


@dataclass(frozen=True, init=False)
class BoundRun:
    run_token: str
    packet_set: ValidatedPacketSet
    _validate: Callable
    _classify: Callable
    _started: Callable
    _ready: Callable
    _protocol_name: str

    def __init__(self, run_token: str, packet_set: ValidatedPacketSet,
                 sender_protocol):
        if not isinstance(run_token, str) or not re.fullmatch(r"[0-9a-f]{32}", run_token):
            raise RuntimeContractError("run_token_invalid")
        if not isinstance(packet_set, ValidatedPacketSet):
            raise RuntimeContractError("validated_packetset_required")
        object.__setattr__(self, "run_token", run_token)
        object.__setattr__(self, "packet_set", packet_set)
        for attr, name in (("_validate", "validate_result"),
                           ("_classify", "classify_sender_result"),
                           ("_started", "parse_started"), ("_ready", "parse_ready")):
            function = getattr(sender_protocol, name)
            if not callable(function):
                raise RuntimeContractError("sender_parser_unavailable:" + name)
            object.__setattr__(self, attr, function)
        object.__setattr__(self, "_protocol_name", str(sender_protocol.SCHEMA))

    def validate_result(self, record):
        return self._validate(record, self.run_token,
                              expected_wire_nonce_hex=self.packet_set.wire_nonce_hex,
                              packet_set_manifest=self.packet_set.manifest())

    def classify_result(self, record):
        # Validate with the independently bound token before the adapter, which
        # otherwise reads its expected token from the record itself. Preserve
        # the original validation error rather than replacing its cause.
        self.validate_result(record)
        return self._classify(record,
                              expected_wire_nonce_hex=self.packet_set.wire_nonce_hex,
                              packet_set_manifest=self.packet_set.manifest())

    def parse_started(self, record):
        return self._started(record, self.run_token,
                             expected_wire_nonce_hex=self.packet_set.wire_nonce_hex)

    def parse_ready(self, line):
        return self._ready(line, expected_wire_nonce_hex=self.packet_set.wire_nonce_hex)

    def audit(self):
        return {"schema": "rx149-bound-run/v1", "implementation_revision": "Test124",
                "sender_protocol_schema": self._protocol_name,
                "packet_set_sha256": self.packet_set.sha256,
                "run_token_sha256": hashlib.sha256(self.run_token.encode()).hexdigest(),
                "validated_from_wire_bytes": True,
                "mutable_manifest_consulted_after_binding": False}


def native_terminal(capture: dict, *, run_token: str, boot_epoch: int,
                    expected_loaded_uuid: str) -> dict:
    """Derive cleanup separately from exercise outcome; never grant a retry.

    Old workers recognize only state 7. State 10 is a known failed exercise
    with safe cleanup, provided all three post samples prove that same owner.
    The original worker report is retained unchanged.
    """
    result = {"state": "unknown", "cleanup": "unknown", "exercise": "unknown",
              "retry_allowed": False, "functional_delivery_proven": False}
    if (capture.get("arm_run_token") != run_token or
            type(boot_epoch) is not int or boot_epoch <= 0 or
            capture.get("boot_epoch") != boot_epoch or
            not isinstance(expected_loaded_uuid, str) or not expected_loaded_uuid or
            capture.get("expected_loaded_uuid") != expected_loaded_uuid or
            capture.get("boot_attempt_claim_consumed") is not True):
        return {**result, "reason": "native_capture_binding_mismatch"}
    samples = capture.get("post_samples")
    if not isinstance(samples, list) or len(samples) != 3:
        return {**result, "reason": "native_post_samples_incomplete"}
    owner_keys = ("NativeP2PProbeContextGeneration", "NativeP2PProbePowerGeneration",
                  "NativeP2PProbeStationGeneration", "NativeP2PRocGeneration",
                  "NativeP2PRxTraceOwnerSerial")
    owners = [s.get("current_owner_and_epochs") for s in samples if isinstance(s, dict)]
    if (len(owners) != 3 or any(not isinstance(owner, dict) or
            any(type(owner.get(key)) is not int or owner[key] <= 0
                for key in owner_keys) for owner in owners) or
            any(owner != owners[0] for owner in owners)):
        return {**result, "reason": "native_owner_inconsistent"}
    states = []
    for sample in samples:
        lifecycle = sample.get("native_p2p_probe_lifecycle")
        if not isinstance(lifecycle, dict):
            return {**result, "reason": "native_lifecycle_missing"}
        for key, expected in (("Selected", 1), ("Attempted", 1), ("EndSeen", 1),
                              ("RecoveryAttempted", 1), ("ProofAccepted", 1),
                              ("RemoveResult", 0), ("ResourceMayExist", 0)):
            if type(lifecycle.get(key)) is not int or lifecycle[key] != expected:
                return {**result, "reason": "native_cleanup_unproven"}
        state = lifecycle.get("State")
        exercise = lifecycle.get("ExerciseResult")
        if (type(state) is not int or state not in (7, 10) or
                type(exercise) is not int or exercise < 0 or
                (state == 7 and exercise != 0) or (state == 10 and exercise == 0)):
            return {**result, "reason": "native_terminal_inconsistent"}
        states.append(state)
    if len(set(states)) != 1:
        return {**result, "reason": "native_terminal_transition_unresolved"}
    return {**result, "state": "known", "cleanup": "verified",
            "exercise": "failed" if states[0] == 10 else "completed",
            "driver_state": states[0]}
