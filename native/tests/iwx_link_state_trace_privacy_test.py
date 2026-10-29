#!/usr/bin/env python3
"""Static allowlist check for the numeric Wi-Fi transition trace ABI."""
from pathlib import Path
import re


root = Path(__file__).resolve().parents[1]
header = (root / "iwx_link_state_trace.hpp").read_text(encoding="utf-8")


def fields_for(struct_name):
    match = re.search(
        rf"struct\s+{re.escape(struct_name)}\s*\{{(.*?)\n\}};",
        header,
        re.DOTALL,
    )
    assert match, f"missing {struct_name} schema"
    body = match.group(1)
    fields = re.findall(r"^\s*(uint64_t|uint32_t|int32_t)\s+(\w+)\s*;",
                        body, re.MULTILINE)
    arrays = re.findall(r"^\s*Record\s+(\w+)\[kCapacity\]\s*;",
                        body, re.MULTILINE)
    non_comments = re.sub(r"//[^\n]*|/\*.*?\*/", "", body, flags=re.DOTALL)
    declarations = re.findall(r"^\s*[^\n;{}]+;", non_comments, re.MULTILINE)
    assert len(fields) + len(arrays) == len(declarations), (
        f"non-numeric field in {struct_name}")
    return {name for _, name in fields} | set(arrays)


expected_input = {
    "eventCode", "oldState", "newState", "deauthReason", "stateArgument",
    "resultCode", "ifUpRunning", "driverGeneration", "resetGeneration",
    "watchdogSequence", "validMask",
}
expected_record = {
    "sequence", "monotonicNs", "eventCode", "oldState", "newState",
    "deauthReason", "stateArgument", "resultCode", "ifUpRunning",
    "driverGeneration", "resetGeneration", "watchdogSequence", "validMask",
}
expected_snapshot = {
    "schema", "capacity", "versionBegin", "versionEnd", "droppedCount",
    "count", "nextSequence", "records",
}

assert fields_for("Input") == expected_input
assert fields_for("Record") == expected_record
assert fields_for("Snapshot") == expected_snapshot
assert "char *" not in header and "void *" not in header
assert "sizeof(Record) == 64" in header
assert "sizeof(Snapshot) == 544" in header

print("PASS: trace ABI fields are allowlisted numeric scalars with fixed sizes")
