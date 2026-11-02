#!/usr/bin/env python3
"""Decode numeric Test117 scan metadata; never infer a GUI outcome from it."""
import argparse
import json
from pathlib import Path
import struct

HEADER = struct.Struct("<18IQQ")
RECORD = struct.Struct("<QQQIIiI")
NAMES = ("bgscan_cache", "scan_request", "bgscan_config", "home_away")
SIZE = 1048


def decode(raw):
    if len(raw) != SIZE:
        raise ValueError("Unexpected scan-dispatch snapshot size")
    h = HEADER.unpack_from(raw)
    if h[0] != 1 or h[1] != 16:
        raise ValueError("Unsupported scan-dispatch schema/capacity")
    if h[4] not in (0, 1) or h[5] > 16:
        raise ValueError("Invalid snapshot state")
    coherent = bool(h[4])
    if coherent and (h[2] != h[3] or h[2] & 1 or h[5] != min(h[18], 16)):
        raise ValueError("Inconsistent published snapshot")
    out = dict(schema=1, stable=coherent, record_count=h[5],
               version_begin=h[2], version_end=h[3],
               dropped=h[6], overwritten=h[7], unstable_reads=h[8],
               publish_failures=h[17], sequence=h[18], call_serial=h[19],
               hit_counters_may_have_wrapped=h[19] >= 2**32,
               records=[], methods={}, gui_result_proven=False)
    for index, name in enumerate(NAMES):
        out["methods"][name] = dict(entry_hits=h[9 + index*2],
                                    return_hits=h[10 + index*2])
    if not coherent:
        out["note"] = "No coherent rows; counters are provisional."
        return out

    def record(offset):
        seq, call, ns, selector, phase, result, context = RECORD.unpack_from(raw, offset)
        if seq == 0 and call == 0:
            return None
        if not (0 < seq <= h[18] and 0 < call <= h[19] and
                1 <= selector <= 4 and phase in (1, 2)):
            raise ValueError("Invalid scan-dispatch row identity")
        return dict(sequence=seq, call_serial=call, monotonic_ns=ns,
                    selector=selector, method=NAMES[selector-1], phase=phase,
                    result=result if phase == 2 else None,
                    result_hex=f"0x{result & 0xffffffff:08x}" if phase == 2 else None,
                    null_argument=bool(context & 4),
                    gate_context="unknown" if context & 8 else
                                 {"in_gate": bool(context & 1), "on_thread": bool(context & 2)},
                    unknown_context_bits=context & ~15)

    for index in range(h[5]):
        row = record(88 + index*RECORD.size)
        if not row or row["sequence"] != h[18] - h[5] + index + 1:
            raise ValueError("Incomplete chronological ring")
        out["records"].append(row)
    for index, name in enumerate(NAMES):
        entry = record(728 + index*2*RECORD.size)
        returned = record(728 + (index*2+1)*RECORD.size)
        for row, phase in ((entry, 1), (returned, 2)):
            if row and (row["selector"] != index+1 or row["phase"] != phase):
                raise ValueError("Latest record is in the wrong selector/phase slot")
        duration = None
        if entry and returned and entry["call_serial"] == returned["call_serial"]:
            if returned["monotonic_ns"] >= entry["monotonic_ns"]:
                duration = returned["monotonic_ns"] - entry["monotonic_ns"]
        out["methods"][name].update(latest_entry=entry, latest_return=returned,
                                     matched_latest_duration_ns=duration)
    out["note"] = ("Counts/rows are method observations, not an OS client identity, "
                   "scan-list delivery, or AirDrop proof. Keep drop/overwrite/"
                   "publication/clock limits when comparing captures.")
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(decode(args.snapshot.read_bytes()), indent=2))
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
