#!/usr/bin/env python3
"""Exercise the production AWDL BSD queue under host KPI/mbuf shims."""
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
ART = ROOT.parent / "IntelWirelessNative"
SOURCES = [
    ROOT / "native/awdl_native_bsd_data_25G332.hpp",
    ROOT / "native/awdl_native_bsd_data_25G332.cpp",
    ROOT / "native/tests/test064_kernel_shim.hpp",
    ROOT / "native/tests/test064_native_discovery_queue.cpp",
    Path(__file__),
]
KERNEL_HEADERS = (
    "IOKit/IOLib.h",
    "IOKit/IOLocks.h",
    "kern/clock.h",
    "net/kpi_interfacefilter.h",
    "net/if.h",
    "sys/socket.h",
    "sys/mbuf.h",
    "net/kpi_interface.h",
    "sys/kpi_socket.h",
    "netinet/in.h",
    "netinet6/in6_var.h",
)


def run(args, *, check=True):
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result


def main():
    checks = [
        "strict_qm_eligibility_after_checksum_finalization",
        "qu_legacy_other_unknown_qr_mixed_non_in_wrong_group_wrong_mapping_wrong_source_and_wrong_port_rejected",
        "checksum_offload_packet_before_finalization_is_not_discovery_eligible",
        "no_mbuf_copy_alloc_free_or_finalize_while_simplelock_held",
        "fresh_bytes_revalidated_and_invalid_consumed_does_not_advance_awdl_sequence",
        "stale_or_cross_entry_snapshot_does_not_pop_head",
        "epoch_mismatch_closing_radio_off_inflight_expiry_and_empty_head_gates",
        "generation_transition_flushes_only_pretransition_queue_entries",
        "bounded_fifo_scan_selects_earliest_strict_qm_behind_other_without_reordering",
        "exact_once_mbuf_ownership_transfer",
        "concurrent_producer_peeker_consumer_ownership",
    ]
    with tempfile.TemporaryDirectory(prefix="test064-awdl-discovery-") as temp:
        build = Path(temp)
        for header in KERNEL_HEADERS:
            stub = build / header
            stub.parent.mkdir(parents=True, exist_ok=True)
            stub.write_text('#include "test064_kernel_shim.hpp"\n')

        common = [
            "xcrun", "clang++", "-std=c++14", "-O1", "-g", "-Wall",
            "-Wextra", "-Werror", "-fno-omit-frame-pointer",
            "-DITL_NATIVE_AWDL_RESIDENT_25G332=1", f"-I{build}",
            "-Inative/tests", "-Inative",
            "native/awdl_native_bsd_data_25G332.cpp",
            "native/awdl_data_frame.cpp",
            "native/tests/test064_native_discovery_queue.cpp",
        ]
        asan_binary = build / "test064-asan-ubsan"
        run(common[:5] + ["-fsanitize=address,undefined"] + common[5:] +
            ["-o", str(asan_binary)])
        for case in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12):
            try:
                run([str(asan_binary), str(case)])
            except RuntimeError as error:
                raise RuntimeError(f"ASan/UBSan case {case} failed:\n{error}")

        tsan_binary = build / "test064-tsan"
        tsan_compile = run(common[:5] + ["-fsanitize=thread", "-pthread"] +
            common[5:] + ["-o", str(tsan_binary)], check=False)
        if tsan_compile.returncode:
            raise RuntimeError(tsan_compile.stdout + tsan_compile.stderr)
        for case in (9, 12):
            tsan_run = run([str(tsan_binary), str(case)], check=False)
            if tsan_run.returncode:
                raise RuntimeError(f"TSan case {case} failed:\n" +
                    tsan_run.stdout + tsan_run.stderr)

    regression_asan = run([sys.executable,
        "native/tests/test060_native_bridge_asan.py"])
    regression_tsan = run([sys.executable,
        "native/tests/test060_native_bridge_tsan.py"])

    report = {
        "test": "Test064 native discovery queue host verification",
        "checks": checks,
        "asan_ubsan": {"passed": True, "cases": 12},
        "tsan": {"passed": True, "cases": [
            "concurrent_producer_peeker_consumer",
            "generation_transition_interleaving",
        ]},
        "existing_bridge_regression": {
            "asan_ubsan": regression_asan.stdout.strip(),
            "tsan": regression_tsan.stdout.strip(),
        },
        "source_sha256": {
            str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest()
            for path in SOURCES
        },
        "proof_boundary": {
            "compiled_production_bsd_bridge_with_host_kpi_mbuf_shims": True,
            "macos_kernel_runtime_tested": False,
            "firmware_or_rf_tested": False,
            "peer_receipt_or_airdrop_tested": False,
        },
    }
    output = ART / "research/test064-discovery-queue-verification-private.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    os.chmod(output, 0o600)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
