#!/usr/bin/env python3
"""Run production AWDL bridge QM queue selection under host ASan/UBSan."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCES = [
    ROOT / "native/awdl_native_bsd_data_25G332.hpp",
    ROOT / "native/awdl_native_bsd_data_25G332.cpp",
    ROOT / "native/awdl_bsd_packet_bridge.hpp",
    ROOT / "native/awdl_data_frame.cpp",
    ROOT / "native/awdl_data_frame.hpp",
    ROOT / "native/tests/test064_kernel_shim.hpp",
    ROOT / "native/tests/awdl_native_discovery_qm_selection_test.cpp",
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


def run(args):
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result


def main():
    checks = [
        "earliest_supported_continuity_qm_selected_behind_non_targets",
        "wrapped_ring_selection_and_fifo_order_preservation",
        "invalid_and_expired_candidates_skipped_without_queue_loss",
        "snapshot_identity_and_post_peek_bytes_revalidated",
        "generation_and_single_inflight_slot_gates_preserved",
        "close_blocks_claim_and_retires_queued_mbufs_once",
        "generation_transition_retires_old_queue_and_accepts_new_epoch",
    ]
    with tempfile.TemporaryDirectory(prefix="test079-awdl-qm-queue-") as temp:
        build = Path(temp)
        for header in KERNEL_HEADERS:
            stub = build / header
            stub.parent.mkdir(parents=True, exist_ok=True)
            stub.write_text('#include "test064_kernel_shim.hpp"\n')

        binary = build / "test079-awdl-qm-queue-asan-ubsan"
        run([
            "xcrun", "clang++", "-std=c++14", "-O1", "-g", "-Wall",
            "-Wextra", "-Werror", "-fno-omit-frame-pointer",
            "-fno-sanitize-recover=all", "-fsanitize=address,undefined",
            "-pthread", "-DITL_NATIVE_AWDL_RESIDENT_25G332=1",
            f"-I{build}", "-Inative/tests", "-Inative",
            "native/awdl_native_bsd_data_25G332.cpp",
            "native/awdl_data_frame.cpp",
            "native/tests/awdl_native_discovery_qm_selection_test.cpp",
            "-o", str(binary),
        ])
        for case in range(1, 8):
            try:
                run([str(binary), str(case)])
            except RuntimeError as error:
                raise RuntimeError(f"ASan/UBSan case {case} failed:\n{error}")

    print(json.dumps({
        "test": "Test079 native AWDL continuity-QM queue selection",
        "checks": checks,
        "asan_ubsan": {"passed": True, "cases": len(checks)},
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
    }, indent=2))


if __name__ == "__main__":
    main()
