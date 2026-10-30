#!/usr/bin/env python3
"""Independent Test059 helper and source-contract review; host-only, no RF."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
ART = ROOT.parent / "IntelWirelessNative" / "research"


def extract_function(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    state = "code"
    escaped = False
    i = opening
    while i < len(source):
        c = source[i]
        n = source[i + 1] if i + 1 < len(source) else ""
        if state == "line":
            if c == "\n":
                state = "code"
        elif state == "block":
            if c == "*" and n == "/":
                state = "code"
                i += 1
        elif state in ("string", "char"):
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif (state == "string" and c == '"') or (state == "char" and c == "'"):
                state = "code"
        elif c == "/" and n == "/":
            state = "line"
            i += 1
        elif c == "/" and n == "*":
            state = "block"
            i += 1
        elif c == '"':
            state = "string"
        elif c == "'":
            state = "char"
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:i]
        i += 1
    raise AssertionError(f"Unclosed production function: {signature}")


def compile_run(sources, include_dirs, tmp: Path, label: str):
    binary = tmp / label
    command = [
        "xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
    ]
    for path in include_dirs:
        command += ["-I", str(path)]
    command += [str(ROOT / p) for p in sources]
    command += ["-o", str(binary)]
    subprocess.run(command, cwd=ROOT, check=True)
    subprocess.run([str(binary)], cwd=ROOT, check=True)


def main():
    frame_h = ROOT / "native/awdl_data_frame.hpp"
    frame_cpp = ROOT / "native/awdl_data_frame.cpp"
    observation_h = ROOT / "native/awdl_data_tx_observation.hpp"
    tx_test = ROOT / "native/tests/awdl_data_tx_observation_test.cpp"
    rx_cpp = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"
    rx_h = ROOT / "itlwm/hal_iwx/ItlIwx.hpp"
    rx_tap = ROOT / "itlwm/hal_iwx/ItlIwxP2PRx.cpp"
    probe = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"
    bsd = ROOT / "native/awdl_native_bsd_data_25G332.cpp"
    bsd_h = ROOT / "native/awdl_native_bsd_data_25G332.hpp"

    frame_text = frame_cpp.read_text()
    observation_text = observation_h.read_text()
    bsd_text = bsd.read_text()
    rx_text = rx_cpp.read_text()
    tap_text = rx_tap.read_text()
    rx_header = rx_h.read_text()

    candidate = extract_function(frame_text, "bool isAwdlDataCandidate(")
    assert "frameLength < kMacHeaderLength" in candidate
    assert "frameLength <\n            kMacHeaderLength + kQosControlLength" in candidate
    assert "kFrameControlToDs | kFrameControlFromDs" in candidate
    assert "Protected" not in candidate or "kFrameControlProtected" not in candidate
    assert "memcmp(frame + 16, kAwdlBssid" in candidate

    capture = extract_function(bsd_text, "CaptureResult capture(")
    assert capture.index("isAwdlDataCandidate") < capture.index("IOSimpleLockLockDisableInterrupt")
    assert "memcpy(item.bytes,bytes,length)" in capture.replace(" ", "")
    assert "IOBufferMemoryDescriptor" not in capture
    assert "IOMalloc" not in capture and "new " not in capture

    tap = extract_function(tap_text, "void ItlIwx::tahoeP2pTapAction(")
    assert tap.index("NativeAwdlBSD::capture(") < tap.index("tapActionFrame(")
    rx_method = extract_function(rx_text, "void ItlIwx::\niwx_rx_frame(")
    assert rx_method.index("tahoeP2pTapAction(sc,") < rx_method.index("ieee80211_inputm(")
    assert "ieee80211_inputm(IC2IFP(ic), m, ni, rxi, ml);" in rx_method

    # The observer is diagnostic-only: no raw packet or address is exported,
    # and no observation field feeds the encode/submit decision.
    assert "const auto observation=NativeAwdlData::observeAwdlTxPacket(" in bsd_text
    for forbidden in ("IPv6Source", "IPv6Destination", "SourceAddress", "RawPacket", "PayloadBytes"):
        assert forbidden not in bsd_text and forbidden not in rx_tap.read_text()
    assert "uint8_t bytes[MaxEthernet]" in bsd_text
    assert "TxObservationCount" in bsd_text
    assert "udpHasMdnsPort" in observation_text
    assert "Extension headers are intentionally not walked" in observation_text
    assert "summarizeTxObservation(observation)" in bsd_text
    assert "__atomic_fetch_or(&counters[TxChecksumStatusSeenMask]" in bsd_text
    assert "if(delta.sourceEui64Mismatch)add(TxSourceEui64MismatchCount)" in bsd_text
    assert "if(delta.multicastMappingMismatch)add(TxMulticastMappingMismatchCount)" in bsd_text
    assert "if(delta.malformed)add(TxMalformedCount)" in bsd_text
    assert "static_assert(sizeof(names)/sizeof(names[0])==NativeAwdlBSD::Count" in tap_text

    # RX telemetry is numeric and independently bounded from PSF/MIF counters.
    stage_names = re.findall(r'"NativeP2PRxDataStage[^"\n]+"', tap_text)
    # Existing indices/properties remain stable; appended diagnostics are
    # additional counters, not replacements for the original seven stages.
    assert stage_names[:7] == [
        '"NativeP2PRxDataStageEarlyAwdlBssidCandidate"',
        '"NativeP2PRxDataStageAfterDecryptAwdlBssidCandidate"',
        '"NativeP2PRxDataStageDecryptRejectedAwdlBssidCandidate"',
        '"NativeP2PRxDataStageAfterDuplicateAwdlBssidCandidate"',
        '"NativeP2PRxDataStageDuplicateRejectedAwdlBssidCandidate"',
        '"NativeP2PRxDataStageAtTapAwdlBssidCandidate"',
        '"NativeP2PRxDataStageTapRejectedAwdlBssidCandidate"',
    ]
    assert stage_names[7:] == [
        '"NativeP2PRxDataStageTapContextUnavailableAwdlBssidCandidate"',
        '"NativeP2PRxDataStageTapLeaseInactiveAwdlBssidCandidate"',
        '"NativeP2PRxDataStageTapRX149PathNotSelectedAwdlBssidCandidate"',
        '"NativeP2PRxDataStageTapRX149OwnerRejectedAwdlBssidCandidate"',
        '"NativeP2PRxDataStageTapLeaseSnapshotUnavailableAwdlBssidCandidate"',
        '"NativeP2PRxDataStageTapOriginalDescriptorMissingAwdlBssidCandidate"',
        '"NativeP2PRxDataStageTapInputInvalidAwdlBssidCandidate"',
        '"NativeP2PRxDataStageTapPermitRejectedAwdlBssidCandidate"',
        '"NativeP2PRxDataStageTapCaptureRejectedAwdlBssidCandidate"',
        '"NativeP2PRxDataStageTapQueueFullAwdlBssidCandidate"',
    ]
    assert len(stage_names) == 17
    assert len(set(stage_names)) == len(stage_names)
    assert "dataCounts[kDataStageCount]" in rx_header
    assert "if (!generation || stage >= kDataStageCount" in rx_header
    assert "RxRejected" in bsd_h.read_text() and "RxQueueFull" in bsd_h.read_text()

    # Retained the specific MIF stop reason regression test from Test058.
    stop_body = extract_function(
        probe.read_text(), "static void recordMifPacingPlan(P2PProbeRun *probe,")
    assert "if (probe->mifBurstStopReason ==" in stop_body

    with tempfile.TemporaryDirectory(prefix="test059-review-") as d:
        tmp = Path(d)
        compile_run([
            "native/awdl_data_frame.cpp",
            "native/tests/awdl_data_frame_test.cpp",
        ], [ROOT], tmp, "data-frame")
        compile_run([
            "native/awdl_data_frame.cpp",
            "native/tests/awdl_data_tx_observation_test.cpp",
        ], [ROOT], tmp, "tx-observation")
        (tmp / "mixed_observations.cpp").write_text(r'''
#include <assert.h>
#include <stdint.h>
#include "native/awdl_data_tx_observation.hpp"
int main() {
    NativeAwdlData::TxObservation valid{};
    valid.ipv6PacketWellFormed = 1;
    valid.sourceIsLinkLocal = 1;
    valid.sourceEui64MatchesOwn = 1;
    valid.udpChecksumStatus = NativeAwdlData::UdpChecksumStatus::Valid;
    NativeAwdlData::TxObservation invalid = valid;
    invalid.udpChecksumStatus = NativeAwdlData::UdpChecksumStatus::Invalid;
    NativeAwdlData::TxObservation malformed = valid;
    malformed.udpChecksumStatus = NativeAwdlData::UdpChecksumStatus::Malformed;
    malformed.sourceEui64MatchesOwn = 0;
    uint8_t seen = 0;
    uint32_t euiMismatch = 0, malformedCount = 0;
    const NativeAwdlData::TxObservation packets[] = {valid, invalid, malformed};
    for (const auto &packet : packets) {
        const auto delta = NativeAwdlData::summarizeTxObservation(packet);
        seen |= delta.checksumStatusBit;
        euiMismatch += delta.sourceEui64Mismatch;
        malformedCount += delta.malformed;
    }
    assert(seen == ((1u << 1) | (1u << 2) | (1u << 3)));
    assert(euiMismatch == 1 && malformedCount == 1);
}
''')
        compile_run([str(tmp / "mixed_observations.cpp")],
                    [ROOT], tmp, "mixed-observations")
    additional_tests = [
        "native/tests/test_iwx_p2p_rx_tap.py",
        "native/tests/test057_rx_stage_counters.py",
        "native/tests/test_mif_burst_stop_reason.py",
        "native/tests/test052_native_data_gate.py",
    ]
    for test in additional_tests:
        subprocess.run(["python3", str(ROOT / test)], cwd=ROOT, check=True)

    reviewed = [frame_h, frame_cpp, observation_h, tx_test, bsd_h, bsd,
                rx_h, rx_cpp, rx_tap, probe,
                ROOT / "native/tests/test_iwx_p2p_rx_tap.py",
                ROOT / "native/tests/test057_rx_stage_counters.py",
                ROOT / "native/tests/test_mif_burst_stop_reason.py",
                ROOT / "native/tests/test052_native_data_gate.py", Path(__file__)]
    report = {
        "schema": "test059-independent-production-review-v1",
        "source_review_passed": True,
        "asan_ubsan_passed": True,
        "pure_helper_scope": [
            "production 802.11 data candidate classifier and IPv6 frame codec",
            "production numeric-only TX packet observer",
        ],
        "source_contracts_passed": [
            "bounded FC/BSSID/QoS candidate classification; Protected remains candidate-only",
            "capture hook has no allocation and copies only a bounded candidate",
            "original STA RX input remains called after the side tap",
            "observation exports numeric fields only and does not drive packet decisions",
            "checksum status uses cumulative atomic OR; mismatch/malformed totals use cumulative counters",
            "original seven RX candidate stages retained with ten appended diagnostic counters and generation/stage bounds",
            "MIF stop reason preserves a prior specific reason",
        ],
        "additional_host_harnesses_passed": {
            test: "ASan/UBSan host harness" for test in additional_tests
        },
        "reviewed_file_sha256": {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in reviewed
        },
        "scope_limits": {
            "executed": "pure helper tests, RX tap and stage counters, MIF reason regression, and BSD bridge under KPI host shims; all compiled/run with ASan/UBSan",
            "source_review": "RX integration, bounded queue/capture path, IORegistry publishing, and cumulative atomic TX aggregation were source-contract reviewed; mixed status retention was run through the portable summary helper, not the kernel atomic counter path. The KPI shim is not macOS kernel execution",
            "not_executed": "kernel/full Xcode build, firmware, RF, peer receipt, EFI deployment, reboot, and AirDrop runtime",
        },
        "rf_tested": False,
        "kernel_kext_built": False,
        "deployment_performed": False,
    }
    ART.mkdir(parents=True, exist_ok=True)
    output = ART / "test059-independent-review-private.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print("PASS: Test059 independent source contracts and pure helpers under ASan/UBSan")
    print(output)


if __name__ == "__main__":
    main()
