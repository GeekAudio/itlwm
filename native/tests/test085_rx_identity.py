#!/usr/bin/env python3
"""Test085 RX identity, timing, ring source, and owner lifecycle contracts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
IWN = ROOT.parent / "IntelWirelessNative"
RECEIPT = IWN / "research/test085-preparation-private/rx-identity-host-verification.json"
HEADER = ROOT / "native/awdl_rx_entry_telemetry.hpp"
FIXTURE = Path(__file__).with_name("awdl_rx_entry_telemetry_test.cpp")
ITL_CPP = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"
ITL_HEADER = ROOT / "itlwm/hal_iwx/ItlIwx.hpp"
RX_CPP = ROOT / "itlwm/hal_iwx/ItlIwxP2PRx.cpp"
PROBE_CPP = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"
RUNNER = Path(__file__)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract_braced_block(source: str, start: int) -> str:
    opening = source.find("{", start)
    if opening < 0:
        raise AssertionError("missing opening brace")
    depth = 0
    state = "code"
    escaped = False
    index = opening
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "line_comment":
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if char == "*" and next_char == "/":
                state = "code"
                index += 1
        elif state in ("string", "char"):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (state == "string" and char == '"') or (
                state == "char" and char == "'"
            ):
                state = "code"
        else:
            if char == "/" and next_char == "/":
                state = "line_comment"
                index += 1
            elif char == "/" and next_char == "*":
                state = "block_comment"
                index += 1
            elif char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return source[start:index + 1]
        index += 1
    raise AssertionError("unterminated production RX producer close block")


def finish_close_snippet() -> str:
    source = PROBE_CPP.read_text()
    finish_start = source.index("IOReturn ItlIwx::tahoeP2pFinishAction(")
    close_start = source.index("if (rxProducerClosed) {", finish_start)
    snippet = extract_braced_block(source, close_start)
    assert snippet.index("tahoeP2pSyncRxDiagnosticOwner(true)") < snippet.index(
        "tahoeP2pRxConsume()"
    )
    assert "iwx_send_cmd" not in snippet
    assert "nativeP2pResources" not in snippet
    assert "tahoeP2pSyncRxDiagnosticOwner(true)" in snippet
    assert "tahoeP2pRxConsume()" in snippet

    # The production block is entered only after trace owner/run epochs match.
    finish_prefix = source[finish_start:close_start]
    assert "trace.epochs.contextGeneration == run->contextGeneration" in finish_prefix
    assert "trace.epochs.powerGeneration == run->powerGeneration" in finish_prefix
    assert "trace.epochs.stationGeneration == run->stationGeneration" in finish_prefix
    assert "trace.epochs.rocGeneration == run->contextGeneration" in finish_prefix
    assert "trace.ownerSerial ==" in finish_prefix and "sameRunEpoch" in finish_prefix
    return snippet


def finish_harness(snippet: str) -> str:
    return r'''#include <cassert>
#include <cstdint>
#include "native/awdl_rx_entry_telemetry.hpp"

using namespace NativeAwdlRxEntry;

struct FakeOwner {
    Telemetry telemetry;
    Epochs current{71, 72, 73, 71};
    bool closeTuplePresent = true;
    bool diagnosticEligible = false;
    uint32_t consumeCalls = 0;

    void tahoeP2pSyncRxDiagnosticOwner(bool closeOnly) {
        if (closeOnly)
            (void)telemetry.syncOwner(true, current, closeTuplePresent);
        else
            (void)telemetry.syncOwner(false, current, diagnosticEligible);
    }
    void tahoeP2pRxConsume() {
        ++consumeCalls;
        // Mirrors the current production Consume behavior: an ineligible poll
        // is nonterminal and cannot reopen a closed same-epoch owner.
        (void)telemetry.syncOwner(false, current, diagnosticEligible);
    }
};

static Inspection validMpdu() {
    Inspection observation{};
    observation.payloadLength = 72;
    observation.dmaCapacity = 160;
    observation.descriptorSize = 48;
    observation.descriptorVersion = 1;
    observation.minimumMpduLength = 24;
    observation.statusPresent = 1;
    observation.status = 3;
    observation.crcOk = 1;
    observation.overrunOk = 1;
    observation.mpduLengthPresent = 1;
    observation.mpduLength = 24;
    observation.descriptorPresent = 1;
    observation.channelPresent = 1;
    observation.channel = 149;
    observation.macPhyIndexPresent = 1;
    observation.macPhyIndex = 0x11;
    observation.macContextPresent = 1;
    observation.macContext = 0x80;
    observation.macIndexPresent = 1;
    observation.macIndex = 1;
    observation.phyIndexPresent = 1;
    observation.phyIndex = 1;
    observation.macPhyIndexDecodeModePresent = 1;
    observation.macPhyIndexDecodeMode = MacPhyDecodeLegacy;
    observation.capacityFits = 1;
    observation.payloadFits = 1;
    observation.frameRangeValid = 1;
    observation.frameControlPresent = 1;
    observation.frameControl = 0x0008;
    observation.frameType = 2;
    observation.frameSubtype = 0;
    return observation;
}

static void recordMpdu(FakeOwner &owner) {
    assert(owner.telemetry.record(owner.current, validMpdu(), false));
}

static void finishWithProductionBlock(FakeOwner *owner,
                                      bool rxProducerClosed) {
    @@@FINISH_CLOSE_SNIPPET@@@
}

int main() {
    Layout unusedLayout{};
    (void)inspect(nullptr, 0, 0, unusedLayout); // Link actual production inspector.
    // Accepted START with no MPDU and no END: timeout closes the owner while
    // preserving the accepted generation and a zero-frame snapshot.
    {
        FakeOwner owner;
        assert(owner.telemetry.beginOwner(owner.current));
        owner.diagnosticEligible = false; // timeout/outcome-unknown
        finishWithProductionBlock(&owner, true);
        const auto snapshot = owner.telemetry.snapshot();
        assert(!snapshot.active);
        assert(sameEpochs(snapshot.epochs, owner.current));
        assert(snapshot.counts[OwnerGateEntries] == 0);
        assert(owner.consumeCalls == 1);
    }

    // A descriptor received before a missing-END timeout remains publishable.
    {
        FakeOwner owner;
        assert(owner.telemetry.beginOwner(owner.current));
        recordMpdu(owner);
        const auto before = owner.telemetry.snapshot();
        finishWithProductionBlock(&owner, true);
        const auto after = owner.telemetry.snapshot();
        assert(!after.active);
        assert(sameEpochs(after.epochs, before.epochs));
        assert(after.counts[OwnerGateEntries] == 1);
        assert(after.counts[Channel149] == 1);
        assert(after.lastDescriptor.present == 1);
    }

    // Canonical END may close first; repeated timeout/finish callbacks cannot
    // reopen the same owner or erase its descriptor witness.
    {
        FakeOwner owner;
        assert(owner.telemetry.beginOwner(owner.current));
        recordMpdu(owner);
        owner.tahoeP2pSyncRxDiagnosticOwner(true); // canonical END
        assert(!owner.telemetry.active());
        finishWithProductionBlock(&owner, true);
        finishWithProductionBlock(&owner, true);
        const auto snapshot = owner.telemetry.snapshot();
        assert(!snapshot.active);
        assert(snapshot.counts[OwnerGateEntries] == 1);
        assert(snapshot.lastDescriptor.present == 1);
        assert(owner.consumeCalls == 2);
    }

    // A stale run's epoch cannot close a newer owner; production epoch checks
    // suppress the close tuple before the extracted finish block calls it.
    {
        FakeOwner owner;
        const Epochs newer{81, 82, 83, 81};
        assert(owner.telemetry.beginOwner(newer));
        owner.current = Epochs{71, 72, 73, 71}; // stale run
        owner.closeTuplePresent = true;
        owner.diagnosticEligible = false;
        finishWithProductionBlock(&owner, true);
        const auto snapshot = owner.telemetry.snapshot();
        assert(snapshot.active);
        assert(sameEpochs(snapshot.epochs, newer));
        assert(snapshot.counts[OwnerGateEntries] == 0);
    }

    // An END/finish with no existing entry owner remains a no-op.
    {
        FakeOwner owner;
        finishWithProductionBlock(&owner, true);
        const auto snapshot = owner.telemetry.snapshot();
        assert(!snapshot.active);
        assert(snapshot.epochs.contextGeneration == 0);
        assert(snapshot.counts[OwnerGateEntries] == 0);
    }
}
'''.replace("@@@FINISH_CLOSE_SNIPPET@@@", snippet)


def source_contracts() -> None:
    header = HEADER.read_text()
    cpp = ITL_CPP.read_text()
    itl_header = ITL_HEADER.read_text()
    rx_cpp = RX_CPP.read_text()
    finish_close_snippet()

    assert "static const uint32_t kSchema = 2;" in header
    for old_counter in (
        "OwnerGateEntries", "StatusTruncated", "CrcRejected",
        "OverrunRejected", "MpduLengthShort", "DescriptorTruncated",
        "PayloadTruncated", "CapacityOverflow", "FullDescriptor",
        "FrameControlValid", "ManagementFrame", "ControlFrame",
        "DataFrame", "ReservedFrame", "QosDataFrame",
        "AwdlBssidCandidate", "FilterMatchAvailable",
        "FilterMatchUnavailable",
    ):
        assert old_counter in header
    for extension in (
        "Channel149", "Channel36", "ExpectedMacPhy149",
        "MacIndex1Channel149", "lastTarget", "lastMacIndexTarget",
        "macContextPresent", "gp2OnAirRisePresent",
        "tsfOnAirRisePresent", "tsfValidPresent",
        "hostRxMonotonicUsPresent", "rxRingSlotPresent",
        "transportNotificationQidPresent",
        "transportNotificationIndexPresent",
    ):
        assert extension in header
    assert "const bool strictDescriptor = observation.statusPresent &&" in header
    assert "observation.crcOk && observation.overrunOk &&" in header
    assert "observation.frameRangeValid" in header
    assert "observation.frameControlPresent" in header
    assert "observation.macIndex == 1" in header
    assert "observation.phyIndex == 1" in header

    # Compile-time checks tie the production offsets to the actual C structs.
    for abi in (
        "IWX_RX_DESC_SIZE_V1 == 48", "sizeof(struct iwx_rx_mpdu_desc) == 64",
        "offsetof(struct iwx_rx_mpdu_desc, phy_info) == 5",
        "offsetof(struct iwx_rx_mpdu_desc, mac_phy_idx) == 7",
        "offsetof(struct iwx_rx_mpdu_desc, status) == 12",
        "iwx_rx_mpdu_desc_v1, mac_context) == 35",
        "iwx_rx_mpdu_desc_v1, gp2_on_air_rise) == 36",
        "iwx_rx_mpdu_desc_v1, tsf_on_air_rise) == 40",
        "iwx_rx_mpdu_desc_v1, filter_match) == 24",
        "iwx_rx_mpdu_desc_v3, mac_context) == 43",
        "iwx_rx_mpdu_desc_v3, gp2_on_air_rise) == 44",
        "iwx_rx_mpdu_desc_v3, tsf_on_air_rise) == 48",
        "iwx_rx_mpdu_desc_v3, filter_match) == 20",
    ):
        assert abi in cpp, f"missing firmware ABI offset assertion: {abi}"
    for field in (
        "layout.macContextOffset", "layout.gp2OnAirRiseOffset",
        "layout.tsfOnAirRiseOffset", "layout.phyInfoOffset",
        "layout.macPhyIndexDecodeMode",
    ):
        assert field in cpp
    assert "IWX_UCODE_TLV_API_BAND_IN_RX_DATA" in cpp

    # Real slot comes from the RFH Q0 ring cursor and is distinct from packet
    # notification qid/index. The host timestamp precedes ring recycling.
    assert "const uint32_t ringSlot = static_cast<uint32_t>(sc->rxq.cur);" in cpp
    assert "iwx_rx_pkt(sc, data, &ml, ringSlot);" in cpp
    assert cpp.count("maxlen, ml, rxRingSlot,") >= 2
    assert "static_cast<uint32_t>(pkt->hdr.qid)" in cpp
    assert "static_cast<uint32_t>(pkt->hdr.idx)" in cpp
    rx_pkt_start = cpp.index("iwx_rx_pkt(struct iwx_softc *sc")
    rx_pkt_end = cpp.index("void ItlIwx::\niwx_notif_intr(", rx_pkt_start)
    rx_pkt = cpp[rx_pkt_start:rx_pkt_end]
    assert rx_pkt.index("hostRxMonotonicUs = tahoeMonotonicNs() / 1000ULL") < rx_pkt.index(
        "iwx_rx_addbuf(sc, IWX_RBUF_SIZE, sc->rxq.cur)"
    )
    rx_entry_start = cpp.index("iwx_rx_mpdu_mq(struct iwx_softc *sc")
    rx_entry_end = cpp.index("\nvoid ItlIwx::", rx_entry_start + 1)
    rx_entry = cpp[rx_entry_start:rx_entry_end]
    assert "NativeAwdlRxEntry::Dispatch rxEntryDispatch{}" in rx_entry
    assert "transportNotificationQidPresent = 1" in rx_entry
    assert "transportNotificationIndexPresent = 1" in rx_entry
    assert "setProperty(" not in rx_entry
    assert "IOKit" not in rx_entry

    # Close-only lifecycle sync checks the current tuple and never begins.
    assert "tahoeP2pSyncRxDiagnosticOwner(bool closeOnly)" in rx_cpp
    sync_start = rx_cpp.index("void ItlIwx::tahoeP2pSyncRxDiagnosticOwner(")
    sync_end = rx_cpp.index("IOReturn ItlIwx::tahoeP2pRxDrainAction(", sync_start)
    sync = rx_cpp[sync_start:sync_end]
    assert "if (!tahoeP2pOnMainGate())" in sync
    assert "tahoeP2pCurrentRxDiagnosticEpochs(&com, &current)" in sync
    assert "if (!closeOnly)" in sync
    assert "nativeAwdlRxEntryTelemetry_.syncOwner(" in sync
    assert "true, current, true" in sync
    close_branch = sync[sync.index("// Closing is deliberately stricter"):]
    assert "lease.contextGeneration != currentRoc" in close_branch
    assert "lease.powerGeneration != currentPower" in close_branch
    assert "lease.stationGeneration != currentStation" in close_branch
    assert "session.generation != currentRoc" in close_branch
    assert "beginOwner(" not in close_branch
    consume_start = rx_cpp.index("void ItlIwx::tahoeP2pRxConsume()")
    consume_end = rx_cpp.index("\nvoid ItlIwx::", consume_start + 1)
    consume = rx_cpp[consume_start:consume_end]
    assert "tahoeP2pSyncRxDiagnosticOwner(false);" in consume
    assert "nativeAwdlRxEntryTelemetry_.endOwner" not in consume

    publisher_start = rx_cpp.index(
        "void ItlIwx::tahoeP2pPublishRxEntryTelemetry("
    )
    publisher_end = rx_cpp.index("void ItlIwx::tahoePublishResetTrace(", publisher_start)
    publisher = rx_cpp[publisher_start:publisher_end]
    for field in (
        "NativeP2PRxEntryCountChannel149",
        "NativeP2PRxEntryCountChannel36",
        "NativeP2PRxEntryCountExpectedMacPhy149",
        "NativeP2PRxEntryCountMacIndex1Channel149",
        "NativeP2PRxEntryLastTarget",
        "NativeP2PRxEntryLastMacIndexTarget",
        "NativeP2PRxEntryLastDescriptor",
        "NativeP2PRxEntryLastAwdlDataCandidate",
        "HostRxMonotonicUs", "TsfOnAirRiseRaw",
    ):
        assert field in publisher
    assert "setProperty(name, value, 64)" in publisher
    assert "static_assert(sizeof(counterNames) / sizeof(counterNames[0]) ==" in publisher
    assert "void tahoeP2pSyncRxDiagnosticOwner(bool closeOnly);" in itl_header


def run_sanitized_fixture() -> None:
    with tempfile.TemporaryDirectory(prefix="test085-rx-identity-",
                                     dir="/private/tmp") as tmp:
        binary = Path(tmp) / "rx-identity-test"
        subprocess.run([
            "xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            str(FIXTURE), str(ROOT / "native/awdl_data_frame.cpp"),
            "-o", str(binary),
        ], check=True, capture_output=True, text=True)
        subprocess.run([str(binary)], check=True, timeout=5,
                       capture_output=True, text=True)

        finish_binary = Path(tmp) / "rx-finish-close-test"
        harness = Path(tmp) / "rx-finish-close-test.cpp"
        harness.write_text(finish_harness(finish_close_snippet()))
        subprocess.run([
            "xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            "-I", str(ROOT), str(harness), "-o", str(finish_binary),
        ], check=True, capture_output=True, text=True)
        subprocess.run([str(finish_binary)], check=True, timeout=5,
                       capture_output=True, text=True)


def main() -> None:
    source_contracts()
    run_sanitized_fixture()
    sources = [HEADER, FIXTURE, ITL_CPP, ITL_HEADER, RX_CPP, PROBE_CPP, RUNNER]
    report = {
        "schema": "test085-rx-identity-host-v1",
        "offline_host_tests_passed": True,
        "source_contracts_passed": True,
        "sanitizers": ["address", "undefined"],
        "coverage": [
            "actual production inspect and record helpers",
            "bounded v1/v3 descriptor layouts",
            "raw and missing mac_context",
            "raw zero and unknown or band-in-RX decode mode",
            "raw GP2 wrap and separate TSF presence/validity",
            "64-bit host timestamp and distinct RFH slot versus notification qid/index",
            "epoch mismatch and stale close rejection",
            "pre-ACK no-owner and eligible post-ACK begin",
            "empty END cannot create, duplicate begin preserves counters, terminal epoch cannot reopen",
            "strict valid MAC/PHY target and strict MAC-only target under band-in-RX",
            "CRC, overrun, truncated descriptor, and invalid MPDU bounds do not create target witnesses",
            "extracted production finish-close block: no-END timeout with zero frames closes and retains epochs",
            "extracted production finish-close block: pre-timeout MPDU counters/witnesses survive closure",
            "extracted production finish-close block: repeated END/finish does not reopen or clear evidence",
            "extracted production finish-close block: stale epoch cannot close newer owner",
            "extracted production finish-close block: empty-owner finish remains inactive",
        ],
        "source_sha256": {
            str(path.relative_to(ROOT)): sha256(path) for path in sources
        },
        "kernel_build_or_rf_tested": False,
    }
    RECEIPT.parent.mkdir(parents=True, exist_ok=True)
    RECEIPT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("PASS: Test085 RX identity, finish-close lifecycle glue, timing, ring and strict target host verification")
    print(RECEIPT)


if __name__ == "__main__":
    main()
