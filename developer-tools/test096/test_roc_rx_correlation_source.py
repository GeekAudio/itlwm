#!/usr/bin/env python3
"""Guard Test096 source integration against the frozen receive baseline."""

import hashlib
from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
BASELINE = "7de62a3d887fb1ec48e2080787838fe418489eec"
DRIVER_CPP = "itlwm/hal_iwx/ItlIwx.cpp"
DRIVER_HPP = "itlwm/hal_iwx/ItlIwx.hpp"
P2P_CPP = "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"
FEATURE = "ITL_NATIVE_RX_PREOWNER_OBSERVATION_25G332"


def read_baseline(path: str) -> str:
    return subprocess.check_output(
        ["git", "show", f"{BASELINE}:{path}"], cwd=ROOT, text=True
    )


def extract_function(source: str, marker: str) -> str:
    """Return one C++ function, balancing braces outside comments/literals."""
    start = source.find(marker)
    if start < 0:
        raise AssertionError(f"function marker not found: {marker}")
    opening = source.find("{", start)
    if opening < 0:
        raise AssertionError(f"function body not found: {marker}")

    depth = 0
    state = "code"
    index = opening
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and next_char == "*":
                state = "block-comment"
                index += 2
                continue
            if char == "/" and next_char == "/":
                state = "line-comment"
                index += 2
                continue
            if char == '"':
                state = "string"
                index += 1
                continue
            if char == "'":
                state = "char"
                index += 1
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return source[start:index + 1]
        elif state == "block-comment":
            if char == "*" and next_char == "/":
                state = "code"
                index += 2
                continue
        elif state == "line-comment":
            if char == "\n":
                state = "code"
        elif state in ("string", "char"):
            if char == "\\":
                index += 2
                continue
            if (state == "string" and char == '"') or (
                    state == "char" and char == "'"):
                state = "code"
        index += 1
    raise AssertionError(f"unterminated function: {marker}")


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class RocRxCorrelationSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.current_cpp = (ROOT / DRIVER_CPP).read_text()
        cls.baseline_cpp = read_baseline(DRIVER_CPP)
        cls.current_hpp = (ROOT / DRIVER_HPP).read_text()
        cls.current_p2p = (ROOT / P2P_CPP).read_text()

    def test_crc_length_decrypt_and_reorder_receive_path_matches_baseline(self):
        marker = "iwx_rx_mpdu_mq(struct iwx_softc *sc"
        rx_tail_marker = (
            "// The RX notification declares its actual payload length separately from"
        )
        current_mpdu = extract_function(self.current_cpp, marker)
        baseline_mpdu = extract_function(self.baseline_cpp, marker)
        current_tail = current_mpdu[current_mpdu.index(rx_tail_marker):]
        baseline_tail = baseline_mpdu[baseline_mpdu.index(rx_tail_marker):]

        self.assertEqual(sha256(current_tail), sha256(baseline_tail))
        self.assertIn("IWX_RX_MPDU_RES_STATUS_CRC_OK", current_tail)
        self.assertIn("len > actualPayloadLength - desc_size", current_tail)
        self.assertIn("iwx_rx_hwdecrypt(sc, m", current_tail)
        self.assertIn("iwx_rx_reorder(sc, m", current_tail)

        # These downstream handlers are part of the same acceptance path.
        for marker in (
            "iwx_rx_frame(struct iwx_softc *sc",
            "iwx_rx_hwdecrypt(struct iwx_softc *sc",
            "iwx_rx_reorder(struct iwx_softc *sc",
        ):
            self.assertEqual(
                sha256(extract_function(self.current_cpp, marker)),
                sha256(extract_function(self.baseline_cpp, marker)),
                marker,
            )

    def test_one_copy_result_flows_through_one_slot_token_then_finishes(self):
        current = extract_function(
            self.current_cpp, "iwx_notif_intr(struct iwx_softc *sc"
        )
        self.assertEqual(current.count("tryCopyForIdentity("), 1)
        self.assertEqual(current.count("beginSlot(input, observation)"), 1)

        copy_at = current.index("tryCopyForIdentity(")
        begin_at = current.index("beginSlot(input, observation)")
        packet_at = current.index(
            "iwx_rx_pkt(sc, data, &ml, ringSlot, rocCopyToken)", begin_at
        )
        finish_at = current.index("finishSlot(rocCopyToken)", packet_at)
        cursor_at = current.index(
            "sc->rxq.cur = (ringSlot + 1) % IWX_RX_MQ_RING_COUNT;", finish_at
        )
        self.assertLess(copy_at, begin_at)
        self.assertLess(begin_at, packet_at)
        self.assertLess(packet_at, finish_at)
        self.assertLess(finish_at, cursor_at)
        self.assertIn("recordAttempt(\n                &nativeRxCompletionTelemetry_", current)
        self.assertIn("hw, ringSlot, observation);", current)

        # Preserve the production RX descriptor lookup, cursor advance, and
        # RFH write-index calculation exactly as they existed at the base.
        for statement in (
            "const uint32_t ringSlot = static_cast<uint32_t>(sc->rxq.cur);",
            "struct iwx_rx_data *data = &sc->rxq.data[ringSlot];",
            "sc->rxq.cur = (ringSlot + 1) % IWX_RX_MQ_RING_COUNT;",
            "hw = (hw == 0) ? IWX_RX_MQ_RING_COUNT - 1 : hw - 1;",
            "IWX_WRITE(sc, IWX_RFH_Q0_FRBDCB_WIDX_TRG, hw & ~7);",
        ):
            self.assertEqual(self.baseline_cpp.count(statement), 1, statement)
            self.assertEqual(self.current_cpp.count(statement), 1, statement)

        # Token presence only enables diagnostic fields/timestamp capture. The
        # original MPDU-count/add-buffer condition remains byte-for-byte.
        original_dispatch = (
            "if (code == IWX_REPLY_RX_MPDU_CMD && ++nmpdu == 1) {"
        )
        self.assertEqual(self.baseline_cpp.count(original_dispatch), 1)
        self.assertEqual(self.current_cpp.count(original_dispatch), 1)

    def test_roc_boundaries_are_independent_of_owner_and_frame_filters(self):
        function = extract_function(
            self.current_p2p, "tahoeP2pTapSessionEvent(struct iwx_softc *sc"
        )
        reducer_at = function.index("nativeP2pRocEvents_.noteNotification(")
        observation_at = function.index(
            "// Observe actual reducer boundaries independently of per-MPDU owner"
        )
        owner_at = function.index("const auto traceOwner =")
        self.assertLess(reducer_at, observation_at)
        self.assertLess(observation_at, owner_at)
        correlation_block = function[observation_at:owner_at]
        for forbidden in ("traceOwnerMatches", "ownerQualified", "decoded149"):
            self.assertNotIn(forbidden, correlation_block)
        self.assertIn("canonicalStart", correlation_block)
        self.assertIn("canonicalEnd", correlation_block)
        self.assertIn("sessionToken = generation", correlation_block)

        packet = extract_function(
            self.current_cpp,
            "iwx_rx_pkt(struct iwx_softc *sc, struct iwx_rx_data *data",
        )
        validated_at = packet.index(
            "NotificationOutcome::kValidated, true"
        )
        non_mpdu_at = packet.index(
            "NotificationOutcome::kNonMpdu, true"
        )
        end_event_at = packet.index("tahoeP2pTapSessionEvent(sc,")
        self.assertLess(validated_at, non_mpdu_at)
        self.assertLess(non_mpdu_at, end_event_at)

    def test_token_api_and_publication_are_feature_isolated_and_read_only(self):
        for source, marker in (
            (self.current_cpp, "tahoeRxRocCorrelationSync(uint64_t nowUs)"),
            (self.current_cpp, "tahoeRxRocCorrelationPublish(IOEthernetController *controller)"),
            (self.current_hpp, "NativeIwxRocRxCorrelation::Recorder nativeRxRocCorrelation_"),
        ):
            # The new symbols exist only in the opt-in observation profile.
            symbol_at = source.index(marker)
            guards = [
                match.start()
                for match in re.finditer(r"(?m)^\s*#if[^\n]*$", source[:symbol_at])
                if FEATURE in match.group(0)
            ]
            guard_at = guards[-1] if guards else -1
            self.assertGreater(guard_at, -1, marker)
            self.assertNotIn("#endif", source[guard_at:symbol_at], marker)
            self.assertGreater(source.find("#endif", symbol_at), symbol_at, marker)

        publisher = extract_function(
            self.current_cpp,
            "tahoeRxRocCorrelationPublish(IOEthernetController *controller)",
        )
        self.assertIn("nativeRxRocPublishAttempts_ >= 3u", publisher)
        self.assertIn("readyToEncode()", publisher)
        self.assertIn("nativeRxRocCorrelation_.encode(", publisher)
        self.assertIn("nativeRxRocPublishWire_", publisher)
        self.assertEqual(publisher.count("controller->setProperty("), 1)
        self.assertIn('"NativeRXRocCopyCorrelation"', publisher)
        for hardware_operation in (
            "IWX_READ(", "IWX_WRITE(", "bus_dmamap_", "tryCopyForIdentity(",
            "used_desc_dma", "rxq.data[",
        ):
            self.assertNotIn(hardware_operation, publisher)

        self.assertIn(
            f"flags += ' -D{FEATURE}=1'", (ROOT / "scripts/build_tahoe.py").read_text()
        )

    def test_arm_publication_and_stop_are_serialized_without_blocking_rx(self):
        sync = extract_function(
            self.current_cpp, "tahoeRxRocCorrelationSync(uint64_t nowUs)"
        )
        self.assertIn("!tahoeP2pOnMainGate()", sync)
        self.assertIn("nativeRxRocArmReady_, __ATOMIC_ACQUIRE", sync)

        # A firmware/layout profile without the observed completion mapping
        # must close incomplete before START/END can produce a zero-slot pass.
        family_check_at = sync.index(
            "if (uint32_t(com.sc_device_family) !=\n"
            "        NativeIwxCompletionObserver::kObservedFamily)"
        )
        stop_check_at = sync.index("nativeRxPreOwnerStopSerial_", family_check_at)
        family_guard = sync[family_check_at:stop_check_at]
        self.assertIn(
            "recorder.close(CloseReason::kInvalidBoundary, nowUs)", family_guard
        )
        self.assertIn("return;", family_guard)
        completion_header = (ROOT / "native/iwx_completion_observer.hpp").read_text()
        self.assertRegex(completion_header, r"kObservedFamily\s*=\s*2\s*;")
        self.assertIn("family != kObservedFamily", completion_header)

        self.assertIn("nativeRxPreOwnerStopSerial_", sync)
        self.assertIn("nativeRxRocArmStopSerial_", sync)
        self.assertIn("nativeRxPreOwnerStopDepth_", sync)
        self.assertIn("recorder.close(CloseReason::kStop, nowUs)", sync)
        self.assertIn(
            "recorder.state() == State::kArmed &&\n               !nativeRxPreOwner_.enabled()",
            sync,
        )

        arm = extract_function(
            self.current_p2p, "IOReturn ItlIwx::nativeP2pArmProbe()"
        )
        self.assertIn("nativeRxPreOwnerStopSerial_, __ATOMIC_ACQUIRE", arm)
        self.assertIn("nativeRxRocArmUs_", arm)
        self.assertIn("nativeRxRocArmGeneration_", arm)
        self.assertIn("nativeRxRocArmStopSerial_", arm)
        self.assertIn("nativeRxRocArmReady_, 1u, __ATOMIC_RELEASE", arm)
        self.assertIn("nativeRxPreOwnerArmed_, 1u, __ATOMIC_RELEASE", arm)
        self.assertIn("observerStopSerial != __atomic_load_n(", arm)

        # Stop may race the top-of-loop check. The post-finish Sync must see
        # the monotonically changing serial/depth and close before publication;
        # readyToEncode also waits until the slot token is finalized.
        loop = extract_function(
            self.current_cpp, "iwx_notif_intr(struct iwx_softc *sc"
        )
        finish_at = loop.index("finishSlot(rocCopyToken)")
        sync_after_finish = loop.index(
            "tahoeRxRocCorrelationSync(tahoeMonotonicNs() / 1000ULL);",
            finish_at,
        )
        cursor_at = loop.index(
            "sc->rxq.cur = (ringSlot + 1) % IWX_RX_MQ_RING_COUNT;",
            sync_after_finish,
        )
        self.assertLess(finish_at, sync_after_finish)
        self.assertLess(sync_after_finish, cursor_at)

    def test_summary_hooks_share_the_registered_main_workloop_gate(self):
        attach = extract_function(self.current_cpp, "bool ItlIwx::attach(")
        self.assertIn("pci.workloop = getMainWorkLoop();", attach)

        iwx_attach = extract_function(
            self.current_cpp, "iwx_attach(struct iwx_softc *sc"
        )
        self.assertIn("rxInterruptWorkloop_ = pa->workloop;", iwx_attach)
        self.assertIn("rxInterruptWorkloop_->addEventSource(sc->sc_ih)",
                      iwx_attach)
        self.assertIn("IOFilterInterruptEventSource::filterInterruptEventSource(",
                      iwx_attach)

        main_gate = self.current_hpp[
            self.current_hpp.index("bool tahoeP2pOnMainGate()"):
            self.current_hpp.index("IOCommandGate *tahoeP2pCommandGate()")
        ]
        self.assertIn("getMainWorkLoop()", main_gate)
        self.assertIn("loop->inGate()", main_gate)

        irq_observer = extract_function(
            self.current_cpp, "void ItlIwx::tahoeRxPreOwnerIrq("
        )
        self.assertIn("if (tahoeP2pOnMainGate())", irq_observer)
        self.assertIn("observeRxInterrupt(event.nowUs, msix)", irq_observer)
        for blocking_or_heavy_call in (
            "IOSimpleLock", "IORecursiveLock", "runAction(", "setProperty(",
            "IWX_READ(", "IWX_WRITE(", "tryCopyForIdentity(",
        ):
            self.assertNotIn(blocking_or_heavy_call, irq_observer)

        legacy_irq = extract_function(
            self.current_cpp, "iwx_intr(OSObject *object"
        )
        msix_irq = extract_function(
            self.current_cpp, "iwx_intr_msix(OSObject *object"
        )
        self.assertIn("that->tahoeRxPreOwnerIrq(uint32_t(r1), false);",
                      legacy_irq)
        self.assertIn("that->iwx_notif_intr(sc);", legacy_irq)
        self.assertIn("that->tahoeRxPreOwnerIrq(inta_fh, true);", msix_irq)
        self.assertIn("that->iwx_notif_intr(sc);", msix_irq)

        drain = extract_function(
            self.current_cpp, "iwx_notif_intr(struct iwx_softc *sc"
        )
        self.assertIn("observeRxDrain(drainUs)", drain)
        self.assertIn("observeRxRingSlot(hostUptimeUs, ringSlot, hw)", drain)
        self.assertLess(drain.index("observeRxDrain(drainUs)"),
                        drain.index("const uint32_t ringSlot"))
        self.assertLess(drain.index("observeRxRingSlot(hostUptimeUs"),
                        drain.index("iwx_rx_pkt(sc, data, &ml, ringSlot"))

        packet = extract_function(
            self.current_cpp,
            "iwx_rx_pkt(struct iwx_softc *sc, struct iwx_rx_data *data",
        )
        summary_at = packet.index("RxNotificationStage::kRxMpduNotificationValidated")
        actual_owner_dispatch_at = packet.index(
            "if (code == IWX_REPLY_RX_MPDU_CMD && ++nmpdu == 1)"
        )
        self.assertLess(summary_at, actual_owner_dispatch_at)
        self.assertIn("tahoeP2pOnMainGate()", packet[:summary_at])


if __name__ == "__main__":
    unittest.main()
