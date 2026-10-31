#!/usr/bin/env python3
"""Structural checks for the production AWDL RX observer integration.

This does not execute kernel code. It protects the gate, epoch, timestamp and
numeric-only publication boundaries in the source that will be built into the
Tahoe target.
"""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]


def function_body(source: str, signature: str) -> str:
    match = re.search(signature + r"\s*\{", source)
    assert match, f"missing function matching {signature!r}"
    start = match.end() - 1
    depth = 0
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start + 1:index]
    raise AssertionError(f"unterminated function {signature!r}")


def main() -> None:
    rx = (ROOT / "itlwm/hal_iwx/ItlIwxP2PRx.cpp").read_text()
    router = (ROOT / "native/intel_p2p_rx_router.cpp").read_text()
    airport = (ROOT / "AirportItlwm/AirportItlwm.cpp").read_text()

    drain = function_body(rx, r"void\s+ItlIwx::tahoeP2pRxDrain\(\)")
    callback = function_body(
        rx, r"IOReturn\s+ItlIwx::tahoeP2pRxDrainAction\([^)]*\)"
    )
    consume = function_body(rx, r"void\s+ItlIwx::tahoeP2pRxConsume\(\)")
    tap = function_body(
        rx, r"void\s+ItlIwx::tahoeP2pTapAction\([^)]*\)"
    )

    # The watchdog runs on its own workloop. A busy main gate must not block it;
    # the next timer tick retries because the queue is left untouched here.
    assert "fWatchdogWorkLoop = IOWorkLoop::workLoop()" in airport
    assert "fWatchdogWorkLoop->addEventSource(watchdogTimer)" in airport
    fallback_start = drain.index("if (!workLoop->inGate())")
    fallback_end = drain.index("const uint64_t nowUs", fallback_start)
    fallback = drain[fallback_start:fallback_end]
    assert "attemptAction(tahoeP2pRxDrainAction, this)" in fallback
    assert "return;" in fallback
    assert "popRecord" not in fallback
    assert "owner->getMainWorkLoop()->inGate()" in callback
    assert "owner->tahoeP2pRxDrain()" in callback

    # Queue mutation now lives in the main-gate consume helper. The watchdog
    # drain retries the gate non-blockingly, consumes only after the gate check,
    # then takes a fresh publication epoch/time before snapshotting the observer.
    consume_call = drain.index("tahoeP2pRxConsume();")
    assert fallback_start < consume_call < fallback_end
    consume_gate = consume.index("if (!tahoeP2pOnMainGate())")
    consume_time = consume.index("const uint64_t nowUs = tahoeP2pRxMonotonicUs()")
    consume_epochs_start = consume.index("const IntelAwdlPeer::RuntimeEpochs epochs")
    observe_at = consume.index("tahoe_awdl_peer_observer_.observe(")
    assert consume_gate < consume_time < consume_epochs_start < observe_at
    assert "tahoe_awdl_peer_observer_.observe(" not in drain

    drain_epochs_start = drain.index("const IntelAwdlPeer::RuntimeEpochs epochs")
    snapshot_at = drain.index("tahoe_awdl_peer_observer_.snapshot(")
    assert consume_call < fallback_end < drain_epochs_start < snapshot_at
    for body, epochs_start in ((consume, consume_epochs_start),
                               (drain, drain_epochs_start)):
        epochs = body[epochs_start:body.index("};", epochs_start)]
        assert "nativeP2pProbeGeneration_ != 0" in epochs
        assert "IEEE80211_S_RUN" in epochs
        assert "IWX_FLAG_SHUTDOWN | IWX_FLAG_HW_ERR" in epochs
        assert "tahoe_p2p_rx_lease_" not in epochs
        assert "lease.active" not in epochs

    # Receive time and three record generations are captured at the RX tap.
    assert "tahoeP2pRxMonotonicUs()" in tap
    assert re.search(
        r"tahoe_p2p_rx_router_\.tapActionFrame\([\s\S]*?"
        r"tahoeP2pRxMonotonicUs\(\),\s*gp2TimestampUs,\s*"
        r"gp2TimestampPresent,",
        tap,
    )
    assert "out.generation = lease.contextGeneration;" in router
    assert "out.powerGeneration = lease.powerGeneration;" in router
    assert "out.stationGeneration = lease.stationGeneration;" in router
    assert "out.rxMonotonicUs = rxMonotonicUs;" in router

    # Only scalar diagnostics leave the observer. No peer address, ARPA name,
    # or raw frame data may be published through IORegistry properties.
    properties = re.findall(r'setProperty\("([^"]+)"', drain)
    assert properties
    forbidden = ("Mac", "Address", "Name", "Raw", "Bytes", "Payload")
    assert not [name for name in properties if any(word in name for word in forbidden)]
    assert "bzero(&record, sizeof(record));" in consume


if __name__ == "__main__":
    main()
