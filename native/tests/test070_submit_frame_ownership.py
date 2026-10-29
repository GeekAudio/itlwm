#!/usr/bin/env python3
"""Exercise the production callback/worker frame-ownership reconciliation."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"


def extract(source, marker):
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def main():
    source = PROBE.read_text(encoding="utf-8")
    run = extract(source, "struct P2PTxSubmitRun {") + ";"
    reconcile = extract(source, "static void reconcileP2PTxSubmitFrame(")
    worker = extract(source, "static int runTxProbeSession(")
    callback = extract(source, "static IOReturn tahoeP2pSubmitActionInGate(")
    gate_call = worker.index("gate->runAction(\n                tahoeP2pSubmitActionInGate, &submit)")
    reconcile_call = worker.index("reconcileP2PTxSubmitFrame(frame, &submit)")
    assert reconcile_call > gate_call
    assert "if (submit.frameConsumed)" not in worker
    assert "submit->frameStale" in reconcile
    replacement = callback.index(
        "mbuf_freem(action->frame);\n        action->frame = refreshedFrame;")
    identity_failure = callback.index(
        "if (identityFailure != kNativeIdentityVerified)")
    assert replacement < identity_failure
    assert "action->frameStale = true;" in callback[identity_failure:]

    fixture = r"""
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
struct P2PProbeRun;
struct FakeMbuf { unsigned id; bool freed; };
using mbuf_t = FakeMbuf *;
static unsigned gFrees[8]{};
static void mbuf_freem(mbuf_t frame) {
    assert(frame && frame->id < 8 && !frame->freed);
    frame->freed = true;
    ++gFrees[frame->id];
}
static FakeMbuf gA{1, false}, gB{2, false}, gC{3, false};
""" + run + "\n" + reconcile + r"""
int main() {
    // Callback replaces A with B, then a later identity check rejects. Worker
    // still held A by value; the boundary must free only returned current B.
    {
        mbuf_t workerFrame = &gA;
        P2PTxSubmitRun submit{};
        submit.frame = &gA;
        mbuf_freem(submit.frame); // same swap order as production callback
        submit.frame = &gB;
        submit.frameStale = true;
        reconcileP2PTxSubmitFrame(&workerFrame, &submit);
        assert(workerFrame == nullptr && submit.frame == nullptr);
        assert(gFrees[1] == 1 && gFrees[2] == 1);
    }
    // If the callback has not replaced A, a stale return frees A once.
    {
        mbuf_t workerFrame = &gC;
        P2PTxSubmitRun submit{};
        submit.frame = &gC;
        submit.frameStale = true;
        reconcileP2PTxSubmitFrame(&workerFrame, &submit);
        assert(workerFrame == nullptr && submit.frame == nullptr);
        assert(gFrees[3] == 1);
    }
    // A non-stale replacement is returned to the worker for the next attempt.
    {
        FakeMbuf replacement{4, false};
        mbuf_t workerFrame = &gA;
        P2PTxSubmitRun submit{};
        submit.frame = &replacement;
        reconcileP2PTxSubmitFrame(&workerFrame, &submit);
        assert(workerFrame == &replacement && submit.frame == &replacement);
        assert(gFrees[4] == 0);
        mbuf_freem(workerFrame);
        assert(gFrees[4] == 1);
    }
    // The low-level HAL consumes the frame on success. The callback reports
    // the ownership transfer, so the boundary must not free it a second time.
    {
        FakeMbuf consumed{5, false};
        mbuf_t workerFrame = &gA;
        P2PTxSubmitRun submit{};
        submit.frame = &consumed;
        mbuf_freem(submit.frame); // production Action HAL success path
        submit.frame = nullptr;
        submit.frameConsumed = true;
        submit.result = 0;
        reconcileP2PTxSubmitFrame(&workerFrame, &submit);
        assert(workerFrame == nullptr && submit.frame == nullptr);
        assert(gFrees[5] == 1);
    }
    // Exact pre-doorbell cancellation also consumes/frees the mbuf once; its
    // error status must not make the caller reclaim the transferred pointer.
    {
        FakeMbuf cancelled{7, false};
        mbuf_t workerFrame = &gA;
        P2PTxSubmitRun submit{};
        submit.frame = &cancelled;
        mbuf_freem(submit.frame); // production cancelBeforeDoorbell path
        submit.frame = nullptr;
        submit.frameConsumed = true;
        submit.result = ETIMEDOUT;
        reconcileP2PTxSubmitFrame(&workerFrame, &submit);
        assert(workerFrame == nullptr && submit.frame == nullptr);
        assert(gFrees[7] == 1);
    }
    // A retryable non-stale return preserves the callback's current frame.
    {
        FakeMbuf retained{6, false};
        mbuf_t workerFrame = &gA;
        P2PTxSubmitRun submit{};
        submit.frame = &retained;
        reconcileP2PTxSubmitFrame(&workerFrame, &submit);
        assert(workerFrame == &retained && gFrees[6] == 0);
        mbuf_freem(workerFrame);
        assert(gFrees[6] == 1);
    }
    std::puts("PASS: production submit-boundary replacement, stale, consume and retry ownership is exactly-once under ASan/UBSan");
}
"""
    with tempfile.TemporaryDirectory(prefix="test070-submit-frame-ownership-") as temp:
        cpp = Path(temp) / "test070_submit_frame_ownership.cpp"
        binary = Path(temp) / "test070_submit_frame_ownership"
        cpp.write_text(fixture)
        subprocess.run([
            "c++", "-std=c++14", "-O1", "-g", "-Wall", "-Wextra",
            "-Werror", "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer", str(cpp), "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
