#!/usr/bin/env python3
"""Test142: classify MIF, advertised-window, and physical-lease timestamps."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"


def braced_source(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for end in range(opening, len(source)):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if depth == 0:
                return source[start : end + 1]
    raise AssertionError(f"unterminated block: {marker}")


def main() -> int:
    source = SOURCE.read_text(encoding="utf-8")
    enum = braced_source(source, "enum class CurrentAwLeaseEvidenceClass")
    classifier = braced_source(source, "static CurrentAwLeaseEvidenceClass classifyCurrentAwLeaseEvidence(")

    # Test141 evidence: MIF and planner are late for the local PSF-advertised
    # channel-6 slots, while still inside the more conservative physical ROC
    # deadline. This must remain a diagnostic class, never an authorization.
    harness = r"""
#include <assert.h>
#include <stdint.h>
__ENUM__;
__CLASSIFIER__
int main() {
    using C = CurrentAwLeaseEvidenceClass;
    assert(classifyCurrentAwLeaseEvidence(false, 10, 11, 12, 20) ==
           C::kNoEvidence);
    assert(classifyCurrentAwLeaseEvidence(true, 185048458ULL, 185049161ULL,
           185043443ULL, 185063966ULL) ==
           C::kMifAfterAdvertisedWindowButInsidePhysicalLease);
    assert(classifyCurrentAwLeaseEvidence(true, 99, 100, 100, 120) ==
           C::kPlannerAfterAdvertisedWindowButMifInside);
    assert(classifyCurrentAwLeaseEvidence(true, 100, 101, 100, 120) ==
           C::kMifAfterAdvertisedWindowButInsidePhysicalLease);
    assert(classifyCurrentAwLeaseEvidence(true, 100, 120, 100, 120) ==
           C::kPlannerAtOrAfterPhysicalDeadline);
    assert(classifyCurrentAwLeaseEvidence(true, 120, 121, 100, 120) ==
           C::kMifAtOrAfterPhysicalDeadline);
    assert(classifyCurrentAwLeaseEvidence(true, 110, 109, 100, 120) ==
           C::kInvalidTimestampOrder);
    assert(classifyCurrentAwLeaseEvidence(true, 110, 111, 120, 119) ==
           C::kInvalidBoundaryOrder);
    return 0;
}
""".replace("__ENUM__", enum).replace("__CLASSIFIER__", classifier)

    compiler = shutil.which("clang++") or shutil.which("clang")
    if not compiler:
        raise RuntimeError("clang++ or clang is required for Test142")
    with tempfile.TemporaryDirectory(prefix="test142-lease-evidence-") as temp:
        source_path = Path(temp) / "lease-evidence.cpp"
        binary = Path(temp) / "lease-evidence"
        source_path.write_text(harness, encoding="utf-8")
        subprocess.run(
            [compiler, "-std=c++14", "-Wall", "-Wextra", "-Werror",
             str(source_path), "-o", str(binary)],
            check=True,
        )
        subprocess.run([str(binary)], check=True)

    mif = braced_source(source, "static mbuf_t takeDiscoveryPacketMifCurrent(")
    assert "timingInput.binding.sameEntryVerified" in mif
    assert "Status::kInvalidInput &&\n         verifiedMifIdentityForTrace" in mif
    assert "run->mifPacingWindowEndUs" in mif
    assert "run->psfCandidate.hardDeadlineUs" in mif
    assert "run->discoveryBinding.authorizeTake(" in mif
    assert mif.index("planDiscoveryMifCurrentTarget(") < mif.index(
        "run->discoveryBinding.authorizeTake("
    )
    print("PASS: Test142 lease evidence distinguishes the advertised window from physical ROC time")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
