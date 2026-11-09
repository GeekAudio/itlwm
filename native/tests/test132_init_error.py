#!/usr/bin/env python3
"""Fault-inject the production Gen3 scratch-allocation failure branch."""
from __future__ import annotations

import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"


def extract_scratch_failure_prefix(source: str) -> str:
    marker = "int ItlIwx::\niwx_ctxt_info_gen3_init("
    start = source.index(marker)
    success_path = source.index(
        "    prph_scratch = (struct iwx_prph_scratch *)", start
    )
    production = source[start:success_path]
    assert "iwx_dma_contig_alloc(sc->sc_dmat, &sc->prph_scratch_dma," in production
    assert "return ENOMEM;" in production
    assert "return false;" not in production
    return production


production_prefix = extract_scratch_failure_prefix(SOURCE.read_text())

HARNESS = r"""
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>

struct iwx_context_info_gen3;
struct iwx_prph_scratch_ctrl_cfg;
struct iwx_prph_scratch { uint64_t reserved; };
struct iwx_dma_info { uint32_t reserved; };
struct iwx_softc {
    void *sc_dmat = nullptr;
    iwx_dma_info prph_scratch_dma{};
};
struct iwx_fw_sects {};

#define XYLog(...) ((void)0)
#define DEVNAME(sc) "fault-test"

static int allocatorResult = 1;
static int allocatorCalls = 0;
static void *seenTag = nullptr;
static iwx_dma_info *seenDma = nullptr;
static size_t seenSize = 0;
static int seenAlignment = -1;

static int iwx_dma_contig_alloc(void *tag, iwx_dma_info *dma,
                                size_t size, int alignment)
{
    ++allocatorCalls;
    seenTag = tag;
    seenDma = dma;
    seenSize = size;
    seenAlignment = alignment;
    return allocatorResult;
}

class ItlIwx {
public:
    int iwx_ctxt_info_gen3_init(struct iwx_softc *, const struct iwx_fw_sects *);
};

""" + production_prefix + r"""
    (void)ctxt_info_gen3;
    (void)prph_scratch;
    (void)prph_sc_ctrl;
    (void)control_flags;
    (void)fws;
    return 0;
}

int main()
{
    int dmaTag = 0;
    iwx_softc sc{};
    sc.sc_dmat = &dmaTag;
    iwx_fw_sects firmware{};

    allocatorResult = 1; // Production allocator reports failure as 1, not errno.
    const int result = ItlIwx{}.iwx_ctxt_info_gen3_init(&sc, &firmware);

    assert(result == ENOMEM);
    assert(allocatorCalls == 1);
    assert(seenTag == sc.sc_dmat);
    assert(seenDma == &sc.prph_scratch_dma);
    assert(seenSize == sizeof(iwx_prph_scratch));
    assert(seenAlignment == 0);
    return 0;
}
"""


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="test132-init-error-") as temp:
        directory = pathlib.Path(temp)
        cpp = directory / "test.cpp"
        binary = directory / "test"
        cpp.write_text(HARNESS)
        subprocess.run(
            [
                "xcrun",
                "clang++",
                "-std=c++14",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wno-unused-variable",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                str(cpp),
                "-o",
                str(binary),
            ],
            check=True,
        )
        subprocess.run([str(binary)], check=True)
    print(
        "PASS: Gen3 scratch DMA failure returns ENOMEM through the "
        "production branch (ASan/UBSan)"
    )


if __name__ == "__main__":
    main()
