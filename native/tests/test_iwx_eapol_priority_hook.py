#!/usr/bin/env python3
"""Test the strict RSN Group2 classifier and its production TX/trace hooks."""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[2]


def function_body(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:index]
    raise AssertionError(f"unterminated function: {marker}")


def test_production_hooks() -> None:
    tx_source = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
    tx = function_body(tx_source, "iwx_tx(struct iwx_softc *sc, mbuf_t m")
    classify = tx.index("IwxEapolPriority::isRsnGroup2(")
    sequence_control = tx.index("const uint16_t sequenceControl =")
    copy = tx.index("mbuf_copydata(m, hdrlen, sizeof(body), body) == 0")
    mark = tx.index("flags |= htole32(IWX_TX_FLAGS_HIGH_PRI)", classify)
    protect = tx.index("if (wh->i_fc[1] & IEEE80211_FC1_PROTECTED)", mark)
    assert sequence_control < copy < classify < mark < protect
    assert "wh->i_seq[0]" in tx[sequence_control:classify]
    assert "wh->i_seq[1]) << 8" in tx[sequence_control:classify]
    assert "sequenceControl, body, sizeof(body)" in tx[classify:mark]
    assert "hdrlen == sizeof(struct ieee80211_frame)" in tx
    assert "mbuf_pkthdr_len(m) == hdrlen +" in tx
    assert "group2Tag" not in tx[copy:protect]
    assert tx.index("tx_gen3->flags = htole16(flags)") > mark
    assert tx.index("tx_gen2->flags = htole32(flags)") > mark

    input_source = (
        ROOT / "itl80211/openbsd/net80211/ieee80211_pae_input.c"
    ).read_text()
    output_source = (
        ROOT / "itl80211/openbsd/net80211/ieee80211_pae_output.c"
    ).read_text()
    output_proto = (
        ROOT / "itl80211/openbsd/net80211/ieee80211_proto.h"
    ).read_text()
    trace_header = (ROOT / "native/iwx_sta_auth_trace.h").read_text()

    internal = function_body(
        output_source, "ieee80211_send_group_msg2_internal("
    )
    write_replay = internal.index(
        "BE_WRITE_8(key->replaycnt, ni->ni_replaycnt)"
    )
    echo = internal.index("iwx_sta_auth_replay_echo_flags(", write_replay)
    send = internal.index("ieee80211_send_eapol_key_internal(", echo)
    assert write_replay < echo < send
    assert "receivedReplay, key->replaycnt" in internal[echo:send]

    wrapper = function_body(
        input_source, "static int ieee80211_tahoe_send_group_msg2("
    )
    assert "receivedReplay" in wrapper and "replayEchoFlags" in wrapper
    assert "ieee80211_send_group_msg2_traced(" in wrapper
    assert "return ieee80211_send_group_msg2(ic, ni, key)" not in wrapper
    assert input_source.count("traceAttempt, key->replaycnt, &group2ReplayEchoFlags") == 2
    assert input_source.count("group2Result, group2ReplayEchoFlags, 0,") == 2
    assert "IWX_STA_FLAG_GROUP2_REPLAY_ECHO_CHECKED = 1u << 12" in trace_header
    assert "IWX_STA_FLAG_GROUP2_REPLAY_ECHO_EQUAL = 1u << 13" in trace_header
    assert "IWX_STA_FLAG_GROUP2_REPLAY_ECHO_MISMATCH = 1u << 14" in trace_header
    assert "const struct IwxGroup2TxTag *, const u_int8_t *, uint32_t *" in output_proto


def test_classifier_and_echo() -> None:
    compiler = shutil.which("clang++") or shutil.which("g++")
    assert compiler, "clang++ or g++ is required for the pure helper test"
    source = ROOT / "native/tests/iwx_eapol_priority_test.cpp"
    with tempfile.TemporaryDirectory(prefix="iwx-eapol-priority-") as temp:
        binary = pathlib.Path(temp) / "iwx_eapol_priority_test"
        subprocess.run(
            [compiler, "-std=c++11", "-Wall", "-Wextra", "-Werror",
             str(source), "-o", str(binary)],
            check=True,
        )
        subprocess.run([str(binary)], check=True)


def main() -> None:
    test_classifier_and_echo()
    test_production_hooks()
    print("Test102 RSN Group2 priority/replay-echo: PASS")


if __name__ == "__main__":
    main()
