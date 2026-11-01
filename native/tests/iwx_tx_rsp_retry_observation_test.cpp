// SPDX-License-Identifier: GPL-2.0-only
#include "native/iwx_tx_rsp_retry_observation.hpp"

#include <array>
#include <cassert>
#include <cstdint>

using namespace IwxTxRspRetryObservation;

static void testCompleteSingleFramePrefix()
{
    std::array<uint8_t, kSingleFrameMinimumPayloadLength> payload{};
    payload[0] = 1;
    payload[1] = 0;
    payload[2] = 2;
    payload[3] = 3;

    Fields fields{};
    assert(decodeSingleFrameV1(payload.data(), payload.size(),
                               kSingleFrameMinimumPayloadLength, &fields));
    assert(fields.frame_count == 1);
    assert(fields.bt_kill_count == 0); // Present zero stays distinguishable.
    assert(fields.failure_rts == 2);
    assert(fields.failure_frame == 3);
}

static void testMalformedAndNonSingleFrameInputsFailClosed()
{
    std::array<uint8_t, kSingleFrameMinimumPayloadLength> payload{};
    payload[0] = 1;
    Fields fields{9, 9, 9, 9};

    assert(!decodeSingleFrameV1(nullptr, payload.size(), payload.size(), &fields));
    assert(!decodeSingleFrameV1(payload.data(), payload.size(), payload.size(), nullptr));
    assert(!decodeSingleFrameV1(payload.data(), payload.size(),
                                kSingleFrameMinimumPayloadLength - 1, &fields));
    assert(!decodeSingleFrameV1(payload.data(), payload.size() - 1,
                                kSingleFrameMinimumPayloadLength, &fields));
    assert(!decodeSingleFrameV1(payload.data(), payload.size(),
                                payload.size() + 1, &fields));
    assert(fields.frame_count == 9); // Rejection does not partially overwrite output.

    payload[0] = 0;
    assert(!decodeSingleFrameV1(payload.data(), payload.size(), payload.size(), &fields));
    payload[0] = 2; // Aggregate replies do not define the single-frame counters.
    assert(!decodeSingleFrameV1(payload.data(), payload.size(), payload.size(), &fields));
}

int main()
{
    testCompleteSingleFramePrefix();
    testMalformedAndNonSingleFrameInputsFailClosed();
    return 0;
}
