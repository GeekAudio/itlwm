#include "../intel_roc_time_event.hpp"

#include <array>
#include <cassert>
#include <cstdint>

using namespace IntelROC;

static void TestNormalRocGoldenBytes()
{
    TimeEventCommand command{};
    assert(BuildTimeEventCommand(3, 0xa1, RocKind::kNormal, 300, &command));

    const std::array<std::uint8_t, kTimeEventCommandSize> expected = {{
        0x03, 0xa1, 0x00, 0x00, // MAC ID + color
        0x01, 0x00, 0x00, 0x00, // ADD
        0x04, 0x00, 0x00, 0x00, // P2P device discoverable
        0x00, 0x00, 0x00, 0x00, // apply time
        0x92, 0x00, 0x00, 0x00, // 300 ms / 2 = 150 ms -> 146 TU
        0x00, 0x00, 0x00, 0x00, // dependency
        0x01, 0x00, 0x00, 0x00, // interval
        0x24, 0x01, 0x00, 0x00, // 300 ms -> 292 TU
        0x01, 0x05,             // repeat once, 5 fragments
        0x03, 0x08,             // host start/end + start immediately
    }};
    assert(command.bytes == expected);
}

static void TestManagementTxEventAndRawResponse()
{
    TimeEventCommand command{};
    assert(BuildTimeEventCommand(7, 2, RocKind::kManagementTx, 500, &command));
    assert(command.bytes[8] == 9); // P2P client association event

    const std::array<std::uint8_t, kTimeEventResponseSize> responseBytes = {{
        0x01, 0x00, 0x00, 0x00, // raw status: do not infer success here
        0x09, 0x00, 0x00, 0x00, // event type
        0x78, 0x56, 0x34, 0x12, // unique UID
        0x07, 0x02, 0x00, 0x00, // matching MAC ID + color
    }};
    TimeEventResponse response{};
    assert(DecodeRawTimeEventResponse(responseBytes.data(), responseBytes.size(),
                                      &response) == ResponseResult::kDecoded);
    assert(response.rawStatus == 1);
    assert(response.rawEventType == 9);
    assert(response.uniqueId == 0x12345678u);
    assert(response.rawMacIdAndColor == 0x207u);
}

static void TestRejectsInvalidInputsAndResponses()
{
    TimeEventCommand command{};
    assert(!BuildTimeEventCommand(1, 1, RocKind::kNormal, 0, &command));
    assert(!BuildTimeEventCommand(1, 1, RocKind::kNormal, 1, &command));
    assert(!BuildTimeEventCommand(1, 1, static_cast<RocKind>(0xff), 300, &command));

    std::array<std::uint8_t, kTimeEventResponseSize> bytes = {{
        0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x03, 0xa1, 0x00, 0x00,
    }};
    TimeEventResponse response{};
    assert(DecodeRawTimeEventResponse(bytes.data(), bytes.size() - 1,
                                      &response) == ResponseResult::kInvalidLength);
    assert(DecodeRawTimeEventResponse(bytes.data(), bytes.size(),
                                      &response) == ResponseResult::kDecoded);
    assert(response.rawStatus == 0);
    assert(response.rawEventType == 4);
    assert(response.uniqueId == 0); // Preserve; zero is not proven invalid.
    assert(response.rawMacIdAndColor == 0xa103u);

    bytes[0] = 0xff;
    bytes[1] = 0xff;
    bytes[2] = 0xff;
    bytes[3] = 0xff;
    assert(DecodeRawTimeEventResponse(bytes.data(), bytes.size(),
                                      &response) == ResponseResult::kDecoded);
    assert(response.rawStatus == 0xffffffffu); // Preserve unknown/error bits.
}

int main()
{
    TestNormalRocGoldenBytes();
    TestManagementTxEventAndRawResponse();
    TestRejectsInvalidInputsAndResponses();
    return 0;
}
