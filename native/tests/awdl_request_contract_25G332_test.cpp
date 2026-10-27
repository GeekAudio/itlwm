#include "../awdl_request_contract_25G332.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <limits>

using namespace ItlAwdlRequestContract25G332;

static void writeLe16(uint8_t *bytes, size_t offset, uint16_t value) {
    bytes[offset] = static_cast<uint8_t>(value & 0xff);
    bytes[offset + 1] = static_cast<uint8_t>(value >> 8);
}

static void writeLe32(uint8_t *bytes, size_t offset, uint32_t value) {
    for (size_t i = 0; i < 4; ++i) {
        bytes[offset + i] = static_cast<uint8_t>(value >> (i * 8));
    }
}

static void writeLe64(uint8_t *bytes, size_t offset, uint64_t value) {
    for (size_t i = 0; i < 8; ++i) {
        bytes[offset + i] = static_cast<uint8_t>(value >> (i * 8));
    }
}

int main() {
    assert(kSyncRequestBytes == 16);
    assert(kOobRequestPrefixBytes == 56);
    assert(kSyncPrefixBytes == 2);
    assert(kOobHeaderBytes == 38);

    // Strict native comparison: total == max is rejected; max-1 is allowed.
    assert(checkNativeTxBound(10, 4, 14) == ParseResult::kNativeTxLimitExceeded);
    assert(checkNativeTxBound(10, 4, 15) == ParseResult::kViewOnly);
    assert(checkNativeTxBound(std::numeric_limits<size_t>::max(), 1,
                              std::numeric_limits<size_t>::max()) ==
           ParseResult::kLengthArithmeticOverflow);

    SyncTemplateView syncOut{0xaaaaaaaa, 0xbbbbbbbbbbbbbbbbULL, 0xcccc};
    std::array<uint8_t, kSyncRequestBytes> sync{};
    writeLe32(sync.data(), 0, 0xfedcba98); // Deliberately arbitrary; version is ignored.
    writeLe32(sync.data(), 4, 2);
    writeLe64(sync.data(), 8, static_cast<uint64_t>(std::numeric_limits<uintptr_t>::max()));
    Limits syncLimits{2, 17};
    assert(parseSyncTemplate(sync.data(), 15, syncLimits, &syncOut) == ParseResult::kShortRequest);
    assert(syncOut.payloadLength == 0xaaaaaaaa);
    assert(parseSyncTemplate(sync.data(), sync.size(), syncLimits, &syncOut) == ParseResult::kViewOnly);
    assert(syncOut.payloadLength == 2);
    assert(syncOut.nativeLengthPrefix == 2);
    assert(syncOut.borrowedPayloadAddress == std::numeric_limits<uintptr_t>::max());

    // Zero is rejected by selector 151 before it can be submitted.
    writeLe32(sync.data(), 4, 0);
    assert(parseSyncTemplate(sync.data(), sync.size(), syncLimits, &syncOut) == ParseResult::kZeroSyncPayload);

    // The 2-byte native prefix truncates uint32 lengths above 65535.
    writeLe32(sync.data(), 4, 65536);
    assert(parseSyncTemplate(sync.data(), sync.size(), {65536, 65550}, &syncOut) ==
           ParseResult::kPrefixWouldTruncate);
    writeLe32(sync.data(), 4, 65535);
    assert(parseSyncTemplate(sync.data(), sync.size(), {65534, 65550}, &syncOut) ==
           ParseResult::kIndependentCapExceeded);

    writeLe32(sync.data(), 4, 1);
    writeLe64(sync.data(), 8, 0);
    assert(parseSyncTemplate(sync.data(), sync.size(), {1, 15}, &syncOut) ==
           ParseResult::kNullExternalPayload);
    writeLe64(sync.data(), 8, 0x1234);
    assert(parseSyncTemplate(sync.data(), sync.size(), {1, 15}, &syncOut) ==
           ParseResult::kNativeTxLimitExceeded); // 1 + 2-byte prefix + 12-byte name == max

    // OOB uses a 56-byte native prefix with a pointer-sized value at +48.
    // This deliberately does not match the legacy inline-array declaration.
    std::array<uint8_t, kOobRequestPrefixBytes> oob{};
    OobRequestView oobOut{0xdeadbeef, 0xbeef, 0xbeef, 0xdeadbeef,
                          0xbeef, 0xbeef, 0xdeadbeef};
    writeLe32(oob.data(), 0, 0xabcdef01); // Version is not inspected.
    writeLe32(oob.data(), 4, 0x11223344);
    writeLe32(oob.data(), 8, 0x55667788);
    writeLe16(oob.data(), 20, 0x99aa);
    writeLe32(oob.data(), 22, 0xbbccddee);
    writeLe16(oob.data(), 26, 0xff01);
    writeLe16(oob.data(), 40, 1782);
    writeLe64(oob.data(), 48, 0x12345678);
    assert(parseOobRequest(oob.data(), 55, {1782, 1832}, &oobOut) == ParseResult::kShortRequest);
    assert(oobOut.unk1 == 0xdeadbeef);
    assert(parseOobRequest(oob.data(), oob.size(), {1782, 1832}, &oobOut) == ParseResult::kViewOnly);
    assert(oobOut.unk1 == 0x11223344);
    assert(oobOut.unk2Low16 == 0x7788);
    assert(oobOut.pad1 == 0x99aa);
    assert(oobOut.unk5 == 0xbbccddee);
    assert(oobOut.unk6 == 0xff01);
    assert(oobOut.dataLength == 1782);
    assert(oobOut.borrowedDataAddress == 0x12345678);

    assert(parseOobRequest(oob.data(), oob.size(), {1781, 1832}, &oobOut) ==
           ParseResult::kIndependentCapExceeded);
    assert(parseOobRequest(oob.data(), oob.size(), {1782, 1831}, &oobOut) ==
           ParseResult::kNativeTxLimitExceeded); // Native rejects total >= max.

    writeLe64(oob.data(), 48, 0);
    assert(parseOobRequest(oob.data(), oob.size(), {1782, 1832}, &oobOut) ==
           ParseResult::kNullExternalPayload);
    writeLe16(oob.data(), 40, 0);
    assert(parseOobRequest(oob.data(), oob.size(), {0, 50}, &oobOut) ==
           ParseResult::kViewOnly); // No external bytes are read for a zero length.

    assert(parseOobRequest(nullptr, oob.size(), {1, 50}, &oobOut) == ParseResult::kNullRequest);
    assert(parseOobRequest(oob.data(), oob.size(), {1, 50}, nullptr) == ParseResult::kNullOutput);
    assert(parseSyncTemplate(sync.data(), sync.size(), {1, 50}, nullptr) == ParseResult::kNullOutput);
    return 0;
}
