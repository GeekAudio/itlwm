#!/usr/bin/env python3
"""Execute the production RX149 helper and pre-STA duplicate branch offline.

The test extracts the actual HAL helper, early disposition block, and shared
STA duplicate function. Stubs model only the OS bridge queue and mbuf boundary;
no hardware, Wi-Fi, firmware, or EFI is accessed.
"""

from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
HAL = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"
P2P = ROOT / "itlwm/hal_iwx/ItlIwxP2PRx.cpp"


def extract_braced(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
        end += 1
    return source[start:end]


hal_text = HAL.read_text()
p2p_text = P2P.read_text()
mpdu = extract_braced(hal_text, "iwx_rx_mpdu_mq(struct iwx_softc *sc")
helper = extract_braced(
    p2p_text,
    "NativeP2PRx149DataInput::EarlyRoute\n"
    "ItlIwx::tahoeP2pCaptureAwdlDataBeforeStaDedup(",
)
duplicate = extract_braced(
    hal_text, "int ItlIwx::\niwx_detect_duplicate(struct iwx_softc *sc")

decrypt_pos = mpdu.index("if (iwx_rx_hwdecrypt(sc, m,")
early_call_pos = mpdu.index("tahoeP2pCaptureAwdlDataBeforeStaDedup(")
duplicate_pos = mpdu.index("if (iwx_detect_duplicate(sc, m,")
reorder_pos = mpdu.index("if (iwx_rx_reorder(sc, m,")
assert decrypt_pos < early_call_pos < duplicate_pos < reorder_pos
assert "chanidx = desc->v3.channel;" in mpdu[:early_call_pos]
assert "chanidx = desc->v1.channel;" in mpdu[:early_call_pos]
assert "mbuf_freem(m);\n            return;" in mpdu[early_call_pos:duplicate_pos]
assert "CaptureResult::Captured" in helper
assert "CaptureResult::Duplicate" in helper
assert "descriptor.protectedFrame" in helper
assert "decoded.amsdu" in helper
assert "originalData->hardwareDeaggregated" in helper

branch_start = mpdu.rfind("if (rxStageAwdlDataCandidate)", 0, duplicate_pos)
assert branch_start >= 0
early_branch = extract_braced(
    mpdu[branch_start:], "if (rxStageAwdlDataCandidate)")
# The production function owns an OriginalDescriptor local and passes its
# address. This fixture accepts the descriptor pointer as a test input.
early_branch = early_branch.replace("&originalData);", "originalData);")
assert "EarlyRoute::QueuedForNative" in early_branch
assert "EarlyRoute::DuplicateRetry" in helper
assert "earlyRoute != NativeP2PRx149DataInput::EarlyRoute::PassToSta" in early_branch
assert "mbuf_freem(m);" in early_branch and "return;" in early_branch

prelude = r'''
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>
#include "native/awdl_data_frame.hpp"
#include "native/p2p_rx149_data_input.hpp"

#define ITL_NATIVE_AWDL_RESIDENT_25G332 1
#define ITL_NATIVE_AWDL_RX149_OBSERVATION_25G332 1
#define ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332 1
#define IWX_UCODE_TLV_API_BAND_IN_RX_DATA (1ull << 5)
#define IEEE80211_FC1_PROTECTED 0x40
#define IEEE80211_FC1_RETRY 0x08
#define IEEE80211_FC0_TYPE_MASK 0x0c
#define IEEE80211_FC0_TYPE_CTL 0x04
#define IEEE80211_FC0_SUBTYPE_MASK 0xf0
#define IEEE80211_FC0_SUBTYPE_NODATA 0x40
#define IEEE80211_SEQ_SEQ_SHIFT 4
#define IEEE80211_RXI_SAME_SEQ 0x01
#define IEEE80211_QOS_TID 0x0f
#define IWX_MAX_TID_COUNT 16
#define IWX_RX_MPDU_AMSDU_SUBFRAME_IDX_MASK 0x0f
#define IWX_RX_MPDU_MFLG2_AMSDU 0x01
#define nitems(x) (sizeof(x) / sizeof((x)[0]))
#define isset(bits, flag) (((bits) & (flag)) != 0)
#define mtod(m, T) reinterpret_cast<T>((m)->bytes)

struct ieee80211_frame {
    uint8_t i_fc[2]; uint8_t i_dur[2]; uint8_t i_addr1[6];
    uint8_t i_addr2[6]; uint8_t i_addr3[6]; uint8_t i_seq[2];
};
using u_int16_t = uint16_t;
struct ieee80211_qosframe { ieee80211_frame base; uint8_t qos[2]; };
struct ieee80211_qosframe_addr4 {
    ieee80211_frame base; uint8_t ext[6]; uint8_t qos[2];
};
static bool ieee80211_has_qos(const ieee80211_frame *wh) {
    return (wh->i_fc[0] & 0x80) != 0;
}
static uint16_t ieee80211_get_qos(const ieee80211_frame *wh) {
    const auto *p = reinterpret_cast<const uint8_t *>(wh);
    return uint16_t(p[24]) | (uint16_t(p[25]) << 8);
}
static bool IEEE80211_IS_MULTICAST(const uint8_t *address) {
    return (address[0] & 1u) != 0;
}
static uint16_t letoh16(uint16_t value) { return value; }

struct iwx_rxq_dup_data {
    uint16_t last_seq[IWX_MAX_TID_COUNT + 1]{};
    uint8_t last_sub_frame[IWX_MAX_TID_COUNT + 1]{};
};
struct iwx_node { iwx_rxq_dup_data dup_data; };
struct ieee80211_channel { uint16_t number = 0; };
struct ieee80211com {
    iwx_node *ic_bss = nullptr;
    ieee80211_channel ic_channels[196]{};
};
struct iwx_softc {
    ieee80211com sc_ic;
    uint32_t sc_generation = 72;
    uint64_t sc_ucode_api = IWX_UCODE_TLV_API_BAND_IN_RX_DATA;
};
struct iwx_rx_mpdu_desc {
    uint8_t amsdu_info = 0;
    uint8_t mac_flags2 = 0;
    uint8_t mac_phy_idx = 1;
};
struct ieee80211_rxinfo { uint32_t rxi_flags = 0; };
struct mbuf_list {};
struct Packet {
    uint8_t bytes[256]{};
    size_t length = 0;
    bool freed = false;
};
using mbuf_t = Packet *;
static size_t mbuf_len(mbuf_t m) { return m->length; }
static void mbuf_freem(mbuf_t m) {
    assert(m && !m->freed);
    m->freed = true;
}
static uint16_t ieee80211_chan2ieee(ieee80211com *, ieee80211_channel *ch) {
    return ch->number;
}

namespace NativeAwdlRxEntry {
enum : uint32_t { MacPhyDecodeLegacy = 1, MacPhyDecodeBandInRx = 2 };
}
namespace NativeAwdlBSD {
enum class CaptureResult : uint8_t {
    NotAwdlDataCandidate, Captured, Rejected, QueueFull, Duplicate
};
CaptureResult nextResult = CaptureResult::Captured;
unsigned captureCalls = 0;
unsigned queuePushes = 0;
std::vector<uint8_t> queued;
NativeP2PRx149DataInput::Permit queuedPermit{};
inline CaptureResult captureRx149Data(
    const uint8_t *bytes, size_t length, bool protectedFrame,
    const NativeP2PRx149DataInput::Lease &lease,
    const NativeP2PRx149DataInput::Permit &permit, uint32_t generation) {
    ++captureCalls;
    assert(!protectedFrame);
    assert(NativeP2PRx149DataInput::stillCurrent(permit, lease, lease.nowUs));
    assert(generation == permit.epochs.power);
    if (nextResult == CaptureResult::Captured) {
        queued.assign(bytes, bytes + length);
        queuedPermit = permit;
        ++queuePushes;
    } else if (nextResult == CaptureResult::Duplicate) {
        // A Duplicate disposition is legal only after a copied queue owner.
        assert(queuePushes == 1 && queuedPermit.valid);
    }
    return nextResult;
}
}

static NativeP2PRx149DataInput::Lease validLease() {
    using namespace NativeP2PRx149DataInput;
    Lease v{};
    v.compiled = v.runtimeEnabled = v.profileEnabled = true;
    v.profileSelected = v.receiveObservationOnly = v.leaseActive = true;
    v.ownerCurrent = v.epochsMatch = v.tokenMatches = true;
    v.commandReturned = v.commandSucceeded = v.deviceDiscoveryConfiguration = true;
    v.startSeen = v.startSucceeded = true;
    v.epochs = {71, 72, 73, 71};
    v.ownerSerial = 901;
    v.startUs = 1000;
    v.nowUs = 1001;
    return v;
}
struct TahoeAwdlRxStageCounters {
    enum DataStage : unsigned {
        kDataPreDuplicateQueueAccepted = 17,
        kDataPreDuplicateRetrySuppressed = 18
    };
    unsigned queueAccepted = 0;
    unsigned retrySuppressed = 0;
    bool recordData(uint32_t generation, unsigned stage) {
        if (!generation) return false;
        if (stage == kDataPreDuplicateQueueAccepted) ++queueAccepted;
        else if (stage == kDataPreDuplicateRetrySuppressed) ++retrySuppressed;
        else return false;
        return true;
    }
};
static unsigned gDuplicateDetectorCalls = 0;

struct ItlIwx {
    TahoeAwdlRxStageCounters tahoe_awdl_rx_stage_counters_;
    NativeP2PRx149DataInput::Lease lease = validLease();
    bool leaseAvailable = true;
    unsigned reorderCalls = 0;
    bool tahoeP2pRx149DataLease(NativeP2PRx149DataInput::Lease *out) {
        if (!leaseAvailable) return false;
        *out = lease;
        return true;
    }
    NativeP2PRx149DataInput::EarlyRoute
    tahoeP2pCaptureAwdlDataBeforeStaDedup(
        struct iwx_softc *, const uint8_t *, size_t, uint8_t, uint32_t,
        const NativeP2PRx149DataInput::OriginalDescriptor *);
    int iwx_detect_duplicate(struct iwx_softc *, mbuf_t,
        struct iwx_rx_mpdu_desc *, struct ieee80211_rxinfo *);
    int iwx_rx_reorder(struct iwx_softc *, mbuf_t, uint8_t,
        struct iwx_rx_mpdu_desc *, uint16_t, uint32_t, uint32_t,
        struct ieee80211_rxinfo *, struct mbuf_list *) {
        ++reorderCalls;
        return 0;
    }
    void runEarlySplit(struct iwx_softc *, mbuf_t, struct iwx_rx_mpdu_desc *,
        const NativeP2PRx149DataInput::OriginalDescriptor *, uint8_t,
        uint32_t, uint32_t);
};
'''

duplicate = duplicate.replace(
    "{\n    struct ieee80211com *ic = &sc->sc_ic;",
    "{\n    ++gDuplicateDetectorCalls;\n    struct ieee80211com *ic = &sc->sc_ic;",
    1,
)
assert "++gDuplicateDetectorCalls;" in duplicate

run_method = r'''
void ItlIwx::runEarlySplit(struct iwx_softc *sc, mbuf_t m,
    struct iwx_rx_mpdu_desc *desc,
    const NativeP2PRx149DataInput::OriginalDescriptor *originalData,
    uint8_t chanidx, uint32_t macPhyIndex, uint32_t generation) {
    bool rxStageAwdlDataCandidate = false;
    const uint32_t rxStageOwnerGeneration = generation;
    if (rxStageOwnerGeneration)
        rxStageAwdlDataCandidate = NativeAwdlData::isAwdlDataCandidate(
            mtod(m, const uint8_t *), mbuf_len(m));
'''+early_branch+r'''
    if (iwx_detect_duplicate(sc, m, desc, nullptr)) {
        mbuf_freem(m);
        return;
    }
    (void)iwx_rx_reorder(sc, m, chanidx, desc, 0, 0, 0, nullptr, nullptr);
}
'''

support = r'''
static std::vector<uint8_t> makeFrame(const uint8_t source[6],
    const uint8_t destination[6], uint16_t sequence, bool retry,
    bool qos = false, uint8_t tid = 0) {
    uint8_t ipv6[40]{};
    ipv6[0] = 0x60;
    ipv6[7] = 64;
    NativeAwdlData::EncodeInput input{};
    memcpy(input.destinationAddress, destination, 6);
    memcpy(input.sourceAddress, source, 6);
    input.wifiSequenceNumber = sequence;
    input.awdlSequenceNumber = uint16_t(sequence + 7);
    input.ipv6Packet = ipv6;
    input.ipv6Length = sizeof(ipv6);
    std::vector<uint8_t> frame(128);
    size_t written = 0;
    assert(NativeAwdlData::encodeIpv6DataMpdu(
        &input, frame.data(), frame.size(), &written) ==
        NativeAwdlData::Status::Ok);
    frame.resize(written);
    if (qos) {
        frame.insert(frame.begin() + 24, {uint8_t(tid & 0x0f), 0});
        frame[0] = 0x88;
    }
    if (retry) frame[1] |= IEEE80211_FC1_RETRY;
    return frame;
}

static std::vector<uint8_t> makeAmsduFrame(const uint8_t source[6],
    const uint8_t destination[6], uint16_t sequence, uint8_t tid) {
    const auto plain = makeFrame(source, destination, sequence, false);
    const size_t bodyLength = plain.size() - 24;
    std::vector<uint8_t> frame(26 + 14 + bodyLength, 0);
    frame[0] = 0x88;
    memcpy(frame.data() + 4, plain.data() + 4, 18);
    memcpy(frame.data() + 22, plain.data() + 22, 2);
    frame[24] = uint8_t((tid & 0x0f) | 0x80);
    memcpy(frame.data() + 26, destination, 6);
    memcpy(frame.data() + 32, source, 6);
    frame[38] = uint8_t(bodyLength >> 8);
    frame[39] = uint8_t(bodyLength);
    memcpy(frame.data() + 40, plain.data() + 24, bodyLength);
    return frame;
}

static Packet packetFrom(const std::vector<uint8_t> &bytes) {
    assert(bytes.size() <= sizeof(Packet::bytes));
    Packet packet{};
    packet.length = bytes.size();
    memcpy(packet.bytes, bytes.data(), bytes.size());
    return packet;
}

struct Fixture {
    ItlIwx driver;
    iwx_softc sc;
    iwx_node node;
    iwx_rx_mpdu_desc desc{};
    NativeP2PRx149DataInput::OriginalDescriptor original{true,false,false,0x12345678};
    Fixture() {
        sc.sc_ic.ic_bss = &node;
        sc.sc_ic.ic_channels[149].number = 149;
        desc.mac_phy_idx = 1;
    }
    void run(Packet *packet, uint8_t channel = 149, uint32_t macPhy = 1,
             uint32_t owner = 71,
             const NativeP2PRx149DataInput::OriginalDescriptor *originalData = nullptr,
             bool useNullOriginalDescriptor = false) {
        if (channel < nitems(sc.sc_ic.ic_channels))
            sc.sc_ic.ic_channels[channel].number = channel;
        desc.mac_phy_idx = static_cast<uint8_t>(macPhy);
        driver.runEarlySplit(&sc, packet, &desc,
            useNullOriginalDescriptor ? nullptr :
                (originalData ? originalData : &original),
            channel, macPhy, owner);
    }
};
'''

postlude = r'''
int main() {
    using NativeAwdlBSD::CaptureResult;
    const uint8_t peer[6] = {0x02,0x11,0x22,0x33,0x44,0x55};
    const uint8_t local[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};

    // Prove the actual STA duplicate detector rejects this Retry before the
    // early branch gets a chance to route it. The integration must intercept
    // the frame before that function and must not reorder it afterward.
    {
        Fixture f;
        auto bytes = makeFrame(peer, local, 42, true);
        Packet packet = packetFrom(bytes);
        f.node.dup_data.last_seq[IWX_MAX_TID_COUNT] = 42;
        assert(f.driver.iwx_detect_duplicate(&f.sc, &packet, &f.desc, nullptr) == 1);
        assert(gDuplicateDetectorCalls == 1);
        gDuplicateDetectorCalls = 0;
    }

    // A successful queue copy is the only new-frame disposition that owns
    // and consumes the original mbuf. The actual helper must preserve bytes,
    // descriptor status and permit; shared STA duplicate/reorder is skipped.
    {
        Fixture f;
        auto bytes = makeFrame(peer, local, 42, true);
        Packet packet = packetFrom(bytes);
        f.node.dup_data.last_seq[IWX_MAX_TID_COUNT] = 42;
        f.node.dup_data.last_sub_frame[IWX_MAX_TID_COUNT] = 0x7f;
        NativeAwdlBSD::nextResult = CaptureResult::Captured;
        NativeAwdlBSD::captureCalls = NativeAwdlBSD::queuePushes = 0;
        NativeAwdlBSD::queued.clear();
        NativeAwdlBSD::queuedPermit = {};
        f.run(&packet, 149, 1, 71);
        assert(packet.freed && f.driver.reorderCalls == 0);
        assert(gDuplicateDetectorCalls == 0);
        assert(NativeAwdlBSD::captureCalls == 1 && NativeAwdlBSD::queuePushes == 1);
        assert(NativeAwdlBSD::queued == bytes);
        assert(NativeAwdlBSD::queuedPermit.valid);
        assert(NativeAwdlBSD::queuedPermit.originalRawStatus == f.original.rawStatus);
        assert(f.node.dup_data.last_sub_frame[IWX_MAX_TID_COUNT] == 0x7f);
        assert(f.driver.tahoe_awdl_rx_stage_counters_.queueAccepted == 1);
        assert(f.driver.tahoe_awdl_rx_stage_counters_.retrySuppressed == 0);
    }

    // The bridge's distinct Duplicate result suppresses only an already
    // copied Retry. It consumes the retransmitted original but never reports
    // another queue acceptance or increments the captured-stage counter.
    {
        Fixture f;
        auto bytes = makeFrame(peer, local, 43, true);
        Packet first = packetFrom(bytes);
        NativeAwdlBSD::nextResult = CaptureResult::Captured;
        NativeAwdlBSD::captureCalls = NativeAwdlBSD::queuePushes = 0;
        NativeAwdlBSD::queued.clear();
        f.run(&first);
        assert(first.freed && NativeAwdlBSD::queuePushes == 1);
        const auto originalCopy = NativeAwdlBSD::queued;
        Packet retry = packetFrom(bytes);
        NativeAwdlBSD::nextResult = CaptureResult::Duplicate;
        f.node.dup_data.last_seq[IWX_MAX_TID_COUNT] = 43;
        f.run(&retry);
        assert(retry.freed && f.driver.reorderCalls == 0);
        assert(gDuplicateDetectorCalls == 0);
        assert(NativeAwdlBSD::captureCalls == 2 && NativeAwdlBSD::queuePushes == 1);
        assert(NativeAwdlBSD::queued == originalCopy);
        assert(f.driver.tahoe_awdl_rx_stage_counters_.queueAccepted == 1);
        assert(f.driver.tahoe_awdl_rx_stage_counters_.retrySuppressed == 1);
    }

    // Non-capture outcomes fall back to the real STA duplicate detector.
    // A retry already seen by STA is dropped there, not credited as a native
    // duplicate/capture. A new QueueFull frame continues through reorder.
    for (auto outcome : {CaptureResult::Rejected, CaptureResult::QueueFull,
                         CaptureResult::NotAwdlDataCandidate}) {
        Fixture f;
        auto retryBytes = makeFrame(peer, local, 44, true);
        Packet retry = packetFrom(retryBytes);
        f.node.dup_data.last_seq[IWX_MAX_TID_COUNT] = 44;
        NativeAwdlBSD::nextResult = outcome;
        NativeAwdlBSD::captureCalls = NativeAwdlBSD::queuePushes = 0;
        NativeAwdlBSD::queued.clear();
        gDuplicateDetectorCalls = 0;
        f.run(&retry);
        assert(retry.freed && f.driver.reorderCalls == 0);
        assert(gDuplicateDetectorCalls == 1 && NativeAwdlBSD::captureCalls == 1);
        assert(NativeAwdlBSD::queuePushes == 0);
        assert(f.driver.tahoe_awdl_rx_stage_counters_.queueAccepted == 0);
        assert(f.driver.tahoe_awdl_rx_stage_counters_.retrySuppressed == 0);
    }
    {
        Fixture f;
        auto bytes = makeFrame(peer, local, 45, false);
        Packet packet = packetFrom(bytes);
        NativeAwdlBSD::nextResult = CaptureResult::QueueFull;
        NativeAwdlBSD::captureCalls = NativeAwdlBSD::queuePushes = 0;
        NativeAwdlBSD::queued.clear();
        gDuplicateDetectorCalls = 0;
        f.run(&packet);
        assert(!packet.freed && f.driver.reorderCalls == 1);
        assert(gDuplicateDetectorCalls == 1 && NativeAwdlBSD::captureCalls == 1);
        assert(NativeAwdlBSD::queuePushes == 0);
    }

    // The true early helper rejects invalid authority and unsafe frame classes
    // without invoking bridge capture; the exact STA path still owns them.
    struct RejectCase {
        bool stale, unknown, protectedFrame, amsdu, deaggregated, missingDescriptor;
        uint8_t channel;
        uint32_t macPhy;
        bool ordinaryBssid;
    };
    const RejectCase cases[] = {
        {true,false,false,false,false,false,149,1,false},
        {false,true,false,false,false,false,149,1,false},
        {false,false,true,false,false,false,149,1,false},
        {false,false,false,true,false,false,149,1,false},
        {false,false,false,false,true,false,149,1,false},
        {false,false,false,false,false,true,149,1,false},
        {false,false,false,false,false,false,148,1,false},
        {false,false,false,false,false,false,149,2,false},
        {false,false,false,false,false,false,149,1,true},
    };
    for (const auto &item : cases) {
        Fixture f;
        auto bytes = item.amsdu ? makeAmsduFrame(peer, local, 46, 3) :
                     makeFrame(peer, local, 46, false);
        if (item.protectedFrame) bytes[1] |= IEEE80211_FC1_PROTECTED;
        if (item.ordinaryBssid) bytes[16] ^= 0x02;
        Packet packet = packetFrom(bytes);
        if (item.stale) f.driver.lease.ownerCurrent = false;
        if (item.unknown) f.driver.lease.outcomeUnknown = true;
        auto original = f.original;
        original.protectedFrame = item.protectedFrame;
        original.hardwareDeaggregated = item.deaggregated;
        const auto *descriptor = item.missingDescriptor ? nullptr : &original;
        NativeAwdlBSD::nextResult = CaptureResult::Captured;
        NativeAwdlBSD::captureCalls = NativeAwdlBSD::queuePushes = 0;
        NativeAwdlBSD::queued.clear();
        gDuplicateDetectorCalls = 0;
        f.run(&packet, item.channel, item.macPhy, 71, descriptor,
            item.missingDescriptor);
        assert(!packet.freed && f.driver.reorderCalls == 1);
        assert(gDuplicateDetectorCalls == 1 && NativeAwdlBSD::captureCalls == 0);
        assert(NativeAwdlBSD::queuePushes == 0);
        assert(f.driver.tahoe_awdl_rx_stage_counters_.queueAccepted == 0);
        assert(f.driver.tahoe_awdl_rx_stage_counters_.retrySuppressed == 0);
    }

    // No current P2P owner means the production candidate flag remains false;
    // an ordinary STA frame with a different BSSID also never reaches bridge.
    for (bool noOwner : {false, true}) {
        Fixture f;
        auto bytes = makeFrame(peer, local, 47, false);
        if (!noOwner) bytes[16] ^= 0x02;
        Packet packet = packetFrom(bytes);
        NativeAwdlBSD::nextResult = CaptureResult::Captured;
        NativeAwdlBSD::captureCalls = NativeAwdlBSD::queuePushes = 0;
        gDuplicateDetectorCalls = 0;
        f.run(&packet, 149, 1, noOwner ? 0 : 71);
        assert(!packet.freed && f.driver.reorderCalls == 1);
        assert(gDuplicateDetectorCalls == 1 && NativeAwdlBSD::captureCalls == 0);
    }
}
'''

fixture = prelude + helper + duplicate + support + run_method + postlude
with tempfile.TemporaryDirectory(prefix="iwx-awdl-predup-") as tmp:
    cpp = Path(tmp) / "fixture.cpp"
    binary = Path(tmp) / "fixture"
    cpp.write_text(fixture)
    subprocess.run([
        "xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-parameter", "-Wno-sign-compare",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(ROOT), str(cpp),
        str(ROOT / "native/awdl_data_frame.cpp"), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True)

print("PASS: production RX149 helper, early ownership branch and STA duplicate detector; "
      "Captured/Duplicate ownership and all fallback/safety cases")
