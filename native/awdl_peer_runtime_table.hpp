// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_PEER_RUNTIME_TABLE_HPP
#define NATIVE_AWDL_PEER_RUNTIME_TABLE_HPP

#include "awdl_peer_election.hpp"
#include "awdl_peer_observer.hpp"

#include <stddef.h>
#include <stdint.h>

namespace IntelAwdlPeerRuntime {

constexpr size_t kPeerCapacity = IntelAwdlElection::kMaximumPeers;
constexpr uint64_t kCandidateTtlUs = IntelAwdlPeer::kPeerTtlUs;
constexpr uint64_t kMifLeaseTtlUs = 5ULL * 1000ULL * 1000ULL;
constexpr uint64_t kPsfLeaseTtlUs = 5ULL * 1000ULL * 1000ULL;
constexpr size_t kTimingSampleCapacity = 3;

enum class Result : uint8_t {
    kAdmitted,
    kUpdated,
    kCandidate,
    kInactive,
    kStaleGeneration,
    kInvalidTimestamp,
    kExpiredFrame,
    kOutOfOrderFrame,
    kInvalidFrame,
    kInvalidMif,
    kInvalidSourceAddress,
    kClockRegression,
    kInvalidPsf,
    kNone = 0xff
};

// One raw tuple from a valid PSF or MIF. RX host time is captured at the RX
// tap after reorder; GP2 and peer PHY remain separate device-clock domains.
struct TimingSample {
    uint64_t rxMonotonicUs;
    uint32_t rxGp2TimestampUs;
    uint32_t peerPhyTxTimestampUs;
    uint8_t subtype; // 0=PSF, 3=MIF; do not compare across sources blindly.
    bool rxGp2TimestampPresent;
};

// Address-free, fixed-size entry. MIF fields remain available as numeric
// history while `mifFresh` is false, but must never be used for election then.
struct PeerSnapshot {
    uint64_t frameAgeUs;
    uint64_t mifAgeUs;
    uint64_t contextGeneration;
    uint64_t powerGeneration;
    uint64_t stationGeneration;
    uint64_t mifRxMonotonicUs;
    uint32_t mifRxGp2TimestampUs;
    uint32_t phyTxTimestampUs;
    uint32_t targetTxTimestampUs;
    uint32_t masterMetric;
    uint32_t masterCounter;
    uint32_t ownMetric;
    uint32_t ownCounter;
    uint32_t height;
    TimingSample timingSamples[kTimingSampleCapacity]; // Oldest first.
    uint16_t rxChannel;
    uint16_t txDownCounterTu;
    uint16_t awPeriodTu;
    uint16_t actionFramePeriodTu;
    uint16_t nextAwSequence;
    uint16_t syncParameterLength;
    uint16_t syncTailLength;
    uint8_t nextAwChannel;
    bool embeddedSequencePresent;
    bool embeddedSequenceRecognized;
    bool embeddedSequenceVerified;
    bool embeddedSequenceMismatch;
    uint8_t embeddedMismatchIndex;
    uint8_t embeddedMismatchChannel;
    uint8_t canonicalMismatchChannel;
    uint8_t channelSlots[16];
    uint8_t version;
    uint8_t deviceClass;
    uint8_t timingSampleCount;
    bool tracked;
    bool hasMif;
    bool mifFresh;
    bool syncConsistent;
    bool mifRxGp2TimestampPresent;
    bool electionV2;
};

// Full, address-free view of one peer's PSF advertisement. Kept separate
// from PeerSnapshot's MIF history and returned one slot at a time so the
// worker's fixed 4 KiB Snapshot stack budget remains unchanged.
struct PsfPeerSnapshot {
    uint64_t psfAgeUs;
    uint64_t contextGeneration;
    uint64_t powerGeneration;
    uint64_t stationGeneration;
    uint64_t psfRxMonotonicUs;
    uint32_t psfRxGp2TimestampUs;
    uint32_t phyTxTimestampUs;
    uint32_t targetTxTimestampUs;
    uint32_t height;
    uint32_t masterMetric;
    uint32_t masterCounter;
    uint32_t ownMetric;
    uint32_t ownCounter;
    uint16_t rxChannel;
    uint16_t txDownCounterTu;
    uint16_t awPeriodTu;
    uint16_t actionFramePeriodTu;
    uint16_t nextAwSequence;
    uint16_t syncParameterLength;
    uint16_t syncTailLength;
    uint8_t nextAwChannel;
    uint8_t channelSlots[16];
    uint8_t version;
    uint8_t deviceClass;
    bool tracked;
    bool hasPsf;
    bool psfFresh;
    bool syncConsistent;
    bool psfRxGp2TimestampPresent;
    bool embeddedSequencePresent;
    bool embeddedSequenceRecognized;
    bool embeddedSequenceVerified;
    bool embeddedSequenceMismatch;
    uint8_t embeddedMismatchIndex;
    uint8_t embeddedMismatchChannel;
    uint8_t canonicalMismatchChannel;
    bool electionV2;
};

struct Snapshot {
    uint32_t freshMifPeerCount;
    uint32_t freshPsfPeerCount;
    uint32_t trackedPeerCount;
    uint32_t admittedTotal;
    uint32_t updatedTotal;
    uint32_t candidateFrameTotal;
    uint32_t mifFrameTotal;
    uint32_t acceptedPsfTotal;
    uint32_t rejectedTotal;
    uint32_t rejectedMifTotal;
    uint32_t rejectedPsfTotal;
    uint64_t lastAdmittedContextGeneration;
    uint64_t lastRejectedContext;
    uint8_t lastRejectedResult; // Result numeric value; 0xff before any reject.
    uint8_t lastMifDecodeStatus; // DecodeStatus value; 0xff before MIF decode.
    uint8_t lastPsfDecodeStatus; // DecodeStatus value; 0xff before PSF decode.
    // Last decode attempt. rejectStage==kNone can still carry successful
    // numeric shape such as syncParameterLength and embedded verification.
    IntelAwdlElection::DecodeDiagnostics lastMifRejectDiagnostics;
    IntelAwdlElection::DecodeDiagnostics lastPsfRejectDiagnostics;
    uint8_t latestFreshMifSlot; // 0xff when no fresh MIF is retained.
    uint8_t latestFreshPsfSlot; // 0xff when no fresh PSF is retained.
    PeerSnapshot peers[kPeerCapacity]; // Array index is the private table slot.
};

// No address is returned from election. selectedSlot maps to `peers[]` in a
// Snapshot from the same epoch; 0xff means the local node remains master.
struct SelectionSummary {
    uint8_t selectedSlot;
    uint32_t height;
    uint32_t masterMetric;
    uint32_t masterCounter;
    bool followsPeer;
};

// Fixed-capacity single-consumer table for captured ActionFrameRecords. The
// same serialized worker must call observe(), snapshot(), and selectMaster().
// It retains no raw frame bytes, names, firmware resources, or TX permission.
class Table {
public:
    Table();

    Result observe(const IntelP2PRx::ActionFrameRecord &record,
                   const IntelAwdlPeer::RuntimeEpochs &current,
                   uint64_t nowMonotonicUs);

    Snapshot snapshot(const IntelAwdlPeer::RuntimeEpochs &current,
                      uint64_t nowMonotonicUs);

    // Return one address-free PSF advertisement, including its independent
    // 5 second freshness and same-frame RX/GP2 observation. MIF does not
    // refresh or replace this state.
    bool getPsfSnapshot(uint8_t slot,
                        const IntelAwdlPeer::RuntimeEpochs &current,
                        uint64_t nowMonotonicUs,
                        PsfPeerSnapshot *output);

    // Pure election over MIFs fresh within kMifLeaseTtlUs and internally
    // consistent. This result is diagnostic only and must not schedule TX or
    // change channel without independently verified clock-map evidence.
    bool selectMaster(const IntelAwdlPeer::RuntimeEpochs &current,
                      uint64_t nowMonotonicUs,
                      const IntelAwdlElection::LocalState &local,
                      IntelAwdlElection::Ranking ranking,
                      SelectionSummary *output);

    void reset();

private:
    struct Entry {
        uint8_t sourceAddress[6]; // Private matching key; never returned.
        IntelAwdlElection::Advertisement mifAdvertisement;
        IntelAwdlElection::Advertisement psfAdvertisement;
        TimingSample timing[kTimingSampleCapacity];
        uint64_t lastFrameUs;
        uint64_t lastMifUs;
        uint64_t lastPsfUs;
        uint64_t contextGeneration;
        uint64_t powerGeneration;
        uint64_t stationGeneration;
        uint32_t mifRxGp2TimestampUs;
        uint32_t psfRxGp2TimestampUs;
        uint16_t rxChannel;
        uint16_t psfRxChannel;
        uint8_t timingCount;
        uint8_t timingNext;
        bool mifRxGp2TimestampPresent;
        bool psfRxGp2TimestampPresent;
        bool hasMif;
        bool hasPsf;
        bool used;
    };

    void clearEntries();
    void synchronizeEpochs(const IntelAwdlPeer::RuntimeEpochs &current);
    void expire(uint64_t nowMonotonicUs);
    void noteRejected(Result result, uint64_t contextGeneration,
                      bool rejectedMif, bool rejectedPsf);
    static bool validAddress(const IntelAwdlElection::Address &address);
    static bool recordMatchesEpochs(
        const IntelP2PRx::ActionFrameRecord &record,
        const IntelAwdlPeer::RuntimeEpochs &current);

    Entry entries_[kPeerCapacity];
    IntelAwdlPeer::RuntimeEpochs current_;
    uint64_t lastNowUs_;
    uint64_t lastAdmittedContextGeneration_;
    uint32_t admittedTotal_;
    uint32_t updatedTotal_;
    uint32_t candidateFrameTotal_;
    uint32_t mifFrameTotal_;
    uint32_t acceptedPsfTotal_;
    uint32_t rejectedTotal_;
    uint32_t rejectedMifTotal_;
    uint32_t rejectedPsfTotal_;
    uint64_t lastRejectedContext_;
    uint8_t lastRejectedResult_;
    uint8_t lastMifDecodeStatus_;
    IntelAwdlElection::DecodeDiagnostics lastMifRejectDiagnostics_;
    uint8_t lastPsfDecodeStatus_;
    IntelAwdlElection::DecodeDiagnostics lastPsfRejectDiagnostics_;
    bool haveCurrent_;
};

static_assert(sizeof(PeerSnapshot) * kPeerCapacity < 4 * 1024,
              "peer snapshot must remain below the 4 KiB worker stack budget");
static_assert(sizeof(Snapshot) < 4 * 1024,
              "peer snapshot must remain below the 4 KiB worker stack budget");
static_assert(sizeof(PsfPeerSnapshot) < 512,
              "single-peer PSF snapshot must remain bounded");
static_assert(sizeof(Table) < 12 * 1024,
              "peer election table must remain fixed and small");

} // namespace IntelAwdlPeerRuntime

#endif // NATIVE_AWDL_PEER_RUNTIME_TABLE_HPP
