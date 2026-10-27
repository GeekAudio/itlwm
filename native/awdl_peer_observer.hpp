// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_PEER_OBSERVER_HPP
#define NATIVE_AWDL_PEER_OBSERVER_HPP

#include "intel_p2p_rx_router.hpp"

#include <stddef.h>
#include <stdint.h>

namespace IntelAwdlPeer {

constexpr size_t kPeerCapacity = 16;
constexpr uint64_t kPeerTtlUs = 60ULL * 1000ULL * 1000ULL;

struct RuntimeEpochs {
    uint64_t contextGeneration;
    uint64_t powerGeneration;
    uint64_t stationGeneration;
    bool active;
};

enum class ObserveResult : uint8_t {
    kAdmittedPeer,
    kUpdatedPeer,
    kCandidateOnly,
    kInactive,
    kStaleGeneration,
    kInvalidTimestamp,
    kExpiredFrame,
    kOutOfOrderFrame,
    kInvalidFrame,
    kInvalidSourceAddress
};

// The snapshot deliberately contains no addresses, names, or raw frame data.
// rxChannelIndex is the driver's RX channel index, not an IEEE channel number.
struct Snapshot {
    uint32_t validPeerCount;
    bool hasLatestPeer;
    bool syncFieldsValid;
    uint16_t rxChannelIndex;
    uint8_t nextAwChannel;
    uint8_t masterChannel;
    uint16_t nextSlotTu;
    uint16_t awPeriodTu;
    uint16_t actionFramePeriodTu;
    uint8_t presenceMode;
    uint16_t nextAwSequence;
    uint64_t latestPeerAgeUs;
    // Lifetime totals count only structurally valid, source-validated observer
    // inputs. They survive peer expiry and runtime epoch changes; reset() clears
    // them only when explicitly requested.
    uint32_t candidateFramesTotal;
    uint32_t psfFramesTotal;
    uint32_t mifFramesTotal;
    uint32_t admittedFramesTotal;
    uint32_t updatedFramesTotal;
    uint64_t lastAdmittedContextGeneration;
    // Peak valid peers in the current (or most recently ended) active epoch.
    // It survives deactivation, and starts at zero on the next active epoch.
    uint32_t activeWindowPeakValidPeerCount;
    uint64_t activeWindowPeakContextGeneration;
};

// A single-consumer, bounded observer for already parsed AWDL Action frames.
// Call observe() and snapshot() on the same serialized worker/workloop.
class Observer {
public:
    Observer();

    // nowMonotonicUs and ActionFrameRecord::rxMonotonicUs are monotonic
    // microseconds. The latter must be captured at RX tap time, not at drain.
    ObserveResult observe(const IntelP2PRx::ActionFrameRecord &record,
                          const RuntimeEpochs &current,
                          uint64_t nowMonotonicUs);

    // Generation changes and expiry are applied before the snapshot is made.
    Snapshot snapshot(const RuntimeEpochs &current,
                      uint64_t nowMonotonicUs);

    void reset();

private:
    struct SyncEvidence {
        uint8_t nextAwChannel;
        uint8_t masterChannel;
        uint16_t nextSlotTu;
        uint16_t awPeriodTu;
        uint16_t actionFramePeriodTu;
        uint8_t presenceMode;
        uint16_t nextAwSequence;
        bool valid;
    };

    struct PeerSlot {
        uint8_t sourceAddress[6]; // Private matching key; never returned.
        uint64_t lastSeenUs;
        uint16_t rxChannelIndex;
        uint8_t version;
        uint8_t deviceClass;
        SyncEvidence sync;
        bool used;
        bool sawMif;
    };

    void clearSlots();
    void synchronizeEpochs(const RuntimeEpochs &current);
    void expire(uint64_t nowMonotonicUs);
    static bool extractEvidence(
        const IntelP2PRx::ActionFrameRecord &record, uint8_t *sourceAddress,
        SyncEvidence *sync, uint8_t *version, uint8_t *deviceClass);
    static bool isValidPeer(const PeerSlot &peer);

    PeerSlot peers_[kPeerCapacity];
    RuntimeEpochs current_;
    bool haveCurrent_;
    uint32_t candidateFramesTotal_;
    uint32_t psfFramesTotal_;
    uint32_t mifFramesTotal_;
    uint32_t admittedFramesTotal_;
    uint32_t updatedFramesTotal_;
    uint64_t lastAdmittedContextGeneration_;
    uint32_t activeWindowPeakValidPeerCount_;
    uint64_t activeWindowPeakContextGeneration_;
};

} // namespace IntelAwdlPeer

#endif // NATIVE_AWDL_PEER_OBSERVER_HPP
