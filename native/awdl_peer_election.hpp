// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_PEER_ELECTION_HPP
#define NATIVE_AWDL_PEER_ELECTION_HPP

#include "awdl_action_frame.hpp"

#include <stddef.h>
#include <stdint.h>

namespace IntelAwdlElection {

constexpr size_t kAddressLength = 6;
constexpr size_t kMaximumPeers = 16;
constexpr uint32_t kMaximumFollowedHeight = 10;

struct Address {
    uint8_t bytes[kAddressLength];
};

// A decoded PSF or MIF advertisement. The frame's public identity is Addr2.
// No raw frame bytes are retained by this value type.
struct Advertisement {
    Address peer;
    Address master;
    Address sync;
    uint8_t nextAwChannel;
    uint8_t channelSlots[16];
    uint16_t txDownCounterTu;
    uint16_t awPeriodTu;
    uint16_t actionFramePeriodTu;
    uint16_t nextAwSequence;
    uint16_t syncParameterLength;
    uint16_t syncTailLength; // Bytes after the fixed 33-byte sync prefix.
    uint32_t phyTxTimestampUs;
    uint32_t targetTxTimestampUs;
    uint32_t height;
    uint32_t masterMetric;
    uint32_t masterCounter;
    uint32_t ownMetric;
    uint32_t ownCounter;
    uint8_t version;
    uint8_t deviceClass;
    bool electionV2;
    // Required parsed fields are in range and master identities agree. This
    // is protocol-field consistency only; it does not establish sync to the
    // peer's radio clock or prove that its advertised schedule was served.
    bool syncConsistent;
    bool embeddedSequencePresent;
    bool embeddedSequenceRecognized;
    // True only when an embedded type-4 channel sequence was completely
    // decoded and matched the required independent type-18 sequence. This
    // validates a copied field, not clock alignment or schedule execution.
    bool embeddedSequenceVerified;
    // A recognized embedded copy can disagree with type 18 without making
    // the advertisement unusable. The required type-18 sequence is canonical.
    bool embeddedSequenceMismatch;
    uint8_t embeddedMismatchIndex;
    uint8_t embeddedMismatchChannel;
    uint8_t canonicalMismatchChannel;
};

enum class DecodeRejectStage : uint8_t {
    kNone = 0,
    kDuplicateSyncTlv,
    kShortSyncPrefix,
    kSyncCounterOutOfRange,
    kSyncAwPeriodInvalid,
    kSyncPresenceModeInvalid,
    kSyncMasterAddressInvalid,
    kEmbeddedSequenceMalformed,
    // Retained for numeric compatibility; copy disagreement is now a
    // nonfatal diagnostic and is never emitted as a reject stage.
    kEmbeddedSequenceMismatch,
    kDuplicateChannelSequenceTlv,
    kChannelSequenceMalformed,
};

// Keep the original MIF spelling source-compatible while sharing the same
// numeric diagnostics for PSF and MIF decoding.
using MifDecodeRejectStage = DecodeRejectStage;
using PsfDecodeRejectStage = DecodeRejectStage;

// Numeric-only failure detail. Offsets point to the TLV header in the MPDU;
// no address, payload byte, or frame is retained.
struct DecodeDiagnostics {
    DecodeRejectStage rejectStage;
    uint8_t offendingTlvType;
    uint8_t relatedTlvType;
    uint8_t nextAwChannel;
    uint8_t masterChannel;
    uint8_t presenceMode;
    uint8_t embeddedSequencePresent;
    uint8_t embeddedSequenceRecognized;
    uint8_t embeddedSequenceVerified;
    uint8_t embeddedSequenceMismatch;
    uint8_t embeddedMismatchIndex;
    uint8_t embeddedMismatchChannel;
    uint8_t canonicalMismatchChannel;
    uint16_t txDownCounterTu;
    uint16_t awPeriodTu;
    uint16_t actionFramePeriodTu;
    uint16_t nextAwSequence;
    uint16_t apAlignment;
    uint16_t syncParameterLength;
    uint16_t syncTailLength; // Bytes after the fixed 33-byte sync prefix.
    uint32_t tlvOffset;
    uint32_t declaredLength;
    uint32_t availableLength;
    uint32_t relatedTlvOffset;
    uint32_t relatedDeclaredLength;
};

enum class DecodeStatus : uint8_t {
    Ok,
    InvalidArgument,
    InvalidFrame,
    NotMif,
    InvalidPeerAddress,
    InvalidVersion,
    InvalidSync,
    InvalidElection,
    MasterMismatch,
    NotPsf
};

enum class Ranking : uint8_t { CounterFirst, MetricFirst };

struct LocalState {
    Address own;
    uint32_t ownMetric;
    uint32_t ownCounter;
};

struct Selection {
    Address master;
    Address sync;
    uint32_t height;
    uint32_t masterMetric;
    uint32_t masterCounter;
    bool followsPeer;
};

// Decode only election and synchronization fields from a structurally valid
// MIF. Type 24 wins over type 5 when present, as specified by AWDL.
DecodeStatus decodeMif(const uint8_t *frame, size_t length,
                       Advertisement *output,
                       DecodeDiagnostics *diagnostics = nullptr);

// Decode the synchronization, election, and channel-sequence advertisement
// carried by one structurally valid PSF. PSFs do not carry MIF-only ARPA
// identity data; callers must keep PSF and MIF observations separately.
DecodeStatus decodePsf(const uint8_t *frame, size_t length,
                       Advertisement *output,
                       DecodeDiagnostics *diagnostics = nullptr);

// Select among already-valid MIF peers. Caller must provide a current peer
// snapshot and the device's current own metric/counter. No state is retained.
// The defaults in the reference implementation are metric 60/counter 0, but
// callers must pass their actual current values.
bool selectMaster(const LocalState *local, const Advertisement *peers,
                  size_t peerCount, Ranking ranking, Selection *output);

} // namespace IntelAwdlElection

#endif
