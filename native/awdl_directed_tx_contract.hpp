// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_DIRECTED_TX_CONTRACT_HPP
#define NATIVE_AWDL_DIRECTED_TX_CONTRACT_HPP

// Typed authorization for one peer-scoped AWDL reply. This header evaluates
// trusted, copied driver evidence only; it does not issue commands, touch mbufs,
// ring MMIO, or prove over-the-air delivery. HAL/BSD adapters must sample the
// stated facts under their owning gate and revalidate them at the final doorbell.
// Authority, PreparedResources, and TxCompletionEvidence are ordinary public
// snapshots, not unforgeable evidence tokens; callers can construct fixtures.
// A production adapter must source them only from the authoritative HAL/firmware
// state while holding the real gate. Never treat this model's Decision/TxPermit
// as hardware authorization by itself.
// The caller must keep that same serialization held from the final check through
// the actual hardware submission: this model cannot make an external MMIO write
// atomic with markDoorbell(). Run/owner high-water marks and fresh nonce
// generation are supplied by the persistent caller; this object stores only one
// run and does not make an instance-local value globally unique.
#include <stdint.h>
#include <string.h>

#ifndef ITL_NATIVE_AWDL_DIRECTED_REPLY_TX_25G332
#define ITL_NATIVE_AWDL_DIRECTED_REPLY_TX_25G332 0
#endif

namespace NativeAwdlDirectedTxContract {

constexpr uint16_t kChannel149 = 149;
constexpr uint64_t kMaximumLeaseUs = 99328; // 97 TU, minus commit/RF tail
// Experimental conservative policy bits: the applied-channel PASSIVE flag is
// treated as a no-transmit gate, while this NVM bit describes active scanning
// capability only. Neither field is an authoritative firmware TX permission
// or a regulatory/legal determination.
constexpr uint32_t kChannelPassive = 0x0200;
constexpr uint32_t kNvmChannelValid = 0x0001;
constexpr uint32_t kNvmChannelActiveScan = 0x0008;
constexpr uint8_t kQueueIdLimit = 32;
constexpr bool kFeatureCompiled =
    ITL_NATIVE_AWDL_DIRECTED_REPLY_TX_25G332 != 0;

enum class Role : uint8_t { Rx149Only = 0, Directed149Reply = 1 };
enum class Stage : uint8_t {
    Disarmed = 0, Armed, Prepared, WaitStart, AwaitRequest,
    ReplyQueued, CommitReserved, DoorbellIssued, Completed,
    Quarantined, Closed
};
enum class Reason : uint8_t {
    None = 0, FeatureNotCompiled, WrongRole, NotExplicitlyArmed,
    RuntimeDisabled, ShadowOnly, AlreadyUsed, InvalidArmSerial, InvalidOwner, StaleOwner,
    InvalidEpochs, InvalidIdentity, InvalidDeadline, ClockRollback, StaleAuthority,
    ReceiveOnlyLease, EndObserved, ChannelMismatch,
    ChannelPassive, ChannelNvmInvalid, ChannelActiveScanMissing,
    FirmwareTxNotAllowed, BindingNotAcked, StationNotAcked, ResourceAckMissing,
    QueueNotAcked, QueueSlotNotProvenFree, StaQueueCollision,
    ResourceEvidenceStale, ResourceEvidenceExhausted,
    InvalidPhyBinding, InvalidAllocationSerial, InvalidQueueId,
    StaContextChanged, StaWorkPending, StartNotSucceeded,
    RequestNotConfirmed, InputFailed, ReplyNotMatched, DeadlineExpired,
    PermitInvalid, CompletionMismatch, CompletionFailed, CompletionUnknown, OwnerClosed
};

struct Epochs {
    uint32_t context;
    uint32_t power;
    uint32_t station;
    uint32_t roc;
};
struct MacAddress { uint8_t bytes[6]; };
struct Ipv6Address { uint8_t bytes[16]; };
struct Nonce { uint8_t bytes[8]; };

struct Identity {
    uint64_t runSerial;
    uint64_t ownerSerial;
    Epochs epochs;
    uint64_t interfaceIncarnation;
    uint32_t ifindex;
    uint32_t regulatoryRevision;
    uint64_t shadowGuardVersion;
    uint16_t channel;
    uint64_t startUs;
    uint64_t deadlineUs;
    MacAddress ownMac;
    MacAddress peerMac;
    Ipv6Address ownIpv6;
    Ipv6Address peerIpv6;
    Nonce nonce;
    uint16_t peerRequestPort;
    uint16_t localRequestPort;
};

struct ArmIntent {
    Role role;
    bool explicitlyRequested;
    bool runtimeEnabled;
    bool txCapabilityEnabled;
    bool shadowOnly;
    uint64_t armSerial;
};

// Trusted fresh values sampled under the driver's main gate at each transition;
// these booleans are evidence fields, not a hardware-verification mechanism.
struct Authority {
    uint64_t runSerial;
    uint64_t ownerSerial;
    Epochs epochs;
    uint64_t interfaceIncarnation;
    uint32_t ifindex;
    uint32_t regulatoryRevision;
    uint64_t shadowGuardVersion;
    uint16_t channel;
    uint64_t nowUs;
    bool ownerCurrent;
    bool leaseActive;
    bool receiveObservationOnly;
    bool commandSucceeded;
    bool startSucceeded;
    bool endSeen;
    bool outcomeUnknown;
    bool radioReady;
    bool staAssociated;
    bool staChannelUnchanged;
    bool commandQueueIdle;
    bool scanIdle;
    bool newStateIdle;
};

// HAL-adapter snapshot of exact active-channel, MAC/binding/PHY and host queue-slot evidence. A
// returned firmware qid alone never proves that its host ring is available.
struct PreparedResources {
    uint64_t runSerial;
    uint64_t ownerSerial;
    Epochs epochs;
    uint64_t interfaceIncarnation;
    uint32_t ifindex;
    MacAddress bindingOwnMac;
    MacAddress bindingPeerMac;
    MacAddress stationPeerMac;
    uint32_t appliedChannelFlags;
    uint32_t nvmProfileFlags;
    uint16_t channel;
    uint32_t regulatoryRevision;
    uint64_t snapshotSerial;
    bool bindingAck;
    bool stationAck;
    bool directedPeerStation;
    bool queueAck;
    bool firmwareAllowsDataTx;
    bool exactHostQueueSlotFree;
    bool queueOwnedBySta;
    bool staContextPreserved;
    uint8_t phyId;
    uint8_t macId;
    uint8_t macColor;
    uint8_t queueId;
    uint8_t stationId;
    uint64_t bindingAllocationSerial;
    uint64_t stationAllocationSerial;
    uint64_t queueAllocationSerial;
};

// Raw request facts for ShadowProofProvider; only the trusted shadow ledger
// integration should copy these after ifnet_input returns success and a matching
// current-association check. Ordinary BSD callers cannot mark proof valid.
struct ConfirmedRequest {
    uint64_t runSerial;
    uint64_t ownerSerial;
    Epochs epochs;
    uint64_t interfaceIncarnation;
    uint32_t guardVersion;
    uint64_t sequence;
    uint64_t deadlineUs;
    MacAddress sourceMac;
    MacAddress destinationMac;
    Ipv6Address sourceIpv6;
    Ipv6Address destinationIpv6;
    Nonce nonce;
    uint16_t sourcePort;
    uint16_t destinationPort;
    int32_t ifnetInputResult;
    bool inputConfirmed;
    bool associationCurrent;
};

class Candidate;
class ShadowProofProvider;
class ShadowRequestProof {
public:
    ShadowRequestProof() : request_{}, valid_(false), consumed_(false) {}
    ShadowRequestProof(const ShadowRequestProof &) = delete;
    ShadowRequestProof &operator=(const ShadowRequestProof &) = delete;
    bool valid() const { return valid_ && !consumed_; }
private:
    friend class Candidate;
    friend class ShadowProofProvider;
    ConfirmedRequest request_;
    bool valid_;
    bool consumed_;
};

// A reply must reverse the exact admitted request identity. Payload is exactly
// the per-run nonce; arbitrary callers cannot turn a boolean into TX consent.
struct ReplyEnvelope {
    uint64_t requestSequence;
    MacAddress sourceMac;
    MacAddress destinationMac;
    Ipv6Address sourceIpv6;
    Ipv6Address destinationIpv6;
    Nonce payload;
    uint16_t sourcePort;
    uint16_t destinationPort;
};

enum class CompletionStatus : uint8_t { Success = 0, Failure, Unknown };
// Trusted HAL response/timeout adapter record. responseMatched must be set only
// after matching the real response to the submitted slot token. Even Success is
// local queue/firmware completion evidence, never peer receipt or RF proof.
struct TxCompletionEvidence {
    uint64_t armSerial;
    uint64_t runSerial;
    uint64_t ownerSerial;
    Epochs epochs;
    uint64_t interfaceIncarnation;
    uint32_t ifindex;
    uint64_t requestSequence;
    uint64_t queueAllocationSerial;
    uint8_t queueId;
    CompletionStatus status;
    bool responseMatched;
};

struct Decision { bool accepted; Reason reason; Stage stage; };
struct Snapshot {
    Role role;
    Stage stage;
    Reason lastReason;
    uint64_t ownerSerial;
    uint64_t runHighWater;
    uint64_t ownerHighWater;
    uint64_t armSerial;
    uint64_t requestSequence;
    uint64_t deadlineUs;
    uint64_t monotonicUsHighWater;
    uint64_t resourceSnapshotHighWater;
    uint32_t doorbellCount;
    bool compiled;
    bool runtimeEnabled;
    bool shadowOnly;
    bool activeChannel;
    bool resourcesPrepared;
    bool requestConfirmed;
    bool replyQueued;
    bool permitIssued;
    bool doorbellIssued;
    bool quarantined;
};

class TxPermit {
public:
    TxPermit() : valid_(false), armSerial_(0), runSerial_(0), ownerSerial_(0),
        requestSequence_(0), deadlineUs_(0), bindingSerial_(0),
        stationSerial_(0), queueSerial_(0), nonce_{}, queueId_(0), stationId_(0),
        phyId_(0), macId_(0), macColor_(0) {}
    TxPermit(const TxPermit &) = delete;
    TxPermit &operator=(const TxPermit &) = delete;
    bool valid() const { return valid_; }
    uint64_t armSerial() const { return armSerial_; }
    uint64_t runSerial() const { return runSerial_; }
    uint64_t ownerSerial() const { return ownerSerial_; }
    uint64_t requestSequence() const { return requestSequence_; }
    uint64_t deadlineUs() const { return deadlineUs_; }
    uint64_t bindingAllocationSerial() const { return bindingSerial_; }
    uint64_t stationAllocationSerial() const { return stationSerial_; }
    uint64_t queueAllocationSerial() const { return queueSerial_; }
    uint8_t queueId() const { return queueId_; }
    uint8_t stationId() const { return stationId_; }
    uint8_t phyId() const { return phyId_; }
    uint8_t macId() const { return macId_; }
    uint8_t macColor() const { return macColor_; }
private:
    friend class Candidate;
    void invalidate()
    {
        valid_ = false;
        armSerial_ = runSerial_ = ownerSerial_ = requestSequence_ = deadlineUs_ = 0;
        bindingSerial_ = stationSerial_ = queueSerial_ = 0;
        memset(&nonce_, 0, sizeof(nonce_));
        queueId_ = stationId_ = phyId_ = macId_ = macColor_ = 0;
    }
    bool valid_;
    uint64_t armSerial_;
    uint64_t runSerial_;
    uint64_t ownerSerial_;
    uint64_t requestSequence_;
    uint64_t deadlineUs_;
    uint64_t bindingSerial_;
    uint64_t stationSerial_;
    uint64_t queueSerial_;
    Nonce nonce_;
    uint8_t queueId_;
    uint8_t stationId_;
    uint8_t phyId_;
    uint8_t macId_;
    uint8_t macColor_;
};

inline bool validEpochs(const Epochs &e)
{
    return e.context && e.power && e.station && e.roc;
}
inline bool sameEpochs(const Epochs &a, const Epochs &b)
{
    return a.context == b.context && a.power == b.power &&
        a.station == b.station && a.roc == b.roc;
}
inline bool sameMac(const MacAddress &a, const MacAddress &b)
{
    return memcmp(a.bytes, b.bytes, sizeof(a.bytes)) == 0;
}
inline bool sameIpv6(const Ipv6Address &a, const Ipv6Address &b)
{
    return memcmp(a.bytes, b.bytes, sizeof(a.bytes)) == 0;
}
inline bool sameNonce(const Nonce &a, const Nonce &b)
{
    uint8_t difference = 0;
    for (unsigned i = 0; i != sizeof(a.bytes); ++i)
        difference |= static_cast<uint8_t>(a.bytes[i] ^ b.bytes[i]);
    return difference == 0;
}
inline bool validUnicastMac(const MacAddress &m)
{
    uint8_t any = 0;
    for (unsigned i = 0; i != sizeof(m.bytes); ++i) any |= m.bytes[i];
    return any != 0 && (m.bytes[0] & 0x01) == 0;
}
inline bool validAwdlLinkLocalIpv6(const Ipv6Address &ip)
{
    uint8_t any = 0;
    for (unsigned i = 0; i != sizeof(ip.bytes); ++i) any |= ip.bytes[i];
    return any != 0 && ip.bytes[0] == 0xfe && (ip.bytes[1] & 0xc0) == 0x80;
}
inline bool ownAwdlEui64Matches(const Ipv6Address &ip, const MacAddress &mac)
{
    static const uint8_t zero[6] = {0, 0, 0, 0, 0, 0};
    const uint8_t iid[8] = {
        static_cast<uint8_t>(mac.bytes[0] ^ 0x02), mac.bytes[1], mac.bytes[2],
        0xff, 0xfe, mac.bytes[3], mac.bytes[4], mac.bytes[5]
    };
    return validAwdlLinkLocalIpv6(ip) &&
        memcmp(ip.bytes + 2, zero, sizeof(zero)) == 0 &&
        memcmp(ip.bytes + 8, iid, sizeof(iid)) == 0;
}
inline bool validNonce(const Nonce &n)
{
    static const uint8_t oldTest104Marker[8] =
        {'T','0','8','6','R','X','0','1'};
    uint8_t any = 0;
    for (unsigned i = 0; i != sizeof(n.bytes); ++i) any |= n.bytes[i];
    return any != 0 && memcmp(n.bytes, oldTest104Marker, sizeof(n.bytes)) != 0;
}
inline bool activeTxChannel(const PreparedResources &r)
{
    // The ACTIVE/PASSIVE checks below are a conservative experiment policy.
    // NVM ACTIVE is an active-scan bit, not an independent TX/regulatory verdict.
    return r.channel == kChannel149 &&
        !(r.appliedChannelFlags & kChannelPassive) &&
        (r.nvmProfileFlags & kNvmChannelValid) != 0 &&
        (r.nvmProfileFlags & kNvmChannelActiveScan) != 0 &&
        r.firmwareAllowsDataTx;
}

class Candidate {
public:
    Candidate() : Candidate(Role::Rx149Only, 0, 0) {}
    // Role cannot change after construction; an RX-only run is never promoted.
    explicit Candidate(Role immutableRole, uint64_t runHighWater = 0,
                       uint64_t ownerHighWater = 0) : role_(immutableRole),
        stage_(Stage::Disarmed), lastReason_(Reason::None),
        runHighWater_(runHighWater), ownerHighWater_(ownerHighWater),
        armSerial_(0), requestSequence_(0), deadlineUs_(0),
        runtimeEnabled_(false), shadowOnly_(true), activeChannel_(false),
        resourcesPrepared_(false), requestConfirmed_(false), replyQueued_(false),
        permitIssued_(false), doorbellIssued_(false), quarantined_(false),
        closed_(false), doorbellCount_(0), lastNowUs_(0),
        lastResourceSnapshotSerial_(0), identity_{}, resources_{} {}
    Candidate(const Candidate &) = delete;
    Candidate &operator=(const Candidate &) = delete;

    Role role() const { return role_; }
    Stage stage() const { return stage_; }
    Reason lastReason() const { return lastReason_; }

    Decision arm(const ArmIntent &intent, const Identity &identity,
                 const Authority &authority)
    {
        if (closed_ || stage_ != Stage::Disarmed) return reject(Reason::AlreadyUsed);
        if (!kFeatureCompiled) return reject(Reason::FeatureNotCompiled);
        if (role_ != Role::Directed149Reply || intent.role != role_)
            return reject(Reason::WrongRole);
        if (!intent.explicitlyRequested) return reject(Reason::NotExplicitlyArmed);
        if (!intent.runtimeEnabled || !intent.txCapabilityEnabled)
            return reject(Reason::RuntimeDisabled);
        if (intent.shadowOnly) return reject(Reason::ShadowOnly);
        if (!intent.armSerial) return reject(Reason::InvalidArmSerial);
        if (!identity.runSerial || identity.runSerial != intent.armSerial ||
            identity.runSerial <= runHighWater_ || !identity.ownerSerial ||
            identity.ownerSerial <= ownerHighWater_)
            return reject(Reason::StaleOwner);
        if (!validEpochs(identity.epochs)) return reject(Reason::InvalidEpochs);
        if (!identity.interfaceIncarnation || !identity.ifindex ||
            !identity.regulatoryRevision || !identity.shadowGuardVersion)
            return reject(Reason::InvalidIdentity);
        if (identity.channel != kChannel149 ||
            identity.peerRequestPort != 49152 || identity.localRequestPort != 49153 ||
            !validUnicastMac(identity.ownMac) || !validUnicastMac(identity.peerMac) ||
            sameMac(identity.ownMac, identity.peerMac) ||
            !ownAwdlEui64Matches(identity.ownIpv6, identity.ownMac) ||
            !validAwdlLinkLocalIpv6(identity.peerIpv6) ||
            sameIpv6(identity.ownIpv6, identity.peerIpv6) ||
            !validNonce(identity.nonce)) return reject(Reason::InvalidIdentity);
        if (identity.deadlineUs <= identity.startUs ||
            identity.deadlineUs - identity.startUs > kMaximumLeaseUs ||
            authority.nowUs > identity.startUs ||
            authority.nowUs >= identity.deadlineUs) return reject(Reason::InvalidDeadline);
        if (!authority.ownerCurrent || !authority.leaseActive ||
            authority.runSerial != identity.runSerial ||
            authority.ownerSerial != identity.ownerSerial ||
            !sameEpochs(authority.epochs, identity.epochs) ||
            authority.interfaceIncarnation != identity.interfaceIncarnation ||
            authority.ifindex != identity.ifindex ||
            authority.regulatoryRevision != identity.regulatoryRevision ||
            authority.shadowGuardVersion != identity.shadowGuardVersion ||
            authority.channel != identity.channel || authority.endSeen ||
            authority.outcomeUnknown || authority.receiveObservationOnly ||
            !authority.radioReady || !authority.staAssociated ||
            !authority.staChannelUnchanged || !authority.commandQueueIdle ||
            !authority.scanIdle || !authority.newStateIdle)
            return reject(authority.receiveObservationOnly ?
                          Reason::ReceiveOnlyLease : Reason::StaleAuthority);
        identity_ = identity;
        lastNowUs_ = authority.nowUs;
        runHighWater_ = identity.runSerial;
        ownerHighWater_ = identity.ownerSerial;
        armSerial_ = intent.armSerial;
        runtimeEnabled_ = true;
        shadowOnly_ = false;
        stage_ = Stage::Armed;
        lastReason_ = Reason::None;
        return accept();
    }

    Decision prepare(const PreparedResources &resources,
                     const Authority &authority)
    {
        if (!current(authority, false)) return quarantine(lastReason_);
        if (stage_ != Stage::Armed) return reject(Reason::AlreadyUsed);
        if (!consumeResourceSnapshot(resources.snapshotSerial))
            return reject(lastReason_);
        if (!resourcesMatchIdentity(resources)) return reject(Reason::InvalidIdentity);
        if (resources.channel != identity_.channel)
            return reject(Reason::ChannelMismatch);
        if (resources.regulatoryRevision != identity_.regulatoryRevision)
            return reject(Reason::StaleAuthority);
        if (resources.appliedChannelFlags & kChannelPassive)
            return reject(Reason::ChannelPassive);
        if (!(resources.nvmProfileFlags & kNvmChannelValid))
            return reject(Reason::ChannelNvmInvalid);
        if (!(resources.nvmProfileFlags & kNvmChannelActiveScan))
            return reject(Reason::ChannelActiveScanMissing);
        if (!resources.firmwareAllowsDataTx)
            return reject(Reason::FirmwareTxNotAllowed);
        if (resources.phyId != 1 || resources.macId != 1 || !resources.macColor)
            return reject(Reason::InvalidPhyBinding);
        if (!resources.bindingAllocationSerial ||
            !resources.stationAllocationSerial || !resources.queueAllocationSerial)
            return reject(Reason::InvalidAllocationSerial);
        if (resources.queueId >= kQueueIdLimit)
            return reject(Reason::InvalidQueueId);
        if (!resources.exactHostQueueSlotFree)
            return reject(Reason::QueueSlotNotProvenFree);
        if (resources.queueOwnedBySta)
            return reject(Reason::StaQueueCollision);
        if (!resources.staContextPreserved || !authority.staChannelUnchanged)
            return reject(Reason::StaContextChanged);
        if (!authority.staAssociated || !authority.radioReady)
            return reject(Reason::StaleAuthority);
        if (!authority.commandQueueIdle || !authority.scanIdle ||
            !authority.newStateIdle) return reject(Reason::StaWorkPending);
        if (!resources.bindingAck) return reject(Reason::BindingNotAcked);
        if (!resources.directedPeerStation) return reject(Reason::StationNotAcked);
        if (!resources.stationAck) return reject(Reason::StationNotAcked);
        if (!resources.queueAck) return reject(Reason::QueueNotAcked);
        resources_ = resources;
        activeChannel_ = activeTxChannel(resources);
        resourcesPrepared_ = true;
        stage_ = Stage::Prepared;
        lastReason_ = Reason::None;
        return accept();
    }

    Decision startSucceeded(const Authority &authority)
    {
        if (!current(authority, false)) return quarantine(lastReason_);
        if (stage_ != Stage::Prepared || !resourcesPrepared_ ||
            !authority.commandSucceeded || !authority.startSucceeded)
            return reject(Reason::StartNotSucceeded);
        stage_ = Stage::AwaitRequest;
        lastReason_ = Reason::None;
        return accept();
    }

    Decision confirmRequest(ShadowRequestProof &proof,
                            const Authority &authority)
    {
        if (!proof.valid_ || proof.consumed_)
            return reject(Reason::RequestNotConfirmed);
        ConfirmedRequest request = proof.request_;
        proof.consumed_ = true;
        proof.valid_ = false;
        memset(&proof.request_, 0, sizeof(proof.request_));
        return confirmRequestFields(request, authority);
    }

    Decision queueReply(const ReplyEnvelope &reply, const Authority &authority)
    {
        if (!current(authority)) return quarantine(lastReason_);
        if (replyQueued_ || stage_ == Stage::ReplyQueued)
            return reject(Reason::AlreadyUsed);
        if (stage_ != Stage::AwaitRequest || !requestConfirmed_ ||
            reply.requestSequence != requestSequence_)
            return reject(Reason::RequestNotConfirmed);
        if (!sameMac(reply.sourceMac, identity_.ownMac) ||
            !sameMac(reply.destinationMac, identity_.peerMac) ||
            !sameIpv6(reply.sourceIpv6, identity_.ownIpv6) ||
            !sameIpv6(reply.destinationIpv6, identity_.peerIpv6) ||
            !sameNonce(reply.payload, identity_.nonce) ||
            reply.sourcePort != identity_.localRequestPort ||
            reply.destinationPort != identity_.peerRequestPort)
            return reject(Reason::ReplyNotMatched);
        if (replyQueued_) return reject(Reason::AlreadyUsed);
        replyQueued_ = true;
        stage_ = Stage::ReplyQueued;
        lastReason_ = Reason::None;
        return accept();
    }

    Decision reservePermit(uint64_t requestSequence,
                           const PreparedResources &resources,
                           const Authority &authority, TxPermit *permit)
    {
        if (permit) permit->invalidate();
        if (!permit) return reject(Reason::PermitInvalid);
        if (!kFeatureCompiled) return reject(Reason::FeatureNotCompiled);
        if (!current(authority)) return quarantine(lastReason_);
        if (role_ != Role::Directed149Reply || !runtimeEnabled_ || shadowOnly_)
            return reject(Reason::ShadowOnly);
        if (doorbellCount_ || permitIssued_ || stage_ != Stage::ReplyQueued)
            return reject(Reason::AlreadyUsed);
        if (!requestConfirmed_ || !replyQueued_ ||
            requestSequence != requestSequence_)
            return reject(Reason::ReplyNotMatched);
        if (authority.nowUs >= deadlineUs_) return reject(Reason::DeadlineExpired);
        if (!consumeResourceSnapshot(resources.snapshotSerial))
            return reject(lastReason_);
        if (resources.appliedChannelFlags & kChannelPassive)
            return reject(Reason::ChannelPassive);
        if (!(resources.nvmProfileFlags & kNvmChannelValid))
            return reject(Reason::ChannelNvmInvalid);
        if (!(resources.nvmProfileFlags & kNvmChannelActiveScan))
            return reject(Reason::ChannelActiveScanMissing);
        if (!resources.firmwareAllowsDataTx)
            return reject(Reason::FirmwareTxNotAllowed);
        if (!resourcesMatchIdentity(resources) || !resourcesPreparedMatch(resources))
            return reject(Reason::ResourceAckMissing);
        permitIssued_ = true;
        stage_ = Stage::CommitReserved;
        lastReason_ = Reason::None;
        permit->valid_ = true;
        permit->armSerial_ = armSerial_;
        permit->runSerial_ = identity_.runSerial;
        permit->ownerSerial_ = identity_.ownerSerial;
        permit->requestSequence_ = requestSequence_;
        permit->deadlineUs_ = deadlineUs_;
        permit->bindingSerial_ = resources_.bindingAllocationSerial;
        permit->stationSerial_ = resources_.stationAllocationSerial;
        permit->queueSerial_ = resources_.queueAllocationSerial;
        permit->nonce_ = identity_.nonce;
        permit->queueId_ = resources_.queueId;
        permit->stationId_ = resources_.stationId;
        permit->phyId_ = resources_.phyId;
        permit->macId_ = resources_.macId;
        permit->macColor_ = resources_.macColor;
        return accept();
    }

    Decision markDoorbell(const TxPermit &permit,
                          const PreparedResources &freshResources,
                          const Authority &authority)
    {
        if (!permit.valid_ || !permitIssued_ || stage_ != Stage::CommitReserved ||
            permit.armSerial_ != armSerial_ ||
            permit.runSerial_ != identity_.runSerial ||
            permit.ownerSerial_ != identity_.ownerSerial ||
            !sameNonce(permit.nonce_, identity_.nonce) ||
            permit.requestSequence_ != requestSequence_ ||
            permit.deadlineUs_ != deadlineUs_ ||
            permit.bindingSerial_ != resources_.bindingAllocationSerial ||
            permit.stationSerial_ != resources_.stationAllocationSerial ||
            permit.queueSerial_ != resources_.queueAllocationSerial ||
            permit.queueId_ != resources_.queueId ||
            permit.stationId_ != resources_.stationId ||
            permit.phyId_ != resources_.phyId ||
            permit.macId_ != resources_.macId ||
            permit.macColor_ != resources_.macColor || doorbellCount_)
            return reject(Reason::PermitInvalid);
        if (!current(authority)) return quarantine(lastReason_);
        if (authority.nowUs >= deadlineUs_) return quarantine(Reason::DeadlineExpired);
        if (!consumeResourceSnapshot(freshResources.snapshotSerial))
            return quarantine(lastReason_);
        if (!resourcesMatchIdentity(freshResources) ||
            !resourcesPreparedMatch(freshResources))
            return quarantine(Reason::ResourceAckMissing);
        doorbellCount_ = 1;
        doorbellIssued_ = true;
        stage_ = Stage::DoorbellIssued;
        lastReason_ = Reason::None;
        return accept();
    }

    Decision complete(const TxPermit &permit,
                      const TxCompletionEvidence &completion,
                      const Authority &authority)
    {
        if (stage_ != Stage::DoorbellIssued || !doorbellIssued_ ||
            !permitMatches(permit)) return reject(Reason::PermitInvalid);
        if (!completionMatches(completion))
            return reject(Reason::CompletionMismatch);
        switch (completion.status) {
        case CompletionStatus::Success:
            break;
        case CompletionStatus::Failure:
            return quarantine(Reason::CompletionFailed);
        case CompletionStatus::Unknown:
        default:
            return quarantine(Reason::CompletionUnknown);
        }
        // A precisely matched TX response may arrive after ROC END. END blocks
        // new permits; it does not invalidate completion of this in-flight slot.
        if (!completion.responseMatched)
            return reject(Reason::CompletionMismatch);
        if (authority.interfaceIncarnation != identity_.interfaceIncarnation ||
            authority.ifindex != identity_.ifindex)
            return quarantine(Reason::CompletionMismatch);
        stage_ = Stage::Completed;
        closed_ = true;
        lastReason_ = Reason::None;
        return accept();
    }

    Decision close(Reason reason)
    {
        if (stage_ == Stage::Completed) return {true, Reason::None, stage_};
        if (stage_ == Stage::Quarantined || stage_ == Stage::Closed)
            return {false, lastReason_, stage_};
        if (doorbellIssued_)
            return quarantine(reason == Reason::None ? Reason::OwnerClosed : reason);
        stage_ = Stage::Closed;
        closed_ = true;
        requestConfirmed_ = false;
        replyQueued_ = false;
        permitIssued_ = false;
        lastReason_ = reason == Reason::None ? Reason::OwnerClosed : reason;
        return {false, lastReason_, stage_};
    }

    Snapshot snapshot() const
    {
        Snapshot s{};
        s.role = role_; s.stage = stage_; s.lastReason = lastReason_;
        s.ownerSerial = identity_.ownerSerial; s.runHighWater = runHighWater_;
        s.ownerHighWater = ownerHighWater_;
        s.armSerial = armSerial_; s.requestSequence = requestSequence_;
        s.deadlineUs = deadlineUs_; s.monotonicUsHighWater = lastNowUs_;
        s.resourceSnapshotHighWater = lastResourceSnapshotSerial_;
        s.doorbellCount = doorbellCount_;
        s.compiled = kFeatureCompiled; s.runtimeEnabled = runtimeEnabled_;
        s.shadowOnly = shadowOnly_; s.activeChannel = activeChannel_;
        s.resourcesPrepared = resourcesPrepared_; s.requestConfirmed = requestConfirmed_;
        s.replyQueued = replyQueued_; s.permitIssued = permitIssued_;
        s.doorbellIssued = doorbellIssued_; s.quarantined = quarantined_;
        return s;
    }

private:
    Decision confirmRequestFields(const ConfirmedRequest &request,
                                  const Authority &authority)
    {
        if (!current(authority)) return quarantine(lastReason_);
        if (stage_ != Stage::AwaitRequest || requestConfirmed_ || !request.sequence ||
            !request.inputConfirmed || !request.associationCurrent ||
            request.ifnetInputResult != 0 || request.deadlineUs <= authority.nowUs)
            return reject(request.ifnetInputResult != 0 ?
                          Reason::InputFailed : Reason::RequestNotConfirmed);
        if (request.runSerial != identity_.runSerial ||
            request.ownerSerial != identity_.ownerSerial ||
            !sameEpochs(request.epochs, identity_.epochs) ||
            request.interfaceIncarnation != identity_.interfaceIncarnation ||
            request.guardVersion != identity_.shadowGuardVersion ||
            request.deadlineUs > identity_.deadlineUs ||
            !sameMac(request.sourceMac, identity_.peerMac) ||
            !sameMac(request.destinationMac, identity_.ownMac) ||
            !sameIpv6(request.sourceIpv6, identity_.peerIpv6) ||
            !sameIpv6(request.destinationIpv6, identity_.ownIpv6) ||
            !sameNonce(request.nonce, identity_.nonce) ||
            request.sourcePort != identity_.peerRequestPort ||
            request.destinationPort != identity_.localRequestPort)
            return reject(Reason::RequestNotConfirmed);
        requestSequence_ = request.sequence;
        deadlineUs_ = request.deadlineUs;
        requestConfirmed_ = true;
        lastReason_ = Reason::None;
        return accept();
    }
    bool consumeResourceSnapshot(uint64_t serial)
    {
        if (lastResourceSnapshotSerial_ == UINT64_MAX) {
            lastReason_ = Reason::ResourceEvidenceExhausted;
            return false;
        }
        if (!serial || serial <= lastResourceSnapshotSerial_) {
            lastReason_ = Reason::ResourceEvidenceStale;
            return false;
        }
        lastResourceSnapshotSerial_ = serial;
        return true;
    }
    bool permitMatches(const TxPermit &p) const
    {
        return p.valid_ && p.armSerial_ == armSerial_ &&
            p.runSerial_ == identity_.runSerial &&
            p.ownerSerial_ == identity_.ownerSerial &&
            p.requestSequence_ == requestSequence_ && p.deadlineUs_ == deadlineUs_ &&
            p.bindingSerial_ == resources_.bindingAllocationSerial &&
            p.stationSerial_ == resources_.stationAllocationSerial &&
            p.queueSerial_ == resources_.queueAllocationSerial &&
            p.queueId_ == resources_.queueId && p.stationId_ == resources_.stationId &&
            p.phyId_ == resources_.phyId && p.macId_ == resources_.macId &&
            p.macColor_ == resources_.macColor && sameNonce(p.nonce_, identity_.nonce);
    }
    bool completionMatches(const TxCompletionEvidence &c) const
    {
        return c.armSerial == armSerial_ && c.runSerial == identity_.runSerial &&
            c.ownerSerial == identity_.ownerSerial && sameEpochs(c.epochs, identity_.epochs) &&
            c.interfaceIncarnation == identity_.interfaceIncarnation &&
            c.ifindex == identity_.ifindex && c.requestSequence == requestSequence_ &&
            c.queueAllocationSerial == resources_.queueAllocationSerial &&
            c.queueId == resources_.queueId;
    }
    bool resourcesMatchIdentity(const PreparedResources &r) const
    {
        return r.runSerial == identity_.runSerial &&
            r.ownerSerial == identity_.ownerSerial &&
            sameEpochs(r.epochs, identity_.epochs) &&
            r.interfaceIncarnation == identity_.interfaceIncarnation &&
            r.ifindex == identity_.ifindex &&
            sameMac(r.bindingOwnMac, identity_.ownMac) &&
            sameMac(r.bindingPeerMac, identity_.peerMac) &&
            sameMac(r.stationPeerMac, identity_.peerMac);
    }
    bool resourcesPreparedMatch(const PreparedResources &r) const
    {
        return activeTxChannel(r) && r.channel == identity_.channel &&
            r.regulatoryRevision == identity_.regulatoryRevision &&
            r.bindingAck && r.stationAck && r.directedPeerStation && r.queueAck &&
            r.exactHostQueueSlotFree && !r.queueOwnedBySta && r.staContextPreserved &&
            r.phyId == 1 && r.macId == 1 && r.macColor != 0 &&
            r.queueId < kQueueIdLimit &&
            r.bindingAllocationSerial == resources_.bindingAllocationSerial &&
            r.stationAllocationSerial == resources_.stationAllocationSerial &&
            r.queueAllocationSerial == resources_.queueAllocationSerial &&
            r.queueId == resources_.queueId && r.stationId == resources_.stationId &&
            r.phyId == resources_.phyId && r.macId == resources_.macId &&
            r.macColor == resources_.macColor;
    }
    Decision accept() const { return {true, Reason::None, stage_}; }
    Decision reject(Reason reason)
    {
        if (stage_ == Stage::Quarantined || stage_ == Stage::Closed ||
            stage_ == Stage::Completed)
            return {false, lastReason_, stage_};
        lastReason_ = reason;
        return {false, reason, stage_};
    }
    Decision quarantine(Reason reason)
    {
        if (stage_ == Stage::Completed) return {true, Reason::None, stage_};
        if (stage_ == Stage::Quarantined || stage_ == Stage::Closed)
            return {false, lastReason_, stage_};
        quarantined_ = true;
        stage_ = Stage::Quarantined;
        lastReason_ = reason;
        return {false, reason, stage_};
    }
    bool current(const Authority &a, bool requireStarted = true)
    {
        if (stage_ == Stage::Quarantined) return false;
        if (stage_ == Stage::Closed || closed_) {
            lastReason_ = Reason::OwnerClosed;
            return false;
        }
        if (role_ != Role::Directed149Reply ||
            !runtimeEnabled_ || shadowOnly_) {
            lastReason_ = closed_ ? Reason::OwnerClosed : Reason::ShadowOnly;
            return false;
        }
        if (a.nowUs < lastNowUs_) { lastReason_ = Reason::ClockRollback; return false; }
        lastNowUs_ = a.nowUs;
        if (a.endSeen) { lastReason_ = Reason::EndObserved; return false; }
        if (a.outcomeUnknown || a.receiveObservationOnly ||
            !a.ownerCurrent || !a.leaseActive ||
            a.runSerial != identity_.runSerial ||
            a.ownerSerial != identity_.ownerSerial ||
            !sameEpochs(a.epochs, identity_.epochs) ||
            a.interfaceIncarnation != identity_.interfaceIncarnation ||
            a.ifindex != identity_.ifindex ||
            a.regulatoryRevision != identity_.regulatoryRevision ||
            a.shadowGuardVersion != identity_.shadowGuardVersion ||
            a.channel != identity_.channel ||
            (requireStarted && (!a.commandSucceeded || !a.startSucceeded)) ||
            !a.radioReady || !a.staAssociated ||
            !a.staChannelUnchanged || !a.commandQueueIdle || !a.scanIdle ||
            !a.newStateIdle) {
            lastReason_ = a.receiveObservationOnly ? Reason::ReceiveOnlyLease :
                          Reason::StaleAuthority;
            return false;
        }
        const uint64_t activeDeadline = deadlineUs_ ? deadlineUs_ : identity_.deadlineUs;
        if (a.nowUs >= identity_.deadlineUs || a.nowUs >= activeDeadline) {
            lastReason_ = Reason::DeadlineExpired;
            return false;
        }
        return true;
    }

    const Role role_;
    Stage stage_;
    Reason lastReason_;
    uint64_t runHighWater_;
    uint64_t ownerHighWater_;
    uint64_t armSerial_;
    uint64_t requestSequence_;
    uint64_t deadlineUs_;
    bool runtimeEnabled_;
    bool shadowOnly_;
    bool activeChannel_;
    bool resourcesPrepared_;
    bool requestConfirmed_;
    bool replyQueued_;
    bool permitIssued_;
    bool doorbellIssued_;
    bool quarantined_;
    bool closed_;
    uint32_t doorbellCount_;
    uint64_t lastNowUs_;
    uint64_t lastResourceSnapshotSerial_;
    Identity identity_;
    PreparedResources resources_;
};

} // namespace NativeAwdlDirectedTxContract

#endif // NATIVE_AWDL_DIRECTED_TX_CONTRACT_HPP
