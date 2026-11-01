#include "awdl_directed_tx_contract.hpp"

#include <assert.h>
#include <stdint.h>
#include <type_traits>
#include <stdio.h>

namespace NativeAwdlDirectedTxContract {
// Test-only stand-in for the trusted shadow ledger. Production defines this
// provider next to the ledger and calls issue() only after successful ifnet input.
class ShadowProofProvider {
public:
    static void issue(ShadowRequestProof &proof, const ConfirmedRequest &request)
    {
        proof.request_ = request;
        proof.valid_ = true;
        proof.consumed_ = false;
    }
};
}

using namespace NativeAwdlDirectedTxContract;

static_assert(!std::is_copy_constructible<TxPermit>::value,
              "a doorbell permit must not be copyable");
static_assert(!std::is_copy_constructible<ShadowRequestProof>::value,
              "a shadow input proof must not be copyable");
static_assert(!std::is_copy_constructible<Candidate>::value,
              "a candidate ledger must not be copyable");

static Identity identity(uint64_t run = 41, uint64_t owner = 7)
{
    Identity i{};
    i.runSerial = run;
    i.ownerSerial = owner;
    i.epochs = {11, 12, 13, 14};
    i.interfaceIncarnation = 5;
    i.ifindex = 12;
    i.regulatoryRevision = 3;
    i.shadowGuardVersion = 6;
    i.channel = kChannel149;
    i.startUs = 1000;
    i.deadlineUs = 100328;
    i.ownMac.bytes[0] = 0x02;
    i.ownMac.bytes[5] = 0x01;
    i.peerMac.bytes[0] = 0x02;
    i.peerMac.bytes[5] = 0x02;
    i.ownIpv6.bytes[0] = 0xfe;
    i.ownIpv6.bytes[1] = 0x80;
    i.ownIpv6.bytes[8] = 0x00;
    i.ownIpv6.bytes[9] = 0x00;
    i.ownIpv6.bytes[10] = 0x00;
    i.ownIpv6.bytes[11] = 0xff;
    i.ownIpv6.bytes[12] = 0xfe;
    i.ownIpv6.bytes[13] = 0x00;
    i.ownIpv6.bytes[14] = 0x00;
    i.ownIpv6.bytes[15] = 0x01;
    i.peerIpv6.bytes[0] = 0xfe;
    i.peerIpv6.bytes[1] = 0x80;
    i.peerIpv6.bytes[8] = 0x00;
    i.peerIpv6.bytes[9] = 0x00;
    i.peerIpv6.bytes[10] = 0x00;
    i.peerIpv6.bytes[11] = 0xff;
    i.peerIpv6.bytes[12] = 0xfe;
    i.peerIpv6.bytes[13] = 0x00;
    i.peerIpv6.bytes[14] = 0x00;
    i.peerIpv6.bytes[15] = 0x02;
    for (unsigned n = 0; n != sizeof(i.nonce.bytes); ++n)
        i.nonce.bytes[n] = static_cast<uint8_t>(0x31 + n);
    i.peerRequestPort = 49152;
    i.localRequestPort = 49153;
    return i;
}

static Authority authority(const Identity &i, uint64_t now = 1000)
{
    Authority a{};
    a.runSerial = i.runSerial;
    a.ownerSerial = i.ownerSerial;
    a.epochs = i.epochs;
    a.interfaceIncarnation = i.interfaceIncarnation;
    a.ifindex = i.ifindex;
    a.regulatoryRevision = i.regulatoryRevision;
    a.shadowGuardVersion = i.shadowGuardVersion;
    a.channel = i.channel;
    a.nowUs = now;
    a.ownerCurrent = true;
    a.leaseActive = true;
    a.commandSucceeded = true;
    a.startSucceeded = true;
    a.radioReady = true;
    a.staAssociated = true;
    a.staChannelUnchanged = true;
    a.commandQueueIdle = true;
    a.scanIdle = true;
    a.newStateIdle = true;
    return a;
}

static ArmIntent intent(const Identity &i)
{
    ArmIntent a{};
    a.role = Role::Directed149Reply;
    a.explicitlyRequested = true;
    a.runtimeEnabled = true;
    a.txCapabilityEnabled = true;
    a.shadowOnly = false;
    a.armSerial = i.runSerial;
    return a;
}

#if ITL_NATIVE_AWDL_DIRECTED_REPLY_TX_25G332
static PreparedResources resources(const Identity &i)
{
    PreparedResources r{};
    r.runSerial = i.runSerial;
    r.ownerSerial = i.ownerSerial;
    r.epochs = i.epochs;
    r.interfaceIncarnation = i.interfaceIncarnation;
    r.ifindex = i.ifindex;
    r.bindingOwnMac = i.ownMac;
    r.bindingPeerMac = i.peerMac;
    r.stationPeerMac = i.peerMac;
    r.appliedChannelFlags = 0x08030140; // no PASSIVE bit
    r.nvmProfileFlags = kNvmChannelValid | kNvmChannelActiveScan;
    r.channel = i.channel;
    r.regulatoryRevision = i.regulatoryRevision;
    r.snapshotSerial = 10;
    r.bindingAck = true;
    r.stationAck = true;
    r.directedPeerStation = true;
    r.queueAck = true;
    r.firmwareAllowsDataTx = true;
    r.exactHostQueueSlotFree = true;
    r.queueOwnedBySta = false;
    r.staContextPreserved = true;
    r.phyId = 1;
    r.macId = 1;
    r.macColor = 1;
    r.queueId = 3;
    r.stationId = 5;
    r.bindingAllocationSerial = 101;
    r.stationAllocationSerial = 102;
    r.queueAllocationSerial = 103;
    return r;
}

static PreparedResources freshResources(const PreparedResources &r, uint64_t serial)
{
    PreparedResources fresh = r;
    fresh.snapshotSerial = serial;
    return fresh;
}

static ConfirmedRequest confirmedRequest(const Identity &i, uint64_t sequence = 55)
{
    ConfirmedRequest r{};
    r.runSerial = i.runSerial;
    r.ownerSerial = i.ownerSerial;
    r.epochs = i.epochs;
    r.interfaceIncarnation = i.interfaceIncarnation;
    r.guardVersion = 6;
    r.sequence = sequence;
    r.deadlineUs = i.deadlineUs - 1000;
    r.sourceMac = i.peerMac;
    r.destinationMac = i.ownMac;
    r.sourceIpv6 = i.peerIpv6;
    r.destinationIpv6 = i.ownIpv6;
    r.nonce = i.nonce;
    r.sourcePort = 49152;
    r.destinationPort = 49153;
    r.ifnetInputResult = 0;
    r.inputConfirmed = true;
    r.associationCurrent = true;
    return r;
}

static ReplyEnvelope reply(const Identity &i, uint64_t sequence = 55)
{
    ReplyEnvelope r{};
    r.requestSequence = sequence;
    r.sourceMac = i.ownMac;
    r.destinationMac = i.peerMac;
    r.sourceIpv6 = i.ownIpv6;
    r.destinationIpv6 = i.peerIpv6;
    r.payload = i.nonce;
    r.sourcePort = 49153;
    r.destinationPort = 49152;
    return r;
}

static TxCompletionEvidence completion(const Identity &i, const PreparedResources &r,
                                       uint64_t sequence = 55,
                                       CompletionStatus status = CompletionStatus::Success,
                                       bool responseMatched = true)
{
    TxCompletionEvidence e{};
    e.armSerial = i.runSerial;
    e.runSerial = i.runSerial;
    e.ownerSerial = i.ownerSerial;
    e.epochs = i.epochs;
    e.interfaceIncarnation = i.interfaceIncarnation;
    e.ifindex = i.ifindex;
    e.requestSequence = sequence;
    e.queueAllocationSerial = r.queueAllocationSerial;
    e.queueId = r.queueId;
    e.status = status;
    e.responseMatched = responseMatched;
    return e;
}

static Decision armCandidate(Candidate &c, const Identity &i, Authority &a)
{
    return c.arm(intent(i), i, a);
}

static Decision getToAwaitRequest(Candidate &c, const Identity &i,
                                  Authority &a, const PreparedResources &r)
{
    Decision d = armCandidate(c, i, a);
    if (!d.accepted) return d;
    d = c.prepare(r, a);
    if (!d.accepted) return d;
    d = c.startSucceeded(a);
    if (!d.accepted) return d;
    a.nowUs = i.startUs + 100;
    return d;
}

static Decision admit(Candidate &c, const Identity &i, Authority &a,
                      uint64_t sequence = 55)
{
    ShadowRequestProof proof;
    ShadowProofProvider::issue(proof, confirmedRequest(i, sequence));
    Decision d = c.confirmRequest(proof, a);
    assert(!proof.valid());
    return d;
}

static Decision queue(Candidate &c, const Identity &i, Authority &a,
                      uint64_t sequence = 55)
{
    return c.queueReply(reply(i, sequence), a);
}
#endif

#if !ITL_NATIVE_AWDL_DIRECTED_REPLY_TX_25G332
static void testCompileOffDefault()
{
    Identity i = identity();
    Authority a = authority(i);
    Candidate directed(Role::Directed149Reply);
    Decision d = directed.arm(intent(i), i, a);
    assert(!d.accepted && d.reason == Reason::FeatureNotCompiled);
    Snapshot s = directed.snapshot();
    assert(s.stage == Stage::Disarmed && !s.runtimeEnabled && s.shadowOnly);
    TxPermit p;
    assert(!p.valid());
    puts("compile-off defaults remain disarmed");
}
#else
static void testRoleAndArmGates()
{
    Identity i = identity();
    Authority a = authority(i);
    Candidate rxOnly;
    Decision d = armCandidate(rxOnly, i, a);
    assert(!d.accepted && d.reason == Reason::WrongRole);
    assert(rxOnly.snapshot().doorbellCount == 0);

    Candidate noExplicit(Role::Directed149Reply);
    ArmIntent x = intent(i); x.explicitlyRequested = false;
    d = noExplicit.arm(x, i, a);
    assert(!d.accepted && d.reason == Reason::NotExplicitlyArmed);

    Candidate shadow(Role::Directed149Reply);
    x = intent(i); x.shadowOnly = true;
    d = shadow.arm(x, i, a);
    assert(!d.accepted && d.reason == Reason::ShadowOnly);

    Candidate receiveOnly(Role::Directed149Reply);
    a.receiveObservationOnly = true;
    d = armCandidate(receiveOnly, i, a);
    assert(!d.accepted && d.reason == Reason::ReceiveOnlyLease);
    assert(receiveOnly.snapshot().doorbellCount == 0);
}

static void testActiveHappyPathLateEndAndIdempotentClose()
{
    Identity i = identity();
    Authority a = authority(i);
    PreparedResources r = resources(i);
    Candidate c(Role::Directed149Reply, 40, 6);
    assert(armCandidate(c, i, a).accepted);
    assert(c.prepare(r, a).accepted);
    assert(c.startSucceeded(a).accepted);
    a.nowUs = 1200;
    assert(admit(c, i, a).accepted);
    assert(queue(c, i, a).accepted);

    TxPermit p;
    assert(c.reservePermit(55, freshResources(r, 11), a, &p).accepted);
    assert(p.valid() && p.runSerial() == i.runSerial);
    assert(c.markDoorbell(p, freshResources(r, 12), a).accepted);
    assert(c.snapshot().doorbellCount == 1);
    Decision second = c.markDoorbell(p, freshResources(r, 12), a);
    assert(!second.accepted && c.snapshot().doorbellCount == 1);

    // END revokes new submissions, but an exact matching response can retire
    // the one already in flight without reviving its owner.
    a.endSeen = true;
    a.leaseActive = false;
    a.ownerCurrent = false;
    TxCompletionEvidence e = completion(i, r);
    assert(c.complete(p, e, a).accepted);
    assert(c.snapshot().stage == Stage::Completed);
    assert(c.close(Reason::OwnerClosed).accepted);
    assert(c.snapshot().stage == Stage::Completed && !c.snapshot().quarantined);
}

static void testActiveVsPassiveAndNvmGates()
{
    Identity i = identity();
    Authority a = authority(i);
    PreparedResources r = resources(i);
    Candidate passive(Role::Directed149Reply);
    assert(armCandidate(passive, i, a).accepted);
    r.appliedChannelFlags |= kChannelPassive;
    Decision d = passive.prepare(r, a);
    assert(!d.accepted && d.reason == Reason::ChannelPassive);
    assert(passive.snapshot().doorbellCount == 0);

    r = resources(i); r.nvmProfileFlags = kNvmChannelValid;
    Candidate noActiveNvm(Role::Directed149Reply);
    assert(armCandidate(noActiveNvm, i, a).accepted);
    d = noActiveNvm.prepare(r, a);
    assert(!d.accepted && d.reason == Reason::ChannelActiveScanMissing);

    r = resources(i); r.nvmProfileFlags = kNvmChannelActiveScan;
    Candidate invalidNvm(Role::Directed149Reply);
    assert(armCandidate(invalidNvm, i, a).accepted);
    d = invalidNvm.prepare(r, a);
    assert(!d.accepted && d.reason == Reason::ChannelNvmInvalid);

    r = resources(i); r.firmwareAllowsDataTx = false;
    Candidate fwDenied(Role::Directed149Reply);
    assert(armCandidate(fwDenied, i, a).accepted);
    d = fwDenied.prepare(r, a);
    assert(!d.accepted && d.reason == Reason::FirmwareTxNotAllowed);
}

static void testQueueAndMacResourceGates()
{
    Identity i = identity();
    Authority a = authority(i);
    PreparedResources r = resources(i);

    Candidate wrongMac(Role::Directed149Reply);
    assert(armCandidate(wrongMac, i, a).accepted);
    r.bindingPeerMac.bytes[5] = 0x03;
    Decision d = wrongMac.prepare(r, a);
    assert(!d.accepted && d.reason == Reason::InvalidIdentity);

    r = resources(i); r.phyId = 0;
    Candidate wrongPhy(Role::Directed149Reply);
    assert(armCandidate(wrongPhy, i, a).accepted);
    d = wrongPhy.prepare(r, a);
    assert(!d.accepted && d.reason == Reason::InvalidPhyBinding);

    r = resources(i); r.queueOwnedBySta = true;
    Candidate staCollision(Role::Directed149Reply);
    assert(armCandidate(staCollision, i, a).accepted);
    d = staCollision.prepare(r, a);
    assert(!d.accepted && d.reason == Reason::StaQueueCollision);

    r = resources(i); r.exactHostQueueSlotFree = false;
    Candidate noSlotProof(Role::Directed149Reply);
    assert(armCandidate(noSlotProof, i, a).accepted);
    d = noSlotProof.prepare(r, a);
    assert(!d.accepted && d.reason == Reason::QueueSlotNotProvenFree);

    r = resources(i); r.queueId = kQueueIdLimit;
    Candidate invalidQid(Role::Directed149Reply);
    assert(armCandidate(invalidQid, i, a).accepted);
    d = invalidQid.prepare(r, a);
    assert(!d.accepted && d.reason == Reason::InvalidQueueId);

    r = resources(i); r.queueAck = false;
    Candidate noQueueAck(Role::Directed149Reply);
    assert(armCandidate(noQueueAck, i, a).accepted);
    d = noQueueAck.prepare(r, a);
    assert(!d.accepted && d.reason == Reason::QueueNotAcked);

    r = resources(i); r.bindingAck = false;
    Candidate noBindingAck(Role::Directed149Reply);
    assert(armCandidate(noBindingAck, i, a).accepted);
    d = noBindingAck.prepare(r, a);
    assert(!d.accepted && d.reason == Reason::BindingNotAcked);

    r = resources(i); r.stationAck = false;
    Candidate noStationAck(Role::Directed149Reply);
    assert(armCandidate(noStationAck, i, a).accepted);
    d = noStationAck.prepare(r, a);
    assert(!d.accepted && d.reason == Reason::StationNotAcked);

    r = resources(i); r.directedPeerStation = false;
    Candidate noPeerStation(Role::Directed149Reply);
    assert(armCandidate(noPeerStation, i, a).accepted);
    d = noPeerStation.prepare(r, a);
    assert(!d.accepted && d.reason == Reason::StationNotAcked);

    r = resources(i); r.staContextPreserved = false;
    Candidate staChanged(Role::Directed149Reply);
    assert(armCandidate(staChanged, i, a).accepted);
    d = staChanged.prepare(r, a);
    assert(!d.accepted && d.reason == Reason::StaContextChanged);
}

static void testShadowProofAndReplyTupleAreOneShot()
{
    Identity i = identity();
    Authority a = authority(i);
    PreparedResources r = resources(i);
    Candidate c(Role::Directed149Reply);
    assert(getToAwaitRequest(c, i, a, r).accepted);

    ConfirmedRequest raw = confirmedRequest(i);
    raw.sourcePort = 49153;
    ShadowRequestProof invalidProof;
    ShadowProofProvider::issue(invalidProof, raw);
    Decision d = c.confirmRequest(invalidProof, a);
    assert(!d.accepted && !invalidProof.valid());

    ShadowRequestProof proof;
    ShadowProofProvider::issue(proof, confirmedRequest(i));
    assert(c.confirmRequest(proof, a).accepted);
    assert(!proof.valid());
    ShadowRequestProof duplicate;
    ShadowProofProvider::issue(duplicate, confirmedRequest(i, 56));
    d = c.confirmRequest(duplicate, a);
    assert(!d.accepted && c.snapshot().requestSequence == 55);

    ReplyEnvelope bad = reply(i);
    bad.payload.bytes[0] ^= 1;
    d = c.queueReply(bad, a);
    assert(!d.accepted && d.reason == Reason::ReplyNotMatched);
    assert(queue(c, i, a).accepted);
    d = queue(c, i, a);
    assert(!d.accepted && d.reason == Reason::AlreadyUsed);
}

static void testRequestFailureAndStaleAuthorityRetire()
{
    Identity i = identity();
    Authority a = authority(i);
    PreparedResources r = resources(i);
    Candidate inputFail(Role::Directed149Reply);
    assert(getToAwaitRequest(inputFail, i, a, r).accepted);
    ConfirmedRequest raw = confirmedRequest(i);
    raw.ifnetInputResult = 5;
    ShadowRequestProof failed;
    ShadowProofProvider::issue(failed, raw);
    Decision d = inputFail.confirmRequest(failed, a);
    assert(!d.accepted && d.reason == Reason::InputFailed);

    Candidate stale(Role::Directed149Reply);
    a = authority(i);
    assert(armCandidate(stale, i, a).accepted);
    a.ownerSerial++;
    d = stale.prepare(r, a);
    assert(!d.accepted && d.stage == Stage::Quarantined);
    a = authority(i);
    d = stale.prepare(r, a);
    assert(!d.accepted && stale.snapshot().quarantined);

    Candidate endSeen(Role::Directed149Reply);
    a = authority(i);
    assert(armCandidate(endSeen, i, a).accepted);
    a.endSeen = true;
    d = endSeen.prepare(r, a);
    assert(!d.accepted && d.reason == Reason::EndObserved);
}

static void testRunAndOwnerHighWaterRejectRevival()
{
    Identity i = identity(40, 6);
    Authority a = authority(i);
    Candidate c(Role::Directed149Reply, 40, 6);
    Decision d = armCandidate(c, i, a);
    assert(!d.accepted && d.reason == Reason::StaleOwner);

    i = identity(41, 6); a = authority(i);
    Candidate c2(Role::Directed149Reply, 40, 6);
    d = armCandidate(c2, i, a);
    assert(!d.accepted && d.reason == Reason::StaleOwner);

    i = identity(41, 7); a = authority(i);
    Candidate c3(Role::Directed149Reply, 40, 6);
    assert(armCandidate(c3, i, a).accepted);
    assert(c3.snapshot().runHighWater == 41 && c3.snapshot().ownerHighWater == 7);
}

static void testFreshDoorbellResourceRecheckAndDeadline()
{
    Identity i = identity();
    Authority a = authority(i);
    PreparedResources r = resources(i);
    Candidate c(Role::Directed149Reply);
    assert(getToAwaitRequest(c, i, a, r).accepted);
    assert(admit(c, i, a).accepted);
    assert(queue(c, i, a).accepted);
    TxPermit p;
    assert(c.reservePermit(55, freshResources(r, 11), a, &p).accepted);
    PreparedResources changed = freshResources(r, 12);
    changed.queueAllocationSerial++;
    Decision d = c.markDoorbell(p, changed, a);
    assert(!d.accepted && d.stage == Stage::Quarantined);
    assert(c.snapshot().doorbellCount == 0);

    Candidate expired(Role::Directed149Reply);
    a = authority(i);
    assert(armCandidate(expired, i, a).accepted);
    a.nowUs = i.deadlineUs;
    d = expired.prepare(r, a);
    assert(!d.accepted && d.reason == Reason::DeadlineExpired);
    assert(d.stage == Stage::Quarantined);
}

static void testCompletionOrderingAndUnknownQuarantine()
{
    Identity i = identity();
    Authority a = authority(i);
    PreparedResources r = resources(i);
    Candidate c(Role::Directed149Reply);
    assert(getToAwaitRequest(c, i, a, r).accepted);
    assert(admit(c, i, a).accepted);
    assert(queue(c, i, a).accepted);
    TxPermit p;
    assert(c.reservePermit(55, freshResources(r, 11), a, &p).accepted);
    assert(c.markDoorbell(p, freshResources(r, 12), a).accepted);

    TxCompletionEvidence lateWrong = completion(i, r, 54);
    Decision d = c.complete(p, lateWrong, a);
    assert(!d.accepted && d.reason == Reason::CompletionMismatch);
    assert(c.snapshot().stage == Stage::DoorbellIssued);

    TxCompletionEvidence unknown = completion(i, r, 55, CompletionStatus::Unknown, false);
    d = c.complete(p, unknown, a);
    assert(!d.accepted && d.reason == Reason::CompletionUnknown);
    assert(d.stage == Stage::Quarantined && c.snapshot().doorbellCount == 1);
    TxCompletionEvidence ack = completion(i, r);
    d = c.complete(p, ack, a);
    assert(!d.accepted && c.snapshot().stage == Stage::Quarantined);
}

static void testCompletionTupleMismatchAndDuplicateSuccess()
{
    Identity i = identity();
    Authority a = authority(i);
    PreparedResources r = resources(i);
    Candidate c(Role::Directed149Reply);
    assert(getToAwaitRequest(c, i, a, r).accepted);
    assert(admit(c, i, a).accepted);
    assert(queue(c, i, a).accepted);
    TxPermit p;
    assert(c.reservePermit(55, freshResources(r, 11), a, &p).accepted);
    assert(c.markDoorbell(p, freshResources(r, 12), a).accepted);

    TxCompletionEvidence base = completion(i, r);
    TxCompletionEvidence bad = base; bad.armSerial++;
    Decision d = c.complete(p, bad, a);
    assert(!d.accepted && d.reason == Reason::CompletionMismatch);
    assert(c.snapshot().stage == Stage::DoorbellIssued);
    bad = base; bad.runSerial++;
    d = c.complete(p, bad, a);
    assert(!d.accepted && d.reason == Reason::CompletionMismatch);
    bad = base; bad.ownerSerial++;
    d = c.complete(p, bad, a);
    assert(!d.accepted && d.reason == Reason::CompletionMismatch);
    bad = base; bad.epochs.station++;
    d = c.complete(p, bad, a);
    assert(!d.accepted && d.reason == Reason::CompletionMismatch);
    bad = base; bad.interfaceIncarnation++;
    d = c.complete(p, bad, a);
    assert(!d.accepted && d.reason == Reason::CompletionMismatch);
    bad = base; bad.ifindex++;
    d = c.complete(p, bad, a);
    assert(!d.accepted && d.reason == Reason::CompletionMismatch);
    bad = base; bad.requestSequence++;
    d = c.complete(p, bad, a);
    assert(!d.accepted && d.reason == Reason::CompletionMismatch);
    bad = base; bad.queueAllocationSerial++;
    d = c.complete(p, bad, a);
    assert(!d.accepted && d.reason == Reason::CompletionMismatch);
    bad = base; bad.queueId++;
    d = c.complete(p, bad, a);
    assert(!d.accepted && d.reason == Reason::CompletionMismatch);

    bad = base; bad.responseMatched = false;
    d = c.complete(p, bad, a);
    assert(!d.accepted && d.reason == Reason::CompletionMismatch);
    assert(c.snapshot().stage == Stage::DoorbellIssued);

    assert(c.complete(p, base, a).accepted);
    d = c.complete(p, base, a);
    assert(!d.accepted && c.snapshot().stage == Stage::Completed);
    assert(!c.snapshot().quarantined);
}

static void testDoorbellCloseAndCloseBeforeDoorbell()
{
    Identity i = identity();
    Authority a = authority(i);
    PreparedResources r = resources(i);
    Candidate beforeDoorbell(Role::Directed149Reply);
    assert(getToAwaitRequest(beforeDoorbell, i, a, r).accepted);
    assert(admit(beforeDoorbell, i, a).accepted);
    assert(queue(beforeDoorbell, i, a).accepted);
    TxPermit stale;
    assert(beforeDoorbell.reservePermit(55, freshResources(r, 11), a, &stale).accepted);
    Decision d = beforeDoorbell.close(Reason::OwnerClosed);
    assert(!d.accepted && d.stage == Stage::Closed);
    d = beforeDoorbell.markDoorbell(stale, freshResources(r, 12), a);
    assert(!d.accepted && d.stage == Stage::Closed);
    assert(beforeDoorbell.snapshot().doorbellCount == 0);

    Candidate inFlight(Role::Directed149Reply);
    a = authority(i);
    assert(getToAwaitRequest(inFlight, i, a, r).accepted);
    assert(admit(inFlight, i, a).accepted);
    assert(queue(inFlight, i, a).accepted);
    TxPermit submitted;
    assert(inFlight.reservePermit(55, freshResources(r, 11), a, &submitted).accepted);
    assert(inFlight.markDoorbell(submitted, freshResources(r, 12), a).accepted);
    d = inFlight.close(Reason::OwnerClosed);
    assert(!d.accepted && d.stage == Stage::Quarantined);
    TxCompletionEvidence late = completion(i, r);
    d = inFlight.complete(submitted, late, a);
    assert(!d.accepted && d.stage == Stage::Quarantined);
    assert(inFlight.snapshot().doorbellCount == 1);
}

static void testPermitReplayAndUnknownBeforeDoorbell()
{
    Identity i = identity();
    Authority a = authority(i);
    PreparedResources r = resources(i);
    Candidate original(Role::Directed149Reply, 40, 6);
    assert(getToAwaitRequest(original, i, a, r).accepted);
    assert(admit(original, i, a).accepted);
    assert(queue(original, i, a).accepted);
    TxPermit permit;
    assert(original.reservePermit(55, freshResources(r, 11), a, &permit).accepted);

    // A new candidate with a newer run cannot accept an old permit.
    Identity newer = identity(42, 8);
    Authority newerA = authority(newer);
    PreparedResources newerR = resources(newer);
    Candidate replacement(Role::Directed149Reply, 41, 7);
    assert(getToAwaitRequest(replacement, newer, newerA, newerR).accepted);
    assert(admit(replacement, newer, newerA).accepted);
    assert(queue(replacement, newer, newerA).accepted);
    TxPermit replacementPermit;
    assert(replacement.reservePermit(55, freshResources(newerR, 11), newerA, &replacementPermit).accepted);
    Decision d = replacement.markDoorbell(permit, freshResources(newerR, 12), newerA);
    assert(!d.accepted && d.reason == Reason::PermitInvalid);
    assert(replacement.markDoorbell(replacementPermit, freshResources(newerR, 12), newerA).accepted);

    Candidate unknownBeforeDoorbell(Role::Directed149Reply);
    a = authority(i);
    assert(armCandidate(unknownBeforeDoorbell, i, a).accepted);
    a.outcomeUnknown = true;
    d = unknownBeforeDoorbell.prepare(r, a);
    assert(!d.accepted && d.stage == Stage::Quarantined);
}

static void testCloseBeforeDoorbellAndCompletionFailure()
{
    Identity i = identity();
    Authority a = authority(i);
    PreparedResources r = resources(i);
    Candidate closed(Role::Directed149Reply);
    assert(armCandidate(closed, i, a).accepted);
    Decision d = closed.close(Reason::OwnerClosed);
    assert(!d.accepted && d.stage == Stage::Closed);
    d = closed.prepare(r, a);
    assert(!d.accepted && d.stage == Stage::Closed);
    assert(!closed.snapshot().quarantined);

    Candidate failed(Role::Directed149Reply);
    a = authority(i);
    assert(getToAwaitRequest(failed, i, a, r).accepted);
    assert(admit(failed, i, a).accepted);
    assert(queue(failed, i, a).accepted);
    TxPermit p;
    assert(failed.reservePermit(55, freshResources(r, 11), a, &p).accepted);
    assert(failed.markDoorbell(p, freshResources(r, 12), a).accepted);
    TxCompletionEvidence failure = completion(
        i, r, 55, CompletionStatus::Failure, true);
    d = failed.complete(p, failure, a);
    assert(!d.accepted && d.reason == Reason::CompletionFailed);
    assert(d.stage == Stage::Quarantined);
}

static void testEvidenceSerialAndClockHighWater()
{
    Identity i = identity();
    Authority a = authority(i);
    PreparedResources r = resources(i);
    Candidate c(Role::Directed149Reply);
    assert(armCandidate(c, i, a).accepted);
    r.bindingOwnMac.bytes[5] ^= 1;
    Decision d = c.prepare(r, a);
    assert(!d.accepted && d.reason == Reason::InvalidIdentity);
    PreparedResources sameSerial = resources(i);
    d = c.prepare(sameSerial, a);
    assert(!d.accepted && d.reason == Reason::ResourceEvidenceStale);
    PreparedResources newEvidence = freshResources(sameSerial, 11);
    assert(c.prepare(newEvidence, a).accepted);
    assert(c.snapshot().resourceSnapshotHighWater == 11);

    Identity j = identity();
    Authority b = authority(j);
    PreparedResources jr = resources(j);
    Candidate rollback(Role::Directed149Reply);
    assert(getToAwaitRequest(rollback, j, b, jr).accepted);
    assert(admit(rollback, j, b).accepted);
    assert(queue(rollback, j, b).accepted); // accepts the 1100 us timestamp
    b.nowUs = j.startUs + 50; // monotonic clock moved behind the last accepted sample
    TxPermit rollbackPermit;
    d = rollback.reservePermit(55, freshResources(jr, 11), b, &rollbackPermit);
    assert(!d.accepted && d.reason == Reason::ClockRollback);
    assert(d.stage == Stage::Quarantined);
}

static void testResourceSnapshotNeedsAdvanceAtEveryGate()
{
    Identity i = identity();
    Authority a = authority(i);
    PreparedResources r = resources(i);
    Candidate c(Role::Directed149Reply);
    assert(getToAwaitRequest(c, i, a, r).accepted);
    assert(admit(c, i, a).accepted);
    assert(queue(c, i, a).accepted);
    TxPermit permit;
    Decision d = c.reservePermit(55, r, a, &permit);
    assert(!d.accepted && d.reason == Reason::ResourceEvidenceStale);
    assert(c.reservePermit(55, freshResources(r, 11), a, &permit).accepted);
    d = c.markDoorbell(permit, freshResources(r, 11), a);
    assert(!d.accepted && d.reason == Reason::ResourceEvidenceStale);
    assert(d.stage == Stage::Quarantined && c.snapshot().doorbellCount == 0);
}

static void testHighWaterAtUint64LimitAndInvalidCompletionStatus()
{
    Identity i = identity(UINT64_MAX, UINT64_MAX);
    Authority a = authority(i);
    Candidate last(Role::Directed149Reply, UINT64_MAX - 1, UINT64_MAX - 1);
    assert(armCandidate(last, i, a).accepted);
    Candidate exhausted(Role::Directed149Reply, UINT64_MAX, UINT64_MAX);
    Decision d = armCandidate(exhausted, i, a);
    assert(!d.accepted && d.reason == Reason::StaleOwner);

    Identity j = identity();
    Authority b = authority(j);
    PreparedResources r = resources(j);
    Candidate c(Role::Directed149Reply);
    assert(getToAwaitRequest(c, j, b, r).accepted);
    assert(admit(c, j, b).accepted);
    assert(queue(c, j, b).accepted);
    TxPermit permit;
    assert(c.reservePermit(55, freshResources(r, 11), b, &permit).accepted);
    assert(c.markDoorbell(permit, freshResources(r, 12), b).accepted);
    TxCompletionEvidence unknown = completion(j, r);
    unknown.status = static_cast<CompletionStatus>(99);
    d = c.complete(permit, unknown, b);
    assert(!d.accepted && d.reason == Reason::CompletionUnknown);
    assert(d.stage == Stage::Quarantined);
}

static void testInvalidIdentityAndNonce()
{
    Identity i = identity();
    Authority a = authority(i);
    ArmIntent x = intent(i);
    Candidate wrongPort(Role::Directed149Reply);
    i.peerRequestPort = 1234;
    a = authority(i); x = intent(i);
    Decision d = wrongPort.arm(x, i, a);
    assert(!d.accepted && d.reason == Reason::InvalidIdentity);

    i = identity(); i.nonce = {};
    Candidate zeroNonce(Role::Directed149Reply);
    a = authority(i); x = intent(i);
    d = zeroNonce.arm(x, i, a);
    assert(!d.accepted && d.reason == Reason::InvalidIdentity);

    i = identity();
    const uint8_t marker[8] = {'T','0','8','6','R','X','0','1'};
    for (unsigned n = 0; n != 8; ++n) i.nonce.bytes[n] = marker[n];
    Candidate staleNonce(Role::Directed149Reply);
    a = authority(i); x = intent(i);
    d = staleNonce.arm(x, i, a);
    assert(!d.accepted && d.reason == Reason::InvalidIdentity);

    i = identity(); i.ownIpv6.bytes[15] ^= 1;
    Candidate nonAwdlAddress(Role::Directed149Reply);
    a = authority(i); x = intent(i);
    d = nonAwdlAddress.arm(x, i, a);
    assert(!d.accepted && d.reason == Reason::InvalidIdentity);
}
#endif

int main()
{
#if !ITL_NATIVE_AWDL_DIRECTED_REPLY_TX_25G332
    testCompileOffDefault();
#else
    testRoleAndArmGates();
    testActiveHappyPathLateEndAndIdempotentClose();
    testActiveVsPassiveAndNvmGates();
    testQueueAndMacResourceGates();
    testShadowProofAndReplyTupleAreOneShot();
    testRequestFailureAndStaleAuthorityRetire();
    testRunAndOwnerHighWaterRejectRevival();
    testFreshDoorbellResourceRecheckAndDeadline();
    testCompletionOrderingAndUnknownQuarantine();
    testCompletionTupleMismatchAndDuplicateSuccess();
    testDoorbellCloseAndCloseBeforeDoorbell();
    testPermitReplayAndUnknownBeforeDoorbell();
    testCloseBeforeDoorbellAndCompletionFailure();
    testEvidenceSerialAndClockHighWater();
    testResourceSnapshotNeedsAdvanceAtEveryGate();
    testHighWaterAtUint64LimitAndInvalidCompletionStatus();
    testInvalidIdentityAndNonce();
    puts("directed AWDL TX contract tests passed; model authorization is not hardware/RF proof");
#endif
    return 0;
}
