#include "native/iwx_tx_queue_observation.hpp"

#include <cassert>
#include <atomic>
#include <cstdint>
#include <limits>
#include <memory>
#include <thread>

using namespace IwxTxQueueObservation;

static std::unique_ptr<iwx_tx_queue_observation_state> newState()
{
    auto state = std::unique_ptr<iwx_tx_queue_observation_state>(
        new iwx_tx_queue_observation_state);
    initialize(state.get());
    return state;
}

static iwx_txq_obs_input configInput(uint64_t now, uint32_t epoch,
                                    uint32_t cur = 0, uint32_t tail = 0,
                                    uint32_t queued = 0)
{
    iwx_txq_obs_input input{};
    input.presence_flags = IWX_TXQ_OBS_HAS_TIME |
        IWX_TXQ_OBS_HAS_EPOCH | IWX_TXQ_OBS_HAS_OWNER |
        IWX_TXQ_OBS_HAS_STATION_ID | IWX_TXQ_OBS_HAS_STATION_COLOR |
        IWX_TXQ_OBS_HAS_QUEUE_TID | IWX_TXQ_OBS_HAS_RING_COUNT |
        IWX_TXQ_OBS_HAS_QUEUED | IWX_TXQ_OBS_HAS_CUR |
        IWX_TXQ_OBS_HAS_TAIL;
    input.owner = IWX_TXQ_OBS_OWNER_STA;
    input.station_id = 0;
    input.station_color = 17;
    input.queue_tid = 15;
    input.ring_count = 256;
    input.queued = queued;
    input.cur = cur;
    input.tail = tail;
    input.output_epoch = epoch;
    input.monotonic_ns = now;
    return input;
}

static uint64_t configure(iwx_tx_queue_observation_state *state,
                          uint32_t qid, uint64_t now, uint32_t epoch,
                          uint32_t cur = 0, uint32_t tail = 0,
                          uint32_t queued = 0)
{
    auto input = configInput(now, epoch, cur, tail, queued);
    const uint64_t attempt = beginConfig(state, qid, &input);
    assert(attempt != 0);
    assert(finishConfig(state, attempt, qid,
                        IWX_TXQ_OBS_CONFIG_ACK_COMMITTED, &input));
    return attempt;
}

static iwx_txq_obs_input submitInput(uint64_t now, uint32_t epoch,
                                    uint32_t index, uint32_t queued,
                                    uint32_t cur, uint32_t tail)
{
    iwx_txq_obs_input input{};
    input.presence_flags = IWX_TXQ_OBS_HAS_TIME |
        IWX_TXQ_OBS_HAS_EPOCH | IWX_TXQ_OBS_HAS_RING_COUNT |
        IWX_TXQ_OBS_HAS_QUEUED | IWX_TXQ_OBS_HAS_CUR |
        IWX_TXQ_OBS_HAS_TAIL | IWX_TXQ_OBS_HAS_DESCRIPTOR_INDEX |
        IWX_TXQ_OBS_HAS_FRAME_CONTROL;
    input.ring_count = 256;
    input.queued = queued;
    input.cur = cur;
    input.tail = tail;
    input.descriptor_index = index;
    input.frame_control = 0x0088; // QoS data; no addresses or payload retained.
    input.output_epoch = epoch;
    input.monotonic_ns = now;
    return input;
}

static void testSameEpochResetGetsANewIncarnationAndCannotLookLikeWrap()
{
    auto state = newState();
    configure(state.get(), 1, 100, 5, 35, 35, 0);
    auto reclaim = configInput(110, 5, 35, 35, 0);
    assert(recordRingSample(state.get(), 1, 5, IWX_TXQ_OBS_OP_RECLAIM,
                            &reclaim));
    // Expiry snapshots are anchored only by a real submit/doorbell or its
    // exact timer-arm token. A reclaim event alone must not pick a qid.
    auto observedSubmit = submitInput(110, 5, 35, 1, 35, 35);
    const uint64_t observedToken =
        recordSubmit(state.get(), 1, &observedSubmit);
    assert(observedToken != 0);
    assert(recordArm(state.get(), 5, observedToken, 111));
    iwx_txq_obs_snapshot before{};
    assert(snapshot(state.get(), 112, &before));
    assert(before.queue_known == 1);
    assert(before.queue.incarnation == 1);
    assert(before.queue.tail == 35 && before.queue.cur == 35);

    // AUTH re-entry re-enables the same qid in the same device epoch.
    const auto reset = configInput(120, 5, 35, 35, 0);
    assert(recordReset(state.get(), 1, 0xA17, &reset));
    iwx_txq_obs_snapshot afterReset{};
    assert(snapshot(state.get(), 121, &afterReset));
    assert(afterReset.queue_known == 0);
    assert(afterReset.queue.incarnation == before.queue.incarnation + 1);
    assert(afterReset.queue.reset_tail == 35);
    assert((afterReset.queue.presence_flags &
            IWX_TXQ_OBS_HAS_RESET_SAMPLE) != 0);

    configure(state.get(), 1, 130, 5, 0, 0, 0);
    auto submit = submitInput(131, 5, 0, 1, 1, 0);
    const uint64_t token = recordSubmit(state.get(), 1, &submit);
    assert(token != 0);
    assert(recordArm(state.get(), 5, token, 132));
    iwx_txq_obs_snapshot final{};
    assert(snapshot(state.get(), 133, &final));
    assert(final.complete == 1 && final.queue_known == 1);
    assert(final.queue.output_epoch == 5);
    assert(final.queue.incarnation > before.queue.incarnation);
    assert(final.queue.cur == 1 && final.queue.tail == 0);
    assert(final.queue.last_submit_index == 0);
    assert(final.arm_binding_known == 1);
    assert(final.arm.submit_serial == token && final.arm.qid == 1);
}

static void testConfigAttemptIsBoundToThePerQueueMutation()
{
    auto state = newState();
    auto input = configInput(150, 5);
    const uint64_t attempt = beginConfig(state.get(), 4, &input);
    assert(attempt != 0);
    const auto &queue = state->queues[4];
    assert(queue.config_attempt_serial == attempt);
    assert(queue.config_begin_mutation_serial ==
        __atomic_load_n(&state->queue_mutation_serial[4], __ATOMIC_ACQUIRE));
    assert(finishConfig(state.get(), attempt, 4,
                        IWX_TXQ_OBS_CONFIG_ACK_COMMITTED, &input));

    // The next reset advances the mutation and incarnation even when the
    // output epoch is unchanged; the former config token cannot revive it.
    const auto reset = configInput(151, 5);
    const uint64_t staleAttempt = beginConfig(state.get(), 4, &input);
    assert(staleAttempt != 0);
    assert(recordReset(state.get(), 4, 0xA16, &reset));
    assert(state->queues[4].incarnation >= 2);
    assert(!finishConfig(state.get(), staleAttempt, 4,
                         IWX_TXQ_OBS_CONFIG_ACK_COMMITTED, &input));
}

static void testDoorbellThenResetInvalidatesTimerTupleAndPendingConfig()
{
    auto state = newState();
    configure(state.get(), 1, 200, 7);
    auto submit = submitInput(210, 7, 12, 1, 13, 12);
    const uint64_t token = recordSubmit(state.get(), 1, &submit);
    assert(token != 0 && recordArm(state.get(), 7, token, 211));

    // Reset after the new submit but before TX_RSP/timer-clear must revoke the
    // binding, and it must also make an in-flight old config attempt stale.
    auto config = configInput(220, 7);
    const uint64_t attempt = beginConfig(state.get(), 1, &config);
    assert(attempt != 0);
    assert(recordReset(state.get(), 1, 0xA18, &config));
    assert(!finishConfig(state.get(), attempt, 1,
                         IWX_TXQ_OBS_CONFIG_ACK_COMMITTED, &config));
    assert(!recordArm(state.get(), 7, token, 221));

    iwx_txq_obs_snapshot sample{};
    assert(snapshot(state.get(), 222, &sample));
    assert(sample.arm_binding_known == 0);
    assert(sample.queue_known == 0);
    assert(sample.complete == 0);
    assert((sample.queue.presence_flags &
            IWX_TXQ_OBS_HAS_INCARNATION) == 0);
}

static void testCommittedMutationVersionBlocksLateInvalidationIdentity()
{
    constexpr uint32_t qid = 19;

    // Simulate the late-invalidation race: an invalidator advances the
    // lockless qid version, then a racing config completion leaves valid=1.
    // The old committed version must still prevent reclaim/submit/arm/expiry
    // from treating this ACTIVE-looking row as the same host identity.
    auto sampleState = newState();
    configure(sampleState.get(), qid, 230, 8);
    const uint64_t sampleVersion = __atomic_load_n(
        &sampleState->queue_mutation_serial[qid], __ATOMIC_ACQUIRE);
    assert(sampleState->queues[qid].committed_mutation_serial == sampleVersion);
    __atomic_add_fetch(&sampleState->queue_mutation_serial[qid], 1ULL,
                       __ATOMIC_ACQ_REL);
    __atomic_store_n(&sampleState->queue_valid[qid], 1U, __ATOMIC_RELEASE);
    assert(sampleState->queues[qid].phase == IWX_TXQ_OBS_PHASE_ACTIVE);
    auto reclaim = configInput(231, 8);
    assert(!recordRingSample(sampleState.get(), qid, 8,
                             IWX_TXQ_OBS_OP_RECLAIM, &reclaim));

    auto submitState = newState();
    configure(submitState.get(), qid, 240, 8);
    const uint64_t submitVersion = __atomic_load_n(
        &submitState->queue_mutation_serial[qid], __ATOMIC_ACQUIRE);
    __atomic_add_fetch(&submitState->queue_mutation_serial[qid], 1ULL,
                       __ATOMIC_ACQ_REL);
    __atomic_store_n(&submitState->queue_valid[qid], 1U, __ATOMIC_RELEASE);
    auto submit = submitInput(241, 8, 3, 1, 4, 3);
    assert(recordSubmit(submitState.get(), qid, &submit) == 0);
    assert(submitState->queues[qid].committed_mutation_serial == submitVersion);

    auto armState = newState();
    configure(armState.get(), qid, 250, 8);
    auto armSubmit = submitInput(251, 8, 4, 1, 5, 4);
    const uint64_t token = recordSubmit(armState.get(), qid, &armSubmit);
    assert(token != 0);
    const uint64_t armVersion = __atomic_load_n(
        &armState->queue_mutation_serial[qid], __ATOMIC_ACQUIRE);
    assert(armState->queues[qid].committed_mutation_serial == armVersion);
    __atomic_add_fetch(&armState->queue_mutation_serial[qid], 1ULL,
                       __ATOMIC_ACQ_REL);
    __atomic_store_n(&armState->queue_valid[qid], 1U, __ATOMIC_RELEASE);
    assert(!recordArm(armState.get(), 8, token, 252));

    auto snapshotState = newState();
    configure(snapshotState.get(), qid, 260, 8);
    auto snapshotSubmit = submitInput(261, 8, 5, 1, 6, 5);
    const uint64_t snapshotToken = recordSubmit(
        snapshotState.get(), qid, &snapshotSubmit);
    assert(snapshotToken != 0);
    assert(recordArm(snapshotState.get(), 8, snapshotToken, 262));
    const uint64_t snapshotVersion = __atomic_load_n(
        &snapshotState->queue_mutation_serial[qid], __ATOMIC_ACQUIRE);
    __atomic_add_fetch(&snapshotState->queue_mutation_serial[qid], 1ULL,
                       __ATOMIC_ACQ_REL);
    __atomic_store_n(&snapshotState->queue_valid[qid], 1U, __ATOMIC_RELEASE);
    iwx_txq_obs_snapshot sample{};
    assert(snapshot(snapshotState.get(), 263, &sample));
    assert(sample.complete == 1); // Collector is complete; identity is not.
    assert(sample.selected_qid == qid);
    assert(sample.queue_known == 0);
    assert(sample.queue.committed_mutation_serial == snapshotVersion);
}

static void testStickyIncompleteRejectsKnownLookingQueueIdentity()
{
    constexpr uint32_t qid = 20;
    auto state = newState();
    configure(state.get(), qid, 270, 9);
    auto submit = submitInput(271, 9, 6, 1, 7, 6);
    const uint64_t token = recordSubmit(state.get(), qid, &submit);
    assert(token != 0);
    assert(recordArm(state.get(), 9, token, 272));

    noteDrop(state.get());
    auto reclaim = configInput(273, 9);
    assert(!recordRingSample(state.get(), qid, 9,
                             IWX_TXQ_OBS_OP_RECLAIM, &reclaim));
    auto nextSubmit = submitInput(274, 9, 7, 1, 8, 7);
    assert(recordSubmit(state.get(), qid, &nextSubmit) == 0);
    assert(!recordArm(state.get(), 9, token, 275));

    iwx_txq_obs_snapshot sample{};
    assert(snapshot(state.get(), 276, &sample));
    assert(sample.complete == 0);
    assert(sample.queue_known == 0);
    assert(sample.selected_qid == qid);
}

static void testFailedConfigInvalidatesOldIncarnation()
{
    auto state = newState();
    configure(state.get(), 3, 300, 9);
    auto input = configInput(310, 9);
    const uint64_t attempt = beginConfig(state.get(), 3, &input);
    assert(attempt != 0);
    assert(finishConfig(state.get(), attempt, 3,
                        IWX_TXQ_OBS_CONFIG_OUTCOME_UNKNOWN, &input));
    iwx_txq_obs_snapshot sample{};
    assert(snapshot(state.get(), 311, &sample));
    assert(sample.queue_known == 0 && sample.complete == 0);
    auto submit = submitInput(312, 9, 0, 1, 1, 0);
    assert(recordSubmit(state.get(), 3, &submit) == 0);
}

static void testUnknownTvqmRequestResolvesWithoutPermanentIncomplete()
{
    auto state = newState();
    auto input = configInput(400, 11);
    const uint64_t attempt = beginConfig(state.get(),
        IWX_TXQ_OBS_UNKNOWN_QID, &input);
    assert(attempt != 0);
    assert(prepareReplacement(state.get(), attempt, 255));
    iwx_txq_obs_snapshot pending{};
    assert(snapshot(state.get(), 401, &pending));
    assert(pending.complete == 0);

    auto reset = configInput(405, 11);
    auto free = configInput(407, 11);
    assert(recordReset(state.get(), 255, IWX_TXQ_OBS_OP_RESET, &reset));
    assert(recordFree(state.get(), 255, IWX_TXQ_OBS_OP_FREE, &free));
    auto resolved = configInput(410, 11);
    assert(finishConfig(state.get(), attempt, 255,
                        IWX_TXQ_OBS_CONFIG_ACK_COMMITTED, &resolved));
    iwx_txq_obs_snapshot active{};
    assert(snapshot(state.get(), 411, &active));
    // A committed config identity is not itself a TX doorbell. The observer
    // reports the resolved config qid without treating its ring shadow as an
    // expiry target until a submit/arm supplies that anchor.
    assert(active.complete == 1 && active.queue_known == 0);
    assert(active.selected_qid == IWX_TXQ_OBS_UNKNOWN_QID);
    assert(active.latest_config_resolved_qid == 255);

    // A missing prepare token cannot commit a firmware-assigned qid.
    auto state2 = newState();
    const uint64_t attempt2 = beginConfig(state2.get(),
        IWX_TXQ_OBS_UNKNOWN_QID, &input);
    assert(!finishConfig(state2.get(), attempt2, 10,
                         IWX_TXQ_OBS_CONFIG_ACK_COMMITTED, &resolved));
    iwx_txq_obs_snapshot stale{};
    assert(snapshot(state2.get(), 412, &stale));
    assert(stale.complete == 0 && stale.queue_known == 0);

    // The exact target reset->free sequence is mandatory; a third mutation
    // on another qid makes the global replacement window ambiguous.
    auto state3 = newState();
    const uint64_t attempt3 = beginConfig(state3.get(),
        IWX_TXQ_OBS_UNKNOWN_QID, &input);
    assert(prepareReplacement(state3.get(), attempt3, 10));
    assert(recordReset(state3.get(), 10, IWX_TXQ_OBS_OP_RESET, &reset));
    assert(recordFree(state3.get(), 10, IWX_TXQ_OBS_OP_FREE, &free));
    assert(recordReset(state3.get(), 9, IWX_TXQ_OBS_OP_RESET, &reset));
    assert(!finishConfig(state3.get(), attempt3, 10,
                         IWX_TXQ_OBS_CONFIG_ACK_COMMITTED, &resolved));
    iwx_txq_obs_snapshot extraMutation{};
    assert(snapshot(state3.get(), 413, &extraMutation));
    assert(extraMutation.complete == 0 && extraMutation.queue_known == 0);

    // Reset without the matching free is also not a committed replacement.
    auto state4 = newState();
    const uint64_t attempt4 = beginConfig(state4.get(),
        IWX_TXQ_OBS_UNKNOWN_QID, &input);
    assert(prepareReplacement(state4.get(), attempt4, 11));
    assert(recordReset(state4.get(), 11, IWX_TXQ_OBS_OP_RESET, &reset));
    assert(!finishConfig(state4.get(), attempt4, 11,
                         IWX_TXQ_OBS_CONFIG_ACK_COMMITTED, &resolved));
    iwx_txq_obs_snapshot partial{};
    assert(snapshot(state4.get(), 414, &partial));
    assert(partial.complete == 0 && partial.queue_known == 0);
}

static void testMissingOptionalQoSTidAndSequenceRemainPresenceUnknown()
{
    auto state = newState();
    configure(state.get(), 1, 500, 13);
    // Control/non-QoS frames do not have QoS TID or ordinary sequence-control
    // fields. Absence is recorded as absence; it does not invalidate the token.
    auto input = submitInput(510, 13, 4, 1, 5, 4);
    const uint64_t token = recordSubmit(state.get(), 1, &input);
    assert(token != 0);
    assert(recordArm(state.get(), 13, token, 511));
    iwx_txq_obs_snapshot sample{};
    assert(snapshot(state.get(), 512, &sample));
    assert(sample.complete == 1 && sample.arm_binding_known == 1);
    assert((sample.queue.submit_presence_flags &
            IWX_TXQ_OBS_HAS_PACKET_TID) == 0);
    assert((sample.queue.submit_presence_flags &
            IWX_TXQ_OBS_HAS_SEQUENCE_CONTROL) == 0);
}

static void testSnapshotDoesNotFallBackToConfigOrResetActivity()
{
    auto state = newState();
    configure(state.get(), 18, 530, 15);

    // A configured queue is not an expiry target until there was a real
    // doorbell/submit or an exact timer-arm binding for it.
    iwx_txq_obs_snapshot sample{};
    assert(snapshot(state.get(), 531, &sample));
    assert(sample.available == 1);
    assert(sample.selected_qid == IWX_TXQ_OBS_UNKNOWN_QID);
    assert(sample.selected_reason == 0);
    assert(sample.queue_known == 0);
}

static void testLockContentionFailsClosedWithoutRestoringOldIdentity()
{
    auto state = newState();
    configure(state.get(), 6, 600, 21);
    __atomic_store_n(&state->lock, 1U, __ATOMIC_RELEASE);
    auto input = configInput(610, 21);
    assert(beginConfig(state.get(), 6, &input) == 0);
    __atomic_store_n(&state->lock, 0U, __ATOMIC_RELEASE);

    iwx_txq_obs_snapshot sample{};
    assert(snapshot(state.get(), 611, &sample));
    assert(sample.complete == 0 && sample.queue_known == 0);
    assert(sample.dropped_count == 1);
    assert((sample.queue.presence_flags &
            IWX_TXQ_OBS_HAS_INCARNATION) == 0);
}

static void testResetAndFreeLockFailureInvalidateIdentity()
{
    auto state = newState();
    configure(state.get(), 12, 650, 21);
    const uint64_t incarnation = state->queues[12].incarnation;

    __atomic_store_n(&state->lock, 1U, __ATOMIC_RELEASE);
    auto input = configInput(651, 21);
    assert(!recordReset(state.get(), 12, 0xA20, &input));
    assert(__atomic_load_n(&state->queue_valid[12], __ATOMIC_ACQUIRE) == 0);
    __atomic_store_n(&state->lock, 0U, __ATOMIC_RELEASE);
    iwx_txq_obs_snapshot afterReset{};
    assert(snapshot(state.get(), 652, &afterReset));
    assert(afterReset.complete == 0 && afterReset.queue_known == 0);
    assert(afterReset.selected_qid == IWX_TXQ_OBS_UNKNOWN_QID);
    assert(state->queues[12].incarnation == incarnation);

    // Reconfigure the observed identity, then make sure a failed free record
    // also fails closed without advertising the now-retired incarnation.
    configure(state.get(), 12, 653, 21);
    __atomic_store_n(&state->lock, 1U, __ATOMIC_RELEASE);
    assert(!recordFree(state.get(), 12, 0xA21, &input));
    assert(__atomic_load_n(&state->queue_valid[12], __ATOMIC_ACQUIRE) == 0);
    __atomic_store_n(&state->lock, 0U, __ATOMIC_RELEASE);
    iwx_txq_obs_snapshot afterFree{};
    assert(snapshot(state.get(), 654, &afterFree));
    assert(afterFree.complete == 0 && afterFree.queue_known == 0);
    assert((afterFree.queue.presence_flags &
            IWX_TXQ_OBS_HAS_INCARNATION) == 0);
}

static void testSubmitSerialSaturationAndNewStateLifecycle()
{
    auto state = newState();
    configure(state.get(), 8, 700, 22);
    state->next_submit_serial = std::numeric_limits<uint64_t>::max();
    auto submit = submitInput(710, 22, 2, 1, 3, 2);
    assert(recordSubmit(state.get(), 8, &submit) == 0);

    const uint64_t task = beginNewState(state.get(), 2, 2, 44, 22, true, 720);
    assert(task != 0);
    assert(endNewState(state.get(), task, 0, 730));
    iwx_txq_obs_snapshot sample{};
    assert(snapshot(state.get(), 731, &sample));
    assert(sample.complete == 0); // Serial saturation is sticky.
    assert(sample.newstate.token == task);
    assert(sample.newstate.old_state == 2 && sample.newstate.target_state == 2);
    assert(sample.newstate.task_generation == 44);
    assert(sample.newstate.driver_generation == 22);
    assert(sample.newstate.repeated_auth == 1);
    assert(sample.newstate.terminal_reason == 0);
}

static void testConcurrentInvalidationAndSnapshotTryLockStress()
{
    auto state = newState();
    configure(state.get(), 13, 800, 31);
    std::atomic<bool> start{false};
    auto resetInput = configInput(810, 31);
    auto freeInput = configInput(811, 31);

    std::thread resetter([&]() {
        while (!start.load(std::memory_order_acquire)) {}
        for (uint32_t i = 0; i < 5000; ++i)
            (void)recordReset(state.get(), 13, IWX_TXQ_OBS_OP_RESET,
                              &resetInput);
    });
    std::thread freer([&]() {
        while (!start.load(std::memory_order_acquire)) {}
        for (uint32_t i = 0; i < 5000; ++i)
            (void)recordFree(state.get(), 13, IWX_TXQ_OBS_OP_FREE,
                             &freeInput);
    });
    std::thread reader([&]() {
        while (!start.load(std::memory_order_acquire)) {}
        for (uint32_t i = 0; i < 5000; ++i) {
            iwx_txq_obs_snapshot sample{};
            (void)snapshot(state.get(), 812, &sample);
        }
    });
    start.store(true, std::memory_order_release);
    resetter.join();
    freer.join();
    reader.join();

    iwx_txq_obs_snapshot final{};
    assert(snapshot(state.get(), 813, &final));
    assert(final.queue_known == 0);
}

int main()
{
    static_assert(sizeof(iwx_txq_obs_snapshot) <= 1024,
                  "single-qid snapshot stays small");
    testSameEpochResetGetsANewIncarnationAndCannotLookLikeWrap();
    testConfigAttemptIsBoundToThePerQueueMutation();
    testDoorbellThenResetInvalidatesTimerTupleAndPendingConfig();
    testCommittedMutationVersionBlocksLateInvalidationIdentity();
    testStickyIncompleteRejectsKnownLookingQueueIdentity();
    testFailedConfigInvalidatesOldIncarnation();
    testUnknownTvqmRequestResolvesWithoutPermanentIncomplete();
    testMissingOptionalQoSTidAndSequenceRemainPresenceUnknown();
    testSnapshotDoesNotFallBackToConfigOrResetActivity();
    testLockContentionFailsClosedWithoutRestoringOldIdentity();
    testResetAndFreeLockFailureInvalidateIdentity();
    testSubmitSerialSaturationAndNewStateLifecycle();
    testConcurrentInvalidationAndSnapshotTryLockStress();
    return 0;
}
