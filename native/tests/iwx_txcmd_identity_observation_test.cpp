#include "native/iwx_txcmd_identity_observation.hpp"

#include <cassert>
#include <cstdint>

static iwx_txcmd_identity_candidate candidate(uint32_t index,
                                               uint32_t sequenceControl)
{
    iwx_txcmd_identity_candidate value{};
    value.qid = 1;
    value.index = index;
    value.api_generation = 2;
    value.command_version = 7;
    value.frame_control = 0x4108;
    value.sequence_control = sequenceControl;
    value.command_flags = 0x5;
    value.offload_assist = 0x0c00;
    return value;
}

static void recordAll(iwx_txcmd_identity_scan &scan, uint32_t tail,
                      const uint32_t *seqs, uint32_t count)
{
    for (uint32_t i = 0; i < count; ++i) {
        auto value = candidate((tail + i) % scan.ring_count, seqs[i]);
        assert(iwx_txcmd_identity_scan_record(&scan, value.index, 1, &value));
    }
}

static void testExactUniqueJoinAndRawCommandFields()
{
    iwx_txcmd_identity_scan scan{};
    assert(iwx_txcmd_identity_scan_begin(&scan, 1, 1024, 80, 4, 84,
                                         0x4108, 0x0580));
    const uint32_t seqs[] = {0x0540, 0x0580, 0x05a0, 0x0600};
    recordAll(scan, 80, seqs, 4);
    assert(scan.status == IWX_TXCMD_IDENTITY_SCAN_COMPLETE);
    assert(scan.scanned_count == 4 && scan.candidate_count == 1);
    assert(iwx_txcmd_identity_scan_has_unique_candidate(&scan));
    assert(scan.first_candidate.index == 81);
    assert(scan.first_candidate.api_generation == 2);
    assert(scan.first_candidate.command_version == 7);
    assert(scan.first_candidate.command_flags == 0x5);
    assert(scan.first_candidate.offload_assist == 0x0c00);
}

static void testObservedPlus0x20DoesNotBecomeACommandMatch()
{
    iwx_txcmd_identity_scan scan{};
    assert(iwx_txcmd_identity_scan_begin(&scan, 1, 1024, 88, 3, 91,
                                         0x4108, 0x05a0));
    const uint32_t seqs[] = {0x0580, 0x0500, 0x0540};
    recordAll(scan, 88, seqs, 3);
    assert(scan.status == IWX_TXCMD_IDENTITY_SCAN_COMPLETE);
    assert(scan.candidate_count == 0);
    assert(!iwx_txcmd_identity_scan_has_unique_candidate(&scan));
}

static void testDuplicateCommandTupleRemainsAmbiguous()
{
    iwx_txcmd_identity_scan scan{};
    assert(iwx_txcmd_identity_scan_begin(&scan, 1, 16, 4, 4, 8,
                                         0x4108, 0x0580));
    const uint32_t seqs[] = {0x0580, 0x0580, 0x0600, 0x0640};
    recordAll(scan, 4, seqs, 4);
    assert(scan.status == IWX_TXCMD_IDENTITY_SCAN_COMPLETE);
    assert(scan.candidate_count == 2);
    assert(!iwx_txcmd_identity_scan_has_unique_candidate(&scan));
}

static void testAnyUnreadDescriptorInvalidatesUniqueness()
{
    iwx_txcmd_identity_scan scan{};
    assert(iwx_txcmd_identity_scan_begin(&scan, 1, 8, 6, 3, 1,
                                         0x4108, 0x0580));
    auto hit = candidate(6, 0x0580);
    auto other = candidate(0, 0x0600);
    assert(iwx_txcmd_identity_scan_record(&scan, 6, 1, &hit));
    assert(iwx_txcmd_identity_scan_record(&scan, 7, 0, nullptr));
    assert(iwx_txcmd_identity_scan_record(&scan, 0, 1, &other));
    assert(scan.status == IWX_TXCMD_IDENTITY_SCAN_INCOMPLETE);
    assert(scan.scanned_count == 3 && scan.candidate_count == 1);
    assert(!iwx_txcmd_identity_scan_has_unique_candidate(&scan));
}

static void testInvalidIntervalsAreRejected()
{
    iwx_txcmd_identity_scan scan{};
    assert(!iwx_txcmd_identity_scan_begin(&scan, 1, 1024, 0, 0, 1,
                                          0x4108, 0x0580));
    assert(!iwx_txcmd_identity_scan_begin(&scan, 1, 1024, 1024, 1, 1,
                                          0x4108, 0x0580));
    assert(!iwx_txcmd_identity_scan_begin(&scan, 1, 2048, 0, 1, 1,
                                          0x4108, 0x0580));
    assert(!iwx_txcmd_identity_scan_begin(&scan, 1, 16, 0, 1, 1,
                                          0x10000, 0x0580));
}

int main()
{
    testExactUniqueJoinAndRawCommandFields();
    testObservedPlus0x20DoesNotBecomeACommandMatch();
    testDuplicateCommandTupleRemainsAmbiguous();
    testAnyUnreadDescriptorInvalidatesUniqueness();
    testInvalidIntervalsAreRejected();
}
