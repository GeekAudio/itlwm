#include <cassert>
#include <cstdint>

#include "../iwx_fw_diagnostics.hpp"

using namespace IwxFirmwareDiagnostics;

int main()
{
    // Model the observed race: the ADD_STA_KEY submission belongs to
    // generation 11, then recovery advances the live driver to generation 12
    // before the phase-14/15 rows are published.
    Entry commandSubmitted{};
    commandSubmitted.phase = static_cast<uint32_t>(Phase::CommandSubmitted);
    applyMetadataGeneration(&commandSubmitted, 11U, 11U, 11U);
    assert(commandSubmitted.driver_generation == 11U);
    assert(commandSubmitted.firmware_generation == 11U);

    Entry rxSequence{};
    rxSequence.phase = static_cast<uint32_t>(Phase::KeyRxSequenceSubmitted);
    rxSequence.driver_generation = commandSubmitted.driver_generation;
    rxSequence.flags = kOriginGenerationPresent | kKeySequenceValuePresent;
    // Inject the generation transition at the precise interval between the
    // submit row and sequence-row publication.
    applyMetadataGeneration(&rxSequence, 12U, 12U, 12U);
    assert(rxSequence.driver_generation == 11U);
    assert(rxSequence.firmware_generation == 0U);
    assert((rxSequence.flags & kOriginGenerationPresent) != 0U);
    assert((rxSequence.flags & kOriginGenerationChangedBeforeRecord) != 0U);
    assert((rxSequence.flags & kFirmwareStateKnown) == 0U);

    Entry transitionDuringRecord{};
    transitionDuringRecord.phase =
        static_cast<uint32_t>(Phase::KeyRxSequenceSubmitted);
    transitionDuringRecord.driver_generation = 11U;
    transitionDuringRecord.flags = kOriginGenerationPresent |
        kKeySequenceValuePresent;
    // A second atomic generation sample detects a reset that starts while
    // the recorder is reading current generation and firmware-alive state.
    applyMetadataGeneration(&transitionDuringRecord, 11U, 11U, 12U);
    assert(transitionDuringRecord.driver_generation == 11U);
    assert(transitionDuringRecord.firmware_generation == 0U);
    assert((transitionDuringRecord.flags &
            kOriginGenerationChangedBeforeRecord) != 0U);
    assert((transitionDuringRecord.flags & kFirmwareStateKnown) == 0U);

    Entry txSequence{};
    txSequence.phase = static_cast<uint32_t>(Phase::KeyTxSequenceSubmitted);
    txSequence.driver_generation = 12U;
    txSequence.flags = kOriginGenerationPresent | kKeySequenceValuePresent;
    applyMetadataGeneration(&txSequence, 12U, 12U, 12U);
    assert(txSequence.driver_generation == 12U);
    assert(txSequence.firmware_generation == 12U);
    assert((txSequence.flags & kFirmwareStateKnown) != 0U);
    assert((txSequence.flags & kOriginGenerationChangedBeforeRecord) == 0U);

    Entry unavailable{};
    unavailable.phase = static_cast<uint32_t>(Phase::KeySequenceUnavailable);
    // A missing origin must stay unknown; it must not inherit current gen 12.
    applyMetadataGeneration(&unavailable, 12U, 12U, 12U);
    assert(unavailable.driver_generation == 0U);
    assert(unavailable.firmware_generation == 0U);
    assert((unavailable.flags & kFirmwareStateKnown) == 0U);

    Entry ordinary{};
    ordinary.phase = static_cast<uint32_t>(Phase::RxValidated);
    ordinary.driver_generation = 99U;
    applyMetadataGeneration(&ordinary, 12U, 12U, 12U);
    assert(ordinary.driver_generation == 12U);
    assert(ordinary.firmware_generation == 12U);
    assert((ordinary.flags & kFirmwareStateKnown) != 0U);
    return 0;
}
