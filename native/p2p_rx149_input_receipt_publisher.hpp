// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_P2P_RX149_INPUT_RECEIPT_PUBLISHER_HPP
#define NATIVE_P2P_RX149_INPUT_RECEIPT_PUBLISHER_HPP

#include "awdl_native_bsd_data_25G332.hpp"
#include <stdint.h>

namespace NativeAwdlBSD {

// Publishes one latest-MPDU receipt through an IORegistry-style numeric
// writer. The callbacks keep the publication protocol host-testable while
// using the same code in the driver and sanitizer harness.
class Rx149InputReceiptPublisher {
public:
    template <typename Reader, typename Writer>
    bool publish(const Rx149InputReceipt &receipt,
                 Reader readNumber, Writer writeNumber) {
        if (receipt.schemaVersion != 2 || receipt.contentRevision == 0)
            return false;

        uint64_t priorSchema = 0;
        uint64_t priorRevision = 0;
        uint64_t priorBegin = 0;
        uint64_t priorEnd = 0;
        const bool hasSchema = readNumber(
            "NativeAwdlDataRx149ReceiptSchemaVersion", &priorSchema);
        const bool hasRevision = readNumber(
            "NativeAwdlDataRx149ReceiptContentRevision", &priorRevision);
        const bool hasBegin = readNumber(
            "NativeAwdlDataRx149ReceiptSnapshotBegin", &priorBegin);
        const bool hasEnd = readNumber(
            "NativeAwdlDataRx149ReceiptSnapshotEnd", &priorEnd);
        const bool priorComplete = hasSchema && hasRevision && hasBegin &&
            hasEnd && priorSchema == 2 && priorBegin != 0 &&
            priorBegin == priorEnd && (priorBegin & 1u) == 0;
        if (priorComplete && priorRevision == receipt.contentRevision) {
            if (priorEnd > publicationVersion_)
                publicationVersion_ = priorEnd;
            return true;
        }

        uint64_t base = publicationVersion_;
        if (hasBegin && priorBegin > base)
            base = priorBegin;
        if (hasEnd && priorEnd > base)
            base = priorEnd;
        if (base & 1u) {
            if (base == UINT64_MAX)
                return false;
            ++base;
        }
        if (base > UINT64_MAX - 2)
            return false;
        const uint64_t begin = base + 1; // odd: invalidate old snapshot
        const uint64_t end = base + 2;   // even: commit after payload

        if (!writeNumber("NativeAwdlDataRx149ReceiptSnapshotBegin",
                         begin, 64))
            return false;

#define RX149_WRITE32(name, value) \
        do { if (!writeNumber(name, static_cast<uint64_t>(value), 32)) \
            return false; } while (0)
#define RX149_WRITE64(name, value) \
        do { if (!writeNumber(name, static_cast<uint64_t>(value), 64)) \
            return false; } while (0)
        RX149_WRITE32("NativeAwdlDataRx149ReceiptSchemaVersion",
                      receipt.schemaVersion);
        RX149_WRITE64("NativeAwdlDataRx149ReceiptContentRevision",
                      receipt.contentRevision);
        RX149_WRITE32("NativeAwdlDataRx149ReceiptDisposition",
                      receipt.disposition);
        RX149_WRITE64("NativeAwdlDataRx149ReceiptSequence",
                      receipt.sequence);
        RX149_WRITE64("NativeAwdlDataRx149ReceiptOwnerSerial",
                      receipt.ownerSerial);
        RX149_WRITE64("NativeAwdlDataRx149ReceiptInterfaceIncarnation",
                      receipt.interfaceIncarnation);
        RX149_WRITE32("NativeAwdlDataRx149ReceiptContextGeneration",
                      receipt.contextGeneration);
        RX149_WRITE32("NativeAwdlDataRx149ReceiptPowerGeneration",
                      receipt.powerGeneration);
        RX149_WRITE32("NativeAwdlDataRx149ReceiptStationGeneration",
                      receipt.stationGeneration);
        RX149_WRITE32("NativeAwdlDataRx149ReceiptRocGeneration",
                      receipt.rocGeneration);
        RX149_WRITE64("NativeAwdlDataRx149ReceiptCaptureMonotonicUs",
                      receipt.captureUs);
        RX149_WRITE64("NativeAwdlDataRx149ReceiptInputMonotonicUs",
                      receipt.inputUs);
        RX149_WRITE64("NativeAwdlDataRx149ReceiptDeadlineMonotonicUs",
                      receipt.deadlineUs);
        RX149_WRITE32("NativeAwdlDataRx149ReceiptIeeeChannel",
                      receipt.ieeeChannel);
        RX149_WRITE32("NativeAwdlDataRx149ReceiptMacIndexPresent",
                      receipt.macIndexPresent);
        RX149_WRITE32("NativeAwdlDataRx149ReceiptMacIndex",
                      receipt.macIndex);
        RX149_WRITE32("NativeAwdlDataRx149ReceiptMacPhyDecodeMode",
                      receipt.macPhyDecodeMode);
        RX149_WRITE32("NativeAwdlDataRx149ReceiptOriginalRxStatus",
                      receipt.originalRxStatus);
        RX149_WRITE32("NativeAwdlDataRx149ReceiptMpduLength",
                      receipt.mpduLength);
        RX149_WRITE32("NativeAwdlDataRx149ReceiptDecodedIpv6Count",
                      receipt.decodedIpv6Count);
        RX149_WRITE32("NativeAwdlDataRx149ReceiptIfnetInputResultPresent",
                      receipt.ifnetInputResultPresent);
        RX149_WRITE32("NativeAwdlDataRx149ReceiptIfnetInputResult",
                      static_cast<uint32_t>(receipt.ifnetInputResult));
#undef RX149_WRITE32
#undef RX149_WRITE64

        // End is published while Begin is still odd. Only the final matching
        // even Begin makes a reader's snapshot complete.
        if (!writeNumber("NativeAwdlDataRx149ReceiptSnapshotEnd", end, 64) ||
            !writeNumber("NativeAwdlDataRx149ReceiptSnapshotBegin", end, 64))
            return false;
        publicationVersion_ = end;
        return true;
    }

private:
    uint64_t publicationVersion_ = 0;
};

} // namespace NativeAwdlBSD

#endif // NATIVE_P2P_RX149_INPUT_RECEIPT_PUBLISHER_HPP
