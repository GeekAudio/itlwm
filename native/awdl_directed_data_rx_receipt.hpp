// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stdint.h>

namespace NativeAwdlBSD {

enum DirectedDataRxInputDisposition : uint32_t {
    DirectedDataRxReceiptNone=0,
    DirectedDataRxReceiptCaptured=1,
    DirectedDataRxReceiptStaleOrInvalid=2,
    DirectedDataRxReceiptDecodeRejected=3,
    DirectedDataRxReceiptAddressRejected=4,
    DirectedDataRxReceiptMbufAllocationFailed=5,
    DirectedDataRxReceiptIfnetInputSucceeded=6,
    DirectedDataRxReceiptIfnetInputFailed=7,
    DirectedDataRxReceiptQueueFull=8
};

// Payload-free local bridge receipt for the exact mode-4/channel-6 owner.
// A successful DLIL result proves only local input, never RF ACK or AirDrop.
struct DirectedDataRxInputReceipt {
    uint32_t schemaVersion=1;
    uint32_t disposition=DirectedDataRxReceiptNone;
    uint64_t sequence=0;
    uint64_t contentRevision=0;
    uint64_t ownerSerial=0;
    uint64_t interfaceIncarnation=0;
    uint32_t contextGeneration=0;
    uint32_t powerGeneration=0;
    uint32_t stationGeneration=0;
    uint32_t rocGeneration=0;
    uint64_t captureUs=0;
    uint64_t inputUs=0;
    uint64_t startUs=0;
    uint64_t deadlineUs=0;
    uint32_t ieeeChannel=0;
    uint32_t macIndexPresent=1;
    uint32_t macIndex=0;
    uint32_t macPhyDecodeMode=0;
    uint32_t originalRxStatus=0;
    uint32_t mpduLength=0;
    uint32_t decodedIpv6Count=0;
    uint32_t ifnetInputResultPresent=0;
    int32_t ifnetInputResult=0;
};

} // namespace NativeAwdlBSD
