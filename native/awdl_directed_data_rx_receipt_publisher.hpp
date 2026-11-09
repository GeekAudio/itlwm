// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include "awdl_directed_data_rx_receipt.hpp"
#include <stdint.h>

namespace NativeAwdlBSD {

class DirectedDataRxReceiptPublisher {
public:
    template <typename Reader,typename Writer>
    bool publish(const DirectedDataRxInputReceipt &receipt,
                 Reader readNumber,Writer writeNumber) {
        if(receipt.schemaVersion!=1||receipt.contentRevision==0)
            return false;
        uint64_t priorRevision=0,priorBegin=0,priorEnd=0;
        const bool hasRevision=readNumber(
            "NativeAwdlDataDirectedRxReceiptContentRevision",&priorRevision);
        const bool hasBegin=readNumber(
            "NativeAwdlDataDirectedRxReceiptSnapshotBegin",&priorBegin);
        const bool hasEnd=readNumber(
            "NativeAwdlDataDirectedRxReceiptSnapshotEnd",&priorEnd);
        const bool priorComplete=hasRevision&&hasBegin&&hasEnd&&
            priorBegin!=0&&priorBegin==priorEnd&&(priorBegin&1u)==0;
        if(priorComplete&&priorRevision==receipt.contentRevision) {
            if(priorEnd>publicationVersion_)
                publicationVersion_=priorEnd;
            return true;
        }
        uint64_t base=publicationVersion_;
        if(hasBegin&&priorBegin>base)base=priorBegin;
        if(hasEnd&&priorEnd>base)base=priorEnd;
        if(base&1u) {
            if(base==UINT64_MAX)return false;
            ++base;
        }
        if(base>UINT64_MAX-2u)return false;
        const uint64_t begin=base+1u;
        const uint64_t end=base+2u;
        if(!writeNumber("NativeAwdlDataDirectedRxReceiptSnapshotBegin",
                        begin,64))
            return false;
#define DIRECTED_RX_WRITE32(name,value) \
        do { if(!writeNumber(name,static_cast<uint64_t>(value),32)) \
            return false; } while(0)
#define DIRECTED_RX_WRITE64(name,value) \
        do { if(!writeNumber(name,static_cast<uint64_t>(value),64)) \
            return false; } while(0)
        DIRECTED_RX_WRITE32("NativeAwdlDataDirectedRxReceiptSchemaVersion",
                            receipt.schemaVersion);
        DIRECTED_RX_WRITE64("NativeAwdlDataDirectedRxReceiptContentRevision",
                            receipt.contentRevision);
        DIRECTED_RX_WRITE32("NativeAwdlDataDirectedRxReceiptDisposition",
                            receipt.disposition);
        DIRECTED_RX_WRITE64("NativeAwdlDataDirectedRxReceiptSequence",
                            receipt.sequence);
        DIRECTED_RX_WRITE64("NativeAwdlDataDirectedRxReceiptOwnerSerial",
                            receipt.ownerSerial);
        DIRECTED_RX_WRITE64("NativeAwdlDataDirectedRxReceiptInterfaceIncarnation",
                            receipt.interfaceIncarnation);
        DIRECTED_RX_WRITE32("NativeAwdlDataDirectedRxReceiptContextGeneration",
                            receipt.contextGeneration);
        DIRECTED_RX_WRITE32("NativeAwdlDataDirectedRxReceiptPowerGeneration",
                            receipt.powerGeneration);
        DIRECTED_RX_WRITE32("NativeAwdlDataDirectedRxReceiptStationGeneration",
                            receipt.stationGeneration);
        DIRECTED_RX_WRITE32("NativeAwdlDataDirectedRxReceiptRocGeneration",
                            receipt.rocGeneration);
        DIRECTED_RX_WRITE64("NativeAwdlDataDirectedRxReceiptCaptureMonotonicUs",
                            receipt.captureUs);
        DIRECTED_RX_WRITE64("NativeAwdlDataDirectedRxReceiptInputMonotonicUs",
                            receipt.inputUs);
        DIRECTED_RX_WRITE64("NativeAwdlDataDirectedRxReceiptStartMonotonicUs",
                            receipt.startUs);
        DIRECTED_RX_WRITE64("NativeAwdlDataDirectedRxReceiptDeadlineMonotonicUs",
                            receipt.deadlineUs);
        DIRECTED_RX_WRITE32("NativeAwdlDataDirectedRxReceiptIeeeChannel",
                            receipt.ieeeChannel);
        DIRECTED_RX_WRITE32("NativeAwdlDataDirectedRxReceiptMacIndexPresent",
                            receipt.macIndexPresent);
        DIRECTED_RX_WRITE32("NativeAwdlDataDirectedRxReceiptMacIndex",
                            receipt.macIndex);
        DIRECTED_RX_WRITE32("NativeAwdlDataDirectedRxReceiptMacPhyDecodeMode",
                            receipt.macPhyDecodeMode);
        DIRECTED_RX_WRITE32("NativeAwdlDataDirectedRxReceiptOriginalRxStatus",
                            receipt.originalRxStatus);
        DIRECTED_RX_WRITE32("NativeAwdlDataDirectedRxReceiptMpduLength",
                            receipt.mpduLength);
        DIRECTED_RX_WRITE32("NativeAwdlDataDirectedRxReceiptDecodedIpv6Count",
                            receipt.decodedIpv6Count);
        DIRECTED_RX_WRITE32(
            "NativeAwdlDataDirectedRxReceiptIfnetInputResultPresent",
            receipt.ifnetInputResultPresent);
        DIRECTED_RX_WRITE32("NativeAwdlDataDirectedRxReceiptIfnetInputResult",
                            static_cast<uint32_t>(receipt.ifnetInputResult));
        static const char *replyNames[2][19]={
            {"NativeAwdlDataDirectedRxExactReply0Present",
             "NativeAwdlDataDirectedRxExactReply0Captured",
             "NativeAwdlDataDirectedRxExactReply0Delivered",
             "NativeAwdlDataDirectedRxExactReply0Valid",
             "NativeAwdlDataDirectedRxExactReply0Slot",
             "NativeAwdlDataDirectedRxExactReply0Ifindex",
             "NativeAwdlDataDirectedRxExactReply0ContextGeneration",
             "NativeAwdlDataDirectedRxExactReply0PowerGeneration",
             "NativeAwdlDataDirectedRxExactReply0StationGeneration",
             "NativeAwdlDataDirectedRxExactReply0RocGeneration",
             "NativeAwdlDataDirectedRxExactReply0TicketSerial",
             "NativeAwdlDataDirectedRxExactReply0PacketSerial",
             "NativeAwdlDataDirectedRxExactReply0OwnerSerial",
             "NativeAwdlDataDirectedRxExactReply0RunSerial",
             "NativeAwdlDataDirectedRxExactReply0InterfaceIncarnation",
             "NativeAwdlDataDirectedRxExactReply0DoorbellMonotonicUs",
             "NativeAwdlDataDirectedRxExactReply0CaptureMonotonicUs",
             "NativeAwdlDataDirectedRxExactReply0InputMonotonicUs",
             "NativeAwdlDataDirectedRxExactReply0SchemaVersion"},
            {"NativeAwdlDataDirectedRxExactReply1Present",
             "NativeAwdlDataDirectedRxExactReply1Captured",
             "NativeAwdlDataDirectedRxExactReply1Delivered",
             "NativeAwdlDataDirectedRxExactReply1Valid",
             "NativeAwdlDataDirectedRxExactReply1Slot",
             "NativeAwdlDataDirectedRxExactReply1Ifindex",
             "NativeAwdlDataDirectedRxExactReply1ContextGeneration",
             "NativeAwdlDataDirectedRxExactReply1PowerGeneration",
             "NativeAwdlDataDirectedRxExactReply1StationGeneration",
             "NativeAwdlDataDirectedRxExactReply1RocGeneration",
             "NativeAwdlDataDirectedRxExactReply1TicketSerial",
             "NativeAwdlDataDirectedRxExactReply1PacketSerial",
             "NativeAwdlDataDirectedRxExactReply1OwnerSerial",
             "NativeAwdlDataDirectedRxExactReply1RunSerial",
             "NativeAwdlDataDirectedRxExactReply1InterfaceIncarnation",
             "NativeAwdlDataDirectedRxExactReply1DoorbellMonotonicUs",
             "NativeAwdlDataDirectedRxExactReply1CaptureMonotonicUs",
             "NativeAwdlDataDirectedRxExactReply1InputMonotonicUs",
             "NativeAwdlDataDirectedRxExactReply1SchemaVersion"}
        };
        for(size_t i=0;i<kDirectedDataExactReplySlots;++i) {
            const auto &reply=receipt.exactReplies[i];
            const uint64_t values[19]={
                reply.present,reply.captured,reply.delivered,reply.valid,
                reply.slot,reply.ifindex,reply.contextGeneration,
                reply.powerGeneration,reply.stationGeneration,
                reply.rocGeneration,reply.ticketSerial,reply.packetSerial,
                reply.ownerSerial,reply.runSerial,reply.interfaceIncarnation,
                reply.doorbellUs,reply.captureUs,reply.inputUs,
                reply.schemaVersion};
            for(size_t field=0;field<19;++field)
                if(!writeNumber(replyNames[i][field],values[field],
                        field>=10&&field<=17?64:32))
                    return false;
        }
#undef DIRECTED_RX_WRITE32
#undef DIRECTED_RX_WRITE64
        if(!writeNumber("NativeAwdlDataDirectedRxReceiptSnapshotEnd",end,64)||
           !writeNumber("NativeAwdlDataDirectedRxReceiptSnapshotBegin",end,64))
            return false;
        publicationVersion_=end;
        return true;
    }

private:
    uint64_t publicationVersion_=0;
};

} // namespace NativeAwdlBSD
