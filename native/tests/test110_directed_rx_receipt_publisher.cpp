// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_directed_data_rx_receipt_publisher.hpp"

#include <assert.h>
#include <map>
#include <string>

using namespace NativeAwdlBSD;

int main() {
    DirectedDataRxInputReceipt receipt{};
    receipt.disposition=DirectedDataRxReceiptIfnetInputSucceeded;
    receipt.sequence=8;receipt.contentRevision=2;receipt.ownerSerial=75;
    receipt.interfaceIncarnation=4;receipt.contextGeneration=51;
    receipt.powerGeneration=52;receipt.stationGeneration=53;
    receipt.rocGeneration=51;receipt.captureUs=3000010;
    receipt.inputUs=3000020;receipt.startUs=3000000;
    receipt.deadlineUs=3100000;receipt.ieeeChannel=6;
    receipt.macIndexPresent=1;receipt.macIndex=1;
    receipt.macPhyDecodeMode=2;receipt.originalRxStatus=0x8100;
    receipt.mpduLength=128;receipt.decodedIpv6Count=1;
    receipt.ifnetInputResultPresent=1;receipt.ifnetInputResult=0;
    auto &first=receipt.exactReplies[0];
    first.present=1;first.captured=1;first.delivered=1;first.valid=1;
    first.slot=0;first.ifindex=8;first.contextGeneration=51;
    first.powerGeneration=52;first.stationGeneration=53;
    first.rocGeneration=51;first.ticketSerial=100;
    first.packetSerial=200;first.ownerSerial=75;first.runSerial=301;
    first.interfaceIncarnation=4;first.doorbellUs=3000005;
    first.captureUs=3000010;first.inputUs=3000020;
    auto &second=receipt.exactReplies[1];
    second.present=1;second.captured=1;second.delivered=0;second.valid=0;
    second.slot=1;second.ifindex=8;second.contextGeneration=51;
    second.powerGeneration=52;second.stationGeneration=53;
    second.rocGeneration=51;second.ticketSerial=100;
    second.packetSerial=201;second.ownerSerial=75;second.runSerial=301;
    second.interfaceIncarnation=4;second.doorbellUs=3000030;
    second.captureUs=3000035;second.inputUs=0;

    std::map<std::string,uint64_t> properties;
    unsigned writeCount=0,failAt=0;
    auto read=[&](const char *name,uint64_t *out) {
        auto found=properties.find(name);
        if(found==properties.end())return false;
        *out=found->second;return true;
    };
    auto write=[&](const char *name,uint64_t value,unsigned bits) {
        assert(bits==32||bits==64);
        ++writeCount;
        if(failAt&&writeCount==failAt)return false;
        properties[name]=value;return true;
    };
    DirectedDataRxReceiptPublisher publisher;
    assert(publisher.publish(receipt,read,write));
    uint64_t begin=0,end=0,value=0;
    assert(read("NativeAwdlDataDirectedRxReceiptSnapshotBegin",&begin));
    assert(read("NativeAwdlDataDirectedRxReceiptSnapshotEnd",&end));
    assert(begin==end&&begin!=0&&(begin&1u)==0);
    assert(read("NativeAwdlDataDirectedRxReceiptOwnerSerial",&value)&&value==75);
    assert(read("NativeAwdlDataDirectedRxExactReply0Present",&value)&&value==1);
    assert(read("NativeAwdlDataDirectedRxExactReply0Valid",&value)&&value==1);
    assert(read("NativeAwdlDataDirectedRxExactReply0Slot",&value)&&value==0);
    assert(read("NativeAwdlDataDirectedRxExactReply0PacketSerial",&value)&&value==200);
    assert(read("NativeAwdlDataDirectedRxExactReply0DoorbellMonotonicUs",
                &value)&&value==3000005);
    assert(read("NativeAwdlDataDirectedRxExactReply1Present",&value)&&value==1);
    assert(read("NativeAwdlDataDirectedRxExactReply1Delivered",&value)&&value==0);
    assert(read("NativeAwdlDataDirectedRxExactReply1Valid",&value)&&value==0);
    assert(read("NativeAwdlDataDirectedRxExactReply1Slot",&value)&&value==1);
    assert(read("NativeAwdlDataDirectedRxExactReply1PacketSerial",&value)&&value==201);
    assert(read("NativeAwdlDataDirectedRxExactReply1CaptureMonotonicUs",
                &value)&&value==3000035);
    const unsigned before=writeCount;
    assert(publisher.publish(receipt,read,write)&&writeCount==before);

    auto failedReceipt=receipt;
    failedReceipt.contentRevision=4;
    writeCount=0;failAt=7;
    assert(!publisher.publish(failedReceipt,read,write));
    assert(read("NativeAwdlDataDirectedRxReceiptSnapshotBegin",&begin));
    assert(begin&1u);
    failAt=0;writeCount=0;
    assert(publisher.publish(failedReceipt,read,write));
    assert(read("NativeAwdlDataDirectedRxReceiptSnapshotBegin",&begin));
    assert(read("NativeAwdlDataDirectedRxReceiptSnapshotEnd",&end));
    assert(begin==end&&(begin&1u)==0);
    return 0;
}
