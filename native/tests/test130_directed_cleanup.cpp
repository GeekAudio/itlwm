// SPDX-License-Identifier: GPL-2.0-only
// Real origin lifecycle into the terminal resource proof; no hardware or RF.
#include <cassert>
#include <cstdio>
#include "../p2p_directed_complete_cleanup.hpp"
using namespace NativeAwdlDirectedOriginTx;
using NativeP2PDirectedCompleteCleanup::evaluateOriginProof;

struct Run {
    Ledger ledger;
    OpenRequest request{};
    Ticket ticket{};
    PacketIdentity packets[2]{};
    uint8_t own[6]{2,1,2,3,4,5};
    Run() {
        request.ownerSerial=7; request.runSerial=9;
        request.rocStartUs=10000; request.deadlineUs=110000;
        request.rocChannelIndex=6; request.epochs={1,2,3,4};
        request.packetCount=2;
        request.sourceIPv6[0]=request.peerIPv6[0]=0xfe;
        request.sourceIPv6[1]=request.peerIPv6[1]=0x80;
        request.sourceIPv6[15]=1; request.peerIPv6[15]=2;
        request.peerMac[0]=2; request.peerMac[5]=6;
        request.packetNonces[0][7]=1; request.packetNonces[1][7]=2;
        assert(ledger.open(request,10001,2,8,12,own,request.sourceIPv6,&ticket));
        for (uint8_t i=0;i<2;++i) assert(ledger.packetIdentity(ticket,i,&packets[i]));
    }
    void pop(uint8_t slot,uint64_t now,bool encoded=true) {
        assert(ledger.acceptsOutput(ticket,slot,now,true,2,8));
        assert(ledger.beginPop(ticket,packets[slot],now+1,true,2,8));
        assert(ledger.finishPop(ticket,packets[slot],now+2,true,2,8,encoded)==encoded);
    }
    void completeFirst() {
        pop(0,11000);
        assert(ledger.recordTxDoorbell(ticket,packets[0],12000,12000,2,8));
        assert(ledger.recordExactReplyCaptured(ticket,packets[0],12500,12500,2,8));
        assert(ledger.recordExactReplyDelivered(ticket,packets[0],12500,12600,12600,2,8));
        assert(ledger.recordTxCompletion(ticket,packets[0],true,13000,13000,2,8));
        assert(ledger.snapshot(13001,true).state==State::OpenNext);
    }
    bool proof(uint64_t now,bool allDoorbellsComplete,bool noDoorbell) {
        return evaluateOriginProof(ledger.snapshot(now,true),ticket,7,9,
            true,false,allDoorbellsComplete,noDoorbell).terminalAccepted;
    }
};

int main() {
    // First packet completed; next packet never accepted. Retirement is safe
    // without claiming a two-packet exchange or requiring a second doorbell.
    for (unsigned terminal=0;terminal<3;++terminal) {
        Run r; r.completeFirst();
        if (terminal==0) assert(r.ledger.close(r.ticket,14000));
        if (terminal==1) assert(r.ledger.expire(110000));
        if (terminal==2) assert(r.ledger.revoke(14000));
        const uint64_t now=terminal==1?110001:14001;
        assert(r.proof(now,true,false));
        assert(!r.proof(now,false,false)); // unknown outstanding TX is never safe
    }
    {
        Run r; r.completeFirst();
        assert(r.ledger.acceptsOutput(r.ticket,1,14000,true,2,8));
        assert(r.ledger.close(r.ticket,14001));
        assert(!r.proof(14002,true,false)); // close is not a queued mbuf free
        assert(r.ledger.retireQueuedPacket(r.ticket,r.packets[1]));
        assert(r.proof(14003,true,false));
    }
    {
        Run r; r.completeFirst();
        assert(r.ledger.acceptsOutput(r.ticket,1,14000,true,2,8));
        assert(r.ledger.beginPop(r.ticket,r.packets[1],14001,true,2,8));
        assert(r.ledger.close(r.ticket,14002));
        assert(!r.proof(14003,true,false)); // outstanding lock-free encoder
        assert(!r.ledger.finishPop(r.ticket,r.packets[1],14004,true,2,8,true));
        assert(r.proof(14005,true,false));
    }
    {
        Run r; r.pop(0,11000,false);
        assert(r.ledger.snapshot(11003,true).state==State::Failed);
        assert(r.proof(11004,false,true)); // encoding failed, no hardware submit
        assert(!r.proof(11004,false,false));
    }
    {
        Run r; r.completeFirst(); r.pop(1,14000);
        assert(r.ledger.recordTxDoorbell(r.ticket,r.packets[1],15000,15000,2,8));
        assert(r.ledger.recordTxCompletion(r.ticket,r.packets[1],false,16000,16000,2,8));
        assert(r.ledger.snapshot(16001,true).state==State::Failed);
        assert(r.proof(16002,true,false)); // precise failed TX can still retire
        assert(!r.proof(16002,false,false));
    }
    {
        Run r; r.completeFirst();
        assert(!r.proof(14000,true,false)); // active OpenNext is not terminal
        assert(r.ledger.close(r.ticket,14001));
        auto snapshot=r.ledger.snapshot(14002,true);
        auto check=[&](const Snapshot &s) { return evaluateOriginProof(
            s,r.ticket,7,9,true,false,true,false).terminalAccepted; };
        auto wrong=snapshot; ++wrong.epochs.roc; assert(!check(wrong));
        wrong=snapshot; wrong.packets[1].packetSerial=wrong.packets[0].packetSerial;
        assert(!check(wrong));
        wrong=snapshot; wrong.packets[1].present=false; assert(!check(wrong));
        wrong=snapshot; wrong.packets[1].packetPopping=true; assert(!check(wrong));
        // The old single-packet Closed/Spent rule is unchanged.
        wrong=snapshot; wrong.packetCount=1; assert(!check(wrong));
    }
    std::puts("Test130 actual origin lifecycle and bounded cleanup proof passed");
}
