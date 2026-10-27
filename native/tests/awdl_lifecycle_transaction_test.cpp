// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_lifecycle_transaction.hpp"
#include <assert.h>
using NativeAwdlLifecycle::TransactionState;
struct Operations {
    int fail, calls=0, retirement=0;
    bool retirementReady=true;
    TransactionState retiredState{};
    bool step(){return ++calls!=fail;}
    bool initialize(){return step();}
    bool attach(){return step();}
    bool createQueues(){return step();}
    bool registerInterface(){return step();}
    bool start(){return step();}
    bool verifyStarted(){return step();}
    void publish(){++calls;}
    bool observeBSD(){return step();}
    bool retire(const TransactionState &s){++retirement;retiredState=s;return retirementReady;}
};
int main(){
    // Failure injection covers each real transaction boundary, including a
    // true start result followed by an incomplete native-state witness.
    const int failures[]={0,1,2,3,4,5,6,8};
    for(int failure: failures) {
        Operations ops{failure};TransactionState state{};
        const bool ok=NativeAwdlLifecycle::execute(ops,state);
        assert(ok==(failure==0));assert(ops.retirement==1);
        if(failure==6)assert(state.startCalled&&!state.startComplete&&!state.published);
        if(failure==4)assert(!state.registered&&!state.startCalled);
        if(failure==8)assert(state.published&&state.startComplete);
    }
    Operations held{0};held.retirementReady=false;TransactionState state{};
    assert(!NativeAwdlLifecycle::execute(held,state));
    assert(held.retirement==1&&state.published);
    Operations resident{0};TransactionState live{};
    assert(NativeAwdlLifecycle::start(resident,live));
    assert(live.startComplete&&live.published&&resident.retirement==0);
    assert(resident.retire(live)&&resident.retirement==1);
    return 0;
}
