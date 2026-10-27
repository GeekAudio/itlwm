// SPDX-License-Identifier: GPL-2.0-only
#include "fault_reporter.hpp"

#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOService.h>

class CCDataStream;

// Exact 25G241 native C++ entry points. Explicit labels avoid dispatch through
// legacy CCPipe virtual declarations. The opaque pointer is the native this.
extern "C" bool startNativePipe(void *) __asm__("__ZN6CCPipe9startPipeEv");
extern "C" void stopNativePipe(void *) __asm__("__ZN6CCPipe8stopPipeEv");

// Static factory declarations with the real native symbol names. Only the
// shared OSObject retain/release/metaCast prefix is used. These are deliberately
// not complete native layouts: never allocate, instantiate, sizeof, access a
// field, or call a derived virtual method through either declaration.
class CCFaultReporter : public OSObject {
public:
    static CCFaultReporter *withStreamWorkloop(CCDataStream *, IOWorkLoop *);
};

class IO80211FaultReporter : public OSObject {
public:
    static IO80211FaultReporter *allocWithParams(CCFaultReporter *);
};

namespace NativeWifi {
bool startNativeCapturePipe(OSObject *pipe)
{
    if (!pipe) return false;
    auto typedPipe = pipe->metaCast("CCPipe");
    return typedPipe && startNativePipe(typedPipe);
}

void stopNativeCapturePipe(OSObject *pipe, IOService *owner)
{
    if (pipe && owner) {
        auto typedPipe = pipe->metaCast("CCPipe");
        auto service = static_cast<IOService *>(pipe->metaCast("IOService"));
        if (typedPipe && service) {
            // Native stopPipe only detaches the owner; it does not cancel the
            // CCDataPipe timer. Stop through the audited IOService prefix first.
            service->stop(owner);
            stopNativePipe(typedPipe);
        }
    }
}

OSObject *createNativeFaultReporter(OSObject *dataStream, IOWorkLoop *workLoop)
{
    if (!dataStream || !workLoop || workLoop->inGate())
        return nullptr;

    // Do not allow a log/base stream to reach a typed native data-stream API.
    auto typedStream = dataStream->metaCast("CCDataStream");
    if (!typedStream)
        return nullptr;

    CCFaultReporter *reporter = CCFaultReporter::withStreamWorkloop(
        reinterpret_cast<CCDataStream *>(typedStream), workLoop);
    if (!reporter)
        return nullptr;

    IO80211FaultReporter *wrapper = IO80211FaultReporter::allocWithParams(reporter);
    // Native wrapper init retains reporter. On either factory outcome, give up
    // this helper's initial reference exactly once; native free owns cleanup.
    reporter->release();
    if (!wrapper)
        return nullptr;

    if (!wrapper->metaCast("IO80211FaultReporter") ||
        !wrapper->metaCast("CommonFaultReporter")) {
        wrapper->release();
        return nullptr;
    }
    return wrapper;
}
}
