// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <libkern/c++/OSObject.h>

class IOWorkLoop;
class IOService;

namespace NativeWifi {
// Use the exact native entry points, without the legacy CCPipe virtual layout.
// Factory initialization attaches the pipe but does not start its timer.
bool startNativeCapturePipe(OSObject *pipe);
void stopNativeCapturePipe(OSObject *pipe, IOService *owner);

// Create the actual native CommonFaultReporter implementation, not a data
// stream cast to that protocol. Inputs are borrowed; success returns +1.
// Call during serialized startup, outside workLoop's gate. Its native factory
// creates a timer; final release can cancel/remove that timer and must also
// happen outside its workloop callbacks/gate after clients have stopped.
OSObject *createNativeFaultReporter(OSObject *dataStream, IOWorkLoop *workLoop);
}
