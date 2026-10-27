#!/usr/bin/env python3
"""Execute actual capture startup/cleanup with staged native-factory failures."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]


def body(file, marker):
    source = (root / file).read_text()
    start = source.index(marker)
    opening = source.index('{', start)
    end, depth = opening + 1, 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


shim = r'''
#include <cassert>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#define AIRPORT_TAHOE 1
#define LOWER32(x) ((uint64_t(x))&0xffffffff)
#define HIGHER32(x) ((uint64_t(x))>>32)
#define OSSafeReleaseNULL(x) do{if(x){(x)->release();(x)=nullptr;}}while(0)
struct CCPipe;
static std::vector<std::string> events;
struct OSObject {
 std::string kind; bool released=false;
 explicit OSObject(const char*k):kind(k){} virtual ~OSObject()=default;
 virtual void *metaCast(const char*name){return kind==name?this:nullptr;}
 void release(){assert(!released);released=true;events.push_back("release:"+kind);}
};
static std::vector<OSObject*> allocations;
struct IOService:OSObject {
 explicit IOService(const char*k):OSObject(k){} virtual void stop(IOService*){}
};
struct IOWorkLoop {bool gated=false;bool inGate(){return gated;}};
static IOWorkLoop queue; static IOWorkLoop *_fWorkloop=&queue;
struct CCPipeOptions {
 uint64_t pipe_type=0,log_data_type=0,pipe_size=0,min_log_size_notify=0;
 uint32_t notify_threshold=0,pad9=0,pad10=0;
 char file_name[256]{},name[240]{},directory_name[256]{};
};
struct CCStreamOptions {uint64_t console_level=0;uint32_t stream_type=0;};
static unsigned factories=0,streams=0,failFactory=0,failStart=0,failStream=0;
static bool failReporter=false;
struct CCPipe:IOService {
 unsigned id;bool started=false,timer=false,detached=false;
 explicit CCPipe(unsigned n):IOService("CCPipe"),id(n){}
 void *metaCast(const char*n) override {
  return !strcmp(n,"CCPipe")||!strcmp(n,"IOService")?this:nullptr;
 }
 void stop(IOService*owner) override {
  assert(owner&&started&&!released);timer=false;started=false;
  events.push_back("stop"+std::to_string(id));
 }
 static CCPipe *withOwnerNameCapacity(IOService*,const char*,const char*,CCPipeOptions*) {
  unsigned n=++factories;if(n==failFactory)return nullptr;
  auto p=new CCPipe(n);allocations.push_back(p);return p;
 }
};
bool startNativePipe(void*p) {
 auto pipe=static_cast<CCPipe*>(p);assert(!pipe->released&&!pipe->started);
 events.push_back("start"+std::to_string(pipe->id));
 if(pipe->id==failStart)return false;
 pipe->started=true;pipe->timer=true;return true;
}
void stopNativePipe(void*p) {
 auto pipe=static_cast<CCPipe*>(p);assert(!pipe->timer&&!pipe->started&&!pipe->released);
 assert(!pipe->detached);pipe->detached=true;
 events.push_back("detach"+std::to_string(pipe->id));
}
struct CCStream:OSObject {
 CCPipe*pipe;
 CCStream(const char*k,CCPipe*p):OSObject(k),pipe(p){}
 static CCStream *withPipeAndName(CCPipe*p,const char*,CCStreamOptions*o) {
  assert(p&&p->started&&p->timer);++streams;if(streams==failStream)return nullptr;
  auto s=new CCStream(o->stream_type?"CCDataStream":"CCLogStream",p);
  allocations.push_back(s);return s;
 }
};
namespace NativeWifi {
 bool startNativeCapturePipe(OSObject*);
 void stopNativeCapturePipe(OSObject*,IOService*);
 OSObject *createNativeFaultReporter(OSObject*s,IOWorkLoop*q) {
  assert(s&&s->metaCast("CCDataStream")&&q&&!q->inGate());
  auto stream=static_cast<CCStream*>(s);assert(stream->pipe->timer);
  if(failReporter)return nullptr;
  auto r=new OSObject("reporter");allocations.push_back(r);return r;
 }
}
struct Provider {
 std::map<std::string,uint32_t> metadata;
 void setProperty(const char*k,uint32_t v,unsigned){metadata[k]=v;}
};
struct AirportItlwm:IOService {
 Provider provider;
 CCPipe *driverLogPipe=nullptr,*driverDataPathPipe=nullptr,*driverSnapshotsPipe=nullptr;
 CCStream *nativeLogger=nullptr,*driverFaultReporter=nullptr;
 OSObject *nativeFaultReporter=nullptr;uint32_t nativeCaptureStarted=0;
 AirportItlwm():IOService("owner"){}
 Provider *getProvider(){return &provider;}
 bool initCCLogs();void releaseNativeCapture();
};
'''
main = r'''
void cleanup() {
 for(auto p:allocations){assert(p->released);delete p;}
 allocations.clear();events.clear();factories=streams=failFactory=failStart=failStream=0;
 failReporter=false;queue.gated=false;
}
void checkReleased(AirportItlwm&a) {
 a.releaseNativeCapture();assert(!a.nativeCaptureStarted);
 // Cleanup is safe after an earlier cleanup as well.
 auto count=events.size();a.releaseNativeCapture();assert(events.size()==count);
 for(auto p:allocations)if(auto pipe=dynamic_cast<CCPipe*>(p)){
  assert(!pipe->timer&&!pipe->started);
  if(pipe->id!=failStart)assert(pipe->detached);
 }
}
int main() {
 {AirportItlwm a;assert(a.initCCLogs());
  assert(a.nativeCaptureStarted==7&&a.provider.metadata.at("NativeCaptureReady")==63);
  assert(a.provider.metadata.at("NativeCaptureStarted")==7);
  // Delayed capture may begin only with the data-pipe timer created by start.
  for(unsigned i=0;i<256;++i)assert(a.driverSnapshotsPipe->timer);
  checkReleased(a);
  auto pos=[&](const char*s){for(unsigned i=0;i<events.size();++i)if(events[i]==s)return i;return unsigned(events.size());};
  assert(pos("release:reporter")<pos("release:CCDataStream"));
  assert(pos("release:CCDataStream")<pos("stop3"));
  assert(pos("stop3")<pos("detach3"));cleanup();}
 for(unsigned n=1;n<=3;++n){failFactory=n;AirportItlwm a;assert(!a.initCCLogs());checkReleased(a);cleanup();}
 for(unsigned n=1;n<=3;++n){failStart=n;AirportItlwm a;assert(!a.initCCLogs());checkReleased(a);cleanup();}
 for(unsigned n=1;n<=2;++n){failStream=n;AirportItlwm a;assert(!a.initCCLogs());checkReleased(a);cleanup();}
 {failReporter=true;AirportItlwm a;assert(!a.initCCLogs());checkReleased(a);cleanup();}
 {queue.gated=true;AirportItlwm a;assert(!a.initCCLogs()&&!factories);checkReleased(a);cleanup();}
 {OSObject wrong("wrong");assert(!NativeWifi::startNativeCapturePipe(&wrong));
  NativeWifi::stopNativeCapturePipe(&wrong,nullptr);assert(!NativeWifi::startNativeCapturePipe(nullptr));}
}
'''
code = shim + '\nnamespace NativeWifi {\n' + '\n'.join([
    body('native/fault_reporter.cpp', 'bool startNativeCapturePipe('),
    body('native/fault_reporter.cpp', 'void stopNativeCapturePipe('),
]) + '\n}\n' + body('AirportItlwm/AirportItlwmV2.cpp', 'bool AirportItlwm::\ninitCCLogs()') + '\n' + body(
    'AirportItlwm/AirportItlwmV2.cpp', 'void AirportItlwm::releaseNativeCapture()') + main
with tempfile.TemporaryDirectory(prefix='intel-capture-lifecycle-') as directory:
    path = Path(directory)
    (path / 'test.cpp').write_text(code)
    subprocess.run(['xcrun','clang++','-std=c++14','-O1','-fsanitize=address,undefined',
        '-fno-omit-frame-pointer',str(path/'test.cpp'),'-o',str(path/'test')],check=True)
    subprocess.run([str(path/'test')],check=True)
print('PASS: actual startup/cleanup order, 9 staged failures, gate rejection, null/type checks and repeated cleanup')
