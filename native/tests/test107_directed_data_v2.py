#!/usr/bin/env python3
"""Exercise the production Tahoe directed-data admin path under host shims."""
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
AIRPORT_SOURCE = (ROOT / "AirportItlwm/AirportItlwmV2.cpp").read_text()
DATA_HEADER = (ROOT / "itlwm/hal_iwx/ItlIwxP2PData.hpp").read_text()


def function_body(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    end, depth = opening + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def declaration(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    end, depth = opening + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end] + ";"


HELPERS = "\n".join(function_body(AIRPORT_SOURCE, marker) for marker in (
    "bool validRx149RunToken(",
    "bool validDirectedPrepareRunToken(",
    "bool validDirectedPreparePeer(",
    "static bool directedPrepareRx149DataInputProfileEnabled(",
    "static bool validDirectedDataLocalIpv6(",
    "static bool validDirectedDataNonce(",
))
DATA_LIMIT = next(line for line in DATA_HEADER.splitlines() if line.startswith("static constexpr uint8_t kTahoeP2PDirectedDataMaxPackets"))
DATA_ARM = DATA_LIMIT + "\n" + declaration(DATA_HEADER, "struct TahoeP2PDirectedDataArm {")
READONLY_HELPER = function_body(
    AIRPORT_SOURCE, "static bool directedDataHasReadonlyKeys(")
DATA_CALLBACK_CONTEXT = declaration(
    AIRPORT_SOURCE, "struct NativeP2PDirectedDataArmContext {")
DATA_CALLBACK = function_body(
    AIRPORT_SOURCE, "IOReturn armNativeP2PDirectedDataOnMainGate(")
SETTER = function_body(AIRPORT_SOURCE, "IOReturn AirportItlwm::setProperties(")


SHIM = r"""
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using IOReturn = int;
static constexpr IOReturn kIOReturnSuccess = 0;
static constexpr IOReturn kIOReturnUnsupported = -1;
static constexpr IOReturn kIOReturnBadArgument = -2;
static constexpr IOReturn kIOReturnNotReady = -3;
static constexpr IOReturn kIOReturnNotPrivileged = -4;
static constexpr IOReturn kIOReturnNoMemory = -5;
static constexpr IOReturn kIOReturnBusy = -6;
static constexpr int kIOClientPrivilegeAdministrator = 1;

class OSObject {
public:
    virtual ~OSObject() = default;
};

class OSBoolean final : public OSObject {
public:
    explicit OSBoolean(bool value) : value(value) {}
    bool value;
};
static OSBoolean trueBoolean(true);
static OSBoolean falseBoolean(false);
static OSObject *const kOSBooleanTrue = &trueBoolean;
static OSObject *const kOSBooleanFalse = &falseBoolean;

class OSNumber final : public OSObject {
public:
    explicit OSNumber(uint64_t value) : value_(value) {}
    uint64_t unsigned64BitValue() const { return value_; }
private:
    uint64_t value_;
};

class OSString final : public OSObject {
public:
    explicit OSString(const char *value) : value_(value ? value : "") {}
    explicit OSString(std::string value) : value_(std::move(value)) {}
    unsigned getLength() const { return static_cast<unsigned>(value_.size()); }
    const char *getCStringNoCopy() const { return value_.c_str(); }
private:
    std::string value_;
};

class OSData final : public OSObject {
public:
    explicit OSData(std::vector<uint8_t> value) : value_(std::move(value)) {}
    unsigned getLength() const { return static_cast<unsigned>(value_.size()); }
    const void *getBytesNoCopy() const {
        return value_.empty() ? nullptr : value_.data();
    }
private:
    std::vector<uint8_t> value_;
};

class OSDictionary final : public OSObject {
public:
    std::map<std::string, OSObject *> entries;
    OSObject *getObject(const char *key) const {
        auto found = entries.find(key);
        return found == entries.end() ? nullptr : found->second;
    }
    unsigned getCount() const { return static_cast<unsigned>(entries.size()); }
    void add(const char *key, OSObject *value) { entries[key] = value; }
};

class OSCollectionIterator final : public OSObject {
public:
    static bool allocationFails;
    static OSCollectionIterator *withCollection(OSDictionary *dictionary) {
        if (allocationFails || !dictionary)
            return nullptr;
        auto result = new OSCollectionIterator();
        for (const auto &entry : dictionary->entries)
            result->keys_.push_back(new OSString(entry.first));
        return result;
    }
    OSObject *getNextObject() {
        return index_ == keys_.size() ? nullptr : keys_[index_++];
    }
    void release() { delete this; }
private:
    ~OSCollectionIterator() override {
        for (auto *key : keys_)
            delete key;
    }
    std::vector<OSString *> keys_;
    size_t index_ = 0;
};
bool OSCollectionIterator::allocationFails = false;

#define OSDynamicCast(type, object) dynamic_cast<type *>(object)

struct IOCommandGate;
struct IOEthernetController : OSObject {
    std::map<std::string, OSObject *> properties;
    bool rejectSet = false;
    bool dropSet = false;
    unsigned propertyWrites = 0;
    OSObject *getProperty(const char *key) const {
        auto found = properties.find(key);
        return found == properties.end() ? nullptr : found->second;
    }
    bool setProperty(const char *key, OSObject *value) {
        ++propertyWrites;
        if (rejectSet)
            return false;
        if (!dropSet)
            properties[key] = value;
        return true;
    }
    void removeProperty(const char *key) { properties.erase(key); }
};

class BaseService : public IOEthernetController {
public:
    unsigned parentCalls = 0;
    IOReturn parentResult = kIOReturnSuccess;
    IOReturn setProperties(OSObject *) { ++parentCalls; return parentResult; }
};
#define super BaseService

struct IOCommandGate {
    using Action = IOReturn (*)(OSObject *, void *, void *, void *, void *);
    unsigned calls = 0;
    OSObject *target = nullptr;
    IOReturn runAction(Action action, void *argument) {
        ++calls;
        return action(target, argument, nullptr, nullptr, nullptr);
    }
};
struct IOWorkLoop {
    bool gate = false;
    bool inGate() const { return gate; }
};
static IOCommandGate commandGate;
static IOWorkLoop workLoop;
static IOCommandGate *_fCommandGate = &commandGate;
static IOWorkLoop *_fWorkloop = &workLoop;

class ItlHalService : public OSObject {
public:
    IOReturn nativeP2pArmProbe() { return kIOReturnSuccess; }
};
class ItlIwx : public ItlHalService {
public:
    unsigned dataArmCalls = 0;
    IOReturn dataArmResult = kIOReturnSuccess;
    IOCommandGate *tahoeP2pCommandGate() const { return _fCommandGate; }
    IOReturn nativeP2pArmDirectedData(const TahoeP2PDirectedDataArm &arm);
    TahoeP2PDirectedDataArm lastArm{};
};

class AirportItlwm : public BaseService {
public:
    ItlHalService *fHalService = nullptr;
    IOReturn setProperties(OSObject *properties);
};

IOReturn ItlIwx::nativeP2pArmDirectedData(
    const TahoeP2PDirectedDataArm &arm) {
    ++dataArmCalls;
    lastArm = arm;
    return dataArmResult;
}

static IOReturn gPrivilege = kIOReturnSuccess;
class IOUserClient {
public:
    static IOReturn clientHasPrivilege(void *, int) { return gPrivilege; }
};
static void *current_task() { return nullptr; }

struct NativeRx149ArmContext { OSString *runToken; };
static IOReturn armNativeRx149OnMainGate(
    OSObject *, void *, void *, void *, void *) { return kIOReturnUnsupported; }
struct NativeP2PDirectedPrepareArmContext { OSData *peerMac; OSString *runToken; };
static IOReturn armNativeP2PDirectedPrepareOnMainGate(
    OSObject *, void *, void *, void *, void *) { return kIOReturnUnsupported; }

"""


BODY = r"""
static std::vector<uint8_t> bytes(std::initializer_list<uint8_t> values) {
    return std::vector<uint8_t>(values);
}
static std::vector<uint8_t> validPeer() {
    return bytes({0x02, 0x11, 0x22, 0x33, 0x44, 0x55});
}
static std::vector<uint8_t> validLocal() {
    return bytes({0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                  0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77});
}
static std::vector<uint8_t> validNonce() {
    return bytes({0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08});
}
static OSString validToken("0123456789abcdef0123456789abcdef");
static OSBoolean onceTrue(true), onceFalse(false);
static OSData peerData(validPeer()), localData(validLocal()), nonceData(validNonce());

struct RequestObjects {
    OSBoolean once{true};
    OSData peer{validPeer()}, local{validLocal()}, nonce{validNonce()};
    OSString token{"0123456789abcdef0123456789abcdef"};
    OSDictionary request;
    RequestObjects() {
        request.add("NativeP2PDirectedDataOnce", kOSBooleanTrue);
        request.add("NativeP2PDirectedDataPeerMAC", &peer);
        request.add("NativeP2PDirectedDataLocalIPv6", &local);
        request.add("NativeP2PDirectedDataNonce", &nonce);
        request.add("NativeP2PDirectedDataRunToken", &token);
    }
};

static void configureProfile(AirportItlwm &driver, OSNumber &availability) {
    driver.properties["NativeP2PDirectedDataCompiled"] = kOSBooleanTrue;
    driver.properties["NativeP2PDirectedDataEnabled"] = kOSBooleanTrue;
    driver.properties["NativeAwdlResidentEnabled"] = kOSBooleanTrue;
    driver.properties["NativeP2PManualTrigger"] = kOSBooleanTrue;
    driver.properties["NativeP2PProbe"] = kOSBooleanTrue;
    driver.properties["NativeP2PRx149ObservationOnly"] = kOSBooleanTrue;
    driver.properties["NativeP2PRx149DataInputProfileEnabled"] = &availability;
    driver.properties["NativeP2PRocProbe"] = kOSBooleanFalse;
    driver.properties["NativeP2PTxProbe"] = kOSBooleanFalse;
    driver.properties["NativeP2PAwdlPsfObservationOnly"] = kOSBooleanFalse;
    driver.properties["NativeP2PAwdlMifFollowup"] = kOSBooleanFalse;
}

static IOReturn invoke(AirportItlwm &driver, OSDictionary &request) {
    commandGate.target = &driver;
    return driver.setProperties(&request);
}

static void assertNoArm(AirportItlwm &driver, ItlIwx &hal) {
    assert(hal.dataArmCalls == 0);
    assert(driver.getProperty("NativeP2PDirectedDataAcceptedRunToken") == nullptr);
    assert(driver.parentCalls == 0);
}

#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
static void testAvailabilityNumberGate() {
    IOEthernetController controller;
    OSNumber one(1), zero(0), two(2), high(0x100000001ULL);
    OSString stringOne("1");
    assert(directedPrepareRx149DataInputProfileEnabled(nullptr) == false);
    controller.properties["NativeP2PRx149DataInputProfileEnabled"] = &one;
    assert(directedPrepareRx149DataInputProfileEnabled(&controller));
    for (OSObject *wrong : {static_cast<OSObject *>(&zero),
                            static_cast<OSObject *>(&two),
                            static_cast<OSObject *>(&high),
                            static_cast<OSObject *>(&trueBoolean),
                            static_cast<OSObject *>(&stringOne)}) {
        controller.properties["NativeP2PRx149DataInputProfileEnabled"] = wrong;
        assert(!directedPrepareRx149DataInputProfileEnabled(&controller));
    }
    controller.properties.erase("NativeP2PRx149DataInputProfileEnabled");
    assert(!directedPrepareRx149DataInputProfileEnabled(&controller));
}

static void testReadonlyPrefix() {
    for (const char *key : {
            "NativeP2PDirectedDataStage", "NativeP2PDirectedDataResult",
            "NativeP2PDirectedDataReady", "NativeP2PDirectedDataCompiled",
            "NativeP2PDirectedDataAcceptedRunToken",
            "NativeP2PDirectedDataFutureStatus"}) {
        OSDictionary request;
        request.add(key, kOSBooleanFalse);
        assert(directedDataHasReadonlyKeys(&request));
        AirportItlwm driver; ItlIwx hal; OSNumber one(1);
        configureProfile(driver, one); driver.fHalService = &hal;
        assert(invoke(driver, request) == kIOReturnUnsupported);
        assertNoArm(driver, hal);
    }
    RequestObjects valid;
    assert(!directedDataHasReadonlyKeys(&valid.request));
    OSCollectionIterator::allocationFails = true;
    assert(directedDataHasReadonlyKeys(&valid.request));
    OSCollectionIterator::allocationFails = false;
}

static void testExactArmSuccessAndReceiptFailures() {
    OSNumber one(1);
    {
        AirportItlwm driver; ItlIwx hal; RequestObjects input;
        configureProfile(driver, one); driver.fHalService = &hal;
        assert(invoke(driver, input.request) == kIOReturnSuccess);
        assert(commandGate.calls == 1);
        assert(hal.dataArmCalls == 1);
        assert(driver.parentCalls == 0);
        assert(hal.lastArm.peerMac[0] == 0x02 && hal.lastArm.peerMac[5] == 0x55);
        assert(hal.lastArm.localIpv6[0] == 0xfe && hal.lastArm.localIpv6[1] == 0x80);
        assert(hal.lastArm.localIpv6[15] == 0x77);
        assert(hal.lastArm.nonce[0] == 1 && hal.lastArm.nonce[7] == 8);
        assert(hal.lastArm.packetCount == 1);
        assert(std::memcmp(hal.lastArm.runToken,
                           "0123456789abcdef0123456789abcdef", 32) == 0);
        assert(hal.lastArm.runToken[32] == '\0');
        assert(driver.getProperty("NativeP2PDirectedDataAcceptedRunToken") ==
               &input.token);
    }
    for (bool rejectWrite : {false, true}) {
        AirportItlwm driver; ItlIwx hal; RequestObjects input;
        configureProfile(driver, one); driver.fHalService = &hal;
        driver.rejectSet = rejectWrite;
        driver.dropSet = !rejectWrite;
        assert(invoke(driver, input.request) == kIOReturnNoMemory);
        assert(hal.dataArmCalls == 1); // The consumed arm is never retried.
        assert(driver.propertyWrites == 1);
        assert(driver.getProperty("NativeP2PDirectedDataAcceptedRunToken") == nullptr);
    }
    {
        AirportItlwm driver; ItlIwx hal; RequestObjects input;
        configureProfile(driver, one); driver.fHalService = &hal;
        hal.dataArmResult = kIOReturnBusy;
        assert(invoke(driver, input.request) == kIOReturnBusy);
        assert(hal.dataArmCalls == 1);
        assert(driver.getProperty("NativeP2PDirectedDataAcceptedRunToken") == nullptr);
    }
}

static void testExactTwoPacketArm() {
    OSNumber one(1), two(2), tooMany(3), wideCount(0x100000002ULL);
    for (unsigned variant = 0; variant < 12; ++variant) {
        AirportItlwm driver; ItlIwx hal; RequestObjects input;
        configureProfile(driver, one); driver.fHalService = &hal;
        OSData peerIp(bytes({0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                             0, 1, 2, 3, 4, 5, 6, 0x88}));
        OSData nonce2(bytes({9, 10, 11, 12, 13, 14, 15, 16}));
        input.request.add("NativeP2PDirectedDataPacketCount", &two);
        input.request.add("NativeP2PDirectedDataPeerIPv6", &peerIp);
        input.request.add("NativeP2PDirectedDataNonce2", &nonce2);
        switch (variant) {
        case 1: input.request.add("NativeP2PDirectedDataPacketCount", &one); break;
        case 2: input.request.add("NativeP2PDirectedDataPacketCount", &tooMany); break;
        case 3: input.request.add("NativeP2PDirectedDataPacketCount", &wideCount); break;
        case 4: input.request.add("NativeP2PDirectedDataPacketCount", kOSBooleanTrue); break;
        case 5: input.request.entries.erase("NativeP2PDirectedDataNonce2"); break;
        case 6: input.request.add("NativeP2PDirectedDataNonce2", &input.nonce); break;
        case 7: nonce2 = OSData(bytes({0, 0, 0, 0, 0, 0, 0, 0})); break;
        case 8: input.request.add("NativeP2PDirectedDataPeerIPv6", &input.local); break;
        case 9: peerIp = OSData(bytes({0xfe, 0x80})); break;
        case 10: input.request.add("Unexpected", &one); break;
        case 11: input.request.entries.erase("NativeP2PDirectedDataPeerIPv6"); break;
        }
        const auto result = invoke(driver, input.request);
        if (variant == 0) {
            assert(result == kIOReturnSuccess && hal.dataArmCalls == 1);
            assert(hal.lastArm.packetCount == 2);
            assert(std::memcmp(hal.lastArm.packetNonces[0], input.nonce.getBytesNoCopy(), 8) == 0);
            assert(std::memcmp(hal.lastArm.packetNonces[1], nonce2.getBytesNoCopy(), 8) == 0);
            assert(std::memcmp(hal.lastArm.peerIPv6, peerIp.getBytesNoCopy(), 16) == 0);
        } else {
            assert(result == kIOReturnBadArgument);
            assertNoArm(driver, hal);
        }
    }
}

static void testAuthorizationAndProfileGates() {
    OSNumber one(1);
    {
        AirportItlwm driver; ItlIwx hal; RequestObjects input;
        configureProfile(driver, one); driver.fHalService = &hal;
        gPrivilege = kIOReturnNotPrivileged;
        assert(invoke(driver, input.request) == kIOReturnNotPrivileged);
        assertNoArm(driver, hal);
        gPrivilege = kIOReturnSuccess;
    }
    for (const char *key : {
            "NativeP2PDirectedDataCompiled", "NativeP2PDirectedDataEnabled",
            "NativeAwdlResidentEnabled", "NativeP2PManualTrigger",
            "NativeP2PProbe", "NativeP2PRx149ObservationOnly"}) {
        for (OSObject *value : {static_cast<OSObject *>(kOSBooleanFalse),
                                static_cast<OSObject *>(nullptr)}) {
            AirportItlwm driver; ItlIwx hal; RequestObjects input;
            configureProfile(driver, one); driver.fHalService = &hal;
            if (value)
                driver.properties[key] = value;
            else
                driver.properties.erase(key);
            assert(invoke(driver, input.request) == kIOReturnUnsupported);
            assertNoArm(driver, hal);
        }
    }
    for (const char *key : {
            "NativeP2PRocProbe", "NativeP2PTxProbe",
            "NativeP2PAwdlPsfObservationOnly", "NativeP2PAwdlMifFollowup"}) {
        AirportItlwm driver; ItlIwx hal; RequestObjects input;
        configureProfile(driver, one); driver.fHalService = &hal;
        driver.properties[key] = kOSBooleanTrue;
        assert(invoke(driver, input.request) == kIOReturnUnsupported);
        assertNoArm(driver, hal);
    }
    for (OSObject *availability : {
            static_cast<OSObject *>(new OSNumber(0)),
            static_cast<OSObject *>(new OSNumber(2)),
            static_cast<OSObject *>(kOSBooleanTrue),
            static_cast<OSObject *>(new OSString("1")),
            static_cast<OSObject *>(nullptr)}) {
        AirportItlwm driver; ItlIwx hal; RequestObjects input;
        configureProfile(driver, one); driver.fHalService = &hal;
        if (availability)
            driver.properties["NativeP2PRx149DataInputProfileEnabled"] = availability;
        else
            driver.properties.erase("NativeP2PRx149DataInputProfileEnabled");
        assert(invoke(driver, input.request) == kIOReturnUnsupported);
        assertNoArm(driver, hal);
        if (availability != kOSBooleanTrue)
            delete availability;
    }
    {
        AirportItlwm driver; RequestObjects input; OSNumber availability(1);
        configureProfile(driver, availability);
        assert(invoke(driver, input.request) == kIOReturnNotReady);
    }
    {
        AirportItlwm driver; ItlIwx hal; RequestObjects input;
        configureProfile(driver, one); driver.fHalService = &hal;
        _fCommandGate = nullptr;
        assert(invoke(driver, input.request) == kIOReturnNotReady);
        assertNoArm(driver, hal);
        _fCommandGate = &commandGate;
        _fWorkloop = nullptr;
        assert(invoke(driver, input.request) == kIOReturnNotReady);
        assertNoArm(driver, hal);
        _fWorkloop = &workLoop;
    }
}

static void testExactFiveKeysAndValidators() {
    OSNumber one(1);
    for (unsigned missing = 0; missing < 5; ++missing) {
        AirportItlwm driver; ItlIwx hal; RequestObjects input;
        configureProfile(driver, one); driver.fHalService = &hal;
        const char *keys[] = {"NativeP2PDirectedDataOnce",
            "NativeP2PDirectedDataPeerMAC", "NativeP2PDirectedDataLocalIPv6",
            "NativeP2PDirectedDataNonce", "NativeP2PDirectedDataRunToken"};
        input.request.entries.erase(keys[missing]);
        const auto result = invoke(driver, input.request);
        if (result != kIOReturnBadArgument)
            std::fprintf(stderr, "missing-key case %u result=%d\\n", missing, result);
        assert(result == kIOReturnBadArgument);
        assertNoArm(driver, hal);
    }
    for (const char *legacy : {
            "NativeP2PArmOnce", "NativeP2PRx149ArmOnce",
            "NativeP2PRx149RunToken", "NativeP2PDirectedPrepareOnce",
            "NativeP2PDirectedPreparePeerMAC",
            "NativeP2PDirectedPrepareRunToken", "UnrelatedExtra"}) {
        AirportItlwm driver; ItlIwx hal; RequestObjects input;
        configureProfile(driver, one); driver.fHalService = &hal;
        input.request.add(legacy, kOSBooleanTrue);
        const auto result = invoke(driver, input.request);
        if (result != kIOReturnBadArgument)
            std::fprintf(stderr, "mixed-key case %s result=%d\\n", legacy, result);
        assert(result == kIOReturnBadArgument);
        assertNoArm(driver, hal);
    }
    {
        AirportItlwm driver; ItlIwx hal; RequestObjects input;
        configureProfile(driver, one); driver.fHalService = &hal;
        input.once = OSBoolean(false);
        input.request.add("NativeP2PDirectedDataOnce", &input.once);
        assert(invoke(driver, input.request) == kIOReturnBadArgument);
        assertNoArm(driver, hal);
    }
    for (unsigned invalid = 0; invalid < 8; ++invalid) {
        AirportItlwm driver; ItlIwx hal; RequestObjects input;
        configureProfile(driver, one); driver.fHalService = &hal;
        if (invalid == 0) input.peer = OSData(bytes({1, 2, 3, 4, 5, 6}));
        if (invalid == 1) input.peer = OSData(bytes({0, 0, 0, 0, 0, 0}));
        if (invalid == 2) input.peer = OSData(bytes({2, 1, 2, 3, 4}));
        if (invalid == 3) input.local = OSData(bytes({0xfe, 0x81, 0, 0, 0, 0, 0, 0,
                                                       0, 1, 2, 3, 4, 5, 6, 7}));
        if (invalid == 4) input.local = OSData(bytes({0xfe, 0x80, 0, 0, 0, 0, 0, 1,
                                                       0, 1, 2, 3, 4, 5, 6, 7}));
        if (invalid == 5) input.local = OSData(bytes({0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                                       0, 0, 0, 0, 0, 0, 0, 0}));
        if (invalid == 6) input.nonce = OSData(bytes({0, 0, 0, 0, 0, 0, 0, 0}));
        if (invalid == 7) input.token = OSString("00000000000000000000000000000000");
        input.request.add("NativeP2PDirectedDataPeerMAC", &input.peer);
        input.request.add("NativeP2PDirectedDataLocalIPv6", &input.local);
        input.request.add("NativeP2PDirectedDataNonce", &input.nonce);
        input.request.add("NativeP2PDirectedDataRunToken", &input.token);
        const auto result = invoke(driver, input.request);
        if (result != kIOReturnBadArgument)
            std::fprintf(stderr, "invalid-field case %u result=%d\\n", invalid, result);
        assert(result == kIOReturnBadArgument);
        assertNoArm(driver, hal);
    }
    {
        AirportItlwm driver; ItlIwx hal; RequestObjects input;
        configureProfile(driver, one); driver.fHalService = &hal;
        input.request.add("NativeP2PDirectedDataReady", kOSBooleanFalse);
        assert(invoke(driver, input.request) == kIOReturnUnsupported);
        assertNoArm(driver, hal);
    }
}
#endif

int main() {
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
    testAvailabilityNumberGate();
    testReadonlyPrefix();
    testExactArmSuccessAndReceiptFailures();
    testExactTwoPacketArm();
    testAuthorizationAndProfileGates();
    testExactFiveKeysAndValidators();
#else
    AirportItlwm driver; ItlIwx hal; RequestObjects input; OSNumber one(1);
    configureProfile(driver, one); driver.fHalService = &hal;
    const auto disabledResult = invoke(driver, input.request);
    if (disabledResult != kIOReturnUnsupported)
        std::fprintf(stderr, "disabled Data setter result=%d\\n", disabledResult);
    assert(disabledResult == kIOReturnUnsupported);
    assert(hal.dataArmCalls == 0);
    assert(driver.parentCalls == 0);
#endif
}
"""


def compile_and_run(enabled: bool) -> None:
    feature = "ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332"
    code = "#include <cstdint>\n" + DATA_ARM + "\n" + SHIM + "\n" + HELPERS + "\n"
    if enabled:
        code += "#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332\n"
        code += READONLY_HELPER + "\n" + DATA_CALLBACK_CONTEXT + "\n" + DATA_CALLBACK
        code += "\n#endif\n"
    code += r"""
static IOReturn invokeLegacyRxCallback(OSObject *target, void *argument,
                                      void *a, void *b, void *c) {
    return armNativeRx149OnMainGate(target, argument, a, b, c);
}
"""
    code += SETTER + "\n" + BODY
    with tempfile.TemporaryDirectory(prefix="itlwm-test107-data-v2-") as directory:
        cpp = Path(directory) / "directed_data_v2.cpp"
        exe = Path(directory) / "directed_data_v2"
        cpp.write_text(code)
        subprocess.run([
            "xcrun", "clang++", "-std=c++14", "-O1", "-Wall", "-Wextra",
            "-Werror", "-Wno-unused-function", "-Wno-unused-const-variable",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            f"-D{feature}={1 if enabled else 0}", str(cpp), "-o", str(exe),
        ], check=True)
        subprocess.run([str(exe)], check=True)


def main() -> None:
    compile_and_run(False)
    compile_and_run(True)
    print("PASS: Test107 production Data admin path, strict profile gates, read-only namespace, exact Arm forwarding, and receipt failure behavior (ASan/UBSan, feature macro 0/1)")


if __name__ == "__main__":
    main()
