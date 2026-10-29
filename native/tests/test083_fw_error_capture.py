#!/usr/bin/env python3
"""Fault-inject the real Tahoe firmware error-table capture action.

The test extracts the production table declarations, status helpers, and
`_tahoe_fw_error_snapshot_action` from ItlIwx.cpp. Only the kernel services
(main-gate state, MMIO, delay/clock, softc, and owner storage) are replaced.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"


def extract_braced_declaration(text: str, marker: str, include_semicolon: bool) -> str:
    start = text.find(marker)
    if start < 0:
        raise AssertionError(f"production marker missing: {marker}")
    opening = text.find("{", start)
    if opening < 0:
        raise AssertionError(f"opening brace missing after: {marker}")
    depth = 0
    state = "code"
    escaped = False
    i = opening
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if state == "line_comment":
            if ch == "\n":
                state = "code"
        elif state == "block_comment":
            if ch == "*" and nxt == "/":
                state = "code"
                i += 1
        elif state in ("string", "char"):
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif (state == "string" and ch == '"') or (
                state == "char" and ch == "'"
            ):
                state = "code"
        else:
            if ch == "/" and nxt == "/":
                state = "line_comment"
                i += 1
            elif ch == "/" and nxt == "*":
                state = "block_comment"
                i += 1
            elif ch == '"':
                state = "string"
            elif ch == "'":
                state = "char"
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    if include_semicolon:
                        semicolon = text.find(";", end)
                        if semicolon < 0:
                            raise AssertionError(f"semicolon missing after: {marker}")
                        end = semicolon + 1
                    return text[start:end]
        i += 1
    raise AssertionError(f"unclosed production block: {marker}")


def production_blocks() -> str:
    source = SOURCE.read_text()
    markers = [
        ("struct iwx_error_event_table {", True),
        ("struct iwx_umac_error_event_table {", True),
        ("struct TahoeFirmwareErrorCaptureRequest {", True),
        ("static uint32_t tahoeFirmwareErrorPointerStatus(", False),
        ("static bool tahoeFirmwareErrorTableWasRead(", False),
        ("static bool tahoeFirmwareErrorTableValidIsSuspect(", False),
        ("static bool tahoeFirmwareErrorDeadlineExpired(", False),
        ("static bool tahoeFirmwareReadErrorTableWords(", False),
        ("static void tahoeSetUnreadTableStatus(", False),
        ("IOReturn ItlIwx::_tahoe_fw_error_snapshot_action(", False),
        ("void ItlIwx::tahoeFreezeFirmwareMetadata(", False),
    ]
    blocks = "\n\n".join(
        extract_braced_declaration(source, marker, semicolon)
        for marker, semicolon in markers
    )
    sample_block = extract_braced_declaration(
        source, "if (!nativeFwDiagnosticTraceFrozen_ &&", False)
    return blocks + "\n\nvoid ItlIwx::runFirmwareTraceSample(struct iwx_softc *sc, bool forceTraceSample) {\n" + \
        "    const uint64_t now = tahoeMonotonicNs();\n" + \
        "    constexpr uint64_t kLiveSampleIntervalNs = 5ULL * 1000000000ULL;\n" + \
        sample_block + "\n}\n"


HARNESS = r'''#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include "native/iwx_fw_diagnostics.hpp"

static uint32_t le32toh(uint32_t value) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return __builtin_bswap32(value);
#else
    return value;
#endif
}
static uint32_t htole32(uint32_t value) { return le32toh(value); }

#define __packed __attribute__((packed))
#define IWX_CSR_GP_CNTRL 0x024U
#define IWX_HBUS_BASE 0x400U
#define IWX_HBUS_TARG_MEM_RADDR (IWX_HBUS_BASE + 0x00cU)
#define IWX_HBUS_TARG_MEM_RDAT (IWX_HBUS_BASE + 0x01cU)
#define IWX_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY 0x00000001U
#define IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ 0x00000008U
#define IWX_CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP 0x00000010U
#define IWX_ERROR_EVENT_TABLE_LMAC1 (1U << 0)
#define IWX_ERROR_EVENT_TABLE_UMAC (1U << 2)
#define IWX_FW_ADDR_CACHE_CONTROL 0xC0000000U

using IOReturn = int;
constexpr IOReturn kIOReturnSuccess = 0;
constexpr IOReturn kIOReturnBadArgument = -1;
struct OSObject {};

static uint64_t g_now_ns = 100000000ULL;
static uint64_t tahoeMonotonicNs() { return g_now_ns; }

struct iwx_softc;
class ItlIwx;
struct MmioOp { char kind; uint32_t reg; uint32_t value; };
struct FakeMMIO {
    uint32_t gp = IWX_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY | 0x2U;
    uint32_t gp_read_override = UINT32_MAX;
    uint32_t grant_mode = 0; // 0=grant, 1=deny but retain our request
    bool retain_request_on_release = false;
    uint32_t read_latency_ns = 1000;
    uint32_t hbus_address = 0;
    uint32_t read_words = 0;
    uint32_t mutate_after_word = 0;
    uint32_t mutation_kind = 0; // 1=firmware generation, 2=TLV generation, 3=sc generation
    std::unordered_map<uint32_t, uint32_t> memory;
    std::vector<MmioOp> ops;
    ItlIwx *owner = nullptr;
    iwx_softc *sc = nullptr;
};

struct iwx_ucode_status {
    uint32_t uc_lmac_error_event_table[2]{};
    uint32_t uc_umac_error_event_table = 0;
    unsigned int error_event_table_tlv_status = 0;
    int uc_ok = 0;
};
struct iwx_softc {
    uint32_t sc_generation = 0;
    iwx_ucode_status sc_uc{};
    int sc_nic_locks = 0;
    FakeMMIO *mmio = nullptr;
};

namespace IwxResetTrace {
struct Snapshot {
    uint32_t lastInitTaskTrigger = 0;
    uint32_t lastInitTaskTriggerSequence = 0;
};
struct Trace {
    bool available = false;
    Snapshot value{};
    bool read(Snapshot *out) const {
        if (!available || !out) return false;
        *out = value;
        return true;
    }
};
}

class ItlIwx {
public:
    struct iwx_softc com{};
    uint32_t nativeFwDiagnosticAliveGeneration_ = 0;
    uint32_t nativeFwDiagnosticTlvGeneration_ = 0;
    uint32_t nativeFwDiagnosticExpectedLmacTable_[2]{};
    uint32_t nativeFwDiagnosticExpectedUmacTable_ = 0;
    IwxFirmwareDiagnostics::FirmwareErrorSnapshot nativeFwErrorSnapshot_{};
    uint32_t nativeFwDiagnosticCaptureStatus_ = 0;
    uint32_t nativeFwDiagnosticCaptureGeneration_ = 0;
    IwxFirmwareDiagnostics::TraceRing nativeFwDiagnosticTrace_{};
    IwxFirmwareDiagnostics::TraceSnapshot nativeFwDiagnosticPendingTrace_{};
    uint32_t nativeFwDiagnosticPendingTraceGeneration_ = 0;
    uint32_t nativeFwDiagnosticPendingWatchdogSequence_ = 0;
    uint32_t nativeFwDiagnosticPendingTracePresent_ = 0;
    uint32_t nativeFwDiagnosticTraceFrozen_ = 0;
    uint32_t nativeFwDiagnosticTraceManualLatched_ = 0;
    uint64_t nativeFwDiagnosticTraceLastSampleNs_ = 0;
    IwxResetTrace::Trace nativeResetTrace_{};
    bool mainGate = true;
    std::vector<IwxFirmwareDiagnostics::Entry> metadata;

    bool tahoeP2pOnMainGate() const { return mainGate; }
    void runFirmwareTraceSample(struct iwx_softc *, bool forceTraceSample);
    void tahoeFreezeFirmwareMetadata(struct iwx_softc *, uint32_t);
    void tahoeRecordFirmwareMetadata(
        struct iwx_softc *, IwxFirmwareDiagnostics::Entry entry) {
        metadata.push_back(entry);
    }
    static IOReturn _tahoe_fw_error_snapshot_action(
        OSObject *, void *, void *, void *, void *);
};

static uint32_t fakeRead(iwx_softc *sc, uint32_t reg);
static void fakeWrite(iwx_softc *sc, uint32_t reg, uint32_t value);
static void fakeDelay(uint32_t usec) { g_now_ns += uint64_t(usec) * 1000U; }
#define IWX_READ(sc, reg) fakeRead((sc), (reg))
#define IWX_WRITE(sc, reg, value) fakeWrite((sc), (reg), (value))
#define IWX_CLRBITS(sc, reg, mask) \
    IWX_WRITE((sc), (reg), IWX_READ((sc), (reg)) & ~(mask))
#define DELAY(usec) fakeDelay((usec))

static uint32_t fakeRead(iwx_softc *sc, uint32_t reg) {
    FakeMMIO *bus = sc->mmio;
    if (reg == IWX_CSR_GP_CNTRL) {
        bus->ops.push_back({'R', reg, bus->gp});
        return bus->gp;
    }
    if (reg == IWX_HBUS_TARG_MEM_RDAT) {
        const uint32_t value = bus->memory.count(bus->hbus_address)
            ? bus->memory[bus->hbus_address] : 0U;
        bus->ops.push_back({'R', reg, htole32(value)});
        ++bus->read_words;
        bus->hbus_address += sizeof(uint32_t);
        g_now_ns += bus->read_latency_ns;
        if (bus->mutate_after_word != 0 &&
            bus->read_words == bus->mutate_after_word) {
            if (bus->mutation_kind == 1)
                ++bus->owner->nativeFwDiagnosticAliveGeneration_;
            else if (bus->mutation_kind == 2)
                ++bus->owner->nativeFwDiagnosticTlvGeneration_;
            else if (bus->mutation_kind == 3)
                ++bus->sc->sc_generation;
        }
        return htole32(value);
    }
    bus->ops.push_back({'R', reg, 0U});
    return 0U;
}

static void fakeWrite(iwx_softc *sc, uint32_t reg, uint32_t value) {
    FakeMMIO *bus = sc->mmio;
    bus->ops.push_back({'W', reg, value});
    if (reg == IWX_CSR_GP_CNTRL) {
        if ((value & IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ) != 0) {
            if (bus->grant_mode == 1U)
                bus->gp = (value & ~IWX_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY) |
                    IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ;
            else
                bus->gp = value | IWX_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY |
                    IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ;
        } else if (bus->retain_request_on_release &&
                   (bus->gp & IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ) != 0) {
            bus->gp = value | IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ;
        } else {
            bus->gp = value;
        }
    } else if (reg == IWX_HBUS_TARG_MEM_RADDR) {
        bus->hbus_address = value;
    }
}

''' + production_blocks() + r'''

#define CHECK(expr) do { \
    if (!(expr)) { \
        std::cerr << "assertion failed: " << #expr << " at " \
                  << __FILE__ << ":" << __LINE__ << "\n"; \
        return 1; \
    } \
} while (0)

static constexpr uint32_t kGeneration = 7U;
static constexpr uint32_t kLmacAddress = 0x00401000U;
static constexpr uint32_t kUmacAddress = 0x00402000U;
static constexpr uint32_t kOtherGpFlag = 0x2U;

static void seedWords(FakeMMIO &bus, uint32_t address, size_t count,
                      uint32_t valid, uint32_t errorId) {
    for (size_t i = 0; i < count; ++i)
        bus.memory[address + uint32_t(i * 4U)] = 0x11000000U + uint32_t(i);
    bus.memory[address] = valid;
    if (count > 1U)
        bus.memory[address + 4U] = errorId;
}

static void setup(ItlIwx &owner, FakeMMIO &bus, uint32_t lmacValid = 1U,
                  uint32_t umacValid = 1U) {
    g_now_ns = 100000000ULL;
    owner = ItlIwx{};
    bus = FakeMMIO{};
    owner.com.mmio = &bus;
    owner.com.sc_generation = kGeneration;
    owner.com.sc_uc.uc_ok = 1;
    owner.com.sc_uc.error_event_table_tlv_status =
        IWX_ERROR_EVENT_TABLE_LMAC1 | IWX_ERROR_EVENT_TABLE_UMAC;
    owner.com.sc_uc.uc_lmac_error_event_table[0] = kLmacAddress;
    owner.com.sc_uc.uc_umac_error_event_table =
        kUmacAddress | IWX_FW_ADDR_CACHE_CONTROL;
    owner.nativeFwDiagnosticAliveGeneration_ = kGeneration;
    owner.nativeFwDiagnosticTlvGeneration_ = kGeneration;
    owner.nativeFwDiagnosticExpectedLmacTable_[0] = kLmacAddress;
    owner.nativeFwDiagnosticExpectedUmacTable_ = kUmacAddress;
    owner.nativeResetTrace_.available = true;
    owner.nativeResetTrace_.value.lastInitTaskTrigger = 3U;
    owner.nativeResetTrace_.value.lastInitTaskTriggerSequence = 19U;
    bus.owner = &owner;
    bus.sc = &owner.com;
    IwxFirmwareDiagnostics::initialize(&owner.nativeFwDiagnosticTrace_);
    seedWords(bus, kLmacAddress, sizeof(iwx_error_event_table) / 4U,
              lmacValid, 0x1a2b3c4dU);
    seedWords(bus, kUmacAddress, sizeof(iwx_umac_error_event_table) / 4U,
              umacValid, 0x5a6b7c8dU);
}

static TahoeFirmwareErrorCaptureRequest request() {
    return TahoeFirmwareErrorCaptureRequest{55U, kGeneration, 12U, 9U, 1U, 42U};
}

static IOReturn run(ItlIwx &owner, struct iwx_softc *sc,
                    TahoeFirmwareErrorCaptureRequest *req) {
    return ItlIwx::_tahoe_fw_error_snapshot_action(
        nullptr, &owner, sc, req, nullptr);
}

static uint32_t getStatus(uint32_t value) { return value; }

static int case_layout_and_pointer_helpers() {
    CHECK(sizeof(iwx_error_event_table) == 152U);
    CHECK(sizeof(iwx_umac_error_event_table) == 60U);
    using IwxFirmwareDiagnostics::TableStatus;
    const size_t lmacBytes = sizeof(iwx_error_event_table);
    CHECK(tahoeFirmwareErrorPointerStatus(false, 0x401000U, 0x401000U,
        lmacBytes) == getStatus(static_cast<uint32_t>(TableStatus::MissingPointer)));
    CHECK(tahoeFirmwareErrorPointerStatus(true, 0U, 0x401000U, lmacBytes) ==
        getStatus(static_cast<uint32_t>(TableStatus::MissingPointer)));
    CHECK(tahoeFirmwareErrorPointerStatus(true, 0x401000U, 0x402000U,
        lmacBytes) == getStatus(static_cast<uint32_t>(TableStatus::PointerMismatch)));
    CHECK(tahoeFirmwareErrorPointerStatus(true, 0x400001U, 0x400001U,
        lmacBytes) == getStatus(static_cast<uint32_t>(TableStatus::MisalignedPointer)));
    CHECK(tahoeFirmwareErrorPointerStatus(true, 0x100000U, 0x100000U,
        lmacBytes) == getStatus(static_cast<uint32_t>(TableStatus::InvalidPointer)));
    CHECK(tahoeFirmwareErrorPointerStatus(true, 0xfffffffcU, 0xfffffffcU,
        lmacBytes) == getStatus(static_cast<uint32_t>(TableStatus::RangeUnproven)));
    CHECK(tahoeFirmwareErrorPointerStatus(true, 0x401000U, 0x401000U,
        lmacBytes) == getStatus(static_cast<uint32_t>(TableStatus::NotAttempted)));
    return 0;
}

static int case_capture_real_fields_and_release() {
    ItlIwx owner; FakeMMIO bus; setup(owner, bus);
    auto req = request();
    CHECK(run(owner, &owner.com, &req) == kIOReturnSuccess);
    const auto &s = owner.nativeFwErrorSnapshot_;
    using IwxFirmwareDiagnostics::CaptureStatus;
    using IwxFirmwareDiagnostics::TableStatus;
    CHECK(s.capture_status == static_cast<uint32_t>(CaptureStatus::Captured));
    CHECK(s.snapshot_complete == 1U);
    CHECK(s.lmac_status == static_cast<uint32_t>(TableStatus::Captured));
    CHECK(s.umac_status == static_cast<uint32_t>(TableStatus::Captured));
    CHECK(s.lmac_valid_present == 1U && s.lmac_valid == 1U);
    CHECK(s.lmac_error_id_present == 1U && s.lmac_error_id == 0x1a2b3c4dU);
    CHECK(s.lmac_trm_status0 == 0x11000002U);
    CHECK(s.umac_valid_present == 1U && s.umac_valid == 1U);
    CHECK(s.umac_error_id_present == 1U && s.umac_error_id == 0x5a6b7c8dU);
    CHECK(s.umac_major == 0x11000009U && s.umac_minor == 0x1100000aU);
    CHECK(s.umac_command_header == 0x1100000dU);
    CHECK(s.read_word_count == sizeof(iwx_error_event_table) / 4U +
          sizeof(iwx_umac_error_event_table) / 4U);
    CHECK(s.read_word_count == bus.read_words);
    CHECK(s.lmac_read_word_count == sizeof(iwx_error_event_table) / 4U);
    CHECK(s.umac_read_word_count == sizeof(iwx_umac_error_event_table) / 4U);
    CHECK(s.driver_generation == kGeneration && s.firmware_generation == kGeneration);
    CHECK(s.reset_reason == req.resetReason); // error-table contents never rewrite the caller's reason
    CHECK(s.latest_init_trigger == 3U && s.latest_init_trigger_sequence == 19U);
    CHECK(owner.com.sc_nic_locks == 0);
    CHECK((bus.gp & IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ) == 0U);
    CHECK((bus.gp & kOtherGpFlag) != 0U);
    CHECK(owner.metadata.size() == 1U);
    CHECK(owner.metadata[0].phase == static_cast<uint32_t>(
        IwxFirmwareDiagnostics::Phase::FirmwareErrorTableCapture));
    std::vector<uint32_t> addresses;
    for (const auto &op : bus.ops)
        if (op.kind == 'W' && op.reg == IWX_HBUS_TARG_MEM_RADDR)
            addresses.push_back(op.value);
    CHECK(addresses.size() == 2U);
    CHECK(addresses[0] == kLmacAddress && addresses[1] == kUmacAddress);
    return 0;
}

static int case_empty_tables_are_valid_capture() {
    ItlIwx owner; FakeMMIO bus; setup(owner, bus, 0U, 0U);
    auto req = request();
    CHECK(run(owner, &owner.com, &req) == kIOReturnSuccess);
    using IwxFirmwareDiagnostics::CaptureStatus;
    using IwxFirmwareDiagnostics::TableStatus;
    const auto &s = owner.nativeFwErrorSnapshot_;
    CHECK(s.capture_status == static_cast<uint32_t>(CaptureStatus::Captured));
    CHECK(s.snapshot_complete == 1U);
    CHECK(s.lmac_status == static_cast<uint32_t>(TableStatus::Empty));
    CHECK(s.umac_status == static_cast<uint32_t>(TableStatus::Empty));
    CHECK(s.lmac_valid_present == 1U && s.lmac_valid == 0U);
    CHECK(s.umac_valid_present == 1U && s.umac_valid == 0U);
    CHECK(s.read_word_count == bus.read_words && bus.read_words == 53U);
    CHECK((bus.gp & IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ) == 0U);
    return 0;
}

static int case_invalid_pointer_inputs_do_not_touch_hbus() {
    using IwxFirmwareDiagnostics::TableStatus;
    for (uint32_t mode = 0; mode < 5U; ++mode) {
        ItlIwx owner; FakeMMIO bus; setup(owner, bus);
        auto &sc = owner.com;
        if (mode == 0U) {
            sc.sc_uc.error_event_table_tlv_status = 0U;
        } else if (mode == 1U) {
            owner.nativeFwDiagnosticExpectedLmacTable_[0] = 0U;
            owner.nativeFwDiagnosticExpectedUmacTable_ = 0U;
        } else if (mode == 2U) {
            sc.sc_uc.uc_lmac_error_event_table[0] += 4U;
            sc.sc_uc.uc_umac_error_event_table =
                (kUmacAddress + 4U) | IWX_FW_ADDR_CACHE_CONTROL;
        } else if (mode == 3U) {
            owner.nativeFwDiagnosticExpectedLmacTable_[0] = 0x400001U;
            owner.nativeFwDiagnosticExpectedUmacTable_ = 0x400001U;
            sc.sc_uc.uc_lmac_error_event_table[0] = 0x400001U;
            sc.sc_uc.uc_umac_error_event_table = 0x400001U |
                IWX_FW_ADDR_CACHE_CONTROL;
        } else {
            owner.nativeFwDiagnosticExpectedLmacTable_[0] = 0xfffffffcU;
            owner.nativeFwDiagnosticExpectedUmacTable_ = 0xfffffffcU;
            sc.sc_uc.uc_lmac_error_event_table[0] = 0xfffffffcU;
            sc.sc_uc.uc_umac_error_event_table = 0xfffffffcU |
                IWX_FW_ADDR_CACHE_CONTROL;
        }
        auto req = request();
        CHECK(run(owner, &sc, &req) == kIOReturnSuccess);
        CHECK(bus.read_words == 0U);
        for (const auto &op : bus.ops)
            CHECK(!(op.kind == 'W' && op.reg == IWX_HBUS_TARG_MEM_RADDR));
        for (const auto &op : bus.ops)
            CHECK(!(op.kind == 'W' && op.reg == IWX_CSR_GP_CNTRL));
        CHECK((bus.gp & IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ) == 0U);
        const auto &s = owner.nativeFwErrorSnapshot_;
        CHECK(s.snapshot_complete == 0U);
        CHECK(s.lmac_valid_present == 0U && s.umac_valid_present == 0U);
        CHECK(s.lmac_status != static_cast<uint32_t>(TableStatus::Captured));
        CHECK(s.umac_status != static_cast<uint32_t>(TableStatus::Captured));
    }
    return 0;
}

static int case_one_invalid_table_does_not_read_that_table() {
    ItlIwx owner; FakeMMIO bus; setup(owner, bus);
    owner.nativeFwDiagnosticExpectedUmacTable_ = 0U;
    auto req = request();
    CHECK(run(owner, &owner.com, &req) == kIOReturnSuccess);
    using IwxFirmwareDiagnostics::CaptureStatus;
    using IwxFirmwareDiagnostics::TableStatus;
    const auto &s = owner.nativeFwErrorSnapshot_;
    CHECK(s.capture_status == static_cast<uint32_t>(CaptureStatus::Partial));
    CHECK(s.snapshot_complete == 0U);
    CHECK(s.lmac_status == static_cast<uint32_t>(TableStatus::Captured));
    CHECK(s.umac_status == static_cast<uint32_t>(TableStatus::MissingPointer));
    CHECK(s.lmac_read_word_count == sizeof(iwx_error_event_table) / 4U);
    CHECK(s.umac_read_word_count == 0U && s.umac_valid_present == 0U);
    std::vector<uint32_t> addresses;
    for (const auto &op : bus.ops)
        if (op.kind == 'W' && op.reg == IWX_HBUS_TARG_MEM_RADDR)
            addresses.push_back(op.value);
    CHECK(addresses.size() == 1U && addresses[0] == kLmacAddress);
    CHECK(owner.com.sc_nic_locks == 0);
    CHECK((bus.gp & IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ) == 0U);
    return 0;
}

static int case_wrong_owner_gate_busy_and_existing_request_are_not_stolen() {
    ItlIwx owner; FakeMMIO bus; setup(owner, bus);
    ItlIwx other; FakeMMIO otherBus; setup(other, otherBus);
    auto req = request();
    CHECK(run(owner, &other.com, &req) == kIOReturnBadArgument);
    CHECK(bus.ops.empty() && owner.metadata.empty());

    owner.mainGate = false;
    CHECK(run(owner, &owner.com, &req) == kIOReturnBadArgument);
    CHECK(bus.ops.empty() && owner.metadata.empty());
    owner.mainGate = true;

    owner.com.sc_nic_locks = 1;
    CHECK(run(owner, &owner.com, &req) == kIOReturnSuccess);
    CHECK(owner.com.sc_nic_locks == 1);
    CHECK(bus.read_words == 0U);
    for (const auto &op : bus.ops)
        CHECK(!(op.kind == 'W' && (op.reg == IWX_CSR_GP_CNTRL ||
                                   op.reg == IWX_HBUS_TARG_MEM_RADDR)));

    setup(owner, bus);
    bus.gp |= IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ;
    CHECK(run(owner, &owner.com, &req) == kIOReturnSuccess);
    CHECK((bus.gp & IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ) != 0U);
    CHECK(bus.read_words == 0U);
    for (const auto &op : bus.ops)
        CHECK(!(op.kind == 'W' && (op.reg == IWX_CSR_GP_CNTRL ||
                                   op.reg == IWX_HBUS_TARG_MEM_RADDR)));
    using IwxFirmwareDiagnostics::CaptureStatus;
    CHECK(owner.nativeFwErrorSnapshot_.capture_status ==
          static_cast<uint32_t>(CaptureStatus::NicAccessBusy));
    return 0;
}

static int case_failed_grant_clears_only_our_request() {
    ItlIwx owner; FakeMMIO bus; setup(owner, bus);
    bus.grant_mode = 1U;
    auto req = request();
    CHECK(run(owner, &owner.com, &req) == kIOReturnSuccess);
    using IwxFirmwareDiagnostics::CaptureStatus;
    using IwxFirmwareDiagnostics::TableStatus;
    CHECK(owner.nativeFwErrorSnapshot_.capture_status ==
          static_cast<uint32_t>(CaptureStatus::NicAccessUnavailable));
    CHECK(owner.nativeFwErrorSnapshot_.lmac_status ==
          static_cast<uint32_t>(TableStatus::NicAccessUnavailable));
    CHECK(owner.com.sc_nic_locks == 0);
    CHECK(bus.read_words == 0U);
    std::vector<uint32_t> gpWrites;
    for (const auto &op : bus.ops)
        if (op.kind == 'W' && op.reg == IWX_CSR_GP_CNTRL)
            gpWrites.push_back(op.value);
    CHECK(gpWrites.size() == 2U);
    CHECK((gpWrites[0] & IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ) != 0U);
    CHECK((gpWrites[1] & IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ) == 0U);
    CHECK((gpWrites[1] & kOtherGpFlag) != 0U);
    CHECK((bus.gp & IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ) == 0U);
    return 0;
}

static int case_suspicious_valid_sentinel_is_not_complete_or_a_cause() {
    using IwxFirmwareDiagnostics::CaptureStatus;
    using IwxFirmwareDiagnostics::TableStatus;
    const uint32_t sentinels[] = {
        UINT32_MAX, 0xa5a5a5a5U, 0x5a5a5a5aU
    };
    for (uint32_t sentinel : sentinels) {
        ItlIwx owner; FakeMMIO bus; setup(owner, bus, sentinel, 1U);
        auto req = request();
        CHECK(run(owner, &owner.com, &req) == kIOReturnSuccess);
        const auto &s = owner.nativeFwErrorSnapshot_;
        CHECK(s.capture_status == static_cast<uint32_t>(CaptureStatus::Partial));
        CHECK(s.snapshot_complete == 0U);
        CHECK(s.lmac_status == static_cast<uint32_t>(TableStatus::SuspectContents));
        CHECK(s.umac_status == static_cast<uint32_t>(TableStatus::Captured));
        CHECK(s.lmac_valid_present == 1U && s.lmac_valid == sentinel);
        CHECK(s.lmac_error_id_present == 1U && s.lmac_error_id == 0x1a2b3c4dU);
        CHECK(s.reset_reason == req.resetReason);
        CHECK(s.capture_status != s.lmac_error_id);
        CHECK(owner.metadata.size() == 1U);
        CHECK(owner.metadata[0].result_detail ==
              ((static_cast<uint32_t>(TableStatus::SuspectContents) << 16) |
               static_cast<uint32_t>(TableStatus::Captured)));
        CHECK((bus.gp & IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ) == 0U);
    }
    return 0;
}

static int case_budget_abort_counts_actual_words_and_keeps_unread_fields_absent() {
    ItlIwx owner; FakeMMIO bus; setup(owner, bus);
    bus.read_latency_ns = 450000U;
    auto req = request();
    CHECK(run(owner, &owner.com, &req) == kIOReturnSuccess);
    using IwxFirmwareDiagnostics::CaptureStatus;
    using IwxFirmwareDiagnostics::TableStatus;
    const auto &s = owner.nativeFwErrorSnapshot_;
    CHECK(s.capture_status == static_cast<uint32_t>(CaptureStatus::ReadBudgetExceeded));
    CHECK(s.snapshot_complete == 0U);
    CHECK(s.read_word_count == bus.read_words);
    CHECK(s.read_word_count > 0U && s.read_word_count < 53U);
    CHECK(s.read_word_count == s.lmac_read_word_count + s.umac_read_word_count);
    CHECK(s.lmac_status == static_cast<uint32_t>(TableStatus::ReadBudgetExceeded) ||
          s.umac_status == static_cast<uint32_t>(TableStatus::ReadBudgetExceeded));
    CHECK(s.lmac_valid_present == (s.lmac_read_word_count >= 1U ? 1U : 0U));
    CHECK(s.lmac_error_id_present == (s.lmac_read_word_count >= 2U ? 1U : 0U));
    CHECK(s.umac_valid_present == (s.umac_read_word_count >= 1U ? 1U : 0U));
    CHECK(s.umac_error_id_present == (s.umac_read_word_count >= 2U ? 1U : 0U));
    if (s.lmac_read_word_count < sizeof(iwx_error_event_table) / 4U)
        CHECK(s.lmac_trm_status0 == 0U);
    if (s.umac_read_word_count < sizeof(iwx_umac_error_event_table) / 4U)
        CHECK(s.umac_major == 0U && s.umac_minor == 0U);
    CHECK(s.read_budget_ns == 5000000ULL);
    CHECK(owner.com.sc_nic_locks == 0);
    CHECK((bus.gp & IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ) == 0U);
    bool sawRequest = false, sawRelease = false;
    for (const auto &op : bus.ops) {
        if (op.kind == 'W' && op.reg == IWX_CSR_GP_CNTRL) {
            if (op.value & IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ) sawRequest = true;
            else if (sawRequest) sawRelease = true;
        }
    }
    CHECK(sawRequest && sawRelease);
    return 0;
}

static int case_generation_change_during_read_is_stale_and_released() {
    for (uint32_t mutation = 1U; mutation <= 3U; ++mutation) {
        ItlIwx owner; FakeMMIO bus; setup(owner, bus);
        bus.mutate_after_word = 3U;
        bus.mutation_kind = mutation;
        auto req = request();
        CHECK(run(owner, &owner.com, &req) == kIOReturnSuccess);
        using IwxFirmwareDiagnostics::CaptureStatus;
        using IwxFirmwareDiagnostics::TableStatus;
        const auto &s = owner.nativeFwErrorSnapshot_;
        CHECK(s.capture_status == static_cast<uint32_t>(CaptureStatus::StaleGeneration));
        CHECK(s.snapshot_complete == 0U);
        CHECK(s.lmac_status == static_cast<uint32_t>(TableStatus::StaleGeneration));
        CHECK(s.umac_status == static_cast<uint32_t>(TableStatus::StaleGeneration));
        CHECK(bus.read_words >= 3U);
        CHECK(owner.com.sc_nic_locks == 0);
        CHECK((bus.gp & IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ) == 0U);
    }
    return 0;
}

static int case_release_failure_is_reported_after_clear_attempt() {
    ItlIwx owner; FakeMMIO bus; setup(owner, bus);
    bus.retain_request_on_release = true;
    auto req = request();
    CHECK(run(owner, &owner.com, &req) == kIOReturnSuccess);
    using IwxFirmwareDiagnostics::CaptureStatus;
    using IwxFirmwareDiagnostics::TableStatus;
    const auto &s = owner.nativeFwErrorSnapshot_;
    CHECK(s.capture_status == static_cast<uint32_t>(CaptureStatus::AccessReleaseFailed));
    CHECK(s.snapshot_complete == 0U);
    CHECK(s.lmac_status == static_cast<uint32_t>(TableStatus::AccessReleaseFailed));
    CHECK(s.umac_status == static_cast<uint32_t>(TableStatus::AccessReleaseFailed));
    CHECK(owner.com.sc_nic_locks == 0);
    bool attemptedClear = false;
    for (const auto &op : bus.ops)
        if (op.kind == 'W' && op.reg == IWX_CSR_GP_CNTRL &&
            (op.value & IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ) == 0U)
            attemptedClear = true;
    CHECK(attemptedClear);
    return 0;
}

static int case_entry_generation_and_firmware_gates_do_no_mmio() {
    using IwxFirmwareDiagnostics::CaptureStatus;
    using IwxFirmwareDiagnostics::TableStatus;
    for (uint32_t mode = 0; mode < 3U; ++mode) {
        ItlIwx owner; FakeMMIO bus; setup(owner, bus);
        auto req = request();
        if (mode == 0U) ++req.driverGeneration;
        else if (mode == 1U) owner.com.sc_uc.uc_ok = 0;
        else ++owner.nativeFwDiagnosticTlvGeneration_;
        CHECK(run(owner, &owner.com, &req) == kIOReturnSuccess);
        CHECK(bus.read_words == 0U);
        for (const auto &op : bus.ops)
            CHECK(!(op.kind == 'W' && (op.reg == IWX_CSR_GP_CNTRL ||
                                       op.reg == IWX_HBUS_TARG_MEM_RADDR)));
        CHECK(owner.com.sc_nic_locks == 0);
        CHECK(owner.nativeFwErrorSnapshot_.snapshot_complete == 0U);
        if (mode == 0U) {
            CHECK(owner.nativeFwErrorSnapshot_.capture_status ==
                  static_cast<uint32_t>(CaptureStatus::StaleGeneration));
            CHECK(owner.nativeFwErrorSnapshot_.lmac_status ==
                  static_cast<uint32_t>(TableStatus::StaleGeneration));
        } else if (mode == 1U) {
            CHECK(owner.nativeFwErrorSnapshot_.capture_status ==
                  static_cast<uint32_t>(CaptureStatus::FirmwareNotAlive));
            CHECK(owner.nativeFwErrorSnapshot_.lmac_status ==
                  static_cast<uint32_t>(TableStatus::FirmwareNotAlive));
        } else {
            CHECK(owner.nativeFwErrorSnapshot_.capture_status ==
                  static_cast<uint32_t>(CaptureStatus::StaleGeneration));
        }
    }
    return 0;
}

static void record_trace_row(ItlIwx &owner, uint32_t phase) {
    IwxFirmwareDiagnostics::Entry entry{};
    entry.monotonic_ns = g_now_ns;
    entry.driver_generation = kGeneration;
    entry.firmware_generation = kGeneration;
    entry.phase = phase;
    entry.source = static_cast<uint32_t>(IwxFirmwareDiagnostics::Source::HostCommand);
    (void)IwxFirmwareDiagnostics::record(&owner.nativeFwDiagnosticTrace_, entry);
}

static int case_manual_latch_and_watchdog_freeze_precedence() {
    ItlIwx owner; FakeMMIO bus; setup(owner, bus);
    record_trace_row(owner, 1U);
    owner.runFirmwareTraceSample(&owner.com, true); // actual Test083 ROC-close sampling block
    CHECK(owner.nativeFwDiagnosticPendingTracePresent_ == 1U);
    CHECK(owner.nativeFwDiagnosticTraceManualLatched_ == 1U);
    CHECK(owner.nativeFwDiagnosticPendingTrace_.window_end_serial == 1U);
    const uint64_t manualSampleTime = owner.nativeFwDiagnosticTraceLastSampleNs_;

    record_trace_row(owner, 2U);
    g_now_ns += 5000000001ULL;
    owner.runFirmwareTraceSample(&owner.com, false); // periodic sample must respect the latch
    CHECK(owner.nativeFwDiagnosticPendingTrace_.window_end_serial == 1U);
    CHECK(owner.nativeFwDiagnosticTraceLastSampleNs_ == manualSampleTime);

    owner.runFirmwareTraceSample(&owner.com, true); // another bounded close can force a fresh snapshot
    CHECK(owner.nativeFwDiagnosticPendingTrace_.window_end_serial == 2U);
    CHECK(owner.nativeFwDiagnosticTraceManualLatched_ == 1U);

    record_trace_row(owner, 3U);
    owner.tahoeFreezeFirmwareMetadata(&owner.com, 99U); // actual watchdog freeze helper
    CHECK(owner.nativeFwDiagnosticTraceFrozen_ == 1U);
    CHECK(owner.nativeFwDiagnosticPendingTrace_.window_end_serial == 3U);
    CHECK(owner.nativeFwDiagnosticPendingWatchdogSequence_ == 99U);
    CHECK(owner.nativeFwDiagnosticPendingTrace_.owner_watchdog_sequence_present == 1U);
    record_trace_row(owner, 4U);
    g_now_ns += 5000000001ULL;
    owner.runFirmwareTraceSample(&owner.com, false);
    owner.runFirmwareTraceSample(&owner.com, true);
    CHECK(owner.nativeFwDiagnosticPendingTrace_.window_end_serial == 3U);
    CHECK(owner.nativeFwDiagnosticPendingWatchdogSequence_ == 99U);
    CHECK(owner.nativeFwDiagnosticTraceManualLatched_ == 1U);
    return 0;
}

static int case_dispatch(const std::string &name) {
    if (name == "layout") return case_layout_and_pointer_helpers();
    if (name == "capture") return case_capture_real_fields_and_release();
    if (name == "empty") return case_empty_tables_are_valid_capture();
    if (name == "pointers") return case_invalid_pointer_inputs_do_not_touch_hbus();
    if (name == "partial-pointer") return case_one_invalid_table_does_not_read_that_table();
    if (name == "guards") return case_wrong_owner_gate_busy_and_existing_request_are_not_stolen();
    if (name == "grant") return case_failed_grant_clears_only_our_request();
    if (name == "sentinel") return case_suspicious_valid_sentinel_is_not_complete_or_a_cause();
    if (name == "budget") return case_budget_abort_counts_actual_words_and_keeps_unread_fields_absent();
    if (name == "stale") return case_generation_change_during_read_is_stale_and_released();
    if (name == "release") return case_release_failure_is_reported_after_clear_attempt();
    if (name == "entry-gates") return case_entry_generation_and_firmware_gates_do_no_mmio();
    if (name == "manual-latch") return case_manual_latch_and_watchdog_freeze_precedence();
    std::cerr << "unknown scenario: " << name << "\n";
    return 2;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    return case_dispatch(argv[1]);
}
'''


class FirmwareErrorCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shutil.which("clang++") or shutil.which("g++")
        if not compiler:
            raise unittest.SkipTest("C++ compiler unavailable")
        cls.temp = tempfile.TemporaryDirectory(prefix="test083-fw-capture-")
        cls.binary = Path(cls.temp.name) / "fw_error_capture_tests"
        source = Path(cls.temp.name) / "fw_error_capture_tests.cpp"
        source.write_text(HARNESS)
        cmd = [
            compiler,
            "-std=c++17",
            "-O1",
            "-g",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
            "-I",
            str(ROOT),
            str(source),
            "-o",
            str(cls.binary),
        ]
        cls.build = subprocess.run(cmd, text=True, capture_output=True)
        if cls.build.returncode != 0:
            raise AssertionError(
                "sanitized production extraction build failed:\n"
                + cls.build.stdout
                + cls.build.stderr
            )

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "temp"):
            cls.temp.cleanup()

    def run_case(self, name: str) -> None:
        env = dict(os.environ)
        env.setdefault("ASAN_OPTIONS", "detect_leaks=0")
        result = subprocess.run(
            [str(self.binary), name], text=True, capture_output=True, env=env
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_real_abi_layout_and_pointer_preflight(self) -> None:
        self.run_case("layout")

    def test_real_action_captures_fields_and_releases_lease(self) -> None:
        self.run_case("capture")

    def test_empty_tables_are_a_valid_completed_snapshot(self) -> None:
        self.run_case("empty")

    def test_invalid_pointer_cases_never_issue_hbus_reads(self) -> None:
        self.run_case("pointers")

    def test_invalid_pointer_for_one_table_does_not_read_that_table(self) -> None:
        self.run_case("partial-pointer")

    def test_owner_main_gate_nic_busy_and_existing_request_guards(self) -> None:
        self.run_case("guards")

    def test_failed_grant_clears_only_the_request_created_by_capture(self) -> None:
        self.run_case("grant")

    def test_suspicious_valid_sentinel_is_partial_not_a_root_cause(self) -> None:
        self.run_case("sentinel")

    def test_budget_abort_keeps_actual_word_counts_and_absent_fields(self) -> None:
        self.run_case("budget")

    def test_post_read_generation_changes_reject_the_snapshot(self) -> None:
        self.run_case("stale")

    def test_access_request_release_failure_is_explicit(self) -> None:
        self.run_case("release")

    def test_entry_generation_alive_and_tlv_gates_skip_mmio(self) -> None:
        self.run_case("entry-gates")

    def test_manual_sample_latch_and_watchdog_freeze_precedence(self) -> None:
        self.run_case("manual-latch")

    def test_roc_close_uses_forced_firmware_trace_sample(self) -> None:
        probe = (ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp").read_text()
        marker = "// A bounded live command/RX trace snapshot at the existing ROC close"
        self.assertIn(marker, probe)
        section = probe[probe.index(marker):probe.index(marker) + 700]
        self.assertIn("tahoePublishFirmwareDiagnostics(", section)
        self.assertIn("&owner->com, true)", section)


if __name__ == "__main__":
    unittest.main()
