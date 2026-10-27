#!/usr/bin/env python3
"""Exercise the production P2P TX firmware gate against shipped fw68 TLVs."""

from pathlib import Path
import argparse
import json
import re
import os
import shutil
import struct
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
FIRMWARE_ROOT = ROOT / "itlwm/firmware"
PROBE_SOURCE = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"
DRIVER_SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"
HEADER_SIZE = 88  # iwx_tlv_ucode_header, including the 64-byte text field.
TLV_CMD_VERSIONS = 48
TLV_ENABLED_CAPABILITIES = 30
TLV_PHY_SKU = 23
FW_MAGIC = 0x0A4C5749
DQA_CAPABILITY = 12


def parse_firmware(path):
    """Read the same aligned TLV stream used by iwx_read_firmware()."""
    data = path.read_bytes()
    if len(data) < HEADER_SIZE:
        raise AssertionError("firmware is shorter than the fw TLV header")
    zero, magic = struct.unpack_from("<II", data)
    if zero != 0 or magic != FW_MAGIC:
        raise AssertionError(f"unexpected firmware header: zero={zero}, magic={magic:#x}")

    offset = HEADER_SIZE
    command_tables = []
    enabled_capabilities = set()
    phy_configs = []
    while offset + 8 <= len(data):
        tlv_type, length = struct.unpack_from("<II", data, offset)
        offset += 8
        if length > len(data) - offset:
            raise AssertionError(f"truncated TLV {tlv_type} at {offset - 8:#x}")
        payload = data[offset : offset + length]

        if tlv_type == TLV_CMD_VERSIONS:
            if length % 4:
                raise AssertionError(f"CMD_VERSIONS has non-entry tail ({length} bytes)")
            command_tables.append(
                [struct.unpack_from("<4B", payload, index) for index in range(0, length, 4)]
            )
        elif tlv_type == TLV_ENABLED_CAPABILITIES:
            if length != 8:
                raise AssertionError(f"ENABLED_CAPABILITIES has unexpected size {length}")
            api_index, flags = struct.unpack("<II", payload)
            if api_index * 32 + 31 >= 128:
                raise AssertionError(f"capability index out of range: {api_index}")
            enabled_capabilities.update(
                api_index * 32 + bit for bit in range(32) if flags & (1 << bit)
            )
        elif tlv_type == TLV_PHY_SKU:
            if length != 4:
                raise AssertionError(f"PHY_SKU has unexpected size {length}")
            phy_configs.append(struct.unpack("<I", payload)[0])

        offset += (length + 3) & ~3

    if offset != len(data):
        raise AssertionError(f"trailing partial TLV header at {offset:#x}")
    if len(command_tables) != 1:
        raise AssertionError(f"expected one CMD_VERSIONS TLV, found {len(command_tables)}")
    entries = command_tables[0]
    if not entries:
        raise AssertionError("firmware CMD_VERSIONS table is empty")
    if len(phy_configs) != 1:
        raise AssertionError(f"expected one PHY_SKU TLV, found {len(phy_configs)}")
    return entries, enabled_capabilities, phy_configs[0]


def parse_configs(source):
    """Extract firmware/family pairs from real iwl_cfg declarations."""
    result = {}
    for match in re.finditer(
        r"const struct iwl_cfg\s+(\w+)\s*=\s*\{(.*?)\n\};",
        source,
        re.S,
    ):
        symbol, body = match.groups()
        firmware = re.search(r'\.fwname\s*=\s*"([^"]+)"', body)
        family = re.search(r"\.device_family\s*=\s*(IWX_DEVICE_FAMILY_\w+)", body)
        if firmware and family:
            result[symbol] = firmware.group(1), family.group(1)
    return result


def extract_function(source, marker):
    start = source.index(marker)
    opening = source.index("{", start)
    end = opening + 1
    depth = 1
    while depth:
        if end >= len(source):
            raise AssertionError(f"unterminated production function {marker}")
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def make_harness(entries, capabilities, phy_config, production_helper,
                 family, tx_command, layout):
    table = ",\n".join(
        "    {%d, %d, %d, %d}" % entry for entry in entries
    )
    capability_bytes = [0] * 16
    for bit in capabilities:
        capability_bytes[bit // 8] |= 1 << (bit % 8)
    caps = ", ".join(str(value) for value in capability_bytes)
    return r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <vector>

#include "native/p2p_action_tx.hpp"
#include "native/p2p_tx_firmware.hpp"

#define IWX_DEVICE_FAMILY_22000 1
#define IWX_DEVICE_FAMILY_AX210 2
#define IWX_LONG_GROUP 0x01
#define IWX_DATA_PATH_GROUP 0x05
#define IWX_TX_CMD 0x1c
#define IWX_SCD_QUEUE_CFG 0x1d
#define IWX_TXPATH_FLUSH 0x1e
#define IWX_REMOVE_STA 0x19
#define IWX_FW_CMD_VER_UNKNOWN 99
#define IWX_UCODE_TLV_CAPA_DQA_SUPPORT 12
#define IWX_RATE_6M_INDEX 4
#define IWX_FIRST_OFDM_RATE IWX_RATE_6M_INDEX
#define IWX_RATE_MCS_ANT_NUM 3
#define IWX_RATE_MCS_ANT_POS 14
#define IWX_RATE_MCS_LEGACY_OFDM_MSK (1U << 8)
#define REAL_PHY_CONFIG REAL_PHY_CONFIG_VALUE
#define LIVE_FAMILY LIVE_FAMILY_VALUE
#define EXPECTED_TX_COMMAND EXPECTED_TX_COMMAND_VALUE
#define EXPECTED_TX_LAYOUT EXPECTED_TX_LAYOUT_VALUE

struct iwx_fw_cmd_version {
    uint8_t cmd, group, cmd_ver, notif_ver;
};
struct iwx_softc {
    int sc_device_family = LIVE_FAMILY;
    uint32_t sc_fw_phy_config = REAL_PHY_CONFIG;
    bool forceNoValidAntennaForTest = false;
    uint8_t sc_enabled_capa[16] = {CAPABILITY_BYTES};
    std::vector<iwx_fw_cmd_version> cmd_versions = {
ACTUAL_COMMAND_TABLE
    };
    int n_cmd_versions() const { return static_cast<int>(cmd_versions.size()); }
};

static bool isset(const uint8_t *bitmap, unsigned bit) {
    return (bitmap[bit / 8] & static_cast<uint8_t>(1U << (bit % 8))) != 0;
}

struct ItlIwx {
    uint8_t iwx_lookup_cmd_ver(iwx_softc *sc, uint8_t group, uint8_t cmd) {
        for (const auto &entry : sc->cmd_versions)
            if (entry.group == group && entry.cmd == cmd) return entry.cmd_ver;
        return IWX_FW_CMD_VER_UNKNOWN;
    }
    uint8_t iwx_lookup_notif_ver(iwx_softc *sc, uint8_t group, uint8_t cmd) {
        for (const auto &entry : sc->cmd_versions)
            if (entry.group == group && entry.cmd == cmd) return entry.notif_ver;
        return IWX_FW_CMD_VER_UNKNOWN;
    }
    uint8_t iwx_fw_valid_tx_ant(iwx_softc *sc) {
        if (sc->forceNoValidAntennaForTest) return 0;
        return static_cast<uint8_t>((sc->sc_fw_phy_config >> 16) & 0x0f);
    }
};

PRODUCTION_HELPER

static uint32_t rejected(ItlIwx &owner, iwx_softc &sc) {
    const auto profile = txFirmwareProfile(&owner, &sc);
    return IntelP2PFirmware::rejectionMask(profile, IWX_FW_CMD_VER_UNKNOWN);
}
static iwx_softc realFirmware() {
    iwx_softc sc;
    return sc;
}
static bool eraseCommand(iwx_softc &sc, uint8_t group, uint8_t cmd) {
    for (auto it = sc.cmd_versions.begin(); it != sc.cmd_versions.end(); ++it) {
        if (it->group == group && it->cmd == cmd) {
            sc.cmd_versions.erase(it);
            return true;
        }
    }
    return false;
}

int main() {
    ItlIwx owner;
    iwx_softc baseline = realFirmware();
    const auto accepted = txFirmwareProfile(&owner, &baseline);
    assert(accepted.deviceFamily == static_cast<IntelP2PFirmware::DeviceFamily>(LIVE_FAMILY));
    assert(accepted.txCommand == EXPECTED_TX_COMMAND && accepted.txNotification == 7);
    assert(IntelP2PFirmware::txLayout(accepted.deviceFamily,
        accepted.txCommand, accepted.txNotification) ==
        static_cast<IntelP2PFirmware::TxLayout>(EXPECTED_TX_LAYOUT));
    assert(accepted.queueCommand == 2 && accepted.queueResponse == 2);
    assert(accepted.modernQueueCommand == IWX_FW_CMD_VER_UNKNOWN);
    assert(accepted.flushCommand == 2 && accepted.flushResponse == 1);
    assert(accepted.removeStationCommand == 2);
    assert(!accepted.dqa); // The shipped firmware's TLV 30 leaves DQA bit 12 clear.
    assert(accepted.rateValid); // Rate encoding uses the real PHY_SKU TX-chain mask.
    assert(rejected(owner, baseline) == 0);

    // The other real hardware/firmware pair remains supported. Cross-pairing
    // a command version with the wrong transport family fails closed.
    const auto crossFamily = LIVE_FAMILY == IWX_DEVICE_FAMILY_22000
        ? IntelP2PFirmware::DeviceFamily::kAX210
        : IntelP2PFirmware::DeviceFamily::k22000;
    assert(IntelP2PFirmware::txLayout(crossFamily,
        accepted.txCommand, accepted.txNotification) ==
        IntelP2PFirmware::TxLayout::kUnsupported);
    iwx_softc wrongFamily = realFirmware();
    wrongFamily.sc_device_family = crossFamily == IntelP2PFirmware::DeviceFamily::kAX210
        ? IWX_DEVICE_FAMILY_AX210 : IWX_DEVICE_FAMILY_22000;
    assert((rejected(owner, wrongFamily) & IntelP2PFirmware::kTxCommand) != 0);

    iwx_softc missing = realFirmware();
    assert(eraseCommand(missing, IWX_LONG_GROUP, IWX_TX_CMD));
    assert(rejected(owner, missing) ==
        (IntelP2PFirmware::kTxCommand | IntelP2PFirmware::kTxNotification));

    iwx_softc wrongVersion = realFirmware();
    bool changedVersion = false;
    for (auto &entry : wrongVersion.cmd_versions) {
        if (entry.group == IWX_LONG_GROUP && entry.cmd == IWX_TX_CMD) {
            entry.cmd_ver = 8;
            changedVersion = true;
        }
    }
    assert(changedVersion);
    assert(rejected(owner, wrongVersion) == IntelP2PFirmware::kTxCommand);

    iwx_softc modernQueue = realFirmware();
    modernQueue.cmd_versions.push_back({0x17, IWX_DATA_PATH_GROUP, 1, 0});
    assert(rejected(owner, modernQueue) == IntelP2PFirmware::kModernQueuePresent);

    iwx_softc invalidRate = realFirmware();
    invalidRate.forceNoValidAntennaForTest = true;
    assert(rejected(owner, invalidRate) == IntelP2PFirmware::kRate);

    std::puts("real fw68 TX profile: family/layout admission, cross-family rejection, four fault cases, DQA=false, production rate encoder passed");
    return 0;
}
'''.replace("ACTUAL_COMMAND_TABLE", table).replace(
        "CAPABILITY_BYTES", caps
    ).replace("PRODUCTION_HELPER", production_helper).replace(
        "REAL_PHY_CONFIG_VALUE", hex(phy_config)
    ).replace("LIVE_FAMILY_VALUE", str(family)).replace(
        "EXPECTED_TX_COMMAND_VALUE", str(tx_command)
    ).replace("EXPECTED_TX_LAYOUT_VALUE", str(layout))


def main():
    compiler = os.environ.get("CXX") or shutil.which("clang++") or shutil.which("c++")
    if not compiler:
        raise SystemExit("No C++ compiler found (set CXX or install clang++)")
    source = PROBE_SOURCE.read_text()
    helper = extract_function(source, "static IntelP2PFirmware::Profile txFirmwareProfile(")

    # Tie the two real firmware files to their model configs in the production
    # table so the fixture cannot silently test a mismatched file/family pair.
    driver = DRIVER_SOURCE.read_text()
    configs = parse_configs(driver)
    fixtures = [
        ("iwlwifi-QuZ-a0-hr-b0-68.ucode", "iwl_ax201_cfg_quz_hr",
         "k22000", 9, 1),
        ("iwlwifi-so-a0-hr-b0-68.ucode", "iwl_cfg_so_a0_hr_a0",
         "kAX210", 10, 2),
    ]
    assert configs["iwl_ax201_cfg_quz_hr"] == (
        "iwlwifi-QuZ-a0-hr-b0-68.ucode", "IWX_DEVICE_FAMILY_22000")
    assert configs["iwl_cfg_so_a0_hr_a0"] == (
        "iwlwifi-so-a0-hr-b0-68.ucode", "IWX_DEVICE_FAMILY_AX210")
    assert re.search(
        r"IWL_PCI_DEVICE\(0x7AF0,\s*PCI_ANY_ID,\s*iwl_so_trans_cfg\)",
        driver,
    ), "the 7AF0 PCI path must select the So transport family"
    so_transport = re.search(
        r"const struct iwl_cfg_trans_params\s+iwl_so_trans_cfg\s*=\s*"
        r"\{(.*?)\n\};",
        driver,
        re.S,
    )
    assert so_transport and re.search(
        r"\.device_family\s*=\s*IWX_DEVICE_FAMILY_AX210",
        so_transport.group(1),
    ), "the 7AF0 So transport must use AX210-family command structures"
    assert re.search(
        r"_IWL_DEV_INFO\(IWL_CFG_ANY,\s*IWL_CFG_ANY,\s*"
        r"IWL_CFG_MAC_TYPE_SO,\s*IWL_CFG_ANY,\s*IWL_CFG_RF_TYPE_HR2,"
        r"\s*IWL_CFG_ANY,\s*IWL_CFG_160,\s*IWL_CFG_ANY,\s*"
        r"IWL_CFG_NO_CDB,\s*iwl_cfg_so_a0_hr_a0,\s*iwl_ax201_name\)",
        driver,
        re.S,
    ), "the So HR2/160 AX201 model must select the So-HR configuration"

    firmware_layouts = []
    for firmware, config, family_name, command_version, layout in fixtures:
        entries, capabilities, phy_config = parse_firmware(
            FIRMWARE_ROOT / firmware)
        family = 1 if family_name == "k22000" else 2
        assert configs[config] == (
            firmware,
            "IWX_DEVICE_FAMILY_22000" if family == 1 else "IWX_DEVICE_FAMILY_AX210",
        )
        firmware_layouts.append((entries, capabilities, phy_config, family,
                                 command_version, layout, firmware))

    # Optional current-machine evidence allows the same test to check a live
    # runtime report without making another machine's local report a fixture.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-result", type=Path)
    args = parser.parse_args()
    runtime = None
    if args.runtime_result:
        runtime = json.loads(args.runtime_result.read_text())
        p2p = runtime.get("p2p", {})
        assert runtime.get("loaded_build") == runtime.get("expected_build")
        assert runtime.get("binary_identity", {}).get("binary_identity_verified") is True
        assert runtime.get("wifi_ready") is True
        assert p2p.get("NativeP2PTxFwCommandVersion") == 10
        assert p2p.get("NativeP2PTxFwNotificationVersion") == 7
        rejection = p2p.get("NativeP2PTxPreflightRejectMask", 0)
        assert (rejection & (1 << 0 | 1 << 1)) == (1 << 0 | 1 << 1)
        if "NativeP2PTxDeviceFamily" in p2p:
            assert p2p["NativeP2PTxDeviceFamily"] == 2
            assert p2p.get("NativeP2PTxFirmwareFile") == "iwlwifi-so-a0-hr-b0-68.ucode"

    with tempfile.TemporaryDirectory(prefix="iwx-fw-profile-") as temporary:
        temporary_path = Path(temporary)
        for (entries, capabilities, phy_config, family, command_version,
             layout, firmware) in firmware_layouts:
            harness = temporary_path / f"tx_profile_{family}.cpp"
            binary = temporary_path / f"tx_profile_{family}"
            harness.write_text(make_harness(
                entries, capabilities, phy_config, helper, family,
                command_version, layout))
            subprocess.run(
                [
                    compiler,
                    "-std=c++17",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer",
                    "-g",
                    f"-I{ROOT}",
                    str(harness),
                    str(ROOT / "native/p2p_action_tx.cpp"),
                    "-o",
                    str(binary),
                ],
                check=True,
                cwd=ROOT,
            )
            subprocess.run([str(binary)], check=True, cwd=ROOT)
            print(f"firmware fixture passed: {firmware}")
    if runtime:
        print("live loaded build TX10/7 matches the source-verified So/AX201 profile; the TX attempt was preflight-blocked")


if __name__ == "__main__":
    main()
