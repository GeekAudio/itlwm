#!/usr/bin/env python3
"""Offline address-identity and shared-main-gate interleaving checks."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def run(arguments, cwd=ROOT):
    result = subprocess.run(arguments, cwd=cwd, text=True,
                            capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout


def main():
    airport = (ROOT / "AirportItlwm/AirportItlwmV2.cpp").read_text()
    lifecycle = (ROOT / "native/awdl_native_lifecycle_25G332.cpp").read_text()
    probe = (ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp").read_text()
    action = (ROOT / "itlwm/hal_iwx/ItlIwxP2PAction.cpp").read_text()
    identity = (ROOT / "native/awdl_advertisement_identity.hpp").read_text()
    iwx = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
    workloop_sdk = (ROOT / "MacKernelSDK/Headers/IOKit/IOWorkLoop.h").read_text()

    stop = airport[airport.index("void AirportItlwm::stop("):]
    assert stop.index("_fCommandGate->runAction") < stop.index("stopResident(this)")
    publish = lifecycle[lifecycle.index("bool publishClosingInGate("):
                        lifecycle.index("bool residentPending(")]
    assert "loop->inGate()" in publish
    assert "NativeAwdlBSD::publishClosing()" in publish
    assert "loop->runAction(publishClosingAction,controller)" in publish
    retire = lifecycle[lifecycle.index("bool ItlAwdlLifecycle25G332::retire("):
                       lifecycle.index("void ItlAwdlLifecycle25G332::free(")]
    assert retire.index("NativeAwdlLifecycle::publishClosing(controller_)") < retire.index("NativeAwdlBSD::close()")
    assert "NativeAwdlBSD::address(powerGeneration" in probe
    assert "NativeAwdlBSD::address(generation" in action
    assert action.index("residentAddressBound") < action.index("iwx_tahoe_p2p_tvqm_mark_doorbell(")
    assert "NativeAwdl::actionFrameAdvertisesAddress" in action
    assert "kAwdlActionHeaderLength" in identity
    psf_details = probe[probe.index("static void publishPsfProbeDetails("):
                        probe.index("static void publishMifProbeDetails(")]
    mif_details = probe[probe.index("static void publishMifProbeDetails("):
                        probe.index("static mbuf_t makeActionFrameFromBytes(")]
    assert "NativeP2PAwdlNativeAddressCandidateVerified" in psf_details
    assert "NativeP2PAwdlNativeAddressCandidateVerified" in mif_details
    assert "NativeP2PAwdlNativeAddressVerified" not in psf_details
    assert "NativeP2PAwdlNativeAddressVerified" not in mif_details
    submit_start = probe.index("const int result=iwx_tahoe_p2p_action_tx_submit(")
    submit_end = probe.index("};\n            gate->runAction(submitData,probe)", submit_start)
    submit_callback = probe[submit_start:submit_end]
    assert "TahoeP2PActionTxSubmitStage::kDoorbellIssued" in submit_callback
    assert "TahoeP2PActionTxSubmitStage::kPostDoorbellFinish" in submit_callback
    assert "if(doorbellIssued)" in submit_callback
    assert submit_callback.index("NativeAwdlBSD::submitted") < submit_callback.index("return kIOReturnSuccess;")
    assert "state==TahoeP2PActionTxState::kQuarantined" not in submit_callback
    assert "gate->runAction(submitData,probe)" in probe
    assert "pa->workloop->addEventSource(sc->sc_ih)" in iwx
    tx_response = iwx[iwx.index("case IWX_TX_CMD:"):]
    assert tx_response.index("iwx_tahoe_p2p_action_tx_response") < tx_response.index("iwx_rx_tx_cmd")
    assert "single threaded against all other work-loop event sources" in workloop_sdk

    headers = (
        "IOKit/IOLib.h", "IOKit/IOLocks.h", "kern/clock.h",
        "net/kpi_interfacefilter.h", "net/if.h", "sys/socket.h",
        "sys/mbuf.h", "net/kpi_interface.h", "sys/kpi_socket.h",
        "netinet/in.h", "netinet6/in6_var.h",
    )
    with tempfile.TemporaryDirectory(prefix="native-awdl061-gate-") as temp:
        directory = Path(temp)
        for header in headers:
            path = directory / header
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('#include "awdl_bsd_bridge_shim.hpp"\n')
        binary = directory / "gate-interleave"
        run(["xcrun", "clang++", "-std=c++14", "-O1", "-g",
             "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
             "-fno-omit-frame-pointer", "-DITL_NATIVE_AWDL_RESIDENT_25G332=1",
             f"-I{directory}", "-Inative/tests", "-Inative",
             "native/awdl_native_bsd_data_25G332.cpp",
             "native/awdl_data_frame.cpp",
             "native/tests/awdl_native_close_gate_interleave_test.cpp",
             "-o", str(binary)])
        run([str(binary), "1"])
        run([str(binary), "2"])

        identity_binary = directory / "advertisement-identity-asan-ubsan"
        run(["xcrun", "clang++", "-std=c++14", "-O1", "-g",
             "-Wall", "-Wextra", "-Werror",
             "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
             "native/awdl_action_frame.cpp", "native/awdl_action_encode.cpp",
             "native/awdl_mif_encode.cpp",
             "native/tests/awdl_advertisement_identity_test.cpp",
             "-o", str(identity_binary)])
        run([str(identity_binary)])

    print("Test061 production PSF/MIF-to-identity helper ASan/UBSan checks and serialized close interleavings passed")


if __name__ == "__main__":
    main()
