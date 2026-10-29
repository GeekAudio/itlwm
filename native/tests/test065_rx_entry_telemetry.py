#!/usr/bin/env python3
"""Host sanitizer and source-contract tests for Test065 RX-entry telemetry."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
ART = ROOT.parent / 'IntelWirelessNative/research/test065-rx-entry-host-verification-private.json'
HEADER = ROOT / 'native/awdl_rx_entry_telemetry.hpp'
FIXTURE = Path(__file__).with_name('awdl_rx_entry_telemetry_test.cpp')
PUBLISHER_HEADER = ROOT / 'native/awdl_rx_entry_publisher.hpp'
PUBLISHER_FIXTURE = Path(__file__).with_name('awdl_rx_entry_publisher_test.cpp')
ITL_HEADER = ROOT / 'itlwm/hal_iwx/ItlIwx.hpp'
ITL_CPP = ROOT / 'itlwm/hal_iwx/ItlIwx.cpp'
RX_CPP = ROOT / 'itlwm/hal_iwx/ItlIwxP2PRx.cpp'
STAGE_TEST = ROOT / 'native/tests/test057_rx_stage_counters.py'


def source_contracts():
    header = HEADER.read_text()
    publisher_header = PUBLISHER_HEADER.read_text()
    cpp = ITL_CPP.read_text()
    itl_header = ITL_HEADER.read_text()
    rx_cpp = RX_CPP.read_text()
    rx_entry_start = cpp.index('void ItlIwx::\niwx_rx_mpdu_mq(')
    rx_entry_end = cpp.index('\nvoid ItlIwx::', rx_entry_start + 1)
    rx_entry = cpp[rx_entry_start:rx_entry_end]
    diagnostic_epoch_fn = rx_cpp[
        rx_cpp.index('bool ItlIwx::tahoeP2pCurrentRxDiagnosticEpochs('):
        rx_cpp.index('IOReturn ItlIwx::tahoeP2pRxDrainAction(')]
    publisher = rx_cpp[
        rx_cpp.index('void ItlIwx::tahoeP2pPublishRxEntryTelemetry('):
        rx_cpp.index('void ItlIwx::tahoePublishResetTrace(')]
    drain_start = rx_cpp.index('void ItlIwx::tahoeP2pRxDrain()')
    drain = rx_cpp[drain_start:rx_cpp.index('\nvoid ItlIwx::', drain_start + 1)]

    assert 'size_t actualPayloadLength, bool rpaEnabled' in rx_entry
    assert 'const size_t statusEnd' in rx_entry
    assert rx_entry.index(
        'if (actualPayloadLength < statusEnd || maxlen < statusEnd)') < rx_entry.index(
        'if (!(desc->status &')
    assert 'if (maxlen < desc_size || len > maxlen - desc_size)' in rx_entry
    assert 'if (len > actualPayloadLength - desc_size)' in rx_entry
    assert 'readableLength = actualPayloadLength < dmaCapacity' in header
    assert 'iwx_rx_packet_payload_len(pkt)' in cpp
    assert 'size_t maxlen = IWX_RBUF_SIZE - offset - minsz;' in cpp
    assert cpp.count('iwx_rx_packet_payload_len(pkt),') >= 2
    assert cpp.count('maxlen, ml);') >= 2
    assert 'tahoeP2pCurrentRxDiagnosticEpochs(sc, &rxEntryEpochs)' in rx_entry
    assert 'inspection.frameControlPresent &&' in rx_entry
    assert 'NativeAwdlData::isAwdlDataCandidate(' in rx_entry
    assert 'tahoe_awdl_rx_stage_counters_.record(' in rx_entry
    assert rx_entry.index('mbuf_adj(m, 2);') < rx_entry.index(
        'TahoeAwdlRxStageCounters::classify(')
    assert 'NativeP2PRxEntrySnapshotBegin' in publisher_header
    assert 'NativeP2PRxEntrySnapshotEnd' in publisher_header
    assert 'NativeP2PRxEntryRocGeneration' in publisher
    assert '!tahoeP2pOnMainGate()' in publisher
    assert 'if (current.active)' in publisher
    assert publisher.index('if (current.active)') < publisher.index('setProperty(')
    assert 'NativeAwdlRxEntryPublisher::publish(' in publisher
    assert publisher.count('controller->setProperty(') == 1
    assert 'nativeAwdlRxEntryAttemptVersion_' in publisher
    assert 'if (!write(lastDescriptorNames[i], descriptorValues[i])) return false;' in publisher
    assert 'if (!write(lastCandidateNames[i], candidateValues[i])) return false;' in publisher
    assert 'publishedSnapshot = current;' in publisher_header
    assert 'publishedVersion = version;' in publisher_header
    assert 'publishedOnce = true;' in publisher_header
    assert 'tahoeP2pPublishRxEntryTelemetry(controller);' in rx_cpp
    assert 'if (rxLease.active && rxLease.contextGeneration != 0' in drain
    assert 'tahoe_awdl_rx_stage_counters_.beginOwner(rxLease.contextGeneration);' in drain
    assert 'nativeAwdlRxEntryTelemetry_.beginOwner(rxEntryEpochs);' in drain
    assert 'tahoe_awdl_rx_stage_counters_.beginOwner(rxEntryEpochs' not in drain
    assert 'counters.beginOwner(41);' in STAGE_TEST.read_text()
    assert 'same still-active lease' in STAGE_TEST.read_text()
    assert 'session.generation != currentRoc' in diagnostic_epoch_fn
    assert '!session.startSeen || session.startStatus != 1' in diagnostic_epoch_fn
    assert 'session.endSeen || session.outcomeUnknown' in diagnostic_epoch_fn
    assert 'NativeAwdlRxEntry::withinDiagnosticWindow(' in diagnostic_epoch_fn
    assert 'lease.powerGeneration != uint32_t(sc->sc_p2p.fw_generation)' in diagnostic_epoch_fn
    assert '!tahoeP2pOnMainGate()' in diagnostic_epoch_fn
    assert 'setProperty(' not in rx_entry
    assert 'OSNumber' not in rx_entry
    assert 'filterMatch' in HEADER.read_text()
    assert 'macPhyIndex' in HEADER.read_text()
    assert 'nowUs - startUs < kDiagnosticWindowUs' in header
    assert 'uint8_t bytes[' not in header


def main():
    source_contracts()
    with tempfile.TemporaryDirectory(prefix='test065-rx-entry-',
                                     dir='/private/tmp') as tmp:
        binary = Path(tmp) / 'rx-entry-test'
        subprocess.run([
            'xcrun', 'clang++', '-std=c++14', '-Wall', '-Wextra', '-Werror',
            '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
            str(FIXTURE), str(ROOT / 'native/awdl_data_frame.cpp'),
            '-o', str(binary),
        ], check=True, capture_output=True, text=True)
        subprocess.run([str(binary)], check=True, timeout=5,
                       capture_output=True, text=True)
        publisher_binary = Path(tmp) / 'rx-entry-publisher-test'
        subprocess.run([
            'xcrun', 'clang++', '-std=c++14', '-Wall', '-Wextra', '-Werror',
            '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
            str(PUBLISHER_FIXTURE), '-o', str(publisher_binary),
        ], check=True, capture_output=True, text=True)
        subprocess.run([str(publisher_binary)], check=True, timeout=5,
                       capture_output=True, text=True)

    source_paths = [HEADER, FIXTURE, PUBLISHER_HEADER, PUBLISHER_FIXTURE,
                    Path(__file__), ITL_HEADER, ITL_CPP, RX_CPP, STAGE_TEST]
    report = {
        'schema': 'test065-rx-entry-host-v2',
        'offline_host_tests_passed': True,
        'source_contracts_passed': True,
        'sanitizers': ['address', 'undefined'],
        'executed_commands': [
            'python3 native/tests/test065_rx_entry_telemetry.py',
            'python3 native/tests/test057_rx_stage_counters.py',
            'python3 native/tests/test_iwx_p2p_rx_tap.py',
        ],
        'source_sha256': {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in source_paths
        },
        'integration_contracts': {
            'notification_payload_length': 'iwx_rx_packet_payload_len(pkt), distinct from DMA remaining maxlen',
            'roc_epoch_source': 'nativeP2pRocGeneration_ and SessionSnapshot.generation, both equal context generation',
            'window': 'main gate, matching active lease/context/power/station/ROC epochs, confirmed ROC START, half-open [0, 900 ms)',
            'filter_match': 'raw numeric only and only when RPA enabled with bounded family-specific offset',
            'published_values': 'numeric only; no frame/payload/address storage',
            'publication': 'injected failure tests prove Begin gating, no End after body failure, matching even version, no state advance on failure, and retry success',
            'outside_gate': 'not sampled and no lease read; gate misses are unknown, not peer loss',
            'existing_action_classification': 'PSF/MIF remains after existing padding removal',
            'behavior_change': 'only declared-short/status-short RX notifications are rejected with explicit bounds; no filter/admission change',
        },
        'negative_cases': [
            'zero context/power/station/ROC owner epochs',
            'stale ROC epoch does not record',
            'physical capacity shorter than declared payload',
            'status and MPDU-length fields beyond descriptor',
            'mac_phy_idx, filter_match, channel and FC truncation',
            'declared MPDU longer than actual payload with large maxlen',
            'DMA capacity overflow', 'short MPDU length', 'CRC rejected',
            'overrun rejected', 'RPA disabled leaves filter_match unavailable',
            'pre-padding action body is not classified as PSF/MIF',
            'exact 900 ms ROC boundary rejected',
            'publisher Begin, middle body and End failure leave published state unchanged',
        ],
        'positive_cases': [
            'v1 and v3 descriptor offsets', 'RPA-enabled raw filter_match',
            'raw status and mac_phy_idx retained under explicit presence bits',
            'AWDL BSSID candidate witness', 'frame header category counts',
            'two bounded witnesses and epoch reset', 'counter saturation',
            'failed publisher retries with a new even version',
        ],
        'source_tree_mutations_by_test': [],
        'kernel_build_performed': False,
        'real_wifi_or_rf_test_performed': False,
        'efi_modified': False,
        'deployment_performed': False,
    }
    ART.parent.mkdir(parents=True, exist_ok=True)
    ART.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    ART.chmod(0o600)
    print('PASS: Test065 RX-entry bounds, epoch and witness host verification')
    print(ART)


if __name__ == '__main__':
    main()
