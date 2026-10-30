#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build and package the Tahoe test driver; never install or load it."""
import argparse
import hashlib
import json
import plistlib
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]


def receive149_profile_errors(args):
    data_input = getattr(args, 'native_awdl_rx149_data_input', False)
    if getattr(args, 'native_rx_preowner_observation', False) and not data_input:
        return ['Pre-owner observation requires the isolated RX149 data-input profile']
    if data_input and not args.native_awdl_rx149_observation_only:
        return ['RX149 data input requires the isolated RX149 manual receive profile']
    if not args.native_awdl_rx149_observation_only:
        return []
    errors = []
    if not (args.p2p_probe and args.p2p_manual_trigger and args.native_awdl_resident_data):
        errors.append('RX149 requires the manual probe and resident interface')
    incompatible = ('p2p_roc_probe', 'p2p_tx_probe', 'p2p_awdl_psf_observation_only',
                    'p2p_awdl_mif_followup', 'p2p_gp2_observation',
                    'native_awdl_init_observation_only', 'native_awdl_lifecycle_observation_only',
                    'native_awdl_tx_evidence', 'native_awdl_discovery_experiment',
                    'native_awdl_discovery_mif_current_slot',
                    'native_awdl_discovery_current_aw_fallback')
    if any(getattr(args, name) for name in incompatible):
        errors.append('RX149 excludes legacy ROC, TX, GP2 and discovery profiles')
    return errors


def resident_build_flags(args):
    flags = ('OTHER_CPLUSPLUSFLAGS=$(inherited) '
             '-DITL_NATIVE_AWDL_LIFECYCLE_25G332=1 '
             '-DITL_NATIVE_AWDL_RESIDENT_25G332=1')
    # Keep the existing implementations compiled for compatibility checks;
    # their runtime switches are all disabled in this distinct receive profile.
    if args.native_awdl_tx_evidence or args.native_awdl_rx149_observation_only:
        flags += ' -DITL_NATIVE_AWDL_TX_EVIDENCE_25G332=1'
    if args.native_awdl_discovery_experiment or args.native_awdl_rx149_observation_only:
        flags += ' -DITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332=1'
    if args.native_awdl_rx149_observation_only:
        flags += ' -DITL_NATIVE_AWDL_RX149_OBSERVATION_25G332=1'
    if getattr(args, 'native_awdl_rx149_data_input', False):
        flags += ' -DITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332=1'
    if getattr(args, 'native_rx_preowner_observation', False):
        flags += ' -DITL_NATIVE_RX_PREOWNER_OBSERVATION_25G332=1'
    return flags


def apply_artifact_profile(personality, args):
    personality.update({
        'NativeP2PProbe': bool(args.p2p_probe or args.p2p_roc_probe or args.p2p_tx_probe),
        'NativeP2PRocProbe': bool(args.p2p_roc_probe or args.p2p_tx_probe),
        'NativeP2PTxProbe': bool(args.p2p_tx_probe),
        'NativeP2PManualTrigger': bool(args.p2p_manual_trigger),
        'NativeP2PAwdlPsfObservationOnly': bool(args.p2p_awdl_psf_observation_only),
        'NativeP2PAwdlMifFollowup': bool(args.p2p_awdl_mif_followup),
        'NativeP2PGp2Observation': bool(args.p2p_gp2_observation),
        'NativeAwdlInitObservationOnly': bool(args.native_awdl_init_observation_only),
        'NativeAwdlLifecycleObservationOnly': bool(args.native_awdl_lifecycle_observation_only),
        'NativeAwdlResidentEnabled': bool(args.native_awdl_resident_data),
        'NativeAwdlTxEvidenceEnabled': bool(args.native_awdl_tx_evidence),
        'NativeAwdlDiscoveryExperimentEnabled': bool(args.native_awdl_discovery_experiment),
        'NativeAwdlDiscoveryMifCurrentSlotEnabled': bool(args.native_awdl_discovery_mif_current_slot),
        'NativeAwdlDiscoveryCurrentAwFallbackEnabled': bool(args.native_awdl_discovery_current_aw_fallback),
        'NativeP2PRx149ObservationOnly': bool(args.native_awdl_rx149_observation_only),
        'NativeP2PRx149DataInputExperiment': bool(getattr(args, 'native_awdl_rx149_data_input', False)),
        'NativeRxPreOwnerObservation': bool(getattr(args, 'native_rx_preowner_observation', False)),
    })


def run(command, log):
    result = subprocess.run(command, cwd=PROJECT, stdout=log,
                            stderr=subprocess.STDOUT, check=False)
    log.flush()
    if result.returncode:
        raise RuntimeError(f"{command[0]} failed ({result.returncode}); see build log")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--configuration', choices=('Debug', 'Release'), default='Release')
    parser.add_argument('--verify-legacy-profiles', action='store_true',
                        help='Syntax-check changed Tahoe units in ordinary/resident/discovery profiles before packaging')
    parser.add_argument('--p2p-probe', action='store_true',
                        help='Enable the one-shot MAC-context probe in this test artifact only')
    parser.add_argument('--p2p-roc-probe', action='store_true',
                        help='Enable the one-shot MAC/PHY/binding/session probe in this artifact only')
    parser.add_argument('--p2p-tx-probe', action='store_true',
                        help='Enable one diagnostic Action TX during the one-shot P2P session')
    parser.add_argument('--p2p-manual-trigger', action='store_true',
                        help='Keep the TX probe dormant until an administrator arms it once')
    parser.add_argument('--p2p-awdl-psf-observation-only', action='store_true',
                        help='Use one experimental control-only AWDL PSF; not a native AWDL service')
    parser.add_argument('--p2p-awdl-mif-followup', action='store_true',
                        help='Follow the PSF with one MIF in the same manually armed session')
    parser.add_argument('--p2p-gp2-observation', action='store_true',
                        help='Read two raw GP2 brackets around the manual PSF/MIF session')
    parser.add_argument('--native-awdl-init-observation-only', action='store_true',
                        help='Manual unpublished native init/cleanup; skip all firmware/RF probes')
    parser.add_argument('--native-awdl-lifecycle-observation-only', action='store_true',
                        help='Manual native attach/start/register/stop transaction; no RF/data traffic')
    parser.add_argument('--native-awdl-resident-data', action='store_true',
                        help='Resident native awdl0 with BSD/Intel data bridge; RF remains one manual bounded session')
    parser.add_argument('--native-awdl-tx-evidence', action='store_true',
                        help='Record bounded PSF/MIF host-time ticket evidence; never changes TX permission')
    parser.add_argument('--native-awdl-discovery-experiment', action='store_true',
                        help='Allow one real native QM discovery packet using an explicitly estimated PSF target; no formal peer admission change')
    parser.add_argument('--native-awdl-discovery-mif-current-slot', action='store_true',
                        help='Test066: use a same-peer MIF current-slot estimate and bounded early MIF preparation')
    parser.add_argument('--native-awdl-discovery-current-aw-fallback', action='store_true',
                        help='Test077: try the current AW only after the original next-AW planner reports an empty conservative window')
    parser.add_argument('--native-awdl-rx149-observation-only', action='store_true',
                        help='Test080: one manual 100ms channel149 receive observation; no host management/data TX')
    parser.add_argument('--native-awdl-rx149-data-input', action='store_true',
                        help='Test086: allow bounded channel149 inbound data into native awdl0; host frame TX remains blocked')
    parser.add_argument('--native-rx-preowner-observation', action='store_true',
                        help='Test087: independent bounded numeric RX observation before owner admission; no RX/TX policy changes')
    args = parser.parse_args()
    for error in receive149_profile_errors(args):
        parser.error(error)
    if args.native_awdl_discovery_current_aw_fallback and not args.native_awdl_discovery_mif_current_slot:
        parser.error('Current-AW fallback requires the manual MIF current-slot discovery profile')
    if args.native_awdl_discovery_mif_current_slot and not args.native_awdl_discovery_experiment:
        parser.error('MIF current-slot mode requires the bounded native discovery experiment')
    if args.native_awdl_discovery_experiment and not (
            args.native_awdl_resident_data and args.native_awdl_tx_evidence and
            args.p2p_gp2_observation and args.p2p_manual_trigger and
            args.p2p_awdl_psf_observation_only and args.p2p_awdl_mif_followup):
        parser.error('Discovery experiment requires manual resident PSF/MIF, GP2 and TX evidence')
    if args.native_awdl_tx_evidence and not (
            args.native_awdl_resident_data and args.p2p_manual_trigger and
            args.p2p_awdl_psf_observation_only and args.p2p_awdl_mif_followup):
        parser.error('TX time evidence requires resident data with manual PSF/MIF')
    if args.native_awdl_resident_data and not (
            args.p2p_manual_trigger and
            (args.native_awdl_rx149_observation_only or
             (args.p2p_tx_probe and args.p2p_awdl_mif_followup)) and
            not args.native_awdl_init_observation_only and not args.native_awdl_lifecycle_observation_only):
        parser.error('Resident data requires manual PSF/MIF and excludes observation-only lifecycle profiles')
    if args.native_awdl_lifecycle_observation_only and not (
            args.p2p_manual_trigger and args.p2p_tx_probe and
            not args.native_awdl_init_observation_only and
            not args.p2p_awdl_psf_observation_only and
            not args.p2p_awdl_mif_followup and not args.p2p_gp2_observation):
        parser.error('Native lifecycle requires manual control and no init-only/RF observation profile')
    if args.p2p_manual_trigger and not (args.p2p_tx_probe or args.native_awdl_rx149_observation_only):
        parser.error('--p2p-manual-trigger requires --p2p-tx-probe')
    if args.p2p_awdl_psf_observation_only and not (
            args.p2p_tx_probe and args.p2p_manual_trigger):
        parser.error('--p2p-awdl-psf-observation-only requires a manual TX probe')
    if args.p2p_awdl_mif_followup and not args.p2p_awdl_psf_observation_only:
        parser.error('--p2p-awdl-mif-followup requires --p2p-awdl-psf-observation-only')
    if args.p2p_gp2_observation and not args.p2p_awdl_mif_followup:
        parser.error('--p2p-gp2-observation requires --p2p-awdl-mif-followup')
    if args.native_awdl_init_observation_only and not (
            args.p2p_manual_trigger and args.p2p_tx_probe and
            not args.p2p_awdl_psf_observation_only and
            not args.p2p_awdl_mif_followup and not args.p2p_gp2_observation):
        parser.error('Native init-only observation requires manual TX control and no RF observation profile')
    output = args.output.resolve()
    if output.exists() or output.suffix != '.zip' or 'EFI' in output.parts:
        parser.error('Choose a new ZIP path outside EFI')
    output.parent.mkdir(parents=True, exist_ok=True)
    log_path = output.with_suffix('.build.log')
    with tempfile.TemporaryDirectory(prefix='intel-tahoe-', dir='/private/tmp') as directory:
        derived = Path(directory)
        with log_path.open('w') as log:
            build_command = ['xcodebuild', '-project', 'itlwm.xcodeproj', '-scheme', 'AirportItlwm-Tahoe',
                 '-configuration', args.configuration, '-derivedDataPath', str(derived),
                 'ARCHS=x86_64', 'CODE_SIGNING_ALLOWED=NO']
            if args.native_awdl_init_observation_only:
                build_command.append('OTHER_CPLUSPLUSFLAGS=$(inherited) -DITL_NATIVE_AWDL_INIT_OBSERVATION_25G332=1')
            if args.native_awdl_lifecycle_observation_only:
                build_command.append('OTHER_CPLUSPLUSFLAGS=$(inherited) -DITL_NATIVE_AWDL_LIFECYCLE_25G332=1')
            if args.native_awdl_resident_data:
                build_command.append(resident_build_flags(args))
            run(build_command + ['build'], log)
            if args.verify_legacy_profiles:
                from verify_tahoe_compile_profiles import verify
                verify(PROJECT, log_path, output.with_suffix('.profiles.json'))
            bundle = derived / 'Build/Products' / args.configuration / 'Tahoe/AirportItlwm.kext'
            if not bundle.is_dir():
                raise RuntimeError('Expected Tahoe build product is missing')
            info_path = bundle / 'Contents/Info.plist'
            probe_info = plistlib.loads(info_path.read_bytes())
            build_tag = probe_info.get('AirportTahoeBuild', '')
            if not re.fullmatch(r'[0-9A-Z]+-Test[0-9]+', build_tag):
                raise RuntimeError('Missing or invalid Tahoe test build tag')
            probe_info['IOKitPersonalities']['NetworkController']['NativeTestBuild'] = build_tag
            # Every artifact gets an explicit profile. A normal Wi-Fi build
            # must not inherit experimental firmware probes from a prior plist.
            personality = probe_info['IOKitPersonalities']['NetworkController']
            apply_artifact_profile(personality, args)
            info_path.write_bytes(plistlib.dumps(probe_info, sort_keys=False))
            run(['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', str(bundle)], log)
            run(['/usr/bin/codesign', '--verify', '--strict', str(bundle)], log)
        info = plistlib.loads((bundle / 'Contents/Info.plist').read_bytes())
        if info['CFBundleIdentifier'] != 'org.geekaudio.AirportItlwm':
            raise RuntimeError('Unexpected product identifier')
        # The target uses dynamic lookup for private Apple APIs. It must never
        # silently leave one of our own implementation symbols unresolved.
        undefined = subprocess.check_output(
            ['xcrun', 'nm', '-u', str(bundle / 'Contents/MacOS/AirportItlwm')],
            text=True)
        own_names = ('NativeWifi', 'NativeAwdl', 'NativeRxPreOwner', 'NativeP2PProbe', 'IntelP2PRx',
                     'IntelAwdl', 'IntelAwdlElection', 'IntelROCEvent', 'IntelP2PTx', 'IntelP2PAction',
                     'IntelP2PFirmware', 'IntelGp2Clock',
                     'iwx_tahoe_p2p', 'IwxTxRate', 'IwxResetTrace', 'AirportItlwm',
                     'ItlIwx', 'ItlHalService', 'ItlAwdl')
        missing = [line.strip() for line in undefined.splitlines()
                   if any(name in line for name in own_names)]
        if missing:
            raise RuntimeError('Unresolved project symbols: ' + ', '.join(missing))
        uuid_output = subprocess.check_output(
            ['xcrun', 'dwarfdump', '--uuid', str(bundle / 'Contents/MacOS/AirportItlwm')],
            text=True)
        match = re.search(r'UUID: ([0-9A-F-]{36}) \(x86_64\)', uuid_output)
        if not match:
            raise RuntimeError('Cannot identify the built x86_64 Mach-O UUID')
        with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(bundle.rglob('*')):
                if path.is_file() and not path.is_symlink():
                    archive.write(path, str(path.relative_to(bundle.parent)))
        print(json.dumps({'output': str(output), 'version': info['CFBundleVersion'],
                          'sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
                          'installed': False, 'p2p_probe': args.p2p_probe or args.p2p_roc_probe or args.p2p_tx_probe,
                          'p2p_roc_probe': args.p2p_roc_probe or args.p2p_tx_probe,
                          'p2p_tx_probe': args.p2p_tx_probe,
                          'p2p_manual_trigger': args.p2p_manual_trigger,
                          'p2p_awdl_psf_observation_only': args.p2p_awdl_psf_observation_only,
                          'p2p_awdl_mif_followup': args.p2p_awdl_mif_followup,
                          'p2p_gp2_observation': args.p2p_gp2_observation,
                          'native_awdl_init_observation_only': args.native_awdl_init_observation_only,
                          'native_awdl_lifecycle_observation_only': args.native_awdl_lifecycle_observation_only,
                          'native_awdl_resident_data': args.native_awdl_resident_data,
                          'native_awdl_tx_evidence': args.native_awdl_tx_evidence,
                          'native_awdl_discovery_experiment': args.native_awdl_discovery_experiment,
                          'native_awdl_discovery_mif_current_slot': args.native_awdl_discovery_mif_current_slot,
                          'native_awdl_discovery_current_aw_fallback': args.native_awdl_discovery_current_aw_fallback,
                          'native_awdl_rx149_observation_only': args.native_awdl_rx149_observation_only,
                          'native_awdl_rx149_data_input': args.native_awdl_rx149_data_input,
                          'native_rx_preowner_observation': args.native_rx_preowner_observation,
                          'test_build': build_tag, 'mach_o_uuid': match.group(1),
                          'log': str(log_path)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
