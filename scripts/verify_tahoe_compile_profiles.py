#!/usr/bin/env python3
"""Syntax-check the changed Tahoe units using the live Xcode build arguments."""
import json
from pathlib import Path
import shlex
import subprocess

UNITS = ('ItlIwx.cpp', 'ItlIwxP2PProbe.cpp', 'ItlIwxP2PRoc.cpp',
         'ItlIwxP2PRx.cpp', 'ItlIwxP2PTx.cpp', 'AirportItlwmV2.cpp',
         'awdl_native_bsd_data_25G332.cpp')
PROFILES = {
    'ordinary_wifi': (),
    'resident': ('LIFECYCLE', 'RESIDENT'),
    'discovery': ('LIFECYCLE', 'RESIDENT', 'TX_EVIDENCE', 'DISCOVERY_EXPERIMENT'),
    'rx149_observation': ('LIFECYCLE', 'RESIDENT', 'TX_EVIDENCE', 'DISCOVERY_EXPERIMENT', 'RX149_OBSERVATION'),
    'rx149_data_input': ('LIFECYCLE', 'RESIDENT', 'TX_EVIDENCE', 'DISCOVERY_EXPERIMENT', 'RX149_OBSERVATION', 'RX149_DATA_INPUT'),
}

def expand_response_files(arguments):
    expanded = []
    for argument in arguments:
        if argument.startswith('@'):
            expanded.extend(expand_response_files(shlex.split(
                Path(argument[1:]).read_text())))
        else:
            expanded.append(argument)
    return expanded

def verify(project, log_path, output_path):
    commands = {}
    for line in log_path.read_text().splitlines():
        if '/clang ' not in line or ' -c ' not in line:
            continue
        arguments = shlex.split(line.strip())
        if (not arguments or Path(arguments[0]).name != 'clang'
                or not Path(arguments[0]).is_relative_to('/Applications/Xcode.app')):
            continue
        source = next((a for a in arguments if Path(a).name in UNITS), None)
        if source is not None:
            commands[Path(source).name] = expand_response_files(arguments)
    if set(commands) != set(UNITS):
        raise RuntimeError('Cannot locate all selected production compilation commands')
    records = []
    for unit, arguments in commands.items():
        cleaned = []
        skip = False
        source_prefix_header = False
        for argument in arguments:
            if source_prefix_header:
                # The just-built .gch embeds this artifact's feature macros.
                # Reparse the source header for each compatibility profile.
                header = project / 'itlwm/PrivateSPI.pch'
                if not header.is_file():
                    raise RuntimeError('Source prefix header is missing')
                cleaned.append(str(header))
                source_prefix_header = False
                continue
            if skip:
                skip = False
                continue
            if argument == '-include':
                cleaned.append(argument)
                source_prefix_header = True
                continue
            if argument in ('-o', '-MF', '-MT', '-MQ', '-serialize-diagnostics', '--serialize-diagnostics'):
                skip = True
                continue
            if argument in ('-c', '-MMD', '-MD', '-MP'):
                continue
            if argument.startswith('-DITL_NATIVE_AWDL_'):
                continue
            cleaned.append(argument)
        for profile, defines in PROFILES.items():
            command = [*cleaned, '-fsyntax-only', *(
                '-DITL_NATIVE_AWDL_' + name + '_25G332=1' for name in defines)]
            result = subprocess.run(command, cwd=project, capture_output=True, text=True)
            records.append({'unit':unit, 'profile':profile,
                            'exit_code':result.returncode,
                            'stdout':result.stdout, 'stderr':result.stderr})
            if result.returncode:
                output_path.write_text(json.dumps({'passed':False,'records':records},indent=2)+'\n')
                raise RuntimeError('Legacy production syntax check failed: '+unit+' / '+profile)
    output_path.write_text(json.dumps({'passed':True, 'records':records,
        'scope':'Production translation units only; no target execution or runtime proof.'},indent=2)+'\n')

