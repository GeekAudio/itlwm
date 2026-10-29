#!/usr/bin/env python3
"""Measure internet download over the specified Wi-Fi interface without toggling it."""
import argparse
import datetime
import json
import ipaddress
import plistlib
import socket
import subprocess
import time
from pathlib import Path


def properties(class_name):
    tree = plistlib.loads(subprocess.check_output(
        ['/usr/sbin/ioreg', '-a', '-r', '-c', class_name]))
    found = {}

    def visit(node):
        found.update({k: v for k, v in node.items()
                      if k.startswith('Native') and isinstance(v, (str, int, bool))})
        for child in node.get('IORegistryEntryChildren', []):
            visit(child)

    for node in tree:
        visit(node)
    return found


def ready(interface):
    state = properties('AirportItlwm')
    text = subprocess.check_output(['/sbin/ifconfig', interface], text=True)
    return (state.get('NativePowerReady') == 1 and 'status: active' in text
            and '\n\tinet ' in text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface', default='en1')
    parser.add_argument('--expect-build', default='25G241-Test015')
    parser.add_argument('--bytes', type=int, default=10000000)
    args = parser.parse_args()
    if not 1000000 <= args.bytes <= 10000000:
        parser.error('--bytes must be between 1000000 and 10000000')
    if properties('IOPCIEDeviceWrapper').get('NativeTestBuild') != args.expect_build:
        raise SystemExit('Loaded driver differs from expected build; no traffic generated.')
    if not ready(args.interface):
        raise SystemExit('Wi-Fi is not ready with an active IPv4 link; no speed result.')

    host = 'speed.cloudflare.com'
    addresses = [x[4][0] for x in socket.getaddrinfo(
        host, 443, socket.AF_INET, socket.SOCK_STREAM)]
    resolve_mode = 'system IPv4'
    if any(ipaddress.ip_address(x) in ipaddress.ip_network('198.18.0.0/15')
           for x in addresses):
        # An interface-bound socket bypasses the TUN route for fake DNS IPs.
        # Resolve only this probe host without changing the system resolver;
        # every measured payload is still explicitly bound to the Wi-Fi NIC.
        query = subprocess.run([
            '/usr/bin/curl', '-4', '--noproxy', '*', '--connect-timeout', '5',
            '--max-time', '10', '-sS',
            'https://dns.alidns.com/resolve?name=' + host + '&type=A',
        ], capture_output=True, text=True)
        if query.returncode:
            raise SystemExit('Probe DNS resolution failed; no speed result.')
        try:
            addresses = [x['data'] for x in json.loads(query.stdout).get('Answer', [])
                         if x.get('type') == 1 and ipaddress.ip_address(x['data']).is_global]
        except (ValueError, KeyError):
            addresses = []
        resolve_mode = 'real IPv4 via DoH; resolver query uses default path'
    if not addresses:
        raise SystemExit('No real probe-server IPv4 address; no speed result.')

    results = []
    for index in range(3):
        if not ready(args.interface):
            results.append({'sample': index + 1, 'status': 'wifi_link_lost'})
            break
        url = ('https://speed.cloudflare.com/__down?bytes=' + str(args.bytes) + '&native_probe='
               + str(time.time_ns()))
        probe = subprocess.run([
            '/usr/bin/curl', '-4', '--noproxy', '*', '--interface', args.interface,
            '--resolve', host + ':443:' + addresses[0],
            '--connect-timeout', '5', '--max-time', '20', '--silent', '--show-error',
            '--output', '/dev/null', '--write-out', '%{json}', url,
        ], capture_output=True, text=True)
        try:
            data = json.loads(probe.stdout)
        except ValueError:
            data = {}
        count = data.get('size_download', 0)
        elapsed = data.get('time_total', 0)
        good = probe.returncode == 0 and data.get('http_code') == 200 and count == args.bytes
        result = {'sample': index + 1, 'status': 'ok' if good else 'failed',
                  'curl_exit': probe.returncode, 'http': data.get('http_code', 0),
                  'bytes': count, 'seconds': elapsed,
                  'download_mbps': round(data.get('speed_download', 0) * 8 / 1000000, 2)
                  if good else None}
        results.append(result)
        print(json.dumps(result), flush=True)
        if not good or not ready(args.interface):
            break

    good = [x for x in results if x['status'] == 'ok']
    total_time = sum(x['seconds'] for x in good)
    report = {'build': args.expect_build, 'interface': args.interface,
              'test': 'IPv4 internet download, interface bound, proxy disabled',
              'resolution': resolve_mode,
              'scope': 'Internet path throughput, not maximum Wi-Fi PHY rate',
              'samples': results, 'wifi_still_ready': ready(args.interface),
              'average_mbps': round(sum(x['bytes'] for x in good) * 8 / total_time / 1000000, 2)
              if total_time else None}
    directory = Path(__file__).resolve().parent / 'research/wifi-rate-private'
    directory.mkdir(exist_ok=True, mode=0o700)
    destination = directory / (datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.json')
    destination.write_text(json.dumps(report, indent=2) + '\n')
    destination.chmod(0o600)
    print(json.dumps({'average_mbps': report['average_mbps'],
                      'successful_samples': len(good),
                      'wifi_still_ready': report['wifi_still_ready']}))
    if len(good) != 3 or not report['wifi_still_ready']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
