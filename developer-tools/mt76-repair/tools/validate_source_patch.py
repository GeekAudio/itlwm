#!/usr/bin/env python3
"""Offline source-extracted host test; this does not compile a kernel module."""
import argparse
import atexit
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile

PACKAGE = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description='Apply and exercise the NULL-vif source patch against the exact upstream files.')
parser.add_argument('--mt76-source', type=Path, required=True,
                    help='checkout or source directory containing the four pinned mt76 files')
args = parser.parse_args()
SOURCE = args.mt76_source.expanduser().resolve()
OUT_TEMP = tempfile.TemporaryDirectory(prefix='mt76-source-validate-')
atexit.register(OUT_TEMP.cleanup)
OUT = Path(OUT_TEMP.name)

PATCH_MANIFEST = json.loads((PACKAGE / 'PATCH-MANIFEST.json').read_text())
SOURCE_HASHES = {row['source']: row['base_sha256'] for row in PATCH_MANIFEST['source_files']}
SOURCE_HASHES.update(PATCH_MANIFEST['source_test_inputs'])
PROPOSED_HASHES = {row['source']: row['proposed_sha256']
                   for row in PATCH_MANIFEST['source_files']}
source_names = list(SOURCE_HASHES)
base = {name: (SOURCE / name).read_text() for name in source_names}
for name, expected in SOURCE_HASHES.items():
    if hashlib.sha256((SOURCE / name).read_bytes()).hexdigest() != expected:
        raise SystemExit(f'source hash mismatch for {name}; expected the pinned upstream base')

with tempfile.TemporaryDirectory(prefix='mt76-patch-fixture-') as fixture:
    fixture = Path(fixture)
    for name in source_names:
        shutil.copyfile(SOURCE / name, fixture / name)
    patches = sorted((PACKAGE / 'patches').glob('*.patch'))
    check = subprocess.run(['git', 'apply', '--check', *map(str, patches)],
                           cwd=fixture, capture_output=True, text=True)
    if check.returncode:
        raise SystemExit(f'git apply --check failed: {check.stderr}')
    apply = subprocess.run(['git', 'apply', *map(str, patches)],
                           cwd=fixture, capture_output=True, text=True)
    if apply.returncode:
        raise SystemExit(f'git apply failed: {apply.stderr}')
    fixed = {name: (fixture / name).read_text()
             for name in ['mt76_connac_mac.c', 'mac80211.c']}
    for name, expected in PROPOSED_HASHES.items():
        if hashlib.sha256((fixture / name).read_bytes()).hexdigest() != expected:
            raise SystemExit(f'patched source hash mismatch for {name}')
patch_application_passed = True


def function(text, name):
    start = text.index('u16 ' + name + '(')
    brace = text.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


def macro(text, name):
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith('#define ' + name + '('))
    end = start
    while lines[end].endswith('\\'):
        end += 1
    return '\n'.join(lines[start:end + 1])


fixed = {name: fixed[name] for name in ['mt76_connac_mac.c', 'mac80211.c']}
rate = 'mt76_connac2_mac_tx_rate_val'
helper = 'mt76_calculate_default_rate'
enum = re.search(r'enum mt76_phy_type\s*\{.*?\};', base['mt76.h'], re.S)
assert enum, 'exact PHY enum not found'
table = re.search(r'struct ieee80211_rate mt76_rates\[\]\s*=\s*\{.*?\n\};', base['mac80211.c'], re.S)
assert table, 'exact rate table not found'
masks = '\n'.join(line for line in base['mt76_connac2_mac.h'].splitlines()
                  if re.match(r'#define MT_TX_RATE_(NSS|IDX|MODE)\s', line))
assert len(masks.splitlines()) == 3
shim = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
typedef uint8_t u8;
typedef uint16_t u16;
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define GENMASK(h, l) (((~0U) >> (31 - (h))) & ((~0U) << (l)))
#define FIELD_PREP(mask, v) (((unsigned)(v) << __builtin_ctz(mask)) & (mask))
#define hweight16(v) __builtin_popcount((unsigned)(uint16_t)(v))
#define hweight32(v) __builtin_popcount((unsigned)(uint32_t)(v))
#define IEEE80211_RATE_SHORT_PREAMBLE 1
enum { NL80211_BAND_2GHZ, NL80211_BAND_5GHZ, NL80211_BAND_6GHZ };
struct ieee80211_channel { int band; };
struct cfg80211_chan_def { struct ieee80211_channel *chan; };
struct ieee80211_rate { int bitrate, flags; u16 hw_value, hw_value_short; };
struct ieee80211_chanctx_conf { struct cfg80211_chan_def def; };
struct mt76_vif { struct ieee80211_chanctx_conf *ctx; };
struct cfg80211_bitrate_mask {
    struct { uint32_t legacy; u8 ht_mcs[10]; u16 vht_mcs[8], he_mcs[8]; } control[3];
};
struct ieee80211_bss_conf {
    uint32_t basic_rates;
    int mcast_rate[3];
    struct cfg80211_bitrate_mask beacon_tx_rate;
};
/* Synthetic host layout; deliberately not the vendor struct ABI. */
struct ieee80211_vif { struct ieee80211_bss_conf bss_conf; struct mt76_vif drv_priv[1]; };
struct mt76_dev { bool mt7921; };
struct mt76_phy { struct cfg80211_chan_def chandef; struct mt76_dev *dev; };
#define is_mt7921(dev) ((dev)->mt7921)
'''
parts = [shim, enum.group(), masks, macro(base['mt76.h'], 'CCK_RATE'),
         macro(base['mt76.h'], 'OFDM_RATE'), table.group(),
         macro(base['mt76_connac_mac.c'], '__bitrate_mask_check')]
for tag, content in [('base', base), ('fixed', fixed)]:
    parts.append(function(content['mac80211.c'], helper).replace(helper, tag + '_helper'))
    parts.append(function(content['mt76_connac_mac.c'], rate)
                 .replace(rate, tag + '_rate').replace(helper, tag + '_helper'))
# The tempting partial fix is deliberately exercised as a negative control.
parts.append(function(fixed['mt76_connac_mac.c'], rate)
             .replace(rate, 'guard_only_rate').replace(helper, 'base_helper'))
parts.append(r'''
static void pattern(struct ieee80211_vif *vif, int band, int p) {
    struct cfg80211_bitrate_mask *mask = &vif->bss_conf.beacon_tx_rate;
    memset(mask, 0, sizeof(*mask));
    switch (p) {
    case 0: break;
    case 1: mask->control[band].legacy = 1; break;
    case 2: mask->control[band].legacy = 1 << 7; break;
    case 3: mask->control[band].legacy = 3; break;
    case 4: mask->control[band].ht_mcs[0] = 1; break;
    case 5: mask->control[band].ht_mcs[1] = 1 << 7; break;
    case 6: mask->control[band].vht_mcs[0] = 1; break;
    case 7: mask->control[band].vht_mcs[3] = 1 << 9; break;
    case 8: mask->control[band].he_mcs[0] = 1; break;
    case 9: mask->control[band].he_mcs[7] = 1 << 11; break;
    case 10: mask->control[band].ht_mcs[0] = 3;
             mask->control[band].vht_mcs[0] = 3;
             mask->control[band].he_mcs[0] = 3; break;
    case 11: mask->control[band].ht_mcs[0] = 1;
             mask->control[band].vht_mcs[1] = 1 << 4;
             mask->control[band].he_mcs[2] = 1 << 5; break;
    case 12: mask->control[(band + 1) % 3].he_mcs[0] = 1; break;
    default: abort();
    }
}
int main(int argc, char **argv) {
    struct ieee80211_channel channels[3] = {{0}, {1}, {2}};
    struct ieee80211_chanctx_conf ctx = {0};
    struct mt76_dev dev = {0};
    struct mt76_phy phy = {.chandef = {&channels[1]}, .dev = &dev};
    struct ieee80211_vif vif = {0};
    const uint32_t basics[] = {0, 1, 3, 1 << 7, 1 << 15};
    const int mcasts[] = {-1, 0, 1, 4, 8, 99};
    const int indexes[] = {-1, 0, 1, 3, 7, 8, 11, 12, 31};
    const u16 expected2[] = {0, 0, 1, 3, 270, 265, 268, 0, 0};
    const u16 expected5[] = {267, 267, 271, 270, 268, 267, 267, 267, 267};
    size_t rate_checks = 0, helper_checks = 0, null_checks = 0;
    if (argc == 2 && !strcmp(argv[1], "base-null")) {
        printf("%u\n", base_rate(&phy, NULL, false, false));
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "guard-only-null")) {
        printf("%u\n", guard_only_rate(&phy, NULL, false, false));
        return 0;
    }
    for (int physical = 0; physical < 3; physical++) {
        phy.chandef.chan = &channels[physical];
        for (int c = -1; c < 3; c++) {
            ctx.def.chan = c < 0 ? NULL : &channels[c];
            vif.drv_priv[0].ctx = c < 0 ? NULL : &ctx;
            int band = c < 0 ? physical : c;
            for (size_t k = 0; k < ARRAY_SIZE(indexes); k++) {
                assert(base_helper(&phy, &vif, indexes[k]) == fixed_helper(&phy, &vif, indexes[k]));
                helper_checks++;
            }
            for (int mt = 0; mt < 2; mt++) {
                dev.mt7921 = mt;
                for (size_t b = 0; b < ARRAY_SIZE(basics); b++) {
                    vif.bss_conf.basic_rates = basics[b];
                    for (size_t m = 0; m < ARRAY_SIZE(mcasts); m++) {
                        for (int i = 0; i < 3; i++) vif.bss_conf.mcast_rate[i] = mcasts[m];
                        for (int p = 0; p < 13; p++) {
                            pattern(&vif, band, p);
                            for (int flags = 0; flags < 4; flags++) {
                                assert(base_rate(&phy, &vif, flags & 1, flags & 2) ==
                                       fixed_rate(&phy, &vif, flags & 1, flags & 2));
                                rate_checks++;
                            }
                        }
                    }
                }
            }
        }
        for (size_t k = 0; k < ARRAY_SIZE(indexes); k++) {
            assert(fixed_helper(&phy, NULL, indexes[k]) ==
                   (physical == 0 ? expected2[k] : expected5[k]));
            null_checks++;
        }
        for (int mt = 0; mt < 2; mt++) {
            dev.mt7921 = mt;
            for (int flags = 0; flags < 4; flags++) {
                u16 expected = physical == 0 ? 0 : FIELD_PREP(MT_TX_RATE_MODE, 1) | FIELD_PREP(MT_TX_RATE_IDX, 11);
                assert(fixed_rate(&phy, NULL, flags & 1, flags & 2) == expected);
                null_checks++;
            }
        }
    }
    printf("{\"nonnull_rate_comparisons\":%zu,\"nonnull_helper_comparisons\":%zu,\"null_checks\":%zu}\n",
           rate_checks, helper_checks, null_checks);
    return 0;
}
''')
source = OUT / 'source-extracted-harness.c'
source.write_text('\n\n'.join(parts) + '\n')
compiler = shutil.which('clang')
assert compiler
cmd = [compiler, '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
       '-Wno-sign-compare', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
       str(source), '-o', str(OUT / 'source-extracted-harness')]
build = subprocess.run(cmd, capture_output=True, text=True)
(OUT / 'compile.log').write_text(build.stdout + build.stderr)
assert build.returncode == 0, build.stderr
env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0:halt_on_error=1:abort_on_error=0',
           UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
results = {}
for mode in ['base-null', 'guard-only-null', 'regression']:
    run = subprocess.run([str(OUT / 'source-extracted-harness')] + ([] if mode == 'regression' else [mode]),
                         capture_output=True, text=True, env=env)
    (OUT / (mode + '.stdout')).write_text(run.stdout)
    (OUT / (mode + '.stderr')).write_text(run.stderr)
    expected = run.returncode != 0 and 'runtime error:' in run.stderr if mode != 'regression' else run.returncode == 0
    results[mode] = {'exit_code': run.returncode, 'expected_outcome_observed': expected}
    if mode == 'regression' and run.returncode == 0:
        results[mode]['checks'] = json.loads(run.stdout)
    assert expected, (mode, run.returncode, run.stdout, run.stderr)

results['patch_application'] = {'git_apply_check': 'PASS', 'applied_bytes_match_pinned_hashes': patch_application_passed}
report = {'schema': 'mt76-source-extracted-host-validation/v1', 'compiler':
          subprocess.check_output([compiler, '--version'], text=True).splitlines()[0],
          'results': results,
          'source_extracted_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
          'limits': 'Synthetic host layout and types, actual source function bodies/table/macros. This is not a target kernel/ABI/module build, live driver test, RF test, Intel receive test, AirDrop test, or proof of a historical panic cause.',
          'kernel_or_rf_operations': 0}
print(json.dumps(report, indent=2))
