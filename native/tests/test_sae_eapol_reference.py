#!/usr/bin/env python3
"""Cross-check production SAE EAPOL paths against independent references.

Run with an isolated oracle environment, from the repository root:

  python3 -m venv /tmp/ax201-sae-oracle
  /tmp/ax201-sae-oracle/bin/pip install --only-binary=:all: --require-hashes \
    -r native/tests/sae-oracle-macos-x86_64.txt
  /tmp/ax201-sae-oracle/bin/python native/tests/test_sae_eapol_reference.py

The requirements pin official PyPI wheel hashes for this test host.
At pin time PyPI's latest cryptography release (50.0.2) had no Intel macOS
wheel, so this test pins the latest compatible universal2 release (48.0.1)
for this CPython 3.9 x86_64 host. Missing cryptography is a hard error because
CMAC is a core oracle, not a skipped check.

The EAPOL/KDF/PAE production function bodies are extracted and compiled in a
host harness. Kernel HMAC/CMAC and key-wrap APIs are test adapters: CommonCrypto
backs the CMAC shim, which is cross-checked against the independent Python
cryptography oracle; AES-wrap dispatch/length are checked with call-recording
stubs, while the oracle library separately passes the RFC 3394 known-answer
vector. This does not validate the kernel's primitive implementation or a
firmware/device execution path.
"""

from __future__ import annotations

import hashlib
import hmac
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

try:
    from cryptography.hazmat.primitives import cmac
    from cryptography.hazmat.primitives.ciphers import algorithms
    from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap
except ImportError as exc:  # pragma: no cover - exercised on an unprovisioned host
    raise SystemExit(
        "Required CMAC/AES-wrap oracle is missing. Create the isolated venv and "
        "install native/tests/sae-oracle-macos-x86_64.txt with --require-hashes; see this "
        "test's module docstring."
    ) from exc

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test082_auth_retry_cleanup import production_function


ROOT = Path(__file__).resolve().parents[2]
CRYPTO_C = ROOT / "itl80211/openbsd/net80211/ieee80211_crypto.c"
CRYPTO_H = ROOT / "itl80211/openbsd/net80211/ieee80211_crypto.h"
IEEE_H = ROOT / "itl80211/openbsd/net80211/ieee80211.h"
PAE_IN = ROOT / "itl80211/openbsd/net80211/ieee80211_pae_input.c"
PAE_OUT = ROOT / "itl80211/openbsd/net80211/ieee80211_pae_output.c"


def cmac_oracle(key: bytes, message: bytes) -> bytes:
    ctx = cmac.CMAC(algorithms.AES(key))
    ctx.update(message)
    return ctx.finalize()


def check_public_vectors() -> None:
    # RFC 4493, section 4, Example 2 (one complete AES block).
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    message = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    expected = bytes.fromhex("070a16b46b4d4144f79bdd9dd04a287c")
    assert cmac_oracle(key, message) == expected

    # RFC 3394, section 4.1 AES-128 key-wrap known-answer vector.
    kek = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    wrapped = bytes.fromhex(
        "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"
    )
    assert aes_key_wrap(kek, plaintext) == wrapped
    assert aes_key_unwrap(kek, wrapped) == plaintext


def extract_descriptor_contracts(pae_in: str, pae_out: str) -> tuple[str, str]:
    start = pae_in.index("    /* Ordinary SAE uses AKM-defined descriptor version 0. */")
    end = pae_in.index("    /* make sure the key data field is contiguous */", start)
    ingress = pae_in[start:end]

    start = pae_out.index("    info &= ~EAPOL_KEY_VERSION_MASK;")
    end_marker = "    BE_WRITE_2(key->info, info);"
    end = pae_out.index(end_marker, start) + len(end_marker)
    egress = pae_out[start:end]
    return ingress, egress


def derive_ptk_sha256(
    pmk: bytes, aa: bytes, spa: bytes, anonce: bytes, snonce: bytes
) -> bytes:
    addresses = min(aa, spa) + max(aa, spa)
    nonces = min(anonce, snonce) + max(anonce, snonce)
    context = addresses + nonces
    # Production passes length 23, including the string's terminating NUL.
    label = b"Pairwise key expansion\x00"
    bit_length = (64 * 8).to_bytes(2, "little")
    return b"".join(
        hmac.new(
            pmk,
            counter.to_bytes(2, "little") + label + context + bit_length,
            hashlib.sha256,
        ).digest()
        for counter in range(1, 3)
    )


def derive_ptk_legacy(
    pmk: bytes, aa: bytes, spa: bytes, anonce: bytes, snonce: bytes
) -> bytes:
    addresses = min(aa, spa) + max(aa, spa)
    nonces = min(anonce, snonce) + max(anonce, snonce)
    context = addresses + nonces
    # Production passes length 23, including the string's terminating NUL.
    label = b"Pairwise key expansion\x00"
    return b"".join(
        hmac.new(pmk, label + context + bytes((counter,)), hashlib.sha1).digest()
        for counter in range(4)
    )[:64]


CPP_PREAMBLE = r"""
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonHMAC.h>
#include <assert.h>
#include <initializer_list>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

using u_int8_t = uint8_t;
using u_int16_t = uint16_t;
using u_int32_t = uint32_t;
using u_int64_t = uint64_t;
using u_int = unsigned int;
constexpr unsigned SHA1_DIGEST_LENGTH = 20;
constexpr unsigned SHA256_DIGEST_LENGTH = 32;
constexpr unsigned EAPOL_KEY_NONCE_LEN = 32;
constexpr unsigned EAPOL_KEY_IV_LEN = 16;
constexpr unsigned EAPOL_KEY_MIC_LEN = 16;
constexpr unsigned IEEE80211_ADDR_LEN = 6;
constexpr unsigned IEEE80211_PMK_LEN = 32;
constexpr unsigned IEEE80211_PMKID_LEN = 16;
constexpr unsigned EAPOL_KEY_VERSION_MASK = 0x7;
constexpr unsigned EAPOL_KEY_DESC_AKM_DEFINED = 0;
constexpr unsigned EAPOL_KEY_DESC_V1 = 1;
constexpr unsigned EAPOL_KEY_DESC_V2 = 2;
constexpr unsigned EAPOL_KEY_DESC_V3 = 3;
constexpr unsigned IEEE80211_AKM_NONE = 0;
constexpr unsigned IEEE80211_AKM_8021X = 1;
constexpr unsigned IEEE80211_AKM_PSK = 2;
constexpr unsigned IEEE80211_AKM_SHA256_8021X = 4;
constexpr unsigned IEEE80211_AKM_SHA256_PSK = 8;
constexpr unsigned IEEE80211_AKM_SAE = 16;
constexpr unsigned IEEE80211_CIPHER_TKIP = 4;
constexpr unsigned IEEE80211_CIPHER_CCMP = 8;
constexpr unsigned IEEE80211_M_STA = 1;
constexpr unsigned IEEE80211_M_IBSS = 2;
constexpr unsigned IEEE80211_PROTO_RSN = 1;
constexpr unsigned IEEE80211_PROTO_WPA = 2;
constexpr unsigned IEEE80211_NODE_MFP = 0x0080;
constexpr unsigned IEEE80211_NODE_PMK = 0x0100;
constexpr unsigned IEEE80211_NODE_RSN_NEW_PTK = 0x2000;
constexpr unsigned RSNA_SUPP_INITIALIZE = 0;
constexpr unsigned IEEE80211_ELEMID_VENDOR = 221;
constexpr unsigned IEEE80211_KDE_PMKID = 4;
constexpr unsigned EAPOL_VERSION = 1;
constexpr unsigned EAPOL_KEY = 3;
constexpr unsigned RC4STATE = 256;
constexpr unsigned IFF_DEBUG = 1;
#define XYLog(...) ((void)0)
#define DPRINTF(...) ((void)0)
#define AIRPORT_TAHOE 1
#define htole16(v) (v)
#define BE_READ_2(p) ((uint16_t)(((const uint8_t *)(p))[0] << 8 | ((const uint8_t *)(p))[1]))
#define BE_WRITE_2(p, v) do { ((uint8_t *)(p))[0] = (uint8_t)((v) >> 8); ((uint8_t *)(p))[1] = (uint8_t)(v); } while (0)

enum ieee80211_akm {
    IEEE80211_AKM_ENUM_NONE = IEEE80211_AKM_NONE,
    IEEE80211_AKM_ENUM_8021X = IEEE80211_AKM_8021X,
    IEEE80211_AKM_ENUM_PSK = IEEE80211_AKM_PSK,
    IEEE80211_AKM_ENUM_SHA256_8021X = IEEE80211_AKM_SHA256_8021X,
    IEEE80211_AKM_ENUM_SHA256_PSK = IEEE80211_AKM_SHA256_PSK,
    IEEE80211_AKM_ENUM_SAE = IEEE80211_AKM_SAE
};
enum ieee80211_cipher {
    IEEE80211_CIPHER_ENUM_TKIP = IEEE80211_CIPHER_TKIP,
    IEEE80211_CIPHER_ENUM_CCMP = IEEE80211_CIPHER_CCMP
};

struct __attribute__((packed)) ieee80211_eapol_key {
    uint8_t version, type, len[2], desc, info[2], keylen[2], replaycnt[8];
    uint8_t nonce[32], iv[16], rsc[8], reserved[8], mic[16], paylen[2];
};
static_assert(sizeof(ieee80211_eapol_key) == 99, "EAPOL-Key wire size");
struct __attribute__((packed)) ieee80211_ptk { uint8_t kck[16], kek[16], tk[32]; };
struct ieee80211_pmk { uint8_t pmk_key[32]; };

struct ieee80211_node {
    uint32_t ni_flags = 0;
    uint32_t ni_rsnakms = IEEE80211_AKM_PSK;
    uint32_t ni_rsncipher = IEEE80211_CIPHER_CCMP;
    uint32_t ni_rsngroupcipher = IEEE80211_CIPHER_CCMP;
    int ni_rsn_supp_state = 1;
    bool ni_replaycnt_ok = false;
    uint64_t ni_replaycnt = 0;
    uint8_t ni_pmk[32]{};
    uint8_t ni_pmkid[16]{};
    uint8_t ni_macaddr[6]{};
    uint8_t ni_nonce[32]{};
    uint32_t ni_pmf_key_epoch = 0;
    uint8_t ni_pmf_link_pending = 0;
    uint8_t ni_pmf_key_batch_ready = 0;
    uint32_t ni_pmf_pending_key_ids = 0;
};
struct test_ifnet { unsigned if_flags = 0; char if_xname[16]{}; };
struct test_stats { unsigned is_rx_eapol_replay = 0; };
struct ieee80211com {
    int ic_opmode = IEEE80211_M_STA;
    uint8_t ic_psk[32]{};
    uint8_t ic_nonce[32]{};
    uint8_t ic_myaddr[6]{};
    uint8_t ic_globalcnt[32]{};
    test_ifnet ic_if{};
    test_stats ic_stats{};
};
static const uint8_t IEEE80211_OUI[3] = {0x00, 0x0f, 0xac};
static unsigned gSha1Finals = 0, gSha256Finals = 0;
static unsigned gAesWrapOnlyCalls = 0, gAesWrapCalls = 0;
static unsigned gAesUnwrapSetupCalls = 0, gAesUnwrapCalls = 0;
static unsigned gRc4Calls = 0, gMsg2Calls = 0;
static ieee80211_ptk gSentPtk{};

static uint64_t BE_READ_8(const uint8_t *p) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value = (value << 8) | p[i];
    return value;
}
static void BE_WRITE_8(uint8_t *p, uint64_t value) {
    for (int i = 7; i >= 0; --i) { p[i] = (uint8_t)value; value >>= 8; }
}
static const char *ether_sprintf(const uint8_t *) { return "test-peer"; }
static void arc4random_buf(void *p, size_t n) {
    auto *b = static_cast<uint8_t *>(p);
    for (size_t i = 0; i < n; ++i) b[i] = (uint8_t)(0xa0 + i);
}

struct HMAC_SHA1_CTX { uint8_t key[64]; size_t keylen; uint8_t data[2048]; size_t len; };
struct HMAC_SHA256_CTX { uint8_t key[64]; size_t keylen; uint8_t data[2048]; size_t len; };
struct HMAC_MD5_CTX { uint8_t key[64]; size_t keylen; uint8_t data[2048]; size_t len; };
static void hmac_init(uint8_t *key, size_t *keylen, uint8_t *data, size_t *len,
                      const uint8_t *source, size_t source_len) {
    assert(source_len <= 64); memcpy(key, source, source_len); *keylen = source_len; *len = 0;
    (void)data;
}
static void hmac_update(uint8_t *data, size_t *len, const uint8_t *input, size_t n) {
    assert(*len + n <= 2048); memcpy(data + *len, input, n); *len += n;
}
static void HMAC_SHA1_Init(HMAC_SHA1_CTX *c, const uint8_t *key, size_t n)
{ hmac_init(c->key, &c->keylen, c->data, &c->len, key, n); }
static void HMAC_SHA1_Update(HMAC_SHA1_CTX *c, const uint8_t *p, size_t n)
{ hmac_update(c->data, &c->len, p, n); }
static void HMAC_SHA1_Final(uint8_t *out, HMAC_SHA1_CTX *c) {
    CCHmac(kCCHmacAlgSHA1, c->key, c->keylen, c->data, c->len, out); ++gSha1Finals;
}
static void HMAC_SHA256_Init(HMAC_SHA256_CTX *c, const uint8_t *key, size_t n)
{ hmac_init(c->key, &c->keylen, c->data, &c->len, key, n); }
static void HMAC_SHA256_Update(HMAC_SHA256_CTX *c, const uint8_t *p, size_t n)
{ hmac_update(c->data, &c->len, p, n); }
static void HMAC_SHA256_Final(uint8_t *out, HMAC_SHA256_CTX *c) {
    CCHmac(kCCHmacAlgSHA256, c->key, c->keylen, c->data, c->len, out); ++gSha256Finals;
}
static void HMAC_MD5_Init(HMAC_MD5_CTX *c, const uint8_t *key, size_t n)
{ hmac_init(c->key, &c->keylen, c->data, &c->len, key, n); }
static void HMAC_MD5_Update(HMAC_MD5_CTX *c, const uint8_t *p, size_t n)
{ hmac_update(c->data, &c->len, p, n); }
static void HMAC_MD5_Final(uint8_t *out, HMAC_MD5_CTX *c)
{ CCHmac(kCCHmacAlgMD5, c->key, c->keylen, c->data, c->len, out); }

struct AES_CMAC_CTX { uint8_t key[16]; uint8_t data[4096]; size_t len; };
typedef union _ANY_CTX { HMAC_MD5_CTX md5; HMAC_SHA1_CTX sha1; AES_CMAC_CTX cmac; } ANY_CTX;
static bool aes_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    size_t moved = 0;
    return CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionECBMode,
                   key, kCCKeySizeAES128, nullptr, in, 16, out, 16, &moved) == kCCSuccess && moved == 16;
}
static void cmac_double(uint8_t out[16], const uint8_t in[16]) {
    uint8_t carry = 0;
    for (int i = 15; i >= 0; --i) { uint8_t b = in[i]; out[i] = (uint8_t)((b << 1) | carry); carry = (uint8_t)(b >> 7); }
    if (carry) out[15] ^= 0x87;
}
static void independent_test_cmac(const uint8_t key[16], const uint8_t *data,
                                  size_t len, uint8_t out[16]) {
    uint8_t zero[16]{}, l[16], k1[16], k2[16], state[16]{};
    assert(aes_encrypt_block(key, zero, l)); cmac_double(k1, l); cmac_double(k2, k1);
    size_t blocks = len == 0 ? 1 : (len + 15) / 16;
    bool complete = len != 0 && (len % 16) == 0;
    for (size_t n = 0; n + 1 < blocks; ++n) {
        for (unsigned i = 0; i < 16; ++i) state[i] ^= data[n * 16 + i];
        uint8_t next[16]; assert(aes_encrypt_block(key, state, next)); memcpy(state, next, 16);
    }
    uint8_t final_block[16]{};
    size_t offset = (blocks - 1) * 16;
    size_t remainder = len - offset;
    if (remainder) memcpy(final_block, data + offset, remainder);
    if (!complete) final_block[remainder] = 0x80;
    const uint8_t *subkey = complete ? k1 : k2;
    for (unsigned i = 0; i < 16; ++i) state[i] ^= final_block[i] ^ subkey[i];
    assert(aes_encrypt_block(key, state, out));
}
static void AES_CMAC_Init(AES_CMAC_CTX *c) { memset(c, 0, sizeof(*c)); }
static void AES_CMAC_SetKey(AES_CMAC_CTX *c, const uint8_t *key) { memcpy(c->key, key, 16); }
static void AES_CMAC_Update(AES_CMAC_CTX *c, const uint8_t *data, size_t n) {
    assert(c->len + n <= sizeof(c->data)); memcpy(c->data + c->len, data, n); c->len += n;
}
static void AES_CMAC_Final(uint8_t *out, AES_CMAC_CTX *c)
{ independent_test_cmac(c->key, c->data, c->len, out); }

struct rc4_ctx { uint8_t unused; };
struct aes_key_wrap_ctx { uint8_t unused; };
static void aes_key_wrap_set_key_wrap_only(aes_key_wrap_ctx *, const uint8_t *, size_t)
{ ++gAesWrapOnlyCalls; }
static void aes_key_wrap(aes_key_wrap_ctx *, const uint8_t *in, size_t blocks, uint8_t *out) {
    ++gAesWrapCalls; assert(blocks == 2); memmove(out, in, 16); memset(out + 16, 0xa5, 8);
}
static void aes_key_wrap_set_key(aes_key_wrap_ctx *, const uint8_t *, size_t)
{ ++gAesUnwrapSetupCalls; }
static int aes_key_unwrap(aes_key_wrap_ctx *, const uint8_t *, uint8_t *, size_t blocks)
{ ++gAesUnwrapCalls; assert(blocks == 2); return 0; }
static void rc4_keysetup(rc4_ctx *, const uint8_t *, size_t) { ++gRc4Calls; }
static void rc4_skip(rc4_ctx *, size_t) { ++gRc4Calls; }
static void rc4_crypt(rc4_ctx *, const uint8_t *, const uint8_t *, size_t) { ++gRc4Calls; }

static int ieee80211_is_8021x_akm(enum ieee80211_akm akm) {
    return akm == IEEE80211_AKM_ENUM_8021X || akm == IEEE80211_AKM_ENUM_SHA256_8021X;
}
static ieee80211_pmk *ieee80211_pmksa_find(ieee80211com *, ieee80211_node *, const uint8_t *)
{ return nullptr; }
static int ieee80211_send_4way_msg2(ieee80211com *, ieee80211_node *, const uint8_t *, ieee80211_ptk *ptk) {
    ++gMsg2Calls; memcpy(&gSentPtk, ptk, sizeof(*ptk)); return 0;
}
"""


def make_harness() -> str:
    crypto = CRYPTO_C.read_text()
    crypto_h = CRYPTO_H.read_text()
    ieee_h = IEEE_H.read_text()
    pae_in = PAE_IN.read_text()
    pae_out = PAE_OUT.read_text()

    functions = [
        production_function(crypto_h, "static __inline int\nieee80211_is_sha256_akm(enum ieee80211_akm akm"),
        production_function(crypto, "void\nieee80211_prf(const u_int8_t *key"),
        production_function(crypto, "void\nieee80211_kdf(const u_int8_t *key"),
        production_function(crypto, "void\nieee80211_derive_ptk(enum ieee80211_akm akm"),
        production_function(crypto, "void\nieee80211_eapol_key_mic(struct ieee80211_eapol_key *key"),
        production_function(crypto, "int\nieee80211_eapol_key_check_mic(struct ieee80211_eapol_key *key"),
        production_function(crypto, "void\nieee80211_eapol_key_encrypt(struct ieee80211com *ic"),
        production_function(crypto, "int\nieee80211_eapol_key_decrypt(struct ieee80211_eapol_key *key"),
        production_function(pae_in, "void\nieee80211_recv_4way_msg1(struct ieee80211com *ic"),
    ]
    ingress, egress = extract_descriptor_contracts(pae_in, pae_out)

    helpers = r"""
static bool production_admit_descriptor(uint32_t akm, uint32_t cipher,
                                        uint32_t group_cipher, uint16_t info) {
    ieee80211_node node{};
    node.ni_rsnakms = akm;
    node.ni_rsncipher = cipher;
    node.ni_rsngroupcipher = group_cipher;
    auto *ni = &node;
    u_int16_t desc = 0;
@@INGRESS@@
    return true;
done:
    return false;
}
static uint16_t production_output_descriptor(uint32_t akm, uint32_t cipher,
                                             uint32_t group_cipher, uint16_t initial_info) {
    ieee80211_node node{};
    node.ni_rsnakms = akm;
    node.ni_rsncipher = cipher;
    node.ni_rsngroupcipher = group_cipher;
    auto *ni = &node;
    ieee80211_eapol_key storage{};
    auto *key = &storage;
    u_int16_t info = initial_info;
    BE_WRITE_2(key->info, info);
    info = BE_READ_2(key->info);
@@EGRESS@@
    return BE_READ_2(key->info) & EAPOL_KEY_VERSION_MASK;
}
static void emit_ptk(const char *label, enum ieee80211_akm akm) {
    uint8_t pmk[32], aa[6] = {2,0x11,0x22,0x33,0x44,0x55};
    uint8_t spa[6] = {2,0xaa,0xbb,0xcc,0xdd,0xee};
    uint8_t anonce[32], snonce[32];
    for (unsigned i=0;i<32;++i) { pmk[i]=(uint8_t)i; anonce[i]=(uint8_t)i; snonce[i]=(uint8_t)(0x80+i); }
    ieee80211_ptk ptk{};
    ieee80211_derive_ptk(akm, pmk, aa, spa, anonce, snonce, &ptk);
    printf("PTK_%s ", label);
    const auto *bytes = reinterpret_cast<const uint8_t *>(&ptk);
    for (size_t i=0;i<sizeof(ptk);++i) printf("%02x", bytes[i]);
    printf("\n");
}
static void exercise_mic() {
    struct __attribute__((packed)) frame { ieee80211_eapol_key key; uint8_t data[8]; } f{};
    f.key.version = EAPOL_VERSION; f.key.type = EAPOL_KEY;
    BE_WRITE_2(f.key.len, 103); f.key.desc = 2;
    BE_WRITE_2(f.key.info, 0x0108); BE_WRITE_2(f.key.keylen, 16);
    BE_WRITE_8(f.key.replaycnt, UINT64_C(0x0102030405060708));
    for (unsigned i=0;i<32;++i) f.key.nonce[i]=(uint8_t)(0x30+i);
    for (unsigned i=0;i<16;++i) f.key.iv[i]=(uint8_t)(0x50+i);
    for (unsigned i=0;i<8;++i) { f.key.rsc[i]=(uint8_t)(0x70+i); f.key.reserved[i]=(uint8_t)(0x80+i); f.data[i]=(uint8_t)(0x90+i); }
    BE_WRITE_2(f.key.paylen, 8);
    uint8_t kck[16]; for (unsigned i=0;i<16;++i) kck[i]=(uint8_t)(0xa0+i);
    ieee80211_eapol_key_mic(&f.key, kck);
    printf("EAPOL_FRAME ");
    const auto *bytes = reinterpret_cast<const uint8_t *>(&f);
    for (size_t i=0;i<sizeof(f);++i) printf("%02x", bytes[i]);
    printf("\n");
    auto valid = f;
    assert(ieee80211_eapol_key_check_mic(&valid.key, kck) == 0);
    auto tampered = f; tampered.data[3] ^= 1;
    assert(ieee80211_eapol_key_check_mic(&tampered.key, kck) != 0);
    auto wrong_key = f; uint8_t bad_kck[16]; memcpy(bad_kck,kck,16); bad_kck[0] ^= 1;
    assert(ieee80211_eapol_key_check_mic(&wrong_key.key, bad_kck) != 0);
}
static void exercise_aes_wrap_dispatch() {
    struct __attribute__((packed)) frame { ieee80211_eapol_key key; uint8_t data[32]; } f{};
    BE_WRITE_2(f.key.info, EAPOL_KEY_DESC_AKM_DEFINED);
    BE_WRITE_2(f.key.paylen, 16); BE_WRITE_2(f.key.len, 111);
    for (unsigned i=0;i<16;++i) f.data[i]=(uint8_t)i;
    uint8_t kek[16]{}; ieee80211com ic{};
    ieee80211_eapol_key_encrypt(&ic, &f.key, kek);
    assert(gAesWrapOnlyCalls == 1 && gAesWrapCalls == 1 && gRc4Calls == 0);
    assert(BE_READ_2(f.key.paylen) == 24 && BE_READ_2(f.key.len) == 119);
    assert(ieee80211_eapol_key_decrypt(&f.key, kek) == 0);
    assert(gAesUnwrapSetupCalls == 1 && gAesUnwrapCalls == 1 && gRc4Calls == 0);
}
static void exercise_m1_pmk_handoff_and_replay() {
    ieee80211com ic{};
    for (unsigned i=0;i<32;++i) { ic.ic_psk[i]=0x5a; ic.ic_nonce[i]=0x33; }
    ieee80211_eapol_key key{};
    BE_WRITE_2(key.len, 95); BE_WRITE_2(key.paylen, 0); BE_WRITE_8(key.replaycnt, 1);
    ieee80211_node sae{}; sae.ni_rsnakms=IEEE80211_AKM_SAE; sae.ni_rsn_supp_state=1;
    memset(sae.ni_pmk, 0x22, sizeof(sae.ni_pmk));
    unsigned before = gSha256Finals; gMsg2Calls=0;
    ieee80211_recv_4way_msg1(&ic, &key, &sae);
    assert(gSha256Finals == before && gMsg2Calls == 0);
    assert((sae.ni_flags & IEEE80211_NODE_PMK) == 0 && sae.ni_pmk[0] == 0x22);

    // The SAE confirm path supplies NODE_PMK; only then may Msg1 derive PTK/send Msg2.
    for (unsigned i=0;i<32;++i) sae.ni_pmk[i]=(uint8_t)(0xc0+i);
    sae.ni_flags |= IEEE80211_NODE_PMK; sae.ni_replaycnt_ok=true; sae.ni_replaycnt=1;
    BE_WRITE_8(key.replaycnt, 2); before=gSha256Finals;
    ieee80211_recv_4way_msg1(&ic, &key, &sae);
    assert(gSha256Finals > before && gMsg2Calls == 1);
    assert(gSentPtk.kck[0] != 0);

    // Replayed Msg1 cannot derive or send another Msg2.
    sae.ni_replaycnt=2; before=gSha256Finals;
    ieee80211_recv_4way_msg1(&ic, &key, &sae);
    assert(gSha256Finals == before && gMsg2Calls == 1 && ic.ic_stats.is_rx_eapol_replay == 1);

    // WPA2 PSK keeps its legacy PMK source and is not routed through the SAE guard.
    ieee80211_node psk{}; psk.ni_rsnakms=IEEE80211_AKM_PSK; psk.ni_rsn_supp_state=1;
    memset(psk.ni_pmk, 0x11, sizeof(psk.ni_pmk)); BE_WRITE_8(key.replaycnt, 3);
    ieee80211_recv_4way_msg1(&ic, &key, &psk);
    assert((psk.ni_flags & IEEE80211_NODE_PMK) != 0);
    assert(memcmp(psk.ni_pmk, ic.ic_psk, sizeof(psk.ni_pmk)) == 0 && gMsg2Calls == 2);
}
int main() {
    assert(production_admit_descriptor(IEEE80211_AKM_SAE, IEEE80211_CIPHER_CCMP,
                                       IEEE80211_CIPHER_CCMP, 0));
    for (uint16_t d=1; d<=3; ++d)
        assert(!production_admit_descriptor(IEEE80211_AKM_SAE, IEEE80211_CIPHER_CCMP,
                                           IEEE80211_CIPHER_CCMP, d));
    assert(production_admit_descriptor(IEEE80211_AKM_PSK, IEEE80211_CIPHER_CCMP,
                                       IEEE80211_CIPHER_CCMP, EAPOL_KEY_DESC_V2));
    for (uint16_t d : {uint16_t(0),uint16_t(1),uint16_t(3)})
        assert(!production_admit_descriptor(IEEE80211_AKM_PSK, IEEE80211_CIPHER_CCMP,
                                           IEEE80211_CIPHER_CCMP, d));
    assert(production_admit_descriptor(IEEE80211_AKM_SHA256_PSK, IEEE80211_CIPHER_CCMP,
                                       IEEE80211_CIPHER_CCMP, EAPOL_KEY_DESC_V3));
    for (uint16_t d : {uint16_t(0),uint16_t(1),uint16_t(2)})
        assert(!production_admit_descriptor(IEEE80211_AKM_SHA256_PSK, IEEE80211_CIPHER_CCMP,
                                           IEEE80211_CIPHER_CCMP, d));
    assert(production_output_descriptor(IEEE80211_AKM_SAE, IEEE80211_CIPHER_CCMP,
                                        IEEE80211_CIPHER_CCMP, 0x0108) == 0);
    assert(production_output_descriptor(IEEE80211_AKM_PSK, IEEE80211_CIPHER_CCMP,
                                        IEEE80211_CIPHER_CCMP, 0x0108) == EAPOL_KEY_DESC_V2);
    assert(production_output_descriptor(IEEE80211_AKM_SHA256_PSK, IEEE80211_CIPHER_CCMP,
                                        IEEE80211_CIPHER_CCMP, 0x0108) == EAPOL_KEY_DESC_V3);
    emit_ptk("SAE", static_cast<ieee80211_akm>(IEEE80211_AKM_SAE));
    emit_ptk("SHA256_PSK", static_cast<ieee80211_akm>(IEEE80211_AKM_SHA256_PSK));
    emit_ptk("PSK", static_cast<ieee80211_akm>(IEEE80211_AKM_PSK));
    exercise_mic();
    exercise_aes_wrap_dispatch();
    exercise_m1_pmk_handoff_and_replay();
    puts("PASS production SAE EAPOL harness");
}
"""
    helpers = helpers.replace("@@INGRESS@@", ingress).replace("@@EGRESS@@", egress)
    return CPP_PREAMBLE + "\n" + "\n".join(functions) + "\n" + helpers


def main() -> None:
    check_public_vectors()
    source = make_harness()
    compiler = shutil.which("clang++")
    if compiler is None:
        raise SystemExit("clang++ is required to compile the production-function harness")
    with tempfile.TemporaryDirectory(prefix="sae-eapol-reference-") as temp_dir:
        tmp = Path(temp_dir)
        cpp = tmp / "test.cpp"
        exe = tmp / "test"
        cpp.write_text(source)
        subprocess.run(
            [compiler, "-std=c++17", "-Wall", "-Wextra", "-Wno-deprecated-declarations",
             "-Wno-unused-const-variable", "-Wno-unused-function",
             "-I", str(ROOT), str(cpp), "-o", str(exe)],
            check=True,
        )
        completed = subprocess.run([str(exe)], text=True, capture_output=True)
        if completed.returncode != 0:
            sys.stderr.write(completed.stdout)
            sys.stderr.write(completed.stderr)
            raise subprocess.CalledProcessError(completed.returncode, [str(exe)])

    lines = completed.stdout.splitlines()
    values = {}
    for line in lines:
        if " " in line:
            key, value = line.split(" ", 1)
            values[key] = value.strip()

    pmk = bytes(range(32))
    aa = bytes((2, 0x11, 0x22, 0x33, 0x44, 0x55))
    spa = bytes((2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee))
    anonce = bytes(range(32))
    snonce = bytes(range(0x80, 0xa0))
    assert bytes.fromhex(values["PTK_SAE"]) == derive_ptk_sha256(pmk, aa, spa, anonce, snonce)
    assert bytes.fromhex(values["PTK_SHA256_PSK"]) == derive_ptk_sha256(pmk, aa, spa, anonce, snonce)
    assert bytes.fromhex(values["PTK_PSK"]) == derive_ptk_legacy(pmk, aa, spa, anonce, snonce)

    eapol_frame = bytearray.fromhex(values["EAPOL_FRAME"])
    assert len(eapol_frame) == 107
    assert eapol_frame[5:7] == bytes((0x01, 0x08))  # Key MIC + pairwise, descriptor version 0.
    mic_offset = 81
    actual_mic = bytes(eapol_frame[mic_offset : mic_offset + 16])
    eapol_frame[mic_offset : mic_offset + 16] = bytes(16)
    kck = bytes(range(0xa0, 0xb0))
    assert actual_mic == cmac_oracle(kck, bytes(eapol_frame))
    print("PASS: RFC 4493 CMAC + RFC 3394 AES-wrap KATs")
    print("PASS: production SAE descriptor 0 ingress/egress; WPA2 CCMP v2; SHA256-PSK v3")
    print("PASS: production SAE PTK KDF SHA-256; PSK legacy PRF-SHA1 reference")
    print("PASS: production SAE EAPOL MIC/check; tamper and wrong-KCK rejection")
    print("PASS: production descriptor-0 AES-wrap dispatch and unwrap dispatch")
    print("PASS: production Msg1 PMK gate after SAE confirm and replay rejection")
    print("Evidence scope: source-function host harness and software crypto oracle only")


if __name__ == "__main__":
    main()
