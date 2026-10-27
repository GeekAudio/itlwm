//
//  AirportItlwmSkywalkInterface.cpp
//  AirportItlwm-Sonoma
//
//  Created by qcwap on 2023/6/27.
//  Copyright © 2023 钟先耀. All rights reserved.
//
#include "AirportItlwmV2.hpp"
#include "AirportItlwmSkywalkInterface.hpp"
#include <sys/CTimeout.hpp>
#include <libkern/c++/OSMetaClass.h>
#include <crypto/sha1.h>
#include <net80211/ieee80211_node.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_priv.h>
#ifdef AIRPORT_TAHOE
#include "../itlwm/hal_iwx/IwxTxRate.hpp"
#include "../native/key_material.hpp"
#include "../native/runtime_guard.hpp"
#include "../native/scan_address.hpp"
#include "../native/wcl_channels.hpp"
extern IOCommandGate *_fCommandGate;

static void publishCurrentTxRateDiagnostics(
    AirportItlwmSkywalkInterface *interface,
    const IwxTxRate::Snapshot &snapshot,
    const IwxTxRate::Decoded *rate, IOReturn status);

static IOReturn decodeCurrentTxRate(AirportItlwmSkywalkInterface *interface,
                                    struct ieee80211com *ic,
                                    IwxTxRate::Decoded *rate)
{
    IwxTxRate::Snapshot snapshot{};
    IOReturn result = kIOReturnNotReady;
    if (interface == nullptr || rate == nullptr) {
        result = kIOReturnBadArgument;
        publishCurrentTxRateDiagnostics(interface, snapshot, nullptr, result);
        return result;
    }
    if (ic != nullptr && ic->ic_bss != nullptr) {
        struct ieee80211_node *ni = ic->ic_bss;
        const uint32_t generationBefore = __atomic_load_n(
            &ni->ni_tx_rate_generation, __ATOMIC_ACQUIRE);
        if (!IwxTxRate::readSnapshot(
                &ni->ni_tx_rate_sequence, &ni->ni_tx_rate_sample,
                &ni->ni_tx_rate_flags_raw, &ni->ni_tx_rate_sample_generation,
                &ni->ni_tx_rate_update_count, &ni->ni_tx_rate_single_count,
                &ni->ni_tx_rate_aggregate_count, &snapshot)) {
            result = kIOReturnNotReady;
        } else {
            const uint32_t generationAfter = __atomic_load_n(
                &ni->ni_tx_rate_generation, __ATOMIC_ACQUIRE);
            const IwxTxRate::CurrentStatus status = generationBefore != generationAfter
                ? IwxTxRate::CurrentNotReady
                : IwxTxRate::decodeCurrentSample(
                    ic->ic_state == IEEE80211_S_RUN, true, snapshot.sample,
                    snapshot.generation, generationAfter, rate);
            switch (status) {
                case IwxTxRate::CurrentReady: result = kIOReturnSuccess; break;
                case IwxTxRate::CurrentNotReady: result = kIOReturnNotReady; break;
                case IwxTxRate::CurrentUnsupported: result = kIOReturnUnsupported; break;
                case IwxTxRate::CurrentBadArgument: result = kIOReturnBadArgument; break;
            }
        }
    } else if (ic == nullptr) {
        result = kIOReturnBadArgument;
    }
    publishCurrentTxRateDiagnostics(interface, snapshot, rate, result);
    return result;
}

static void publishCurrentTxRateDiagnostics(
    AirportItlwmSkywalkInterface *interface,
    const IwxTxRate::Snapshot &snapshot,
    const IwxTxRate::Decoded *rate, IOReturn status)
{
    if (interface == nullptr)
        return;
    const IwxTxRate::DecodedSample metadata =
        IwxTxRate::unpackCurrentSample(snapshot.sample);
    uint32_t mbps = 0;
    const bool valid = status == kIOReturnSuccess && rate != nullptr &&
        IwxTxRate::rateMbps(*rate, &mbps);
    interface->setProperty("NativeTxRateValid", valid ? 1U : 0U, 32);
    interface->setProperty("NativeTxRateSource",
                           static_cast<uint32_t>(metadata.source), 32);
    interface->setProperty("NativeTxRateVersion",
                           static_cast<uint32_t>(metadata.firmwareVersion), 32);
    interface->setProperty("NativeTxRateRawFlags", snapshot.rawFlags, 32);
    interface->setProperty("NativeTxRateNormalizedFlags",
                           metadata.normalizedFlags, 32);
    interface->setProperty("NativeTxRateUpdateCount", snapshot.updateCount, 32);
    interface->setProperty("NativeTxRateSingleCount", snapshot.singleCount, 32);
    interface->setProperty("NativeTxRateAggregateCount",
                           snapshot.aggregateCount, 32);
    interface->setProperty("NativeTxRateMbps", valid ? mbps : 0U, 32);
    interface->setProperty("NativeTxRateFormat",
                           valid ? static_cast<uint32_t>(rate->format) : 0U, 32);
    interface->setProperty("NativeTxRateMcs",
                           valid ? static_cast<uint32_t>(rate->mcs) : 0U, 32);
    interface->setProperty("NativeTxRateNss",
                           valid ? static_cast<uint32_t>(rate->nss) : 0U, 32);
    interface->setProperty("NativeTxRateBandwidthMHz",
                           valid ? static_cast<uint32_t>(rate->bandwidthMHz) : 0U, 32);
    interface->setProperty("NativeTxRateGuardIntervalNs",
                           valid ? static_cast<uint32_t>(rate->guardIntervalNs) : 0U, 32);
}
#endif

#define super IO80211InfraProtocol
OSDefineMetaClassAndStructors(AirportItlwmSkywalkInterface, IO80211InfraProtocol);

const char* hexdump(uint8_t *buf, size_t len) {
    ssize_t str_len = len * 3 + 1;
    char *str = (char*)IOMalloc(str_len);
    if (!str)
        return nullptr;
    for (size_t i = 0; i < len; i++)
    snprintf(str + 3 * i, (len - i) * 3, "%02x ", buf[i]);
    str[MAX(str_len - 2, 0)] = 0;
    return str;
}

static int ieeeChanFlag2appleScanFlagVentura(int flags)
{
    int ret = 0;
    if (flags & IEEE80211_CHAN_2GHZ)
        ret |= APPLE80211_C_FLAG_2GHZ;
    if (flags & IEEE80211_CHAN_5GHZ)
        ret |= APPLE80211_C_FLAG_5GHZ;
    ret |= (APPLE80211_C_FLAG_ACTIVE | APPLE80211_C_FLAG_20MHZ);
    return ret;
}

static int ieeeChanFlag2apple(int flags, int bw)
{
    int ret = 0;
    if (flags & IEEE80211_CHAN_2GHZ)
        ret |= APPLE80211_C_FLAG_2GHZ;
    if (flags & IEEE80211_CHAN_5GHZ)
        ret |= APPLE80211_C_FLAG_5GHZ;
    if (!(flags & IEEE80211_CHAN_PASSIVE))
        ret |= APPLE80211_C_FLAG_ACTIVE;
    if (flags & IEEE80211_CHAN_DFS)
        ret |= APPLE80211_C_FLAG_DFS;
    if (bw == -1) {
        if (flags & IEEE80211_CHAN_VHT) {
            if ((flags & IEEE80211_CHAN_VHT160) || (flags & IEEE80211_CHAN_VHT80_80))
                ret |= APPLE80211_C_FLAG_160MHZ;
            if (flags & IEEE80211_CHAN_VHT80)
                ret |= APPLE80211_C_FLAG_80MHZ;
        } else if ((flags & IEEE80211_CHAN_HT40) && (flags & IEEE80211_CHAN_HT)) {
            ret |= APPLE80211_C_FLAG_40MHZ;
            if (flags & IEEE80211_CHAN_HT40U)
                ret |= APPLE80211_C_FLAG_EXT_ABV;
        } else if (flags & IEEE80211_CHAN_HT20)
            ret |= APPLE80211_C_FLAG_20MHZ;
        else if ((flags & IEEE80211_CHAN_CCK) || (flags & IEEE80211_CHAN_OFDM))
            ret |= APPLE80211_C_FLAG_10MHZ;
    } else {
        switch (bw) {
            case IEEE80211_CHAN_WIDTH_80P80:
            case IEEE80211_CHAN_WIDTH_160:
                ret |= APPLE80211_C_FLAG_160MHZ;
                break;
            case IEEE80211_CHAN_WIDTH_80:
                ret |= APPLE80211_C_FLAG_80MHZ;
                break;
            case IEEE80211_CHAN_WIDTH_40:
                ret |= APPLE80211_C_FLAG_40MHZ;
                if (flags & IEEE80211_CHAN_HT40U)
                    ret |= APPLE80211_C_FLAG_EXT_ABV;
                break;
            case IEEE80211_CHAN_WIDTH_20:
                ret |= APPLE80211_C_FLAG_20MHZ;
                break;
            default:
                if (flags & IEEE80211_CHAN_HT20)
                    ret |= APPLE80211_C_FLAG_20MHZ;
                else if ((flags & IEEE80211_CHAN_CCK) || (flags & IEEE80211_CHAN_OFDM))
                    ret |= APPLE80211_C_FLAG_10MHZ;
                break;
        }
    }
    return ret;
}

void AirportItlwmSkywalkInterface::associateSSID(uint8_t *ssid, uint32_t ssid_len, const struct ether_addr &bssid, uint32_t authtype_lower, uint32_t authtype_upper, uint8_t *key, uint32_t key_len, int key_index)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    
    ieee80211_disable_rsn(ic);
    ieee80211_disable_wep(ic);
    
    struct ieee80211_wpaparams     wpa;
    struct ieee80211_nwkey         nwkey;
    bzero(&wpa, sizeof(wpa));
    bzero(&nwkey, sizeof(nwkey));
    
    memset(ic->ic_des_essid, 0, IEEE80211_NWID_LEN);
    memcpy(ic->ic_des_essid, ssid, ssid_len);
    ic->ic_des_esslen = ssid_len;
    
    bool is_zero = true;
    for (int i = 0; i < IEEE80211_ADDR_LEN; i++)
    is_zero &= bssid.octet[i] == 0;
    
    if (!is_zero) {
        IEEE80211_ADDR_COPY(ic->ic_des_bssid, bssid.octet);
        ic->ic_flags |= IEEE80211_F_DESBSSID;
    }
    else {
        memset(ic->ic_des_bssid, 0, IEEE80211_ADDR_LEN);
        ic->ic_flags &= ~IEEE80211_F_DESBSSID;
    }

    // AUTHTYPE_WPA3_SAE AUTHTYPE_WPA3_FT_SAE
    // we don't really support WPA3, but we have announced we support WPA3 in card capability function. so we fake it as WPA2 to support some WPA2/WPA3 mix wifi connection.
    if (authtype_upper == APPLE80211_AUTHTYPE_WPA3_SAE || authtype_upper == APPLE80211_AUTHTYPE_WPA3_FT_SAE) {
        wpa.i_protos |= IEEE80211_WPA_PROTO_WPA2;
        authtype_upper |= APPLE80211_AUTHTYPE_WPA2_PSK;// hack
    }
    // AUTHTYPE_WPA3_ENTERPRISE AUTHTYPE_WPA3_FT_ENTERPRISE
    if (authtype_upper == APPLE80211_AUTHTYPE_WPA3_ENTERPRISE || authtype_upper == APPLE80211_AUTHTYPE_WPA3_FT_ENTERPRISE) {
        wpa.i_protos |= IEEE80211_WPA_PROTO_WPA2;
        authtype_upper |= APPLE80211_AUTHTYPE_WPA2;// hack
    }
    
    if (authtype_upper & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA_PSK | APPLE80211_AUTHTYPE_WPA2 | APPLE80211_AUTHTYPE_WPA2_PSK | APPLE80211_AUTHTYPE_SHA256_PSK | APPLE80211_AUTHTYPE_SHA256_8021X)) {
        XYLog("%s %d\n", __FUNCTION__, __LINE__);
        wpa.i_protos = IEEE80211_WPA_PROTO_WPA1 | IEEE80211_WPA_PROTO_WPA2;
    }
    
    if (authtype_upper & (APPLE80211_AUTHTYPE_WPA_PSK | APPLE80211_AUTHTYPE_WPA2_PSK | APPLE80211_AUTHTYPE_SHA256_PSK)) {
        XYLog("%s %d\n", __FUNCTION__, __LINE__);
        wpa.i_akms |= IEEE80211_WPA_AKM_PSK | IEEE80211_WPA_AKM_SHA256_PSK;
        wpa.i_enabled = 1;
        memcpy(ic->ic_psk, key, sizeof(ic->ic_psk));
        ic->ic_flags |= IEEE80211_F_PSK;
        ieee80211_ioctl_setwpaparms(ic, &wpa);
    }
    if (authtype_upper & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA2 | APPLE80211_AUTHTYPE_SHA256_8021X)) {
        XYLog("%s %d\n", __FUNCTION__, __LINE__);
        wpa.i_akms |= IEEE80211_WPA_AKM_8021X | IEEE80211_WPA_AKM_SHA256_8021X;
        wpa.i_enabled = 1;
        ieee80211_ioctl_setwpaparms(ic, &wpa);
    }
    
    if (authtype_lower == APPLE80211_AUTHTYPE_SHARED) {
        XYLog("shared key authentication is not supported!\n");
        return;
    }
    
    if (authtype_upper == APPLE80211_AUTHTYPE_NONE && authtype_lower == APPLE80211_AUTHTYPE_OPEN) { // Open or WEP Open System
        if (key_len > 0) {
            XYLog("%s %d\n", __FUNCTION__, __LINE__);
            nwkey.i_wepon = IEEE80211_NWKEY_WEP;
            nwkey.i_defkid = key_index + 1;
            nwkey.i_key[key_index].i_keylen = (int)key_len;
            nwkey.i_key[key_index].i_keydat = key;
            ieee80211_ioctl_setnwkeys(ic, &nwkey);
        }
    }
}

void AirportItlwmSkywalkInterface::setPTK(const u_int8_t *key, size_t key_len) {
    struct ieee80211com *ic = fHalService->get80211Controller();
    struct ieee80211_node    * ni = ic->ic_bss;
    struct ieee80211_key *k;
    int keylen;
    
    ni->ni_rsn_supp_state = RNSA_SUPP_PTKDONE;
    
    if (ni->ni_rsncipher != IEEE80211_CIPHER_USEGROUP) {
        u_int64_t prsc;
        
        /* check that key length matches that of pairwise cipher */
        keylen = ieee80211_cipher_keylen(ni->ni_rsncipher);
        if (key_len != keylen) {
            XYLog("PTK length mismatch. expected %d, got %zu\n", keylen, key_len);
            return;
        }
        prsc = /*(gtk == NULL) ? LE_READ_6(key->rsc) :*/ 0;
        
        /* map PTK to 802.11 key */
        k = &ni->ni_pairwise_key;
        memset(k, 0, sizeof(*k));
        k->k_cipher = ni->ni_rsncipher;
        k->k_rsc[0] = prsc;
        k->k_len = keylen;
        memcpy(k->k_key, key, k->k_len);
        /* install the PTK */
        if ((*ic->ic_set_key)(ic, ni, k) != 0) {
            XYLog("setting PTK failed\n");
            return;
        }
        else
            XYLog("setting PTK successfully\n");
        ni->ni_flags &= ~IEEE80211_NODE_RSN_NEW_PTK;
        ni->ni_flags &= ~IEEE80211_NODE_TXRXPROT;
        ni->ni_flags |= IEEE80211_NODE_RXPROT;
    } else if (ni->ni_rsncipher != IEEE80211_CIPHER_USEGROUP)
        XYLog("%s: unexpected pairwise key update received from %s\n",
              ic->ic_if.if_xname, ether_sprintf(ni->ni_macaddr));
}

void AirportItlwmSkywalkInterface::setGTK(const u_int8_t *gtk, size_t key_len, u_int8_t kid, u_int8_t *rsc) {
    struct ieee80211com *ic = fHalService->get80211Controller();
    struct ieee80211_node    * ni = ic->ic_bss;
    struct ieee80211_key *k;
    int keylen;
    
    if (gtk != NULL) {
        /* check that key length matches that of group cipher */
        keylen = ieee80211_cipher_keylen(ni->ni_rsngroupcipher);
        if (key_len != keylen) {
            XYLog("GTK length mismatch. expected %d, got %zu\n", keylen, key_len);
            return;
        }
        /* map GTK to 802.11 key */
        k = &ic->ic_nw_keys[kid];
        if (k->k_cipher == IEEE80211_CIPHER_NONE || k->k_len != keylen || memcmp(k->k_key, gtk, keylen) != 0) {
            memset(k, 0, sizeof(*k));
            k->k_id = kid;    /* 0-3 */
            k->k_cipher = ni->ni_rsngroupcipher;
            k->k_flags = IEEE80211_KEY_GROUP;
            //if (gtk[6] & (1 << 2))
            //  k->k_flags |= IEEE80211_KEY_TX;
            k->k_rsc[0] = LE_READ_6(rsc);
            k->k_len = keylen;
            memcpy(k->k_key, gtk, k->k_len);
            /* install the GTK */
            if ((*ic->ic_set_key)(ic, ni, k) != 0) {
                XYLog("setting GTK failed\n");
                return;
            }
            else
                XYLog("setting GTK successfully\n");
        }
    }
    
    if (true) {
        ni->ni_flags |= IEEE80211_NODE_TXRXPROT;
#ifndef IEEE80211_STA_ONLY
        if (ic->ic_opmode != IEEE80211_M_IBSS ||
            ++ni->ni_key_count == 2)
#endif
        {
            XYLog("marking port %s valid\n",
                  ether_sprintf(ni->ni_macaddr));
            ni->ni_port_valid = 1;
            ieee80211_set_link_state(ic, LINK_STATE_UP);
            ni->ni_assoc_fail = 0;
            if (ic->ic_opmode == IEEE80211_M_STA)
                ic->ic_rsngroupcipher = ni->ni_rsngroupcipher;
        }
    }
}

bool AirportItlwmSkywalkInterface::
init(IOService *provider)
{
    bool ret = IO80211InfraInterface::init();
    if (!ret) {
        XYLog("%s IO80211InfraInterface init failed\n", __PRETTY_FUNCTION__);
        return false;
    }
    instance = OSDynamicCast(AirportItlwm, provider);
    if (!instance)
        return false;
    this->fHalService = instance->fHalService;
    this->scanSource = instance->scanSource;
#ifdef AIRPORT_TAHOE
    nativeBackend = new NativeWifi::Backend;
    nativeIngress = new NativeWifi::Ingress;
    if (!nativeBackend || !nativeIngress ||
        !nativeIngress->initialize(_fCommandGate, consumeNative, this)) {
        if (nativeIngress) { nativeIngress->shutdown(); nativeIngress->destroy(); delete nativeIngress; nativeIngress = nullptr; }
        delete nativeBackend; nativeBackend = nullptr;
        return false;
    }
    memcpy(permanentAddress, fHalService->get80211Controller()->ic_myaddr, 6);
    ether_addr hardware {}; memcpy(&hardware, permanentAddress, 6);
    setInitMacAddress(hardware);
    NativeWifi::Operations operations {this, radioScan, radioJoin, radioLeave, emitNative, privateReady, radioCancelScan};
    nativeBackend->initialize(operations);
    retain(); instance->retain(); nativeLease = true;
#endif
    return ret;
}

//ifnet_t AirportItlwmSkywalkInterface::
//getBSDInterface()
//{
//    if (instance->bsdInterface)
//        return instance->bsdInterface->getIfnet();
//    return NULL;
//}

IOReturn AirportItlwmSkywalkInterface::
getSSID(struct apple80211_ssid_data *sd)
{
#ifdef AIRPORT_TAHOE
    if (!sd) return kIOReturnBadArgument;
    auto ic = fHalService->get80211Controller();
    bzero(sd, sizeof(*sd)); sd->version = APPLE80211_VERSION;
    if (ic->ic_state == IEEE80211_S_RUN && ic->ic_bss) {
        if (ic->ic_bss->ni_esslen > sizeof(sd->ssid_bytes)) return kIOReturnBadArgument;
        sd->ssid_len = ic->ic_bss->ni_esslen;
        memcpy(sd->ssid_bytes, ic->ic_bss->ni_essid, sd->ssid_len);
        return kIOReturnSuccess;
    }
    if (ic->ic_des_esslen < 0 || size_t(ic->ic_des_esslen) > sizeof(sd->ssid_bytes))
        return kIOReturnBadArgument;
    if (!ic->ic_des_esslen) return kIOReturnNotReady;
    sd->ssid_len = uint32_t(ic->ic_des_esslen);
    memcpy(sd->ssid_bytes, ic->ic_des_essid, sd->ssid_len);
    return kIOReturnSuccess;
#else

    struct ieee80211com * ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(sd, 0, sizeof(*sd));
        sd->version = APPLE80211_VERSION;
        memcpy(sd->ssid_bytes, ic->ic_des_essid, strlen((const char*)ic->ic_des_essid));
        sd->ssid_len = (uint32_t)strlen((const char*)ic->ic_des_essid);
        return kIOReturnSuccess;
    }
    return 6;
#endif
}

IOReturn AirportItlwmSkywalkInterface::
getAUTH_TYPE(struct apple80211_authtype_data *ad)
{
    ad->version = APPLE80211_VERSION;
    ad->authtype_lower = current_authtype_lower;
    ad->authtype_upper = current_authtype_upper;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setAUTH_TYPE(struct apple80211_authtype_data *ad)
{
    current_authtype_lower = ad->authtype_lower;
    current_authtype_upper = ad->authtype_upper;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setCIPHER_KEY(struct apple80211_key *key)
{
#ifdef AIRPORT_TAHOE
    return _fCommandGate->runAction(nativeRequest, this, reinterpret_cast<void *>(uintptr_t(10)), key);
#else
    XYLog("%s\n", __FUNCTION__);
    const char* keydump = hexdump(key->key, key->key_len);
    const char* rscdump = hexdump(key->key_rsc, key->key_rsc_len);
    const char* eadump = hexdump(key->key_ea.octet, APPLE80211_ADDR_LEN);
    static_assert(__offsetof(struct apple80211_key, key_ea) == 92, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, key_rsc_len) == 80, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, wowl_kck_len) == 100, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, wowl_kek_len) == 120, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, wowl_kck_key) == 104, "struct corrupted");
    if (keydump && rscdump && eadump)
        XYLog("Set key request: len=%d cipher_type=%d flags=%d index=%d key=%s rsc_len=%d rsc=%s ea=%s\n",
              key->key_len, key->key_cipher_type, key->key_flags, key->key_index, keydump, key->key_rsc_len, rscdump, eadump);
    else
        XYLog("Set key request, but failed to allocate memory for hexdump\n");
    
    if (keydump)
        IOFree((void*)keydump, 3 * key->key_len + 1);
    if (rscdump)
        IOFree((void*)rscdump, 3 * key->key_rsc_len + 1);
    if (eadump)
        IOFree((void*)eadump, 3 * APPLE80211_ADDR_LEN + 1);
    
    switch (key->key_cipher_type) {
        case APPLE80211_CIPHER_NONE:
            // clear existing key
//            XYLog("Setting NONE key is not supported\n");
            break;
        case APPLE80211_CIPHER_WEP_40:
        case APPLE80211_CIPHER_WEP_104:
            XYLog("Setting WEP key %d is not supported\n", key->key_index);
            break;
        case APPLE80211_CIPHER_TKIP:
        case APPLE80211_CIPHER_AES_OCB:
        case APPLE80211_CIPHER_AES_CCM:
            switch (key->key_flags) {
                case 4: // PTK
                    setPTK(key->key, key->key_len);
                    break;
                case 0: // GTK
                    setGTK(key->key, key->key_len, key->key_index, key->key_rsc);
                    break;
            }
            break;
        case APPLE80211_CIPHER_PMK:
            XYLog("Setting WPA PMK is not supported\n");
            break;
        case APPLE80211_CIPHER_MSK:
            XYLog("Setting MSK\n");
            ieee80211_pmksa_add(fHalService->get80211Controller(), IEEE80211_AKM_8021X,
                                fHalService->get80211Controller()->ic_bss->ni_macaddr, key->key, 0);
            break;
        case APPLE80211_CIPHER_PMKSA:
            XYLog("Setting WPA PMKSA\n");
            ieee80211_pmksa_add(fHalService->get80211Controller(), IEEE80211_AKM_8021X,
                                fHalService->get80211Controller()->ic_bss->ni_macaddr, key->key, 0);
            break;
    }
    //fInterface->postMessage(APPLE80211_M_CIPHER_KEY_CHANGED);
    return kIOReturnSuccess;
#endif
}

IOReturn AirportItlwmSkywalkInterface::
getPHY_MODE(struct apple80211_phymode_data *pd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    
    pd->version = APPLE80211_VERSION;
    pd->phy_mode = APPLE80211_MODE_11A
    | APPLE80211_MODE_11B
    | APPLE80211_MODE_11G
    | APPLE80211_MODE_11N;
    
    if (ic->ic_flags & IEEE80211_F_VHTON)
        pd->phy_mode |= APPLE80211_MODE_11AC;
    
    if (ic->ic_flags & IEEE80211_F_HEON)
        pd->phy_mode |= APPLE80211_MODE_11AX;
    
    switch (fHalService->get80211Controller()->ic_curmode) {
        case IEEE80211_MODE_AUTO:
            pd->active_phy_mode = APPLE80211_MODE_AUTO;
            break;
        case IEEE80211_MODE_11A:
            pd->active_phy_mode = APPLE80211_MODE_11A;
            break;
        case IEEE80211_MODE_11B:
            pd->active_phy_mode = APPLE80211_MODE_11B;
            break;
        case IEEE80211_MODE_11G:
            pd->active_phy_mode = APPLE80211_MODE_11G;
            break;
        case IEEE80211_MODE_11N:
            pd->active_phy_mode = APPLE80211_MODE_11N;
            break;
        case IEEE80211_MODE_11AC:
            pd->active_phy_mode = APPLE80211_MODE_11AC;
            break;
        case IEEE80211_MODE_11AX:
            pd->active_phy_mode = APPLE80211_MODE_11AX;
            break;
            
        default:
            pd->active_phy_mode = APPLE80211_MODE_AUTO;
            break;
    }
    
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getCHANNEL(struct apple80211_channel_data *cd)
{
    struct ieee80211com * ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(cd, 0, sizeof(apple80211_channel_data));
        cd->version = APPLE80211_VERSION;
        cd->channel.version = APPLE80211_VERSION;
        cd->channel.channel = ieee80211_chan2ieee(ic, ic->ic_bss->ni_chan);
        cd->channel.flags = ieeeChanFlag2apple(ic->ic_bss->ni_chan->ic_flags, ic->ic_bss->ni_chw);
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getSTATE(struct apple80211_state_data *sd)
{
    memset(sd, 0, sizeof(*sd));
    sd->version = APPLE80211_VERSION;
    sd->state = fHalService->get80211Controller()->ic_state;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getMCS_INDEX_SET(struct apple80211_mcs_index_set_data *ad)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(ad, 0, sizeof(*ad));
        ad->version = APPLE80211_VERSION;
        size_t size = min(ARRAY_SIZE(ic->ic_bss->ni_rxmcs), ARRAY_SIZE(ad->mcs_set_map));
        for (int i = 0; i < size; i++)
            ad->mcs_set_map[i] = ic->ic_bss->ni_rxmcs[i];
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getVHT_MCS_INDEX_SET(struct apple80211_vht_mcs_index_set_data *data)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL || ic->ic_curmode < IEEE80211_MODE_11AC) {
        return kIOReturnError;
    }
    memset(data, 0, sizeof(struct apple80211_vht_mcs_index_set_data));
    data->version = APPLE80211_VERSION;
    data->mcs_map = ic->ic_bss->ni_vht_mcsinfo.tx_mcs_map;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getMCS_VHT(struct apple80211_mcs_vht_data *data)
{
#ifdef AIRPORT_TAHOE
    if (data == nullptr)
        return kIOReturnBadArgument;
    struct ieee80211com *ic = fHalService->get80211Controller();
    IwxTxRate::Decoded rate;
    IOReturn result = decodeCurrentTxRate(this, ic, &rate);
    if (result != kIOReturnSuccess)
        return result;
    if (rate.format != IwxTxRate::Vht)
        return kIOReturnUnsupported;

    bzero(data, sizeof(*data));
    data->version = APPLE80211_VERSION;
    data->guard_interval = rate.guardIntervalNs;
    data->index = rate.mcs;
    data->nss = rate.nss;
    data->bw = rate.bandwidthMHz;
    return kIOReturnSuccess;
#else
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL || ic->ic_curmode < IEEE80211_MODE_11AC) {
        return kIOReturnError;
    }
    memset(data, 0, sizeof(struct apple80211_mcs_vht_data));
    data->version = APPLE80211_VERSION;
    data->guard_interval = (ieee80211_node_supports_vht_sgi80(ic->ic_bss) || ieee80211_node_supports_vht_sgi160(ic->ic_bss)) ? APPLE80211_GI_SHORT : APPLE80211_GI_LONG;
    data->index = ic->ic_bss->ni_txmcs;
    data->nss = fHalService->getDriverInfo()->getTxNSS();
    switch (ic->ic_bss->ni_chw) {
        case IEEE80211_CHAN_WIDTH_40:
            data->bw = 40;
            break;
        case IEEE80211_CHAN_WIDTH_80:
            data->bw = 80;
            break;
        case IEEE80211_CHAN_WIDTH_80P80:
        case IEEE80211_CHAN_WIDTH_160:
            data->bw = 160;
            break;
            
        default:
            data->bw = 20;
            break;
    }
    return kIOReturnSuccess;
#endif
}

IOReturn AirportItlwmSkywalkInterface::
getRATE_SET(struct apple80211_rate_set_data *ad)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(ad, 0, sizeof(*ad));
        ad->version = APPLE80211_VERSION;
        ad->num_rates = ic->ic_bss->ni_rates.rs_nrates;
        size_t size = min(ic->ic_bss->ni_rates.rs_nrates, ARRAY_SIZE(ad->rates));
        for (int i=0; i < size; i++) {
            struct apple80211_rate apple_rate = ad->rates[i];
            apple_rate.version = APPLE80211_VERSION;
            apple_rate.rate = ic->ic_bss->ni_rates.rs_rates[i];
            apple_rate.flags = 0;
        }
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getOP_MODE(struct apple80211_opmode_data *od)
{
    od->version = APPLE80211_VERSION;
    od->op_mode = APPLE80211_M_STA;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getTXPOWER(struct apple80211_txpower_data *txd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(txd, 0, sizeof(*txd));
        txd->version = APPLE80211_VERSION;
        txd->txpower = ic->ic_txpower;
        txd->txpower_unit = APPLE80211_UNIT_PERCENT;
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getRATE(struct apple80211_rate_data *rd)
{
#ifdef AIRPORT_TAHOE
    if (rd == nullptr)
        return kIOReturnBadArgument;
    struct ieee80211com *ic = fHalService->get80211Controller();
    IwxTxRate::Decoded rate;
    IOReturn result = decodeCurrentTxRate(this, ic, &rate);
    if (result != kIOReturnSuccess)
        return result;
    uint32_t mbps = 0;
    if (!IwxTxRate::rateMbps(rate, &mbps))
        return kIOReturnUnsupported;

    bzero(rd, sizeof(*rd));
    rd->version = APPLE80211_VERSION;
    rd->num_radios = 1;
    rd->rate[0] = mbps;
    return kIOReturnSuccess;
#else
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL)
        return 6;
    int nss;
    int sgi;
    int index = 0;
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(rd, 0, sizeof(*rd));
        rd->version = APPLE80211_VERSION;
        rd->num_radios = 1;
        sgi = ieee80211_node_supports_sgi(ic->ic_bss);
        if (ic->ic_curmode == IEEE80211_MODE_11AC) {
            if (sgi)
                index += 1;
            nss = fHalService->getDriverInfo()->getTxNSS();
            switch (ic->ic_bss->ni_chw) {
                case IEEE80211_CHAN_WIDTH_40:
                    index += 4;
                    break;
                case IEEE80211_CHAN_WIDTH_80:
                    index += 8;
                    break;
                case IEEE80211_CHAN_WIDTH_80P80:
                case IEEE80211_CHAN_WIDTH_160:
                    index += 12;
                    break;

                default:
                    break;
            }
            index += 2 * (nss - 1);
            const struct ieee80211_vht_rateset *rs = &ieee80211_std_ratesets_11ac[index];
            rd->rate[0] = rs->rates[ic->ic_bss->ni_txmcs % rs->nrates] / 2;
        } else if (ic->ic_curmode == IEEE80211_MODE_11N) {
            int is_40mhz = ic->ic_bss->ni_chw == IEEE80211_CHAN_WIDTH_40;
            if (sgi)
                index += 1;
            if (is_40mhz)
                index += (IEEE80211_HT_RATESET_MIMO4_SGI + 1);
            index += (ic->ic_bss->ni_txmcs / 16);
            nss = ic->ic_bss->ni_txmcs / 8 + 1;
            index += 2 * (nss - 1);
            rd->rate[0] = ieee80211_std_ratesets_11n[index].rates[ic->ic_bss->ni_txmcs % 8] / 2;
        } else
            rd->rate[0] = ic->ic_bss->ni_rates.rs_rates[ic->ic_bss->ni_txrate];
        return kIOReturnSuccess;
    }
    return 6;
#endif
}

IOReturn AirportItlwmSkywalkInterface::
getBSSID(struct apple80211_bssid_data *bd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(bd, 0, sizeof(*bd));
        bd->version = APPLE80211_VERSION;
        memcpy(bd->bssid.octet, ic->ic_bss->ni_bssid, APPLE80211_ADDR_LEN);
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getRSSI(struct apple80211_rssi_data *rd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(rd, 0, sizeof(*rd));
        rd->num_radios = 1;
        rd->rssi_unit = APPLE80211_UNIT_DBM;
        rd->rssi[0] = rd->aggregate_rssi
        = rd->rssi_ext[0]
        = rd->aggregate_rssi_ext
        = -(0 - IWM_MIN_DBM - ic->ic_bss->ni_rssi);
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getRSN_IE(struct apple80211_rsn_ie_data *data)
{
#ifdef USE_APPLE_SUPPLICANT
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL || ic->ic_bss->ni_rsnie == NULL) {
        return kIOReturnError;
    }
    data->version = APPLE80211_VERSION;
    if (ic->ic_rsn_ie_override[1] > 0) {
        data->len = 2 + ic->ic_rsn_ie_override[1];
        memcpy(data->ie, ic->ic_rsn_ie_override, data->len);
    }
    else {
        data->len = 2 + ic->ic_bss->ni_rsnie[1];
        memcpy(data->ie, ic->ic_bss->ni_rsnie, data->len);
    }
    return kIOReturnSuccess;
#else
    return kIOReturnUnsupported;
#endif
}

IOReturn AirportItlwmSkywalkInterface::
setRSN_IE(struct apple80211_rsn_ie_data *data)
{
#ifdef USE_APPLE_SUPPLICANT
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (!data)
        return kIOReturnError;
    static_assert(sizeof(ic->ic_rsn_ie_override) == APPLE80211_MAX_RSN_IE_LEN, "Max RSN IE length mismatch");
    memcpy(ic->ic_rsn_ie_override, data->ie, APPLE80211_MAX_RSN_IE_LEN);
    if (ic->ic_state == IEEE80211_S_RUN && ic->ic_bss != nullptr)
        ieee80211_save_ie(data->ie, &ic->ic_bss->ni_rsnie);
    return kIOReturnSuccess;
#else
    return kIOReturnUnsupported;
#endif
}

IOReturn AirportItlwmSkywalkInterface::
getAP_IE_LIST(struct apple80211_ap_ie_data *data)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (!data)
        return kIOReturnError;
    if (ic->ic_bss == NULL || ic->ic_bss->ni_rsnie_tlv == NULL || ic->ic_bss->ni_rsnie_tlv_len == 0 || ic->ic_bss->ni_rsnie_tlv_len > data->len || ic->ic_bss->ni_rsnie_tlv_len > 1024)
        return kIOReturnError;
    data->version = APPLE80211_VERSION;
    data->len = ic->ic_bss->ni_rsnie_tlv_len;
    memcpy(data->ie_data, ic->ic_bss->ni_rsnie_tlv, data->len);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getNOISE(struct apple80211_noise_data *nd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(nd, 0, sizeof(*nd));
        nd->version = APPLE80211_VERSION;
        nd->num_radios = 1;
        nd->noise[0]
        = nd->aggregate_noise = -fHalService->getDriverInfo()->getBSSNoise();
        nd->noise_unit = APPLE80211_UNIT_DBM;
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getPOWERSAVE(struct apple80211_powersave_data *pd)
{
    pd->version = APPLE80211_VERSION;
    pd->powersave_level = APPLE80211_POWERSAVE_MODE_DISABLED;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getNSS(struct apple80211_nss_data *data)
{
#ifdef AIRPORT_TAHOE
    if (data == nullptr)
        return kIOReturnBadArgument;
    struct ieee80211com *ic = fHalService->get80211Controller();
    IwxTxRate::Decoded rate;
    IOReturn result = decodeCurrentTxRate(this, ic, &rate);
    if (result != kIOReturnSuccess)
        return result;
    bzero(data, sizeof(*data));
    data->version = APPLE80211_VERSION;
    data->nss = rate.nss;
    return kIOReturnSuccess;
#else
    memset(data, 0, sizeof(*data));
    data->version = APPLE80211_VERSION;
    data->nss = fHalService->getDriverInfo()->getTxNSS();
    return kIOReturnSuccess;
#endif
}

IOReturn AirportItlwmSkywalkInterface::
setASSOCIATE(struct apple80211_assoc_data *ad)
{
#ifdef AIRPORT_TAHOE
    (void)ad;
    return kIOReturnUnsupported;
#else
    XYLog("%s [%s] mode=%d ad_auth_lower=%d ad_auth_upper=%d rsn_ie_len=%d%s%s%s%s%s%s%s\n", __FUNCTION__, ad->ad_ssid, ad->ad_mode, ad->ad_auth_lower, ad->ad_auth_upper, ad->ad_rsn_ie_len,
          (ad->ad_flags & 2) ? ", Instant Hotspot" : "",
          (ad->ad_flags & 4) ? ", Auto Instant Hotspot" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 1) ? ", don't disassociate" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 2) ? ", don't blacklist" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 4) ? ", closed Network" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 8) ? ", 802.1X" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 0x20) ? ", force BSSID" : "");
    
    struct apple80211_rsn_ie_data rsn_ie_data;
    struct apple80211_authtype_data auth_type_data;
    struct ieee80211com *ic = fHalService->get80211Controller();

    if (!ad)
        return kIOReturnError;
    
    if (ic->ic_state < IEEE80211_S_SCAN)
        return kIOReturnSuccess;
    
    if (ic->ic_state == IEEE80211_S_ASSOC || ic->ic_state == IEEE80211_S_AUTH)
        return kIOReturnSuccess;

    if (ad->ad_mode != APPLE80211_AP_MODE_IBSS) {
        disassocIsVoluntary = false;
        auth_type_data.version = APPLE80211_VERSION;
        auth_type_data.authtype_upper = ad->ad_auth_upper;
        auth_type_data.authtype_lower = ad->ad_auth_lower;
        setAUTH_TYPE(&auth_type_data);
        rsn_ie_data.version = APPLE80211_VERSION;
        rsn_ie_data.len = ad->ad_rsn_ie[1] + 2;
        memcpy(rsn_ie_data.ie, ad->ad_rsn_ie, rsn_ie_data.len);
        setRSN_IE(&rsn_ie_data);

        associateSSID(ad->ad_ssid, ad->ad_ssid_len, ad->ad_bssid, ad->ad_auth_lower, ad->ad_auth_upper, ad->ad_key.key, ad->ad_key.key_len, ad->ad_key.key_index);
    }
    return kIOReturnSuccess;
#endif
}

IOReturn AirportItlwmSkywalkInterface::
setDISASSOCIATE(struct apple80211_disassoc_data *ad)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = fHalService->get80211Controller();

    if (ic->ic_state < IEEE80211_S_SCAN)
        return kIOReturnSuccess;
    
    if (ic->ic_state > IEEE80211_S_AUTH && ic->ic_bss != NULL)
        IEEE80211_SEND_MGMT(ic, ic->ic_bss, IEEE80211_FC0_SUBTYPE_DEAUTH, IEEE80211_REASON_AUTH_LEAVE);
    
    if (ic->ic_state == IEEE80211_S_ASSOC || ic->ic_state == IEEE80211_S_AUTH)
        return kIOReturnSuccess;
    
    disassocIsVoluntary = true;

    ieee80211_del_ess(ic, nullptr, 0, 1);
    ieee80211_deselect_ess(ic);
#ifdef USE_APPLE_SUPPLICANT
    ic->ic_rsn_ie_override[1] = 0;
#endif
    ic->ic_assoc_status = APPLE80211_STATUS_UNAVAILABLE;
    ic->ic_deauth_reason = APPLE80211_REASON_ASSOC_LEAVING;
    ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getSUPPORTED_CHANNELS(struct apple80211_sup_channel_data *ad)
{
    if (!ad)
        return kIOReturnBadArgument;
    if (!fHalService || !fHalService->get80211Controller())
        return kIOReturnNotReady;
    memset(ad, 0, sizeof(*ad));
    ad->version = APPLE80211_VERSION;
    struct ieee80211com *ic = fHalService->get80211Controller();
    for (int i = 0; i < IEEE80211_CHAN_MAX &&
                    ad->num_channels < APPLE80211_MAX_CHANNELS; i++) {
        if (ic->ic_channels[i].ic_freq != 0) {
            ad->supported_channels[ad->num_channels].channel = ieee80211_chan2ieee(ic, &ic->ic_channels[i]);
            ad->supported_channels[ad->num_channels].flags = ieeeChanFlag2appleScanFlagVentura(ic->ic_channels[i].ic_flags);
            ad->num_channels++;
        }
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getHW_SUPPORTED_CHANNELS(struct apple80211_sup_channel_data *ad)
{
    if (!ad)
        return kIOReturnBadArgument;
    if (!fHalService || !fHalService->get80211Controller())
        return kIOReturnNotReady;
    // The legacy STA request path maps both channel-list request IDs to the
    // same supported-channel getter.
    return getSUPPORTED_CHANNELS(ad);
}

IOReturn AirportItlwmSkywalkInterface::
getCHANNELS_INFO(struct apple80211_channels_info *data)
{
    if (!data)
        return kIOReturnBadArgument;
    if (!fHalService)
        return kIOReturnNotReady;

    struct ieee80211com *ic = fHalService->get80211Controller();
    if (!ic)
        return kIOReturnNotReady;

    // Preserve the fields populated by the existing legacy STA getter. Other
    // capability arrays remain zero until the driver has authoritative values.
    memset(data, 0, sizeof(*data));
    data->version = APPLE80211_VERSION;
    for (int i = 0; i < IEEE80211_CHAN_MAX &&
                    data->num_chan_specs < APPLE80211_MAX_CHANNELS; ++i) {
        struct ieee80211_channel *channel = &ic->ic_channels[i];
        if (!channel->ic_freq)
            continue;

        const uint16_t index = data->num_chan_specs++;
        data->chan_num[index] = ieee80211_chan2ieee(ic, channel);
        data->support_80Mhz[index] = IEEE80211_IS_CHAN_VHT80(channel);
        data->support_40Mhz[index] = IEEE80211_IS_CHAN_HT40(channel) ||
                                     IEEE80211_IS_CHAN_VHT40(channel);
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getLOCALE(struct apple80211_locale_data *ld)
{
    if (!ld)
        return kIOReturnError;
    ld->version = APPLE80211_VERSION;
    ld->locale  = APPLE80211_LOCALE_FCC;
    
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getDEAUTH(struct apple80211_deauth_data *da)
{
    if (!da)
        return kIOReturnError;
    da->version = APPLE80211_VERSION;
    struct ieee80211com *ic = fHalService->get80211Controller();
    da->deauth_reason = ic->ic_deauth_reason;
//    XYLog("%s, %d\n", __FUNCTION__, da->deauth_reason);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getASSOCIATION_STATUS(struct apple80211_assoc_status_data *hv)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    
    if (!hv)
        return kIOReturnError;
    memset(hv, 0, sizeof(*hv));
    hv->version = APPLE80211_VERSION;
    if (ic->ic_state == IEEE80211_S_RUN)
        hv->status = APPLE80211_STATUS_SUCCESS;
    else
        hv->status = APPLE80211_STATUS_UNAVAILABLE;
//    XYLog("%s, %d\n", __FUNCTION__, hv->status);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setSCANCACHE_CLEAR(void *req)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = fHalService->get80211Controller();
    //if doing background or active scan, don't free nodes.
    if ((ic->ic_flags & IEEE80211_F_BGSCAN) || (ic->ic_flags & IEEE80211_F_ASCAN))
        return kIOReturnSuccess;
    ieee80211_free_allnodes(ic, 0);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setDEAUTH(struct apple80211_deauth_data *da)
{
    XYLog("%s\n", __FUNCTION__);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getMCS(struct apple80211_mcs_data* md)
{
#ifdef AIRPORT_TAHOE
    if (md == nullptr)
        return kIOReturnBadArgument;
    struct ieee80211com *ic = fHalService->get80211Controller();
    IwxTxRate::Decoded rate;
    IOReturn result = decodeCurrentTxRate(this, ic, &rate);
    if (result != kIOReturnSuccess)
        return result;
    uint32_t index = 0;
    if (!IwxTxRate::currentMcsIndex(rate, &index))
        return kIOReturnUnsupported;
    md->version = APPLE80211_VERSION;
    md->index = index;
    return kIOReturnSuccess;
#else
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state != IEEE80211_S_RUN ||  ic->ic_bss == NULL || !md)
        return 6;
    md->version = APPLE80211_VERSION;
    md->index = ic->ic_bss->ni_txmcs;
    return kIOReturnSuccess;
#endif
}

IOReturn AirportItlwmSkywalkInterface::
getLINK_CHANGED_EVENT_DATA(struct apple80211_link_changed_event_data *ed)
{
    if (ed == nullptr)
        return 16;
    
    struct ieee80211com *ic = fHalService->get80211Controller();
    
    bzero(ed, sizeof(apple80211_link_changed_event_data));
    ed->isLinkDown = !(instance->currentStatus & kIONetworkLinkActive);
    if (ed->isLinkDown) {
        ed->voluntary = disassocIsVoluntary;
        ed->reason = APPLE80211_LINK_DOWN_REASON_DEAUTH;
    } else
        ed->rssi = -(0 - IWM_MIN_DBM - ic->ic_bss->ni_rssi);
    XYLog("Link %s, reason: %d, voluntary: %d\n", ed->isLinkDown ? "down" : "up", ed->reason, ed->voluntary);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setSCAN_REQ(struct apple80211_scan_data *sd)
{
#ifdef AIRPORT_TAHOE
    (void)sd;
    return kIOReturnUnsupported;
#else
    struct ieee80211com *ic = fHalService->get80211Controller();
#if 0
    XYLog("%s Type: %u BSS Type: %u PHY Mode: %u Dwell time: %u Rest time: %u Num channels: %u SSID: %s BSSID: %s\n",
          __FUNCTION__,
          sd->scan_type,
          sd->bss_type,
          sd->phy_mode,
          sd->dwell_time,
          sd->rest_time,
          sd->num_channels,
          sd->ssid,
          ether_sprintf(sd->bssid.octet));
#endif
    if (fScanResultWrapping)
        return 22;
    if (ic->ic_state <= IEEE80211_S_INIT)
        return 22;
    if (sd->scan_type == APPLE80211_SCAN_TYPE_FAST || sd->scan_type == APPLE80211_SCAN_TYPE_PASSIVE) {
        if (scanSource) {
            scanSource->setTimeoutMS(100);
            scanSource->enable();
        }
        return kIOReturnSuccess;
    }
    ieee80211_begin_cache_bgscan(&ic->ic_ac.ac_if);
    if (scanSource) {
        scanSource->setTimeoutMS(100);
        scanSource->enable();
    }
    return kIOReturnSuccess;
#endif
}

extern OSDictionary *convertScanToDictionary(apple80211_scan_result *a1);

static int convertNodeToScanResult(ItlHalService *fHalService, struct ieee80211_node *fNextNodeToSend, apple80211_scan_result *result)
{
    bzero(result, sizeof(*result));
    result->version = APPLE80211_VERSION;
    if (fNextNodeToSend->ni_rsnie_tlv && fNextNodeToSend->ni_rsnie_tlv_len > 0) {
        result->asr_ie_len = fNextNodeToSend->ni_rsnie_tlv_len;
        memcpy(result->asr_ie_data, fNextNodeToSend->ni_rsnie_tlv, MIN(result->asr_ie_len, sizeof(result->asr_ie_data)));
    } else {
        result->asr_ie_len = 0;
    }
    result->asr_beacon_int = fNextNodeToSend->ni_intval;
#ifdef AIRPORT_TAHOE
    result->asr_nrates = MIN(fNextNodeToSend->ni_rates.rs_nrates, APPLE80211_MAX_RATES);
#else
    result->asr_nrates = fNextNodeToSend->ni_rates.rs_nrates;
#endif
    for (unsigned i = 0; i < result->asr_nrates; ++i)
        result->asr_rates[i] = fNextNodeToSend->ni_rates.rs_rates[i];
    result->asr_age = (uint32_t)(airport_up_time() - fNextNodeToSend->ni_age_ts);
    result->asr_cap = fNextNodeToSend->ni_capinfo;
    result->asr_channel.version = APPLE80211_VERSION;
    result->asr_channel.channel = ieee80211_chan2ieee(fHalService->get80211Controller(), fNextNodeToSend->ni_chan);
    result->asr_channel.flags = ieeeChanFlag2appleScanFlagVentura(fNextNodeToSend->ni_chan->ic_flags);
    result->asr_noise = -fHalService->getDriverInfo()->getBSSNoise();
    result->asr_rssi = -(0 - IWM_MIN_DBM - fNextNodeToSend->ni_rssi);
    memcpy(result->asr_bssid, fNextNodeToSend->ni_bssid, IEEE80211_ADDR_LEN);
    result->asr_ssid_len = fNextNodeToSend->ni_esslen;
    if (result->asr_ssid_len != 0)
        memcpy(&result->asr_ssid, fNextNodeToSend->ni_essid, result->asr_ssid_len);
    return 0;
}

IOReturn AirportItlwmSkywalkInterface::
getCURRENT_NETWORK(apple80211_scan_result *sr)
{
    if (fHalService->get80211Controller()->ic_state != IEEE80211_S_RUN || fHalService->get80211Controller()->ic_bss == NULL)
        return kIOReturnError;
    convertNodeToScanResult(fHalService, fHalService->get80211Controller()->ic_bss, sr);
    return kIOReturnSuccess;
}

#ifndef AIRPORT_TAHOE
IOReturn AirportItlwmSkywalkInterface::
getCOLOCATED_NETWORK_SCOPE_ID(apple80211_colocated_network_scope_id *as)
{
    if (!as)
        return kIOReturnBadArgument;
    as->version = APPLE80211_VERSION;
    return kIOReturnSuccess;
}

#endif
IOReturn AirportItlwmSkywalkInterface::
getSCAN_RESULT(struct apple80211_scan_result *sr)
{
    if (fNextNodeToSend == NULL) {
        if (fScanResultWrapping) {
            fScanResultWrapping = false;
            return 5;
        } else {
            fNextNodeToSend = RB_MIN(ieee80211_tree, &fHalService->get80211Controller()->ic_tree);
            if (fNextNodeToSend == NULL) {
                return 5;
            }
        }
    }
//    XYLog("%s ni_bssid=%s ni_essid=%s channel=%d flags=%d asr_cap=%d asr_nrates=%d asr_ssid_len=%d asr_ie_len=%d asr_rssi=%d\n", __FUNCTION__, ether_sprintf(fNextNodeToSend->ni_bssid), fNextNodeToSend->ni_essid, ieee80211_chan2ieee(ic, fNextNodeToSend->ni_chan), ieeeChanFlag2apple(fNextNodeToSend->ni_chan->ic_flags, -1), fNextNodeToSend->ni_capinfo, fNextNodeToSend->ni_rates.rs_nrates, fNextNodeToSend->ni_esslen, fNextNodeToSend->ni_rsnie_tlv == NULL ? 0 : fNextNodeToSend->ni_rsnie_tlv_len, fNextNodeToSend->ni_rssi);
    convertNodeToScanResult(fHalService, fNextNodeToSend, sr);
    
    fNextNodeToSend = RB_NEXT(ieee80211_tree, &HalService->get80211Controller()->ic_tree, fNextNodeToSend);
    if (fNextNodeToSend == NULL)
        fScanResultWrapping = true;

    return kIOReturnSuccess;
}

#ifdef AIRPORT_TAHOE
IOReturn AirportItlwmSkywalkInterface::setWCL_UPDATE_FAST_LANE(
    apple80211_fastlane *request) {
    if (!request) return kIOReturnBadArgument;
    // 25G241 command502 is two bytes, with no version prefix. The normal
    // non-Fastlane AP policy is {0,0}; rejecting it aborts setCurrentBSS.
    const auto bytes = reinterpret_cast<const uint8_t *>(request);
    setProperty("NativeFastLaneRequestFlags", uint32_t(bytes[0]) |
        (uint32_t(bytes[1]) << 8), 32);
    IOReturn result = kIOReturnUnsupported;
    if (!bytes[0] && !bytes[1]) {
        result = kIOReturnNotReady;
        if (getBSDInterface()) {
            // Update the real native BSD-interface policy. Do not advertise
            // the optional ACM override, which this target does not implement.
            setFastlaneCapable(false);
            result = kIOReturnSuccess;
        }
    }
    setProperty("NativeFastLaneResult", uint32_t(result), 32);
    return result;
}

IOReturn AirportItlwmSkywalkInterface::setWCL_LINK_STATE_UPDATE(
    apple80211_wcl_update_link_state *state) {
    // 25G241 WCLNetManager sends command 454 after processing real link events.
    // This is a concrete InfraInterface method, not a radio protocol stub.
    // Preserve the caller's serialization and let the native owner update its
    // AP address, link state and notifications. Do not synthesize a link event
    // or decode/copy the private request here.
    const IOReturn result = IO80211InfraInterface::setWCL_LINK_STATE_UPDATE(state);
    setProperty("NativeLinkStateUpdateResult", uint32_t(result), 32);
    return result;
}

namespace {
IOReturn nativeStatus(NativeWifi::Status status) {
    switch (status) {
        case NativeWifi::Status::Ok: return kIOReturnSuccess;
        case NativeWifi::Status::BadRequest: return kIOReturnBadArgument;
        case NativeWifi::Status::Unsupported: return kIOReturnUnsupported;
        case NativeWifi::Status::Busy: return kIOReturnBusy;
        case NativeWifi::Status::NotReady: return kIOReturnNotReady;
        default: return kIOReturnError;
    }
}
enum NativeRequest { Scan = 1, Join = 2, AbortScan = 3, AbortJoin = 4,
    Leave = 5, Bss = 6, BeaconFrame = 7, Address = 8, NativeStop = 9, Cipher = 10 };
}
IOReturn AirportItlwmSkywalkInterface::nativeRequest(OSObject *, void *object,
    void *operation, void *data, void *length) {
    auto self = static_cast<AirportItlwmSkywalkInterface *>(object);
    auto backend = self->nativeBackend;
    if (!backend) return kIOReturnNotReady;
    const uintptr_t op = uintptr_t(operation);
    // The experimental MAC-only probe owns a short command window. Read-only
    // state queries stay available; a new control operation is retried after
    // the worker releases it, rather than racing the firmware command ring.
    if (self->fHalService && self->fHalService->nativeP2pBusy() &&
        (op == Scan || op == Join || op == AbortScan || op == AbortJoin ||
         op == Leave || op == Address || op == Cipher))
        return kIOReturnBusy;
    if (uintptr_t(operation) == Scan || uintptr_t(operation) == Join) {
        // The userland build property can appear after the controller starts.
        // Recheck each request so an early NotReady remains recoverable.
        const bool runtimeReady = NativeWifi::verifyTahoeRuntime(true);
        self->setProperty("NativeRuntimeReady", runtimeReady ? 1U : 0U, 32);
        if (!runtimeReady) return kIOReturnNotReady;
    }
    switch (uintptr_t(operation)) {
        case Scan:
            if (self->addressQuarantined) return kIOReturnNotPermitted;
            if (data) {
                const auto raw=static_cast<const uint8_t *>(data);
                self->setProperty("NativeScanType",NativeWifi::read32(raw+0x40),32);
                self->setProperty("NativeScanHomeTime",NativeWifi::read32(raw+8),32);
                self->setProperty("NativeScanActiveTime",NativeWifi::read32(raw+0x48),32);
                self->setProperty("NativeScanPassiveTime",NativeWifi::read32(raw+0x4c),32);
                self->setProperty("NativeScanRestTime",NativeWifi::read32(raw+0x50),32);
            }
            {
                const IOReturn result=nativeStatus(backend->scanRequest(data,NativeWifi::ScanWireSize));
                self->setProperty("NativeScanRejectField",backend->scanRejectField(),32);
                self->setProperty("NativeScanResult",uint32_t(result),32);
                self->setProperty("NativeScanTimingPolicy",result==kIOReturnSuccess ? "Intel firmware defaults" : "not accepted");
                return result;
            }
        case Join:
            if (self->addressQuarantined) return kIOReturnNotPermitted;
            if (data) {
                const auto raw=static_cast<const uint8_t *>(data);
                self->setProperty("NativeJoinLowerAuth",NativeWifi::read32(raw+0x10),32);
                self->setProperty("NativeJoinUpperAuth",NativeWifi::read32(raw+0x14),32);
                self->setProperty("NativeJoinKeyLength",NativeWifi::read32(raw+0x44),32);
                self->setProperty("NativeJoinCipher",NativeWifi::read32(raw+0x48),32);
                self->setProperty("NativeJoinAllowedAuth",NativeWifi::read32(raw+0x210),32);
                self->setProperty("NativeJoinFlags",NativeWifi::read32(raw+0x1e0),32);
                self->setProperty("NativeJoinFlags2",NativeWifi::read32(raw+0x1e4),32);
                self->setProperty("NativeJoinFlags3",NativeWifi::read32(raw+0x1e8),32);
            }
            {
                const IOReturn result=nativeStatus(backend->joinRequest(data,NativeWifi::JoinWireSize));
                self->setProperty("NativeJoinRejectField",backend->joinRejectField(),32);
                self->setProperty("NativeJoinResult",uint32_t(result),32);
                return result;
            }
        case AbortScan: return nativeStatus(backend->abortScan());
        case AbortJoin: return nativeStatus(backend->leave(true));
        case Leave: return nativeStatus(backend->leave(false));
        case Bss: return nativeStatus(backend->copyBss(data, NativeWifi::BeaconPrefixSize + NativeWifi::MaximumIEBytes));
        case BeaconFrame: return nativeStatus(backend->copyBeacon(data, 0x808));
        case NativeStop:
            backend->stop();
            NativeWifi::erase(self->pendingScanAddress,6);
            NativeWifi::erase(self->previousScanAddress,6);
            self->pendingScanAddressGeneration=0;
            return kIOReturnSuccess;
        case Cipher: {
            const auto key = static_cast<const apple80211_key *>(data);
            if (!key || key->key_len != 32 || key->key_rsc_len ||
                key->wowl_kck_len || key->wowl_kek_len ||
                (key->key_cipher_type != APPLE80211_CIPHER_PMK &&
                 key->key_cipher_type != APPLE80211_CIPHER_PMKSA)) return kIOReturnUnsupported;
            if (!backend->joining() || self->current_authtype_upper != APPLE80211_AUTHTYPE_WPA2_PSK)
                return kIOReturnNotReady;
            auto ic = self->fHalService->get80211Controller();
            memcpy(ic->ic_psk, key->key, 32); ic->ic_flags |= IEEE80211_F_PSK;
            return kIOReturnSuccess;
        }
        case Address:
            return self->applyNativeAddressGated(data, UInt32(uintptr_t(length)));
    }
    return kIOReturnUnsupported;
}
IOReturn AirportItlwmSkywalkInterface::setWCL_SCAN_REQ(apple80211ScanRequest *request) {
    return _fCommandGate->runAction(nativeRequest, this, reinterpret_cast<void *>(Scan), request);
}
IOReturn AirportItlwmSkywalkInterface::getWCL_LOW_LATENCY_INFO(apple80211_low_latency_info *out) {
    if (!out) return kIOReturnBadArgument;
    // 25G241 GET427 is exactly four bytes, with no version prefix. The native
    // join selector uses it to prefer an active low-latency peer's channel.
    // This target has no AWDL/P2P interface or low-latency peer session, so the
    // actual state is inactive, no peer channel. Revisit when adding P2P.
    bzero(out, 4);
    return kIOReturnSuccess;
}
IOReturn AirportItlwmSkywalkInterface::setWCL_ASSOCIATE(apple80211AssocCandidates *request) {
    return _fCommandGate->runAction(nativeRequest, this, reinterpret_cast<void *>(Join), request);
}
IOReturn AirportItlwmSkywalkInterface::setWCL_SCAN_ABORT(void *) {
    return _fCommandGate->runAction(nativeRequest, this, reinterpret_cast<void *>(AbortScan));
}
IOReturn AirportItlwmSkywalkInterface::setWCL_JOIN_ABORT(apple80211_wcl_abort_join *) {
    return _fCommandGate->runAction(nativeRequest, this, reinterpret_cast<void *>(AbortJoin));
}
IOReturn AirportItlwmSkywalkInterface::setWCL_LEAVE_NETWORK(apple80211_leave_network *) {
    return _fCommandGate->runAction(nativeRequest, this, reinterpret_cast<void *>(Leave));
}
IOReturn AirportItlwmSkywalkInterface::getWCL_BSS_INFO(apple80211_beacon_msg *out) {
    return _fCommandGate->runAction(nativeRequest, this, reinterpret_cast<void *>(Bss), out);
}
IOReturn AirportItlwmSkywalkInterface::getBEACON_INFO(apple80211_beacon_info_t *out) {
    return _fCommandGate->runAction(nativeRequest, this, reinterpret_cast<void *>(BeaconFrame), out);
}
IOReturn AirportItlwmSkywalkInterface::getHW_ADDR(apple80211_hw_mac_address *out) {
    if (!out) return kIOReturnBadArgument;
    uint8_t bits = 0;
    for (unsigned i = 0; i < 6; ++i) bits |= permanentAddress[i];
    if (!bits || (permanentAddress[0] & 1)) return kIOReturnNotReady;
    auto bytes = reinterpret_cast<uint8_t *>(out);
    bzero(bytes, 12); NativeWifi::write32(bytes, 1);
    memcpy(bytes + 4, permanentAddress, 6);
    return kIOReturnSuccess;
}
IOReturn AirportItlwmSkywalkInterface::getWCL_CHANNELS_INFO(apple80211ChannelInfo *out) {
    if (!out) return kIOReturnBadArgument;
    if (!fHalService || !NativeWifi::verifyTahoeRuntime() || !_fCommandGate ||
        !_fCommandGate->getWorkLoop() || !_fCommandGate->getWorkLoop()->inGate())
        return kIOReturnNotReady;
    auto ic = fHalService->get80211Controller();
    if (!ic) return kIOReturnNotReady;

    NativeWifi::ChannelInfoWriter writer(out, NativeWifi::ChannelInfoWriter::Size);
    for (unsigned index = 1; index < IEEE80211_CHAN_MAX; ++index) {
        const auto &channel = ic->ic_channels[index];
        const bool available = isset(ic->ic_chan_avail, index) &&
                               isset(ic->ic_chan_active, index);
        const auto result = writer.append(uint16_t(index), channel.ic_freq,
                                           channel.ic_flags, available);
        if (result == NativeWifi::ChannelInfoWriter::AppendResult::Invalid ||
            result == NativeWifi::ChannelInfoWriter::AppendResult::Full) {
            setProperty("NativeChannelInfoCount", uint64_t(0), 32);
            setProperty("NativeChannelInfoResult", uint32_t(kIOReturnUnsupported), 32);
            return kIOReturnUnsupported;
        }
    }
    const auto count = writer.finish();
    const IOReturn result = count ? kIOReturnSuccess : kIOReturnNotReady;
    setProperty("NativeChannelInfoCount", uint32_t(count), 32);
    setProperty("NativeChannelInfoResult", uint32_t(result), 32);
    return result;
}
IOReturn AirportItlwmSkywalkInterface::setMacAddress(mloAddrArray &request) {
    // Native MacAddressAgent always supplies four addresses, even for a
    // single-link card. Byte 24 records whether its previous client was
    // nonzero (and changes how it prepares auxiliary addresses); it does not
    // mean MLO is enabled. Both 0 and 1 are valid for a normal private MAC.
    // This target advertises no MLO links and programs only the primary MAC,
    // just as the native non-11be path does. Preserve the native address.
    auto bytes = reinterpret_cast<const uint8_t *>(&request);
    setProperty("NativeAddressRequestFlags", uint32_t(bytes[24]) |
        (uint32_t(bytes[25]) << 8), 32);
    IOReturn result = kIOReturnUnsupported;
    if (bytes[24] <= 1 && bytes[25] == 1)
        result = instance ? instance->setHardwareAddress(bytes, 6) : kIOReturnNotReady;
    setProperty("NativeAddressResult", uint32_t(result), 32);
    return result;
}
IOReturn AirportItlwmSkywalkInterface::applyNativeAddress(const void *address, UInt32 length) {
    return _fCommandGate->runAction(nativeRequest, this, reinterpret_cast<void *>(Address),
        const_cast<void *>(address), reinterpret_cast<void *>(uintptr_t(length)));
}
IOReturn AirportItlwmSkywalkInterface::applyNativeAddressGated(const void *data, UInt32 length) {
    if (!_fCommandGate || !_fCommandGate->getWorkLoop() ||
        !_fCommandGate->getWorkLoop()->inGate() || !nativeBackend || !instance ||
        !fHalService) return kIOReturnNotReady;
    setProperty("NativeAddressStage", 1U, 32);
    if (addressQuarantined) return kIOReturnNotPermitted;
    if (!data || length != 6 || !instance->bsdInterface ||
        !instance->bsdInterface->getIfnet()) return kIOReturnBadArgument;
    uint8_t address[6]; memcpy(address, data, sizeof(address));
    uint8_t bits = 0;
    for (unsigned i = 0; i < 6; ++i) bits |= address[i];
    if (!bits || (address[0] & 1) ||
        (!(address[0] & 2) && memcmp(address, permanentAddress, 6))) return kIOReturnBadArgument;
    auto ic = fHalService->get80211Controller();
    const bool unchanged = memcmp(address, ic->ic_myaddr, 6) == 0;
    const bool restart = (ic->ic_if.if_flags & (IFF_UP | IFF_RUNNING)) != 0;
    if (!unchanged) {
        // The power action may have yielded this same workloop gate to a
        // bounded Busy retry. Do not let a MAC change re-enable the radio after
        // Off has claimed the current epoch; a stopped radio can still commit
        // the requested address without restarting hardware.
        if (restart && !instance->nativePowerRequested()) return kIOReturnBusy;
        // Do not overwrite an in-flight init or another address transaction.
        if (((ic->ic_if.if_flags & IFF_UP) && !(ic->ic_if.if_flags & IFF_RUNNING)) ||
            nativeBackend->joining() || nativeBackend->changingAddress()) return kIOReturnBusy;
        if (!ic->ic_tahoe_scan_state) return kIOReturnUnsupported;
        addressQuarantined = true;
        setProperty("NativeAddressQuarantined", kOSBooleanTrue);
        nativeBackend->beginAddressChange();
        setProperty("NativeAddressStage", 2U, 32);
        if (restart) {
            // Native SET_MAC_ADDRESS precedes the new WCL join. Quiesce the
            // previous association/scan before changing any address layer.
            const IOReturn result = fHalService->disable(instance->bsdInterface);
            setProperty("NativeAddressQuiesceResult", uint32_t(result), 32);
            if (result == kIOReturnBusy) {
                // The HAL's nonblocking state-task barrier did not acquire a
                // stop lease. Hardware and all MAC layers are still intact.
                nativeBackend->cancelAddressChange();
                addressQuarantined = false;
                setProperty("NativeAddressQuarantined", kOSBooleanFalse);
                return result;
            }
            if (result != kIOReturnSuccess) return result;
        }
        if ((ic->ic_if.if_flags & (IFF_UP | IFF_RUNNING)) ||
            ic->ic_tahoe_scan_state(ic) != ITL_TAHOE_SCAN_STOPPED)
            return kIOReturnNotReady;
        nativeBackend->addressHardwareStopped();
    } else {
        addressQuarantined = true;
        setProperty("NativeAddressQuarantined", kOSBooleanTrue);
    }
    // Preserve the requested native private address exactly. A partial commit
    // remains quarantined, with no fallback to the permanent address.
    setProperty("NativeAddressStage", 3U, 32);
    if (ifnet_set_lladdr(instance->bsdInterface->getIfnet(), address, 6))
        return kIOReturnError;
    if (!instance->bsdInterface->setProperty(kIOMACAddress, address, 6))
        return kIOReturnNoMemory;
    if (!NativeWifi::updateRegistrationAddress(this, registrationState, address))
        return kIOReturnError;
    memcpy(requestedAddress, address, 6);
    addressWasRequested = true;
    if (!unchanged) {
        if_setlladdr(&ic->ic_if, address);
        if (restart) {
            setProperty("NativeAddressStage", 4U, 32);
            const IOReturn result = fHalService->enable(instance->bsdInterface);
            if (result != kIOReturnSuccess) return result;
        }
    }
    addressQuarantined = false;
    setProperty("NativeAddressQuarantined", kOSBooleanFalse);
    setProperty("NativeAddressStage", 5U, 32);
    return kIOReturnSuccess;
}
bool AirportItlwmSkywalkInterface::nativePrivateAddressReady() const { return nativeAddressReady(true); }
bool AirportItlwmSkywalkInterface::nativeAddressReady(bool requirePrivate) const {
    if (addressQuarantined || !nativeBackend || nativeBackend->changingAddress() || !nativeBackend->ready() ||
        !addressWasRequested || (requirePrivate && (requestedAddress[0] & 3) != 2) ||
        !instance->bsdInterface || !instance->bsdInterface->getIfnet()) return false;
    auto ic = fHalService->get80211Controller();
    if (memcmp(requestedAddress, ic->ic_myaddr, 6)) return false;
    uint8_t actual[6] {};
    if (ifnet_lladdr_copy_bytes(instance->bsdInterface->getIfnet(), actual, 6) ||
        memcmp(requestedAddress, actual, 6)) return false;
    auto property = OSDynamicCast(OSData, instance->bsdInterface->getProperty(kIOMACAddress));
    return property && property->getLength() == 6 &&
        memcmp(requestedAddress, property->getBytesNoCopy(), 6) == 0 &&
        NativeWifi::registrationAddressMatches(const_cast<AirportItlwmSkywalkInterface *>(this),
            registrationState, requestedAddress);
}
bool AirportItlwmSkywalkInterface::privateReady(void *context) {
    auto self=static_cast<AirportItlwmSkywalkInterface *>(context);
    auto ic=self->fHalService->get80211Controller();
    // The tested Iwx HAL snapshots the explicit per-request source into its
    // probe template. Primary/per-network MAC coherence is a separate policy.
    return self->nativeBackend && self->nativeBackend->ready() &&
        !self->nativeBackend->changingAddress() && !self->addressQuarantined &&
        ic->ic_tahoe_scan_state && ic->ic_tahoe_scan_cancel;
}
void AirportItlwmSkywalkInterface::emitNative(void *context, uint32_t event,
    const void *payload, size_t size) {
    auto self = static_cast<AirportItlwmSkywalkInterface *>(context);
    uint8_t link[NativeWifi::LinkEventSize] {};
    if (event == NativeWifi::Link) {
        if (!payload || size != sizeof(link)) return;
        memcpy(link, payload, sizeof(link));
        link[7] = self->isDebounceOnGoing() ? 1 : 0;
        payload = link;
        self->setProperty("NativeLastLinkEventUp", uint32_t(link[6]), 32);
    }
    if (event == NativeWifi::BeaconLqm) {
        if (!payload || size != NativeWifi::BeaconLqmSize) return;
        self->setProperty("NativeAssociatedBeaconCount",
            self->nativeBackend->associatedBeacons(), 32);
        self->setProperty("NativeBeaconLqmDelta",
            NativeWifi::read32(static_cast<const uint8_t *>(payload) + 0x28), 32);
        self->setProperty("NativeBeaconLqmEmitCalls", ++self->beaconLqmEmitCalls, 64);
    }
    // The native WCL queue owns a copy, including this driver's measured LQM.
    self->postMessage(event, const_cast<void *>(payload), size, true);
}
NativeWifi::Status AirportItlwmSkywalkInterface::radioScan(void *context,
    const NativeWifi::ScanPlan &plan) {
    auto self = static_cast<AirportItlwmSkywalkInterface *>(context);
    if (self->fHalService->nativeP2pBusy()) return NativeWifi::Status::Busy;
    auto ic = self->fHalService->get80211Controller();
    if (!(ic->ic_if.if_flags & IFF_RUNNING)) return NativeWifi::Status::NotReady;
    if (!ic->ic_tahoe_scan_state) return NativeWifi::Status::Unsupported;
    if (ic->ic_tahoe_scan_state(ic) != 0 || ic->ic_state == IEEE80211_S_AUTH ||
        ic->ic_state == IEEE80211_S_ASSOC) return NativeWifi::Status::Busy;
    uint8_t source[6] {};
    if (plan.privateAddressRequired && !NativeWifi::secureRandomScanAddress(
        source, ic->ic_myaddr, self->previousScanAddress)) return NativeWifi::Status::Failed;
    // Immutable until a real matching scan completion. The HAL snapshots this
    // complete policy under this same gate before sending a firmware request.
    ic->ic_tahoe_scan_private_random_requested=plan.privateAddressRequired;
    if (plan.privateAddressRequired) memcpy(ic->ic_tahoe_scan_source_addr,source,6);
    else bzero(ic->ic_tahoe_scan_source_addr,6);
    ic->ic_tahoe_join_requested = false;
    ic->ic_tahoe_scan_requested = true;
    ic->ic_tahoe_scan_passive = plan.type == 2;
    ic->ic_tahoe_scan_generation = plan.identifier;
    memcpy(ic->ic_tahoe_scan_channels, plan.channels, 32);
    memcpy(ic->ic_tahoe_scan_ssid, plan.ssid, 32);
    ic->ic_tahoe_scan_ssid_len = plan.ssidLength;
    if (ic->ic_state == IEEE80211_S_RUN) {
        ieee80211_begin_cache_bgscan(&ic->ic_if);
        if (!(ic->ic_flags & IEEE80211_F_BGSCAN)) {
            ic->ic_tahoe_scan_requested = false;
            return NativeWifi::Status::Busy;
        }
    } else if (ic->ic_state == IEEE80211_S_SCAN) {
        // SCAN is also the disconnected idle net80211 state. The HAL's real
        // firmware lease, checked above, distinguishes it from an initial scan.
        ieee80211_begin_scan(&ic->ic_if);
    } else if (ic->ic_newstate(ic, IEEE80211_S_SCAN, -1)) {
        ic->ic_tahoe_scan_requested = false;
        return NativeWifi::Status::Failed;
    }
    if (plan.privateAddressRequired) {
        memcpy(self->pendingScanAddress,source,6);
        self->pendingScanAddressGeneration=plan.identifier;
    } else {
        NativeWifi::erase(self->pendingScanAddress,6);
        self->pendingScanAddressGeneration=0;
    }
    NativeWifi::erase(source,sizeof(source));
    return NativeWifi::Status::Ok;
}
NativeWifi::Status AirportItlwmSkywalkInterface::radioCancelScan(void *context) {
    auto self = static_cast<AirportItlwmSkywalkInterface *>(context);
    if (self->fHalService->nativeP2pBusy()) return NativeWifi::Status::Busy;
    auto ic = self->fHalService->get80211Controller();
    if (!ic->ic_tahoe_scan_cancel) return NativeWifi::Status::Unsupported;
    const int error = ic->ic_tahoe_scan_cancel(ic);
    return error == 0 ? NativeWifi::Status::Ok :
        (error == EBUSY ? NativeWifi::Status::Busy : NativeWifi::Status::Failed);
}
NativeWifi::Status AirportItlwmSkywalkInterface::radioJoin(void *context,
    const NativeWifi::JoinPlan &plan) {
    auto self = static_cast<AirportItlwmSkywalkInterface *>(context);
    if (self->fHalService->nativeP2pBusy()) return NativeWifi::Status::Busy;
    auto ic = self->fHalService->get80211Controller();
    if (!(ic->ic_if.if_flags & IFF_RUNNING)) return NativeWifi::Status::NotReady;
    if (!ic->ic_tahoe_scan_state) return NativeWifi::Status::Unsupported;
    if (ic->ic_tahoe_scan_state(ic) != 0) return NativeWifi::Status::Busy;
    if (self->addressWasRequested && !self->nativeAddressReady(false))
        return NativeWifi::Status::NotReady;
    ieee80211_disable_rsn(ic); ieee80211_disable_wep(ic);
    NativeWifi::erase(ic->ic_psk, sizeof(ic->ic_psk));
    ic->ic_flags &= ~(IEEE80211_F_AUTO_JOIN | IEEE80211_F_PSK);
    if (plan.secured) {
        ieee80211_wpaparams parameters {};
        parameters.i_enabled = 1;
        parameters.i_protos = IEEE80211_WPA_PROTO_WPA2;
        parameters.i_akms = IEEE80211_WPA_AKM_PSK;
        parameters.i_ciphers = IEEE80211_WPA_CIPHER_CCMP;
        parameters.i_groupcipher = IEEE80211_WPA_CIPHER_CCMP;
        int error = ieee80211_ioctl_setwpaparms(ic, &parameters);
        if (error && error != ENETRESET) return NativeWifi::Status::Failed;
        if (plan.derivePmk) {
            if (!NativeWifi::deriveWPA2Pmk(plan.password, plan.passwordLength,
                plan.ssid, plan.ssidLength, ic->ic_psk)) {
                NativeWifi::erase(ic->ic_psk, sizeof(ic->ic_psk));
                return NativeWifi::Status::Failed;
            }
        } else memcpy(ic->ic_psk, plan.pmk, 32);
        ic->ic_flags |= IEEE80211_F_PSK;
    }
    ic->ic_des_esslen = plan.ssidLength;
    bzero(ic->ic_des_essid, sizeof(ic->ic_des_essid));
    memcpy(ic->ic_des_essid, plan.ssid, plan.ssidLength);
    memcpy(ic->ic_des_bssid, plan.bssid, 6);
    ic->ic_flags |= IEEE80211_F_DESBSSID;
    ic->ic_tahoe_join_requested = true;
    ic->ic_tahoe_scan_requested = false;
    self->current_authtype_lower = plan.lowerAuth;
    self->current_authtype_upper = plan.upperAuth;
    if (ic->ic_state == IEEE80211_S_SCAN) ieee80211_begin_scan(&ic->ic_if);
    else if (ic->ic_newstate(ic, IEEE80211_S_SCAN, -1)) {
        ic->ic_tahoe_join_requested = false;
        NativeWifi::erase(ic->ic_psk, sizeof(ic->ic_psk));
        return NativeWifi::Status::Failed;
    }
    return NativeWifi::Status::Ok;
}
void AirportItlwmSkywalkInterface::radioLeave(void *context) {
    auto self = static_cast<AirportItlwmSkywalkInterface *>(context);
    auto ic = self->fHalService->get80211Controller();
    ic->ic_tahoe_join_requested = false;
    if (ic->ic_state > IEEE80211_S_SCAN) ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
    ieee80211_disable_rsn(ic); ieee80211_disable_wep(ic);
    NativeWifi::erase(ic->ic_psk, sizeof(ic->ic_psk));
    ic->ic_flags &= ~(IEEE80211_F_PSK | IEEE80211_F_DESBSSID);
    ic->ic_des_esslen = 0;
    bzero(ic->ic_des_essid, sizeof(ic->ic_des_essid));
}
void AirportItlwmSkywalkInterface::captureNativeEvent(int code, void *data) {
    if (!nativeIngress) return;
    auto ic = fHalService->get80211Controller();
    if (code == ITL_TAHOE_EVT_BEACON) {
        auto source = static_cast<const itl_tahoe_beacon_event *>(data);
        if (!source || !source->node || !source->node->ni_chan ||
            source->node->ni_chan == IEEE80211_CHAN_ANYC) return;
        const auto node = source->node;
        const unsigned channel = ieee80211_chan2ieee(ic, node->ni_chan);
        if (!channel || channel > 196) return;
        NativeWifi::Beacon beacon {node->ni_essid, node->ni_bssid, source->ies, source->frame,
            node->ni_esslen, source->ie_length, source->frame_length,
            uint16_t(channel | (IEEE80211_IS_CHAN_5GHZ(node->ni_chan) ? 0xd000 : 0x1000)),
            node->ni_intval, node->ni_capinfo, uint8_t(channel),
            IWM_MIN_DBM + node->ni_rssi, int16_t(-fHalService->getDriverInfo()->getBSSNoise()), 0};
        nativeIngress->receive(beacon);
    } else if (code == IEEE80211_EVT_STA_ASSOC_DONE) {
        nativeIngress->signal(code, ic->ic_assoc_status, ic->ic_bss ? ic->ic_bss->ni_bssid : nullptr);
    } else if (code == IEEE80211_EVT_SCAN_DONE || code == ITL_TAHOE_EVT_SCAN_RESET_DRAINED) {
        const auto event = static_cast<const itl_tahoe_scan_event *>(data);
        nativeIngress->signal(code, event ? event->generation : 0, nullptr,
            event ? event->firmware_status : 0);
    } else nativeIngress->signal(unsigned(code));
}
void AirportItlwmSkywalkInterface::captureNativeAuthorization(bool up) {
    if (nativeIngress) nativeIngress->signal(10, up ? 1 : 0);
}
void AirportItlwmSkywalkInterface::captureNativeTick(uint32_t elapsed) {
    if (nativeIngress) nativeIngress->signal(9, elapsed);
}
void AirportItlwmSkywalkInterface::consumeNative(void *context, const NativeWifi::IngressEntry &entry) {
    auto self = static_cast<AirportItlwmSkywalkInterface *>(context);
    auto backend = self->nativeBackend;
    if (!backend) return;
    switch (entry.kind) {
        case IEEE80211_EVT_STA_ASSOC_DONE:
            backend->observeAssociation(uint16_t(entry.value), entry.bssid);
            self->fHalService->get80211Controller()->ic_tahoe_join_requested = false;
            break;
        case IEEE80211_EVT_STA_DEAUTH: backend->observeAuthorization(false); break;
        case IEEE80211_EVT_SCAN_DONE:
            self->setProperty("NativeScanTerminalGeneration", entry.value, 32);
            self->setProperty("NativeScanTerminalStatus", entry.detail, 32);
            // A true terminal event proves this request was submitted. Busy or
            // synchronous admission failure never advances the previous MAC.
            if (entry.value && entry.value==self->pendingScanAddressGeneration &&
                (entry.detail==1 || entry.detail==2)) {
                memcpy(self->previousScanAddress,self->pendingScanAddress,6);
                NativeWifi::erase(self->pendingScanAddress,6);
                self->pendingScanAddressGeneration=0;
            }
            backend->observeScanComplete(entry.value, entry.detail);
            if (!backend->scanning()) self->fHalService->get80211Controller()->ic_tahoe_scan_requested = false;
            break;
        case ITL_TAHOE_EVT_SCAN_RESET_DRAINED:
            backend->observeScanReset(entry.value);
            if (entry.value && entry.value == self->pendingScanAddressGeneration) {
                memcpy(self->previousScanAddress, self->pendingScanAddress, 6);
                NativeWifi::erase(self->pendingScanAddress, 6);
                self->pendingScanAddressGeneration = 0;
            }
            self->setProperty("NativeScanResetDrainedCount",
                self->fHalService->get80211Controller()->ic_tahoe_scan_reset_count, 32);
            break;
        case ITL_TAHOE_EVT_BEACON: {
            NativeWifi::Beacon beacon {entry.ssid,entry.bssid,entry.frame+36,entry.frame,
                entry.ssidLength,size_t(entry.frameLength-36),entry.frameLength,
                entry.channelSpec,entry.interval,entry.capability,entry.channel,
                entry.rssi,entry.noise,entry.snr};
            backend->observeBeacon(beacon); break;
        }
        case ITL_TAHOE_EVT_DRIVER_READY:
        case ITL_TAHOE_EVT_DRIVER_STOPPED:
            backend->driverState(entry.kind == ITL_TAHOE_EVT_DRIVER_READY);
            // IRQ/task ingress only changed atomics. Publish and notify from
            // this owned, serialized consumer after a real HAL state event.
            self->instance->publishNativePowerState();
            self->instance->wakeNativePowerWaiters();
            self->postMessage(APPLE80211_M_POWER_CHANGED, nullptr, 0, true);
            break;
        case ITL_TAHOE_EVT_RESET_BEGIN:
            if (!backend->changingAddress()) backend->driverState(false);
            break;
        case 9: backend->tick(entry.value); break;
        case 10: backend->observeAuthorization(entry.value != 0); break;
        case IEEE80211_EVT_COUNTRY_CODE_UPDATE:
            self->postMessage(APPLE80211_M_COUNTRY_CODE_CHANGED, nullptr, 0, false); break;
    }
    // Publish counters only from the watchdog or rare control events; beacon RX
    // never performs IORegistry allocation on its producer dynamic stack.
    if (entry.kind != ITL_TAHOE_EVT_BEACON) {
        // These are emit-call counts, not acknowledgements from the native
        // WCL cache. Publish only on this owned consumer, never on RX/IRQ.
        const auto emitted201 = backend->event201EmitCalls();
        const auto emitted237 = backend->event237EmitCalls();
        const auto pendingBeacons = backend->pendingScanBeacons();
        const auto overflows = self->nativeIngress ? self->nativeIngress->overflows() : 0;
        const auto last237Status = backend->last237Status();
        const uint32_t scanState = (backend->scanning() ? 1U : 0U) |
            (backend->scanDraining() ? 2U : 0U);
        if (self->published201Calls != emitted201 || self->published237Calls != emitted237 ||
            self->publishedPendingBeacons != pendingBeacons ||
            self->publishedIngressOverflows != overflows ||
            self->published237Status != last237Status || self->publishedScanState != scanState) {
            self->setProperty("NativeScanBeaconEmitCalls", emitted201, 64);
            self->setProperty("NativeScanCompleteEmitCalls", emitted237, 64);
            self->setProperty("NativeScanCompleteLastStatus", last237Status, 32);
            self->setProperty("NativeScanPendingBeacons", pendingBeacons, 64);
            self->setProperty("NativeIngressOverflows", overflows, 64);
            self->setProperty("NativeScanPending", scanState & 1U, 32);
            self->setProperty("NativeScanDraining", (scanState >> 1) & 1U, 32);
            self->published201Calls = emitted201;
            self->published237Calls = emitted237;
            self->publishedPendingBeacons = pendingBeacons;
            self->publishedIngressOverflows = overflows;
            self->published237Status = last237Status;
            self->publishedScanState = scanState;
        }
        if (self->publishedScanCount != backend->scanRequests()) {
            self->publishedScanCount = backend->scanRequests();
            self->setProperty("NativeScanRequests", self->publishedScanCount, 64);
        }
        if (self->publishedJoinCount != backend->joinRequests()) {
            self->publishedJoinCount = backend->joinRequests();
            self->setProperty("NativeJoinRequests", self->publishedJoinCount, 64);
        }
        if (self->publishedBeaconCount != backend->realBeacons()) {
            self->publishedBeaconCount = backend->realBeacons();
            self->setProperty("NativeRealBeacons", self->publishedBeaconCount, 64);
        }
    }
}
bool AirportItlwmSkywalkInterface::prepareNativeRegistration() {
    return NativeWifi::prepareRegistration(this, permanentAddress, registrationState);
}
IOReturn AirportItlwmSkywalkInterface::deregisterLogicalLink() {
    if (registrationState.published) return kIOReturnUnsupported;
    return IO80211InfraProtocol::deregisterLogicalLink();
}
void AirportItlwmSkywalkInterface::stop(IOService *provider) {
    NativeWifi::detachRegistration(this, registrationState);
    IO80211InfraProtocol::stop(provider);
}
void AirportItlwmSkywalkInterface::free() {
    NativeWifi::detachRegistration(this, registrationState);
    IO80211InfraProtocol::free();
}
bool AirportItlwmSkywalkInterface::stopNative() {
    if (!nativeIngress) return true;
    if (!nativeIngress->shutdown()) return false;
    if (nativeBackend) _fCommandGate->runAction(nativeRequest, this, reinterpret_cast<void *>(NativeStop));
    return true;
}
void AirportItlwmSkywalkInterface::releaseNative() {
    if (nativeIngress) { if (!nativeIngress->destroy()) return; delete nativeIngress; nativeIngress = nullptr; }
    if (nativeBackend) { nativeBackend->stop(); delete nativeBackend; nativeBackend = nullptr; }
    if (nativeLease) { nativeLease = false; instance->release(); release(); }
}
IOReturn AirportItlwmSkywalkInterface::getWCL_VALID_CHANNEL_COUNT(unsigned long *count) {
    if (!count) return kIOReturnBadArgument;
    *count = 0;
    auto ic = fHalService->get80211Controller();
    for (unsigned channel = 1; channel <= 196; ++channel)
        if (ic->ic_channels[channel].ic_flags) ++*count;
    return *count ? kIOReturnSuccess : kIOReturnNotReady;
}
IOReturn AirportItlwmSkywalkInterface::getWCL_EXTENDED_BSS_INFO(apple80211_extended_bss_info *out) {
    if (!out) return kIOReturnBadArgument;
    auto ic = fHalService->get80211Controller();
    if (!ic->ic_bss || ic->ic_state != IEEE80211_S_RUN) return kIOReturnNotReady;
    auto bytes = reinterpret_cast<uint8_t *>(out);
    bzero(bytes, 0x214);
    IOReturn result = getRATE_SET(reinterpret_cast<apple80211_rate_set_data *>(bytes));
    if (result) return result;
    result = getMCS_INDEX_SET(reinterpret_cast<apple80211_mcs_index_set_data *>(bytes + 0xbc));
    if (result) return result;
    NativeWifi::write32(bytes + 0xcc, 1); NativeWifi::write16(bytes + 0xd0, 0xffff);
    NativeWifi::write32(bytes + 0xd4, 1); NativeWifi::write16(bytes + 0xd8, 0xffff);
    return kIOReturnSuccess;
}
#endif
