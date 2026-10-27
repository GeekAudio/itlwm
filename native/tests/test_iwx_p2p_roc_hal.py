#!/usr/bin/env python3
"""Fault-inject the production Tahoe ROC HAL methods with fake firmware I/O."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]


def extract(path, marker):
    source = (root / path).read_text()
    start = source.index(marker)
    opening = source.index("{", start)
    end, depth = opening + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


shim = r"""
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>
#define AIRPORT_TAHOE 1
#define htole32(x) static_cast<uint32_t>(x)
#define isset(bits,bit) (((bits)[(bit)/8] & (1U<<((bit)%8))) != 0)
enum {
 IWX_LONG_GROUP=1, IWX_MAC_CONF_GROUP=3,
 IWX_UCODE_TLV_FLAGS_P2P=3, IWX_UCODE_TLV_CAPA_BINDING_CDB_SUPPORT=39,
 IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD=54,
 IWX_MAC_CONTEXT_CMD=0x28, IWX_PHY_CONTEXT_CMD=0x8,
 IWX_BINDING_CONTEXT_CMD=0x2b, IWX_SESSION_PROTECTION_CMD=5,
 IWX_SESSION_PROTECTION_NOTIF=0xfb,
 IWX_PHY_BAND_24=1, IWX_PHY_BAND_5=0,
 IWX_PHY_VHT_CHANNEL_MODE20=0, IWX_PHY_VHT_CTRL_POS_1_BELOW=0,
 IWX_PHY_RX_CHAIN_VALID_POS=1, IWX_PHY_RX_CHAIN_CNT_POS=10,
 IWX_PHY_RX_CHAIN_MIMO_CNT_POS=12,
 IWX_FW_CTXT_ACTION_ADD=1, IWX_FW_CTXT_ACTION_MODIFY=2,
 IWX_FW_CTXT_ACTION_REMOVE=3, IWX_FW_CTXT_INVALID=0xffffffff,
 IWX_P2P_RESOURCE_ABSENT=0, IWX_P2P_RESOURCE_ACTIVE=1,
 IWX_P2P_RESOURCE_UNKNOWN=2, IWX_P2P_UNCERTAIN_NONE=0,
 IWX_P2P_UNCERTAIN_BINDING=2,
 IWX_P2P_ROC_IDLE=0, IWX_P2P_ROC_PHY_REMOVE_UNKNOWN,
 IWX_P2P_ROC_PHY_REMOVED, IWX_P2P_ROC_PHY_ADD_UNKNOWN,
 IWX_P2P_ROC_PHY_READY, IWX_P2P_ROC_BINDING_ADD_UNKNOWN,
 IWX_P2P_ROC_PREPARED, IWX_P2P_ROC_SESSION_SUBMIT_UNKNOWN,
 IWX_P2P_ROC_SESSION_ACKED, IWX_P2P_ROC_END_CONFIRMED,
 IWX_P2P_ROC_BINDING_REMOVE_UNKNOWN, IWX_P2P_ROC_PHY_RESTORE_REMOVE_UNKNOWN,
 IWX_P2P_ROC_PHY_RESTORE_ADD_UNKNOWN, IWX_P2P_ROC_COMPLETE,
 IWX_P2P_ROC_QUARANTINED,
 IWX_UCODE_TLV_CAPA_CDB_SUPPORT=40,
 IWX_MAC_INDEX_MIN_DRIVER=0, IWX_MAC_INDEX_AUX=4,
 IWX_NUM_PHY_CTX=3, IWX_MAX_MACS_IN_BINDING=3,
 IWX_FLAG_MAC_ACTIVE=1<<0, IWX_FLAG_BINDING_ACTIVE=1<<1,
 IEEE80211_CHAN_MAX=255,
 IEEE80211_CHAN_2GHZ=1<<7, IEEE80211_CHAN_5GHZ=1<<8,
 IEEE80211_CHAN_PASSIVE=1<<9, IEEE80211_CHAN_DFS=1<<19,
 IEEE80211_CHAN_OFDM=1<<6,
 IEEE80211_S_RUN=4
};
typedef unsigned int u_int;
struct ieee80211_channel {
 uint32_t channel; bool is2g; uint16_t ic_freq; uint32_t ic_flags;
 ieee80211_channel(uint32_t c=36,bool g=false):channel(c),is2g(g),
  ic_freq(g?static_cast<uint16_t>(2407+5*c):static_cast<uint16_t>(5000+5*c)),
  ic_flags((g?IEEE80211_CHAN_2GHZ:IEEE80211_CHAN_5GHZ)|IEEE80211_CHAN_OFDM){}
};
struct ieee80211_node { ieee80211_channel *ni_chan=nullptr; uint8_t ni_macaddr[6]{}; };
struct iwx_phy_ctxt { uint16_t id=0,color=0; uint32_t ref=0; ieee80211_channel *channel=nullptr; };
struct iwx_node { iwx_phy_ctxt *in_phyctxt=nullptr; uint16_t in_id=0; ieee80211_node in_ni{}; };
struct ieee80211com {
 int ic_state=IEEE80211_S_RUN; iwx_node *ic_bss=nullptr;
 ieee80211_channel ic_channels[256]{};
};
static unsigned channelLookupCalls=0;
static unsigned ieee80211_chan2ieee(ieee80211com *ic,const ieee80211_channel *c) {
 ++channelLookupCalls;
 for(unsigned i=0;i<=IEEE80211_CHAN_MAX;++i)
  if(c==&ic->ic_channels[i])return i;
 return 1; // Match the OpenBSD helper's bogus-pointer result.
}
struct iwx_p2p_context {
 uint8_t initialized=0,mac_state=0,binding_state=0,phy_leased=0;
 uint8_t mac_id=0,mac_color=0,tsf_id=0,phy_id=0,phy_color=0;
 uint8_t binding_id=0,binding_color=0,uncertain_kind=0,uncertain_action=0;
 uint8_t mac_address[6]{};uint32_t fw_generation=0;
};
struct iwx_p2p_roc_state {
 uint32_t token=0,fw_generation=0; int32_t session_submit_result=0;
 uint32_t binding_raw_status=0; uint8_t phase=0,phy_id=0,phy_color=0;
 uint8_t session_conf_id=0,session_submit_seen=0,binding_status_valid=0,binding_rejected=0;
 ieee80211_channel *original_phy_channel=nullptr,*roc_channel=nullptr;
};
struct iwx_softc {
 int sc_generation=7,sc_flags=IWX_FLAG_MAC_ACTIVE|IWX_FLAG_BINDING_ACTIVE;
 int sc_capaflags=IWX_UCODE_TLV_FLAGS_P2P; uint8_t sc_enabled_capa[8]{};
 iwx_p2p_context sc_p2p{};iwx_p2p_roc_state sc_p2p_roc{};
 iwx_phy_ctxt sc_phyctxt[IWX_NUM_PHY_CTX]{};ieee80211com sc_ic{};
};
struct iwx_fw_channel_info { uint32_t channel;uint8_t band,width,ctrl_pos,reserved; } __attribute__((packed));
struct iwx_phy_context_cmd {
 uint32_t id_and_color,action;iwx_fw_channel_info ci;uint32_t lmac_id,
 rxchain_info,dsp_cfg_flags,reserved;
} __attribute__((packed));
struct iwx_binding_cmd {uint32_t id_and_color,action,macs[3],phy,lmac_id;} __attribute__((packed));
struct iwx_session_prot_cmd {uint32_t id_and_color,action,conf_id,duration_tu,repetition_count,interval;} __attribute__((packed));
static_assert(sizeof(iwx_phy_context_cmd)==32,"PHY v3 ABI");
static_assert(sizeof(iwx_binding_cmd)==28,"binding v2 ABI");
static_assert(sizeof(iwx_session_prot_cmd)==24,"session protection v1 ABI");
#define IWX_FW_CMD_ID_AND_COLOR(id,color) ((id) | ((color)<<8))
#define IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV 2
#define IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION 3
static const uint32_t kTahoeRocDurationMs=100;
static const uint32_t kTahoeSocialTxRocDurationMs=900;
using TahoeP2pRocArmTracker=bool(*)(void*,uint32_t,uint32_t,uint32_t);
static uint32_t iwx_cmd_id(uint8_t op,uint8_t group,uint8_t version) {
 return op+(group<<8)+(version<<16);
}
#define IEEE80211_IS_CHAN_2GHZ(c) ((c)->is2g)
struct ItlIwx {
 iwx_softc com{}; bool allowed=true;
 unsigned macVer=5,phyVer=3,bindingVer=2,bindingNotif=1,sessionVer=1,sessionNotif=2;
 int pduDefault=0,statusResult=0; uint32_t status=0; int pduFailAt=0;
 unsigned pduSends=0,statusSends=0; std::vector<uint32_t> pduIds;
 std::vector<unsigned> pduLens; std::vector<std::vector<uint8_t>> pduPayloads;
 bool armed=false; unsigned armCalls=0;
 bool nativeP2pCommandAllowed() const {return allowed;}
 uint8_t iwx_lookup_cmd_ver(iwx_softc*,uint8_t group,uint8_t cmd) {
  if(group==IWX_LONG_GROUP&&cmd==IWX_MAC_CONTEXT_CMD)return macVer;
  if(group==IWX_LONG_GROUP&&cmd==IWX_PHY_CONTEXT_CMD)return phyVer;
  if(group==IWX_LONG_GROUP&&cmd==IWX_BINDING_CONTEXT_CMD)return bindingVer;
  if(group==IWX_MAC_CONF_GROUP&&cmd==IWX_SESSION_PROTECTION_CMD)return sessionVer;
  return 0;
 }
 uint8_t iwx_lookup_notif_ver(iwx_softc*,uint8_t group,uint8_t cmd) {
  if(group==IWX_LONG_GROUP&&cmd==IWX_BINDING_CONTEXT_CMD)return bindingNotif;
  if(group==IWX_MAC_CONF_GROUP&&cmd==IWX_SESSION_PROTECTION_NOTIF)return sessionNotif;
  return 0;
 }
 uint32_t iwx_lmac_id(iwx_softc*,ieee80211_channel *c) {return c->is2g?0:1;}
 uint8_t iwx_fw_valid_rx_ant(iwx_softc*) {return 3;}
 int iwx_send_cmd_pdu(iwx_softc*,uint32_t id,uint32_t,uint16_t len,const void *data) {
  ++pduSends;pduIds.push_back(id);pduLens.push_back(len);
  const auto *bytes=static_cast<const uint8_t*>(data);
  pduPayloads.emplace_back(bytes,bytes+len);
  if(pduFailAt==static_cast<int>(pduSends))return ETIMEDOUT;
  return pduDefault;
 }
 int iwx_send_cmd_pdu_status(iwx_softc*,uint32_t id,uint16_t len,const void *data,uint32_t *out) {
  ++statusSends;pduIds.push_back(id);pduLens.push_back(len);
  const auto *bytes=static_cast<const uint8_t*>(data);
  pduPayloads.emplace_back(bytes,bytes+len);
  if(statusResult)return statusResult;*out=status;return 0;
 }
 int iwx_p2p_phy_lease(iwx_softc*,uint8_t*);
 int iwx_p2p_phy_release(iwx_softc*);
 int iwx_p2p_binding_add(iwx_softc*);
 int iwx_p2p_binding_remove(iwx_softc*);
 int iwx_p2p_context_reset_after_fw_reset(iwx_softc*,uint32_t);
 int tahoeP2pRocPrepare(iwx_softc*,ieee80211_channel*,uint32_t,uint32_t);
 int tahoeP2pRocSubmit(iwx_softc*,uint32_t,uint32_t,uint32_t,TahoeP2pRocArmTracker,void*);
 int tahoeP2pRocCleanup(iwx_softc*,uint32_t,uint32_t,bool);
 int tahoeP2pRocAbortPrepared(iwx_softc*,uint32_t,uint32_t,bool);
};
"""

actual = "\n".join([
    extract("itlwm/hal_iwx/ItlIwx.cpp", "static int\niwx_p2p_check_fw_contract("),
    extract("itlwm/hal_iwx/ItlIwx.cpp", "int ItlIwx::\niwx_p2p_phy_lease("),
    extract("itlwm/hal_iwx/ItlIwx.cpp", "int ItlIwx::\niwx_p2p_phy_release("),
    extract("itlwm/hal_iwx/ItlIwx.cpp", "int ItlIwx::\niwx_p2p_binding_add("),
    extract("itlwm/hal_iwx/ItlIwx.cpp", "int ItlIwx::\niwx_p2p_binding_remove("),
    extract("itlwm/hal_iwx/ItlIwx.cpp", "int ItlIwx::\niwx_p2p_context_reset_after_fw_reset("),
    extract("itlwm/hal_iwx/ItlIwxP2PRoc.cpp", "static uint8_t\ntahoeP2pRocAntennaCount("),
    extract("itlwm/hal_iwx/ItlIwxP2PRoc.cpp", "static int\ntahoeP2pRocPhyCommand("),
    extract("itlwm/hal_iwx/ItlIwxP2PRoc.cpp", "static int\ntahoeP2pRocRestorePhy("),
    extract("itlwm/hal_iwx/ItlIwxP2PRoc.cpp", "static uint32_t\ntahoeP2pMsecToTu("),
    extract("itlwm/hal_iwx/ItlIwxP2PRoc.cpp", "static bool\ntahoeP2pRocConfigurationSupported("),
    extract("itlwm/hal_iwx/ItlIwxP2PRoc.cpp", "static bool\ntahoeP2pRocCurrentChannelIndex("),
    extract("itlwm/hal_iwx/ItlIwxP2PRoc.cpp", "static bool\ntahoeP2pRocSocialChannel6Allowed("),
    extract("itlwm/hal_iwx/ItlIwxP2PRoc.cpp", "static bool\ntahoeP2pRocOffChannelAllowed("),
    extract("itlwm/hal_iwx/ItlIwxP2PRoc.cpp", "static bool\ntahoeP2pRocLongSocialTxAllowed("),
    extract("itlwm/hal_iwx/ItlIwxP2PRoc.cpp", "int ItlIwx::\ntahoeP2pRocPrepare("),
    extract("itlwm/hal_iwx/ItlIwxP2PRoc.cpp", "int ItlIwx::\ntahoeP2pRocSubmit("),
    extract("itlwm/hal_iwx/ItlIwxP2PRoc.cpp", "int ItlIwx::\ntahoeP2pRocCleanup("),
    extract("itlwm/hal_iwx/ItlIwxP2PRoc.cpp", "int ItlIwx::\ntahoeP2pRocAbortPrepared("),
])

body = r"""
static uint32_t expectedConfiguration=2;
static ieee80211_channel *currentChannel(ItlIwx &h, uint32_t index) {
 assert(index<=IEEE80211_CHAN_MAX);
 return &h.com.sc_ic.ic_channels[index];
}
static ieee80211_channel *tableChannel(ItlIwx &h, const ieee80211_channel &source) {
 assert(source.channel>0&&source.channel<=IEEE80211_CHAN_MAX);
 auto *channel=&h.com.sc_ic.ic_channels[source.channel];
 *channel=source;
 return channel;
}
static ieee80211_channel *liveSocial6(ItlIwx &h) {
 auto *channel=currentChannel(h,6);
 *channel=ieee80211_channel{6,true};
 return channel;
}
static bool arm(void *context,uint32_t generation,uint32_t idColor,uint32_t conf) {
 auto *h=static_cast<ItlIwx*>(context);h->armed=true;++h->armCalls;
 assert(generation==7&&idColor==1&&conf==expectedConfiguration);
 assert(h->pduSends==2); // Tracker is armed before SESSION_PROTECTION_CMD.
 return true;
}
static bool rejectArm(void*,uint32_t,uint32_t,uint32_t) {return false;}
static void setup(ItlIwx &h,ieee80211_channel &staChan,ieee80211_channel &initial) {
 auto *sc=&h.com;
 auto *liveSta=tableChannel(h,staChan);
 auto *liveInitial=tableChannel(h,initial);
 sc->sc_p2p.initialized=1;sc->sc_p2p.mac_state=IWX_P2P_RESOURCE_ACTIVE;
 sc->sc_p2p.binding_state=IWX_P2P_RESOURCE_ABSENT;sc->sc_p2p.mac_id=1;
 sc->sc_p2p.mac_color=0;sc->sc_p2p.tsf_id=1;sc->sc_p2p.fw_generation=7;
 sc->sc_phyctxt[0].id=0;sc->sc_phyctxt[0].channel=liveSta;
 sc->sc_phyctxt[1].id=1;sc->sc_phyctxt[1].color=4;sc->sc_phyctxt[1].channel=liveInitial;
 sc->sc_phyctxt[2].id=2;sc->sc_phyctxt[2].color=5;sc->sc_phyctxt[2].channel=liveInitial;
 static iwx_node sta;sta.in_phyctxt=&sc->sc_phyctxt[0];sta.in_id=0;
 sta.in_ni.ni_chan=liveSta;sc->sc_ic.ic_bss=&sta;sc->sc_ic.ic_state=IEEE80211_S_RUN;
 sc->sc_enabled_capa[IWX_UCODE_TLV_CAPA_BINDING_CDB_SUPPORT/8]|=
      1U<<(IWX_UCODE_TLV_CAPA_BINDING_CDB_SUPPORT%8);
 sc->sc_enabled_capa[IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD/8]|=
      1U<<(IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD%8);
}
int main() {
 static_assert(sizeof(iwx_phy_context_cmd)==32,"actual PHY payload size");
 static_assert(sizeof(iwx_binding_cmd)==28,"actual binding payload size");
 static_assert(sizeof(iwx_session_prot_cmd)==24,"actual session payload size");
 // The normal path changes only the spare PHY, binds it, arms the tracker,
 // submits a 100ms session, and leaves cleanup gated on END observation.
 {
  ItlIwx h;ieee80211_channel staChan{36,false},initial{1,true};setup(h,staChan,initial);
  auto *sc=&h.com;assert(h.tahoeP2pRocPrepare(sc,currentChannel(h,staChan.channel),77,2)==0);
  assert(sc->sc_p2p_roc.phase==IWX_P2P_ROC_PREPARED&&sc->sc_p2p_roc.token==77);
  assert(sc->sc_p2p_roc.session_conf_id==2);
  assert(sc->sc_p2p_roc.original_phy_channel==currentChannel(h,initial.channel)&&
         sc->sc_phyctxt[1].channel==currentChannel(h,staChan.channel));
  assert(h.pduSends==2&&h.statusSends==1);
  auto phy0=reinterpret_cast<const iwx_phy_context_cmd*>(h.pduPayloads[0].data());
  auto phy1=reinterpret_cast<const iwx_phy_context_cmd*>(h.pduPayloads[1].data());
  assert(phy0->id_and_color==0x401&&phy0->action==IWX_FW_CTXT_ACTION_REMOVE);
  assert(phy0->ci.channel==1&&phy0->ci.band==IWX_PHY_BAND_24&&phy0->ci.width==IWX_PHY_VHT_CHANNEL_MODE20);
  assert(phy1->action==IWX_FW_CTXT_ACTION_ADD&&phy1->ci.channel==36);
  assert(phy1->ci.band==IWX_PHY_BAND_5&&phy1->ci.width==IWX_PHY_VHT_CHANNEL_MODE20&&phy1->ci.ctrl_pos==0);
  assert(h.tahoeP2pRocSubmit(sc,77,3,100,arm,&h)==EBUSY);
  assert(h.tahoeP2pRocCleanup(sc,77,3,true)==EBUSY);
  assert(h.pduSends==2&&h.armCalls==0); // A mismatched mode cannot submit or clean up.
  assert(h.tahoeP2pRocSubmit(sc,77,2,100,arm,&h)==0&&h.armed&&h.armCalls==1);
  assert(sc->sc_p2p_roc.phase==IWX_P2P_ROC_SESSION_ACKED);
  assert(h.pduIds.back()==iwx_cmd_id(IWX_SESSION_PROTECTION_CMD,IWX_MAC_CONF_GROUP,0));
  assert(h.pduLens.back()==24);
  auto session=reinterpret_cast<const iwx_session_prot_cmd*>(h.pduPayloads.back().data());
  assert(session->id_and_color==1&&session->action==IWX_FW_CTXT_ACTION_ADD);
  assert(session->conf_id==IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV);
  assert(session->duration_tu==97&&session->repetition_count==0&&session->interval==0);
  unsigned before=h.pduSends+ h.statusSends;
  assert(h.tahoeP2pRocCleanup(sc,77,2,false)==EBUSY);
  assert(h.pduSends+h.statusSends==before); // No END, no teardown.
  assert(h.tahoeP2pRocCleanup(sc,77,2,true)==0);
  assert(sc->sc_p2p_roc.phase==IWX_P2P_ROC_COMPLETE);
  assert(sc->sc_p2p.binding_state==IWX_P2P_RESOURCE_ABSENT&&!sc->sc_p2p.phy_leased);
  assert(sc->sc_phyctxt[1].channel==currentChannel(h,initial.channel));
  assert(h.pduSends==5&&h.statusSends==2);
  auto restore=reinterpret_cast<const iwx_phy_context_cmd*>(h.pduPayloads.back().data());
  assert(restore->action==IWX_FW_CTXT_ACTION_ADD&&restore->ci.channel==1&&restore->ci.width==IWX_PHY_VHT_CHANNEL_MODE20);
 }
 // A management-TX ROC may use the live social channel 6 table entry on
 // leased PHY 1 while STA PHY 0 and its private address context stay intact.
 {
  ItlIwx h;ieee80211_channel staChan{44,false},initial{1,true};
  setup(h,staChan,initial);auto *sc=&h.com;auto *social6=liveSocial6(h);
  const uint8_t staAddress[6]={0x02,0x11,0x22,0x33,0x44,0x55};
  const uint8_t p2pAddress[6]={0x02,0xaa,0xbb,0xcc,0xdd,0xee};
  std::memcpy(sc->sc_ic.ic_bss->in_ni.ni_macaddr,staAddress,sizeof(staAddress));
  std::memcpy(sc->sc_p2p.mac_address,p2pAddress,sizeof(p2pAddress));
  expectedConfiguration=3;
  assert(h.tahoeP2pRocPrepare(sc,social6,79,3)==0);
  assert(sc->sc_p2p_roc.session_conf_id==3&&sc->sc_p2p_roc.phy_id==1);
  assert(sc->sc_p2p_roc.original_phy_channel==currentChannel(h,initial.channel)&&
         sc->sc_p2p_roc.roc_channel==social6);
  assert(sc->sc_phyctxt[0].channel==currentChannel(h,staChan.channel)&&
         sc->sc_ic.ic_bss->in_ni.ni_chan==currentChannel(h,staChan.channel)&&
         sc->sc_phyctxt[1].channel==social6);
  assert(std::memcmp(sc->sc_ic.ic_bss->in_ni.ni_macaddr,staAddress,6)==0&&
         std::memcmp(sc->sc_p2p.mac_address,p2pAddress,6)==0);
  auto phyRemove=reinterpret_cast<const iwx_phy_context_cmd*>(h.pduPayloads[0].data());
  auto phyAdd=reinterpret_cast<const iwx_phy_context_cmd*>(h.pduPayloads[1].data());
  assert(phyRemove->id_and_color==0x401&&phyRemove->action==IWX_FW_CTXT_ACTION_REMOVE);
  assert(phyAdd->id_and_color==0x401&&phyAdd->action==IWX_FW_CTXT_ACTION_ADD);
  assert(phyAdd->ci.channel==6&&phyAdd->ci.band==IWX_PHY_BAND_24&&
         phyAdd->ci.width==IWX_PHY_VHT_CHANNEL_MODE20&&phyAdd->lmac_id==0);
  assert(h.tahoeP2pRocSubmit(sc,79,2,100,arm,&h)==EBUSY);
  social6->ic_flags|=IEEE80211_CHAN_PASSIVE;
  assert(h.tahoeP2pRocSubmit(sc,79,3,300,arm,&h)==EOPNOTSUPP);
  social6->ic_flags&=~IEEE80211_CHAN_PASSIVE;
  assert(h.tahoeP2pRocSubmit(sc,79,3,300,arm,&h)==EOPNOTSUPP);
  sc->sc_p2p.binding_id=2;
  assert(h.tahoeP2pRocSubmit(sc,79,3,900,arm,&h)==EOPNOTSUPP);
  sc->sc_p2p.binding_id=1;
  sc->sc_phyctxt[1].channel=currentChannel(h,staChan.channel);
  assert(h.tahoeP2pRocSubmit(sc,79,3,900,arm,&h)==EOPNOTSUPP);
  sc->sc_phyctxt[1].channel=social6;
  sc->sc_p2p_roc.phy_id=0;
  assert(h.tahoeP2pRocSubmit(sc,79,3,900,arm,&h)==EOPNOTSUPP);
  sc->sc_p2p_roc.phy_id=1;
  assert(h.tahoeP2pRocSubmit(sc,79,3,901,arm,&h)==EOPNOTSUPP);
  assert(h.armCalls==0&&h.pduSends==2);
  assert(h.tahoeP2pRocSubmit(sc,79,3,900,arm,&h)==0);
  auto session=reinterpret_cast<const iwx_session_prot_cmd*>(h.pduPayloads.back().data());
  assert(session->conf_id==IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION&&
         session->duration_tu==878);
  unsigned beforeCleanup=h.pduSends+h.statusSends;
  assert(h.tahoeP2pRocCleanup(sc,79,3,false)==EBUSY);
  assert(h.pduSends+h.statusSends==beforeCleanup);
  assert(h.tahoeP2pRocCleanup(sc,79,3,true)==0);
  assert(sc->sc_phyctxt[0].channel==currentChannel(h,staChan.channel)&&
         sc->sc_ic.ic_bss->in_ni.ni_chan==currentChannel(h,staChan.channel)&&
         sc->sc_phyctxt[1].channel==currentChannel(h,initial.channel));
  auto restore=reinterpret_cast<const iwx_phy_context_cmd*>(h.pduPayloads.back().data());
  assert(restore->id_and_color==0x401&&restore->action==IWX_FW_CTXT_ACTION_ADD&&
         restore->ci.channel==1&&restore->ci.band==IWX_PHY_BAND_24);
  expectedConfiguration=2;
 }
 // MGMT_TX mode is bound through prepare, tracker arm, firmware command and cleanup.
 {
  ItlIwx h;ieee80211_channel staChan{36,false},initial{1,true};setup(h,staChan,initial);
  auto *sc=&h.com;
  expectedConfiguration=3;
  assert(h.tahoeP2pRocPrepare(sc,currentChannel(h,staChan.channel),78,3)==0);
  assert(sc->sc_p2p_roc.session_conf_id==3);
  assert(h.tahoeP2pRocSubmit(sc,78,2,100,arm,&h)==EBUSY);
  assert(h.pduSends==2&&h.armCalls==0);
  assert(h.tahoeP2pRocSubmit(sc,78,3,900,arm,&h)==EOPNOTSUPP);
  assert(h.pduSends==2&&h.armCalls==0); // 900ms is restricted to live channel 6.
  assert(h.tahoeP2pRocSubmit(sc,78,3,100,arm,&h)==0&&h.armCalls==1);
  auto session=reinterpret_cast<const iwx_session_prot_cmd*>(h.pduPayloads.back().data());
  assert(session->conf_id==IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION);
  assert(session->duration_tu==97);
  unsigned before=h.pduSends+h.statusSends;
  assert(h.tahoeP2pRocCleanup(sc,78,2,true)==EBUSY);
  assert(h.pduSends+h.statusSends==before);
  assert(h.tahoeP2pRocCleanup(sc,78,3,true)==0);
  expectedConfiguration=2;
 }
 // Rejecting the tracker arm sends no firmware command.
 {
  ItlIwx h;ieee80211_channel staChan{36,false},initial{1,true};setup(h,staChan,initial);
  auto *sc=&h.com;assert(h.tahoeP2pRocPrepare(sc,currentChannel(h,staChan.channel),5,2)==0);
  assert(h.tahoeP2pRocSubmit(sc,5,2,100,rejectArm,nullptr)==ECANCELED);
  assert(h.pduSends==2&&h.statusSends==1&&sc->sc_p2p_roc.phase==IWX_P2P_ROC_PREPARED);
 }
 // A PHY REMOVE or ADD timeout is ambiguous and retains the lease.
 for(int failAt: {1,2}) {
  ItlIwx h;ieee80211_channel staChan{36,false},initial{1,true};setup(h,staChan,initial);
  h.pduFailAt=failAt;auto *sc=&h.com;
  assert(h.tahoeP2pRocPrepare(sc,currentChannel(h,staChan.channel),9,2)==ETIMEDOUT);
  assert(sc->sc_p2p_roc.phase==IWX_P2P_ROC_QUARANTINED&&sc->sc_p2p.phy_leased);
  assert(sc->sc_p2p.binding_state==IWX_P2P_RESOURCE_ABSENT&&h.statusSends==0);
  sc->sc_generation=8;assert(h.iwx_p2p_context_reset_after_fw_reset(sc,8)==EBUSY);
 }
 // A valid nonzero binding status is a rejection; unwind only known resources.
 {
  ItlIwx h;ieee80211_channel staChan{36,false},initial{1,true};setup(h,staChan,initial);
  h.status=1;auto *sc=&h.com;
  assert(h.tahoeP2pRocPrepare(sc,currentChannel(h,staChan.channel),11,2)==EIO);
  assert(sc->sc_p2p_roc.binding_rejected&&sc->sc_p2p_roc.binding_status_valid);
  assert(sc->sc_p2p_roc.phase==IWX_P2P_ROC_COMPLETE&&!sc->sc_p2p.phy_leased);
  assert(sc->sc_p2p.binding_state==IWX_P2P_RESOURCE_ABSENT&&
         sc->sc_phyctxt[1].channel==currentChannel(h,initial.channel));
  assert(h.pduSends==4&&h.statusSends==1);
 }
 // A transport timeout while adding/removing a binding stays unknown; no
 // speculative PHY/MAC teardown follows.
 {
  ItlIwx h;ieee80211_channel staChan{36,false},initial{1,true};setup(h,staChan,initial);
  h.statusResult=ETIMEDOUT;auto *sc=&h.com;
  assert(h.tahoeP2pRocPrepare(sc,currentChannel(h,staChan.channel),12,2)==ETIMEDOUT);
  assert(sc->sc_p2p_roc.phase==IWX_P2P_ROC_QUARANTINED);
  assert(sc->sc_p2p.binding_state==IWX_P2P_RESOURCE_UNKNOWN&&sc->sc_p2p.phy_leased);
  assert(h.pduSends==2&&h.statusSends==1);
 }
 // Cleanup's binding failure stops before any PHY restore.
 {
  ItlIwx h;ieee80211_channel staChan{36,false},initial{1,true};setup(h,staChan,initial);
  auto *sc=&h.com;assert(h.tahoeP2pRocPrepare(sc,currentChannel(h,staChan.channel),13,2)==0);
  assert(h.tahoeP2pRocSubmit(sc,13,2,100,arm,&h)==0);
  h.statusResult=ETIMEDOUT;unsigned pduBefore=h.pduSends;
  assert(h.tahoeP2pRocCleanup(sc,13,2,true)==ETIMEDOUT);
  assert(sc->sc_p2p_roc.phase==IWX_P2P_ROC_QUARANTINED);
  assert(sc->sc_p2p.binding_state==IWX_P2P_RESOURCE_UNKNOWN);
  assert(sc->sc_p2p.phy_leased&&h.pduSends==pduBefore);
 }
 // Session command transport error does not authorize teardown without END.
 {
  ItlIwx h;ieee80211_channel staChan{36,false},initial{1,true};setup(h,staChan,initial);
  auto *sc=&h.com;assert(h.tahoeP2pRocPrepare(sc,currentChannel(h,staChan.channel),14,2)==0);
  h.pduFailAt=3;
  assert(h.tahoeP2pRocSubmit(sc,14,2,100,arm,&h)==ETIMEDOUT);
  assert(sc->sc_p2p_roc.phase==IWX_P2P_ROC_SESSION_SUBMIT_UNKNOWN);
  unsigned before=h.pduSends+h.statusSends;
  assert(h.tahoeP2pRocCleanup(sc,14,2,false)==EBUSY&&h.pduSends+h.statusSends==before);
  assert(h.tahoeP2pRocCleanup(sc,14,2,true)==0); // END can resolve a timed-out ACK.
 }
 // Channel 6 is accepted only as the exact, active, non-DFS 2437 MHz entry
 // from the current interface table, whether same-channel or off-channel.
 {
  ItlIwx h;ieee80211_channel staChan{36,false},other{40,false},initial{1,true};setup(h,staChan,initial);
  assert(h.tahoeP2pRocPrepare(&h.com,&other,15,2)==EOPNOTSUPP&&h.pduSends==0);
  assert(h.tahoeP2pRocPrepare(&h.com,currentChannel(h,staChan.channel),15,99)==EOPNOTSUPP&&h.pduSends==0);
  auto *social6=liveSocial6(h);
  ieee80211_channel fakeSocial6{6,true};
  assert(h.tahoeP2pRocPrepare(&h.com,&fakeSocial6,15,3)==EOPNOTSUPP&&h.pduSends==0);
  social6->ic_flags|=IEEE80211_CHAN_PASSIVE;
  assert(h.tahoeP2pRocPrepare(&h.com,social6,15,3)==EOPNOTSUPP&&h.pduSends==0);
  *social6=ieee80211_channel{6,true};social6->ic_flags|=IEEE80211_CHAN_DFS;
  assert(h.tahoeP2pRocPrepare(&h.com,social6,15,3)==EOPNOTSUPP&&h.pduSends==0);
  *social6=ieee80211_channel{6,true};social6->ic_freq=0;
  assert(h.tahoeP2pRocPrepare(&h.com,social6,15,3)==EOPNOTSUPP&&h.pduSends==0);
  *social6=ieee80211_channel{6,true};social6->ic_flags=0;
  assert(h.tahoeP2pRocPrepare(&h.com,social6,15,3)==EOPNOTSUPP&&h.pduSends==0);
  *social6=ieee80211_channel{6,true};social6->is2g=false;
  assert(h.tahoeP2pRocPrepare(&h.com,social6,15,3)==EOPNOTSUPP&&h.pduSends==0);
  ieee80211_channel channel11{11,true};
  assert(h.tahoeP2pRocPrepare(&h.com,&channel11,15,2)==EOPNOTSUPP&&h.pduSends==0);
  h.com.sc_phyctxt[0].channel=&other;
  *social6=ieee80211_channel{6,true};
  assert(h.tahoeP2pRocPrepare(&h.com,social6,15,2)==EBUSY&&h.pduSends==0);
  h.com.sc_phyctxt[0].channel=currentChannel(h,staChan.channel);
  h.sessionNotif=1;
  assert(h.tahoeP2pRocPrepare(&h.com,currentChannel(h,staChan.channel),16,2)==EOPNOTSUPP&&h.pduSends==0);
 }
 // A same-channel channel-6 request cannot bypass the regulatory table guard.
 {
  ItlIwx h;ieee80211_channel initial{1,true};
  auto *social6=liveSocial6(h);setup(h,*social6,initial);
  social6->ic_flags|=IEEE80211_CHAN_PASSIVE;
  assert(h.tahoeP2pRocPrepare(&h.com,social6,17,3)==EOPNOTSUPP&&h.pduSends==0);
 }
 // A same-channel channel-6 ROC still works when it uses the live legal entry.
 {
  ItlIwx h;ieee80211_channel initial{1,true};
  auto *social6=liveSocial6(h);setup(h,*social6,initial);expectedConfiguration=2;
  assert(h.tahoeP2pRocPrepare(&h.com,social6,18,2)==0);
  assert(h.tahoeP2pRocSubmit(&h.com,18,2,300,arm,&h)==EOPNOTSUPP);
  assert(h.tahoeP2pRocSubmit(&h.com,18,2,900,arm,&h)==EOPNOTSUPP);
  assert(h.pduSends==2&&h.armCalls==0); // Discovery conf2 stays at 100ms.
  assert(h.tahoeP2pRocSubmit(&h.com,18,2,100,arm,&h)==0);
  unsigned beforeCleanup=h.pduSends+h.statusSends;
  assert(h.tahoeP2pRocCleanup(&h.com,18,2,false)==EBUSY);
  assert(h.pduSends+h.statusSends==beforeCleanup);
  assert(h.tahoeP2pRocCleanup(&h.com,18,2,true)==0);
  expectedConfiguration=2;
 }
 // Even a fake channel-6 object is rejected when STA and target pointers match.
 {
  ItlIwx h;ieee80211_channel fakeSocial6{6,true},initial{1,true};setup(h,fakeSocial6,initial);
  h.com.sc_ic.ic_bss->in_ni.ni_chan=&fakeSocial6;
  h.com.sc_phyctxt[0].channel=&fakeSocial6;
  const unsigned lookupsBefore=channelLookupCalls;
  assert(h.tahoeP2pRocPrepare(&h.com,&fakeSocial6,19,3)==EOPNOTSUPP&&h.pduSends==0);
  assert(channelLookupCalls==lookupsBefore);
 }

 // No session was ever submitted: a verified no-TX cleanup may restore the
 // prepared PHY/binding without fabricating an END notification.
 {
  ItlIwx h;ieee80211_channel staChan{36,false},initial{1,true};setup(h,staChan,initial);
  assert(h.tahoeP2pRocPrepare(&h.com,liveSocial6(h),81,3)==0);
  const auto before=h.pduSends+h.statusSends;
  assert(h.tahoeP2pRocAbortPrepared(&h.com,81,3,false)==EBUSY);
  assert(h.tahoeP2pRocAbortPrepared(&h.com,82,3,true)==EBUSY);
  assert(h.tahoeP2pRocAbortPrepared(&h.com,81,2,true)==EBUSY);
  assert(h.pduSends+h.statusSends==before);
  assert(h.tahoeP2pRocAbortPrepared(&h.com,81,3,true)==0);
  assert(h.com.sc_p2p.binding_state==IWX_P2P_RESOURCE_ABSENT&&!h.com.sc_p2p.phy_leased);
  assert(h.com.sc_p2p_roc.phase==IWX_P2P_ROC_COMPLETE);
  assert(h.com.sc_phyctxt[1].channel==currentChannel(h,1));
 }
 for(unsigned rejection=0;rejection<4;++rejection) {
  ItlIwx h;ieee80211_channel staChan{36,false},initial{1,true};setup(h,staChan,initial);
  assert(h.tahoeP2pRocPrepare(&h.com,liveSocial6(h),83,3)==0);
  if(rejection==0)h.com.sc_p2p_roc.session_submit_seen=1;
  if(rejection==1)h.com.sc_p2p_roc.session_submit_result=ETIMEDOUT;
  if(rejection==2)h.com.sc_p2p_roc.phase=IWX_P2P_ROC_SESSION_SUBMIT_UNKNOWN;
  if(rejection==3)++h.com.sc_generation;
  const auto before=h.pduSends+h.statusSends;
  assert(h.tahoeP2pRocAbortPrepared(&h.com,83,3,true)==EBUSY);
  assert(h.pduSends+h.statusSends==before);
 }
 for(unsigned failure=0;failure<3;++failure) {
  ItlIwx h;ieee80211_channel staChan{36,false},initial{1,true};setup(h,staChan,initial);
  assert(h.tahoeP2pRocPrepare(&h.com,liveSocial6(h),84,3)==0);
  if(failure==0)h.statusResult=ETIMEDOUT;
  else h.pduFailAt=h.pduSends+failure;
  assert(h.tahoeP2pRocAbortPrepared(&h.com,84,3,true)==ETIMEDOUT);
  assert(h.com.sc_p2p_roc.phase==IWX_P2P_ROC_QUARANTINED);
  assert(h.com.sc_p2p.phy_leased);
 }
}
"""

shim = shim.replace("#define AIRPORT_TAHOE 1", "#define AIRPORT_TAHOE 1\n#include <initializer_list>")

with tempfile.TemporaryDirectory(prefix="itlwm-p2p-roc-hal-") as directory:
    cpp = Path(directory) / "p2p_roc_hal_test.cpp"
    exe = Path(directory) / "p2p_roc_hal_test"
    cpp.write_text(shim + "\n" + actual + "\n" + body)
    subprocess.run([
        "xcrun", "clang++", "-std=c++14", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-Wno-sign-compare",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        str(cpp), "-o", str(exe),
    ], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: production Tahoe ROC PHY/binding/session HAL and fault paths")
