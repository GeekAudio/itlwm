#!/usr/bin/env python3
"""Fault-inject the production P2P HAL command methods through fake transport."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
edca_source = (root / "itl80211/openbsd/net80211/ieee80211_output.c").read_text()


def extract(marker):
    start = source.index(marker)
    opening = source.index("{", start)
    end, depth = opening + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def extract_braced_declaration(text, marker):
    start = text.index(marker)
    opening = text.index("{", start)
    end, depth = opening + 1, 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    while text[end].isspace():
        end += 1
    if text[end] == ";":
        end += 1
    return text[start:end]


production_fifo_map = extract_braced_declaration(
    source, "const uint8_t iwx_ac_to_tx_fifo[] = {"
)
production_edca_table = extract_braced_declaration(
    edca_source,
    "const struct ieee80211_edca_ac_params\n    ieee80211_edca_table[",
)


shim = r"""
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#define AIRPORT_TAHOE 1
#define htole32(x) (uint32_t)(x)
#define htole16(x) (uint16_t)(x)
enum {
 IWX_UCODE_TLV_FLAGS_P2P=1<<3, IWX_LONG_GROUP=1,
 IWX_UCODE_TLV_CAPA_BINDING_CDB_SUPPORT=39, IWX_UCODE_TLV_CAPA_CDB_SUPPORT=40,
 IWX_MAC_CONTEXT_CMD=0x28, IWX_BINDING_CONTEXT_CMD=0x2b,
 IWX_FW_MAC_TYPE_P2P_DEVICE=6, IWX_TSF_ID_A=0, IWX_NUM_TSF_IDS=4,
 IWX_MAC_INDEX_MIN_DRIVER=0, IWX_MAC_INDEX_AUX=4,
 IWX_FW_CTXT_ACTION_ADD=1, IWX_FW_CTXT_ACTION_MODIFY=2,
 IWX_FW_CTXT_ACTION_REMOVE=3, IWX_MAC_FILTER_IN_PROMISC=1<<0,
 IWX_MAC_FILTER_IN_CONTROL_AND_MGMT=1<<1,
 IWX_MAC_FILTER_ACCEPT_GRP=1<<2,
 IWX_MAC_FILTER_IN_PROBE_REQUEST=1<<12,
 IWX_NUM_PHY_CTX=3, IWX_MAX_MACS_IN_BINDING=3,
 IWX_FW_CTXT_INVALID=0xffffffff, IWX_MAC_INDEX_AUX_UNUSED=0,
 IWX_P2P_RESOURCE_ABSENT=0, IWX_P2P_RESOURCE_ACTIVE=1,
 IWX_P2P_RESOURCE_UNKNOWN=2, IWX_P2P_UNCERTAIN_NONE=0,
 IWX_P2P_UNCERTAIN_MAC_CONTEXT=1,
 IWX_P2P_UNCERTAIN_BINDING=2,
 IWX_P2P_ROC_IDLE=0, IWX_P2P_ROC_PHY_REMOVE_UNKNOWN,
 IWX_P2P_ROC_PHY_REMOVED, IWX_P2P_ROC_PHY_ADD_UNKNOWN,
 IWX_P2P_ROC_PHY_READY, IWX_P2P_ROC_BINDING_ADD_UNKNOWN,
 IWX_P2P_ROC_PREPARED, IWX_P2P_ROC_SESSION_SUBMIT_UNKNOWN,
 IWX_P2P_ROC_SESSION_ACKED, IWX_P2P_ROC_END_CONFIRMED,
 IWX_P2P_ROC_BINDING_REMOVE_UNKNOWN, IWX_P2P_ROC_PHY_RESTORE_REMOVE_UNKNOWN,
 IWX_P2P_ROC_PHY_RESTORE_ADD_UNKNOWN, IWX_P2P_ROC_COMPLETE,
 IWX_P2P_ROC_QUARANTINED,
 IWX_AC_BK=0, IWX_AC_BE=1, IWX_AC_VI=2, IWX_AC_VO=3, IWX_AC_NUM=4,
 IWX_GEN2_TX_FIFO_CMD=0, IWX_GEN2_EDCA_TX_FIFO_BK=1,
 IWX_GEN2_EDCA_TX_FIFO_BE=2, IWX_GEN2_EDCA_TX_FIFO_VI=3,
 IWX_GEN2_EDCA_TX_FIFO_VO=4,
 EDCA_AC_BE=0, EDCA_AC_BK=1, EDCA_AC_VI=2, EDCA_AC_VO=3,
 EDCA_NUM_AC=4, IEEE80211_MODE_11A=1, IEEE80211_MODE_11B=2,
 IEEE80211_MODE_11G=3, IEEE80211_MODE_11N=4, IEEE80211_MODE_11AC=5,
 IEEE80211_MODE_11AX=6, IEEE80211_MODE_MAX=7
};
enum { IWX_RATE_1M_INDEX=0,IWX_RATE_2M_INDEX=1,IWX_RATE_5M_INDEX=2,
       IWX_RATE_11M_INDEX=3,IWX_FIRST_CCK_RATE=0,IWX_RATE_6M_INDEX=4,
       IWX_RATE_12M_INDEX=6,IWX_RATE_24M_INDEX=8,IWX_FIRST_OFDM_RATE=4 };
#define IWX_RATE_BIT_MSK(r) (1 << IWX_RATE_##r##M_INDEX)
#define IWX_FW_CMD_ID_AND_COLOR(id,color) ((id) | ((color) << 8))
#define isset(bits,bit) (((bits)[(bit)/8] & (1U<<((bit)%8))) != 0)
struct iwx_p2p_context {
 uint8_t initialized=0,mac_state=0,binding_state=0,phy_leased=0;
 uint8_t mac_id=0,mac_color=0,tsf_id=0,phy_id=0,phy_color=0;
 uint8_t binding_id=0,binding_color=0,uncertain_kind=0,uncertain_action=0;
 uint8_t mac_address[6]{};uint32_t fw_generation=0;
};
struct iwx_p2p_roc_state {
 uint32_t token=0,fw_generation=0;int32_t session_submit_result=0;
 uint32_t binding_raw_status=0;uint8_t phase=0,phy_id=0,phy_color=0;
 uint8_t session_submit_seen=0,binding_status_valid=0,binding_rejected=0;
 void *original_phy_channel=nullptr,*roc_channel=nullptr;
};
struct iwx_ac_qos {uint16_t cw_min,cw_max;uint8_t aifsn,fifos_mask;uint16_t edca_txop;} __attribute__((packed));
struct ieee80211_edca_ac_params {
 uint8_t ac_ecwmin,ac_ecwmax,ac_aifsn;uint16_t ac_txoplimit;uint8_t ac_acm;
};
struct iwx_mac_data_p2p_dev {uint32_t is_disc_extended;} __attribute__((packed));
struct iwx_mac_ctx_cmd {
 uint32_t id_and_color,action,mac_type,tsf_id;
 uint8_t node_addr[6];uint16_t reserved_for_node_addr;
 uint8_t bssid_addr[6];uint16_t reserved_for_bssid_addr;
 uint32_t cck_rates,ofdm_rates,protection_flags,cck_short_preamble,
          short_slot,filter_flags,qos_flags;
 iwx_ac_qos ac[5];
 union {uint8_t payload[44]; iwx_mac_data_p2p_dev p2p_dev;};
} __attribute__((packed));
struct iwx_binding_cmd {
 uint32_t id_and_color,action,macs[3],phy,lmac_id;
} __attribute__((packed));
struct ieee80211_channel {uint32_t marker=0;};
struct iwx_phy_ctxt {uint16_t id=0,color=0;uint32_t ref=0;ieee80211_channel *channel=nullptr;};
struct iwx_softc {
 int sc_capaflags=IWX_UCODE_TLV_FLAGS_P2P,sc_generation=7;
 uint8_t sc_enabled_capa[8]{};
 iwx_p2p_context sc_p2p{};iwx_p2p_roc_state sc_p2p_roc{};
 iwx_phy_ctxt sc_phyctxt[IWX_NUM_PHY_CTX]{};
};
static_assert(sizeof(iwx_mac_ctx_cmd)==144,"MAC_CONTEXT_CMD v1 ABI size");
static_assert(sizeof(iwx_binding_cmd)==28,"BINDING_CONTEXT_CMD v2 ABI size");
struct ItlIwx {
 iwx_softc com{};bool allowed=true;uint8_t macVer=5,bindVer=2,bindNotif=1;
 int pduResult=0,statusResult=0;uint32_t status=0;
 unsigned pduSends=0,statusSends=0;uint32_t lastId=0,lastFlags=0;
 uint16_t lastLen=0;uint8_t payload[256]{};uint32_t phyChannel=0;
 bool nativeP2pCommandAllowed() const {return allowed;}
 uint8_t iwx_lookup_cmd_ver(iwx_softc*,uint8_t,uint8_t cmd){return cmd==IWX_MAC_CONTEXT_CMD?macVer:bindVer;}
 uint8_t iwx_lookup_notif_ver(iwx_softc*,uint8_t,uint8_t){return bindNotif;}
 int iwx_p2p_mac_context_configure(iwx_softc*,uint8_t,uint8_t,uint8_t,const uint8_t*);
 int iwx_p2p_mac_context_apply(iwx_softc*,uint32_t);
 int iwx_p2p_mac_context_add(iwx_softc*);
 int iwx_p2p_mac_context_modify(iwx_softc*);
 int iwx_p2p_mac_context_remove(iwx_softc*);
 int iwx_p2p_phy_lease(iwx_softc*,uint8_t*);
 int iwx_p2p_phy_release(iwx_softc*);
 int iwx_p2p_binding_add(iwx_softc*);
 int iwx_p2p_binding_remove(iwx_softc*);
 int iwx_p2p_context_reset_after_fw_reset(iwx_softc*,uint32_t);
 int iwx_lmac_id(iwx_softc*,ieee80211_channel *c){return c?int(c->marker):EINVAL;}
 int iwx_send_cmd_pdu(iwx_softc*,uint32_t id,uint32_t flags,uint16_t len,const void *p){
  ++pduSends;lastId=id;lastFlags=flags;lastLen=len;std::memset(payload,0,sizeof(payload));std::memcpy(payload,p,len);return pduResult;
 }
 int iwx_send_cmd_pdu_status(iwx_softc*,uint32_t id,uint16_t len,const void *p,uint32_t *out){
  ++statusSends;lastId=id;lastFlags=0;lastLen=len;std::memset(payload,0,sizeof(payload));std::memcpy(payload,p,len);*out=status;return statusResult;
 }
};
"""

production_definitions = "\n".join([
    production_fifo_map,
    production_edca_table,
])

markers = [
    "static int\niwx_p2p_check_fw_contract(ItlIwx *owner",
    "static void\niwx_p2p_fill_mac_context(const struct iwx_p2p_context",
    "int ItlIwx::\niwx_p2p_mac_context_configure(",
    "int ItlIwx::\niwx_p2p_mac_context_apply(",
    "int ItlIwx::\niwx_p2p_mac_context_add(",
    "int ItlIwx::\niwx_p2p_mac_context_modify(",
    "int ItlIwx::\niwx_p2p_mac_context_remove(",
    "int ItlIwx::\niwx_p2p_phy_lease(",
    "int ItlIwx::\niwx_p2p_phy_release(",
    "int ItlIwx::\niwx_p2p_binding_add(",
    "int ItlIwx::\niwx_p2p_binding_remove(",
    "int ItlIwx::\niwx_p2p_context_reset_after_fw_reset(",
]

body = r"""
int main() {
 const uint8_t addr[6]={0x02,0x11,0x22,0x33,0x44,0x55};
 {
  ItlIwx h;auto *sc=&h.com;
  assert(h.iwx_p2p_mac_context_configure(sc,0,0,1,addr)==EINVAL);
  assert(h.iwx_p2p_mac_context_configure(sc,1,0,1,nullptr)==EINVAL);
  uint8_t mcast[6]={0x01,1,2,3,4,5};
  assert(h.iwx_p2p_mac_context_configure(sc,1,0,1,mcast)==EINVAL);
  sc->sc_capaflags=0;assert(h.iwx_p2p_mac_context_configure(sc,1,0,1,addr)==EOPNOTSUPP);
  sc->sc_capaflags=IWX_UCODE_TLV_FLAGS_P2P;h.macVer=4;
  assert(h.iwx_p2p_mac_context_configure(sc,1,0,1,addr)==EOPNOTSUPP);
  h.macVer=5;h.allowed=false;
  assert(h.iwx_p2p_mac_context_configure(sc,1,0,1,addr)==EBUSY&&!sc->sc_p2p.initialized);
  h.allowed=true;assert(h.iwx_p2p_mac_context_configure(sc,1,2,1,addr)==0);
  assert(h.iwx_p2p_mac_context_add(sc)==0&&h.pduSends==1);
  assert(h.lastId==IWX_MAC_CONTEXT_CMD&&h.lastFlags==0&&h.lastLen==144);
  auto *m=reinterpret_cast<const iwx_mac_ctx_cmd*>(h.payload);
  assert(m->id_and_color==0x201&&m->action==IWX_FW_CTXT_ACTION_ADD);
  assert(m->mac_type==IWX_FW_MAC_TYPE_P2P_DEVICE&&m->tsf_id==1);
  assert(std::memcmp(m->node_addr,addr,6)==0);
  for(unsigned i=0;i<6;i++)assert(m->bssid_addr[i]==0xff);
  assert(m->cck_rates==0x0f&&m->ofdm_rates==0x15);
  const uint32_t expectedRxFilters=IWX_MAC_FILTER_IN_PROBE_REQUEST |
      IWX_MAC_FILTER_IN_CONTROL_AND_MGMT | IWX_MAC_FILTER_ACCEPT_GRP;
  assert(m->filter_flags==expectedRxFilters);
  assert(!(m->filter_flags&IWX_MAC_FILTER_IN_PROMISC));
  for(uint8_t macId=2;macId<=3;++macId) {
   iwx_p2p_context other{};other.mac_id=macId;other.mac_color=2;other.tsf_id=1;
   iwx_mac_ctx_cmd otherCmd{};
   iwx_p2p_fill_mac_context(&other,IWX_FW_CTXT_ACTION_ADD,&otherCmd);
   assert(otherCmd.filter_flags==IWX_MAC_FILTER_IN_PROBE_REQUEST);
  }
  assert(m->p2p_dev.is_disc_extended==0);
  // The former zero-only P2P fill left every AC without a TX FIFO mapping.
  iwx_mac_ctx_cmd zero_only{};
  for(unsigned i=0;i<IWX_AC_NUM+1;i++) assert(zero_only.ac[i].fifos_mask==0);
  const uint8_t macToUcode[EDCA_NUM_AC]={IWX_AC_BE,IWX_AC_BK,IWX_AC_VI,IWX_AC_VO};
  const uint8_t expectedFifoMasks[EDCA_NUM_AC]={4,2,8,16};
  const struct ieee80211_edca_ac_params *defaults=
      ieee80211_edca_table[IEEE80211_MODE_11G];
  for(unsigned i=0;i<EDCA_NUM_AC;i++) {
   const auto &d=defaults[i];const auto &actual=m->ac[macToUcode[i]];
   assert(actual.cw_min==((1U<<d.ac_ecwmin)-1U));
   assert(actual.cw_max==((1U<<d.ac_ecwmax)-1U));
   assert(actual.aifsn==d.ac_aifsn);
   assert(actual.edca_txop==(d.ac_txoplimit*32U));
   assert(actual.fifos_mask==expectedFifoMasks[i]);
  }
  assert(m->ac[IWX_AC_BK].cw_min==15&&m->ac[IWX_AC_BK].cw_max==1023);
  assert(m->ac[IWX_AC_BE].cw_min==15&&m->ac[IWX_AC_BE].cw_max==1023);
  assert(m->ac[IWX_AC_VI].cw_min==7&&m->ac[IWX_AC_VI].cw_max==15);
  assert(m->ac[IWX_AC_VI].edca_txop==3008);
  assert(m->ac[IWX_AC_VO].cw_min==3&&m->ac[IWX_AC_VO].cw_max==7);
  assert(m->ac[IWX_AC_VO].edca_txop==1504);
  assert(m->qos_flags==0);
  assert(h.iwx_p2p_mac_context_add(sc)==EALREADY&&h.pduSends==1);
  assert(h.iwx_p2p_mac_context_modify(sc)==0&&h.pduSends==2);
  m=reinterpret_cast<const iwx_mac_ctx_cmd*>(h.payload);
  assert(m->action==IWX_FW_CTXT_ACTION_MODIFY&&m->id_and_color==0x201);
  assert(h.iwx_p2p_mac_context_remove(sc)==0&&h.pduSends==3);
  m=reinterpret_cast<const iwx_mac_ctx_cmd*>(h.payload);
  assert(m->action==IWX_FW_CTXT_ACTION_REMOVE&&m->id_and_color==0x201);
  const uint8_t *removeBytes=reinterpret_cast<const uint8_t*>(m);
  for(size_t i=sizeof(uint32_t)*2;i<sizeof(*m);i++) assert(removeBytes[i]==0);
 }
 {
  ItlIwx h;auto *sc=&h.com;assert(h.iwx_p2p_mac_context_configure(sc,1,0,1,addr)==0);
  h.pduResult=ETIMEDOUT;assert(h.iwx_p2p_mac_context_add(sc)==ETIMEDOUT);
  assert(sc->sc_p2p.mac_state==IWX_P2P_RESOURCE_UNKNOWN);
  auto sends=h.pduSends;assert(h.iwx_p2p_mac_context_remove(sc)==EBUSY&&h.pduSends==sends);
  assert(h.iwx_p2p_context_reset_after_fw_reset(sc,7)==EBUSY);
  sc->sc_generation=8;assert(h.iwx_p2p_context_reset_after_fw_reset(sc,7)==EBUSY);
  assert(h.iwx_p2p_context_reset_after_fw_reset(sc,8)==0&&!sc->sc_p2p.initialized);
 }
 {
  ItlIwx h;auto *sc=&h.com;assert(h.iwx_p2p_mac_context_configure(sc,1,3,1,addr)==0);
  assert(h.iwx_p2p_mac_context_add(sc)==0);
  sc->sc_phyctxt[1].id=1;sc->sc_phyctxt[1].color=4;
  sc->sc_enabled_capa[IWX_UCODE_TLV_CAPA_BINDING_CDB_SUPPORT/8] |=
      1U<<(IWX_UCODE_TLV_CAPA_BINDING_CDB_SUPPORT%8);
  sc->sc_enabled_capa[IWX_UCODE_TLV_CAPA_CDB_SUPPORT/8] |=
      1U<<(IWX_UCODE_TLV_CAPA_CDB_SUPPORT%8);
  ieee80211_channel channel;channel.marker=1;sc->sc_phyctxt[1].channel=&channel;
  uint8_t slot=0xff;assert(h.iwx_p2p_phy_lease(sc,&slot)==0&&slot==1);
  assert(h.pduSends==1&&h.statusSends==0);
  assert(h.iwx_p2p_binding_add(sc)==0&&h.statusSends==1);
  assert(h.lastId==IWX_BINDING_CONTEXT_CMD&&h.lastLen==28);
  auto *b=reinterpret_cast<const iwx_binding_cmd*>(h.payload);
  assert(b->id_and_color==0x401&&b->action==IWX_FW_CTXT_ACTION_ADD);
  assert(b->macs[0]==0x301&&b->macs[1]==IWX_FW_CTXT_INVALID&&b->macs[2]==IWX_FW_CTXT_INVALID);
  assert(b->phy==0x401&&b->lmac_id==1);
  h.status=1;assert(h.iwx_p2p_binding_remove(sc)==EIO);
  assert(sc->sc_p2p.binding_state==IWX_P2P_RESOURCE_UNKNOWN);
  assert(h.iwx_p2p_phy_release(sc)==EBUSY);
  auto sends=h.statusSends;assert(h.iwx_p2p_binding_remove(sc)==EBUSY&&h.statusSends==sends);
  sc->sc_generation=8;assert(h.iwx_p2p_context_reset_after_fw_reset(sc,8)==0);
 }
 {
  ItlIwx h;auto *sc=&h.com;assert(h.iwx_p2p_mac_context_configure(sc,1,0,1,addr)==0);
  assert(h.iwx_p2p_mac_context_add(sc)==0);sc->sc_phyctxt[1].id=1;
  ieee80211_channel channel;channel.marker=1;sc->sc_phyctxt[1].channel=&channel;
  uint8_t slot=0;assert(h.iwx_p2p_phy_lease(sc,&slot)==0);
  assert(h.iwx_p2p_binding_add(sc)==0&&h.lastLen==24);
  auto *b=reinterpret_cast<const iwx_binding_cmd*>(h.payload);
  assert(b->lmac_id==0);
 }
 {
  ItlIwx h;auto *sc=&h.com;assert(h.iwx_p2p_mac_context_configure(sc,1,0,1,addr)==0);
  h.bindNotif=0;assert(h.iwx_p2p_mac_context_add(sc)==0);
  sc->sc_phyctxt[1].id=1;ieee80211_channel channel;sc->sc_phyctxt[1].channel=&channel;
  uint8_t slot=0;assert(h.iwx_p2p_phy_lease(sc,&slot)==0);
  assert(h.iwx_p2p_binding_add(sc)==EOPNOTSUPP&&h.statusSends==0);
  h.allowed=false;assert(h.iwx_p2p_mac_context_remove(sc)==EBUSY&&h.pduSends==1);
 }
}
"""

with tempfile.TemporaryDirectory(prefix="itlwm-p2p-hal-") as directory:
    cpp = Path(directory) / "p2p_hal_test.cpp"
    exe = Path(directory) / "p2p_hal_test"
    cpp.write_text(shim + "\n" + production_definitions + "\n" +
                   "\n".join(extract(marker) for marker in markers) + body)
    subprocess.run([
        "xcrun", "clang++", "-std=c++14", "-O1", "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer", str(cpp), "-o", str(exe)
    ], check=True)
    subprocess.run([str(exe)], check=True)
    print("PASS: isolated P2P HAL command ABI and fault paths")
