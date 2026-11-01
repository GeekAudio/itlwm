#!/usr/bin/env python3
"""Host-only regression for SESSION_PROTECTION cancellation after MAC cleanup.

Reads the current checkout. Four real functions are extracted into a temporary
C++ translation unit and run against injected transport results. No source is
written, no saved system observations are read, and no kernel/firmware/device
is contacted. Temporary baseline is produced by removing only this guard.
It demonstrates a reachable host lifecycle defect; it does not prove a
particular firmware crash was caused by it, or simulate firmware execution.

Run: python3 native/tests/test_session_protection_mac_guard.py
Override source checkout for an isolated run: ITLWM_SOURCE_ROOT=/path/to/repo
"""
from pathlib import Path
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import unittest

PREAMBLE = r'''
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#define AIRPORT_TAHOE 1
#define XYLog(...) ((void)0)
#define DPRINTFN(...) ((void)0)
#define DEVNAME(sc) "offline"
#define splassert(...) ((void)0)
#define isset(a,b) ((a)[b])
#define htole32(a) (uint32_t(a))
#define IWX_FW_CMD_ID_AND_COLOR(a,b) ((a)|((b)<<8))
#define IEEE80211_ADDR_COPY(a,b) std::memcpy((a),(b),6)
#define __packed __attribute__((packed))
constexpr int IEEE80211_CHAN_WIDTH_20_NOHT=0,IEEE80211_M_MONITOR=6,IEEE80211_M_STA=1,IEEE80211_DUR_TU=2000;
constexpr uint32_t IEEE80211_NODE_HT=1,IEEE80211_NODE_QOS=2,IEEE80211_NODE_HT_SGI20=4,IEEE80211_NODE_HT_SGI40=8,IEEE80211_NODE_VHT=16,IEEE80211_NODE_VHT_SGI80=32,IEEE80211_NODE_VHT_SGI160=64,IEEE80211_NODE_HE=128;
struct ieee80211_channel{};struct iwx_phy_ctxt{};
struct ieee80211_node{int ni_chw{};uint32_t ni_flags{};ieee80211_channel*ni_chan{};uint8_t ni_macaddr[6]{};uint32_t ni_intval=100;};
struct iwx_node{ieee80211_node in_ni;uint32_t in_id=0,in_color=0;iwx_phy_ctxt*in_phyctxt{};uint8_t in_macaddr[6]{};};
struct ieee80211com{ieee80211_node*ic_bss{};int ic_opmode=IEEE80211_M_STA;ieee80211_channel*ic_ibss_chan{};ieee80211_channel ic_channels[2];};
struct iwx_softc{ieee80211com sc_ic;iwx_node node;int sc_generation=11;uint32_t sc_flags=0;bool sc_enabled_capa[128]{};iwx_phy_ctxt sc_phyctxt[1];struct {uint32_t ring_count=256;}txq[4];
 bool fw_mac=false,ambiguous_remove=false;unsigned fw_asserts=0;std::string fail;int failure=35;std::vector<std::string>calls;std::vector<int>returns;uint32_t duration_seen=0,conf_seen=99;
 iwx_softc(){sc_ic.ic_bss=&node.in_ni;sc_enabled_capa[IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD]=true;}
 int op(const std::string&s){calls.push_back(s);return fail==s?failure:0;}
};
static uint32_t iwx_cmd_id(uint8_t o,uint8_t g,uint8_t v){return o+(uint32_t(g)<<8)+(uint32_t(v)<<16);}
class NativeDeauthObservation{iwx_softc*s_;int r_=-999;public:template<class T>NativeDeauthObservation(T*,iwx_softc*s):s_(s){}void setResult(int r){r_=r;}~NativeDeauthObservation(){s_->returns.push_back(r_);}};
'''

CLASS = r'''
class ItlIwx{public:
int iwx_auth(iwx_softc*);int iwx_deauth(iwx_softc*);
int iwx_schedule_protect_session(iwx_softc*,iwx_node*,uint32_t);
int iwx_cancel_session_protection(iwx_softc*,iwx_node*);
int iwx_phy_ctxt_update(iwx_softc*s,iwx_phy_ctxt*,ieee80211_channel*,int,int,int){return s->op("PHY");}
int iwx_mac_ctxt_cmd(iwx_softc*s,iwx_node*,uint32_t a,int){
 const auto label=a==IWX_FW_CTXT_ACTION_ADD?"MAC_ADD":"MAC_REMOVE";int e=s->op(label);
 if(!e||(a==IWX_FW_CTXT_ACTION_REMOVE&&s->ambiguous_remove))s->fw_mac=(a==IWX_FW_CTXT_ACTION_ADD);return e;}
int iwx_binding_cmd(iwx_softc*s,iwx_node*,uint32_t a){return s->op(a==IWX_FW_CTXT_ACTION_ADD?"BIND_ADD":"BIND_REMOVE");}
int iwx_add_sta_cmd(iwx_softc*s,iwx_node*,int){int e=s->op("STA_ADD");if(!e)s->sc_flags|=IWX_FLAG_STA_ACTIVE;return e;}
int iwx_enable_txq(iwx_softc*s,int,int,int,uint32_t){return s->op("MONITOR_TXQ");}
int iwx_enable_mgmt_queue(iwx_softc*s){return s->op("MGMT_TXQ");}
int iwx_clear_statistics(iwx_softc*s){return s->op("STATS");}
void iwx_protect_session(iwx_softc*s,iwx_node*,uint32_t,uint32_t){(void)s->op("LEGACY_PROTECT");}
void iwx_unprotect_session(iwx_softc*s,iwx_node*){(void)s->op("LEGACY_UNPROTECT");}
int iwx_rm_sta_cmd(iwx_softc*s,iwx_node*){int e=s->op("STA_REMOVE");if(!e)s->sc_flags&=~IWX_FLAG_STA_ACTIVE;return e;}
int iwx_rm_sta(iwx_softc*s,iwx_node*n){return iwx_rm_sta_cmd(s,n);}
int iwx_send_cmd_pdu(iwx_softc*s,uint32_t id,int,size_t len,const void*data){
 assert(id==iwx_cmd_id(IWX_SESSION_PROTECTION_CMD,IWX_MAC_CONF_GROUP,0));assert(len==sizeof(iwx_session_prot_cmd));
 const auto&c=*static_cast<const iwx_session_prot_cmd*>(data);s->conf_seen=c.conf_id;s->duration_seen=c.duration_tu;
 if((c.id_and_color&255)>=5||!s->fw_mac||c.conf_id>=8)++s->fw_asserts;
 return s->op(c.action==IWX_FW_CTXT_ACTION_ADD?"SESSION_ADD":"SESSION_REMOVE");}
};
'''

TESTS = r'''
template<class T>void normal(bool patched){
 T d;iwx_softc s;assert(d.iwx_auth(&s)==0);assert(s.fw_mac);assert(s.conf_seen==0&&s.duration_seen==900);
 assert((s.calls==std::vector<std::string>{"PHY","MAC_ADD","BIND_ADD","STA_ADD","MGMT_TXQ","STATS","SESSION_ADD"}));assert(!s.fw_asserts);
 s.calls.clear();assert(d.iwx_deauth(&s)==0);assert(!s.fw_mac&&!(s.sc_flags&IWX_FLAG_MAC_ACTIVE));
 assert((s.calls==std::vector<std::string>{"SESSION_REMOVE","STA_REMOVE","BIND_REMOVE","MAC_REMOVE","PHY"}));assert(!s.fw_asserts);
 s.calls.clear();assert(d.iwx_deauth(&s)==0);assert(s.fw_asserts==(patched?0u:1u));
 assert((s.calls==(patched?std::vector<std::string>{"PHY"}:std::vector<std::string>{"SESSION_REMOVE","PHY"})));
}
template<class T>void failed_auth(bool patched,const std::string&at){
 T d;iwx_softc s;s.fail=at;assert(d.iwx_auth(&s)==35);assert(!s.fw_mac&&!(s.sc_flags&IWX_FLAG_MAC_ACTIVE));
 s.fail.clear();s.calls.clear();assert(d.iwx_deauth(&s)==0);assert(s.fw_asserts==(patched?0u:1u));assert(s.returns.back()==0);
}
template<class T>void remove_retry(){
 T d;iwx_softc s;assert(d.iwx_auth(&s)==0);s.fail="MAC_REMOVE";assert(d.iwx_deauth(&s)==35);assert(s.fw_mac&&(s.sc_flags&IWX_FLAG_MAC_ACTIVE));
 s.fail.clear();s.calls.clear();assert(d.iwx_deauth(&s)==0);assert(!s.fw_mac);assert(!s.fw_asserts);assert(s.calls.front()=="SESSION_REMOVE");
}
template<class T>void remaining_counterexample(bool ambiguous){
 T d;iwx_softc s;assert(d.iwx_auth(&s)==0);
 if(ambiguous){s.fail="MAC_REMOVE";s.ambiguous_remove=true;assert(d.iwx_deauth(&s)==35);s.fail.clear();}else{s.fw_mac=false;}
 assert(!s.fw_mac&&(s.sc_flags&IWX_FLAG_MAC_ACTIVE));assert(d.iwx_deauth(&s)==0);assert(s.fw_asserts==1);
}
template<class T>std::vector<std::string>legacy(){
 T d;iwx_softc s;s.sc_enabled_capa[IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD]=false;
 assert(d.iwx_auth(&s)==0);assert(d.iwx_deauth(&s)==0);assert(d.iwx_deauth(&s)==0);assert(!s.fw_asserts);return s.calls;
}
int main(){
 normal<baseline::ItlIwx>(false);normal<candidate::ItlIwx>(true);
 const std::vector<std::string>stages={"PHY","MAC_ADD","BIND_ADD","STA_ADD","MGMT_TXQ","STATS"};
 for(auto&s:stages){failed_auth<baseline::ItlIwx>(false,s);failed_auth<candidate::ItlIwx>(true,s);}
 remove_retry<baseline::ItlIwx>();remove_retry<candidate::ItlIwx>();
 remaining_counterexample<baseline::ItlIwx>(false);remaining_counterexample<candidate::ItlIwx>(false);
 remaining_counterexample<baseline::ItlIwx>(true);remaining_counterexample<candidate::ItlIwx>(true);
 assert(legacy<baseline::ItlIwx>()==legacy<candidate::ItlIwx>());
 std::cout<<"PASS 11 scenario groups; 22 baseline/candidate executions; 2 remaining counterexample groups retained\n";
}
'''

def function(text, name):
    pattern = re.compile(r"(?:int|void) ItlIwx::\n" + re.escape(name) + r"\(")
    match = pattern.search(text)
    if match is None:
        raise AssertionError("missing current source function: " + name)
    start = match.start()
    brace = text.index("{", match.end())
    depth = 1
    end = brace + 1
    while depth:
        if text[end] == "{":
            depth += 1
        elif text[end] == "}":
            depth -= 1
        end += 1
    return text[start:end]


def fixture_from_current_source(source_root):
    cpp = (source_root / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
    reg = (source_root / "itlwm/hal_iwx/if_iwxreg.h").read_text()
    var = (source_root / "itlwm/hal_iwx/if_iwxvar.h").read_text()
    guarded = "    else if (sc->sc_flags & IWX_FLAG_MAC_ACTIVE)\n        iwx_cancel_session_protection(sc, in);"
    old = "    else\n        iwx_cancel_session_protection(sc, in);"
    current_cleanup = function(cpp, "iwx_deauth")
    if current_cleanup.count(guarded) != 1:
        raise AssertionError("expected exactly one inactive-MAC cancellation guard in current iwx_deauth")
    names = ["iwx_auth", "iwx_deauth", "iwx_schedule_protect_session", "iwx_cancel_session_protection"]
    fragments = {name: function(cpp, name) for name in names}
    baseline = dict(fragments)
    baseline["iwx_deauth"] = current_cleanup.replace(guarded, old)
    define_names = ["IWX_FLAG_MAC_ACTIVE", "IWX_FLAG_BINDING_ACTIVE", "IWX_FLAG_STA_ACTIVE", "IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD", "IWX_MONITOR_STA_ID", "IWX_DQA_INJECT_MONITOR_QUEUE", "IWX_MGMT_TID", "IWX_FW_CTXT_ACTION_ADD", "IWX_FW_CTXT_ACTION_REMOVE", "IWX_SESSION_PROTECT_CONF_ASSOC", "IWX_SESSION_PROTECTION_CMD", "IWX_MAC_CONF_GROUP"]
    defines = []
    for name in define_names:
        match = re.search(r"^#define\s+" + name + r"\s+(0x[\da-fA-F]+|\d+)\b", reg + "\n" + var, re.M)
        if match is None:
            raise AssertionError("missing actual source constant: " + name)
        defines.append("#define " + name + " " + match.group(1))
    first = reg.index("struct iwx_session_prot_cmd {")
    last = reg.index("} __packed;", first) + len("} __packed;")
    preamble = PREAMBLE.replace("struct ieee80211_channel{};", "\n".join(defines) + "\n" + reg[first:last] + "\nstruct ieee80211_channel{};")
    units = []
    for namespace, fragment_set in [("baseline", baseline), ("candidate", fragments)]:
        units.append("namespace " + namespace + " {\n" + CLASS + "\n" + "\n".join(fragment_set[name] for name in names) + "\n}\n")
    hashes = {name: hashlib.sha256(fragments[name].encode()).hexdigest() for name in names}
    return preamble + "\n".join(units) + TESTS, hashes


class SessionProtectionMacGuardTests(unittest.TestCase):
    def test_current_functions_with_injected_lifecycle_failures(self):
        source_root = Path(os.environ.get("ITLWM_SOURCE_ROOT", str(Path(__file__).resolve().parents[2]))).resolve()
        unit, hashes = fixture_from_current_source(source_root)
        if shutil.which("xcrun"):
            compiler = ["xcrun", "clang++"]
        elif shutil.which("clang++"):
            compiler = ["clang++"]
        else:
            self.fail("clang++ is required for the ASan/UBSan host fixture")
        with tempfile.TemporaryDirectory(prefix="iwx-session-protection-guard-") as temp:
            area = Path(temp)
            source = area / "fault_fixture.cpp"
            binary = area / "fault_fixture"
            source.write_text(unit)
            command = compiler + ["-std=c++17", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-Wno-missing-field-initializers", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", str(source), "-o", str(binary)]
            compiled = subprocess.run(command, text=True, capture_output=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            executed = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30)
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
            self.assertIn("22 baseline/candidate executions", executed.stdout)
            print(executed.stdout.strip())
            print("Current source function SHA256: " + repr(hashes))


if __name__ == "__main__":
    unittest.main()
