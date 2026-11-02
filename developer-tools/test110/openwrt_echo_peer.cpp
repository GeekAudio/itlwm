// SPDX-License-Identifier: GPL-2.0-only
// Controlled one-reply peer. No RF action without --run; never changes Wi-Fi,
// WAN or LAN configuration. A local send result is not over-air delivery proof.
#include "openwrt_echo_core.hpp"
#include "openwrt_echo_channel.hpp"
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

static volatile sig_atomic_t stopped=0;
static void stop(int) { stopped=1; }
static uint64_t nowNs() { timespec t{}; if(clock_gettime(CLOCK_MONOTONIC,&t)) return 0; return uint64_t(t.tv_sec)*1000000000+uint64_t(t.tv_nsec); }
static int hexDigit(char c) { return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:-1; }
static bool hex(const char *s,uint8_t *out,size_t n,bool colon=false) {
    if (strlen(s)!=(colon ? n*3-1:n*2)) return false;
    for(size_t i=0;i<n;++i) {
        size_t p=i*(colon?3:2); int a=hexDigit(s[p]),b=hexDigit(s[p+1]);
        if(a<0||b<0||(colon&&i+1<n&&s[p+2]!=':')) return false;
        out[i]=uint8_t(a*16+b);
    } return true;
}
static bool ll(const uint8_t *a) { return a[0]==0xfe && (a[1]&0xc0)==0x80; }
static bool mac(const uint8_t *a) { uint8_t any=0; for(int i=0;i<6;++i) any|=a[i]; return any && !(a[0]&1); }
static void hexprint(const uint8_t *a,size_t n) { for(size_t i=0;i<n;++i) printf("%02x",a[i]); }

static_assert(GENL_ID_CTRL == Test110Channel::kNlctrlFamilyId,
              "Test110 nlctrl family ID drifted");
constexpr uint8_t kNlctrlGenlVersion = 2;
constexpr uint8_t kNl80211GenlVersion = 1;
static_assert(CTRL_CMD_NEWFAMILY == Test110Channel::kCtrlCmdNewFamily,
              "Test110 ctrl command ID drifted");
static_assert(CTRL_ATTR_FAMILY_ID == Test110Channel::kCtrlAttrFamilyId,
              "Test110 ctrl family ID attribute drifted");
static_assert(CTRL_ATTR_FAMILY_NAME == Test110Channel::kCtrlAttrFamilyName,
              "Test110 ctrl family name attribute drifted");
static_assert(NL80211_CMD_NEW_INTERFACE ==
                  Test110Channel::kNl80211CmdNewInterface,
              "Test110 nl80211 interface command ID drifted");
static_assert(NL80211_ATTR_IFINDEX == Test110Channel::kNl80211AttrIfindex,
              "Test110 nl80211 ifindex attribute drifted");
static_assert(NL80211_ATTR_IFNAME == Test110Channel::kNl80211AttrIfname,
              "Test110 nl80211 ifname attribute drifted");
static_assert(NL80211_ATTR_WIPHY_FREQ == Test110Channel::kNl80211AttrWiphyFreq,
              "Test110 nl80211 frequency attribute drifted");
static_assert(NL80211_ATTR_WIPHY_FREQ_OFFSET ==
                  Test110Channel::kNl80211AttrWiphyFreqOffset,
              "Test110 nl80211 frequency offset attribute drifted");

static bool appendAttribute(uint8_t *buffer, size_t capacity, size_t *used,
                            uint16_t type, const void *value, size_t valueLength)
{
    if(!buffer||!used||(!value&&valueLength)||valueLength>UINT16_MAX-4)return false;
    const size_t length=4+valueLength;
    const size_t aligned=(length+3)&~size_t(3);
    if(*used>capacity||aligned>capacity-*used)return false;
    auto *attribute=reinterpret_cast<nlattr *>(buffer+*used);
    attribute->nla_len=static_cast<uint16_t>(length);
    attribute->nla_type=type;
    if(valueLength)memcpy(buffer+*used+4,value,valueLength);
    if(aligned>length)memset(buffer+*used+length,0,aligned-length);
    *used+=aligned;
    return true;
}

static int openGenericNetlink(uint32_t *localPortId)
{
    if(!localPortId)return -1;
    int fd=socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC,NETLINK_GENERIC);
    if(fd<0)return -1;
    timeval timeout{}; timeout.tv_usec=10000;
    if(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))<0||
       setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout))<0){close(fd);return -1;}
    sockaddr_nl local{}; local.nl_family=AF_NETLINK;
    if(bind(fd,reinterpret_cast<sockaddr*>(&local),sizeof(local))<0){close(fd);return -1;}
    sockaddr_nl actual{}; socklen_t actualLength=sizeof(actual);
    if(getsockname(fd,reinterpret_cast<sockaddr*>(&actual),&actualLength)<0||
       actualLength!=sizeof(actual)||actual.nl_family!=AF_NETLINK||
       actual.nl_pid==0||actual.nl_groups!=0){close(fd);return -1;}
    *localPortId=actual.nl_pid;
    return fd;
}

static bool receiveGenericNetlink(int fd,uint8_t *buffer,size_t capacity,
                                  size_t *length,Test110Channel::SourceAddress *source)
{
    if(fd<0||!buffer||!length||!source||capacity<Test110Channel::kMaximumReplyBytes)return false;
    sockaddr_nl sender{}; iovec io{buffer,capacity}; msghdr message{};
    message.msg_name=&sender; message.msg_namelen=sizeof(sender);
    message.msg_iov=&io; message.msg_iovlen=1;
    const ssize_t received=recvmsg(fd,&message,MSG_TRUNC);
    if(received<0||static_cast<size_t>(received)>capacity||
       (message.msg_flags&(MSG_TRUNC|MSG_CTRUNC))||
       message.msg_namelen!=sizeof(sender)||sender.nl_family!=AF_NETLINK)return false;
    *length=static_cast<size_t>(received);
    source->portId=sender.nl_pid; source->groups=sender.nl_groups;
    return true;
}

static uint32_t nextNetlinkSequence(uint32_t *sequence)
{
    if(!sequence)return 0;
    ++*sequence;
    if(*sequence==0)++*sequence;
    return *sequence;
}

static bool transactGenericNetlink(int fd,uint32_t localPortId,uint16_t family,
                                   uint8_t command,uint8_t version,
                                   uint32_t sequence,const void *attributeValue,
                                   uint16_t attributeType,size_t attributeValueLength,
                                   uint8_t *reply,size_t replyCapacity,size_t *replyLength,
                                   Test110Channel::SourceAddress *source)
{
    if(fd<0||localPortId==0||sequence==0||!reply||!replyLength||!source)return false;
    uint8_t request[128]{};
    constexpr size_t headerBytes=NLMSG_HDRLEN+GENL_HDRLEN;
    if(headerBytes>sizeof(request))return false;
    auto *header=reinterpret_cast<nlmsghdr *>(request);
    header->nlmsg_len=static_cast<uint32_t>(headerBytes);
    header->nlmsg_type=family; header->nlmsg_flags=NLM_F_REQUEST;
    header->nlmsg_seq=sequence; header->nlmsg_pid=localPortId;
    auto *generic=reinterpret_cast<genlmsghdr *>(request+NLMSG_HDRLEN);
    generic->cmd=command; generic->version=version; generic->reserved=0;
    if(attributeValueLength){
        size_t used=headerBytes;
        if(!appendAttribute(request,sizeof(request),&used,attributeType,
                            attributeValue,attributeValueLength))return false;
        header->nlmsg_len=static_cast<uint32_t>(used);
    }
    sockaddr_nl kernel{}; kernel.nl_family=AF_NETLINK; kernel.nl_pid=0; kernel.nl_groups=0;
    const ssize_t sent=sendto(fd,request,header->nlmsg_len,0,
        reinterpret_cast<sockaddr*>(&kernel),sizeof(kernel));
    if(sent!=static_cast<ssize_t>(header->nlmsg_len))return false;
    return receiveGenericNetlink(fd,reply,replyCapacity,replyLength,source);
}

static bool currentNl80211Frequency(uint32_t ifindex,const char *ifname,
                                    uint32_t *frequencyMhz,uint32_t *offsetKhz)
{
    if(!ifindex||!ifname||!*ifname||!frequencyMhz||!offsetKhz)return false;
    uint32_t localPortId=0;
    const int fd=openGenericNetlink(&localPortId);
    if(fd<0)return false;
    uint64_t seed=nowNs();
    uint32_t sequence=static_cast<uint32_t>(seed^(seed>>32));
    if(sequence==0)sequence=1;
    uint8_t reply[4096]{}; size_t replyLength=0;
    Test110Channel::SourceAddress source{}; uint16_t familyId=0;
    const char familyName[]="nl80211";
    const uint32_t familySequence=nextNetlinkSequence(&sequence);
    bool okay=transactGenericNetlink(fd,localPortId,GENL_ID_CTRL,
        CTRL_CMD_GETFAMILY,kNlctrlGenlVersion,familySequence,familyName,
        CTRL_ATTR_FAMILY_NAME,sizeof(familyName),reply,sizeof(reply),&replyLength,&source);
    if(okay){
        okay=Test110Channel::parseFamilyReply(reply,replyLength,source,
            familySequence,localPortId,"nl80211",&familyId)==Test110Channel::Status::kOk;
    }
    uint32_t wireIfindex=ifindex;
    uint32_t frequency=0,offset=0;
    if(okay){
        const uint32_t interfaceSequence=nextNetlinkSequence(&sequence);
        okay=transactGenericNetlink(fd,localPortId,familyId,
            NL80211_CMD_GET_INTERFACE,kNl80211GenlVersion,interfaceSequence,
            &wireIfindex,NL80211_ATTR_IFINDEX,sizeof(wireIfindex),reply,sizeof(reply),
            &replyLength,&source);
        if(okay){
            okay=Test110Channel::parseInterfaceReply(reply,replyLength,source,
                familyId,interfaceSequence,localPortId,ifindex,ifname,
                &frequency,&offset)==Test110Channel::Status::kOk;
        }
    }
    close(fd);
    if(!okay)return false;
    *frequencyMhz=frequency; *offsetKhz=offset;
    return true;
}

int main(int argc,char **argv) {
    const char *values[8]{};
    const char *names[8]={"--interface","--local-mac","--peer-mac","--local-ipv6","--peer-ipv6","--nonce","--run-token","--window-ms"};
    bool run=false;
    for(int i=1;i<argc;++i) {
        if(!strcmp(argv[i],"--run")) { if(run) return 2; run=true; continue; }
        int key=-1; for(int j=0;j<8;++j) if(!strcmp(argv[i],names[j])) key=j;
        if(key<0||values[key]||i+1>=argc) return 2;
        values[key]=argv[++i];
    }
    for(int i=0;i<7;++i) if(!values[i]) return 2;
    if(values[7]&&strcmp(values[7],"16000")) return 2;
    if(!*values[0]||strlen(values[0])>=IFNAMSIZ) return 2;
    for(const char *p=values[0];*p;++p) if(!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||*p=='_'||*p=='-'||*p=='.')) return 2;
    Test110Echo::Contract c{}; uint8_t token[16];
    if(!hex(values[1],c.mac,6,true)||!hex(values[2],c.peerMac,6,true)||
        inet_pton(AF_INET6,values[3],c.ip)!=1||inet_pton(AF_INET6,values[4],c.peerIp)!=1||
        !hex(values[5],c.nonce,8)||!Test110Channel::nonceUsable(c.nonce)||
        !hex(values[6],token,16)||!ll(c.ip)||!ll(c.peerIp)||
        !mac(c.mac)||!mac(c.peerMac)||!memcmp(c.mac,c.peerMac,6)||!memcmp(c.ip,c.peerIp,16)) return 2;
    if(!run) { puts("{\"schema\":\"test110-openwrt-echo-peer/v1\",\"event\":\"PLAN\",\"rf_action\":false,\"channel\":6,\"window_ms\":16000,\"max_replies\":1}"); return 0; }
    if(geteuid()!=0) return 3;
    const unsigned index=if_nametoindex(values[0]); if(!index) return 4;
    int fd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL)); if(fd<0) return 4;
    ifreq req{}; memcpy(req.ifr_name,values[0],strlen(values[0])+1);
    if(ioctl(fd,SIOCGIFHWADDR,&req)||req.ifr_hwaddr.sa_family!=ARPHRD_IEEE80211_RADIOTAP) { close(fd); return 4; }
    if(ioctl(fd,SIOCGIFFLAGS,&req)||!(req.ifr_flags&IFF_UP)) { close(fd); return 4; }
    sockaddr_ll address{}; address.sll_family=AF_PACKET; address.sll_protocol=htons(ETH_P_ALL); address.sll_ifindex=int(index);
    if(bind(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))) { close(fd); return 4; }
    uint32_t initialFrequency=0,initialOffset=0;
    if(!currentNl80211Frequency(index,values[0],&initialFrequency,&initialOffset)||
       initialFrequency!=Test110Channel::kChannel6FrequencyMhz||initialOffset!=0){
        close(fd); fprintf(stderr,"Test110: monitor interface channel preflight failed\n"); return 4;
    }
    signal(SIGINT,stop); signal(SIGTERM,stop);
    const uint64_t begin=nowNs(); if(!begin) { close(fd); return 4; }
    const uint64_t deadline=begin+16000000000ULL;
    // Private stdout: these exact identities allow the coordinator to hash the
    // live READY contract rather than constructing a synthetic readiness file.
    printf("{\"schema\":\"test110-openwrt-echo-peer/v1\",\"event\":\"READY\",\"run_token\":\"%s\",\"nonce\":\"%s\",\"local_mac\":\"%s\",\"peer_mac\":\"%s\",\"local_ipv6\":\"%s\",\"peer_ipv6\":\"%s\",\"channel\":6,\"window_ms\":16000,\"request_source_port\":49153,\"request_destination_port\":49152,\"reply_source_port\":49152,\"reply_destination_port\":49153,\"hop_limit\":1,\"payload_bytes\":8,\"echo_mode\":\"exact-request-payload-once\",\"ifindex\":%u,\"monotonic_start_ns\":%llu,\"monotonic_deadline_ns\":%llu,\"token_bytes_hex\":\"",values[6],values[5],values[1],values[2],values[3],values[4],index,(unsigned long long)begin,(unsigned long long)deadline);
    hexprint(token,16); puts("\"}"); fflush(stdout);
    unsigned observed=0; bool matched=false,sent=false;
    while(!stopped && observed<4096) {
        const uint64_t now=nowNs(); if(!now||now>=deadline) break;
        int wait=int((deadline-now+999999)/1000000); if(wait>100) wait=100;
        pollfd p{fd,POLLIN,0}; int r=poll(&p,1,wait);
        if(r<0) { if(errno==EINTR) continue; break; }
        if(!r) continue;
        if(!(p.revents&POLLIN)) break;
        uint8_t frame[4096]; sockaddr_ll source{}; iovec iov{frame,sizeof(frame)};
        msghdr msg{}; msg.msg_name=&source; msg.msg_namelen=sizeof(source); msg.msg_iov=&iov; msg.msg_iovlen=1;
        ssize_t n=recvmsg(fd,&msg,MSG_DONTWAIT|MSG_TRUNC);
        if(n<0) { if(errno==EAGAIN||errno==EINTR) continue; break; }
        ++observed;
        if(n>ssize_t(sizeof(frame))||(msg.msg_flags&MSG_TRUNC)||source.sll_pkttype==PACKET_OUTGOING||source.sll_ifindex!=int(index)) continue;
        const uint8_t *mpdu=nullptr; size_t length=0;
        if(!Test110Echo::stripRadiotap(frame,size_t(n),&mpdu,&length)||!Test110Echo::requestMatches(mpdu,length,c)) continue;
        matched=true; uint8_t response[106]; size_t bytes=0;
        uint32_t sendFrequency=0,sendOffset=0;
        if(!currentNl80211Frequency(index,values[0],&sendFrequency,&sendOffset)||
           sendFrequency!=Test110Channel::kChannel6FrequencyMhz||sendOffset!=0||
           !Test110Echo::reply(c,response,sizeof(response),&bytes)||stopped||nowNs()>=deadline) break;
        // Exactly one send attempt; EAGAIN/EINTR is reported, never retried.
        sent=sendto(fd,response,bytes,MSG_DONTWAIT,reinterpret_cast<sockaddr*>(&address),sizeof(address))==ssize_t(bytes);
        break;
    }
    close(fd);
    printf("{\"schema\":\"test110-openwrt-echo-peer/v1\",\"event\":\"RESULT\",\"observed_frames\":%u,\"request_matched\":%s,\"reply_local_send\":%s,\"over_air_delivery_proven\":false,\"airdrop_proven\":false,\"stopped\":%s}\n",observed,matched?"true":"false",sent?"true":"false",stopped?"true":"false");
    return stopped?7:sent?0:matched?5:6;
}
