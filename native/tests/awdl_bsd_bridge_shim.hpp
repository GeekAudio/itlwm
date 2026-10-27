// SPDX-License-Identifier: GPL-2.0-only
// Host-only ownership instrumentation. No native system/firmware proof.
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <mutex>
#define EJUSTRETURN (-2)
#define MBUF_DONTWAIT 0
#define MBUF_TYPE_DATA 1
#define MBUF_PKTHDR 2
#define AF_INET6 30
#define IFF_UP 1
#define IFF_RUNNING 0x40
#define SOCK_DGRAM 2
#define IFCAP_HWCSUM 3
#define IFCAP_TSO 0x60
#define IFCAP_CSUM_PARTIAL 0x2000
#define IFCAP_CSUM_ZERO_INVERT 0x4000
#define SIOCAIFADDR_IN6 0x1234
using errno_t=int;
using protocol_family_t=unsigned;
struct FakeIf {unsigned refs=0;bool ipv6=false;uint8_t address[16]{};};using ifnet_t=FakeIf *;
struct FakeMbuf {uint8_t bytes[2048]{};size_t offset=0,length=0,total=0;unsigned flags=0;void *header=nullptr;};
using mbuf_t=FakeMbuf *;
using IOSimpleLock=std::mutex;using IOInterruptState=unsigned;
extern unsigned allocated,freed,delivered,finalized,socketsOpen,socketsClosed;extern uint64_t fakeTime;
extern bool allocateFail,inputFail,detachDelay,offloadFail;
extern bool ipv6Fail,socketFail,packetHeaderMissing;
inline IOSimpleLock *IOSimpleLockAlloc(){return new IOSimpleLock;}
inline IOInterruptState IOSimpleLockLockDisableInterrupt(IOSimpleLock *l){l->lock();return 0;}
inline void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock *l,IOInterruptState){l->unlock();}
inline void clock_get_uptime(uint64_t *p){*p=fakeTime;}
inline void absolutetime_to_nanoseconds(uint64_t a,uint64_t *n){*n=a*1000;}
inline void IOSleep(unsigned){}
inline size_t mbuf_pkthdr_len(mbuf_t m){return m->total;}
inline int mbuf_copydata(mbuf_t m,size_t off,size_t len,void *out){if(off+len>m->total)return EINVAL;memcpy(out,m->bytes+m->offset+off,len);return 0;}
inline int mbuf_getcluster(int,int,size_t n,mbuf_t *m){if(allocateFail||n>2048)return ENOMEM;*m=new FakeMbuf;++allocated;return 0;}
inline int mbuf_getpacket(int,mbuf_t *m){if(allocateFail){*m=nullptr;return ENOMEM;}*m=new FakeMbuf;(*m)->flags=packetHeaderMissing?0:MBUF_PKTHDR;++allocated;return 0;}
inline unsigned mbuf_flags(mbuf_t m){return m->flags;}
inline void *mbuf_data(mbuf_t m){return m->bytes+m->offset;}
inline void mbuf_freem(mbuf_t m){assert(m);delete m;++freed;}
inline void mbuf_setlen(mbuf_t m,size_t n){m->length=n;}
inline void mbuf_pkthdr_setlen(mbuf_t m,size_t n){m->total=n;}
inline void mbuf_pkthdr_setrcvif(mbuf_t,ifnet_t){}
inline void mbuf_pkthdr_setheader(mbuf_t m,void *p){m->header=p;}
inline void mbuf_adj(mbuf_t m,int n){m->offset+=n;m->length-=n;if(m->flags&MBUF_PKTHDR)m->total-=n;}
inline void mbuf_outbound_finalize(mbuf_t,unsigned family,size_t offset){assert(family==AF_INET6&&offset==14);++finalized;}
inline int ifnet_reference(ifnet_t p){++p->refs;return 0;}
inline void ifnet_release(ifnet_t p){assert(p->refs);--p->refs;}
inline int ifnet_set_offload(ifnet_t,unsigned){return offloadFail?EIO:0;}
inline int ifnet_set_mtu(ifnet_t,unsigned){return 0;}
inline int ifnet_set_flags(ifnet_t,unsigned,unsigned){return 0;}
inline int ifnet_set_capabilities_enabled(ifnet_t,unsigned,unsigned){return 0;}
inline int ifnet_set_capabilities_supported(ifnet_t,unsigned,unsigned){return 0;}
inline unsigned ifnet_capabilities_enabled(ifnet_t){return 0x400;}
inline unsigned ifnet_index(ifnet_t){return 8;}
struct sockaddr {uint8_t sa_len,sa_family;char data[14];};
struct in6_addr {uint8_t s6_addr[16];};
struct sockaddr_in6 {uint8_t sin6_len=0,sin6_family=0;uint16_t port=0;uint32_t flow=0;in6_addr sin6_addr{};uint32_t sin6_scope_id=0;};
struct in6_addrlifetime {uint32_t ia6t_vltime=0,ia6t_pltime=0;};
struct in6_aliasreq {char ifra_name[16]{};sockaddr_in6 ifra_addr{},ifra_dstaddr{},ifra_prefixmask{};int ifra_flags=0;in6_addrlifetime ifra_lifetime{};};
using ifaddr_t=FakeIf *;
inline int ifnet_get_address_list_family(ifnet_t p,ifaddr_t **out,unsigned family){assert(family==AF_INET6);static ifaddr_t list[2]{};list[0]=p->ipv6?p:nullptr;list[1]=nullptr;*out=list;return 0;}
inline void ifnet_free_address_list(ifaddr_t *){}
inline int ifaddr_address(ifaddr_t p,sockaddr *out,size_t length){assert(length==sizeof(sockaddr_in6));sockaddr_in6 value{};value.sin6_family=AF_INET6;memcpy(value.sin6_addr.s6_addr,p->address,16);memcpy(out,&value,length);return 0;}
struct iff_filter {
    void *iff_cookie=nullptr;const char *iff_name=nullptr;unsigned iff_protocol=0;
    void *iff_input=nullptr;int (*iff_output)(void *,ifnet_t,unsigned,mbuf_t *)=nullptr;
    void *iff_event=nullptr,*iff_ioctl=nullptr;
    void (*iff_detached)(void *,ifnet_t)=nullptr;
};
using interface_filter_t=iff_filter *;
extern iff_filter installed;extern ifnet_t filterIf;
inline int iflt_attach(ifnet_t p,const iff_filter *f,interface_filter_t *r){installed=*f;filterIf=p;*r=&installed;return 0;}
inline void iflt_detach(interface_filter_t f){if(!detachDelay)f->iff_detached(f->iff_cookie,filterIf);}
inline int ifnet_input(ifnet_t,mbuf_t m,void *){
#if defined(HOST_EXPECT_MISSING_PKTHDR)
    // Controlled negative regression: model the kernel's invariant without
    // deliberately crashing a host process or ever injecting into the kernel.
    if(!(m->flags&MBUF_PKTHDR))exit(86);
#endif
    assert((m->flags&MBUF_PKTHDR)&&"DLIL requires M_PKTHDR");
    assert(m->header==m->bytes&&m->offset==14&&m->total>=40);
    assert(m->bytes[12]==0x86&&m->bytes[13]==0xdd&&(m->bytes[14]>>4)==6);
    if(!inputFail)++delivered;
    mbuf_freem(m);return inputFail?EIO:0;
}
struct FakeSocket{};using socket_t=FakeSocket *;
inline int sock_socket(int family,int type,int,void *,void *,socket_t *out){assert(family==AF_INET6&&type==SOCK_DGRAM);if(socketFail)return ENOMEM;*out=new FakeSocket;++socketsOpen;return 0;}
inline int sock_ioctl(socket_t,unsigned long request,void *arg){
    assert(request==SIOCAIFADDR_IN6);auto p=static_cast<in6_aliasreq *>(arg);
    assert(!strcmp(p->ifra_name,"awdl0")&&p->ifra_addr.sin6_scope_id==8);
    assert(p->ifra_addr.sin6_len==sizeof(sockaddr_in6)&&p->ifra_addr.sin6_family==AF_INET6);
    assert(p->ifra_addr.sin6_addr.s6_addr[0]==0xfe&&p->ifra_addr.sin6_addr.s6_addr[1]==0x80);
    assert(p->ifra_addr.sin6_addr.s6_addr[11]==0xff&&p->ifra_addr.sin6_addr.s6_addr[12]==0xfe);
    assert(p->ifra_lifetime.ia6t_vltime==UINT32_MAX);
    if(ipv6Fail)return EINVAL;filterIf->ipv6=true;memcpy(filterIf->address,p->ifra_addr.sin6_addr.s6_addr,16);return 0;
}
inline void sock_close(socket_t socket){delete socket;++socketsClosed;}
