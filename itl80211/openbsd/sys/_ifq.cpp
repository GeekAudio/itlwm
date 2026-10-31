//
//  _ifq.cpp
//  itlwm
//
//  Created by zxystd on 2022/8/13.
//  Copyright © 2022 钟先耀. All rights reserved.
//

#include <sys/_ifq.h>

#ifdef AIRPORT_TAHOE
#include <sys/kpi_mbuf.h>
#include <sys/errno.h>
#include "../../../native/group2_tx_trace_helpers.h"

static mbuf_tag_id_t iwx_group2_tag_id;
static uint32_t iwx_group2_tag_id_state;

static void ifq_group2_initialize_tag_id(void)
{
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&iwx_group2_tag_id_state, &expected,
            1u, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return;
    const errno_t error = mbuf_tag_id_find("com.zxystd.AirportItlwm",
                                           &iwx_group2_tag_id);
    __atomic_store_n(&iwx_group2_tag_id_state, error == 0 ? 2u : 3u,
                     __ATOMIC_RELEASE);
}

static int ifq_group2_get_tag_id(mbuf_tag_id_t *tag_id)
{
    if (!tag_id || __atomic_load_n(&iwx_group2_tag_id_state,
                                   __ATOMIC_ACQUIRE) != 2u)
        return 0;
    *tag_id = iwx_group2_tag_id;
    return 1;
}

static void ifq_group2_record(struct IwxGroup2TxTrace *trace,
    const struct IwxGroup2TxTag *tag, uint64_t monotonic_us,
    uint16_t stage, int32_t result, uint32_t extra_flags,
    uint32_t queue_id)
{
    if (!trace || !iwx_group2_tx_tag_valid(tag))
        return;
    struct IwxGroup2TxEvent event = {};
    iwx_group2_tx_event_from_tag(&event, tag, monotonic_us, stage);
    event.result = result;
    event.flags |= extra_flags;
    event.queue_id = queue_id;
    (void)iwx_group2_tx_trace_record(trace, &event);
}
#endif

void ifq_init(struct _ifqueue *ifq, struct _ifnet *ifp, unsigned int maxLen)
{
    if (!ifq->queue)
        ifq->queue = IOPacketQueue::withCapacity(maxLen);
    else
        ifq->queue->setCapacity(maxLen);
    ifq->ifq_oactive = 0;
#ifdef AIRPORT_TAHOE
    ifq_group2_initialize_tag_id();
#endif
}

void ifq_destroy(struct _ifqueue *ifq)
{
    if (ifq->queue) {
        ifq->queue->release();
        ifq->queue = nullptr;
    }
}

void ifq_flush(struct _ifqueue *ifq)
{
    if (ifq->queue)
        ifq->queue->lockFlush();
}

bool ifq_empty(struct _ifqueue *ifq)
{
    return ifq->queue->getSize() == 0;
}

uint32_t ifq_len(struct _ifqueue *ifq)
{
    return ifq->queue->getSize();
}

void ifq_set_maxlen(struct _ifqueue *ifq, uint32_t maxLen)
{
    ifq->queue->setCapacity(maxLen);
}

void ifq_set_oactive(struct _ifqueue *ifq)
{
    ifq->ifq_oactive = 1;
}

unsigned int ifq_is_oactive(struct _ifqueue *ifq)
{
    return ifq->ifq_oactive;
}

void ifq_clr_oactive(struct _ifqueue *ifq)
{
    ifq->ifq_oactive = 0;
}

mbuf_t ifq_dequeue(struct _ifqueue *ifq)
{
    return ifq->queue->lockDequeue();
}

int ifq_enqueue(struct _ifqueue *ifq, mbuf_t m)
{
    ifq->queue->lockEnqueueWithDrop(m);
    return 0;
}

#ifdef AIRPORT_TAHOE
int ifq_group2_tag_attach(mbuf_t m, const struct IwxGroup2TxTag *tag)
{
    mbuf_tag_id_t tag_id = 0;
    if (!m || !iwx_group2_tx_tag_valid(tag) ||
        !ifq_group2_get_tag_id(&tag_id))
        return EINVAL;
    void *storage = NULL;
    const errno_t error = mbuf_tag_allocate(m, tag_id,
        static_cast<mbuf_tag_type_t>(IWX_GROUP2_TX_TAG_TYPE),
        sizeof(*tag), MBUF_DONTWAIT, &storage);
    if (error != 0)
        return error;
    __builtin_memcpy(storage, tag, sizeof(*tag));
    return 0;
}

int ifq_group2_tag_copy(mbuf_t m, struct IwxGroup2TxTag *tag)
{
    mbuf_tag_id_t tag_id = 0;
    if (!m || !tag || !ifq_group2_get_tag_id(&tag_id))
        return 0;
    size_t length = sizeof(*tag);
    void *storage = NULL;
    if (mbuf_tag_find(m, tag_id,
            static_cast<mbuf_tag_type_t>(IWX_GROUP2_TX_TAG_TYPE),
            &length, &storage) != 0 || length != sizeof(*tag) || !storage)
        return 0;
    __builtin_memcpy(tag, storage, sizeof(*tag));
    return iwx_group2_tx_tag_valid(tag);
}

int ifq_enqueue_group2(struct _ifqueue *ifq, mbuf_t m,
    struct IwxGroup2TxTrace *trace, const struct IwxGroup2TxTag *tag,
    uint64_t monotonic_us)
{
    if (!ifq || !ifq->queue || !m)
        return EINVAL;
    const UInt32 dropped = ifq->queue->lockEnqueueWithDrop(m);
    // IOPacketQueue reports a call-level drop count. Its contract does not
    // identify which member of a chain was freed, so this event deliberately
    // does not claim this Group2 cookie survived enqueue.
    ifq_group2_record(trace, tag, monotonic_us,
        IWX_GROUP2_TX_STAGE_IFQ_ENQUEUE,
        dropped > static_cast<UInt32>(INT32_MAX) ? INT32_MAX :
            static_cast<int32_t>(dropped),
        IWX_GROUP2_TX_QUEUE_DROP_COUNT_PRESENT | IWX_GROUP2_TX_HAS_QUEUE,
        UINT32_MAX);
    return 0;
}
#endif
