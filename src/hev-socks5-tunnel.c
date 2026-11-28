/*
 ============================================================================
 Name        : hev-socks5-tunnel.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2019 - 2025 hev
 Description : Socks5 Tunnel
 ============================================================================
 */

#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <string.h>
#include <stdatomic.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <hev-sys.h>

#ifdef __GLIBC__
#include <malloc.h>
#endif

#include <lwip/tcp.h>
#include <lwip/udp.h>
#include <lwip/nd6.h>
#include <lwip/netif.h>
#include <lwip/ip4_frag.h>
#include <lwip/ip6_frag.h>
#include <lwip/priv/tcp_priv.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-task-mutex.h>
#include <hev-task-system.h>
#include <hev-memory-allocator.h>

#include "hev-exec.h"
#include "hev-config.h"
#include "hev-utils.h"
#include "hev-logger.h"
#include "hev-compat.h"
#include "hev-tunnel.h"
#include "hev-compiler.h"
#include "hev-mapped-dns.h"
#include "hev-config-const.h"
#include "hev-socks5-session-tcp.h"
#include "hev-socks5-session-udp.h"

#include "hev-main.h"
#include "hev-socks5-tunnel.h"

enum
{
    SYNC_SEND = 1 << 0,
    SYNC_SENT = 1 << 1,
    SYNC_WAIT = 1 << 2,
    SYNC_STOP = 1 << 3,
};

#define DNS_PORT 53
#define DNS_PRIORITY_ADDRS 4
/* A resolver retries a query after about this long without a reply. */
#define DNS_PRIORITY_GRACE_MS 1000

static int run;
static atomic_int tsync;

static int tun_fd = -1;
static int tun_fd_local;
static int session_count;
static int event_fds[2] = { -1, -1 };
static int relief_fds[2] = { -1, -1 };
static pthread_mutex_t relief_mutex = PTHREAD_MUTEX_INITIALIZER;

static size_t stat_tx_packets;
static size_t stat_rx_packets;
static size_t stat_tx_bytes;
static size_t stat_rx_bytes;

static struct netif *netif;
static struct tcp_pcb *tcp;
static struct udp_pcb *udp;

static HevTaskMutex mutex;
static HevTask *task_event;
static HevTask *task_lwip_io;
static HevTask *task_lwip_timer;
static HevTask *task_relief;

/*
 * Live UDP and TCP sessions in one table, least recently active first:
 * max-session-count and the buffer budget are shared by both types.
 */
static HevList session_set;
/* Live sessions of the DNS pool, outside the table and its count. */
static HevList session_dns;
static int session_live_count[SESSION_TYPES];
/* Closed sessions whose task has not exited yet. */
static HevList session_dying;
static int session_dying_count;

/* misc.max-buffer-size, see hev_socks5_tunnel_buffer_charge. */
size_t hev_socks5_tunnel_buffer_limit;
static size_t buffer_used;
static size_t window_used;

/* Written from any thread, read by the tunnel thread. */
static int probe_hold_types = HEV_SOCKS5_TUNNEL_SESSION_UDP |
                              HEV_SOCKS5_TUNNEL_SESSION_TCP;
static int probe_close_types = HEV_SOCKS5_TUNNEL_SESSION_UDP |
                               HEV_SOCKS5_TUNNEL_SESSION_TCP;

/* Written by the tunnel thread, read from any thread. */
static uint64_t stat_created[SESSION_TYPES];
static uint64_t stat_evicted[SESSION_TYPES];
static uint64_t stat_refused[SESSION_TYPES];
static uint64_t stat_relieved[SESSION_TYPES];
static uint64_t stat_refused_adm[SESSION_TYPES];
/* Closed while they held buffers without progress over the budget. */
static uint64_t stat_reclaimed;
/* Protected sessions found the last time room was made. */
static int stat_protected;

/*
 * Written from any thread, read by the tunnel thread. A flow that starts
 * while the address list changes may be matched against either list.
 */
static int dns_priority_cap;
static int dns_priority_timeout_ms;
static int dns_priority_addr_count;
static uint32_t dns_priority_addr[DNS_PRIORITY_ADDRS];
/* Queries that found the pool full and started as ordinary UDP sessions. */
static uint64_t stat_dns_overflow;

typedef struct _HevSocks5TunnelProbe HevSocks5TunnelProbe;

struct _HevSocks5TunnelProbe
{
    HevSocks5TunnelMemoryProbe probe;
    void *user_data;
    int interval_ms;
    int hold_below_kb;
    int close_below_kb;
    int hysteresis_kb;
    int young_ms;
    int young_reserve_kb;
};

/* Set from any thread under probe_mutex, outlives tunnel restarts. */
static HevSocks5TunnelProbe probe_conf;
static pthread_mutex_t probe_mutex = PTHREAD_MUTEX_INITIALIZER;
static int64_t probe_next_ms;

/* Tunnel thread; probe_state and probe_last_kb are also read by stats. */
static HevSocks5TunnelProbe probe_cur;
static int probe_state;
static int64_t probe_last_kb = -1;
/* Time spent in each probe state since the tunnel start, for stats. */
static int64_t probe_state_ms[HEV_SOCKS5_TUNNEL_ADMIT_CLOSED + 1];
static int64_t probe_state_since;
/* Counters belong to the current start only after it has reset them. */
static int stats_ready;

#define YOUNG_RING 128
static int64_t young_ring[YOUNG_RING];
static unsigned int young_head;
/* The last admitted session took the place of an evicted one. */
static int admit_replaced;

typedef struct _HevSocks5TunnelRelief HevSocks5TunnelRelief;

struct _HevSocks5TunnelRelief
{
    int types;
    int idle_ms;
    int max_count;
};

static int64_t
monotonic_ms (void)
{
    struct timespec ts;

#ifdef CLOCK_MONOTONIC_COARSE
    clock_gettime (CLOCK_MONOTONIC_COARSE, &ts);
#else
    clock_gettime (CLOCK_MONOTONIC, &ts);
#endif

    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int
task_io_yielder (HevTaskYieldType type, void *data)
{
    hev_task_yield (type);

    return READ_ONCE (run) ? 0 : -1;
}

static err_t
netif_output_handler (struct netif *netif, struct pbuf *p)
{
    ssize_t s;

    s = hev_tunnel_write (tun_fd, p);
    if (s <= 0) {
        if (errno == EAGAIN)
            return ERR_WOULDBLOCK;
        /* Large packets may not fit, lwIP sends smaller ones then. */
        if ((errno == ENOBUFS) || (errno == ENOMEM))
            return ERR_MEM;
        LOG_W ("socks5 tunnel write");
        return ERR_IF;
    }

    stat_rx_packets++;
    stat_rx_bytes += s;

    return ERR_OK;
}

static err_t
netif_output_v4_handler (struct netif *netif, struct pbuf *p,
                         const ip4_addr_t *ipaddr)
{
    return netif_output_handler (netif, p);
}

static err_t
netif_output_v6_handler (struct netif *netif, struct pbuf *p,
                         const ip6_addr_t *ipaddr)
{
    return netif_output_handler (netif, p);
}

static err_t
netif_init_handler (struct netif *netif)
{
    netif->output = netif_output_v4_handler;
    netif->output_ip6 = netif_output_v6_handler;

    return ERR_OK;
}

static void
stat_inc (uint64_t *counter)
{
    __atomic_fetch_add (counter, 1, __ATOMIC_RELAXED);
}

static int
sessions_empty (void)
{
    return !hev_list_first (&session_set) && !hev_list_first (&session_dns) &&
           !hev_list_first (&session_dying);
}

static HevList *
session_list (int type)
{
    return (type == SESSION_DNS) ? &session_dns : &session_set;
}

/*
 * Closes the session and takes it off its live list at once, so the count and
 * eviction never count or pick it again while its task is still exiting.
 *
 * With release, what it holds in lwIP is dropped right away and the upstream
 * connection is reset: in a burst each new connection brings a full window of
 * data with it before the evicted ones get to run. The caller holds the lwIP
 * mutex then.
 */
static void
session_kill (HevSocks5SessionData *sd, int release)
{
    if (sd->dying)
        return;

    if (release)
        hev_socks5_session_release (sd->self);
    else
        hev_socks5_session_terminate (sd->self);

    hev_list_del (session_list (sd->type), &sd->node);
    __atomic_store_n (&session_live_count[sd->type],
                      session_live_count[sd->type] - 1, __ATOMIC_RELAXED);
    if (sd->type != SESSION_DNS)
        session_count--;

    sd->dying = 1;
    hev_list_add_tail (&session_dying, &sd->node);
    __atomic_store_n (&session_dying_count, session_dying_count + 1,
                      __ATOMIC_RELAXED);
}

/*
 * A session is kept when room is made if upstream replied, it still talked
 * half of evict-protect-idle after it was created, and it has been silent for
 * less than evict-protect-idle: a flow with rare keep-alives outlives a surge
 * of new ones, a one-shot exchange like a DNS query doesn't. A lookup that
 * did not fit in the DNS pool is a one-shot flow even after its reply.
 */
static int
session_is_protected (HevSocks5SessionData *sd, int idle, int64_t now)
{
    if (!idle || !sd->answered || sd->lookup)
        return 0;

    return ((sd->active_time - sd->create_time) >= (idle / 2)) &&
           ((now - sd->active_time) < idle);
}

/*
 * A session upstream answered less than SESSION_EVICT_YOUNG_TIME after it was
 * created, like a TLS handshake after the server hello.
 */
static int
session_is_young (HevSocks5SessionData *sd, int idle, int64_t now)
{
    if (!idle || !sd->answered || sd->lookup)
        return 0;

    return (now - sd->create_time) < SESSION_EVICT_YOUNG_TIME;
}

/*
 * Evicts sessions of the type (SESSION_TYPES: either) from the table until
 * count of them is under limit, the least recently active first. Protected
 * sessions are kept up to half of limit, young ones in what is left of that
 * half, past that they go in the same order as the others. Returns the number
 * evicted. The caller holds the lwIP mutex.
 */
static int
session_make_room (int type, int count, int limit, int64_t now)
{
    int idle = hev_config_get_misc_evict_protect_idle ();
    int protected_over = 0;
    int young_over = 0;
    int evicted = 0;
    HevListNode *node;

    if (count < limit)
        return 0;

    if (idle) {
        int protected_count = 0;
        int young_count = 0;
        int half = limit / 2;

        node = hev_list_first (&session_set);
        for (; node; node = hev_list_node_next (node)) {
            HevSocks5SessionData *sd;

            sd = container_of (node, HevSocks5SessionData, node);
            if (type != SESSION_TYPES && sd->type != type)
                continue;
            if (session_is_protected (sd, idle, now))
                protected_count++;
            else if (session_is_young (sd, idle, now))
                young_count++;
        }

        protected_over = protected_count - half;
        if (protected_over < 0) {
            young_over = young_count + protected_count - half;
            protected_over = 0;
        } else {
            young_over = young_count;
        }
        __atomic_store_n (&stat_protected, protected_count, __ATOMIC_RELAXED);
    }

    node = hev_list_first (&session_set);
    while (node && (count >= limit)) {
        HevListNode *next = hev_list_node_next (node);
        HevSocks5SessionData *sd;

        sd = container_of (node, HevSocks5SessionData, node);
        node = next;
        if (type != SESSION_TYPES && sd->type != type)
            continue;
        if (session_is_protected (sd, idle, now)) {
            if (protected_over <= 0)
                continue;
            protected_over--;
        } else if (session_is_young (sd, idle, now)) {
            if (young_over <= 0)
                continue;
            young_over--;
        }

        stat_inc (&stat_evicted[sd->type]);
        session_kill (sd, 1);
        count--;
        evicted++;
    }

    return evicted;
}

static int
young_count (int64_t now, int young_ms)
{
    unsigned int i;
    int n = 0;

    for (i = 0; i < YOUNG_RING; i++) {
        int64_t t = young_ring[(young_head - 1 - i) % YOUNG_RING];

        if (!t || now - t >= young_ms)
            break;
        n++;
    }

    return n;
}

static void
probe_state_set (int state, int64_t now)
{
    int prev = probe_state;

    if (state == prev)
        return;

    __atomic_fetch_add (&probe_state_ms[prev],
                        now - __atomic_load_n (&probe_state_since,
                                               __ATOMIC_RELAXED),
                        __ATOMIC_RELAXED);
    __atomic_store_n (&probe_state_since, now, __ATOMIC_RELAXED);
    __atomic_store_n (&probe_state, state, __ATOMIC_RELAXED);
}

/*
 * Memory the process can still take, minus what sessions created in the last
 * young_ms are about to take: a new session reaches its full price only after
 * its upstream connection is up, later than the probe sees it.
 */
static int
probe_update (int64_t now)
{
    HevSocks5TunnelProbe *c = &probe_cur;
    int64_t avail_kb;
    int state, prev;

    if (now >= __atomic_load_n (&probe_next_ms, __ATOMIC_RELAXED)) {
        int64_t raw = -1;

        pthread_mutex_lock (&probe_mutex);
        *c = probe_conf;
        pthread_mutex_unlock (&probe_mutex);

        __atomic_store_n (&probe_next_ms,
                          now + (c->probe ? c->interval_ms : 1000),
                          __ATOMIC_RELAXED);
        if (c->probe)
            raw = c->probe (c->user_data);
        __atomic_store_n (&probe_last_kb, raw < 0 ? -1 : raw / 1024,
                          __ATOMIC_RELAXED);
    }

    avail_kb = __atomic_load_n (&probe_last_kb, __ATOMIC_RELAXED);
    prev = probe_state;
    if (!c->probe) {
        probe_state_set (HEV_SOCKS5_TUNNEL_ADMIT_OPEN, now);
        return HEV_SOCKS5_TUNNEL_ADMIT_OPEN;
    }
    if (avail_kb < 0)
        return prev;

    avail_kb -= (int64_t)young_count (now, c->young_ms) * c->young_reserve_kb;

    if (avail_kb < c->close_below_kb)
        state = HEV_SOCKS5_TUNNEL_ADMIT_CLOSED;
    else if (avail_kb < c->hold_below_kb)
        state = HEV_SOCKS5_TUNNEL_ADMIT_HOLD;
    else
        state = HEV_SOCKS5_TUNNEL_ADMIT_OPEN;

    if (state < prev) {
        if (prev == HEV_SOCKS5_TUNNEL_ADMIT_CLOSED &&
            avail_kb < c->close_below_kb + c->hysteresis_kb)
            state = HEV_SOCKS5_TUNNEL_ADMIT_CLOSED;
        else if (avail_kb < c->hold_below_kb + c->hysteresis_kb)
            state = HEV_SOCKS5_TUNNEL_ADMIT_HOLD;
    }

    if (state != prev) {
        LOG_W ("socks5 tunnel admission %d -> %d, available %lld KiB", prev,
               state, (long long)avail_kb);
        probe_state_set (state, now);
    }

    return state;
}

/* The probe state as it applies to one type. */
static int
admission_for (int type, int probe)
{
    if (probe == HEV_SOCKS5_TUNNEL_ADMIT_CLOSED &&
        !(__atomic_load_n (&probe_close_types, __ATOMIC_RELAXED) & (1 << type)))
        probe = HEV_SOCKS5_TUNNEL_ADMIT_HOLD;
    if (probe == HEV_SOCKS5_TUNNEL_ADMIT_HOLD &&
        !(__atomic_load_n (&probe_hold_types, __ATOMIC_RELAXED) & (1 << type)))
        probe = HEV_SOCKS5_TUNNEL_ADMIT_OPEN;

    return probe;
}

/*
 * Makes room for a new session before it is created, so that it can't evict
 * itself and max-session-count sessions can be open at once. A new session is
 * refused only while the memory probe is CLOSED for its type. In HOLD the
 * sessions of its type don't grow: it takes the place of one of them, chosen
 * as at max-session-count, so that a UDP surge does not close TCP connections.
 * The caller holds the lwIP mutex.
 */
static int
session_admit (int type)
{
    int64_t now = monotonic_ms ();
    int state, max;

    admit_replaced = 0;
    state = admission_for (type, probe_update (now));

    if (state >= HEV_SOCKS5_TUNNEL_ADMIT_CLOSED) {
        stat_inc (&stat_refused_adm[type]);
        stat_inc (&stat_refused[type]);
        return -1;
    }

    if (state == HEV_SOCKS5_TUNNEL_ADMIT_HOLD && session_live_count[type] &&
        session_make_room (type, session_live_count[type],
                           session_live_count[type], now))
        admit_replaced = 1;

    max = hev_config_get_misc_max_session_count ();
    if (max > 0 && session_make_room (SESSION_TYPES, session_count, max, now))
        admit_replaced = 1;

    return 0;
}

/*
 * A session waits while its query has no reply yet, up to the time a resolver
 * waits before it asks again. One that got a reply to every query is done: a
 * lookup socket is mostly used once, and a long-lived resolver socket that
 * asks again later simply gets a new session.
 */
static int
dns_session_waiting (HevSocks5SessionData *sd, int64_t now)
{
    if (!sd->answered)
        return now - sd->create_time < DNS_PRIORITY_GRACE_MS;
    if (!sd->pending)
        return 0;

    return now - sd->active_time < DNS_PRIORITY_GRACE_MS;
}

/*
 * Name lookups get a small pool outside the memory probe and the UDP cap: in
 * a storm of new flows a lookup would otherwise lose to the storm, and every
 * new connection of the user fails before it starts. A full pool gives up a
 * session that no longer waits for a reply. While all wait, the new query
 * does not get in: evicting them would let a flood of queries kill each one
 * before its reply. It then takes the ordinary UDP path, so a burst of
 * lookups larger than the pool, as when the tunnel starts, is limited by the
 * UDP cap and the memory probe and not dropped while there is room.
 */
static int
session_admit_dns (void)
{
    int64_t now = monotonic_ms ();
    HevListNode *node;
    int cap;

    admit_replaced = 0;
    cap = __atomic_load_n (&dns_priority_cap, __ATOMIC_RELAXED);
    if (session_live_count[SESSION_DNS] < cap)
        return 0;

    node = hev_list_first (&session_dns);
    for (; node; node = hev_list_node_next (node)) {
        HevSocks5SessionData *sd;

        sd = container_of (node, HevSocks5SessionData, node);
        if (dns_session_waiting (sd, now))
            continue;

        session_kill (sd, 1);
        stat_inc (&stat_evicted[SESSION_DNS]);
        admit_replaced = 1;
        return 0;
    }

    stat_inc (&stat_refused[SESSION_DNS]);
    return -1;
}

static int
dns_priority_match (const ip_addr_t *addr, u16_t port)
{
    uint32_t a;
    int i, n;

    if (port != DNS_PORT ||
        __atomic_load_n (&dns_priority_cap, __ATOMIC_ACQUIRE) <= 0)
        return 0;

    n = __atomic_load_n (&dns_priority_addr_count, __ATOMIC_RELAXED);
    if (!n)
        return 1;
    if (addr->type != IPADDR_TYPE_V4)
        return 0;

    a = ip_2_ip4 (addr)->addr;
    for (i = 0; i < n; i++)
        if (__atomic_load_n (&dns_priority_addr[i], __ATOMIC_RELAXED) == a)
            return 1;

    return 0;
}

/* Comma or space separated IPv4 addresses, at most DNS_PRIORITY_ADDRS. */
static int
dns_priority_parse (const char *list, uint32_t *addrs)
{
    char buf[256], *tok, *save;
    int n = 0;

    if (!list || !list[0])
        return -1;
    if (0 == strcmp (list, "any"))
        return 0;

    strncpy (buf, list, sizeof (buf) - 1);
    buf[sizeof (buf) - 1] = '\0';
    for (tok = strtok_r (buf, ", ", &save); tok;
         tok = strtok_r (NULL, ", ", &save)) {
        struct in_addr in;

        if (n == DNS_PRIORITY_ADDRS || inet_pton (AF_INET, tok, &in) != 1)
            return -1;
        addrs[n++] = in.s_addr;
    }

    return n ? n : -1;
}

/* The pool bypasses the memory probe, so its size stays small. */
static int
dns_priority_valid (int cap, int timeout_ms)
{
    return cap >= 0 && cap <= 32 && timeout_ms >= 1000 && timeout_ms <= 10000;
}

static void
dns_priority_store (int cap, int timeout_ms, const uint32_t *addrs, int n)
{
    int i;

    /* Off while the list changes: a half-written list must not match. */
    __atomic_store_n (&dns_priority_cap, 0, __ATOMIC_SEQ_CST);
    for (i = 0; i < n; i++)
        __atomic_store_n (&dns_priority_addr[i], addrs[i], __ATOMIC_RELAXED);
    __atomic_store_n (&dns_priority_addr_count, n, __ATOMIC_RELAXED);
    __atomic_store_n (&dns_priority_timeout_ms, timeout_ms, __ATOMIC_RELAXED);
    __atomic_store_n (&dns_priority_cap, cap, __ATOMIC_RELEASE);
}

static void
hev_socks5_tunnel_insert_session (HevListNode *node, int type, int lookup)
{
    HevSocks5SessionData *sd;

    sd = container_of (node, HevSocks5SessionData, node);
    sd->create_time = monotonic_ms ();
    sd->active_time = sd->create_time;
    sd->type = type;
    sd->dying = 0;
    sd->pending = 0;
    sd->lookup = lookup;
    sd->timeout = 0;
    sd->buffered = 0;
    sd->relaying = 0;
    if (lookup)
        sd->timeout =
            __atomic_load_n (&dns_priority_timeout_ms, __ATOMIC_RELAXED);

    hev_list_add_tail (session_list (sd->type), node);
    __atomic_store_n (&session_live_count[sd->type],
                      session_live_count[sd->type] + 1, __ATOMIC_RELAXED);
    /* The pool is outside the table, max-session-count does not count it. */
    if (sd->type != SESSION_DNS)
        session_count++;
    stat_inc (&stat_created[sd->type]);
    /*
     * A replacement frees the evicted session's memory as it takes its own,
     * so only net growth reserves memory for young sessions.
     */
    if (!admit_replaced)
        young_ring[young_head++ % YOUNG_RING] = sd->create_time;
    admit_replaced = 0;
}

static void
hev_socks5_tunnel_delete_session (HevListNode *node)
{
    HevSocks5SessionData *sd;

    sd = container_of (node, HevSocks5SessionData, node);
    if (sd->dying) {
        hev_list_del (&session_dying, node);
        __atomic_store_n (&session_dying_count, session_dying_count - 1,
                          __ATOMIC_RELAXED);
        return;
    }

    hev_list_del (session_list (sd->type), node);
    __atomic_store_n (&session_live_count[sd->type],
                      session_live_count[sd->type] - 1, __ATOMIC_RELAXED);
    if (sd->type != SESSION_DNS)
        session_count--;
}

void
hev_socks5_tunnel_update_session (HevListNode *node)
{
    HevSocks5SessionData *sd;

    sd = container_of (node, HevSocks5SessionData, node);
    sd->active_time = monotonic_ms ();

    if (sd->dying)
        return;

    hev_list_del (session_list (sd->type), node);
    hev_list_add_tail (session_list (sd->type), node);
}

/*
 * Buffer budget (misc.max-buffer-size), 0 means unlimited: then nothing is
 * charged, the sessions check hev_socks5_tunnel_buffer_limit first.
 *
 * The packets the sessions hold in lwIP are charged to buffer_used: the TCP
 * receive queues and the UDP datagram queues. Their size is bounded by:
 *
 *  - TCP: the receive window of each session, granted out of 3/4 of the
 *    budget, at least a fair share of it, and never less than what lwIP needs
 *    to announce a closed window again. A session that holds more than it is
 *    granted does not get its window reopened as far, until it is under.
 *  - UDP: datagrams are dropped while the budget is used up. The DNS pool is
 *    outside of it, its small queues are neither charged nor dropped.
 *
 * Only the window floors can overcommit it, by up to a floor for each session
 * that is receiving at once. Then the sessions that hold packets without any
 * progress for BUFFER_RECLAIM_IDLE_TIME are evicted, the least recently
 * active first, the ones that make progress keep going with smaller windows.
 * A session that was silent and just got a packet, like a keep-alive, has
 * not held it that long and is not one of them.
 */
void
hev_socks5_tunnel_buffer_charge (HevSocks5SessionData *sd, int size)
{
    if (size < 0 && -size > sd->buffered)
        size = -sd->buffered;

    if (!sd->buffered && size > 0)
        sd->held_time = monotonic_ms ();
    sd->buffered += size;
    /* Read by the stats from any thread. */
    __atomic_store_n (&buffer_used, buffer_used + size, __ATOMIC_RELAXED);
}

int
hev_socks5_tunnel_buffer_admit (int size)
{
    return (buffer_used + size) <= hev_socks5_tunnel_buffer_limit;
}

unsigned int
hev_socks5_tunnel_window_target (unsigned int window, unsigned int floor,
                                 unsigned int max)
{
    size_t limit, others, room, fair;

    limit = hev_socks5_tunnel_buffer_limit / 4 * 3;
    others = window_used - window;
    room = (limit > others) ? limit - others : 0;

    /* Sessions over their fair share give it back as they go. */
    fair = limit / (session_count + 1);
    if (room < fair)
        room = fair;

    if (room < floor)
        return floor;
    if (room > max)
        return max;
    return room;
}

void
hev_socks5_tunnel_window_set (unsigned int *window, unsigned int size)
{
    window_used += size;
    window_used -= *window;
    *window = size;
}

/* The caller holds the lwIP mutex. */
static void
hev_socks5_tunnel_reclaim (void)
{
    size_t limit = hev_socks5_tunnel_buffer_limit;
    HevListNode *node;
    int64_t now;
    size_t used;

    if (!limit || buffer_used <= limit)
        return;

    now = monotonic_ms ();
    used = buffer_used;
    node = hev_list_first (&session_set);
    while (node && used > limit / 4 * 3) {
        HevListNode *next = hev_list_node_next (node);
        HevSocks5SessionData *sd;

        sd = container_of (node, HevSocks5SessionData, node);
        /* In LRU order, the rest made progress more recently. */
        if ((now - sd->active_time) < BUFFER_RECLAIM_IDLE_TIME)
            break;
        if (sd->buffered > 0 &&
            (now - sd->held_time) >= BUFFER_RECLAIM_IDLE_TIME) {
            LOG_I ("%p socks5 tunnel buffer full, evict", sd->self);
            used -= sd->buffered;
            stat_inc (&stat_reclaimed);
            session_kill (sd, 1);
        }
        node = next;
    }
}

static void
hev_socks5_session_task_entry (void *data)
{
    HevSocks5Session *s = data;

    hev_socks5_session_run (s);

    hev_socks5_tunnel_delete_session (hev_socks5_session_get_node (s));
    hev_object_unref (HEV_OBJECT (s));
}

static void
tcp_pcb_set_gso (struct tcp_pcb *pcb)
{
    /* Leave room for IP and TCP headers within the 64K packet limit. */
    const unsigned int max = 65535 - 128;
    unsigned int n = (max + pcb->mss - 1) / pcb->mss;

    /*
     * Send super segments of n segments, the tunnel device segments them
     * into packets of gso_mss on demand (GSO), or they are delivered as is
     * (jumbo). The segments are shrunk evenly to fill up the 64K limit, so
     * a 64K buffer goes out as one packet instead of a full and a small one.
     */
    pcb->gso_mss = max / n;
    pcb->mss = n * pcb->gso_mss;
}

static err_t
tcp_accept_handler (void *arg, struct tcp_pcb *pcb, err_t err)
{
    HevSocks5SessionTCP *tcp;
    HevListNode *node;
    int stack_size;
    HevTask *task;

    if (err != ERR_OK)
        return err;

    if (!READ_ONCE (run))
        return ERR_RST;

    /*
     * The task goes first: the session can't be destroyed here, its destructor
     * takes the mutex that is held while lwIP calls us. Admission may evict a
     * session, so it goes after the allocation too.
     */
    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task)
        return ERR_MEM;

    /* lwIP aborts the connection and the app gets a reset. */
    if (session_admit (SESSION_TCP) < 0) {
        hev_task_unref (task);
        return ERR_RST;
    }

    /* Before the session sizes its receive window, it depends on the mss. */
    if (hev_tunnel_get_offload () &
        (HEV_TUNNEL_OFFLOAD_TCP | HEV_TUNNEL_OFFLOAD_JUMBO))
        tcp_pcb_set_gso (pcb);

    tcp = hev_socks5_session_tcp_new (pcb, &mutex);
    if (!tcp) {
        hev_task_unref (task);
        return ERR_MEM;
    }

    hev_socks5_session_set_task (HEV_SOCKS5_SESSION (tcp), task);
    node = hev_socks5_session_get_node (HEV_SOCKS5_SESSION (tcp));
    hev_socks5_tunnel_insert_session (node, SESSION_TCP, 0);
    hev_task_run (task, hev_socks5_session_task_entry, tcp);
    hev_task_wakeup (task_lwip_timer);

    return ERR_OK;
}

static void
dns_recv_handler (void *arg, struct udp_pcb *pcb, struct pbuf *p,
                  const ip_addr_t *addr, u16_t port)
{
    HevMappedDNS *dns = arg;
    struct pbuf *b;
    int res;

    LOG_D ("%p mapped dns handle", dns);

    b = pbuf_alloc (PBUF_TRANSPORT, UDP_BUF_SIZE, PBUF_RAM);
    if (!b)
        goto exit;

    res = hev_mapped_dns_handle (dns, p->payload, p->len, b->payload, b->len);
    if (res < 0)
        goto free;

    b->len = res;
    b->tot_len = res;
    udp_sendfrom (pcb, b, &pcb->local_ip, pcb->local_port);

free:
    pbuf_free (b);
exit:
    pbuf_free (p);
    udp_recv (pcb, NULL, NULL);
    udp_remove (pcb);
}

/*
 * The datagram that created the pcb is delivered to it after we return. The
 * pcb must not be removed before, lwIP would create a new one for it again.
 */
static void
udp_drop_handler (void *arg, struct udp_pcb *pcb, struct pbuf *p,
                  const ip_addr_t *addr, u16_t port)
{
    pbuf_free (p);
    udp_recv (pcb, NULL, NULL);
    udp_remove (pcb);
}

static void
udp_recv_handler (void *arg, struct udp_pcb *pcb, struct pbuf *p,
                  const ip_addr_t *addr, u16_t port)
{
    HevSocks5SessionUDP *udp;
    HevListNode *node;
    HevMappedDNS *dns;
    int stack_size;
    HevTask *task;
    int type, lookup, overflow;

    if (!READ_ONCE (run)) {
        udp_recv (pcb, udp_drop_handler, NULL);
        return;
    }

    dns = hev_mapped_dns_get ();
    if (dns && addr->type == IPADDR_TYPE_V4) {
        int faddr = hev_config_get_mapdns_address ();
        int fport = hev_config_get_mapdns_port ();
        if (fport == port && faddr == ip_2_ip4 (addr)->addr) {
            udp_recv (pcb, dns_recv_handler, dns);
            return;
        }
    }

    /* As for TCP, the session can't be destroyed here. */
    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
        udp_recv (pcb, udp_drop_handler, NULL);
        return;
    }

    /* Admission may evict a session, so it goes after the allocation. */
    type = SESSION_UDP;
    overflow = 0;
    lookup = dns_priority_match (addr, port);
    if (lookup) {
        if (session_admit_dns () == 0)
            type = SESSION_DNS;
        else
            overflow = 1;
    }
    if (type == SESSION_UDP && session_admit (SESSION_UDP) < 0) {
        hev_task_unref (task);
        udp_recv (pcb, udp_drop_handler, NULL);
        return;
    }

    udp = hev_socks5_session_udp_new (pcb, &mutex);
    if (!udp) {
        hev_task_unref (task);
        udp_recv (pcb, udp_drop_handler, NULL);
        return;
    }

    hev_socks5_session_set_task (HEV_SOCKS5_SESSION (udp), task);
    node = hev_socks5_session_get_node (HEV_SOCKS5_SESSION (udp));
    hev_socks5_tunnel_insert_session (node, type, lookup);
    if (overflow)
        stat_inc (&stat_dns_overflow);
    hev_task_run (task, hev_socks5_session_task_entry, udp);
    hev_task_wakeup (task_lwip_timer);
}

static void
relieve_sessions (const HevSocks5TunnelRelief *relief)
{
    int64_t now = monotonic_ms ();
    int closed[SESSION_TYPES] = { 0 };
    int total = session_count;
    HevListNode *node;

    hev_task_mutex_lock (&mutex);

    /* The table is least recently active first: max_count picks the quietest. */
    node = hev_list_first (&session_set);
    while (node) {
        HevListNode *next = hev_list_node_next (node);
        HevSocks5SessionData *sd;

        if (relief->max_count &&
            (closed[SESSION_UDP] + closed[SESSION_TCP]) >= relief->max_count)
            break;

        sd = container_of (node, HevSocks5SessionData, node);
        if (now - sd->active_time < relief->idle_ms)
            break;
        if (relief->types & (1 << sd->type)) {
            closed[sd->type]++;
            stat_inc (&stat_relieved[sd->type]);
            session_kill (sd, 1);
        }
        node = next;
    }

    hev_task_mutex_unlock (&mutex);

    LOG_W ("socks5 tunnel relieve types %d idle %d max %d: udp %d tcp %d of %d",
           relief->types, relief->idle_ms, relief->max_count,
           closed[SESSION_UDP], closed[SESSION_TCP], total);
}

static void
relief_task_entry (void *data)
{
    LOG_D ("socks5 tunnel relief task run");

    hev_task_add_fd (task_relief, relief_fds[0], POLLIN);

    for (;;) {
        HevSocks5TunnelRelief relief;
        ssize_t res;

        res = hev_task_io_read (relief_fds[0], &relief, sizeof (relief),
                                task_io_yielder, NULL);
        if (res != sizeof (relief))
            break;

        relieve_sessions (&relief);
    }

    hev_task_del_fd (task_relief, relief_fds[0]);
}

static void
event_task_entry (void *data)
{
    int val, i;

    LOG_D ("socks5 tunnel event task run");

    hev_task_add_fd (task_event, event_fds[0], POLLIN);

    hev_task_io_read (event_fds[0], &val, sizeof (val), NULL, NULL);

    WRITE_ONCE (run, 0);
    atomic_fetch_and (&tsync, ~SYNC_SENT);
    hev_task_wakeup (task_relief);
    for (i = 0; i < 2; i++) {
        HevList *list = i ? &session_dns : &session_set;
        HevListNode *node;

        while ((node = hev_list_first (list)))
            session_kill (container_of (node, HevSocks5SessionData, node), 0);
    }

    hev_task_join (task_lwip_io);
    hev_task_join (task_lwip_timer);
    hev_task_join (task_relief);
    hev_task_del_fd (task_event, event_fds[0]);
}

/*
 * Packets are read into MTU-sized pbufs. The ones that are queued by a
 * session would pin the whole buffer, so small packets are moved into a
 * pbuf that fits them.
 */
static struct pbuf *
tunnel_compact_pbuf (struct pbuf *buf)
{
    struct pbuf *p;

    if (buf->next || (buf->tot_len > COMPACT_PBUF_SIZE))
        return buf;

    p = pbuf_alloc (PBUF_RAW, buf->tot_len, PBUF_RAM);
    if (!p)
        return buf;

    memcpy (p->payload, buf->payload, buf->tot_len);
    pbuf_free (buf);

    return p;
}

static void
lwip_io_task_entry (void *data)
{
    const unsigned int mtu = hev_config_get_tunnel_mtu ();
    unsigned int i;

    LOG_D ("socks5 tunnel lwip task run");

    hev_tunnel_add_task (tun_fd, task_lwip_io);

    for (i = 0; READ_ONCE (run);) {
        struct pbuf *buf;
        uint8_t *data;

        buf = hev_tunnel_read (tun_fd, mtu, task_io_yielder, NULL);
        if (!buf)
            continue;

        stat_tx_packets++;
        stat_tx_bytes += buf->tot_len;

        buf = tunnel_compact_pbuf (buf);

        data = buf->payload;
        if ((data[0] >> 4) == 4 ? (data[9] == IP_PROTO_UDP) :
                                  (data[6] == IP_PROTO_UDP))
            i++;

        hev_task_mutex_lock (&mutex);
        if (netif->input (buf, netif) != ERR_OK)
            pbuf_free (buf);
        hev_task_mutex_unlock (&mutex);

        /*
         * Let the UDP sessions forward what has been received so far, instead
         * of reading packets that will be dropped by full session queues.
         */
        if (i >= TUN_READ_BATCH) {
            hev_task_yield (HEV_TASK_YIELD);
            i = 0;
        }
    }

    hev_tunnel_del_task (tun_fd, task_lwip_io);
}

static void
lwip_timer_task_entry (void *data)
{
    unsigned int i;

    LOG_D ("socks5 tunnel timer task run");

    for (i = 1; READ_ONCE (run); i++) {
        hev_task_mutex_lock (&mutex);
        tcp_tmr ();
        hev_socks5_tunnel_reclaim ();

        if ((i & 3) == 0) {
#if IP_REASSEMBLY
            ip_reass_tmr ();
#endif
#if LWIP_IPV6
            nd6_tmr ();
#if LWIP_IPV6_REASS
            ip6_reass_tmr ();
#endif
#endif
        }
        hev_task_mutex_unlock (&mutex);

        if (!sessions_empty ()) {
            /* Keeps admission and stats current while no session is new. */
            probe_update (monotonic_ms ());
            hev_task_sleep (TCP_TMR_INTERVAL);
        } else {
#if defined(__GLIBC__) && !defined(ENABLE_LIBRARY)
            /* Release free memory from the heap */
            malloc_trim (0);
#endif
            hev_task_yield (HEV_TASK_WAITIO);
        }
    }
}

static int
tunnel_init (int extern_tun_fd)
{
    const char *script_path, *name, *guid, *ipv4, *ipv6;
    int multi_queue, offload, res;
    unsigned int mtu;

    offload = hev_config_get_tunnel_offload ();

    if (extern_tun_fd >= 0) {
#ifndef _WIN32
        int nonblock = 1;

        res = ioctl (extern_tun_fd, FIONBIO, (char *)&nonblock);
        if (res < 0) {
            LOG_E ("socks5 tunnel non-blocking");
            return -1;
        }
#endif

        tun_fd = extern_tun_fd;
        hev_tunnel_set_offload (tun_fd, offload);
        return 0;
    }

    tun_fd_local = 1;
    name = hev_config_get_tunnel_name ();
    multi_queue = hev_config_get_tunnel_multi_queue ();
    guid = hev_config_get_tunnel_guid ();
    tun_fd = hev_tunnel_open (name, multi_queue, guid);
    if (tun_fd < 0) {
        LOG_E ("socks5 tunnel open (%s)", strerror (errno));
        return -1;
    }
    hev_tunnel_set_offload (tun_fd, offload);

    mtu = hev_config_get_tunnel_mtu ();
    res = hev_tunnel_set_mtu (mtu);
    if (res < 0) {
        LOG_E ("socks5 tunnel mtu");
        return -1;
    }

    ipv4 = hev_config_get_tunnel_ipv4_address ();
    if (ipv4) {
        res = hev_tunnel_set_ipv4 (ipv4, 32);
        if (res < 0) {
            LOG_E ("socks5 tunnel ipv4");
            return -1;
        }
    }

    ipv6 = hev_config_get_tunnel_ipv6_address ();
    if (ipv6) {
        res = hev_tunnel_set_ipv6 (ipv6, 128);
        if (res < 0) {
            LOG_E ("socks5 tunnel ipv6");
            return -1;
        }
    }

    res = hev_tunnel_set_state (1);
    if (res < 0) {
        LOG_E ("socks5 tunnel state");
        return -1;
    }

    script_path = hev_config_get_tunnel_post_up_script ();
    if (script_path)
        hev_exec_run (script_path, hev_tunnel_get_name (),
                      hev_tunnel_get_index (), 0);

    return 0;
}

static void
tunnel_fini (void)
{
    const char *script_path;

    if (!tun_fd_local) {
        /* The fd belongs to the caller, only release what we hold for it. */
        hev_tunnel_set_offload (-1, 0);
        tun_fd = -1;
        return;
    }

    script_path = hev_config_get_tunnel_pre_down_script ();
    if (script_path)
        hev_exec_run (script_path, hev_tunnel_get_name (),
                      hev_tunnel_get_index (), 1);

    if (tun_fd >= 0) {
        hev_tunnel_close (tun_fd);
        tun_fd_local = 0;
        tun_fd = -1;
    }
}

static int
gateway_init (void)
{
    static struct netif _netif;
    ip4_addr_t addr4, mask, gw;
    ip6_addr_t addr6;

    netif = netif_add_noaddr (&_netif, NULL, netif_init_handler, ip_input);
    if (!netif) {
        LOG_E ("socks5 tunnel netif");
        return -1;
    }

    ip4_addr_set_loopback (&addr4);
    ip4_addr_set_any (&mask);
    ip4_addr_set_any (&gw);
    netif_set_addr (netif, &addr4, &mask, &gw);

    ip6_addr_set_loopback (&addr6);
    netif_add_ip6_address (netif, &addr6, NULL);

    netif_set_up (netif);
    netif_set_link_up (netif);
    netif_set_default (netif);
    netif_set_flags (netif, NETIF_FLAG_PRETEND_TCP);
    netif_set_flags (netif, NETIF_FLAG_PRETEND_UDP);

    if (hev_tunnel_get_offload () & HEV_TUNNEL_OFFLOAD_CSUM)
        NETIF_SET_CHECKSUM_CTRL (netif, NETIF_CHECKSUM_ENABLE_ALL &
                                            ~(NETIF_CHECKSUM_GEN_TCP |
                                              NETIF_CHECKSUM_GEN_UDP));

    if (hev_config_get_tunnel_icmp ())
        netif_set_flags (netif, NETIF_FLAG_PRETEND_ICMP);

    tcp = tcp_new_ip_type (IPADDR_TYPE_ANY);
    if (!tcp) {
        LOG_E ("socks5 tunnel tcp");
        return -1;
    }

    tcp_bind_netif (tcp, netif);
    tcp_bind (tcp, NULL, 0);
    tcp = tcp_listen (tcp);
    tcp_accept (tcp, tcp_accept_handler);

    udp = udp_new_ip_type (IPADDR_TYPE_ANY);
    if (!udp) {
        LOG_E ("socks5 tunnel udp");
        return -1;
    }

    udp_bind_netif (udp, netif);
    udp_bind (udp, NULL, 0);
    udp_recv (udp, udp_recv_handler, NULL);

    return 0;
}

static void
gateway_fini (void)
{
    if (udp) {
        udp_remove (udp);
        udp = NULL;
    }
    if (tcp) {
        tcp_close (tcp);
        tcp = NULL;
    }
    if (netif) {
        netif_remove (netif);
        netif = NULL;
    }
}

static int
event_task_init (void)
{
    int res;

    res = hev_task_io_socket_socketpair (PF_LOCAL, SOCK_STREAM, 0, event_fds);
    if (res < 0) {
        LOG_E ("socks5 tunnel event");
        return -1;
    }

    if ((hev_task_io_fcntl (event_fds[0], F_SETFD, FD_CLOEXEC) < 0) ||
        (hev_task_io_fcntl (event_fds[1], F_SETFD, FD_CLOEXEC) < 0)) {
        LOG_E ("socks5 tunnel event cloexec");
        return -1;
    }

    task_event = hev_task_new (-1);
    if (!task_event) {
        LOG_E ("socks5 tunnel task event");
        return -1;
    }

    return 0;
}

static void
event_task_fini (void)
{
    if (task_event) {
        hev_task_unref (task_event);
        task_event = NULL;
    }

    if (event_fds[0] >= 0) {
        hev_task_io_close (event_fds[0]);
        event_fds[0] = -1;
    }
    if (event_fds[1] >= 0) {
        hev_task_io_close (event_fds[1]);
        event_fds[1] = -1;
    }
}

static int
relief_task_init (void)
{
    int fds[2];
    int res;

    res = hev_task_io_socket_socketpair (PF_LOCAL, SOCK_STREAM, 0, fds);
    if (res < 0) {
        LOG_E ("socks5 tunnel relief");
        return -1;
    }

    pthread_mutex_lock (&relief_mutex);
    relief_fds[0] = fds[0];
    relief_fds[1] = fds[1];
    pthread_mutex_unlock (&relief_mutex);

    if ((hev_task_io_fcntl (relief_fds[0], F_SETFD, FD_CLOEXEC) < 0) ||
        (hev_task_io_fcntl (relief_fds[1], F_SETFD, FD_CLOEXEC) < 0)) {
        LOG_E ("socks5 tunnel relief cloexec");
        return -1;
    }

    task_relief = hev_task_new (-1);
    if (!task_relief) {
        LOG_E ("socks5 tunnel task relief");
        return -1;
    }

    return 0;
}

static void
relief_task_fini (void)
{
    if (task_relief) {
        hev_task_unref (task_relief);
        task_relief = NULL;
    }

    /* Under the lock: a concurrent relieve must not write to a closed fd. */
    pthread_mutex_lock (&relief_mutex);
    if (relief_fds[0] >= 0) {
        hev_task_io_close (relief_fds[0]);
        relief_fds[0] = -1;
    }
    if (relief_fds[1] >= 0) {
        hev_task_io_close (relief_fds[1]);
        relief_fds[1] = -1;
    }
    pthread_mutex_unlock (&relief_mutex);
}

static int
lwip_io_task_init (void)
{
    task_lwip_io = hev_task_new (-1);
    if (!task_lwip_io) {
        LOG_E ("socks5 tunnel task lwip");
        return -1;
    }
    hev_task_set_priority (task_lwip_io, 1);

    return 0;
}

static void
lwip_io_task_fini (void)
{
    if (task_lwip_io) {
        hev_task_unref (task_lwip_io);
        task_lwip_io = NULL;
    }
}

static int
lwip_timer_task_init (void)
{
    task_lwip_timer = hev_task_new (-1);
    if (!task_lwip_timer) {
        LOG_E ("socks5 tunnel task timer");
        return -1;
    }
    hev_task_set_priority (task_lwip_timer, 1);

    return 0;
}

static void
lwip_timer_task_fini (void)
{
    if (task_lwip_timer) {
        hev_task_unref (task_lwip_timer);
        task_lwip_timer = NULL;
    }
}

static int
mapped_dns_init (void)
{
    HevMappedDNS *dns;
    int cache_size;
    int network;
    int netmask;

    network = hev_config_get_mapdns_network ();
    netmask = hev_config_get_mapdns_netmask ();
    cache_size = hev_config_get_mapdns_cache_size ();

    if (!cache_size)
        return 0;

    dns = hev_mapped_dns_new (network, netmask, cache_size);
    if (!dns)
        return -1;

    hev_mapped_dns_put (dns);

    return 0;
}

static void
mapped_dns_fini (void)
{
    HevMappedDNS *dns;

    dns = hev_mapped_dns_get ();
    if (dns) {
        hev_object_unref (HEV_OBJECT (dns));
        hev_mapped_dns_put (NULL);
    }
}

static void
session_limits_init (void)
{
    uint32_t addrs[DNS_PRIORITY_ADDRS];
    int i, n, cap;

    hev_socks5_tunnel_buffer_limit = hev_config_get_misc_max_buffer_size ();
    buffer_used = 0;
    window_used = 0;
    __atomic_store_n (&stat_reclaimed, 0, __ATOMIC_RELAXED);
    __atomic_store_n (&stat_protected, 0, __ATOMIC_RELAXED);

    hev_socks5_session_udp_reset_queue_stats ();

    __atomic_store_n (&probe_state, HEV_SOCKS5_TUNNEL_ADMIT_OPEN,
                      __ATOMIC_RELAXED);
    for (i = 0; i <= HEV_SOCKS5_TUNNEL_ADMIT_CLOSED; i++)
        __atomic_store_n (&probe_state_ms[i], 0, __ATOMIC_RELAXED);
    __atomic_store_n (&probe_state_since, monotonic_ms (), __ATOMIC_RELAXED);
    __atomic_store_n (&probe_last_kb, -1, __ATOMIC_RELAXED);
    __atomic_store_n (&probe_next_ms, 0, __ATOMIC_RELAXED);
    memset (young_ring, 0, sizeof (young_ring));
    __atomic_store_n (&stat_dns_overflow, 0, __ATOMIC_RELAXED);

    cap = hev_config_get_misc_dns_priority_sessions ();
    n = dns_priority_parse (hev_config_get_misc_dns_priority_addresses (),
                            addrs);
    if (cap && n < 0) {
        LOG_E ("socks5 tunnel dns-priority-addresses invalid, pool off");
        cap = 0;
        n = 0;
    }
    if (!dns_priority_valid (cap,
                             hev_config_get_misc_dns_priority_timeout ())) {
        LOG_E ("socks5 tunnel dns-priority size or timeout out of range, "
               "pool off");
        cap = 0;
    }
    dns_priority_store (cap, hev_config_get_misc_dns_priority_timeout (), addrs,
                        n);

    for (i = 0; i < SESSION_TYPES; i++) {
        __atomic_store_n (&stat_refused_adm[i], 0, __ATOMIC_RELAXED);
        __atomic_store_n (&stat_created[i], 0, __ATOMIC_RELAXED);
        __atomic_store_n (&stat_evicted[i], 0, __ATOMIC_RELAXED);
        __atomic_store_n (&stat_refused[i], 0, __ATOMIC_RELAXED);
        __atomic_store_n (&stat_relieved[i], 0, __ATOMIC_RELAXED);
    }

    __atomic_store_n (&stats_ready, 1, __ATOMIC_RELEASE);
}

int
hev_socks5_tunnel_init (int tun_fd)
{
    int res;

    LOG_D ("socks5 tunnel init");

    session_limits_init ();

    res = tunnel_init (tun_fd);
    if (res < 0)
        goto exit;

    res = gateway_init ();
    if (res < 0)
        goto exit;

    res = event_task_init ();
    if (res < 0)
        goto exit;

    res = relief_task_init ();
    if (res < 0)
        goto exit;

    res = lwip_io_task_init ();
    if (res < 0)
        goto exit;

    res = lwip_timer_task_init ();
    if (res < 0)
        goto exit;

    res = mapped_dns_init ();
    if (res < 0)
        goto exit;

#ifdef SIGPIPE
    signal (SIGPIPE, SIG_IGN);
#endif

    hev_task_mutex_init (&mutex);

    atomic_fetch_or (&tsync, SYNC_SEND);

    return 0;

exit:
    hev_socks5_tunnel_fini ();
    return -1;
}

void
hev_socks5_tunnel_fini (void)
{
    LOG_D ("socks5 tunnel fini");

    __atomic_store_n (&stats_ready, 0, __ATOMIC_RELAXED);

retry:
    if (atomic_fetch_and (&tsync, ~(SYNC_SEND | SYNC_SENT)) & SYNC_WAIT) {
        usleep (500);
        goto retry;
    }

    mapped_dns_fini ();
    lwip_timer_task_fini ();
    lwip_io_task_fini ();
    relief_task_fini ();
    event_task_fini ();
    gateway_fini ();
    tunnel_fini ();

    stat_tx_packets = 0;
    stat_rx_packets = 0;
    stat_tx_bytes = 0;
    stat_rx_bytes = 0;
}

int
hev_socks5_tunnel_run (void)
{
    LOG_D ("socks5 tunnel run");

    if (atomic_fetch_and (&tsync, ~SYNC_STOP) & SYNC_STOP)
        return 0;

    task_event = hev_task_ref (task_event);
    hev_task_run (task_event, event_task_entry, NULL);

    task_lwip_io = hev_task_ref (task_lwip_io);
    hev_task_run (task_lwip_io, lwip_io_task_entry, NULL);

    task_lwip_timer = hev_task_ref (task_lwip_timer);
    hev_task_run (task_lwip_timer, lwip_timer_task_entry, NULL);

    task_relief = hev_task_ref (task_relief);
    hev_task_run (task_relief, relief_task_entry, NULL);

    WRITE_ONCE (run, 1);
    hev_task_system_run ();

    return 0;
}

void
hev_socks5_tunnel_stop (void)
{
    int res;

    LOG_D ("socks5 tunnel stop");

retry:
    res = atomic_fetch_or (&tsync, SYNC_WAIT);
    if (res & SYNC_WAIT) {
        usleep (500);
        goto retry;
    }

    if (res & SYNC_SEND) {
        res = atomic_fetch_or (&tsync, SYNC_SENT);
        if (!(res & SYNC_SENT)) {
            res = hev_task_io_write (event_fds[1], &res, 1, hev_task_io_nowait,
                                     NULL);
            assert (res > 0 && "socks5 tunnel write event");
        }
    } else {
        atomic_fetch_or (&tsync, SYNC_STOP);
    }

    atomic_fetch_and (&tsync, ~SYNC_WAIT);
}

int
hev_socks5_tunnel_relieve (int types, int idle_ms, int max_count)
{
    HevSocks5TunnelRelief relief = { types, idle_ms, max_count };
    ssize_t res = -1;

    if (types & ~(HEV_SOCKS5_TUNNEL_RELIEF_UDP | HEV_SOCKS5_TUNNEL_RELIEF_TCP))
        return -1;

    pthread_mutex_lock (&relief_mutex);
    if (relief_fds[1] >= 0)
        res = hev_task_io_write (relief_fds[1], &relief, sizeof (relief),
                                 hev_task_io_nowait, NULL);
    pthread_mutex_unlock (&relief_mutex);

    if (res != sizeof (relief))
        return -1;

    return 0;
}

int
hev_socks5_tunnel_set_memory_probe_types (int hold_types, int close_types)
{
    int all = HEV_SOCKS5_TUNNEL_SESSION_UDP | HEV_SOCKS5_TUNNEL_SESSION_TCP;

    if ((hold_types & ~all) || (close_types & ~all))
        return -1;

    __atomic_store_n (&probe_hold_types, hold_types, __ATOMIC_RELAXED);
    __atomic_store_n (&probe_close_types, close_types, __ATOMIC_RELAXED);

    return 0;
}

int
hev_socks5_tunnel_set_memory_probe (HevSocks5TunnelMemoryProbe probe,
                                    void *user_data, int interval_ms,
                                    int hold_below_kb, int close_below_kb,
                                    int hysteresis_kb, int young_ms,
                                    int young_reserve_kb)
{
    HevSocks5TunnelProbe c = { probe,         user_data,       interval_ms,
                               hold_below_kb, close_below_kb,  hysteresis_kb,
                               young_ms,      young_reserve_kb };

    if (probe && (close_below_kb < 0 || hold_below_kb < close_below_kb ||
                  hysteresis_kb < 0 || young_ms < 0 || young_reserve_kb < 0))
        return -1;

    if (c.interval_ms <= 0)
        c.interval_ms = 50;

    pthread_mutex_lock (&probe_mutex);
    probe_conf = c;
    pthread_mutex_unlock (&probe_mutex);
    if (!probe)
        __atomic_store_n (&probe_last_kb, -1, __ATOMIC_RELAXED);
    __atomic_store_n (&probe_next_ms, 0, __ATOMIC_RELAXED);

    return 0;
}

int
hev_socks5_tunnel_get_session_stats (HevSocks5TunnelSessionStats *stats)
{
    HevSocks5TunnelSessionStats s;
    int admission[SESSION_TYPES];
    int i;

    if (!stats ||
        stats->size < offsetof (HevSocks5TunnelSessionStats, dns_live) ||
        !__atomic_load_n (&stats_ready, __ATOMIC_ACQUIRE))
        return -1;

    memset (&s, 0, sizeof (s));
    s.size = sizeof (s);
    s.udp_live =
        __atomic_load_n (&session_live_count[SESSION_UDP], __ATOMIC_RELAXED);
    s.tcp_live =
        __atomic_load_n (&session_live_count[SESSION_TCP], __ATOMIC_RELAXED);
    s.dying = __atomic_load_n (&session_dying_count, __ATOMIC_RELAXED);
    s.udp_created =
        __atomic_load_n (&stat_created[SESSION_UDP], __ATOMIC_RELAXED);
    s.tcp_created =
        __atomic_load_n (&stat_created[SESSION_TCP], __ATOMIC_RELAXED);
    s.udp_evicted =
        __atomic_load_n (&stat_evicted[SESSION_UDP], __ATOMIC_RELAXED);
    s.tcp_evicted =
        __atomic_load_n (&stat_evicted[SESSION_TCP], __ATOMIC_RELAXED);
    s.udp_refused =
        __atomic_load_n (&stat_refused[SESSION_UDP], __ATOMIC_RELAXED);
    s.tcp_refused =
        __atomic_load_n (&stat_refused[SESSION_TCP], __ATOMIC_RELAXED);
    s.udp_relieved =
        __atomic_load_n (&stat_relieved[SESSION_UDP], __ATOMIC_RELAXED);
    s.tcp_relieved =
        __atomic_load_n (&stat_relieved[SESSION_TCP], __ATOMIC_RELAXED);
    s.last_probe_kb = __atomic_load_n (&probe_last_kb, __ATOMIC_RELAXED);
    s.udp_queued_frames = hev_socks5_session_udp_get_queued_frames ();
    s.udp_queue_dropped = hev_socks5_session_udp_get_queue_dropped ();
    s.udp_refused_adm =
        __atomic_load_n (&stat_refused_adm[SESSION_UDP], __ATOMIC_RELAXED);
    s.tcp_refused_adm =
        __atomic_load_n (&stat_refused_adm[SESSION_TCP], __ATOMIC_RELAXED);
    for (i = 0; i < SESSION_TYPES; i++)
        admission[i] =
            admission_for (i, __atomic_load_n (&probe_state, __ATOMIC_RELAXED));
    s.admission_udp = admission[SESSION_UDP];
    s.admission_tcp = admission[SESSION_TCP];
    for (i = HEV_SOCKS5_TUNNEL_ADMIT_HOLD; i <= HEV_SOCKS5_TUNNEL_ADMIT_CLOSED;
         i++) {
        int64_t ms = __atomic_load_n (&probe_state_ms[i], __ATOMIC_RELAXED);

        if (__atomic_load_n (&probe_state, __ATOMIC_RELAXED) == i)
            ms += monotonic_ms () -
                  __atomic_load_n (&probe_state_since, __ATOMIC_RELAXED);
        if (i == HEV_SOCKS5_TUNNEL_ADMIT_HOLD)
            s.probe_hold_ms = ms;
        else
            s.probe_closed_ms = ms;
    }
    s.dns_live =
        __atomic_load_n (&session_live_count[SESSION_DNS], __ATOMIC_RELAXED);
    s.dns_cap = __atomic_load_n (&dns_priority_cap, __ATOMIC_RELAXED);
    s.dns_created =
        __atomic_load_n (&stat_created[SESSION_DNS], __ATOMIC_RELAXED);
    s.dns_evicted =
        __atomic_load_n (&stat_evicted[SESSION_DNS], __ATOMIC_RELAXED);
    s.dns_refused =
        __atomic_load_n (&stat_refused[SESSION_DNS], __ATOMIC_RELAXED);
    s.dns_overflow = __atomic_load_n (&stat_dns_overflow, __ATOMIC_RELAXED);
    s.max_session_count = hev_config_get_misc_max_session_count ();
    s.buffer_limit = hev_socks5_tunnel_buffer_limit;
    s.buffer_used = __atomic_load_n (&buffer_used, __ATOMIC_RELAXED);
    s.buffer_reclaimed = __atomic_load_n (&stat_reclaimed, __ATOMIC_RELAXED);
    s.protected_live = __atomic_load_n (&stat_protected, __ATOMIC_RELAXED);

    /* A caller built against an older, shorter struct gets the fields it knows. */
    s.size = stats->size < sizeof (s) ? stats->size : sizeof (s);
    memcpy (stats, &s, s.size);

    return 0;
}

EXPORT_SYMBOL void
hev_socks5_tunnel_stats (size_t *tx_packets, size_t *tx_bytes,
                         size_t *rx_packets, size_t *rx_bytes)
{
    LOG_D ("socks5 tunnel stats");

    if (tx_packets)
        *tx_packets = stat_tx_packets;

    if (tx_bytes)
        *tx_bytes = stat_tx_bytes;

    if (rx_packets)
        *rx_packets = stat_rx_packets;

    if (rx_bytes)
        *rx_bytes = stat_rx_bytes;
}
