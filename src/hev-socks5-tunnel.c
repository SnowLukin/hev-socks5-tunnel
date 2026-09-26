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
#include <sys/ioctl.h>

#include <lwip/tcp.h>
#include <lwip/udp.h>
#include <lwip/nd6.h>
#include <lwip/netif.h>
#include <lwip/ip4_frag.h>
#include <lwip/ip6_frag.h>
#include <lwip/priv/tcp_priv.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-mutex.h>
#include <hev-task-system.h>
#include <hev-memory-allocator.h>

#include "hev-exec.h"
#include "hev-config.h"
#include "hev-logger.h"
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

enum
{
    SESSION_UDP,
    SESSION_TCP,
    SESSION_TYPES,
};

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

/* Live sessions per type, least recently active first. */
static HevList session_live[SESSION_TYPES];
static int session_live_count[SESSION_TYPES];
/* Closed sessions whose task has not exited yet. */
static HevList session_dying;
static int session_dying_count;

/* Written from any thread, read by the tunnel thread. */
static int session_cap[SESSION_TYPES];
static int session_evict_idle_ms[SESSION_TYPES];
static int session_protect_age_ms[SESSION_TYPES];
static int session_protect_idle_ms[SESSION_TYPES];
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

/* HEV_SOCKS5_TUNNEL_ADMIT_* set from outside. */
static int admission_ext[SESSION_TYPES];

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

#define YOUNG_RING 128
static int64_t young_ring[YOUNG_RING];
static unsigned int young_head;

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
session_type_of (HevSocks5SessionData *sd)
{
    if (HEV_OBJECT (sd->self)->klass == HEV_SOCKS5_SESSION_UDP_TYPE)
        return SESSION_UDP;

    return SESSION_TCP;
}

static int
sessions_empty (void)
{
    int i;

    for (i = 0; i < SESSION_TYPES; i++)
        if (hev_list_first (&session_live[i]))
            return 0;

    return !hev_list_first (&session_dying);
}

/*
 * Closes the session and takes it off its live list at once, so caps and
 * eviction never count or pick it again while its task is still exiting.
 */
static void
session_kill (HevSocks5SessionData *sd)
{
    if (sd->dying)
        return;

    hev_socks5_session_terminate (sd->self);

    hev_list_del (&session_live[sd->type], &sd->node);
    __atomic_store_n (&session_live_count[sd->type],
                      session_live_count[sd->type] - 1, __ATOMIC_RELAXED);
    session_count--;

    sd->dying = 1;
    hev_list_add_tail (&session_dying, &sd->node);
    __atomic_store_n (&session_dying_count, session_dying_count + 1,
                      __ATOMIC_RELAXED);
}

static HevSocks5SessionData *
session_lru (int type)
{
    HevListNode *node = hev_list_first (&session_live[type]);

    if (!node)
        return NULL;

    return container_of (node, HevSocks5SessionData, node);
}

/*
 * A new session of this type may take the place of the least recently
 * active one only if that one has been silent long enough: a call or a
 * download never goes silent, a one-shot flow does. An established
 * conversation (got a reply and lived protect_age) keeps its place until it
 * is silent protect_idle, so a keep-alive every few seconds survives a storm
 * of one-shot flows.
 */
static int
session_evict_idle (int type, int64_t now)
{
    int idle_ms, protect_age, protect_idle;
    HevListNode *node;

    idle_ms = __atomic_load_n (&session_evict_idle_ms[type], __ATOMIC_RELAXED);
    protect_age =
        __atomic_load_n (&session_protect_age_ms[type], __ATOMIC_RELAXED);
    protect_idle =
        __atomic_load_n (&session_protect_idle_ms[type], __ATOMIC_RELAXED);

    node = hev_list_first (&session_live[type]);
    for (; node; node = hev_list_node_next (node)) {
        HevSocks5SessionData *sd;

        sd = container_of (node, HevSocks5SessionData, node);
        if (now - sd->active_time < idle_ms)
            break;
        if (protect_age > 0 && sd->answered &&
            now - sd->create_time >= protect_age &&
            now - sd->active_time < protect_idle)
            continue;

        session_kill (sd);
        stat_inc (&stat_evicted[type]);
        return 0;
    }

    return -1;
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
        __atomic_store_n (&probe_state, HEV_SOCKS5_TUNNEL_ADMIT_OPEN,
                          __ATOMIC_RELAXED);
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
        __atomic_store_n (&probe_state, state, __ATOMIC_RELAXED);
    }

    return state;
}

/* The probe state as it applies to one type, combined with the caller's. */
static int
admission_for (int type, int probe)
{
    int ext;

    if (probe == HEV_SOCKS5_TUNNEL_ADMIT_CLOSED &&
        !(__atomic_load_n (&probe_close_types, __ATOMIC_RELAXED) & (1 << type)))
        probe = HEV_SOCKS5_TUNNEL_ADMIT_HOLD;
    if (probe == HEV_SOCKS5_TUNNEL_ADMIT_HOLD &&
        !(__atomic_load_n (&probe_hold_types, __ATOMIC_RELAXED) & (1 << type)))
        probe = HEV_SOCKS5_TUNNEL_ADMIT_OPEN;

    ext = __atomic_load_n (&admission_ext[type], __ATOMIC_RELAXED);
    return ext > probe ? ext : probe;
}

static int
session_admit (int type)
{
    int64_t now = monotonic_ms ();
    int state, cap;

    state = admission_for (type, probe_update (now));

    if (state >= HEV_SOCKS5_TUNNEL_ADMIT_CLOSED) {
        stat_inc (&stat_refused_adm[type]);
        goto refuse;
    }

    cap = __atomic_load_n (&session_cap[type], __ATOMIC_RELAXED);
    if (state == HEV_SOCKS5_TUNNEL_ADMIT_OPEN &&
        (cap <= 0 || session_live_count[type] < cap))
        return 0;

    /* At the cap, and in HOLD at any count: only in place of a silent one. */
    if (session_evict_idle (type, now) == 0)
        return 0;

    if (state == HEV_SOCKS5_TUNNEL_ADMIT_HOLD)
        stat_inc (&stat_refused_adm[type]);
refuse:
    stat_inc (&stat_refused[type]);
    return -1;
}

/* Upstream max-session-count: rotate out the least recently active. */
static void
session_rotate (void)
{
    HevSocks5SessionData *udp, *tcp, *sd;
    int max_session_count;

    max_session_count = hev_config_get_misc_max_session_count ();
    if (!max_session_count || session_count < max_session_count)
        return;

    udp = session_lru (SESSION_UDP);
    tcp = session_lru (SESSION_TCP);
    if (udp && tcp)
        sd = (udp->active_time <= tcp->active_time) ? udp : tcp;
    else
        sd = udp ? udp : tcp;

    if (sd)
        session_kill (sd);
}

static void
hev_socks5_tunnel_insert_session (HevListNode *node)
{
    HevSocks5SessionData *sd;

    sd = container_of (node, HevSocks5SessionData, node);
    sd->create_time = monotonic_ms ();
    sd->active_time = sd->create_time;
    sd->type = session_type_of (sd);
    sd->dying = 0;

    hev_list_add_tail (&session_live[sd->type], node);
    __atomic_store_n (&session_live_count[sd->type],
                      session_live_count[sd->type] + 1, __ATOMIC_RELAXED);
    session_count++;
    stat_inc (&stat_created[sd->type]);
    young_ring[young_head++ % YOUNG_RING] = sd->create_time;

    session_rotate ();
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

    hev_list_del (&session_live[sd->type], node);
    __atomic_store_n (&session_live_count[sd->type],
                      session_live_count[sd->type] - 1, __ATOMIC_RELAXED);
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

    hev_list_del (&session_live[sd->type], node);
    hev_list_add_tail (&session_live[sd->type], node);
}

static void
hev_socks5_session_task_entry (void *data)
{
    HevSocks5Session *s = data;

    hev_socks5_session_run (s);

    hev_socks5_tunnel_delete_session (hev_socks5_session_get_node (s));
    hev_object_unref (HEV_OBJECT (s));
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

    /* lwIP aborts the connection and the app gets a reset. */
    if (session_admit (SESSION_TCP) < 0)
        return ERR_RST;

    tcp = hev_socks5_session_tcp_new (pcb, &mutex);
    if (!tcp)
        return ERR_MEM;

    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
        hev_object_unref (HEV_OBJECT (tcp));
        return ERR_MEM;
    }

    hev_socks5_session_set_task (HEV_SOCKS5_SESSION (tcp), task);
    node = hev_socks5_session_get_node (HEV_SOCKS5_SESSION (tcp));
    hev_socks5_tunnel_insert_session (node);
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

static void
udp_refuse_handler (void *arg, struct udp_pcb *pcb, struct pbuf *p,
                    const ip_addr_t *addr, u16_t port)
{
    pbuf_free (p);
    udp_recv (pcb, NULL, NULL);
    udp_remove (pcb);
}

/*
 * lwIP hands the listener a fresh pcb and then looks the datagram up again.
 * Removing that pcb here would make lwIP create the next one and call the
 * listener again forever, so a refused datagram is dropped on the second
 * lookup instead, like the mapped DNS reply.
 */
static void
udp_refuse (struct udp_pcb *pcb)
{
    udp_recv (pcb, udp_refuse_handler, NULL);
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

    if (!READ_ONCE (run)) {
        udp_refuse (pcb);
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

    if (session_admit (SESSION_UDP) < 0) {
        udp_refuse (pcb);
        return;
    }

    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
        udp_refuse (pcb);
        return;
    }

    udp = hev_socks5_session_udp_new (pcb, &mutex);
    if (!udp) {
        hev_task_unref (task);
        udp_refuse (pcb);
        return;
    }

    hev_socks5_session_set_task (HEV_SOCKS5_SESSION (udp), task);
    node = hev_socks5_session_get_node (HEV_SOCKS5_SESSION (udp));
    hev_socks5_tunnel_insert_session (node);
    hev_task_run (task, hev_socks5_session_task_entry, udp);
    hev_task_wakeup (task_lwip_timer);
}

static void
relieve_sessions (const HevSocks5TunnelRelief *relief)
{
    int64_t now = monotonic_ms ();
    int closed[SESSION_TYPES] = { 0 };
    int total = session_count;

    /* Lists are least recently active first: max_count picks the quietest. */
    for (;;) {
        HevSocks5SessionData *sd = NULL;
        int i;

        if (relief->max_count &&
            (closed[SESSION_UDP] + closed[SESSION_TCP]) >= relief->max_count)
            break;

        for (i = 0; i < SESSION_TYPES; i++) {
            HevSocks5SessionData *c;

            if (!(relief->types & (1 << i)))
                continue;
            c = session_lru (i);
            if (!c || now - c->active_time < relief->idle_ms)
                continue;
            if (!sd || c->active_time < sd->active_time)
                sd = c;
        }
        if (!sd)
            break;

        closed[sd->type]++;
        stat_inc (&stat_relieved[sd->type]);
        session_kill (sd);
    }

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
    for (i = 0; i < SESSION_TYPES; i++) {
        HevSocks5SessionData *sd;

        while ((sd = session_lru (i)))
            session_kill (sd);
    }

    hev_task_join (task_lwip_io);
    hev_task_join (task_lwip_timer);
    hev_task_join (task_relief);
    hev_task_del_fd (task_event, event_fds[0]);
}

static void
lwip_io_task_entry (void *data)
{
    const unsigned int mtu = hev_config_get_tunnel_mtu ();

    LOG_D ("socks5 tunnel lwip task run");

    hev_tunnel_add_task (tun_fd, task_lwip_io);

    for (; READ_ONCE (run);) {
        struct pbuf *buf;

        buf = hev_tunnel_read (tun_fd, mtu, task_io_yielder, NULL);
        if (!buf)
            continue;

        stat_tx_packets++;
        stat_tx_bytes += buf->tot_len;

        hev_task_mutex_lock (&mutex);
        if (netif->input (buf, netif) != ERR_OK)
            pbuf_free (buf);
        hev_task_mutex_unlock (&mutex);
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

        if (!sessions_empty ())
            hev_task_sleep (TCP_TMR_INTERVAL);
        else
            hev_task_yield (HEV_TASK_WAITIO);
    }
}

static int
tunnel_init (int extern_tun_fd)
{
    const char *script_path, *name, *guid, *ipv4, *ipv6;
    int multi_queue, res;
    unsigned int mtu;

    if (extern_tun_fd >= 0) {
        int nonblock = 1;

        res = ioctl (extern_tun_fd, FIONBIO, (char *)&nonblock);
        if (res < 0) {
            LOG_E ("socks5 tunnel non-blocking");
            return -1;
        }

        tun_fd = extern_tun_fd;
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

    if (!tun_fd_local)
        return;

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
    int nonblock = 1;
    int res;

    res = socketpair (PF_LOCAL, SOCK_STREAM, 0, event_fds);
    if (res < 0) {
        LOG_E ("socks5 tunnel event");
        return -1;
    }

    res = ioctl (event_fds[0], FIONBIO, (char *)&nonblock);
    if (res < 0) {
        LOG_E ("socks5 tunnel event nonblock");
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
        close (event_fds[0]);
        event_fds[0] = -1;
    }
    if (event_fds[1] >= 0) {
        close (event_fds[1]);
        event_fds[1] = -1;
    }
}

static int
relief_task_init (void)
{
    int nonblock = 1;
    int fds[2];
    int res;

    res = socketpair (PF_LOCAL, SOCK_STREAM, 0, fds);
    if (res < 0) {
        LOG_E ("socks5 tunnel relief");
        return -1;
    }

    pthread_mutex_lock (&relief_mutex);
    relief_fds[0] = fds[0];
    relief_fds[1] = fds[1];
    pthread_mutex_unlock (&relief_mutex);

    res = ioctl (relief_fds[0], FIONBIO, (char *)&nonblock);
    if (res < 0) {
        LOG_E ("socks5 tunnel relief nonblock");
        return -1;
    }

    res = ioctl (relief_fds[1], FIONBIO, (char *)&nonblock);
    if (res < 0) {
        LOG_E ("socks5 tunnel relief nonblock");
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
        close (relief_fds[0]);
        relief_fds[0] = -1;
    }
    if (relief_fds[1] >= 0) {
        close (relief_fds[1]);
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
    int i;

    __atomic_store_n (&session_cap[SESSION_UDP],
                      hev_config_get_misc_udp_max_sessions (),
                      __ATOMIC_RELAXED);
    __atomic_store_n (&session_cap[SESSION_TCP],
                      hev_config_get_misc_tcp_max_sessions (),
                      __ATOMIC_RELAXED);
    __atomic_store_n (&session_evict_idle_ms[SESSION_UDP],
                      hev_config_get_misc_udp_evict_min_idle (),
                      __ATOMIC_RELAXED);
    __atomic_store_n (&session_evict_idle_ms[SESSION_TCP],
                      hev_config_get_misc_tcp_evict_min_idle (),
                      __ATOMIC_RELAXED);
    for (i = 0; i < SESSION_TYPES; i++) {
        __atomic_store_n (&session_protect_age_ms[i], 0, __ATOMIC_RELAXED);
        __atomic_store_n (&session_protect_idle_ms[i], 0, __ATOMIC_RELAXED);
    }

    hev_socks5_session_udp_set_queue_cap (
        hev_config_get_misc_udp_queue_frames (),
        hev_config_get_misc_udp_queue_total_frames ());
    hev_socks5_session_udp_reset_queue_stats ();

    __atomic_store_n (&probe_state, HEV_SOCKS5_TUNNEL_ADMIT_OPEN,
                      __ATOMIC_RELAXED);
    __atomic_store_n (&probe_next_ms, 0, __ATOMIC_RELAXED);
    memset (young_ring, 0, sizeof (young_ring));

    for (i = 0; i < SESSION_TYPES; i++) {
        __atomic_store_n (&admission_ext[i], HEV_SOCKS5_TUNNEL_ADMIT_OPEN,
                          __ATOMIC_RELAXED);
        __atomic_store_n (&stat_refused_adm[i], 0, __ATOMIC_RELAXED);
        __atomic_store_n (&stat_created[i], 0, __ATOMIC_RELAXED);
        __atomic_store_n (&stat_evicted[i], 0, __ATOMIC_RELAXED);
        __atomic_store_n (&stat_refused[i], 0, __ATOMIC_RELAXED);
        __atomic_store_n (&stat_relieved[i], 0, __ATOMIC_RELAXED);
    }
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

    signal (SIGPIPE, SIG_IGN);

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
            res = write (event_fds[1], &res, 1);
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

    pthread_mutex_lock (&relief_mutex);
    if (relief_fds[1] >= 0)
        res = write (relief_fds[1], &relief, sizeof (relief));
    pthread_mutex_unlock (&relief_mutex);

    if (res != sizeof (relief))
        return -1;

    return 0;
}

static int
session_index (int type)
{
    switch (type) {
    case HEV_SOCKS5_TUNNEL_SESSION_UDP:
        return SESSION_UDP;
    case HEV_SOCKS5_TUNNEL_SESSION_TCP:
        return SESSION_TCP;
    }

    return -1;
}

int
hev_socks5_tunnel_set_session_cap (int type, int max_live,
                                   int evict_min_idle_ms)
{
    int i = session_index (type);

    if (i < 0)
        return -1;

    if (max_live < 0)
        max_live = (i == SESSION_UDP) ? hev_config_get_misc_udp_max_sessions ()
                                      : hev_config_get_misc_tcp_max_sessions ();
    if (evict_min_idle_ms < 0)
        evict_min_idle_ms = (i == SESSION_UDP)
                                ? hev_config_get_misc_udp_evict_min_idle ()
                                : hev_config_get_misc_tcp_evict_min_idle ();

    __atomic_store_n (&session_cap[i], max_live, __ATOMIC_RELAXED);
    __atomic_store_n (&session_evict_idle_ms[i], evict_min_idle_ms,
                      __ATOMIC_RELAXED);

    return 0;
}

int
hev_socks5_tunnel_set_udp_queue_cap (int per_session_frames, int total_frames)
{
    if (per_session_frames > UDP_POOL_SIZE + 1)
        return -1;

    if (per_session_frames <= 0)
        per_session_frames = hev_config_get_misc_udp_queue_frames ();
    if (total_frames < 0)
        total_frames = hev_config_get_misc_udp_queue_total_frames ();

    hev_socks5_session_udp_set_queue_cap (per_session_frames, total_frames);

    return 0;
}

int
hev_socks5_tunnel_set_evict_protect (int type, int min_age_ms,
                                     int min_idle_ms)
{
    int i = session_index (type);

    if (i < 0 || min_age_ms < 0 || min_idle_ms < 0)
        return -1;

    __atomic_store_n (&session_protect_age_ms[i], min_age_ms,
                      __ATOMIC_RELAXED);
    __atomic_store_n (&session_protect_idle_ms[i], min_idle_ms,
                      __ATOMIC_RELAXED);

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
hev_socks5_tunnel_set_admission (int types, int state)
{
    int i;

    if (state < HEV_SOCKS5_TUNNEL_ADMIT_OPEN ||
        state > HEV_SOCKS5_TUNNEL_ADMIT_CLOSED)
        return -1;
    if (types & ~(HEV_SOCKS5_TUNNEL_SESSION_UDP | HEV_SOCKS5_TUNNEL_SESSION_TCP))
        return -1;

    for (i = 0; i < SESSION_TYPES; i++)
        if (types & (1 << i))
            __atomic_store_n (&admission_ext[i], state, __ATOMIC_RELAXED);

    return 0;
}

int
hev_socks5_tunnel_set_memory_probe (HevSocks5TunnelMemoryProbe probe,
                                    void *user_data, int interval_ms,
                                    int hold_below_kb, int close_below_kb,
                                    int hysteresis_kb, int young_ms,
                                    int young_reserve_kb)
{
    HevSocks5TunnelProbe c = { probe,         user_data,      interval_ms,
                               hold_below_kb, close_below_kb, hysteresis_kb,
                               young_ms,      young_reserve_kb };

    if (c.interval_ms <= 0)
        c.interval_ms = 50;

    pthread_mutex_lock (&probe_mutex);
    probe_conf = c;
    pthread_mutex_unlock (&probe_mutex);
    __atomic_store_n (&probe_next_ms, 0, __ATOMIC_RELAXED);

    return 0;
}

int
hev_socks5_tunnel_get_session_stats (HevSocks5TunnelSessionStats *stats)
{
    HevSocks5TunnelSessionStats s;
    int admission[SESSION_TYPES];
    int i;

    if (!stats || stats->size < sizeof (s))
        return -1;

    memset (&s, 0, sizeof (s));
    s.size = sizeof (s);
    s.udp_live = __atomic_load_n (&session_live_count[SESSION_UDP],
                                  __ATOMIC_RELAXED);
    s.tcp_live = __atomic_load_n (&session_live_count[SESSION_TCP],
                                  __ATOMIC_RELAXED);
    s.dying = __atomic_load_n (&session_dying_count, __ATOMIC_RELAXED);
    s.udp_created = __atomic_load_n (&stat_created[SESSION_UDP],
                                     __ATOMIC_RELAXED);
    s.tcp_created = __atomic_load_n (&stat_created[SESSION_TCP],
                                     __ATOMIC_RELAXED);
    s.udp_evicted = __atomic_load_n (&stat_evicted[SESSION_UDP],
                                     __ATOMIC_RELAXED);
    s.tcp_evicted = __atomic_load_n (&stat_evicted[SESSION_TCP],
                                     __ATOMIC_RELAXED);
    s.udp_refused = __atomic_load_n (&stat_refused[SESSION_UDP],
                                     __ATOMIC_RELAXED);
    s.tcp_refused = __atomic_load_n (&stat_refused[SESSION_TCP],
                                     __ATOMIC_RELAXED);
    s.udp_relieved = __atomic_load_n (&stat_relieved[SESSION_UDP],
                                      __ATOMIC_RELAXED);
    s.tcp_relieved = __atomic_load_n (&stat_relieved[SESSION_TCP],
                                      __ATOMIC_RELAXED);
    s.udp_cap = __atomic_load_n (&session_cap[SESSION_UDP], __ATOMIC_RELAXED);
    s.tcp_cap = __atomic_load_n (&session_cap[SESSION_TCP], __ATOMIC_RELAXED);
    s.last_probe_kb = __atomic_load_n (&probe_last_kb, __ATOMIC_RELAXED);
    s.udp_queued_frames = hev_socks5_session_udp_get_queued_frames ();
    s.udp_queue_dropped = hev_socks5_session_udp_get_queue_dropped ();
    s.udp_refused_adm = __atomic_load_n (&stat_refused_adm[SESSION_UDP],
                                         __ATOMIC_RELAXED);
    s.tcp_refused_adm = __atomic_load_n (&stat_refused_adm[SESSION_TCP],
                                         __ATOMIC_RELAXED);
    for (i = 0; i < SESSION_TYPES; i++)
        admission[i] = admission_for (
            i, __atomic_load_n (&probe_state, __ATOMIC_RELAXED));
    s.admission_udp = admission[SESSION_UDP];
    s.admission_tcp = admission[SESSION_TCP];

    *stats = s;

    return 0;
}

void
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
