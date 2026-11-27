/*
 ============================================================================
 Name        : hev-main.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2019 - 2023 hev
 Description : Main
 ============================================================================
 */

#ifndef __HEV_MAIN_H__
#define __HEV_MAIN_H__

#include <stddef.h>
#include "hev-socks5-log-history.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * hev_socks5_tunnel_main:
 * @config_path: config file path
 * @tun_fd: tunnel file descriptor
 *
 * Start and run the socks5 tunnel, this function will blocks until the
 * hev_socks5_tunnel_quit is called or an error occurs.
 *
 * Returns: returns zero on successful, otherwise returns -1.
 *
 * Since: 2.4.6
 */
int hev_socks5_tunnel_main (const char *config_path, int tun_fd);

/**
 * hev_socks5_tunnel_main_from_file:
 * @config_path: config file path
 * @tun_fd: tunnel file descriptor
 *
 * Start and run the socks5 tunnel, this function will blocks until the
 * hev_socks5_tunnel_quit is called or an error occurs.
 *
 * Returns: returns zero on successful, otherwise returns -1.
 *
 * Since: 2.6.7
 */
int hev_socks5_tunnel_main_from_file (const char *config_path, int tun_fd);

/**
 * hev_socks5_tunnel_main_from_str:
 * @config_str: string config
 * @config_len: the byte length of string config
 * @tun_fd: tunnel file descriptor
 *
 * Start and run the socks5 tunnel, this function will blocks until the
 * hev_socks5_tunnel_quit is called or an error occurs.
 *
 * Returns: returns zero on successful, otherwise returns -1.
 *
 * Since: 2.6.7
 */
int hev_socks5_tunnel_main_from_str (const unsigned char *config_str,
                                     unsigned int config_len, int tun_fd);

/**
 * hev_socks5_tunnel_quit:
 *
 * Stop the socks5 tunnel.
 *
 * Since: 2.4.6
 */
void hev_socks5_tunnel_quit (void);

/**
 * HevSocks5TunnelReliefType:
 * @HEV_SOCKS5_TUNNEL_RELIEF_UDP: UDP sessions
 * @HEV_SOCKS5_TUNNEL_RELIEF_TCP: TCP sessions
 *
 * Session types for hev_socks5_tunnel_relieve, can be combined.
 */
enum
{
    HEV_SOCKS5_TUNNEL_RELIEF_UDP = 1,
    HEV_SOCKS5_TUNNEL_RELIEF_TCP = 2,
};

/**
 * hev_socks5_tunnel_relieve:
 * @types: session types to close, HEV_SOCKS5_TUNNEL_RELIEF_* flags
 * @idle_ms: close only sessions without activity for at least this long,
 *           0 for any
 * @max_count: close at most this many sessions, oldest first, 0 for no limit
 *
 * Asynchronously close matching sessions to give memory back, e.g. on a
 * memory pressure warning. The tunnel keeps running; closed UDP flows get a
 * new session on their next packet, closed TCP connections are reset. Safe
 * to call from any thread, also while the tunnel starts or stops.
 *
 * Returns: returns zero on successful, -1 if the tunnel is not running.
 */
int hev_socks5_tunnel_relieve (int types, int idle_ms, int max_count);

/**
 * HevSocks5TunnelSessionType:
 * @HEV_SOCKS5_TUNNEL_SESSION_UDP: UDP sessions
 * @HEV_SOCKS5_TUNNEL_SESSION_TCP: TCP sessions
 *
 * Same values as HEV_SOCKS5_TUNNEL_RELIEF_*, can be combined where a mask
 * is taken.
 */
enum
{
    HEV_SOCKS5_TUNNEL_SESSION_UDP = 1,
    HEV_SOCKS5_TUNNEL_SESSION_TCP = 2,
};

/**
 * HevSocks5TunnelAdmission:
 * @HEV_SOCKS5_TUNNEL_ADMIT_OPEN: new sessions limited only by
 *            misc.max-session-count
 * @HEV_SOCKS5_TUNNEL_ADMIT_HOLD: no growth, a new session takes the place of
 *            one of the same type, chosen as at misc.max-session-count
 * @HEV_SOCKS5_TUNNEL_ADMIT_CLOSED: no new sessions, live ones keep working
 */
enum
{
    HEV_SOCKS5_TUNNEL_ADMIT_OPEN = 0,
    HEV_SOCKS5_TUNNEL_ADMIT_HOLD = 1,
    HEV_SOCKS5_TUNNEL_ADMIT_CLOSED = 2,
};

/**
 * HevSocks5TunnelMemoryProbe:
 * @user_data: as passed to hev_socks5_tunnel_set_memory_probe
 *
 * Called on the tunnel thread while a packet is being handled, so it must be
 * fast and must not block.
 *
 * Returns: bytes the process can still allocate before its limit, negative
 * if unknown.
 */
typedef long long (*HevSocks5TunnelMemoryProbe) (void *user_data);

/**
 * hev_socks5_tunnel_set_memory_probe:
 * @probe: callback, NULL to turn the probe off
 * @user_data: passed to @probe; must stay valid until the tunnel stops: the
 *            tunnel thread may call the previous @probe with its @user_data
 *            once more after it is replaced
 * @interval_ms: call @probe at most this often, the last result is used in
 *            between (50 if not positive)
 * @hold_below_kb: less than this available: HEV_SOCKS5_TUNNEL_ADMIT_HOLD
 * @close_below_kb: less than this available: HEV_SOCKS5_TUNNEL_ADMIT_CLOSED
 * @hysteresis_kb: leave a state only this far above its threshold
 * @young_ms: sessions younger than this have not taken their memory yet
 * @young_reserve_kb: subtracted from the available memory per young session
 *
 * The probe is checked when a new session is about to be created, so the
 * state follows memory from the first packet on, and while sessions are live
 * also on the lwIP timer. The setting outlives tunnel restarts. Safe to call
 * from any thread.
 *
 * Returns: zero, or -1 if thresholds are negative or @close_below_kb is
 * above @hold_below_kb.
 */
int hev_socks5_tunnel_set_memory_probe (HevSocks5TunnelMemoryProbe probe,
                                        void *user_data, int interval_ms,
                                        int hold_below_kb, int close_below_kb,
                                        int hysteresis_kb, int young_ms,
                                        int young_reserve_kb);

/**
 * hev_socks5_tunnel_set_memory_probe_types:
 * @hold_types: HEV_SOCKS5_TUNNEL_SESSION_* mask the probe may put in HOLD
 * @close_types: mask the probe may put in CLOSED; a type out of it gets
 *            HOLD instead if @hold_types has it, otherwise stays OPEN
 *
 * Both default to all types. The setting outlives tunnel restarts. Safe to
 * call from any thread.
 *
 * Returns: zero, or -1 for invalid arguments.
 */
int hev_socks5_tunnel_set_memory_probe_types (int hold_types, int close_types);

/**
 * HevSocks5TunnelSessionStats:
 * @size: set by the caller to sizeof (HevSocks5TunnelSessionStats)
 * @udp_live, @tcp_live: live sessions
 * @dying: closed sessions that have not released their memory yet
 * @udp_queued_frames: datagrams waiting in all UDP session queues
 * @admission_udp, @admission_tcp: admission state in effect,
 *            HEV_SOCKS5_TUNNEL_ADMIT_*
 * @udp_cap, @tcp_cap: always 0, there are no caps per type any more
 * @last_probe_kb: last memory probe result in KiB, negative if none
 * @*_created: sessions created since the tunnel start
 * @*_evicted: sessions closed to make room for a new one, at
 *            misc.max-session-count or in HOLD
 * @*_refused: new sessions refused by CLOSED admission
 * @*_relieved: sessions closed by hev_socks5_tunnel_relieve
 * @*_refused_adm: same as @*_refused
 * @udp_queue_dropped: datagrams dropped because a UDP queue was full or the
 *            buffer budget was used up
 * @probe_hold_ms, @probe_closed_ms: time the memory probe has kept
 *            HEV_SOCKS5_TUNNEL_ADMIT_HOLD and HEV_SOCKS5_TUNNEL_ADMIT_CLOSED
 * @dns_live, @dns_cap: live sessions in the DNS pool and its size, 0 if off
 * @dns_created, @dns_evicted, @dns_refused: DNS pool sessions created,
 *            closed to make room, and queries that found the pool full of
 *            sessions waiting for a reply
 * @dns_overflow: part of @dns_refused that started as ordinary UDP sessions;
 *            the rest was refused by the memory probe
 * @max_session_count: misc.max-session-count, 0 for none
 * @buffer_limit, @buffer_used: misc.max-buffer-size (0: unlimited) and the
 *            bytes charged to it
 * @buffer_reclaimed: sessions closed because they held buffers without
 *            progress while the budget was overcommitted
 * @protected_live: sessions kept by misc.evict-protect-idle the last time
 *            room was made
 *
 * A caller built against an older, shorter struct passes the smaller size and
 * gets the fields it knows.
 */
typedef struct
{
    unsigned int size;
    int udp_live;
    int tcp_live;
    int dying;
    int udp_queued_frames;
    int admission_udp;
    int admission_tcp;
    int udp_cap;
    int tcp_cap;
    long long last_probe_kb;
    unsigned long long udp_created, tcp_created;
    unsigned long long udp_evicted, tcp_evicted;
    unsigned long long udp_refused, tcp_refused;
    unsigned long long udp_relieved, tcp_relieved;
    unsigned long long udp_refused_adm, tcp_refused_adm;
    unsigned long long udp_queue_dropped;
    unsigned long long probe_hold_ms, probe_closed_ms;
    int dns_live;
    int dns_cap;
    unsigned long long dns_created, dns_evicted, dns_refused;
    unsigned long long dns_overflow;
    int max_session_count;
    int protected_live;
    unsigned long long buffer_limit, buffer_used;
    unsigned long long buffer_reclaimed;
} HevSocks5TunnelSessionStats;

/**
 * hev_socks5_tunnel_get_session_stats:
 * @stats (out): filled in, @stats->size must be set first
 *
 * Counters restart with every tunnel start. Safe to call from any thread.
 *
 * Returns: zero, or -1 if @stats->size is too small or the tunnel is not
 * running, so a caller never takes the previous start's counters for the
 * current one.
 */
int hev_socks5_tunnel_get_session_stats (HevSocks5TunnelSessionStats *stats);

/**
 * hev_socks5_tunnel_stats:
 * @tx_packets (out): transmitted packets
 * @tx_bytes (out): transmitted bytes
 * @rx_packets (out): received packets
 * @rx_bytes (out): received bytes
 *
 * Retrieve tunnel interface traffic statistics.
 *
 * Since: 2.6.5
 */
void hev_socks5_tunnel_stats (size_t *tx_packets, size_t *tx_bytes,
                              size_t *rx_packets, size_t *rx_bytes);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_MAIN_H__ */
