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
 * hev_socks5_tunnel_set_session_cap:
 * @type: one HEV_SOCKS5_TUNNEL_SESSION_* value
 * @max_live: most live sessions of this type, 0 for no cap, negative to
 *            restore misc.udp-max-sessions / misc.tcp-max-sessions
 * @evict_min_idle_ms: at the cap a new session closes the least recently
 *            active session of the same type if it has been silent at least
 *            this long, otherwise the new one is refused (TCP gets a reset,
 *            the UDP datagram is dropped); negative to restore
 *            misc.udp-evict-min-idle / misc.tcp-evict-min-idle
 *
 * Lowering the cap below the current count closes nothing by itself: the
 * extra sessions leave by timeout or hev_socks5_tunnel_relieve. Every tunnel
 * start applies the configured values again. Safe to call from any thread.
 *
 * Returns: zero, or -1 for an unknown type.
 */
int hev_socks5_tunnel_set_session_cap (int type, int max_live,
                                       int evict_min_idle_ms);

/**
 * HevSocks5TunnelAdmission:
 * @HEV_SOCKS5_TUNNEL_ADMIT_OPEN: new sessions limited only by the caps
 * @HEV_SOCKS5_TUNNEL_ADMIT_HOLD: no growth, a new session only in place of
 *            a silent one of the same type (as at the cap)
 * @HEV_SOCKS5_TUNNEL_ADMIT_CLOSED: no new sessions, live ones keep working
 */
enum
{
    HEV_SOCKS5_TUNNEL_ADMIT_OPEN = 0,
    HEV_SOCKS5_TUNNEL_ADMIT_HOLD = 1,
    HEV_SOCKS5_TUNNEL_ADMIT_CLOSED = 2,
};

/**
 * hev_socks5_tunnel_set_admission:
 * @types: HEV_SOCKS5_TUNNEL_SESSION_* mask
 * @state: HEV_SOCKS5_TUNNEL_ADMIT_*
 *
 * Admission state set by the caller. The stricter of this and the state
 * derived from the memory probe is in effect. Every tunnel start resets it to
 * OPEN. Safe to call from any thread.
 *
 * Returns: zero, or -1 for invalid arguments.
 */
int hev_socks5_tunnel_set_admission (int types, int state);

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
 * @user_data: passed to @probe
 * @interval_ms: call @probe at most this often, the last result is used in
 *            between (50 if not positive)
 * @hold_below_kb: less than this available: HEV_SOCKS5_TUNNEL_ADMIT_HOLD
 * @close_below_kb: less than this available: HEV_SOCKS5_TUNNEL_ADMIT_CLOSED
 * @hysteresis_kb: leave a state only this far above its threshold
 * @young_ms: sessions younger than this have not taken their memory yet
 * @young_reserve_kb: subtracted from the available memory per young session
 *
 * The probe is checked when a new session is about to be created, so the
 * state follows memory from the first packet on without a timer. The setting
 * outlives tunnel restarts. Safe to call from any thread.
 *
 * Returns: zero.
 */
int hev_socks5_tunnel_set_memory_probe (HevSocks5TunnelMemoryProbe probe,
                                        void *user_data, int interval_ms,
                                        int hold_below_kb, int close_below_kb,
                                        int hysteresis_kb, int young_ms,
                                        int young_reserve_kb);

/**
 * HevSocks5TunnelSessionStats:
 * @size: set by the caller to sizeof (HevSocks5TunnelSessionStats)
 * @udp_live, @tcp_live: live sessions
 * @dying: closed sessions that have not released their memory yet
 * @udp_queued_frames: datagrams waiting in all UDP session queues
 * @admission_udp, @admission_tcp: admission state in effect,
 *            HEV_SOCKS5_TUNNEL_ADMIT_*
 * @udp_cap, @tcp_cap: caps in effect, 0 for none
 * @last_probe_kb: last memory probe result in KiB, negative if none
 * @*_created: sessions created since the tunnel start
 * @*_evicted: silent sessions closed to make room for a new one
 * @*_refused: new sessions refused by a cap or by admission
 * @*_relieved: sessions closed by hev_socks5_tunnel_relieve
 * @*_refused_adm: part of @*_refused due to HOLD or CLOSED admission
 * @udp_queue_dropped: datagrams dropped because a UDP queue was full
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
} HevSocks5TunnelSessionStats;

/**
 * hev_socks5_tunnel_get_session_stats:
 * @stats (out): filled in, @stats->size must be set first
 *
 * Counters restart with every tunnel start. Safe to call from any thread.
 *
 * Returns: zero, or -1 if @stats->size is too small.
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
