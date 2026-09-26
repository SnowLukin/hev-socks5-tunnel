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
