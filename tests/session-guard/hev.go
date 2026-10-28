package main

/*
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include "hev-main.h"

static int run_hev(const char *cfg, int fd) {
    return hev_socks5_tunnel_main_from_str((const unsigned char *)cfg, strlen(cfg), fd);
}
static int mk_socketpair(int *fds) {
    int r = socketpair(AF_UNIX, SOCK_DGRAM, 0, fds);
    int sz = 4 * 1024 * 1024;
    setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
    setsockopt(fds[0], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
    setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    return r;
}

static long long fake_avail = -1;
// Size a caller built before the dns_* fields passes.
static unsigned int stats_guard_size(void) { return offsetof(HevSocks5TunnelSessionStats, dns_live); }
// Size a caller built before dns_overflow passes.
static unsigned int stats_pool_size(void) { return offsetof(HevSocks5TunnelSessionStats, dns_overflow); }
// Calls with that size over a struct filled with 0xab: hev must accept it, report the size back
// and leave every byte after it alone.
static int stats_old_caller(unsigned int size, unsigned int *out_size, int *untouched) {
    HevSocks5TunnelSessionStats s;
    size_t off = size;
    memset(&s, 0xab, sizeof(s));
    s.size = off;
    int r = hev_socks5_tunnel_get_session_stats(&s);
    const unsigned char *p = (const unsigned char *)&s;
    *out_size = s.size;
    *untouched = 1;
    for (size_t i = off; i < sizeof(s); i++)
        if (p[i] != 0xab)
            *untouched = 0;
    return r;
}
static int set_dns_priority(int max_sessions, int timeout_ms, const char *addresses) {
    return hev_socks5_tunnel_set_dns_priority(max_sessions, timeout_ms, addresses);
}
static long long probe_calls;
static long long fake_probe(void *user_data) {
    __atomic_fetch_add(&probe_calls, 1, __ATOMIC_RELAXED);
    return __atomic_load_n(&fake_avail, __ATOMIC_RELAXED);
}
static void set_fake_avail(long long bytes) { __atomic_store_n(&fake_avail, bytes, __ATOMIC_RELAXED); }
static long long get_probe_calls(void) { return __atomic_load_n(&probe_calls, __ATOMIC_RELAXED); }
static int probe_on(int interval_ms, int hold_kb, int close_kb, int hyst_kb, int young_ms, int young_kb) {
    return hev_socks5_tunnel_set_memory_probe(fake_probe, NULL, interval_ms, hold_kb, close_kb, hyst_kb,
                                              young_ms, young_kb);
}
static int probe_off(void) {
    return hev_socks5_tunnel_set_memory_probe(NULL, NULL, 0, 0, 0, 0, 0, 0);
}
static int stats_with_size(HevSocks5TunnelSessionStats *s, unsigned int size) {
    memset(s, 0, sizeof(*s));
    s->size = size;
    return hev_socks5_tunnel_get_session_stats(s);
}
*/
import "C"

import "unsafe"

const (
	sessUDP     = int(C.HEV_SOCKS5_TUNNEL_SESSION_UDP)
	sessTCP     = int(C.HEV_SOCKS5_TUNNEL_SESSION_TCP)
	admitOpen   = int(C.HEV_SOCKS5_TUNNEL_ADMIT_OPEN)
	admitHold   = int(C.HEV_SOCKS5_TUNNEL_ADMIT_HOLD)
	admitClosed = int(C.HEV_SOCKS5_TUNNEL_ADMIT_CLOSED)
)

type sessionStats struct {
	udpLive, tcpLive, dying, udpQueued int
	admUDP, admTCP, udpCap, tcpCap     int
	lastProbeKB                        int64
	udpCreated, tcpCreated             uint64
	udpEvicted, tcpEvicted             uint64
	udpRefused, tcpRefused             uint64
	udpRelieved, tcpRelieved           uint64
	udpRefusedAdm, tcpRefusedAdm       uint64
	udpQueueDropped                    uint64
	probeHoldMs, probeClosedMs         uint64
	dnsLive, dnsCap                    int
	dnsCreated, dnsEvicted, dnsRefused uint64
	dnsOverflow                        uint64
}

func startHev(cfg string, fd int) int {
	cs := C.CString(cfg)
	defer C.free(unsafe.Pointer(cs))
	return int(C.run_hev(cs, C.int(fd)))
}

func quitHev() { C.hev_socks5_tunnel_quit() }

func relieve(types, idleMs, maxCount int) int {
	return int(C.hev_socks5_tunnel_relieve(C.int(types), C.int(idleMs), C.int(maxCount)))
}

func setSessionCap(typ, maxLive, idleMs int) int {
	return int(C.hev_socks5_tunnel_set_session_cap(C.int(typ), C.int(maxLive), C.int(idleMs)))
}

func setAdmission(types, state int) int {
	return int(C.hev_socks5_tunnel_set_admission(C.int(types), C.int(state)))
}

func setEvictProtect(typ, ageMs, idleMs int) int {
	return int(C.hev_socks5_tunnel_set_evict_protect(C.int(typ), C.int(ageMs), C.int(idleMs)))
}

func setProbeTypes(hold, close int) int {
	return int(C.hev_socks5_tunnel_set_memory_probe_types(C.int(hold), C.int(close)))
}

func probeOn(intervalMs, holdKB, closeKB, hystKB, youngMs, youngKB int) int {
	return int(C.probe_on(C.int(intervalMs), C.int(holdKB), C.int(closeKB), C.int(hystKB), C.int(youngMs), C.int(youngKB)))
}

func probeOff() int { return int(C.probe_off()) }

func setFakeAvailKB(kb int64) { C.set_fake_avail(C.longlong(kb * 1024)) }

func probeCalls() int64 { return int64(C.get_probe_calls()) }

func statsWithSize(size int) int {
	var s C.HevSocks5TunnelSessionStats
	return int(C.stats_with_size(&s, C.uint(size)))
}

func stats() (sessionStats, bool) {
	var s C.HevSocks5TunnelSessionStats
	if C.stats_with_size(&s, C.uint(unsafe.Sizeof(s))) != 0 {
		return sessionStats{}, false
	}
	return sessionStats{
		udpLive: int(s.udp_live), tcpLive: int(s.tcp_live), dying: int(s.dying), udpQueued: int(s.udp_queued_frames),
		admUDP: int(s.admission_udp), admTCP: int(s.admission_tcp), udpCap: int(s.udp_cap), tcpCap: int(s.tcp_cap),
		lastProbeKB: int64(s.last_probe_kb),
		udpCreated:  uint64(s.udp_created), tcpCreated: uint64(s.tcp_created),
		udpEvicted: uint64(s.udp_evicted), tcpEvicted: uint64(s.tcp_evicted),
		udpRefused: uint64(s.udp_refused), tcpRefused: uint64(s.tcp_refused),
		udpRelieved: uint64(s.udp_relieved), tcpRelieved: uint64(s.tcp_relieved),
		udpRefusedAdm: uint64(s.udp_refused_adm), tcpRefusedAdm: uint64(s.tcp_refused_adm),
		udpQueueDropped: uint64(s.udp_queue_dropped),
		probeHoldMs:     uint64(s.probe_hold_ms), probeClosedMs: uint64(s.probe_closed_ms),
		dnsLive: int(s.dns_live), dnsCap: int(s.dns_cap),
		dnsCreated: uint64(s.dns_created), dnsEvicted: uint64(s.dns_evicted), dnsRefused: uint64(s.dns_refused),
		dnsOverflow: uint64(s.dns_overflow),
	}, true
}

func socketpair() (int, int) {
	var fds [2]C.int
	C.mk_socketpair(&fds[0])
	return int(fds[0]), int(fds[1])
}

func statsGuardSize() int { return int(C.stats_guard_size()) }
func statsPoolSize() int  { return int(C.stats_pool_size()) }

func statsCallerWithSize(size int) (ret int, got int, untouched bool) {
	var sz C.uint
	var un C.int
	ret = int(C.stats_old_caller(C.uint(size), &sz, &un))
	return ret, int(sz), un != 0
}

// setDnsPriority: addresses nil -> NULL (restore the config value).
func setDnsPriority(maxSessions, timeoutMs int, addresses *string) int {
	if addresses == nil {
		return int(C.set_dns_priority(C.int(maxSessions), C.int(timeoutMs), nil))
	}
	cs := C.CString(*addresses)
	defer C.free(unsafe.Pointer(cs))
	return int(C.set_dns_priority(C.int(maxSessions), C.int(timeoutMs), cs))
}
