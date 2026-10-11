#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <lwip/init.h>
#include <lwip/ip4.h>
#include <lwip/inet_chksum.h>
#include <lwip/netif.h>
#include <hev-task-system.h>
#include <hev-socks5-logger.h>
#include "hev-main.h"
#include "../src/hev-socks5-session-tcp.c"

static char history[128];
static char records[16384];

static void
begin_history (void)
{
    strcpy (history, "/tmp/hev-session-diagnostics.XXXXXX");
    assert (mkdtemp (history));
    assert (!hev_socks5_tunnel_log_history_configure (history, "diagnostics",
                                                      NULL));
    assert (!hev_socks5_logger_init (HEV_SOCKS5_LOGGER_INFO, "stdout"));
}

static void
read_history (void)
{
    DIR *directory;
    struct dirent *entry;
    size_t length = 0;
    hev_socks5_logger_fini ();
    directory = opendir (history);
    assert (directory);
    while ((entry = readdir (directory))) {
        char path[512];
        FILE *file;
        if (strncmp (entry->d_name, "tun2socks.", 10) ||
            !strstr (entry->d_name, ".jsonl"))
            continue;
        snprintf (path, sizeof (path), "%s/%s", history, entry->d_name);
        file = fopen (path, "r");
        assert (file);
        length +=
            fread (records + length, 1, sizeof (records) - length - 1, file);
        fclose (file);
    }
    closedir (directory);
    records[length] = 0;
}

static HevSocks5SessionTCP *
new_session (HevTaskMutex *mutex)
{
    struct tcp_pcb *pcb = tcp_new ();
    ip_addr_t address;
    HevSocks5SessionTCP *session;
    assert (pcb);
    IP_ADDR4 (&address, 203, 0, 113, 10);
    assert (tcp_bind (pcb, &address, 8443) == ERR_OK);
    session = hev_socks5_session_tcp_new (pcb, mutex);
    assert (session);
    hev_socks5_session_set_task (HEV_SOCKS5_SESSION (session),
                                 hev_task_self ());
    hev_socks5_set_timeout (HEV_SOCKS5 (session), 1000);
    return session;
}

static void
expect_failure (const char *operation, const char *reason)
{
    char *failure;
    read_history ();
    assert (strstr (records, "target=[203.0.113.10]:8443"));
    assert (strstr (records, operation));
    assert (strstr (records, reason));
    failure = strstr (records, "socks5 failure");
    assert (failure && !strstr (failure + 1, "socks5 failure"));
    assert (!strstr (records, "socks5 session tcp splice"));
}

static void
expect_transfer_timeout (HevTaskMutex *mutex)
{
    HevSocks5SessionTCP *session;
    int fd[2], flags;

    begin_history ();
    session = new_session (mutex);
    assert (!socketpair (AF_UNIX, SOCK_STREAM, 0, fd));
    HEV_SOCKS5 (session)->fd = fd[0];
    flags = fcntl (fd[0], F_GETFL, 0);
    assert (flags >= 0);
    assert (!fcntl (fd[0], F_SETFL, flags | O_NONBLOCK));
    hev_socks5_set_timeout (HEV_SOCKS5 (session), 1);
    hev_socks5_session_tcp_splice (HEV_SOCKS5_SESSION (session));
    expect_failure ("operation=tcp-transfer", "reason=timeout");
    hev_object_unref (HEV_OBJECT (session));
    close (fd[1]);
}

static void
expect_closed_callback_is_quiet (HevTaskMutex *mutex)
{
    HevSocks5SessionTCP *session;

    begin_history ();
    session = new_session (mutex);
    tcp_err (session->pcb, NULL);
    tcp_abort (session->pcb);
    tcp_err_handler (session, ERR_CLSD);
    read_history ();
    assert (!strstr (records, "socks5 failure"));
    hev_object_unref (HEV_OBJECT (session));
}

static void
expect_cancelled_transfer_is_quiet (HevTaskMutex *mutex)
{
    HevSocks5SessionTCP *session;
    int fd[2], flags;

    begin_history ();
    session = new_session (mutex);
    assert (!socketpair (AF_UNIX, SOCK_STREAM, 0, fd));
    HEV_SOCKS5 (session)->fd = fd[0];
    flags = fcntl (fd[0], F_GETFL, 0);
    assert (flags >= 0);
    assert (!fcntl (fd[0], F_SETFL, flags | O_NONBLOCK));
    hev_socks5_session_terminate (HEV_SOCKS5_SESSION (session));
    hev_socks5_session_tcp_splice (HEV_SOCKS5_SESSION (session));
    read_history ();
    assert (!strstr (records, "socks5 failure"));
    hev_object_unref (HEV_OBJECT (session));
    close (fd[1]);
}

static err_t
accept_output (struct netif *netif, struct pbuf *packet,
               const ip4_addr_t *address)
{
    (void)netif;
    (void)packet;
    (void)address;
    return ERR_OK;
}

static err_t
init_netif (struct netif *netif)
{
    netif->output = accept_output;
    return ERR_OK;
}

static void
expect_rst_through_ip4 (HevTaskMutex *mutex)
{
    unsigned char packet[] = {
        0x45, 0, 0, 40, 0, 1, 0, 0, 64, 6, 0, 0,
        192, 0, 2, 7, 203, 0, 113, 10,
        0xa0, 0x28, 0x20, 0xfb, 0, 0, 0, 1, 0, 0, 0, 0,
        0x50, 0x04, 0, 0, 0, 0, 0, 0
    };
    HevSocks5SessionTCP *session;
    struct netif netif = { 0 };
    struct pbuf *p;
    ip4_addr_t address, mask, gateway;
    ip_addr_t source, destination;
    uint16_t checksum;

    IP4_ADDR (&address, 203, 0, 113, 10);
    IP4_ADDR (&mask, 255, 255, 255, 0);
    IP4_ADDR (&gateway, 203, 0, 113, 1);
    assert (netif_add (&netif, &address, &mask, &gateway, NULL, init_netif,
                       NULL));
    netif_set_up (&netif);
    netif_set_link_up (&netif);
    netif_set_default (&netif);
    begin_history ();
    session = new_session (mutex);
    IP_ADDR4 (&source, 192, 0, 2, 7);
    IP_ADDR4 (&destination, 203, 0, 113, 10);
    assert (tcp_connect (session->pcb, &source, 41000, NULL) == ERR_OK);
    session->pcb->state = ESTABLISHED;
    session->pcb->rcv_nxt = 1;

    checksum = inet_chksum (packet, 20);
    memcpy (packet + 10, &checksum, sizeof (checksum));
    p = pbuf_alloc (PBUF_RAW, 20, PBUF_RAM);
    assert (p);
    assert (pbuf_take (p, packet + 20, 20) == ERR_OK);
    checksum = ip_chksum_pseudo (p, IP_PROTO_TCP, 20, &source, &destination);
    memcpy (packet + 36, &checksum, sizeof (checksum));
    pbuf_free (p);
    p = pbuf_alloc (PBUF_RAW, sizeof (packet), PBUF_RAM);
    assert (p);
    assert (pbuf_take (p, packet, sizeof (packet)) == ERR_OK);
    assert (ip4_input (p, &netif) == ERR_OK);
    assert (!session->pcb);
    expect_failure ("operation=lwip-tcp", "reason=connection-reset code=-14");
    hev_object_unref (HEV_OBJECT (session));
    netif_remove (&netif);
}

static void
expect_drain_timeout (HevTaskMutex *mutex)
{
    HevSocks5SessionTCP *session;
    struct netif netif;
    ip4_addr_t address, mask, gateway;
    int fd[2];

    IP4_ADDR (&address, 203, 0, 113, 1);
    IP4_ADDR (&mask, 255, 255, 255, 0);
    IP4_ADDR (&gateway, 203, 0, 113, 1);
    memset (&netif, 0, sizeof (netif));
    assert (
        netif_add (&netif, &address, &mask, &gateway, NULL, init_netif, NULL));
    netif_set_up (&netif);
    netif_set_link_up (&netif);
    netif_set_default (&netif);
    begin_history ();
    session = new_session (mutex);
    assert (!socketpair (AF_UNIX, SOCK_STREAM, 0, fd));
    HEV_SOCKS5 (session)->fd = fd[0];
    {
        ip_addr_t remote;
        IP_ADDR4 (&remote, 203, 0, 113, 2);
        assert (tcp_connect (session->pcb, &remote, 9443, NULL) == ERR_OK);
    }
    session->pcb->state = ESTABLISHED;
    session->pcb->snd_wnd = 0;
    session->pcb_eof = 1;
    assert (write (fd[1], "x", 1) == 1);
    assert (!shutdown (fd[1], SHUT_WR));
    hev_socks5_set_timeout (HEV_SOCKS5 (session), 1);
    hev_socks5_session_tcp_splice (HEV_SOCKS5_SESSION (session));
    expect_failure ("operation=tcp-drain", "reason=timeout");
    hev_object_unref (HEV_OBJECT (session));
    close (fd[1]);
    netif_remove (&netif);
}

static void
run (void *data)
{
    HevTaskMutex mutex;
    HevSocks5SessionTCP *session;
    int fd[2];
    (void)data;
    hev_task_mutex_init (&mutex);

    begin_history ();
    session = new_session (&mutex);
    tcp_err (session->pcb, NULL);
    tcp_abort (session->pcb);
    tcp_err_handler (session, ERR_RST);
    expect_failure ("operation=lwip-tcp", "reason=connection-reset code=-14");
    hev_object_unref (HEV_OBJECT (session));

    begin_history ();
    session = new_session (&mutex);
    session->buffer = hev_ring_buffer_alloca (64);
    assert (tcp_splice_b (session) < 0);
    expect_failure ("operation=tcp-read", "reason=Bad file descriptor");
    hev_object_unref (HEV_OBJECT (session));

    begin_history ();
    session = new_session (&mutex);
    session->queue = pbuf_alloc (PBUF_RAW, 1, PBUF_RAM);
    assert (session->queue);
    assert (tcp_splice_f (session) < 0);
    expect_failure ("operation=tcp-write", "reason=Bad file descriptor");
    hev_object_unref (HEV_OBJECT (session));

    begin_history ();
    session = new_session (&mutex);
    assert (!socketpair (AF_UNIX, SOCK_STREAM, 0, fd));
    HEV_SOCKS5 (session)->fd = fd[0];
    session->buffer = hev_ring_buffer_alloca (64);
    shutdown (fd[1], SHUT_WR);
    assert (tcp_splice_b (session) < 0);
    read_history ();
    assert (!strstr (records, "socks5 failure"));
    hev_object_unref (HEV_OBJECT (session));
    close (fd[1]);

    begin_history ();
    session = new_session (&mutex);
    hev_socks5_session_terminate (HEV_SOCKS5_SESSION (session));
    tcp_err (session->pcb, NULL);
    tcp_abort (session->pcb);
    tcp_err_handler (session, ERR_ABRT);
    read_history ();
    assert (!strstr (records, "socks5 failure"));
    hev_object_unref (HEV_OBJECT (session));

    expect_transfer_timeout (&mutex);
    expect_rst_through_ip4 (&mutex);
    expect_drain_timeout (&mutex);
    expect_cancelled_transfer_is_quiet (&mutex);
    expect_closed_callback_is_quiet (&mutex);

    assert (!strcmp (hev_lwip_error_string (ERR_TIMEOUT), "timeout"));
    assert (!strcmp (hev_lwip_error_string (ERR_RTE), "no-route"));
    assert (!strcmp (hev_lwip_error_string (-99), "unknown-lwip-error"));
    puts (
        "PASS tunnel diagnostics: TCP reset, read/write errno, transfer/drain timeout, EOF, cancellation, graceful close, JSONL history");
}

int
main (void)
{
    HevTask *task;
    static const unsigned char config[] =
        "misc:\n  tcp-buffer-size: 64\n  max-session-count: 0\n";
    assert (!hev_config_init_from_str (config, sizeof (config) - 1));
    lwip_init ();
    assert (!hev_task_system_init ());
    task = hev_task_new (65536);
    assert (task);
    hev_task_run (task, run, NULL);
    hev_task_system_run ();
    hev_task_system_fini ();
    return 0;
}
