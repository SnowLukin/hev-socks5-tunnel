#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <lwip/init.h>
#include <hev-task-system.h>
#include <hev-socks5-logger.h>
#include "hev-main.h"
#include "../src/hev-socks5-session-udp.c"

static char history[128];
static char records[16384];

static void
begin_history (void)
{
    strcpy (history, "/tmp/hev-udp-diagnostics.XXXXXX");
    assert (mkdtemp (history));
    assert (!hev_socks5_tunnel_log_history_configure (history, "udp", NULL));
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
        length += fread (records + length, 1, sizeof (records) - length - 1,
                         file);
        fclose (file);
    }
    closedir (directory);
    records[length] = 0;
}

static void
expect_one_failure (const char *target, const char *operation,
                    const char *reason)
{
    char *failure;

    read_history ();
    assert (strstr (records, target));
    assert (strstr (records, operation));
    assert (strstr (records, reason));
    failure = strstr (records, "socks5 failure");
    assert (failure && !strstr (failure + 1, "socks5 failure"));
    assert (!strstr (records, "target=[0.0.0.0]:0"));
}

static HevSocks5SessionUDP *
new_session (HevTaskMutex *mutex)
{
    struct udp_pcb *pcb = udp_new ();
    HevSocks5SessionUDP *session;
    ip_addr_t address;

    assert (pcb);
    IP_ADDR4 (&address, 203, 0, 113, 42);
    assert (udp_bind (pcb, &address, 5353) == ERR_OK);
    session = hev_socks5_session_udp_new (pcb, mutex);
    assert (session);
    hev_socks5_session_set_task (HEV_SOCKS5_SESSION (session),
                                 hev_task_self ());
    hev_socks5_set_timeout (HEV_SOCKS5 (session), 1000);
    return session;
}

static void
receive_frame (HevSocks5SessionUDP *session)
{
    struct pbuf *packet = pbuf_alloc (PBUF_RAW, 3, PBUF_RAM);
    ip_addr_t source;

    assert (packet);
    memcpy (packet->payload, "dns", 3);
    IP_ADDR4 (&source, 192, 0, 2, 7);
    udp_recv_handler (session, session->pcb, packet, &source, 41000);
}

static void
expect_alive_timeout_does_not_taint_later_error (HevTaskMutex *mutex)
{
    HevSocks5SessionUDP *session;
    int sockets[2];
    int flags;

    begin_history ();
    session = new_session (mutex);
    assert (!socketpair (AF_UNIX, SOCK_STREAM, 0, sockets));
    flags = fcntl (sockets[0], F_GETFL, 0);
    assert (flags >= 0);
    assert (!fcntl (sockets[0], F_SETFL, flags | O_NONBLOCK));
    HEV_SOCKS5 (session)->fd = sockets[0];
    session->alive = HEV_SOCKS5_SESSION_UDP_ALIVE_F |
                     HEV_SOCKS5_SESSION_UDP_ALIVE_B;
    hev_socks5_set_timeout (HEV_SOCKS5 (session), 1);
    assert (hev_socks5_session_udp_fwd_b (session) == 0);
    assert (session->alive == HEV_SOCKS5_SESSION_UDP_ALIVE_F);
    assert (!HEV_SOCKS5 (session)->timed_out);
    assert (!HEV_SOCKS5 (session)->failure_logged);

    hev_socks5_log_failure (HEV_SOCKS5 (session), "udp-dup", NULL, EBADF);
    expect_one_failure ("target=udp-association", "operation=udp-dup",
                        "reason=Bad file descriptor code=9");
    assert (!strstr (records, "reason=timeout"));
    hev_object_unref (HEV_OBJECT (session));
    close (sockets[1]);
}

static void
run (void *data)
{
    HevTaskMutex mutex;
    HevSocks5SessionUDP *session;
    int sockets[2];
    (void)data;

    hev_task_mutex_init (&mutex);

    begin_history ();
    session = new_session (&mutex);
    receive_frame (session);
    receive_frame (session);
    assert (session->frames == 2);
    assert (!strcmp (HEV_SOCKS5 (session)->diagnostic_target,
                     "[203.0.113.42]:5353"));
    read_history ();
    assert (!strstr (records, "socks5 failure"));
    assert (!strstr (records, "udp-receive"));
    assert (!strstr (records, "udp-send"));
    hev_object_unref (HEV_OBJECT (session));

    begin_history ();
    session = new_session (&mutex);
    receive_frame (session);
    hev_socks5_log_failure (HEV_SOCKS5 (session), "proxy-connect",
                            "connect-failed", 0);
    expect_one_failure ("target=[203.0.113.42]:5353",
                        "operation=proxy-connect", "reason=connect-failed");
    hev_object_unref (HEV_OBJECT (session));

    begin_history ();
    session = new_session (&mutex);
    receive_frame (session);
    hev_socks5_set_diagnostic_target (HEV_SOCKS5 (session),
                                       "udp-association");
    assert (!socketpair (AF_UNIX, SOCK_STREAM, 0, sockets));
    HEV_SOCKS5 (session)->type = HEV_SOCKS5_TYPE_UDP_IN_UDP;
    HEV_SOCKS5 (session)->fd = sockets[0];
    assert (!shutdown (sockets[1], SHUT_WR));
    assert (task_io_yielder (HEV_TASK_WAITIO, session) < 0);
    assert (!hev_socks5_get_timeout (HEV_SOCKS5 (session)));
    hev_socks5_log_failure (HEV_SOCKS5 (session), "udp-transfer",
                            "transfer-stopped", 0);
    expect_one_failure ("target=udp-association", "operation=udp-control",
                        "reason=proxy-closed-association");
    assert (!strstr (records, "[203.0.113.42]:5353"));
    assert (!strstr (records, "reason=timeout"));
    hev_object_unref (HEV_OBJECT (session));
    close (sockets[1]);

    begin_history ();
    session = new_session (&mutex);
    HEV_SOCKS5 (session)->type = HEV_SOCKS5_TYPE_UDP_IN_UDP;
    HEV_SOCKS5 (session)->fd = -1;
    assert (task_io_yielder (HEV_TASK_WAITIO, session) < 0);
    expect_one_failure ("target=udp-association", "operation=udp-control",
                        "reason=Bad file descriptor code=9");
    hev_object_unref (HEV_OBJECT (session));

    begin_history ();
    session = new_session (&mutex);
    HEV_SOCKS5 (session)->type = HEV_SOCKS5_TYPE_UDP_IN_UDP;
    hev_socks5_session_terminate (HEV_SOCKS5_SESSION (session));
    assert (task_io_yielder (HEV_TASK_WAITIO, session) < 0);
    read_history ();
    assert (!strstr (records, "socks5 failure"));
    hev_object_unref (HEV_OBJECT (session));

    expect_alive_timeout_does_not_taint_later_error (&mutex);

    assert (!strcmp (hev_lwip_error_string (ERR_TIMEOUT), "timeout"));
    assert (!strcmp (hev_lwip_error_string (ERR_RTE), "no-route"));
    assert (!strcmp (hev_lwip_error_string (ERR_RST), "connection-reset"));
    assert (!strcmp (hev_lwip_error_string (-99), "unknown-lwip-error"));
    puts ("PASS tunnel diagnostics: UDP target, quiet frames, control EOF/error, cancellation, alive timeout, lwIP reasons");
}

int
main (void)
{
    HevTask *task;

    lwip_init ();
    assert (!hev_task_system_init ());
    task = hev_task_new (65536);
    assert (task);
    hev_task_run (task, run, NULL);
    hev_task_system_run ();
    hev_task_system_fini ();
    return 0;
}
