#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <lwip/init.h>
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
    assert (!hev_socks5_tunnel_log_history_configure (history, "diagnostics", NULL));
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
        length += fread (records + length, 1, sizeof (records) - length - 1, file);
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
    hev_socks5_session_set_task (HEV_SOCKS5_SESSION (session), hev_task_self ());
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

    assert (!strcmp (hev_lwip_error_string (ERR_TIMEOUT), "timeout"));
    assert (!strcmp (hev_lwip_error_string (ERR_RTE), "no-route"));
    assert (!strcmp (hev_lwip_error_string (-99), "unknown-lwip-error"));
    puts ("PASS tunnel diagnostics: TCP reset, read/write errno, EOF, cancellation, JSONL history");
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
