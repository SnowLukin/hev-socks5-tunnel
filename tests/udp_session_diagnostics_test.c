#include <assert.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <lwip/init.h>
#include <lwip/ip4.h>
#include <lwip/inet_chksum.h>
#include <lwip/netif.h>
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
        length +=
            fread (records + length, 1, sizeof (records) - length - 1, file);
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

static err_t
init_input_netif (struct netif *netif)
{
    (void)netif;
    return ERR_OK;
}

static void
receive_frame_through_ip4 (HevSocks5SessionUDP *session)
{
    unsigned char packet[] = {
        0x45, 0, 0, 31, 0, 1, 0, 0, 64, 17, 0, 0,
        192, 0, 2, 7, 203, 0, 113, 42,
        0xa0, 0x28, 0x14, 0xe9, 0, 11, 0, 0, 'd', 'n', 's'
    };
    struct netif netif = { 0 };
    struct pbuf *p;
    ip4_addr_t address, mask, gateway;
    uint16_t checksum;

    IP4_ADDR (&address, 203, 0, 113, 42);
    IP4_ADDR (&mask, 255, 255, 255, 0);
    IP4_ADDR (&gateway, 203, 0, 113, 1);
    assert (netif_add (&netif, &address, &mask, &gateway, NULL,
                       init_input_netif, NULL));
    netif_set_up (&netif);
    netif_set_link_up (&netif);
    checksum = inet_chksum (packet, 20);
    memcpy (packet + 10, &checksum, sizeof (checksum));
    p = pbuf_alloc (PBUF_RAW, sizeof (packet), PBUF_RAM);
    assert (p);
    assert (pbuf_take (p, packet, sizeof (packet)) == ERR_OK);
    assert (ip4_input (p, &netif) == ERR_OK);
    assert (session->frames == 1);
    netif_remove (&netif);
}

static void
expect_partial_tcp_frame_stops_receive (HevTaskMutex *mutex, int ending)
{
    HevSocks5SessionUDP *session;
    int fd[2], flags;

    begin_history ();
    session = new_session (mutex);
    HEV_SOCKS5 (session)->type = HEV_SOCKS5_TYPE_UDP_IN_TCP;
    assert (!socketpair (AF_UNIX, SOCK_STREAM, 0, fd));
    HEV_SOCKS5 (session)->fd = fd[0];
    flags = fcntl (fd[0], F_GETFL, 0);
    assert (flags >= 0);
    assert (!fcntl (fd[0], F_SETFL, flags | O_NONBLOCK));
    assert (!hev_task_add_fd (hev_task_self (), fd[0], POLLIN));
    assert (write (fd[1], "x", 1) == 1);
    if (ending == 0)
        hev_socks5_set_timeout (HEV_SOCKS5 (session), 1);
    else if (ending == 1)
        assert (!shutdown (fd[1], SHUT_WR));
    else
        hev_socks5_session_terminate (HEV_SOCKS5_SESSION (session));

    assert (hev_socks5_session_udp_fwd_b (session, 2) < 0);
    if (ending == 2) {
        read_history ();
        assert (!strstr (records, "socks5 failure"));
    } else {
        expect_one_failure ("target=udp-association", "operation=udp-read",
                            ending == 0 ? "reason=timeout" :
                                          "reason=unexpected EOF");
    }
    hev_object_unref (HEV_OBJECT (session));
    close (fd[1]);
}

typedef struct
{
    int listener;
    int relay;
} LocalSocksServer;

static void
read_exact (int fd, void *buffer, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t count = recv (fd, (char *)buffer + offset, length - offset, 0);
        assert (count > 0);
        offset += count;
    }
}

static void
write_exact (int fd, const void *buffer, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t count =
            send (fd, (const char *)buffer + offset, length - offset, 0);
        assert (count > 0);
        offset += count;
    }
}

static int
bound_loopback_socket (int type, uint16_t *port)
{
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = 0,
    };
    socklen_t length = sizeof (address);
    int fd = socket (AF_INET, type, 0);

    assert (fd >= 0);
    address.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    assert (!bind (fd, (struct sockaddr *)&address, sizeof (address)));
    assert (!getsockname (fd, (struct sockaddr *)&address, &length));
    *port = ntohs (address.sin_port);
    return fd;
}

static void *
serve_udp_association (void *data)
{
    LocalSocksServer *server = data;
    struct pollfd wait_for_socket = {
        .fd = server->listener,
        .events = POLLIN,
    };
    struct sockaddr_in relay_address;
    socklen_t address_length = sizeof (relay_address);
    unsigned char auth[3], request[4], destination[18], packet[64];
    unsigned char method[] = { 5, 0 };
    unsigned char response[] = { 5, 0, 0, 1, 127, 0, 0, 1, 0, 0 };
    int control;
    int address_size;

    assert (poll (&wait_for_socket, 1, 3000) == 1);
    control = accept (server->listener, NULL, NULL);
    assert (control >= 0);
    read_exact (control, auth, sizeof (auth));
    assert (auth[0] == 5 && auth[1] == 1 && auth[2] == 0);
    write_exact (control, method, sizeof (method));

    read_exact (control, request, sizeof (request));
    assert (request[0] == 5 && request[1] == 3 && request[2] == 0);
    address_size = request[3] == 1 ? 6 : request[3] == 4 ? 18 : 0;
    assert (address_size);
    read_exact (control, destination, address_size);

    assert (!getsockname (server->relay, (struct sockaddr *)&relay_address,
                          &address_length));
    memcpy (&response[8], &relay_address.sin_port,
            sizeof (relay_address.sin_port));
    write_exact (control, response, sizeof (response));

    wait_for_socket.fd = server->relay;
    assert (poll (&wait_for_socket, 1, 3000) == 1);
    assert (recv (server->relay, packet, sizeof (packet), 0) > 3);
    close (control);
    return NULL;
}

static void
expect_session_run_switches_to_association (HevTaskMutex *mutex)
{
    HevConfigServer *config = hev_config_get_socks5_server ();
    LocalSocksServer server;
    HevSocks5SessionUDP *session;
    uint16_t port;
    pthread_t thread;

    server.listener = bound_loopback_socket (SOCK_STREAM, &port);
    assert (!listen (server.listener, 1));
    config->port = port;
    server.relay = bound_loopback_socket (SOCK_DGRAM, &port);
    config->udp_in_udp = 1;
    config->pipeline = 0;
    config->user = NULL;
    config->pass = NULL;
    strcpy (config->addr, "127.0.0.1");

    begin_history ();
    session = new_session (mutex);
    receive_frame (session);
    assert (!strcmp (HEV_SOCKS5 (session)->diagnostic_target,
                     "[203.0.113.42]:5353"));
    assert (!pthread_create (&thread, NULL, serve_udp_association, &server));
    hev_socks5_session_run (HEV_SOCKS5_SESSION (session));
    assert (!pthread_join (thread, NULL));
    expect_one_failure ("target=udp-association", "operation=udp-control",
                        "reason=proxy-closed-association");
    assert (!strstr (records, "target=[203.0.113.42]:5353"));
    assert (!strstr (records, "reason=timeout"));
    hev_object_unref (HEV_OBJECT (session));
    close (server.listener);
    close (server.relay);
    config->udp_in_udp = 0;
}

static void
run (void *data)
{
    HevTaskMutex mutex;
    HevSocks5SessionUDP *session;
    (void)data;

    hev_task_mutex_init (&mutex);

    begin_history ();
    session = new_session (&mutex);
    receive_frame_through_ip4 (session);
    receive_frame (session);
    assert (session->frames == 2);
    assert (!strcmp (HEV_SOCKS5 (session)->diagnostic_target,
                     "[203.0.113.42]:5353"));
    read_history ();
    assert (!strstr (records, "socks5 failure"));
    assert (!strstr (records, "udp-receive"));
    assert (!strstr (records, "udp-send"));
    hev_object_unref (HEV_OBJECT (session));

    expect_partial_tcp_frame_stops_receive (&mutex, 0);
    expect_partial_tcp_frame_stops_receive (&mutex, 1);
    expect_partial_tcp_frame_stops_receive (&mutex, 2);

    begin_history ();
    session = new_session (&mutex);
    receive_frame (session);
    hev_socks5_log_failure (HEV_SOCKS5 (session), "proxy-connect",
                            "connect-failed", 0);
    expect_one_failure ("target=[203.0.113.42]:5353", "operation=proxy-connect",
                        "reason=connect-failed");
    hev_object_unref (HEV_OBJECT (session));

    expect_session_run_switches_to_association (&mutex);

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

    assert (!strcmp (hev_lwip_error_string (ERR_TIMEOUT), "timeout"));
    assert (!strcmp (hev_lwip_error_string (ERR_RTE), "no-route"));
    assert (!strcmp (hev_lwip_error_string (ERR_RST), "connection-reset"));
    assert (!strcmp (hev_lwip_error_string (-99), "unknown-lwip-error"));
    puts (
        "PASS tunnel diagnostics: UDP target, quiet frames, control EOF/error, cancellation, lwIP reasons");
}

int
main (void)
{
    HevTask *task;
    const char *config =
        "misc: {udp-copy-buffer-nums: 2, udp-read-write-timeout: 2000}";

    lwip_init ();
    assert (!hev_config_init_from_str ((const unsigned char *)config,
                                       strlen (config)));
    assert (!hev_task_system_init ());
    task = hev_task_new (65536);
    assert (task);
    hev_task_run (task, run, NULL);
    hev_task_system_run ();
    hev_task_system_fini ();
    return 0;
}
