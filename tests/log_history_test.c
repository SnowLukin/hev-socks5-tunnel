#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "hev-logger.h"
#include "hev-main.h"
#include "hev-socks5-logger.h"

void hev_socks5_logger_log (HevSocks5LoggerLevel level, const char *fmt, ...);
int hev_socks5_logger_enabled (HevSocks5LoggerLevel level);

#define SEGMENT_BYTES 2048u
#define SOURCE_BYTES (4u * SEGMENT_BYTES)

static void
fail (const char *message)
{
    fprintf (stderr, "FAIL: %s\n", message);
    exit (1);
}

static void
expect (int condition, const char *message)
{
    if (!condition)
        fail (message);
}

static int
count_parts (const char *directory)
{
    struct dirent *entry;
    DIR *dir;
    int count = 0;

    dir = opendir (directory);
    if (!dir)
        fail ("opendir");

    while ((entry = readdir (dir))) {
        if (0 == strncmp (entry->d_name, "tun2socks.", 10) &&
            strstr (entry->d_name, ".jsonl"))
            count++;
    }
    closedir (dir);

    return count;
}

static off_t
part_bytes (const char *directory)
{
    struct dirent *entry;
    struct stat st;
    char path[1024];
    DIR *dir;
    off_t total = 0;

    dir = opendir (directory);
    if (!dir)
        fail ("opendir");

    while ((entry = readdir (dir))) {
        if (0 != strncmp (entry->d_name, "tun2socks.", 10) ||
            !strstr (entry->d_name, ".jsonl"))
            continue;
        snprintf (path, sizeof (path), "%s/%s", directory, entry->d_name);
        if (stat (path, &st) < 0)
            fail ("stat part");
        total += st.st_size;
    }
    closedir (dir);

    return total;
}

static int
parts_contain (const char *directory, const char *needle)
{
    struct dirent *entry;
    char path[1024];
    char content[4096];
    DIR *dir;

    dir = opendir (directory);
    if (!dir)
        fail ("opendir");

    while ((entry = readdir (dir))) {
        int fd;
        ssize_t length;

        if (0 != strncmp (entry->d_name, "tun2socks.", 10) ||
            !strstr (entry->d_name, ".jsonl"))
            continue;
        snprintf (path, sizeof (path), "%s/%s", directory, entry->d_name);
        fd = open (path, O_RDONLY);
        if (fd < 0)
            fail ("open part");
        length = read (fd, content, sizeof (content) - 1);
        close (fd);
        if (length < 0)
            fail ("read part");
        content[length] = '\0';
        if (strstr (content, needle)) {
            closedir (dir);
            return 1;
        }
    }
    closedir (dir);
    return 0;
}

static void
path_for_part (char *path, size_t length, const char *directory, unsigned int number)
{
    snprintf (path, length, "%s/tun2socks.%020u.jsonl", directory, number);
}

static int
part_exists (const char *directory, unsigned int number)
{
    char path[1024];

    path_for_part (path, sizeof (path), directory, number);
    return access (path, F_OK) == 0;
}

static int
newest_part (char *path, size_t length, const char *directory)
{
    struct dirent *entry;
    unsigned long long newest = 0;
    DIR *dir;
    int found = 0;

    dir = opendir (directory);
    if (!dir)
        fail ("opendir");

    while ((entry = readdir (dir))) {
        unsigned long long number;
        char tail;

        if (sscanf (entry->d_name, "tun2socks.%20llu.jsonl%c", &number, &tail) != 1)
            continue;
        if (!found || number > newest) {
            newest = number;
            found = 1;
        }
    }
    closedir (dir);

    if (found)
        path_for_part (path, length, directory, (unsigned int)newest);

    return found;
}

static void
test_rotation_and_shared_owner (const char *directory)
{
    char message[900];
    char state[4096];
    char active_path[1024];
    struct stat before;
    struct stat after;
    HevSocks5LogHistoryPolicy policy = { SEGMENT_BYTES, SOURCE_BYTES, 4 };
    char connection_id[] = "connection-42";
    int i;

    memset (message, 'a', sizeof (message) - 1);
    message[sizeof (message) - 1] = '\0';

    expect (0 == hev_socks5_tunnel_log_history_configure (directory, connection_id, &policy),
            "configure history");
    connection_id[0] = 'x';
    expect (0 == hev_logger_init (HEV_LOGGER_DEBUG, "stdout"),
            "initialize tunnel logger");
    expect (0 == hev_socks5_logger_init (HEV_SOCKS5_LOGGER_DEBUG, "stdout"),
            "initialize core logger");

    for (i = 0; i < 100; i++) {
        if (i & 1)
            hev_logger_log (HEV_LOGGER_INFO, "root %s", message);
        else
            hev_socks5_logger_log (HEV_SOCKS5_LOGGER_INFO, "core %s", message);
    }

    expect (count_parts (directory) <= 4, "keep at most four parts");
    expect (part_bytes (directory) <= SOURCE_BYTES, "keep source budget");
    expect (count_parts (directory) > 1, "rotate across several parts");
    expect (parts_contain (directory, "\"kind\":\"rotation\""),
            "write a rotation record");

    expect (newest_part (active_path, sizeof (active_path), directory),
            "active part after rotations");
    expect (stat (active_path, &before) == 0, "stat active part");

    hev_logger_fini ();
    hev_socks5_logger_log (HEV_SOCKS5_LOGGER_INFO, "core survives root fini");
    expect (stat (active_path, &after) == 0, "active part remains after root fini");
    expect (after.st_ino == before.st_ino, "core writes through shared active fd");
    expect (after.st_size > before.st_size, "core appends after root fini");

    expect (0 == hev_logger_init (HEV_LOGGER_DEBUG, "stdout"),
            "reinitialize tunnel logger");
    hev_socks5_logger_fini ();
    expect (stat (active_path, &before) == 0, "active part before core fini");
    hev_logger_log (HEV_LOGGER_INFO, "root survives core fini");
    expect (stat (active_path, &after) == 0, "active part remains after core fini");
    expect (after.st_ino == before.st_ino, "root writes through shared active fd");
    expect (after.st_size > before.st_size, "root appends after core fini");
    hev_logger_fini ();
    expect (0 == hev_socks5_tunnel_log_history_state (state, sizeof (state)),
            "read state");
    expect (strstr (state, "\"status\":\"closed\"") != NULL,
            "closed state");
    expect (strstr (state, "\"connectionId\":\"connection-42\"") != NULL,
            "configured connection id is copied");
}

static void
test_crash_tail_and_json (const char *directory)
{
    char old_part[1024];
    char active_part[1024];
    char content[4096];
    HevSocks5LogHistoryPolicy policy = { SEGMENT_BYTES, SOURCE_BYTES, 4 };
    int fd;
    ssize_t length;

    path_for_part (old_part, sizeof (old_part), directory, 7);
    fd = open (old_part, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    if (fd < 0)
        fail ("create crash tail");
    if (write (fd, "{\"bad\":true}", 12) != 12)
        fail ("write crash tail");
    close (fd);

    expect (0 == hev_socks5_tunnel_log_history_configure (directory, "connection-43", &policy),
            "configure after crash tail");
    expect (0 == hev_logger_init (HEV_LOGGER_DEBUG, "stdout"),
            "initialize after crash tail");
    hev_logger_log (HEV_LOGGER_ERROR, "first\nsecond \"quoted\" \\path\tend");
    hev_logger_fini ();

    path_for_part (active_part, sizeof (active_part), directory, 8);
    fd = open (active_part, O_RDONLY);
    if (fd < 0)
        fail ("open new part after crash tail");
    length = read (fd, content, sizeof (content) - 1);
    close (fd);
    if (length < 0)
        fail ("read JSON record");
    content[length] = '\0';

    expect (strstr (content, "\"v\":1") != NULL, "JSON v1");
    expect (strstr (content, "\"source\":\"tun2socks\"") != NULL, "JSON source");
    expect (strstr (content, "\"connectionId\":\"connection-43\"") != NULL,
            "JSON connection id");
    expect (strstr (content, "first\\nsecond \\\"quoted\\\" \\\\path\\tend") != NULL,
            "JSON escapes multiline message");
}

static void
test_policy_validation (const char *directory)
{
    HevSocks5LogHistoryPolicy invalid = { 511, 2048, 4 };
    HevSocks5LogHistoryPolicy partial = { 0, 2048, 4 };
    HevSocks5LogHistoryPolicy valid = { 512, 2048, 4 };

    expect (hev_socks5_tunnel_log_history_configure (directory, NULL, &invalid) < 0,
            "reject policy below minimum segment bytes");
    expect (hev_socks5_tunnel_log_history_configure (directory, NULL, &partial) < 0,
            "reject partially defaulted policy");
    expect (0 == hev_socks5_tunnel_log_history_configure (directory, NULL, &valid),
            "accept minimum valid policy");
    expect (0 == hev_socks5_tunnel_log_history_configure (NULL, NULL, NULL),
            "disable policy after validation");
}

static void
test_open_error (const char *directory)
{
    char path[1024];
    char state[4096];
    int fd;

    snprintf (path, sizeof (path), "%s/not-a-directory", directory);
    fd = open (path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    if (fd < 0)
        fail ("create non-directory");
    close (fd);

    expect (0 == hev_socks5_tunnel_log_history_configure (path, NULL, NULL),
            "configure failing path");
    expect (0 == hev_logger_init (HEV_LOGGER_DEBUG, "stdout"),
            "keep tunnel available after log open error");
    expect (0 == hev_socks5_logger_init (HEV_SOCKS5_LOGGER_DEBUG, "stdout"),
            "keep core available after log open error");
    expect (!hev_logger_enabled (HEV_LOGGER_DEBUG),
            "disable failed history logger");
    expect (!hev_socks5_logger_enabled (HEV_SOCKS5_LOGGER_DEBUG),
            "disable failed core history logger");
    expect (0 == hev_socks5_tunnel_log_history_state (state, sizeof (state)),
            "read failed state");
    expect (strstr (state, "\"status\":\"failed\"") != NULL,
            "failed state");
    expect (strstr (state, "\"errorCode\":\"open-failed\"") != NULL,
            "safe open error code");
    hev_socks5_logger_fini ();
    hev_logger_fini ();
}

static void
test_disabled_keeps_legacy_file_route (const char *directory)
{
    char path[1024];
    char content[2048];
    char message[128];
    int fd;
    ssize_t length;

    snprintf (path, sizeof (path), "%s/legacy.log", directory);
    memset (message, 'p', sizeof (message) - 1);
    message[sizeof (message) - 1] = '\0';
    expect (0 == hev_socks5_tunnel_log_history_configure (NULL, NULL, NULL),
            "disable history");
    expect (0 == hev_logger_init (HEV_LOGGER_DEBUG, path),
            "initialize legacy file route");
    hev_logger_log (HEV_LOGGER_INFO, "%s", message);
    hev_logger_fini ();

    fd = open (path, O_RDONLY);
    if (fd < 0)
        fail ("open legacy log");
    length = read (fd, content, sizeof (content) - 1);
    close (fd);
    if (length < 0)
        fail ("read legacy log");
    content[length] = '\0';

    expect (strstr (content, message) != NULL, "complete legacy message written");
    expect (strstr (content, "\"source\":\"tun2socks\"") == NULL,
            "legacy route stays plain text");

    snprintf (path, sizeof (path), "%s/legacy-core.log", directory);
    expect (0 == hev_socks5_logger_init (HEV_SOCKS5_LOGGER_DEBUG, path),
            "initialize core legacy file route");
    hev_socks5_logger_log (HEV_SOCKS5_LOGGER_INFO, "%s", message);
    hev_socks5_logger_fini ();

    fd = open (path, O_RDONLY);
    if (fd < 0)
        fail ("open core legacy log");
    length = read (fd, content, sizeof (content) - 1);
    close (fd);
    if (length < 0)
        fail ("read core legacy log");
    content[length] = '\0';

    expect (strstr (content, message) != NULL, "complete core legacy message written");
}

static void
test_retention_uses_part_ordinal (const char *directory)
{
    HevSocks5LogHistoryPolicy policy = { 512, 2048, 4 };
    struct timeval times[2];
    char path[1024];
    int fd;
    int number;

    for (number = 1; number <= 10; number++) {
        path_for_part (path, sizeof (path), directory, (unsigned int)number);
        fd = open (path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
        if (fd < 0 || write (fd, "{}\n", 3) != 3)
            fail ("create retained part");
        close (fd);
    }
    times[0].tv_usec = 0;
    times[1].tv_usec = 0;
    times[0].tv_sec = time (NULL) + 10000;
    times[1].tv_sec = times[0].tv_sec;
    path_for_part (path, sizeof (path), directory, 1);
    if (utimes (path, times) < 0)
        fail ("set future mtime");

    expect (0 == hev_socks5_tunnel_log_history_configure (directory, NULL, &policy),
            "configure retained parts");
    expect (0 == hev_logger_init (HEV_LOGGER_DEBUG, "stdout"),
            "initialize retained parts");
    expect (count_parts (directory) == 4, "enforce complete retention limit");
    expect (!part_exists (directory, 1), "delete oldest ordinal despite future mtime");
    expect (part_exists (directory, 10), "keep current highest ordinal");
    hev_logger_fini ();
}

static void
test_restart_does_not_report_persisted_active_state (const char *directory)
{
    char path[1024];
    char state[4096];
    int fd;

    snprintf (path, sizeof (path), "%s/tun2socks.state.json", directory);
    fd = open (path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    if (fd < 0 || write (fd, "{\"v\":1,\"status\":\"active\"}\n", 26) != 26)
        fail ("create persisted active state");
    close (fd);

    expect (0 == hev_socks5_tunnel_log_history_configure (directory, NULL, NULL),
            "configure after restart");
    expect (hev_socks5_tunnel_log_history_state (state, sizeof (state)) < 0,
            "do not report persisted active state as live");
}

static void
test_oversized_metadata_does_not_exceed_part_limit (const char *directory)
{
    HevSocks5LogHistoryPolicy policy = { 512, 2048, 4 };
    char connection_id[513];
    char state[4096];

    memset (connection_id, '"', sizeof (connection_id) - 1);
    connection_id[sizeof (connection_id) - 1] = '\0';
    expect (0 == hev_socks5_tunnel_log_history_configure (directory, connection_id, &policy),
            "configure oversized metadata");
    expect (0 == hev_logger_init (HEV_LOGGER_DEBUG, "stdout"),
            "initialize oversized metadata");
    hev_logger_log (HEV_LOGGER_INFO, "message");
    expect (part_bytes (directory) <= 512, "never exceed part limit");
    expect (0 == hev_socks5_tunnel_log_history_state (state, sizeof (state)),
            "read oversized metadata state");
    expect (strstr (state, "\"errorCode\":\"record-too-large\"") != NULL,
            "report oversized metadata");
    hev_logger_fini ();
}

static void
test_active_disable_closes_history_without_stopping_loggers (const char *directory)
{
    HevSocks5LogHistoryPolicy policy = { 512, 2048, 4 };
    char active_path[1024];
    char state[4096];
    struct stat before;
    struct stat after;

    expect (0 == hev_socks5_tunnel_log_history_configure (directory, NULL, &policy),
            "configure active disable");
    expect (0 == hev_logger_init (HEV_LOGGER_DEBUG, "stdout"),
            "initialize tunnel logger before disable");
    expect (0 == hev_socks5_logger_init (HEV_SOCKS5_LOGGER_DEBUG, "stdout"),
            "initialize core logger before disable");
    hev_logger_log (HEV_LOGGER_INFO, "before active disable");
    expect (newest_part (active_path, sizeof (active_path), directory),
            "find active part before disable");
    expect (stat (active_path, &before) == 0, "stat active part before disable");

    expect (0 == hev_socks5_tunnel_log_history_configure (NULL, NULL, &policy),
            "disable active history");
    hev_logger_log (HEV_LOGGER_INFO, "root after active disable");
    hev_socks5_logger_log (HEV_SOCKS5_LOGGER_INFO, "core after active disable");
    expect (stat (active_path, &after) == 0, "stat active part after disable");
    expect (after.st_size == before.st_size, "disabled loggers do not append history");
    expect (0 == hev_socks5_tunnel_log_history_state (state, sizeof (state)),
            "read closed state after active disable");
    expect (strstr (state, "\"status\":\"closed\"") != NULL,
            "active disable writes closed state");

    hev_socks5_logger_fini ();
    hev_logger_fini ();
    expect (0 == hev_socks5_tunnel_log_history_configure (directory, NULL, &policy),
            "configure history after disabled loggers finish");
}

int
main (void)
{
    char rotation_template[] = "/tmp/hev-log-history-rotation.XXXXXX";
    char crash_template[] = "/tmp/hev-log-history-crash.XXXXXX";
    char error_template[] = "/tmp/hev-log-history-error.XXXXXX";
    char legacy_template[] = "/tmp/hev-log-history-legacy.XXXXXX";
    char policy_template[] = "/tmp/hev-log-history-policy.XXXXXX";
    char retention_template[] = "/tmp/hev-log-history-retention.XXXXXX";
    char restart_template[] = "/tmp/hev-log-history-restart.XXXXXX";
    char metadata_template[] = "/tmp/hev-log-history-metadata.XXXXXX";
    char disable_template[] = "/tmp/hev-log-history-disable.XXXXXX";
    char *directory;

    directory = mkdtemp (rotation_template);
    if (!directory)
        fail ("mkdtemp");
    test_rotation_and_shared_owner (directory);

    directory = mkdtemp (crash_template);
    if (!directory)
        fail ("mkdtemp");
    test_crash_tail_and_json (directory);

    directory = mkdtemp (error_template);
    if (!directory)
        fail ("mkdtemp");
    test_open_error (directory);

    directory = mkdtemp (legacy_template);
    if (!directory)
        fail ("mkdtemp");
    test_disabled_keeps_legacy_file_route (directory);

    directory = mkdtemp (policy_template);
    if (!directory)
        fail ("mkdtemp");
    test_policy_validation (directory);

    directory = mkdtemp (retention_template);
    if (!directory)
        fail ("mkdtemp");
    test_retention_uses_part_ordinal (directory);

    directory = mkdtemp (restart_template);
    if (!directory)
        fail ("mkdtemp");
    test_restart_does_not_report_persisted_active_state (directory);

    directory = mkdtemp (metadata_template);
    if (!directory)
        fail ("mkdtemp");
    test_oversized_metadata_does_not_exceed_part_limit (directory);

    directory = mkdtemp (disable_template);
    if (!directory)
        fail ("mkdtemp");
    test_active_disable_closes_history_without_stopping_loggers (directory);

    printf ("PASS: log history\n");
    return 0;
}
