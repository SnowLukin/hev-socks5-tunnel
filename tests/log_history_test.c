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

static int
parts_have_complete_utf8_before_marker (const char *directory)
{
    struct dirent *entry;
    char path[1024];
    char content[4096];
    const char *message;
    const char *marker;
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
        message = strstr (content, "\"message\":\"");
        marker = strstr (content, " [truncated]");
        if (message && marker) {
            message += strlen ("\"message\":\"");
            if ((marker - message) % 2 == 0 &&
                (unsigned char)marker[-2] == 0xd0 &&
                (unsigned char)marker[-1] == 0x96) {
                closedir (dir);
                return 1;
            }
        }
    }
    closedir (dir);
    return 0;
}

static int
utf8_valid (const unsigned char *data, size_t length)
{
    size_t index = 0;

    while (index < length) {
        unsigned char first = data[index++];
        unsigned char second;

        if (first < 0x80)
            continue;
        if (first >= 0xc2 && first <= 0xdf) {
            if (index >= length || (data[index++] & 0xc0) != 0x80)
                return 0;
            continue;
        }
        if (first >= 0xe0 && first <= 0xef) {
            if (index + 1 >= length)
                return 0;
            second = data[index++];
            if ((second & 0xc0) != 0x80 ||
                (first == 0xe0 && second < 0xa0) ||
                (first == 0xed && second > 0x9f) ||
                (data[index++] & 0xc0) != 0x80)
                return 0;
            continue;
        }
        if (first >= 0xf0 && first <= 0xf4) {
            if (index + 2 >= length)
                return 0;
            second = data[index++];
            if ((second & 0xc0) != 0x80 ||
                (first == 0xf0 && second < 0x90) ||
                (first == 0xf4 && second > 0x8f) ||
                (data[index++] & 0xc0) != 0x80 ||
                (data[index++] & 0xc0) != 0x80)
                return 0;
            continue;
        }
        return 0;
    }
    return 1;
}

static const unsigned char *
skip_json_space (const unsigned char *cursor, const unsigned char *end)
{
    while (cursor < end && (*cursor == ' ' || *cursor == '\t' ||
                            *cursor == '\r' || *cursor == '\n'))
        cursor++;
    return cursor;
}

static int
json_string_end (const unsigned char **cursor, const unsigned char *end)
{
    const unsigned char *value = *cursor;

    if (value >= end || *value++ != '"')
        return 0;
    while (value < end) {
        if (*value == '"') {
            *cursor = value + 1;
            return 1;
        }
        if (*value == '\\') {
            value++;
            if (value >= end)
                return 0;
            if (*value == 'u') {
                int index;

                for (index = 0; index < 4; index++) {
                    value++;
                    if (value >= end || !((*value >= '0' && *value <= '9') ||
                                          (*value >= 'a' && *value <= 'f') ||
                                          (*value >= 'A' && *value <= 'F')))
                        return 0;
                }
            } else if (!strchr ("\"\\/bfnrt", *value)) {
                return 0;
            }
        } else if (*value < 0x20) {
            return 0;
        }
        value++;
    }
    return 0;
}

static int
json_record_is_valid (const unsigned char *record, size_t length)
{
    const unsigned char *cursor = record;
    const unsigned char *end = record + length;

    if (!utf8_valid (record, length))
        return 0;
    cursor = skip_json_space (cursor, end);
    if (cursor >= end || *cursor++ != '{')
        return 0;
    for (;;) {
        cursor = skip_json_space (cursor, end);
        if (!json_string_end (&cursor, end))
            return 0;
        cursor = skip_json_space (cursor, end);
        if (cursor >= end || *cursor++ != ':')
            return 0;
        cursor = skip_json_space (cursor, end);
        if (cursor >= end)
            return 0;
        if (*cursor == '"') {
            if (!json_string_end (&cursor, end))
                return 0;
        } else {
            while (cursor < end && *cursor != ',' && *cursor != '}')
                cursor++;
            if (cursor == end)
                return 0;
        }
        cursor = skip_json_space (cursor, end);
        if (cursor < end && *cursor == ',') {
            cursor++;
            continue;
        }
        if (cursor < end && *cursor++ == '}') {
            cursor = skip_json_space (cursor, end);
            return cursor == end;
        }
        return 0;
    }
}

static int
parts_contain_only_valid_json (const char *directory)
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
        size_t offset = 0;

        if (0 != strncmp (entry->d_name, "tun2socks.", 10) ||
            !strstr (entry->d_name, ".jsonl"))
            continue;
        snprintf (path, sizeof (path), "%s/%s", directory, entry->d_name);
        fd = open (path, O_RDONLY);
        if (fd < 0)
            fail ("open part");
        length = read (fd, content, sizeof (content));
        close (fd);
        if (length <= 0 || (size_t)length == sizeof (content))
            fail ("read JSON part");
        while (offset < (size_t)length) {
            char *newline = memchr (content + offset, '\n', (size_t)length - offset);
            size_t line_length;

            if (!newline) {
                closedir (dir);
                return 0;
            }
            line_length = (size_t)(newline - (content + offset));
            if (!json_record_is_valid ((unsigned char *)content + offset, line_length)) {
                closedir (dir);
                return 0;
            }
            offset += line_length + 1;
        }
    }
    closedir (dir);
    return 1;
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

static void
write_file (const char *path, const char *content)
{
    int fd = open (path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    size_t length = strlen (content);

    if (fd < 0 || write (fd, content, length) != (ssize_t)length)
        fail ("write file");
    close (fd);
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
    expect (!parts_contain (directory, "\"kind\":\"rotation\""),
            "keep segments for log records");

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
test_legacy_cleanup_keeps_current_log (const char *directory)
{
    HevSocks5LogHistoryPolicy policy = { 512, 2048, 4 };
    char path[1024];
    int index;

    snprintf (path, sizeof (path), "%s/tun2socks.log", directory);
    write_file (path, "current legacy\n");
    snprintf (path, sizeof (path), "%s/tun2socks.log.old", directory);
    write_file (path, "old legacy\n");
    for (index = 1; index <= 3; index++) {
        path_for_part (path, sizeof (path), directory, (unsigned int)index);
        write_file (path, "{}\n");
    }

    expect (0 == hev_socks5_tunnel_log_history_configure (directory, NULL, &policy),
            "configure legacy cleanup");
    expect (0 == hev_logger_init (HEV_LOGGER_DEBUG, "stdout"),
            "initialize legacy cleanup");
    snprintf (path, sizeof (path), "%s/tun2socks.log", directory);
    expect (access (path, F_OK) == 0, "keep current legacy log");
    snprintf (path, sizeof (path), "%s/tun2socks.log.old", directory);
    expect (access (path, F_OK) != 0, "evict old legacy log first");
    hev_logger_fini ();
}

static void
test_state_write_failure_reports_failed (const char *directory)
{
    char path[1024];
    char state[4096];

    snprintf (path, sizeof (path), "%s/.tun2socks.state.%ld", directory, (long)getpid ());
    expect (mkdir (path, 0700) == 0, "create state temp directory");
    expect (0 == hev_socks5_tunnel_log_history_configure (directory, NULL, NULL),
            "configure state temp failure");
    expect (0 == hev_logger_init (HEV_LOGGER_DEBUG, "stdout"),
            "initialize state temp failure");
    expect (0 == hev_socks5_tunnel_log_history_state (state, sizeof (state)),
            "read state temp failure");
    expect (strstr (state, "\"status\":\"failed\"") != NULL,
            "state temp failure is not active");
    expect (strstr (state, "\"errorCode\":\"state-write-failed\"") != NULL,
            "report state temp failure");
    hev_logger_fini ();
}

static void
test_state_rename_failure_reports_failed (const char *directory)
{
    char path[1024];
    char state[4096];

    snprintf (path, sizeof (path), "%s/tun2socks.state.json", directory);
    expect (mkdir (path, 0700) == 0, "create state destination directory");
    expect (0 == hev_socks5_tunnel_log_history_configure (directory, NULL, NULL),
            "configure state rename failure");
    expect (0 == hev_logger_init (HEV_LOGGER_DEBUG, "stdout"),
            "initialize state rename failure");
    expect (0 == hev_socks5_tunnel_log_history_state (state, sizeof (state)),
            "read state rename failure");
    expect (strstr (state, "\"status\":\"failed\"") != NULL,
            "state rename failure is not active");
    expect (strstr (state, "\"errorCode\":\"state-write-failed\"") != NULL,
            "report state rename failure");
    hev_logger_fini ();
}

static void
test_state_close_failure_reports_failed (const char *directory)
{
    char path[1024];
    char state[4096];

    expect (0 == hev_socks5_tunnel_log_history_configure (directory, NULL, NULL),
            "configure state close failure");
    expect (0 == hev_logger_init (HEV_LOGGER_DEBUG, "stdout"),
            "initialize state close failure");
    snprintf (path, sizeof (path), "%s/tun2socks.state.json", directory);
    expect (unlink (path) == 0, "remove active state file");
    expect (mkdir (path, 0700) == 0, "block closed state rename");
    hev_logger_fini ();
    expect (0 == hev_socks5_tunnel_log_history_state (state, sizeof (state)),
            "read state close failure");
    expect (strstr (state, "\"status\":\"failed\"") != NULL,
            "state close failure is not closed");
    expect (strstr (state, "\"errorCode\":\"state-write-failed\"") != NULL,
            "report state close failure");
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
test_rotation_preserves_fitting_record (const char *directory)
{
    HevSocks5LogHistoryPolicy policy = { 512, 2048, 4 };
    char active_path[1024];
    char *message;
    struct stat before;
    size_t length;

    expect (0 == hev_socks5_tunnel_log_history_configure (directory, NULL, &policy),
            "configure fitting rotation");
    expect (0 == hev_logger_init (HEV_LOGGER_DEBUG, "stdout"),
            "initialize fitting rotation");
    hev_logger_log (HEV_LOGGER_INFO, "seed");
    expect (newest_part (active_path, sizeof (active_path), directory),
            "find seed part");
    expect (stat (active_path, &before) == 0, "stat seed record");
    expect (before.st_size < 512, "seed leaves room for fitting record");

    length = 512 - (size_t)before.st_size + strlen ("seed");
    message = malloc (length + 1);
    if (!message)
        fail ("allocate fitting record");
    memset (message, 'r', length);
    message[length] = '\0';

    hev_logger_log (HEV_LOGGER_INFO, "%s", message);
    expect (parts_contain (directory, message),
            "preserve fitting record after rotation");
    expect (part_bytes (directory) <= 2048, "keep fitting rotation source budget");
    free (message);
    hev_logger_fini ();
}

#if defined(__APPLE__)
static void
test_startup_cleanup_failure_discards_empty_part (const char *directory)
{
    HevSocks5LogHistoryPolicy policy = { 512, 2048, 4 };
    char path[1024];
    char state[4096];
    int index;

    for (index = 1; index <= 3; index++) {
        path_for_part (path, sizeof (path), directory, (unsigned int)index);
        write_file (path, "{}\n");
    }
    path_for_part (path, sizeof (path), directory, 4);
    write_file (path, "incomplete");
    path_for_part (path, sizeof (path), directory, 1);
    expect (chflags (path, UF_IMMUTABLE) == 0, "make oldest startup part immutable");

    expect (0 == hev_socks5_tunnel_log_history_configure (directory, NULL, &policy),
            "configure startup cleanup failure");
    expect (0 == hev_logger_init (HEV_LOGGER_DEBUG, "stdout"),
            "initialize startup cleanup failure");
    expect (count_parts (directory) <= 4, "discard empty startup part after cleanup failure");
    expect (0 == hev_socks5_tunnel_log_history_state (state, sizeof (state)),
            "read startup cleanup failure state");
    expect (strstr (state, "\"status\":\"failed\"") != NULL,
            "startup cleanup failure is failed");
    expect (chflags (path, 0) == 0, "clear immutable startup part");
    hev_logger_fini ();
}

static void
test_failed_rotation_cleanup_keeps_part_count (const char *directory)
{
    HevSocks5LogHistoryPolicy policy = { 512, 2048, 1 };
    char active_path[1024];
    char state[4096];

    expect (0 == hev_socks5_tunnel_log_history_configure (directory, NULL, &policy),
            "configure cleanup failure");
    expect (0 == hev_logger_init (HEV_LOGGER_DEBUG, "stdout"),
            "initialize cleanup failure");
    hev_logger_log (HEV_LOGGER_INFO, "%0350d", 0);
    expect (newest_part (active_path, sizeof (active_path), directory),
            "find immutable old part");
    expect (chflags (active_path, UF_IMMUTABLE) == 0, "make old part immutable");
    hev_logger_log (HEV_LOGGER_INFO, "%0350d", 1);
    expect (count_parts (directory) == 1, "remove empty part after cleanup failure");
    expect (part_bytes (directory) <= 512, "do not exceed source budget after cleanup failure");
    expect (0 == hev_socks5_tunnel_log_history_state (state, sizeof (state)),
            "read cleanup failure state");
    expect (strstr (state, "\"errorCode\":\"cleanup-failed\"") != NULL,
            "report cleanup failure");
    expect (0 == hev_socks5_tunnel_log_history_configure (NULL, NULL, &policy),
            "disable failed history");
    expect (0 == hev_socks5_tunnel_log_history_state (state, sizeof (state)),
            "read failed state after disable");
    expect (strstr (state, "\"status\":\"failed\"") != NULL,
            "disable preserves failed state");
    expect (chflags (active_path, 0) == 0, "clear immutable old part");
    hev_logger_fini ();
}
#endif

static void
test_long_formatted_messages_have_marker (const char *directory)
{
    HevSocks5LogHistoryPolicy policy = { 2048, 8192, 4 };
    char message[1201];
    size_t index;

    for (index = 0; index < sizeof (message) - 1; index += 2) {
        message[index] = (char)0xd0;
        message[index + 1] = (char)0x96;
    }
    message[sizeof (message) - 1] = '\0';
    expect (0 == hev_socks5_tunnel_log_history_configure (directory, NULL, &policy),
            "configure truncated messages");
    expect (0 == hev_logger_init (HEV_LOGGER_DEBUG, "stdout"),
            "initialize root truncated message");
    expect (0 == hev_socks5_logger_init (HEV_SOCKS5_LOGGER_DEBUG, "stdout"),
            "initialize core truncated message");
    hev_logger_log (HEV_LOGGER_INFO, "%s", message);
    hev_socks5_logger_log (HEV_SOCKS5_LOGGER_INFO, "%s", message);
    expect (parts_have_complete_utf8_before_marker (directory),
            "preserve UTF-8 before truncation marker");
    hev_socks5_logger_fini ();
    hev_logger_fini ();
}

static void
test_invalid_utf8_becomes_valid_json (const char *directory)
{
    HevSocks5LogHistoryPolicy policy = { 2048, 8192, 4 };
    char invalid[] = { 'b', 'a', 'd', (char)0xff, 0 };
    char truncated[] = { 'e', 'n', 'd', (char)0xd0, 0 };
    char overlong[] = { (char)0xc0, (char)0xaf, 0 };
    char surrogate[] = { (char)0xed, (char)0xa0, (char)0x80, 0 };
    char out_of_range[] = { (char)0xf4, (char)0x90, (char)0x80, (char)0x80, 0 };
    char valid[] = { (char)0xd0, (char)0x96, (char)0xd0, (char)0xb8,
                     (char)0xd0, (char)0xb2, (char)0xd0, (char)0xbe,
                     (char)0xd0, (char)0xb9, 0 };

    expect (0 == hev_socks5_tunnel_log_history_configure (directory, NULL, &policy),
            "configure invalid UTF-8");
    expect (0 == hev_logger_init (HEV_LOGGER_DEBUG, "stdout"),
            "initialize root invalid UTF-8");
    expect (0 == hev_socks5_logger_init (HEV_SOCKS5_LOGGER_DEBUG, "stdout"),
            "initialize core invalid UTF-8");
    hev_logger_log (HEV_LOGGER_INFO, "%s", invalid);
    hev_socks5_logger_log (HEV_SOCKS5_LOGGER_INFO, "%s", truncated);
    hev_logger_log (HEV_LOGGER_INFO, "%s", overlong);
    hev_socks5_logger_log (HEV_SOCKS5_LOGGER_INFO, "%s", surrogate);
    hev_logger_log (HEV_LOGGER_INFO, "%s", out_of_range);
    hev_socks5_logger_log (HEV_SOCKS5_LOGGER_INFO, "%s", valid);
    expect (parts_contain_only_valid_json (directory),
            "invalid UTF-8 does not escape JSONL");
    expect (parts_contain (directory, "\xef\xbf\xbd"),
            "invalid UTF-8 is replaced");
    expect (parts_contain (directory, valid),
            "valid multi-byte UTF-8 survives");
    hev_socks5_logger_fini ();
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
    char legacy_cleanup_template[] = "/tmp/hev-log-history-legacy-cleanup.XXXXXX";
    char state_temp_template[] = "/tmp/hev-log-history-state-temp.XXXXXX";
    char state_rename_template[] = "/tmp/hev-log-history-state-rename.XXXXXX";
    char state_close_template[] = "/tmp/hev-log-history-state-close.XXXXXX";
    char policy_template[] = "/tmp/hev-log-history-policy.XXXXXX";
    char retention_template[] = "/tmp/hev-log-history-retention.XXXXXX";
    char fitting_template[] = "/tmp/hev-log-history-fitting.XXXXXX";
#if defined(__APPLE__)
    char cleanup_template[] = "/tmp/hev-log-history-cleanup.XXXXXX";
    char startup_cleanup_template[] = "/tmp/hev-log-history-startup-cleanup.XXXXXX";
#endif
    char truncation_template[] = "/tmp/hev-log-history-truncation.XXXXXX";
    char invalid_utf8_template[] = "/tmp/hev-log-history-invalid-utf8.XXXXXX";
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

    directory = mkdtemp (legacy_cleanup_template);
    if (!directory)
        fail ("mkdtemp");
    test_legacy_cleanup_keeps_current_log (directory);

    directory = mkdtemp (state_temp_template);
    if (!directory)
        fail ("mkdtemp");
    test_state_write_failure_reports_failed (directory);

    directory = mkdtemp (state_rename_template);
    if (!directory)
        fail ("mkdtemp");
    test_state_rename_failure_reports_failed (directory);

    directory = mkdtemp (state_close_template);
    if (!directory)
        fail ("mkdtemp");
    test_state_close_failure_reports_failed (directory);

    directory = mkdtemp (policy_template);
    if (!directory)
        fail ("mkdtemp");
    test_policy_validation (directory);

    directory = mkdtemp (retention_template);
    if (!directory)
        fail ("mkdtemp");
    test_retention_uses_part_ordinal (directory);

    directory = mkdtemp (fitting_template);
    if (!directory)
        fail ("mkdtemp");
    test_rotation_preserves_fitting_record (directory);

#if defined(__APPLE__)
    directory = mkdtemp (startup_cleanup_template);
    if (!directory)
        fail ("mkdtemp");
    test_startup_cleanup_failure_discards_empty_part (directory);

    directory = mkdtemp (cleanup_template);
    if (!directory)
        fail ("mkdtemp");
    test_failed_rotation_cleanup_keeps_part_count (directory);
#endif

    directory = mkdtemp (truncation_template);
    if (!directory)
        fail ("mkdtemp");
    test_long_formatted_messages_have_marker (directory);

    directory = mkdtemp (invalid_utf8_template);
    if (!directory)
        fail ("mkdtemp");
    test_invalid_utf8_becomes_valid_json (directory);

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
