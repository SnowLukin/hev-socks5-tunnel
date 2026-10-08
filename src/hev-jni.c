/*
 ============================================================================
 Name        : hev-jni.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2019 - 2023 hev
 Description : Jave Native Interface
 ============================================================================
 */

#ifdef ANDROID

#include <jni.h>
#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <string.h>

#include "hev-main.h"
#include "hev-socks5-log-history.h"

#include "hev-jni.h"

/* clang-format off */
#ifndef PKGNAME
#define PKGNAME hev/htproxy
#endif
#ifndef CLSNAME
#define CLSNAME TProxyService
#endif
/* clang-format on */

#define STR(s) STR_ARG (s)
#define STR_ARG(c) #c
#define N_ELEMENTS(arr) (sizeof (arr) / sizeof ((arr)[0]))

typedef struct _ThreadData ThreadData;

struct _ThreadData
{
    char *path;
    int fd;
};

static int is_working;
static JavaVM *java_vm;
static pthread_t work_thread;
static pthread_mutex_t mutex;
static pthread_key_t current_jni_env;

static void native_start_service (JNIEnv *env, jobject thiz, jstring conig_path,
                                  jint fd);
static void native_stop_service (JNIEnv *env, jobject thiz);
static jlongArray native_get_stats (JNIEnv *env, jobject thiz);
static void native_configure_log_history (JNIEnv *env, jobject thiz, jstring json);
static jstring native_get_log_history_state (JNIEnv *env, jobject thiz);

static JNINativeMethod native_methods[] = {
    { "TProxyStartService", "(Ljava/lang/String;I)V",
      (void *)native_start_service },
    { "TProxyStopService", "()V", (void *)native_stop_service },
    { "TProxyGetStats", "()[J", (void *)native_get_stats },
    { "ConfigureLogHistory", "(Ljava/lang/String;)V",
      (void *)native_configure_log_history },
    { "GetLogHistoryState", "()Ljava/lang/String;",
      (void *)native_get_log_history_state },
};

static int
json_string_value (const char *json, const char *key, char *value, size_t value_size)
{
    const char *cursor;
    size_t length = 0;

    cursor = strstr (json, key);
    if (!cursor)
        return 0;
    cursor = strchr (cursor + strlen (key), ':');
    if (!cursor)
        return -1;
    cursor++;
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n' || *cursor == '\r')
        cursor++;
    if (*cursor != '"')
        return -1;
    cursor++;
    while (*cursor && *cursor != '"') {
        char c = *cursor++;

        if (c == '\\') {
            c = *cursor++;
            if (!c)
                return -1;
            switch (c) {
            case '"':
            case '\\':
            case '/':
                break;
            case 'b':
                c = '\b';
                break;
            case 'f':
                c = '\f';
                break;
            case 'n':
                c = '\n';
                break;
            case 'r':
                c = '\r';
                break;
            case 't':
                c = '\t';
                break;
            default:
                return -1;
            }
        }
        if (c == '\0' || length + 1 >= value_size)
            return -1;
        value[length++] = c;
    }
    if (*cursor != '"')
        return -1;
    value[length] = '\0';
    return 1;
}

static int
json_size_value (const char *json, const char *key, size_t *value)
{
    const char *cursor;
    char *end;
    unsigned long long parsed;

    cursor = strstr (json, key);
    if (!cursor)
        return 0;
    cursor = strchr (cursor + strlen (key), ':');
    if (!cursor)
        return -1;
    errno = 0;
    parsed = strtoull (cursor + 1, &end, 10);
    if (errno || end == cursor + 1 || parsed > SIZE_MAX)
        return -1;
    *value = (size_t)parsed;
    return 1;
}

static int
configure_log_history_json (const char *json)
{
    HevSocks5LogHistoryPolicy policy;
    char directory[1025];
    char connection_id[513];
    int value;

    if (!json || !*json || 0 == strcmp (json, "null"))
        return hev_socks5_tunnel_log_history_configure (NULL, NULL, NULL);

    value = json_string_value (json, "\"directory\"", directory, sizeof (directory));
    if (value != 1 || directory[0] != '/')
        return -1;
    value = json_string_value (json, "\"connectionId\"", connection_id, sizeof (connection_id));
    if (value < 0)
        return -1;
    if (value == 0)
        connection_id[0] = '\0';

    policy.max_segment_bytes = 2u * 1024u * 1024u;
    policy.max_source_bytes = 8u * 1024u * 1024u;
    policy.max_segments = 4u;
    value = json_size_value (json, "\"maxSegmentBytes\"", &policy.max_segment_bytes);
    if (value < 0)
        return -1;
    value = json_size_value (json, "\"maxSourceBytes\"", &policy.max_source_bytes);
    if (value < 0)
        return -1;
    {
        size_t max_segments = policy.max_segments;
        value = json_size_value (json, "\"maxSegments\"", &max_segments);
        if (value < 0 || max_segments > UINT_MAX)
            return -1;
        policy.max_segments = (unsigned int)max_segments;
    }
    return hev_socks5_tunnel_log_history_configure (
        directory, connection_id[0] ? connection_id : NULL, &policy);
}

static void
detach_current_thread (void *env)
{
    (*java_vm)->DetachCurrentThread (java_vm);
}

jint
JNI_OnLoad (JavaVM *vm, void *reserved)
{
    JNIEnv *env = NULL;
    jclass klass;

    java_vm = vm;
    if (JNI_OK != (*vm)->GetEnv (vm, (void **)&env, JNI_VERSION_1_4)) {
        return 0;
    }

    klass = (*env)->FindClass (env, STR (PKGNAME) "/" STR (CLSNAME));
    (*env)->RegisterNatives (env, klass, native_methods,
                             N_ELEMENTS (native_methods));
    (*env)->DeleteLocalRef (env, klass);

    pthread_key_create (&current_jni_env, detach_current_thread);
    pthread_mutex_init (&mutex, NULL);

    return JNI_VERSION_1_4;
}

static void *
thread_handler (void *data)
{
    ThreadData *tdata = data;

    hev_socks5_tunnel_main (tdata->path, tdata->fd);

    free (tdata->path);
    free (tdata);

    return NULL;
}

static void
native_start_service (JNIEnv *env, jobject thiz, jstring config_path, jint fd)
{
    const jbyte *bytes;
    ThreadData *tdata;
    int res;

    pthread_mutex_lock (&mutex);

    if (is_working)
        goto exit;

    tdata = malloc (sizeof (ThreadData));
    tdata->fd = fd;

    bytes = (const jbyte *)(*env)->GetStringUTFChars (env, config_path, NULL);
    tdata->path = strdup ((const char *)bytes);
    (*env)->ReleaseStringUTFChars (env, config_path, (const char *)bytes);

    res = pthread_create (&work_thread, NULL, thread_handler, tdata);
    if (res < 0) {
        free (tdata->path);
        free (tdata);
        goto exit;
    }

    is_working = 1;
exit:
    pthread_mutex_unlock (&mutex);
}

static void
native_stop_service (JNIEnv *env, jobject thiz)
{
    pthread_mutex_lock (&mutex);

    if (!is_working)
        goto exit;

    hev_socks5_tunnel_quit ();
    pthread_join (work_thread, NULL);

    is_working = 0;
exit:
    pthread_mutex_unlock (&mutex);
}

static void
native_configure_log_history (JNIEnv *env, jobject thiz, jstring json)
{
    const char *value = NULL;

    if (json)
        value = (*env)->GetStringUTFChars (env, json, NULL);
    pthread_mutex_lock (&mutex);
    if (!is_working || !value || !*value || 0 == strcmp (value, "null"))
        configure_log_history_json (value);
    pthread_mutex_unlock (&mutex);
    if (value)
        (*env)->ReleaseStringUTFChars (env, json, value);
}

static jstring
native_get_log_history_state (JNIEnv *env, jobject thiz)
{
    char state[4096];

    if (hev_socks5_tunnel_log_history_state (state, sizeof (state)) < 0)
        return (*env)->NewStringUTF (env, "{\"v\":1,\"status\":\"closed\"}");
    return (*env)->NewStringUTF (env, state);
}

static jlongArray
native_get_stats (JNIEnv *env, jobject thiz)
{
    size_t tx_packets, rx_packets, tx_bytes, rx_bytes;
    jlongArray res;
    jlong array[4];

    hev_socks5_tunnel_stats (&tx_packets, &tx_bytes, &rx_packets, &rx_bytes);
    array[0] = tx_packets;
    array[1] = tx_bytes;
    array[2] = rx_packets;
    array[3] = rx_bytes;

    res = (*env)->NewLongArray (env, 4);
    (*env)->SetLongArrayRegion (env, res, 0, 4, array);

    return res;
}

#endif /* ANDROID */
