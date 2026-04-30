/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <event2/event.h>
#include <memory.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include <strings.h>
#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include <xquic/xqc_http3.h>
#include "platform.h"
#include "src/transport/monitor/xqc_wifi_monitor.h"
#include "src/transport/scheduler/xqc_scheduler_observer.h"
#include "src/transport/xqc_stream.h"
#ifndef XQC_SYS_WINDOWS
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <getopt.h>
#else
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"event.lib")
#pragma comment(lib, "Iphlpapi.lib")
#include "getopt.h"
#endif

extern long xqc_random(void);
extern xqc_usec_t xqc_now();

int
printf_null(const char *format, ...)
{
    return 0;
}

#define XQC_ALPN_TRANSPORT      "transport"
#define XQC_ALPN_TRANSPORT_TEST "transport-test"

//#define printf printf_null

#define DEBUG printf("%s:%d (%s)\n", __FILE__, __LINE__, __FUNCTION__);

#define TEST_DROP (g_drop_rate != 0 && rand() % 1000 < g_drop_rate)

#define TEST_SERVER_ADDR "127.0.0.1"
#define TEST_SERVER_PORT 8443


#define XQC_PACKET_TMP_BUF_LEN 1500
#define MAX_BUF_SIZE (100*1024*1024)
#define XQC_TEST_CLI_LARGE_STREAM_CHUNK_SIZE (16*1024*1024)

#define XQC_MAX_TOKEN_LEN 256

#define XQC_TEST_SHORT_HEADER_PACKET_A "\x40\xAB\x3f\x12\x0a\xcd\xef\x00\x89"
#define XQC_TEST_SHORT_HEADER_PACKET_B "\x80\xAB\x3f\x12\x0a\xcd\xef\x00\x89"

#define MAX_HEADER 100

#define XQC_MAX_LOG_LEN 2048
#define XQC_TEST_CLI_SHORT_DCID_LEN 8
#define XQC_TEST_CLI_QUIC_UNKNOWN_FIELD 0xFF
#define XQC_TEST_CLI_PATH_MAP_SUFFIX ".path_map.csv"
#define XQC_TEST_CLI_SEND_TRACE_SUFFIX ".send_trace.csv"
#define XQC_TEST_CLI_WIFI_STATE_SUFFIX ".wifi_state_trace.csv"
#define XQC_TEST_CLI_SCHED_TRACE_SUFFIX ".scheduler_trace.csv"
#define XQC_TEST_CLI_REQ_TRACE_SUFFIX ".request_trace.csv"
#define XQC_TEST_CLI_STREAM_TRACE_SUFFIX ".stream_trace.csv"

typedef struct user_conn_s user_conn_t;


#define XQC_TEST_DGRAM_BATCH_SZ 32

typedef struct user_datagram_block_s {
    unsigned char *recv_data;
    unsigned char *data;
    size_t         data_len;
    size_t         data_sent;
    size_t         data_recv;
    size_t         data_lost;
    size_t         dgram_lost;
    uint32_t       dgram_id;
} user_dgram_blk_t;
typedef struct client_ctx_s {
    xqc_engine_t   *engine;
    struct event   *ev_engine;
    int             log_fd;
    int             keylog_fd;
    int             path_map_fd;
    int             send_trace_fd;
    int             wifi_state_fd;
    int             scheduler_trace_fd;
    int             request_trace_fd;
    int             stream_trace_fd;
    struct event   *ev_delay;
    struct event_base *eb;
    struct event   *ev_conc;
    int             cur_conn_num;
    char            path_map_path[256];
    char            send_trace_path[256];
    char            wifi_state_path[256];
    char            scheduler_trace_path[256];
    char            request_trace_path[256];
    char            stream_trace_path[256];
    char            wifi_monitor_output_dir[256];
    char            wifi_monitor_config_path[256];
    xqc_wifi_monitor_t *wifi_monitor;
} client_ctx_t;

typedef struct user_stream_s {
    xqc_stream_t            *stream;
    xqc_h3_request_t        *h3_request;
    user_conn_t             *user_conn;
    uint64_t                 send_offset;
    int                      header_sent;
    int                      header_recvd;
    char                    *send_body;
    size_t                   send_body_len;
    size_t                   send_body_max;
    int                      send_body_streaming;
    char                    *recv_body;
    size_t                   recv_body_len;
    FILE                    *recv_body_fp;
    int                      recv_fin;
    xqc_usec_t               start_time;
    xqc_usec_t               first_frame_time;   /* first frame download time */
    xqc_usec_t               last_read_time;
    int                      abnormal_count;
    int                      body_read_notify_cnt;
    xqc_usec_t               last_recv_log_time;
    uint64_t                 recv_log_bytes;

    xqc_h3_ext_bytestream_t *h3_ext_bs;
    struct event            *ev_bytestream_timer;

    int                      snd_times;
    int                      rcv_times;

} user_stream_t;

typedef struct user_conn_s {
    int                 fd;
    xqc_cid_t           cid;

    struct sockaddr    *local_addr;
    socklen_t           local_addrlen;
    xqc_flag_t          get_local_addr;
    struct sockaddr    *peer_addr;
    socklen_t           peer_addrlen;

    unsigned char      *token;
    unsigned            token_len;

    struct event       *ev_socket;
    struct event       *ev_timeout;
    struct event       *ev_abs_timeout;
    uint64_t            conn_create_time;

    /* 用于路径增删debug */
    struct event       *ev_path;
    struct event       *ev_epoch;

    struct event       *ev_request;


    int                 h3;

    user_dgram_blk_t   *dgram_blk;
    size_t              dgram_mss;
    uint8_t             dgram_not_supported;
    int                 dgram_retry_in_hs_cb;

    xqc_connection_t   *quic_conn;
    xqc_h3_conn_t      *h3_conn;
    client_ctx_t       *ctx;
    int                 cur_stream_num;

    uint64_t            black_hole_start_time;
    int                 tracked_pkt_cnt;
} user_conn_t;

#define XQC_DEMO_INTERFACE_MAX_LEN 64
#define XQC_DEMO_MAX_PATH_COUNT    8
#define MAX_HEADER_KEY_LEN 128
#define MAX_HEADER_VALUE_LEN 4096

typedef struct xqc_user_path_s {
    int                 path_fd;
    uint64_t            path_id;
    int                 is_in_used;
    size_t              send_size;
    int                 path_seq;
    unsigned int        ifindex;
    char                ifname[XQC_DEMO_INTERFACE_MAX_LEN];
    user_conn_t        *user_conn;

    struct sockaddr    *peer_addr;
    socklen_t           peer_addrlen;
    struct sockaddr    *local_addr;
    socklen_t           local_addrlen;

    struct event       *ev_socket;

    int                 rebinding_path_fd;
    struct event       *rebinding_ev_socket;
} xqc_user_path_t;


typedef struct {
    double p;
    int val;
} cdf_entry_t;


static char *g_server_addr = NULL;
int g_server_port = TEST_SERVER_PORT;
int g_transport = 0;
int g_conn_count = 0;
int g_max_conn_num = 1000;
int g_conn_num = 100;
int g_process_num = 2;
int g_test_qch_mode = 0;
int g_random_cid = 0;
xqc_data_qos_level_t g_dgram_qos_level;
xqc_conn_settings_t *g_conn_settings;

unsigned char sock_op_buffer[2000];
size_t sock_op_buffer_len = 0;
size_t dgram1_size = 0;
size_t dgram2_size = 0;

int dgram_drop_pkt1 = 0;
client_ctx_t ctx;
struct event_base *eb;
int g_send_dgram;
int g_max_dgram_size;
int g_req_cnt;
int g_bytestream_cnt;
int g_req_max;
size_t g_send_body_size;
int g_send_body_size_defined;
int g_send_body_size_from_cdf;
cdf_entry_t *cdf_list;
int cdf_list_size;
int g_req_paral = 1;
int g_req_per_time = 0;
int g_recovery = 0;
int g_save_body;
int g_read_body;
int g_echo_check;
int g_drop_rate;
int g_spec_url;
int g_is_get;
uint64_t g_last_sock_op_time;
static volatile sig_atomic_t g_stop_signal = 0;
static volatile sig_atomic_t g_stop_requested = 0;
static struct event_base *g_stop_event_base = NULL;
//currently, the maximum used test case id is 19
//please keep this comment updated if you are adding more test cases. :-D
//99 for pure fin
//2XX for datagram testcases
//3XX for h3 ext bytestream testcases
//4XX for conn_settings configuration
int g_test_case;
int g_ipv6;
int g_no_crypt;
int g_conn_timeout = 1;
int g_conn_abs_timeout = 0;
int g_path_timeout = 5000000; /* 5s */
int g_epoch_timeout = 1000000; /* us */
char g_write_file[256];
char g_read_file[256];
char g_log_path[256];
char g_host[64] = "test.xquic.com";
char g_url_path[256] = "/path/resource";
char g_scheme[8] = "https";
char g_url[2048];
char g_headers[MAX_HEADER][256];
int g_header_cnt = 0;
int g_ping_id = 1;
int g_enable_multipath = 0;
xqc_multipath_version_t g_multipath_version = XQC_MULTIPATH_10;
int g_enable_fec = 0;
int g_enable_reinjection = 0;
int g_verify_cert = 0;
int g_verify_cert_allow_self_sign = 0;
int g_enable_wifi_monitor = 0;
int g_header_num = 6;
int g_epoch = 0;
int g_cur_epoch = 0;
int g_mp_backup_mode = 0;
int g_mp_request_accelerate = 0;
double g_copa_ai = 1.0;
double g_copa_delta = 0.05;
int g_pmtud_on = 0;
int g_mp_ping_on = 0;
char g_header_key[MAX_HEADER_KEY_LEN];
char g_header_value[MAX_HEADER_VALUE_LEN];
char g_scheduler_name[64];

char g_multi_interface[XQC_DEMO_MAX_PATH_COUNT][64];
xqc_user_path_t g_client_path[XQC_DEMO_MAX_PATH_COUNT];
int g_multi_interface_cnt = 0;
int mp_has_recved = 0;
char g_priority[64] = {'\0'};
char g_wifi_monitor_output_dir[256];
char g_wifi_monitor_config_path[256];

unsigned char g_token[XQC_MAX_TOKEN_LEN];
int g_token_len = 0;

/* 用于路径增删debug */
int g_debug_path = 0;

#define XQC_TEST_LONG_HEADER_LEN 32769
char test_long_value[XQC_TEST_LONG_HEADER_LEN] = {'\0'};

int hsk_completed = 0;


int g_periodically_request = 0;

static uint64_t last_recv_ts = 0;

static int g_timeout_flag = 0;

static const char *xqc_test_line_break = "\n";

typedef struct xqc_test_cli_quic_visible_fields_s {
    uint8_t                 header_form;
    uint8_t                 pkt_type;
    uint8_t                 dcid_len;
    unsigned char           dcid[20];
    unsigned char           pn_raw[4];
    uint8_t                 pn_len;
} xqc_test_cli_quic_visible_fields_t;

static void
xqc_test_cli_init_quic_visible_fields(xqc_test_cli_quic_visible_fields_t *fields)
{
    if (fields == NULL) {
        return;
    }

    memset(fields, 0, sizeof(*fields));
    fields->header_form = XQC_TEST_CLI_QUIC_UNKNOWN_FIELD;
    fields->pkt_type = XQC_TEST_CLI_QUIC_UNKNOWN_FIELD;
}

static void
xqc_test_cli_format_hex_compact(const unsigned char *src, size_t len,
    char *dst, size_t dst_len)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;

    if (dst == NULL || dst_len == 0) {
        return;
    }

    if (src == NULL || len == 0 || dst_len < 2 || dst_len < (len * 2 + 1)) {
        snprintf(dst, dst_len, "-");
        return;
    }

    for (i = 0; i < len; i++) {
        dst[i * 2] = hex[(src[i] >> 4) & 0x0f];
        dst[i * 2 + 1] = hex[src[i] & 0x0f];
    }
    dst[len * 2] = '\0';
}

static int
xqc_test_cli_read_varint(const unsigned char *buf, size_t buf_len, size_t offset,
    uint64_t *value, uint8_t *encoded_len)
{
    uint8_t b0;
    uint8_t varint_len;
    size_t i;

    if (buf == NULL || value == NULL || encoded_len == NULL || offset >= buf_len) {
        return -1;
    }

    b0 = buf[offset];
    switch (b0 >> 6) {
    case 0:
        varint_len = 1;
        break;
    case 1:
        varint_len = 2;
        break;
    case 2:
        varint_len = 4;
        break;
    default:
        varint_len = 8;
        break;
    }

    if (offset + varint_len > buf_len) {
        return -1;
    }

    *value = (uint64_t) (b0 & 0x3f);
    for (i = 1; i < varint_len; i++) {
        *value = (*value << 8) | buf[offset + i];
    }
    *encoded_len = varint_len;
    return 0;
}

static void
xqc_test_cli_parse_quic_visible_fields(const unsigned char *buf, size_t buf_len,
    xqc_test_cli_quic_visible_fields_t *fields)
{
    uint8_t byte0;
    size_t cursor;
    uint32_t version;
    uint8_t dcid_len_raw, dcid_copy_len, scid_len_raw, pn_len_local, varint_len;
    uint64_t varint_value;

    xqc_test_cli_init_quic_visible_fields(fields);

    if (buf == NULL || fields == NULL || buf_len == 0) {
        return;
    }

    byte0 = buf[0];
    if ((byte0 & 0x40) == 0) {
        return;
    }

    fields->header_form = (byte0 >> 7) & 0x01;

    if (fields->header_form == 0) {
        size_t short_dcid_len = XQC_TEST_CLI_SHORT_DCID_LEN;

        if (buf_len < 1 + short_dcid_len) {
            return;
        }

        memcpy(fields->dcid, buf + 1, short_dcid_len);
        fields->dcid_len = short_dcid_len;
        fields->pkt_type = XQC_TEST_CLI_QUIC_UNKNOWN_FIELD;

        pn_len_local = (byte0 & 0x03) + 1;
        if (buf_len < 1 + short_dcid_len + pn_len_local) {
            xqc_test_cli_init_quic_visible_fields(fields);
            return;
        }

        memcpy(fields->pn_raw, buf + 1 + short_dcid_len, pn_len_local);
        fields->pn_len = pn_len_local;
        return;
    }

    if (buf_len < 6) {
        return;
    }

    version = ((uint32_t) buf[1] << 24)
        | ((uint32_t) buf[2] << 16)
        | ((uint32_t) buf[3] << 8)
        | (uint32_t) buf[4];

    dcid_len_raw = buf[5];
    if (buf_len < 6 + dcid_len_raw + 1) {
        return;
    }

    dcid_copy_len = dcid_len_raw > sizeof(fields->dcid)
        ? sizeof(fields->dcid) : dcid_len_raw;
    memcpy(fields->dcid, buf + 6, dcid_copy_len);
    fields->dcid_len = dcid_copy_len;

    cursor = 6 + dcid_len_raw;
    scid_len_raw = buf[cursor];
    cursor += 1 + scid_len_raw;
    if (cursor > buf_len) {
        xqc_test_cli_init_quic_visible_fields(fields);
        return;
    }

    if (version == 0) {
        fields->pkt_type = XQC_TEST_CLI_QUIC_UNKNOWN_FIELD;
        return;
    }

    fields->pkt_type = (byte0 >> 4) & 0x03;
    if (fields->pkt_type == 3) {
        return;
    }

    pn_len_local = (byte0 & 0x03) + 1;

    if (fields->pkt_type == 0) {
        if (xqc_test_cli_read_varint(buf, buf_len, cursor, &varint_value, &varint_len) != 0) {
            xqc_test_cli_init_quic_visible_fields(fields);
            return;
        }
        cursor += varint_len + (size_t) varint_value;
        if (cursor > buf_len) {
            xqc_test_cli_init_quic_visible_fields(fields);
            return;
        }
    }

    if (xqc_test_cli_read_varint(buf, buf_len, cursor, &varint_value, &varint_len) != 0) {
        xqc_test_cli_init_quic_visible_fields(fields);
        return;
    }
    cursor += varint_len;
    if (cursor + pn_len_local > buf_len) {
        xqc_test_cli_init_quic_visible_fields(fields);
        return;
    }

    memcpy(fields->pn_raw, buf + cursor, pn_len_local);
    fields->pn_len = pn_len_local;
}

static void
xqc_test_cli_build_aux_path(const char *log_path, const char *suffix,
    char *out, size_t out_len)
{
    char base[256];
    char *slash;
    char *dot;

    if (out == NULL || out_len == 0 || suffix == NULL) {
        return;
    }

    if (log_path == NULL || log_path[0] == '\0') {
        snprintf(out, out_len, ".%s", suffix);
        return;
    }

    snprintf(base, sizeof(base), "%s", log_path);
    slash = strrchr(base, '/');
    dot = strrchr(base, '.');
    if (dot != NULL && (slash == NULL || dot > slash)) {
        *dot = '\0';
    }

    snprintf(out, out_len, "%s%s", base, suffix);
}

static int
xqc_test_cli_open_aux_csv(const char *path, const char *header)
{
    int fd;
    off_t end;

    if (path == NULL || header == NULL) {
        return -1;
    }

    fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd < 0) {
        return -1;
    }

    end = lseek(fd, 0, SEEK_END);
    if (end == 0) {
        if (write(fd, header, strlen(header)) < 0
            || write(fd, xqc_test_line_break, 1) < 0)
        {
            close(fd);
            return -1;
        }
    }

    return fd;
}

static void
xqc_test_cli_write_aux_line(int fd, const char *line)
{
    if (fd <= 0 || line == NULL) {
        return;
    }

    if (write(fd, line, strlen(line)) < 0) {
        return;
    }

    (void) write(fd, xqc_test_line_break, 1);
}

static void
xqc_test_cli_open_aux_trace_files(client_ctx_t *c)
{
    if (c == NULL) {
        return;
    }

    xqc_test_cli_build_aux_path(g_log_path, XQC_TEST_CLI_PATH_MAP_SUFFIX,
        c->path_map_path, sizeof(c->path_map_path));
    xqc_test_cli_build_aux_path(g_log_path, XQC_TEST_CLI_SEND_TRACE_SUFFIX,
        c->send_trace_path, sizeof(c->send_trace_path));
    xqc_test_cli_build_aux_path(g_log_path, XQC_TEST_CLI_WIFI_STATE_SUFFIX,
        c->wifi_state_path, sizeof(c->wifi_state_path));
    xqc_test_cli_build_aux_path(g_log_path, XQC_TEST_CLI_SCHED_TRACE_SUFFIX,
        c->scheduler_trace_path, sizeof(c->scheduler_trace_path));

    c->path_map_fd = xqc_test_cli_open_aux_csv(c->path_map_path,
        "ts_us,conn,path_id,path_seq,ifname,ifindex,fd");
    c->send_trace_fd = xqc_test_cli_open_aux_csv(c->send_trace_path,
        "ts_us,conn,path_id,path_seq,ifname,ifindex,fd,len,quic_form,quic_type,quic_dcid,quic_pn_raw,quic_pn_len");
    c->wifi_state_fd = xqc_test_cli_open_aux_csv(c->wifi_state_path,
        "ts_us,conn,path_id,path_seq,ifname,ifindex,wifi_state,pi_degraded,p_long_gap,r_eff_Bpus,last_gap_us,ewma_gap_us,ewma_airtime_us,ewma_burst_bytes,sample_count,last_update_ts_us,gtsd_calibrated,tail_p50_us,tail_p95_us,tail_ratio,tail_baseline,tail_excess,cusum_on,cusum_off");
    c->scheduler_trace_fd = xqc_test_cli_open_aux_csv(c->scheduler_trace_path,
        "ts_us,conn,scheduler,selected_path_id,selected_ifname,selected_ifindex,selected_on_degraded,other_cleaner,path0_id,path0_ifname,path0_ifindex,path0_srtt_us,path0_cwnd_bytes,path0_bytes_in_flight,path0_can_send,path0_path_state,path0_app_status,path0_wifi_state,path0_pi,path0_p_long_gap,path0_last_gap_us,path0_r_eff_Bpus,path0_gtsd_calibrated,path0_tail_p50_us,path0_tail_p95_us,path0_tail_ratio,path0_tail_baseline,path0_tail_excess,path0_cusum_on,path0_cusum_off,path1_id,path1_ifname,path1_ifindex,path1_srtt_us,path1_cwnd_bytes,path1_bytes_in_flight,path1_can_send,path1_path_state,path1_app_status,path1_wifi_state,path1_pi,path1_p_long_gap,path1_last_gap_us,path1_r_eff_Bpus,path1_gtsd_calibrated,path1_tail_p50_us,path1_tail_p95_us,path1_tail_ratio,path1_tail_baseline,path1_tail_excess,path1_cusum_on,path1_cusum_off");
    if (g_transport == 1) {
        xqc_test_cli_build_aux_path(g_log_path, XQC_TEST_CLI_STREAM_TRACE_SUFFIX,
            c->stream_trace_path, sizeof(c->stream_trace_path));
        c->stream_trace_fd = xqc_test_cli_open_aux_csv(c->stream_trace_path,
            "ts_us,conn,stream_id,event,notify_flag,io_bytes,elapsed_ms,send_offset,send_body_len,recv_body_len,header_recvd,recv_fin,stats_send_body_size,stats_recv_body_size,stats_stream_err,stats_mp_state,stats_retrans_cnt,stats_sent_pkt_cnt");
    } else {
        xqc_test_cli_build_aux_path(g_log_path, XQC_TEST_CLI_REQ_TRACE_SUFFIX,
            c->request_trace_path, sizeof(c->request_trace_path));
        c->request_trace_fd = xqc_test_cli_open_aux_csv(c->request_trace_path,
            "ts_us,conn,stream_id,event,notify_flag,io_bytes,elapsed_ms,send_offset,send_body_len,recv_body_len,header_recvd,recv_fin,stats_send_body_size,stats_recv_body_size,stats_stream_err,stats_mp_state,stats_retrans_cnt,stats_sent_pkt_cnt");
    }

    if (c->path_map_fd > 0) {
        printf("path map trace: %s\n", c->path_map_path);
    }
    if (c->send_trace_fd > 0) {
        printf("send trace: %s\n", c->send_trace_path);
    }
    if (c->wifi_state_fd > 0) {
        printf("wifi state trace: %s\n", c->wifi_state_path);
    }
    if (c->scheduler_trace_fd > 0) {
        printf("scheduler trace: %s\n", c->scheduler_trace_path);
    }
    if (c->request_trace_fd > 0) {
        printf("request trace: %s\n", c->request_trace_path);
    }
    if (c->stream_trace_fd > 0) {
        printf("stream trace: %s\n", c->stream_trace_path);
    }
}

static void
xqc_test_cli_close_aux_trace_files(client_ctx_t *c)
{
    if (c == NULL) {
        return;
    }

    if (c->path_map_fd > 0) {
        close(c->path_map_fd);
        c->path_map_fd = 0;
    }
    if (c->send_trace_fd > 0) {
        close(c->send_trace_fd);
        c->send_trace_fd = 0;
    }
    if (c->wifi_state_fd > 0) {
        close(c->wifi_state_fd);
        c->wifi_state_fd = 0;
    }
    if (c->scheduler_trace_fd > 0) {
        close(c->scheduler_trace_fd);
        c->scheduler_trace_fd = 0;
    }
    if (c->request_trace_fd > 0) {
        close(c->request_trace_fd);
        c->request_trace_fd = 0;
    }
    if (c->stream_trace_fd > 0) {
        close(c->stream_trace_fd);
        c->stream_trace_fd = 0;
    }
}

static const char *
xqc_test_cli_wifi_state_label(xqc_wifi_path_state_t state)
{
    switch (state) {
    case XQC_WIFI_PATH_STATE_REGULAR:
        return "REGULAR";
    case XQC_WIFI_PATH_STATE_DEGRADED_CSMA:
        return "DEGRADED_CSMA";
    case XQC_WIFI_PATH_STATE_UNKNOWN:
    default:
        return "UNKNOWN";
    }
}

static int
xqc_test_cli_wifi_state_rank(xqc_wifi_path_state_t state)
{
    switch (state) {
    case XQC_WIFI_PATH_STATE_REGULAR:
        return 0;
    case XQC_WIFI_PATH_STATE_UNKNOWN:
        return 1;
    case XQC_WIFI_PATH_STATE_DEGRADED_CSMA:
    default:
        return 2;
    }
}

static xqc_user_path_t *
xqc_test_cli_find_path_by_id(uint64_t path_id)
{
    int i;

    for (i = 0; i < g_multi_interface_cnt; i++) {
        if (g_client_path[i].is_in_used && g_client_path[i].path_id == path_id) {
            return &g_client_path[i];
        }
    }

    return NULL;
}

static xqc_user_path_t *
xqc_test_cli_find_path_by_ifname(const char *ifname)
{
    int i;

    if (ifname == NULL || ifname[0] == '\0') {
        return NULL;
    }

    for (i = 0; i < g_multi_interface_cnt; i++) {
        if (strcmp(g_client_path[i].ifname, ifname) == 0) {
            return &g_client_path[i];
        }
    }

    return NULL;
}

static xqc_user_path_t *
xqc_test_cli_find_path_by_fd(int fd)
{
    int i;

    if (fd <= 0) {
        return NULL;
    }

    for (i = 0; i < g_multi_interface_cnt; i++) {
        if (g_client_path[i].path_fd == fd || g_client_path[i].rebinding_path_fd == fd) {
            return &g_client_path[i];
        }
    }

    return NULL;
}

static void
xqc_test_cli_log_path_map(xqc_user_path_t *path)
{
    char line[512];
    client_ctx_t *c;

    if (path == NULL || path->user_conn == NULL || path->user_conn->ctx == NULL) {
        return;
    }

    c = path->user_conn->ctx;
    if (c->path_map_fd <= 0) {
        return;
    }

    snprintf(line, sizeof(line), "%"PRIu64",%p,%"PRIu64",%d,%s,%u,%d",
        xqc_now(), path->user_conn, path->path_id, path->path_seq,
        path->ifname[0] ? path->ifname : "-",
        path->ifindex, path->path_fd);
    xqc_test_cli_write_aux_line(c->path_map_fd, line);
}

static void
xqc_test_cli_log_send_trace(xqc_user_path_t *path, const unsigned char *buf, size_t len)
{
    char dcid_hex[41];
    char pn_hex[9];
    char line[640];
    client_ctx_t *c;
    xqc_test_cli_quic_visible_fields_t fields;

    if (path == NULL || path->user_conn == NULL || path->user_conn->ctx == NULL) {
        return;
    }

    c = path->user_conn->ctx;
    if (c->send_trace_fd <= 0) {
        return;
    }

    xqc_test_cli_parse_quic_visible_fields(buf, len, &fields);
    xqc_test_cli_format_hex_compact(fields.dcid, fields.dcid_len, dcid_hex, sizeof(dcid_hex));
    xqc_test_cli_format_hex_compact(fields.pn_raw, fields.pn_len, pn_hex, sizeof(pn_hex));

    snprintf(line, sizeof(line), "%"PRIu64",%p,%"PRIu64",%d,%s,%u,%d,%zu,%u,%u,%s,%s,%u",
        xqc_now(), path->user_conn, path->path_id, path->path_seq,
        path->ifname[0] ? path->ifname : "-",
        path->ifindex, path->path_fd, len,
        fields.header_form, fields.pkt_type, dcid_hex, pn_hex, fields.pn_len);
    xqc_test_cli_write_aux_line(c->send_trace_fd, line);
}

static void
xqc_test_cli_log_request_trace(xqc_h3_request_t *h3_request, user_stream_t *user_stream,
    const char *event, xqc_request_notify_flag_t flag, ssize_t io_bytes)
{
    char line[1024];
    client_ctx_t *c;
    xqc_request_stats_t stats;
    uint64_t now_us;
    uint64_t elapsed_ms = 0;

    if (h3_request == NULL || user_stream == NULL || event == NULL
        || user_stream->user_conn == NULL || user_stream->user_conn->ctx == NULL)
    {
        return;
    }

    c = user_stream->user_conn->ctx;
    if (c->request_trace_fd <= 0) {
        return;
    }

    stats = xqc_h3_request_get_stats(h3_request);
    now_us = xqc_now();
    if (user_stream->start_time > 0 && now_us >= user_stream->start_time) {
        elapsed_ms = (now_us - user_stream->start_time) / 1000;
    }

    snprintf(line, sizeof(line),
        "%"PRIu64",%p,%"PRIu64",%s,%u,%zd,%"PRIu64",%"PRIu64",%zu,%zu,%d,%d,%zu,%zu,%d,%d,%u,%u",
        now_us,
        user_stream->user_conn,
        xqc_h3_stream_id(h3_request),
        event,
        (unsigned) flag,
        io_bytes,
        elapsed_ms,
        user_stream->send_offset,
        user_stream->send_body_len,
        user_stream->recv_body_len,
        user_stream->header_recvd,
        user_stream->recv_fin,
        stats.send_body_size,
        stats.recv_body_size,
        stats.stream_err,
        stats.mp_state,
        stats.retrans_cnt,
        stats.sent_pkt_cnt);
    xqc_test_cli_write_aux_line(c->request_trace_fd, line);
}

static void
xqc_test_cli_log_stream_trace(xqc_stream_t *stream, user_stream_t *user_stream,
    const char *event, uint32_t notify_flag, ssize_t io_bytes)
{
    char line[1024];
    client_ctx_t *c;
    xqc_conn_stats_t conn_stats;
    uint64_t now_us;
    uint64_t elapsed_ms = 0;

    if (stream == NULL || user_stream == NULL || event == NULL
        || user_stream->user_conn == NULL || user_stream->user_conn->ctx == NULL)
    {
        return;
    }

    c = user_stream->user_conn->ctx;
    if (c->stream_trace_fd <= 0) {
        return;
    }

    conn_stats = xqc_conn_get_stats(c->engine, &user_stream->user_conn->cid);
    now_us = xqc_now();
    if (user_stream->start_time > 0 && now_us >= user_stream->start_time) {
        elapsed_ms = (now_us - user_stream->start_time) / 1000;
    }

    snprintf(line, sizeof(line),
        "%"PRIu64",%p,%"PRIu64",%s,%u,%zd,%"PRIu64",%"PRIu64",%zu,%zu,%d,%d,%"PRIu64",%zu,%d,%d,%u,%u",
        now_us,
        user_stream->user_conn,
        stream->stream_id,
        event,
        (unsigned) notify_flag,
        io_bytes,
        elapsed_ms,
        user_stream->send_offset,
        user_stream->send_body_len,
        user_stream->recv_body_len,
        0,
        user_stream->recv_fin,
        stream->stream_send_offset,
        user_stream->recv_body_len,
        (int) stream->stream_err,
        conn_stats.mp_state,
        stream->stream_stats.retrans_pkt_cnt,
        stream->stream_stats.sent_pkt_cnt);
    xqc_test_cli_write_aux_line(c->stream_trace_fd, line);
}

static void
xqc_test_cli_log_wifi_state_snapshot(client_ctx_t *c, xqc_user_path_t *path,
    const xqc_wifi_state_snapshot_t *snapshot)
{
    char line[1024];

    if (c == NULL || snapshot == NULL || c->wifi_state_fd <= 0) {
        return;
    }

    snprintf(line, sizeof(line),
        "%"PRIu64",%p,%"PRIu64",%d,%s,%u,%s,%.6f,%.6f,%.6f,%"PRIu64",%.3f,%.3f,%.3f,%"PRIu64",%"PRIu64",%u,%"PRIu64",%"PRIu64",%.6f,%.6f,%.6f,%.6f,%.6f",
        snapshot->ts_us,
        path ? path->user_conn : NULL,
        path ? path->path_id : 0,
        path ? path->path_seq : -1,
        snapshot->ifname[0] ? snapshot->ifname : "-",
        snapshot->ifindex,
        xqc_test_cli_wifi_state_label(snapshot->state),
        snapshot->pi_degraded,
        snapshot->p_long_gap,
        snapshot->r_eff_Bpus,
        snapshot->last_gap_us,
        snapshot->ewma_gap_us,
        snapshot->ewma_airtime_us,
        snapshot->ewma_burst_bytes,
        snapshot->sample_count,
        snapshot->last_update_ts_us,
        (unsigned) snapshot->gtsd_calibrated,
        snapshot->tail_p50_us,
        snapshot->tail_p95_us,
        snapshot->tail_ratio,
        snapshot->tail_baseline,
        snapshot->tail_excess,
        snapshot->cusum_on,
        snapshot->cusum_off);
    xqc_test_cli_write_aux_line(c->wifi_state_fd, line);
}

static void
xqc_test_cli_wifi_state_update_cb(const xqc_wifi_state_snapshot_t *snapshot, void *user_data)
{
    client_ctx_t *c = user_data;
    xqc_user_path_t *path;

    if (c == NULL || snapshot == NULL) {
        return;
    }

    path = xqc_test_cli_find_path_by_ifname(snapshot->ifname);
    xqc_test_cli_log_wifi_state_snapshot(c, path, snapshot);
}

static void
xqc_test_cli_scheduler_observer_cb(const xqc_scheduler_observation_t *observation,
    void *user_data)
{
    typedef struct xqc_test_cli_sched_row_path_s {
        int present;
        uint64_t path_id;
        const char *ifname;
        unsigned int ifindex;
        uint64_t srtt_us;
        uint64_t cwnd_bytes;
        uint64_t bytes_in_flight;
        uint8_t can_send;
        uint8_t path_state;
        uint8_t app_path_status;
        xqc_wifi_state_snapshot_t wifi_snapshot;
        int has_wifi_snapshot;
    } xqc_test_cli_sched_row_path_t;

    client_ctx_t *c = user_data;
    xqc_test_cli_sched_row_path_t rows[2];
    int row_count = 0;
    int selected_idx = -1;
    int selected_on_degraded = 0;
    int other_cleaner = 0;
    int i;
    char line[4096];
    const char *selected_ifname = "-";
    unsigned int selected_ifindex = 0;

    if (c == NULL || observation == NULL || c->scheduler_trace_fd <= 0) {
        return;
    }

    memset(rows, 0, sizeof(rows));

    for (i = 0; i < observation->path_count && row_count < 2; i++) {
        xqc_scheduler_path_snapshot_t *src = (xqc_scheduler_path_snapshot_t *) &observation->paths[i];
        xqc_user_path_t *path = xqc_test_cli_find_path_by_id(src->path_id);
        int slot = row_count;

        if (path != NULL && path->path_seq >= 0 && path->path_seq < 2) {
            slot = path->path_seq;
        }

        rows[slot].present = 1;
        rows[slot].path_id = src->path_id;
        rows[slot].ifname = (path && path->ifname[0]) ? path->ifname : "-";
        rows[slot].ifindex = path ? path->ifindex : 0;
        rows[slot].srtt_us = src->srtt_us;
        rows[slot].cwnd_bytes = src->cwnd_bytes;
        rows[slot].bytes_in_flight = src->bytes_in_flight;
        rows[slot].can_send = src->can_send;
        rows[slot].path_state = src->path_state;
        rows[slot].app_path_status = src->app_path_status;

        if (c->wifi_monitor != NULL && path != NULL && path->ifname[0] != '\0'
            && xqc_wifi_monitor_get_snapshot(c->wifi_monitor, path->ifname,
                &rows[slot].wifi_snapshot) == 0)
        {
            rows[slot].has_wifi_snapshot = 1;
        }

        if (observation->has_selected_path && observation->selected_path_id == src->path_id) {
            selected_idx = slot;
            selected_ifname = rows[slot].ifname;
            selected_ifindex = rows[slot].ifindex;
        }

        if (slot + 1 > row_count) {
            row_count = slot + 1;
        }
    }

    if (selected_idx >= 0 && rows[selected_idx].has_wifi_snapshot) {
        selected_on_degraded =
            rows[selected_idx].wifi_snapshot.state == XQC_WIFI_PATH_STATE_DEGRADED_CSMA;

        for (i = 0; i < 2; i++) {
            int selected_rank;
            int other_rank;

            if (i == selected_idx || !rows[i].present || !rows[i].has_wifi_snapshot) {
                continue;
            }

            selected_rank = xqc_test_cli_wifi_state_rank(rows[selected_idx].wifi_snapshot.state);
            other_rank = xqc_test_cli_wifi_state_rank(rows[i].wifi_snapshot.state);
            if (other_rank < selected_rank
                || (other_rank == selected_rank
                    && rows[i].wifi_snapshot.pi_degraded + 1e-9
                        < rows[selected_idx].wifi_snapshot.pi_degraded))
            {
                other_cleaner = 1;
                break;
            }
        }
    }

    snprintf(line, sizeof(line),
        "%"PRIu64",%p,%s,%"PRIu64",%s,%u,%d,%d,"
        "%"PRIu64",%s,%u,%"PRIu64",%"PRIu64",%"PRIu64",%u,%u,%u,%s,%.6f,%.6f,%"PRIu64",%.6f,%u,%"PRIu64",%"PRIu64",%.6f,%.6f,%.6f,%.6f,%.6f,"
        "%"PRIu64",%s,%u,%"PRIu64",%"PRIu64",%"PRIu64",%u,%u,%u,%s,%.6f,%.6f,%"PRIu64",%.6f,%u,%"PRIu64",%"PRIu64",%.6f,%.6f,%.6f,%.6f,%.6f",
        observation->ts_us,
        observation->conn_user_data,
        observation->scheduler_name ? observation->scheduler_name : "-",
        observation->has_selected_path ? observation->selected_path_id : 0,
        selected_ifname,
        selected_ifindex,
        selected_on_degraded,
        other_cleaner,
        rows[0].path_id,
        rows[0].ifname ? rows[0].ifname : "-",
        rows[0].ifindex,
        rows[0].srtt_us,
        rows[0].cwnd_bytes,
        rows[0].bytes_in_flight,
        rows[0].can_send,
        rows[0].path_state,
        rows[0].app_path_status,
        rows[0].has_wifi_snapshot ? xqc_test_cli_wifi_state_label(rows[0].wifi_snapshot.state) : "UNKNOWN",
        rows[0].has_wifi_snapshot ? rows[0].wifi_snapshot.pi_degraded : 0.0,
        rows[0].has_wifi_snapshot ? rows[0].wifi_snapshot.p_long_gap : 0.0,
        rows[0].has_wifi_snapshot ? rows[0].wifi_snapshot.last_gap_us : 0,
        rows[0].has_wifi_snapshot ? rows[0].wifi_snapshot.r_eff_Bpus : 0.0,
        rows[0].has_wifi_snapshot ? (unsigned) rows[0].wifi_snapshot.gtsd_calibrated : 0,
        rows[0].has_wifi_snapshot ? rows[0].wifi_snapshot.tail_p50_us : 0,
        rows[0].has_wifi_snapshot ? rows[0].wifi_snapshot.tail_p95_us : 0,
        rows[0].has_wifi_snapshot ? rows[0].wifi_snapshot.tail_ratio : 0.0,
        rows[0].has_wifi_snapshot ? rows[0].wifi_snapshot.tail_baseline : 0.0,
        rows[0].has_wifi_snapshot ? rows[0].wifi_snapshot.tail_excess : 0.0,
        rows[0].has_wifi_snapshot ? rows[0].wifi_snapshot.cusum_on : 0.0,
        rows[0].has_wifi_snapshot ? rows[0].wifi_snapshot.cusum_off : 0.0,
        rows[1].path_id,
        rows[1].ifname ? rows[1].ifname : "-",
        rows[1].ifindex,
        rows[1].srtt_us,
        rows[1].cwnd_bytes,
        rows[1].bytes_in_flight,
        rows[1].can_send,
        rows[1].path_state,
        rows[1].app_path_status,
        rows[1].has_wifi_snapshot ? xqc_test_cli_wifi_state_label(rows[1].wifi_snapshot.state) : "UNKNOWN",
        rows[1].has_wifi_snapshot ? rows[1].wifi_snapshot.pi_degraded : 0.0,
        rows[1].has_wifi_snapshot ? rows[1].wifi_snapshot.p_long_gap : 0.0,
        rows[1].has_wifi_snapshot ? rows[1].wifi_snapshot.last_gap_us : 0,
        rows[1].has_wifi_snapshot ? rows[1].wifi_snapshot.r_eff_Bpus : 0.0,
        rows[1].has_wifi_snapshot ? (unsigned) rows[1].wifi_snapshot.gtsd_calibrated : 0,
        rows[1].has_wifi_snapshot ? rows[1].wifi_snapshot.tail_p50_us : 0,
        rows[1].has_wifi_snapshot ? rows[1].wifi_snapshot.tail_p95_us : 0,
        rows[1].has_wifi_snapshot ? rows[1].wifi_snapshot.tail_ratio : 0.0,
        rows[1].has_wifi_snapshot ? rows[1].wifi_snapshot.tail_baseline : 0.0,
        rows[1].has_wifi_snapshot ? rows[1].wifi_snapshot.tail_excess : 0.0,
        rows[1].has_wifi_snapshot ? rows[1].wifi_snapshot.cusum_on : 0.0,
        rows[1].has_wifi_snapshot ? rows[1].wifi_snapshot.cusum_off : 0.0);
    xqc_test_cli_write_aux_line(c->scheduler_trace_fd, line);
}

static void
xqc_test_cli_resolve_monitor_paths(client_ctx_t *c)
{
    const char *env_out_dir;
    const char *env_cfg_path;
    const char *last_slash;
    size_t prefix_len;

    if (c == NULL) {
        return;
    }

    env_out_dir = g_wifi_monitor_output_dir[0] ? g_wifi_monitor_output_dir : getenv("XQC_WIFI_MONITOR_OUT_DIR");
    env_cfg_path = g_wifi_monitor_config_path[0] ? g_wifi_monitor_config_path : getenv("XQC_WIFI_MONITOR_CONFIG");

    if (env_out_dir && env_out_dir[0] != '\0') {
        snprintf(c->wifi_monitor_output_dir, sizeof(c->wifi_monitor_output_dir), "%s", env_out_dir);
    } else {
        last_slash = strrchr(g_log_path, '/');
        if (last_slash == NULL) {
            snprintf(c->wifi_monitor_output_dir, sizeof(c->wifi_monitor_output_dir), ".");
        } else {
            prefix_len = (size_t) (last_slash - g_log_path);
            if (prefix_len >= sizeof(c->wifi_monitor_output_dir)) {
                prefix_len = sizeof(c->wifi_monitor_output_dir) - 1;
            }
            memcpy(c->wifi_monitor_output_dir, g_log_path, prefix_len);
            c->wifi_monitor_output_dir[prefix_len] = '\0';
        }
    }

    if (env_cfg_path && env_cfg_path[0] != '\0') {
        snprintf(c->wifi_monitor_config_path, sizeof(c->wifi_monitor_config_path), "%s", env_cfg_path);
    } else {
        snprintf(c->wifi_monitor_config_path, sizeof(c->wifi_monitor_config_path), "%s",
            "ebpf-wifi-insider/config.json");
    }
}

static void
xqc_test_cli_init_monitoring(client_ctx_t *c)
{
    xqc_wifi_monitor_config_t monitor_cfg;
    int should_start = 0;

    if (c == NULL) {
        return;
    }

    xqc_scheduler_register_observer(xqc_test_cli_scheduler_observer_cb, c);
    xqc_test_cli_resolve_monitor_paths(c);

#ifndef XQC_SYS_WINDOWS
    should_start = g_enable_wifi_monitor && g_enable_multipath && g_multi_interface_cnt >= 2;
#endif
    if (!should_start) {
        return;
    }

    memset(&monitor_cfg, 0, sizeof(monitor_cfg));
    monitor_cfg.output_dir = c->wifi_monitor_output_dir;
    monitor_cfg.config_path = c->wifi_monitor_config_path;
    monitor_cfg.ifname_primary = g_multi_interface[0];
    monitor_cfg.ifname_secondary = g_multi_interface_cnt > 1 ? g_multi_interface[1] : NULL;
    monitor_cfg.state_update_cb = xqc_test_cli_wifi_state_update_cb;
    monitor_cfg.state_update_user_data = c;

    if (xqc_wifi_monitor_start(&c->wifi_monitor, &monitor_cfg) != 0) {
        printf("wifi monitor start failed\n");
        c->wifi_monitor = NULL;
        return;
    }

    printf("wifi monitor started, output_dir=%s config=%s if0=%s if1=%s\n",
        c->wifi_monitor_output_dir,
        c->wifi_monitor_config_path,
        monitor_cfg.ifname_primary ? monitor_cfg.ifname_primary : "-",
        monitor_cfg.ifname_secondary ? monitor_cfg.ifname_secondary : "-");
}

static void
xqc_test_cli_shutdown_monitoring(client_ctx_t *c)
{
    if (c == NULL) {
        return;
    }

    xqc_scheduler_unregister_observer();
    if (c->wifi_monitor != NULL) {
        xqc_wifi_monitor_stop(c->wifi_monitor);
        c->wifi_monitor = NULL;
    }
}

static int
xqc_test_cli_apply_scheduler_name(const char *name, xqc_conn_settings_t *conn_settings)
{
    if (conn_settings == NULL || name == NULL || name[0] == '\0') {
        return 0;
    }

    if (strcasecmp(name, "minrtt") == 0) {
        conn_settings->scheduler_callback = xqc_minrtt_scheduler_cb;
        return 0;
    }

    if (strcasecmp(name, "backup") == 0) {
        conn_settings->scheduler_callback = xqc_backup_scheduler_cb;
        return 0;
    }

    if (strcasecmp(name, "rap") == 0) {
        conn_settings->scheduler_callback = xqc_rap_scheduler_cb;
        return 0;
    }

    if (strcasecmp(name, "rr") == 0
        || strcasecmp(name, "roundrobin") == 0
        || strcasecmp(name, "round-robin") == 0)
    {
        conn_settings->scheduler_callback = xqc_rr_scheduler_cb;
        return 0;
    }

    if (strcasecmp(name, "red") == 0
        || strcasecmp(name, "redundant") == 0)
    {
        conn_settings->scheduler_callback = xqc_redundant_scheduler_cb;
        conn_settings->reinj_ctl_callback = xqc_redundant_reinj_ctl_cb;
        conn_settings->mp_enable_reinjection |= XQC_REINJ_UNACK_AFTER_SEND
                                                | XQC_REINJ_UNACK_MULTI_PATH;
        return 0;
    }

    if (strcasecmp(name, "copy") == 0
        || strcasecmp(name, "csma_copy") == 0
        || strcasecmp(name, "csma-copy") == 0)
    {
        conn_settings->scheduler_callback = xqc_copy_scheduler_cb;
        conn_settings->reinj_ctl_callback = xqc_redundant_reinj_ctl_cb;
        conn_settings->mp_enable_reinjection |= XQC_REINJ_UNACK_AFTER_SEND
                                                | XQC_REINJ_UNACK_MULTI_PATH;
        return 0;
    }

    if (strcasecmp(name, "xlink") == 0
        || strcasecmp(name, "xquic_scheduler_xlink") == 0)
    {
        conn_settings->scheduler_callback = xquic_scheduler_xlink;
        conn_settings->reinj_ctl_callback = xqc_default_reinj_ctl_cb;
        conn_settings->mp_enable_reinjection |= XQC_REINJ_UNACK_AFTER_SCHED
                                                | XQC_REINJ_UNACK_MULTI_PATH;
        conn_settings->mp_ack_on_any_path = 1;
        return 0;
    }

    if (strcasecmp(name, "blest") == 0) {
        conn_settings->scheduler_callback = xqc_blest_scheduler_cb;
        return 0;
    }

#ifdef XQC_ENABLE_MP_INTEROP
    if (strcasecmp(name, "interop") == 0) {
        conn_settings->scheduler_callback = xqc_interop_scheduler_cb;
        return 0;
    }
#else
    if (strcasecmp(name, "interop") == 0) {
        return -1;
    }
#endif

    if (strcasecmp(name, "backup_fec") == 0
        || strcasecmp(name, "backup-fec") == 0)
    {
        conn_settings->scheduler_callback = xqc_backup_fec_scheduler_cb;
        return 0;
    }

    return -1;
}

static void
xqc_test_cli_apply_scheduler_side_effects(const char *name)
{
    if (name == NULL || name[0] == '\0') {
        return;
    }

    if (strcasecmp(name, "backup") == 0) {
        g_mp_backup_mode = 1;
        return;
    }

    if (strcasecmp(name, "backup_fec") == 0
        || strcasecmp(name, "backup-fec") == 0)
    {
        g_enable_fec = 1;
        g_mp_backup_mode = 1;
    }
}
/*
 CDF file format:
 N (N lines)
 p1(0) v1(0)
 p2 v2
 ....
 pN(1.0) vN
*/
static int
load_cdf(char *cdf_file)
{
    FILE *fp = fopen(cdf_file, "r");
    if (fp == NULL) {
        return -1;
    }
    int n;
    if (fscanf(fp, "%d", &n) != 1) {
        fclose(fp);
        return -1;
    }
    cdf_list_size = n;
    cdf_list = malloc(sizeof(cdf_entry_t) * cdf_list_size);
    while (n--) {
        if (fscanf(fp, "%lf%d", &cdf_list[cdf_list_size - n - 1].p, &cdf_list[cdf_list_size - n - 1].val) != 2) {
            break;
        }
    }
    fclose(fp);
    return 0;
}

static void
destroy_cdf()
{
    if (cdf_list != NULL) {
        free(cdf_list);
        cdf_list = NULL;
    }
}

static int
get_val_from_cdf_by_p(double p)
{
    int last_entry_id = -1, i;
    double p0 = 0, p1 = 0;
    int v0 = 0, v1 = 0;
    int v = 0;
    for (i = 0; i < cdf_list_size; i++) {
        if (p > cdf_list[i].p) {
            last_entry_id = i;
            p0 = cdf_list[i].p;
            v0 = cdf_list[i].val;
        } else {
            //linear interpolation
            p1 = cdf_list[i].p;
            v1 = cdf_list[i].val;
            v = v0 + (int)(((v1 - v0) / (p1 - p0)) * (p - p0));
            break;
        }
    }
    if (v == 0) {
        v = 1;
    }
    return v;
}

static int
get_random_from_cdf()
{
    int r = 1 + (xqc_random() % 1000);
    double p = r * 1.0 / 1000; // 0.001 ~ 1
    return get_val_from_cdf_by_p(p);
}

#ifdef XQC_SYS_WINDOWS
static void usleep(unsigned long usec)
{
    HANDLE timer;
    LARGE_INTEGER interval;
    interval.QuadPart = -(10 * usec);

    timer = CreateWaitableTimer(NULL, TRUE, NULL);
    SetWaitableTimer(timer, &interval, 0, NULL, NULL, 0);
    WaitForSingleObject(timer, INFINITE);
    CloseHandle(timer);
}
#endif


static void xqc_client_socket_event_callback(int fd, short what, void *arg);
static void xqc_client_timeout_callback(int fd, short what, void *arg);
static void xqc_client_abs_timeout_callback(int, short, void*);
static void xqc_client_bytestream_timeout_callback(int, short, void*);

/* 用于路径增删debug */
static void xqc_client_path_callback(int fd, short what, void *arg);
static void xqc_client_epoch_callback(int fd, short what, void *arg);

/*  */

static void 
xqc_client_datagram_send(user_conn_t *user_conn)
{
    if (user_conn->dgram_not_supported) {
        // exit
        printf("[dgram]|peer_does_not_support_datagram|\n");
        xqc_conn_close(ctx.engine, &user_conn->cid);
        return;
    }

    // try to send 0rtt datagram while the client does not have 0rtt transport parameters
    if (g_test_case == 202) {
        if (user_conn->dgram_mss == 0) {
            user_conn->dgram_mss = 1000;
        }
    }

    if (user_conn->dgram_mss == 0) {
        user_conn->dgram_retry_in_hs_cb = 1;
        printf("[dgram]|waiting_for_max_datagram_frame_size_from_peer|please_retry_in_hs_callback|\n");
        return;
    }

    user_dgram_blk_t *dgram_blk = user_conn->dgram_blk;
    int ret;

    if (g_send_dgram == 1) {
        if (g_test_case == 203 && user_conn->dgram_mss) {
            g_test_case = -1;
            user_conn->dgram_mss++;
        }
        uint64_t dgram_id;
        while (dgram_blk->data_sent < dgram_blk->data_len) {
            size_t dgram_size = dgram_blk->data_len - dgram_blk->data_sent;
            if (dgram_size > user_conn->dgram_mss) {
                dgram_size = user_conn->dgram_mss;
            }
            dgram_blk->data[dgram_blk->data_sent] = 0x31;
            ret = xqc_datagram_send(user_conn->quic_conn, dgram_blk->data + dgram_blk->data_sent, dgram_size, &dgram_id, g_dgram_qos_level);
            if (ret == -XQC_EAGAIN) {
                printf("[dgram]|retry_datagram_send_later|\n");
                return;
            } else if (ret == -XQC_EDGRAM_TOO_LARGE) {
                printf("[dgram]|trying_to_send_an_oversized_datagram|recorded_mss:%zu|send_size:%zu|current_mss:%zu|\n", user_conn->dgram_mss, dgram_size, xqc_datagram_get_mss(user_conn->quic_conn));
                xqc_conn_close(ctx.engine, &user_conn->cid);
                return;
            } else if (ret < 0) {
                printf("[dgram]|send_datagram_error|err_code:%d|\n", ret);
                xqc_conn_close(ctx.engine, &user_conn->cid);
                return;
            }
            // printf("[dgram]|send_one_datagram|id:%"PRIu64"|size:%zu|\n", dgram_id, dgram_size);
            dgram_blk->data_sent += dgram_size;

            if (g_epoch) {
                break;
            }
        }
    } else if (g_send_dgram == 2) {
        struct iovec iov[XQC_TEST_DGRAM_BATCH_SZ];
        uint64_t dgram_id_list[XQC_TEST_DGRAM_BATCH_SZ];
        size_t bytes_in_batch = 0;
        int batch_cnt = 0;
        while ((dgram_blk->data_sent + bytes_in_batch) < dgram_blk->data_len) {
            if (batch_cnt == 1) {
                if (g_test_case == 203 && user_conn->dgram_mss) {
                    g_test_case = -1;
                    user_conn->dgram_mss++;
                }
            }
            size_t dgram_size = dgram_blk->data_len - dgram_blk->data_sent - bytes_in_batch;
            size_t succ_sent = 0, succ_sent_bytes = 0;
            if (dgram_size > user_conn->dgram_mss) {
                dgram_size = user_conn->dgram_mss;
            }
            iov[batch_cnt].iov_base = dgram_blk->data + dgram_blk->data_sent + bytes_in_batch;
            iov[batch_cnt].iov_len = dgram_size;
            dgram_blk->data[dgram_blk->data_sent + bytes_in_batch] = 0x31;
            bytes_in_batch += dgram_size;
            batch_cnt++;
            if ((bytes_in_batch + dgram_blk->data_sent) == dgram_blk->data_len
                || batch_cnt == XQC_TEST_DGRAM_BATCH_SZ) 
            {
                ret = xqc_datagram_send_multiple(user_conn->quic_conn, iov, dgram_id_list, batch_cnt, &succ_sent, &succ_sent_bytes, g_dgram_qos_level);
                if (ret == -XQC_EDGRAM_TOO_LARGE) {
                    printf("[dgram]|trying_to_send_an_oversized_datagram|recorded_mss:%zu|send_size:%zu|current_mss:%zu|\n", user_conn->dgram_mss, iov[succ_sent].iov_len, xqc_datagram_get_mss(user_conn->quic_conn));
                    printf("[dgram]|partially_sent_pkts_in_a_batch|cnt:%zu|\n", succ_sent);
                    xqc_conn_close(ctx.engine, &user_conn->cid);
                    return;

                } else if (ret < 0 && ret != -XQC_EAGAIN) {
                    printf("[dgram]|send_datagram_multiple_error|err_code:%d|\n", ret);
                    xqc_conn_close(ctx.engine, &user_conn->cid);
                    return;
                }

                // for (int i = 0; i < succ_sent; i++) {
                //     printf("[dgram]|send_one_datagram|id:%"PRIu64"|size:%zu|\n", dgram_id_list[i], iov[i].iov_len);
                // }

                // printf("[dgram]|datagrams_sent_in_a_batch|cnt:%zu|size:%zu|\n", succ_sent, succ_sent_bytes);
                
                dgram_blk->data_sent += succ_sent_bytes;
                
                if (ret == -XQC_EAGAIN) {
                    printf("[dgram]|retry_datagram_send_multiple_later|\n");
                    return;
                }

                bytes_in_batch = 0;
                batch_cnt = 0;
            }
        }

    }
}

static void
xqc_client_datagram_mss_updated_callback(xqc_connection_t *conn, size_t mss, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    user_conn->dgram_mss = mss;
    printf("[dgram]|mss_callback|updated_mss:%zu|\n", mss);
}

static void
xqc_client_datagram_read_callback(xqc_connection_t *conn, void *user_data, const void *data, size_t data_len, uint64_t dgram_ts)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    if (g_echo_check) {
        memcpy(user_conn->dgram_blk->recv_data + user_conn->dgram_blk->data_recv, data, data_len);
    }
    user_conn->dgram_blk->data_recv += data_len;
    //printf("[dgram]|read_data|size:%zu|recv_time:%"PRIu64"|\n", data_len, dgram_ts);
    if (g_test_case == 206 && g_no_crypt) {
        if (dgram1_size == 0) {
            dgram1_size = data_len;
        } else {
            if (dgram2_size == 0) {
                dgram2_size = data_len;
            }
        }
    }
}

static void 
xqc_client_datagram_write_callback(xqc_connection_t *conn, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    if (g_send_dgram) {
        printf("[dgram]|dgram_write|\n");
        xqc_client_datagram_send(user_conn);
    }
}

static void 
xqc_client_datagram_acked_callback(xqc_connection_t *conn, uint64_t dgram_id, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    if (g_test_case == 207) {
        printf("[dgram]|dgram_acked|dgram_id:%"PRIu64"|\n", dgram_id);
        g_test_case = -1;
    }
}

static int 
xqc_client_datagram_lost_callback(xqc_connection_t *conn, uint64_t dgram_id, void *user_data)
{
    //printf("[dgram]|dgram_lost|dgram_id:%"PRIu64"|\n", dgram_id);
    user_conn_t *user_conn = (user_conn_t*)user_data;
    //user_conn->dgram_blk->data_lost += data_len;
    user_conn->dgram_blk->dgram_lost++;
    if (g_test_case == 205 && g_no_crypt) {
        printf("[dgram]|dgram_lost|dgram_id:%"PRIu64"|\n", dgram_id);
    }
    return 0;
}


static void 
xqc_client_h3_ext_datagram_send(user_conn_t *user_conn)
{
    if (user_conn->dgram_not_supported) {
        // exit
        printf("[h3-dgram]|peer_does_not_support_datagram|\n");
        // xqc_h3_conn_close(ctx.engine, &user_conn->cid);
        return;
    }

    // try to send 0rtt datagram while the client does not have 0rtt transport parameters
    if (g_test_case == 202) {
        if (user_conn->dgram_mss == 0) {
            user_conn->dgram_mss = 1000;
        }
    }

    if (user_conn->dgram_mss == 0) {
        user_conn->dgram_retry_in_hs_cb = 1;
        printf("[h3-dgram]|waiting_for_max_datagram_frame_size_from_peer|please_retry_in_hs_callback|\n");
        return;
    }

    user_dgram_blk_t *dgram_blk = user_conn->dgram_blk;
    int ret;

    if (g_send_dgram == 1) {
        if (g_test_case == 203 && user_conn->dgram_mss) {
            g_test_case = -1;
            user_conn->dgram_mss++;
        }
        uint64_t dgram_id;
        while (dgram_blk->data_sent < dgram_blk->data_len) {
            size_t dgram_size = dgram_blk->data_len - dgram_blk->data_sent;
            if (dgram_size > user_conn->dgram_mss) {
                dgram_size = user_conn->dgram_mss;
            }

            if (g_epoch) {
                if (dgram_blk->data_len - dgram_blk->data_sent < 13) {
                    dgram_blk->data_sent = dgram_blk->data_len;
                    break;
                }
                dgram_blk->data[dgram_blk->data_sent] = 0x32;
                *(uint32_t*)(dgram_blk->data + dgram_blk->data_sent + 1) = dgram_blk->dgram_id++;
                *(uint64_t*)(dgram_blk->data + dgram_blk->data_sent + 5) = xqc_now();

            } else {
                dgram_blk->data[dgram_blk->data_sent] = 0x31;
            }
            
            ret = xqc_h3_ext_datagram_send(user_conn->h3_conn, dgram_blk->data + dgram_blk->data_sent, dgram_size, &dgram_id, g_dgram_qos_level);
            if (ret == -XQC_EAGAIN) {
                printf("[h3-dgram]|retry_datagram_send_later|\n");
                return;
            } else if (ret == -XQC_EDGRAM_TOO_LARGE ) {
                printf("[h3-dgram]|trying_to_send_an_oversized_datagram|recorded_mss:%zu|send_size:%zu|current_mss:%zu|\n", user_conn->dgram_mss, dgram_size, xqc_h3_ext_datagram_get_mss(user_conn->h3_conn));
                xqc_h3_conn_close(ctx.engine, &user_conn->cid);
                return;
            } else if (ret < 0) {
                printf("[h3-dgram]|send_datagram_error|err_code:%d|\n", ret);
                xqc_h3_conn_close(ctx.engine, &user_conn->cid);
                return;
            }
            //printf("[dgram]|send_one_datagram|id:%"PRIu64"|size:%zu|\n", dgram_id, dgram_size);
            dgram_blk->data_sent += dgram_size;
            
            if (g_epoch) {
                break;
            }
        }
    } else if (g_send_dgram == 2) {
        struct iovec iov[XQC_TEST_DGRAM_BATCH_SZ];
        uint64_t dgram_id_list[XQC_TEST_DGRAM_BATCH_SZ];
        size_t bytes_in_batch = 0;
        int batch_cnt = 0;
        while ((dgram_blk->data_sent + bytes_in_batch) < dgram_blk->data_len) {
            if (batch_cnt == 1) {
                if (g_test_case == 203 && user_conn->dgram_mss) {
                    g_test_case = -1;
                    user_conn->dgram_mss++;
                }
            }
            size_t dgram_size = dgram_blk->data_len - dgram_blk->data_sent - bytes_in_batch;
            size_t succ_sent = 0, succ_sent_bytes = 0;
            if (dgram_size > user_conn->dgram_mss) {
                dgram_size = user_conn->dgram_mss;
            }
            iov[batch_cnt].iov_base = dgram_blk->data + dgram_blk->data_sent + bytes_in_batch;
            iov[batch_cnt].iov_len = dgram_size;
            dgram_blk->data[dgram_blk->data_sent + bytes_in_batch] = 0x31;
            bytes_in_batch += dgram_size;
            batch_cnt++;
            if ((bytes_in_batch + dgram_blk->data_sent) == dgram_blk->data_len
                || batch_cnt == XQC_TEST_DGRAM_BATCH_SZ) 
            {
                ret = xqc_h3_ext_datagram_send_multiple(user_conn->h3_conn, iov, dgram_id_list, batch_cnt, &succ_sent, &succ_sent_bytes, g_dgram_qos_level);
                if (ret == -XQC_EDGRAM_TOO_LARGE) {
                    printf("[h3-dgram]|trying_to_send_an_oversized_datagram|recorded_mss:%zu|send_size:%zu|current_mss:%zu|\n", user_conn->dgram_mss, iov[succ_sent].iov_len, xqc_h3_ext_datagram_get_mss(user_conn->h3_conn));
                    printf("[h3-dgram]|partially_sent_pkts_in_a_batch|cnt:%zu|\n", succ_sent);
                    xqc_h3_conn_close(ctx.engine, &user_conn->cid);
                    return;
                } else if (ret < 0 && ret != -XQC_EAGAIN) {
                    printf("[h3-dgram]|send_datagram_multiple_error|err_code:%d|\n", ret);
                    xqc_h3_conn_close(ctx.engine, &user_conn->cid);
                    return;
                }

                // for (int i = 0; i < succ_sent; i++) {
                //     printf("[dgram]|send_one_datagram|id:%"PRIu64"|size:%zu|\n", dgram_id_list[i], iov[i].iov_len);
                // }

                // printf("[dgram]|datagrams_sent_in_a_batch|cnt:%zu|size:%zu|\n", succ_sent, succ_sent_bytes);
                
                dgram_blk->data_sent += succ_sent_bytes;
                
                if (ret == -XQC_EAGAIN) {
                    printf("[h3-dgram]|retry_datagram_send_multiple_later|\n");
                    return;
                } 

                bytes_in_batch = 0;
                batch_cnt = 0;
            }
        }

    }
}


static void
xqc_client_h3_ext_datagram_mss_updated_callback(xqc_h3_conn_t *conn, size_t mss, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    user_conn->dgram_mss = mss;
    printf("[h3-dgram]|callback|updated_mss:%zu|\n", mss);
}

static void
xqc_client_h3_ext_datagram_read_callback(xqc_h3_conn_t *conn, const void *data, size_t data_len, void *user_data, uint64_t ts)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    if (g_echo_check) {
        memcpy(user_conn->dgram_blk->recv_data + user_conn->dgram_blk->data_recv, data, data_len);
    }
    user_conn->dgram_blk->data_recv += data_len;
    // printf("[h3-dgram]|read_data|size:%zu|recv_time:%"PRIu64"|\n", data_len, ts);
    if (g_test_case == 206 && g_no_crypt) {
        if (dgram1_size == 0) {
            dgram1_size = data_len;
        } else {
            if (dgram2_size == 0) {
                dgram2_size = data_len;
            }
        }
    }
}

static void 
xqc_client_h3_ext_datagram_write_callback(xqc_h3_conn_t *conn, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    if (g_send_dgram) {
        printf("[h3-dgram]|dgram_write|\n");
        xqc_client_h3_ext_datagram_send(user_conn);
    }
}

static void
xqc_client_h3_ext_datagram_acked_callback(xqc_h3_conn_t *conn, uint64_t dgram_id, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    if (g_test_case == 207) {
        printf("[h3-dgram]|dgram_acked|dgram_id:%"PRIu64"|\n", dgram_id);
        g_test_case = -1;
    }
    // printf("[h3-dgram]|latest_rtt:%"PRIu64"|\n", xqc_conn_get_lastest_rtt(ctx.engine, &user_conn->cid));
}

static int 
xqc_client_h3_ext_datagram_lost_callback(xqc_h3_conn_t *conn, uint64_t dgram_id, void *user_data)
{
    //printf("[dgram]|dgram_lost|dgram_id:%"PRIu64"|\n", dgram_id);
    user_conn_t *user_conn = (user_conn_t*)user_data;
    user_conn->dgram_blk->data_lost += 0;
    user_conn->dgram_blk->dgram_lost++;
    if (g_test_case == 205 && g_no_crypt) {
        printf("[h3-dgram]|dgram_lost|dgram_id:%"PRIu64"|\n", dgram_id);
    }
    return 0;
}


static void xqc_client_timeout_multi_process_callback(int fd, short what, void *arg);


void
xqc_client_set_event_timer(xqc_usec_t wake_after, void *user_data)
{
    client_ctx_t *ctx = (client_ctx_t *) user_data;
    //printf("xqc_engine_wakeup_after %llu us, now %llu\n", wake_after, xqc_now());

    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);

}

void
save_session_cb(const char * data, size_t data_len, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    printf("save_session_cb use server domain as the key. h3[%d]\n", user_conn->h3);

    FILE * fp  = fopen("test_session", "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if (data_len != write_size) {
        printf("save _session_cb error\n");
        fclose(fp);
        return;
    }
    fclose(fp);
    return;
}


void
save_tp_cb(const char * data, size_t data_len, void * user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    printf("save_tp_cb use server domain as the key. h3[%d]\n", user_conn->h3);

    FILE * fp = fopen("tp_localhost", "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if (data_len != write_size) {
        printf("save _tp_cb error\n");
        fclose(fp);
        return;
    }
    fclose(fp);
    return;
}

void
xqc_client_save_token(const unsigned char *token, unsigned token_len, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    printf("xqc_client_save_token use client ip as the key. h3[%d]\n", user_conn->h3);

    if (g_test_case == 16) { /* test application delay */
        usleep(300*1000);
    }
    int fd = open("./xqc_token", O_TRUNC | O_CREAT | O_WRONLY, 0666);
    if (fd < 0) {
        printf("save token error %s\n", strerror(get_sys_errno()));
        return;
    }

    ssize_t n = write(fd, token, token_len);
    if (n < token_len) {
        printf("save token error %s\n", strerror(get_sys_errno()));
        close(fd);
        return;
    }
    close(fd);
}

int
xqc_client_read_token(unsigned char *token, unsigned token_len)
{
    int fd = open("./xqc_token", O_RDONLY);
    if (fd < 0) {
        printf("read token error %s\n", strerror(get_sys_errno()));
        return -1;
    }

    ssize_t n = read(fd, token, token_len);
    printf("read token size %zu\n", n);
    close(fd);
    return n;
}

int
read_file_data(char *data, size_t data_len, char *filename)
{
    int ret = 0;
    size_t total_len, read_len;
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        ret = -1;
        goto end;
    }

    fseek(fp, 0, SEEK_END);
    total_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (total_len > data_len) {
        ret = -1;
        goto end;
    }

    read_len = fread(data, 1, total_len, fp);
    if (read_len != total_len) {
        ret = -1;
        goto end;
    }

    ret = read_len;

end:
    if (fp) {
        fclose(fp);
    }
    return ret;
}

static int
xqc_test_cli_parse_size_arg(const char *arg, size_t *value)
{
    unsigned long long parsed;
    char *end = NULL;

    if (arg == NULL || value == NULL) {
        return -1;
    }

    errno = 0;
    parsed = strtoull(arg, &end, 10);
    if (errno != 0 || end == arg || *end != '\0' || parsed == 0) {
        return -1;
    }

    *value = (size_t) parsed;
    if ((unsigned long long) *value != parsed) {
        return -1;
    }

    return 0;
}

static void
xqc_test_cli_fill_transport_send_body(char *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        return;
    }

    memset(buf, 1, len);
}

static int
xqc_test_cli_prepare_transport_send_body(user_stream_t *user_stream)
{
    ssize_t ret;
    size_t alloc_len;

    if (user_stream == NULL || user_stream->send_body != NULL) {
        return 0;
    }

    user_stream->send_body_max = MAX_BUF_SIZE;
    if (g_read_body) {
        user_stream->send_body = malloc(user_stream->send_body_max);
        if (user_stream->send_body == NULL) {
            printf("send_body malloc error\n");
            return -1;
        }

        ret = read_file_data(user_stream->send_body, user_stream->send_body_max, g_read_file);
        if (ret < 0) {
            printf("read body error\n");
            return -1;
        }

        user_stream->send_body_len = ret;
        return 0;
    }

    if (g_send_body_size_from_cdf == 1) {
        g_send_body_size = get_random_from_cdf();
        printf("send_request, size_from_cdf:%zu\n", g_send_body_size);
    }

    user_stream->send_body_len = g_send_body_size;
    user_stream->send_body_streaming = user_stream->send_body_len > MAX_BUF_SIZE;
    alloc_len = user_stream->send_body_streaming
        ? xqc_min(user_stream->send_body_len, (size_t) XQC_TEST_CLI_LARGE_STREAM_CHUNK_SIZE)
        : user_stream->send_body_len;

    user_stream->send_body = malloc(alloc_len);
    if (user_stream->send_body == NULL) {
        printf("send_body malloc error\n");
        return -1;
    }

    user_stream->send_body_max = alloc_len;
    xqc_test_cli_fill_transport_send_body(user_stream->send_body, alloc_len);
    return 0;
}

ssize_t 
xqc_client_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user)
{
    user_conn_t *user_conn = (user_conn_t *) user;
    ssize_t res = 0;
    int fd = user_conn->fd;
    xqc_user_path_t *path = xqc_test_cli_find_path_by_fd(fd);

    /* COPY to run corruption test cases */
    unsigned char send_buf[XQC_PACKET_TMP_BUF_LEN];
    size_t send_buf_size = 0;

    if (size > XQC_PACKET_TMP_BUF_LEN) {
        printf("xqc_client_write_socket err: size=%zu is too long\n", size);
        return XQC_SOCKET_ERROR;
    }
    send_buf_size = size;
    memcpy(send_buf, buf, send_buf_size);

    /* trigger version negotiation */
    if (g_test_case == 33) {
        /* makes version 0xff000001 */
        send_buf[1] = 0xff;
    }

    /* make initial packet loss to test 0rtt buffer */
    if (g_test_case == 39) {
        g_test_case = -1;
        return size;
    }

    do {
        set_sys_errno(0);

        g_last_sock_op_time = xqc_now();

        if (TEST_DROP) {
            return send_buf_size;
        }
        if (g_test_case == 5) { /* socket send fail */
            g_test_case = -1;
            set_sys_errno(EAGAIN);
            return XQC_SOCKET_EAGAIN;
        }

        /* client Initial dcid corruption */
        if (g_test_case == 22) {
            /* client initial dcid corruption, bytes [6, 13] is the DCID of xquic's Initial packet */
            g_test_case = -1;
            send_buf[6] = ~send_buf[6];
            printf("test case 22, corrupt byte[6]\n");
        }

        /* client Initial scid corruption */
        if (g_test_case == 23) {
            /* bytes [15, 22] is the SCID of xquic's Initial packet */
            g_test_case = -1;
            send_buf[15] = ~send_buf[15];
            printf("test case 23, corrupt byte[15]\n");
        }

        // drop the first datagram packet
        if ((g_test_case == 205 || g_test_case == 206) && g_no_crypt && !dgram_drop_pkt1) {
            int header_type = send_buf[0] & 0x80;
            if (header_type == 0x80) {
                // long header: 29B + 3B (frame header)
                int lp_type = send_buf[0] & 0x30;
                if (lp_type == 0x10) {
                    //0RTT pkt
                    if (send_buf[29] == 0x31) {
                        //datagram frame
                        if (g_test_case == 206) {
                            //hold data & swap the order with the next one
                            //swap 1st & 2nd dgram
                            memcpy(sock_op_buffer, send_buf, send_buf_size);
                            sock_op_buffer_len = send_buf_size;
                        }
                        dgram_drop_pkt1 = 1;
                        return send_buf_size;
                    }
                }
            } else {
                // short header: 13B + 3B (frame header)
                if (send_buf[13] == 0x31) {
                    //datagram frame
                    if (g_test_case == 206) {
                        //hold data & swap the order with the next one
                        //swap 1st & 2nd dgram
                        memcpy(sock_op_buffer, send_buf, send_buf_size);
                        sock_op_buffer_len = send_buf_size;
                    }
                    dgram_drop_pkt1 = 1;
                    return send_buf_size;
                }
            }
        }

        res = sendto(fd, send_buf, send_buf_size, 0, peer_addr, peer_addrlen);
        if (res < 0) {
            printf("xqc_client_write_socket err %zd %s\n", res, strerror(get_sys_errno()));
            if (get_sys_errno() == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }
            if (errno == EMSGSIZE) {
                res = send_buf_size;
            }
        } else if (path != NULL) {
            xqc_test_cli_log_send_trace(path, send_buf, (size_t) res);
        }

        if (sock_op_buffer_len) {
            int header_type = send_buf[0] & 0x80;
            int frame_type = -1;
            if (header_type == 0x80) {
                // long header: 29B + 3B (frame header)
                int lp_type = send_buf[0] & 0x30;
                if (lp_type == 0x10) {
                    //0RTT pkt
                    frame_type = send_buf[29];
                }  
            } else {
                frame_type = send_buf[13];
            }
            if (frame_type == 0x31) {
                int tmp = sendto(fd, sock_op_buffer, sock_op_buffer_len, 0, peer_addr, peer_addrlen);
                if (tmp < 0) {
                    res = tmp;
                    printf("xqc_client_write_socket err %zd %s\n", res, strerror(errno));
                    if (errno == EAGAIN) {
                        res = XQC_SOCKET_EAGAIN;
                    }
                } else if (path != NULL) {
                    xqc_test_cli_log_send_trace(path, sock_op_buffer, (size_t) tmp);
                }
                sock_op_buffer_len = 0;
            }
        }
    } while ((res < 0) && (get_sys_errno() == EINTR));

    return res;
}

int
xqc_client_get_path_fd_by_id(user_conn_t *user_conn, uint64_t path_id)
{
    int fd = user_conn->fd;

    if (!g_enable_multipath) {
        return fd;
    }

    for (int i = 0; i < g_multi_interface_cnt; i++) {
        if (g_client_path[i].path_id == path_id) {
            fd = g_client_path[i].path_fd;
            break;
        }
    }

    return fd;
}


/* 多路必须保证传正确的path id，因为conn_fd写死了，跟initial path不一定匹配 */
ssize_t
xqc_client_write_socket_ex(uint64_t path_id,
    const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t *)user_data;
    ssize_t res;
    int fd = 0;
    int header_type;
    xqc_user_path_t *path = NULL;

    /* test stateless reset after handshake completed */
    if (g_test_case == 41) {
        if (hsk_completed && ((buf[0] & 0xC0) == 0x40)) {
            if (user_conn->tracked_pkt_cnt < 2) {
                /* send 10 pkts first */
                user_conn->tracked_pkt_cnt++;

            } else {
                /* delay short header packet to make server idle timeout */
                uint64_t nowtime = xqc_now();

                if (user_conn->black_hole_start_time == 0) {
                    user_conn->black_hole_start_time = nowtime;
                    printf("   blackhole start: %"PRIu64"\n", nowtime);
                }

                if (nowtime - user_conn->black_hole_start_time <= 3000000) {
                    return size;
                }

                /* keep blackhole more than 2 seconds, turn off */
                printf("   blackhole end: %"PRIu64"\n", nowtime);
                g_test_case = -1;
            }
        }
    }

    /* test stateless rset during handshake */
    if (g_test_case == 45) {
        uint64_t nowtime = xqc_now();
        if (user_conn->black_hole_start_time == 0) {

            if ((((buf[0] & 0x80) == 0x80) && ((buf[0] & 0x30) >> 4) == 2)
                || ((buf[0] & 0xC0) == 0x40))
            {
                if (user_conn->black_hole_start_time == 0) {
                    user_conn->black_hole_start_time = nowtime;
                    printf("   blackhole start: %"PRIu64"\n", nowtime);
                }

                printf("... block:%zu\n", size);
                return size;
            }

        } else {
            /* drop all client's packet */

            if (nowtime - user_conn->black_hole_start_time <= 10000000) {
                printf("... block:%zu\n", size);
                return size;
            }

            /* keep blackhole more than 2 seconds, turn off */
            printf("   blackhole end: %"PRIu64"\n", nowtime);
            g_test_case = -1;

        }
    }

    /* get path fd */
    fd = xqc_client_get_path_fd_by_id(user_conn, path_id);
    path = xqc_test_cli_find_path_by_id(path_id);
    if (path == NULL) {
        path = xqc_test_cli_find_path_by_fd(fd);
    }

    /* COPY to run corruption test cases */
    unsigned char send_buf[XQC_PACKET_TMP_BUF_LEN];
    size_t send_buf_size = 0;

    if (size > XQC_PACKET_TMP_BUF_LEN) {
        printf("xqc_client_write_socket err: size=%zu is too long\n", size);
        return XQC_SOCKET_ERROR;
    }
    send_buf_size = size;
    memcpy(send_buf, buf, send_buf_size);

    /* trigger version negotiation */
    if (g_test_case == 33) {
        /* makes version 0xff000001 */
        send_buf[1] = 0xff;
    }

    /* make initial packet loss to test 0rtt buffer */
    if (g_test_case == 39) {
        g_test_case = -1;
        return size;
    }

    if (g_test_case == 46) {
        /* drop all initial packets to make server buffer 0rtt packets */
        header_type = send_buf[0] & 0x80;
        /* initial packet */
        uint8_t fixed_bit = send_buf[0] & 0x40;
        xqc_uint_t type = (send_buf[0] & 0x30) >> 4;
        if (type == 0 && g_timeout_flag == 0) { //do not drop conn close frame
            printf("... drop initial pkt, len: %zd\n", size);
            return size;
        }
    }

    if (g_enable_multipath) {
        g_client_path[path_id].send_size += size;
    }

    if (hsk_completed) {
        if (g_test_case == 103 && path_id == 0 && g_client_path[0].send_size > g_send_body_size/10) {
            fd = g_client_path[0].rebinding_path_fd;
        }
        else if (g_test_case == 104 && path_id == 1 && g_client_path[1].send_size > 10240) {
            fd = g_client_path[1].rebinding_path_fd;
        }
    }

    do {
        errno = 0;

        g_last_sock_op_time = xqc_now();

        if (TEST_DROP) {
            return send_buf_size;
        }
        if (g_test_case == 5) { /* socket send fail */
            g_test_case = -1;
            errno = EAGAIN;
            return XQC_SOCKET_EAGAIN;
        }

        /* client Initial dcid corruption */
        if (g_test_case == 22) {
            /* client initial dcid corruption, bytes [6, 13] is the DCID of xquic's Initial packet */
            g_test_case = -1;
            send_buf[6] = ~send_buf[6];
            printf("test case 22, corrupt byte[6]\n");
        }

        /* client Initial scid corruption */
        if (g_test_case == 23) {
            /* bytes [15, 22] is the SCID of xquic's Initial packet */
            g_test_case = -1;
            send_buf[15] = ~send_buf[15];
            printf("test case 23, corrupt byte[15]\n");
        }

        // drop the first datagram packet
        if ((g_test_case == 205 || g_test_case == 206) && g_no_crypt && !dgram_drop_pkt1) {
            header_type = send_buf[0] & 0x80;
            if (header_type == 0x80) {
                // long header: 29B + 3B (frame header)
                int lp_type = send_buf[0] & 0x30;
                if (lp_type == 0x10) {
                    //0RTT pkt
                    if (send_buf[29] == 0x31) {
                        //datagram frame
                        if (g_test_case == 206) {
                            //hold data & swap the order with the next one
                            //swap 1st & 2nd dgram
                            memcpy(sock_op_buffer, send_buf, send_buf_size);
                            sock_op_buffer_len = send_buf_size;
                        }
                        dgram_drop_pkt1 = 1;
                        return send_buf_size;
                    }
                }
            } else {
                // short header: 13B + 3B (frame header)
                if (send_buf[13] == 0x31) {
                    //datagram frame
                    if (g_test_case == 206) {
                        //hold data & swap the order with the next one
                        //swap 1st & 2nd dgram
                        memcpy(sock_op_buffer, send_buf, send_buf_size);
                        sock_op_buffer_len = send_buf_size;
                    }
                    dgram_drop_pkt1 = 1;
                    return send_buf_size;
                }
            }
        }

        res = sendto(fd, send_buf, send_buf_size, 0, peer_addr, peer_addrlen);
        if (res < 0) {
            printf("xqc_client_write_socket_ex path:%"PRIu64" err %zd %s %zu\n", path_id, res, strerror(errno), send_buf_size);
            if (errno == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            } else {
                res = XQC_SOCKET_ERROR;
            }
            if (errno == EMSGSIZE) {
                res = send_buf_size;
            }
        } else if (path != NULL) {
            xqc_test_cli_log_send_trace(path, send_buf, (size_t) res);
        }

        if (sock_op_buffer_len) {
            int header_type = send_buf[0] & 0x80;
            int frame_type = -1;
            if (header_type == 0x80) {
                // long header: 29B + 3B (frame header)
                int lp_type = send_buf[0] & 0x30;
                if (lp_type == 0x10) {
                    //0RTT pkt
                    frame_type = send_buf[29];
                }  
            } else {
                frame_type = send_buf[13];
            }
            if (frame_type == 0x31) {
                int tmp = sendto(fd, sock_op_buffer, sock_op_buffer_len, 0, peer_addr, peer_addrlen);
                if (tmp < 0) {
                    res = tmp;
                    printf("xqc_client_write_socket err %zd %s\n", res, strerror(errno));
                    if (errno == EAGAIN) {
                        res = XQC_SOCKET_EAGAIN;
                    }
                } else if (path != NULL) {
                    xqc_test_cli_log_send_trace(path, sock_op_buffer, (size_t) tmp);
                }
                sock_op_buffer_len = 0;
            }
        }

    } while ((res < 0) && (errno == EINTR));

    return res;
}

ssize_t
xqc_client_send_stateless_reset(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, int fd, void *user)
{
    return xqc_client_write_socket(buf, size, peer_addr, peer_addrlen, user);
}

xqc_int_t 
xqc_client_conn_closing_notify(xqc_connection_t *conn,
    const xqc_cid_t *cid, xqc_int_t err_code, void *conn_user_data)
{
    printf("conn closing: %d\n", err_code);
    return XQC_OK;
}


#if defined(XQC_SUPPORT_SENDMMSG) && !defined(XQC_SYS_WINDOWS)
ssize_t 
xqc_client_write_mmsg(const struct iovec *msg_iov, unsigned int vlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user)
{
    const int MAX_SEG = 128;
    user_conn_t *user_conn = (user_conn_t *) user;
    ssize_t res = 0;
    int fd = user_conn->fd;
    xqc_user_path_t *path = xqc_test_cli_find_path_by_fd(fd);
    struct mmsghdr mmsg[MAX_SEG];
    memset(&mmsg, 0, sizeof(mmsg));
    for (int i = 0; i < vlen; i++) {
        mmsg[i].msg_hdr.msg_iov = (struct iovec *)&msg_iov[i];
        mmsg[i].msg_hdr.msg_iovlen = 1;
    }
    do {
        set_sys_errno(0);
        if (TEST_DROP) return vlen;

        if (g_test_case == 5) { /* socket send fail */
            g_test_case = -1;
            errno = EAGAIN;
            return XQC_SOCKET_EAGAIN;
        }

        res = sendmmsg(fd, mmsg, vlen, 0);
        if (res < 0) {
            printf("sendmmsg err %zd %s\n", res, strerror(errno));
            if (errno == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }
        } else if (path != NULL) {
            int i;
            for (i = 0; i < res; i++) {
                xqc_test_cli_log_send_trace(path,
                    (const unsigned char *) msg_iov[i].iov_base,
                    mmsg[i].msg_len);
            }
        }
    } while ((res < 0) && (errno == EINTR));
    return res;
}


ssize_t
xqc_client_mp_write_mmsg(uint64_t path_id,
    const struct iovec *msg_iov, unsigned int vlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user)
{
    const int MAX_SEG = 128;
    user_conn_t *user_conn = (user_conn_t *) user;
    ssize_t res = 0;
    int fd = 0;
    xqc_user_path_t *path = NULL;

    /* check whether it's initial path */
    if (path_id == 0) {
        fd = user_conn->fd;
    } else {
        fd = g_client_path[path_id].path_fd;
    }
    path = xqc_test_cli_find_path_by_id(path_id);
    if (path == NULL) {
        path = xqc_test_cli_find_path_by_fd(fd);
    }

    struct mmsghdr mmsg[MAX_SEG];
    memset(&mmsg, 0, sizeof(mmsg));
    for (int i = 0; i < vlen; i++) {
        mmsg[i].msg_hdr.msg_iov = (struct iovec *)&msg_iov[i];
        mmsg[i].msg_hdr.msg_iovlen = 1;
    }
    do {
        errno = 0;
        if (TEST_DROP) return vlen;

        if (g_test_case == 5) { /* socket send fail */
            g_test_case = -1;
            errno = EAGAIN;
            return XQC_SOCKET_EAGAIN;
        }

        res = sendmmsg(fd, mmsg, vlen, 0);
        if (res < 0) {
            printf("sendmmsg err %zd %s\n", res, strerror(errno));
            if (errno == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }
        } else if (path != NULL) {
            int i;
            for (i = 0; i < res; i++) {
                xqc_test_cli_log_send_trace(path,
                    (const unsigned char *) msg_iov[i].iov_base,
                    mmsg[i].msg_len);
            }
        }
    } while ((res < 0) && (errno == EINTR));
    return res;
}
#endif

static int
xqc_client_bind_to_interface(int fd, const char *interface_name)
{
#if !defined(XQC_SYS_WINDOWS)
    struct ifreq ifr;
    memset(&ifr, 0x00, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
#if !defined(__APPLE__)
    printf("fd: %d. bind to nic: %s\n", fd, interface_name);
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifr, sizeof(ifr)) < 0) {
        printf("bind to nic error: %d, try use sudo\n", errno);
        return XQC_ERROR;
    }
#endif
#endif

    return XQC_OK;
}

static int 
xqc_client_create_socket(int type, 
    const struct sockaddr *saddr, socklen_t saddr_len, char *interface_type)
{
    int size;
    int fd = -1;
    int flags;

    /* create fd & set socket option */
    fd = socket(type, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("create socket failed, errno: %d\n", get_sys_errno());
        return -1;
    }

#ifdef XQC_SYS_WINDOWS
    if (ioctlsocket(fd, FIONBIO, &flags) == SOCKET_ERROR) {
		goto err;
	}
#else
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        printf("set socket nonblock failed, errno: %d\n", get_sys_errno());
        goto err;
    }
#endif

    size = 1 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

#if !defined(__APPLE__)
    int val = IP_PMTUDISC_DO;
    setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
#endif

    g_last_sock_op_time = xqc_now();

    if (interface_type != NULL
        && xqc_client_bind_to_interface(fd, interface_type) < 0) 
    {
        printf("|xqc_client_bind_to_interface error|");
        goto err;
    }

    /* connect to peer addr */
#if !defined(__APPLE__)
    if (connect(fd, (struct sockaddr *)saddr, saddr_len) < 0) {
        printf("connect socket failed, errno: %d\n", get_sys_errno());
        goto err;
    }
#endif

    return fd;

err:
    close(fd);
    return -1;
}


void 
xqc_convert_addr_text_to_sockaddr(int type,
    const char *addr_text, unsigned int port,
    struct sockaddr **saddr, socklen_t *saddr_len)
{
    if (type == AF_INET6) {
        *saddr = calloc(1, sizeof(struct sockaddr_in6));
        memset(*saddr, 0, sizeof(struct sockaddr_in6));
        struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)(*saddr);
        inet_pton(type, addr_text, &(addr_v6->sin6_addr.s6_addr));
        addr_v6->sin6_family = type;
        addr_v6->sin6_port = htons(port);
        *saddr_len = sizeof(struct sockaddr_in6);

    } else {
        *saddr = calloc(1, sizeof(struct sockaddr_in));
        memset(*saddr, 0, sizeof(struct sockaddr_in));
        struct sockaddr_in *addr_v4 = (struct sockaddr_in *)(*saddr);
        inet_pton(type, addr_text, &(addr_v4->sin_addr.s_addr));
        addr_v4->sin_family = type;
        addr_v4->sin_port = htons(port);
        *saddr_len = sizeof(struct sockaddr_in);
    }
}

void
xqc_client_init_addr(user_conn_t *user_conn,
    const char *server_addr, int server_port)
{
    int ip_type = (g_ipv6 ? AF_INET6 : AF_INET);
    xqc_convert_addr_text_to_sockaddr(ip_type, 
                                      server_addr, server_port,
                                      &user_conn->peer_addr, 
                                      &user_conn->peer_addrlen);

    if (ip_type == AF_INET6) {
        user_conn->local_addr = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in6));
        memset(user_conn->local_addr, 0, sizeof(struct sockaddr_in6));
        user_conn->local_addrlen = sizeof(struct sockaddr_in6);

    } else {
        user_conn->local_addr = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in));
        memset(user_conn->local_addr, 0, sizeof(struct sockaddr_in));
        user_conn->local_addrlen = sizeof(struct sockaddr_in);
    }
}

static int
xqc_client_create_path_socket(xqc_user_path_t *path,
    char *path_interface)
{
    path->path_fd = xqc_client_create_socket((g_ipv6 ? AF_INET6 : AF_INET), 
                         path->peer_addr, path->peer_addrlen, path_interface);
    if (path->path_fd < 0) {
        printf("|xqc_client_create_path_socket error|");
        return XQC_ERROR;
    }
#ifndef XQC_SYS_WINDOWS
    if (path_interface != NULL
        && xqc_client_bind_to_interface(path->path_fd, path_interface) < 0) 
    {
        printf("|xqc_client_bind_to_interface error|");
        return XQC_ERROR;
    }

    if (g_test_case == 103 || g_test_case == 104) {
        path->rebinding_path_fd = xqc_client_create_socket((g_ipv6 ? AF_INET6 : AF_INET), 
                                        path->peer_addr, path->peer_addrlen, path_interface);
        if (path->rebinding_path_fd < 0) {
            printf("|xqc_client_create_path_socket error|");
            return XQC_ERROR;
        }
    }
#endif

    return XQC_OK;
}


static int
xqc_client_create_path(xqc_user_path_t *path, 
    char *path_interface, user_conn_t *user_conn)
{
    path->path_id = 0;
    path->is_in_used = 0;
    path->user_conn = user_conn;
    path->path_seq = -1;
    path->ifindex = 0;
    path->ifname[0] = '\0';

    path->peer_addr = calloc(1, user_conn->peer_addrlen);
    memcpy(path->peer_addr, user_conn->peer_addr, user_conn->peer_addrlen);
    path->peer_addrlen = user_conn->peer_addrlen;

    if (path_interface != NULL) {
        snprintf(path->ifname, sizeof(path->ifname), "%s", path_interface);
        path->ifindex = if_nametoindex(path_interface);
    }
    
    if (xqc_client_create_path_socket(path, path_interface) < 0) {
        printf("xqc_client_create_path_socket error\n");
        return XQC_ERROR;
    }
    
    path->ev_socket = event_new(eb, path->path_fd, 
                EV_READ | EV_PERSIST, xqc_client_socket_event_callback, user_conn);
    event_add(path->ev_socket, NULL);

    if (g_test_case == 103 || g_test_case == 104) {
        path->rebinding_ev_socket = event_new(eb, path->rebinding_path_fd, EV_READ | EV_PERSIST,
                                              xqc_client_socket_event_callback, user_conn);
        event_add(path->rebinding_ev_socket, NULL);
    }

    return XQC_OK;
}

user_conn_t * 
xqc_client_user_conn_multi_process_create(client_ctx_t *ctx, const char *server_addr, int server_port,
    int transport)
{
    user_conn_t *user_conn = calloc(1, sizeof(user_conn_t));
    /* use HTTP3? */
    user_conn->h3 = transport;
    user_conn->ctx = ctx;

    user_conn->ev_timeout = event_new(ctx->eb, -1, 0, xqc_client_timeout_multi_process_callback, user_conn);
    
    /* set connection timeout */
    struct timeval tv;
    tv.tv_sec = g_conn_timeout;
    tv.tv_usec = 0;
    event_add(user_conn->ev_timeout, &tv);

    int ip_type = (g_ipv6 ? AF_INET6 : AF_INET);
    xqc_client_init_addr(user_conn, server_addr, server_port);
                                      
    user_conn->fd = xqc_client_create_socket(ip_type, 
            user_conn->peer_addr, user_conn->peer_addrlen, NULL);
    if (user_conn->fd < 0) {
        printf("xqc_create_socket error\n");
        return NULL;
    }
    user_conn->ev_socket = event_new(ctx->eb, user_conn->fd, EV_READ | EV_PERSIST, 
                                     xqc_client_socket_event_callback, user_conn);
    event_add(user_conn->ev_socket, NULL);

    return user_conn;
}

user_conn_t * 
xqc_client_user_conn_create(const char *server_addr, int server_port,
    int transport)
{
    user_conn_t *user_conn = calloc(1, sizeof(user_conn_t));

    /* use HTTP3? */
    user_conn->h3 = transport;

    user_conn->ev_timeout = event_new(eb, -1, 0, xqc_client_timeout_callback, user_conn);
    /* set connection timeout */
    struct timeval tv;
    tv.tv_sec = g_conn_timeout;
    tv.tv_usec = 0;
    event_add(user_conn->ev_timeout, &tv);

    if (g_epoch > 0) {
        user_conn->ev_epoch = event_new(eb, -1, 0, xqc_client_epoch_callback, user_conn);
        tv.tv_sec = g_epoch_timeout / 1000000;
        tv.tv_usec = g_epoch_timeout % 1000000;
        event_add(user_conn->ev_epoch, &tv);
        printf("epoch timer set!\n");
    }

    if (g_conn_abs_timeout > 0) {
        user_conn->ev_abs_timeout = event_new(eb, -1, 0, xqc_client_abs_timeout_callback, user_conn);
        tv.tv_sec = g_conn_abs_timeout;
        tv.tv_usec = 0;
        event_add(user_conn->ev_abs_timeout, &tv);
    }


    user_conn->conn_create_time = xqc_now();

    int ip_type = (g_ipv6 ? AF_INET6 : AF_INET);
    xqc_client_init_addr(user_conn, server_addr, server_port);
                                      
    return user_conn;
}

int
xqc_client_create_conn_socket(user_conn_t *user_conn)
{
    int ip_type = (g_ipv6 ? AF_INET6 : AF_INET);
    user_conn->fd = xqc_client_create_socket(ip_type, 
                                             user_conn->peer_addr, user_conn->peer_addrlen, NULL);
    if (user_conn->fd < 0) {
        printf("xqc_create_socket error\n");
        return -1;
    }

    user_conn->ev_socket = event_new(eb, user_conn->fd, EV_READ | EV_PERSIST, 
                                     xqc_client_socket_event_callback, user_conn);
    event_add(user_conn->ev_socket, NULL);

    return 0;
}

void
xqc_client_set_path_debug_timer(user_conn_t *user_conn)
{
    if (g_debug_path || g_test_case == 110) {
        if (user_conn->ev_path == NULL) {
            user_conn->ev_path = event_new(eb, -1, 0, xqc_client_path_callback, user_conn);
        }

        struct timeval tv;
        tv.tv_sec = g_path_timeout / 1000000;
        tv.tv_usec = g_path_timeout % 1000000;
        event_add(user_conn->ev_path, &tv);
    }
}

void
xqc_client_path_removed(const xqc_cid_t *scid, uint64_t path_id,
    void *conn_user_data)
{
    user_conn_t *user_conn = (user_conn_t *) conn_user_data;

    if (!g_enable_multipath) {
        return;
    }

    for (int i = 0; i < g_multi_interface_cnt; i++) {
        if (g_client_path[i].path_id == path_id) {
            g_client_path[i].path_id = 0;
            g_client_path[i].is_in_used = 0;
            
            printf("***** path removed. index: %d, path_id: %" PRIu64 "\n", i, path_id);

            xqc_client_set_path_debug_timer(user_conn);
            
            break;
        }
    }
}


int
xqc_client_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *)user_data;
    xqc_conn_set_alp_user_data(conn, user_conn);

    user_conn->dgram_mss = xqc_datagram_get_mss(conn);
    user_conn->quic_conn = conn;

    if (g_test_case == 200 || g_test_case == 201) {
        printf("[dgram-200]|0RTT|initial_mss:%zu|\n", user_conn->dgram_mss);
    }

    printf("xqc_conn_is_ready_to_send_early_data:%d\n", xqc_conn_is_ready_to_send_early_data(conn));
    return 0;
}

int
xqc_client_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *)user_data;

    client_ctx_t *p_ctx;
    if (g_test_qch_mode) {
        p_ctx = user_conn->ctx;
    } else {
        p_ctx = &ctx;
    }

    xqc_int_t err = xqc_conn_get_errno(conn);
    printf("should_clear_0rtt_ticket, conn_err:%d, clear_0rtt_ticket:%d\n", err, xqc_conn_should_clear_0rtt_ticket(err));

    xqc_conn_stats_t stats = xqc_conn_get_stats(p_ctx->engine, cid);
    printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" early_data_flag:%d, conn_err:%d, mp_state:%d, ack_info:%s, alpn:%s\n",
           stats.send_count, stats.lost_count, stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err, stats.mp_state, stats.ack_info, stats.alpn);

    printf("conn_info: \"%s\"\n", stats.conn_info);

    if (!g_test_qch_mode) {
        printf("[dgram]|recv_dgram_bytes:%zu|sent_dgram_bytes:%zu|lost_dgram_bytes:%zu|lost_cnt:%zu|\n", 
               user_conn->dgram_blk->data_recv, user_conn->dgram_blk->data_sent,
               user_conn->dgram_blk->data_lost, user_conn->dgram_blk->dgram_lost);
    }


    if (g_test_qch_mode) {
        if (p_ctx->cur_conn_num == 0) {
            event_base_loopbreak(p_ctx->eb);
        }
    } else {
        event_base_loopbreak(eb);
    }
    return 0;
}

void
xqc_client_conn_ping_acked_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *ping_user_data, void *user_data, void *conn_proto_data)
{
    DEBUG;
    if (ping_user_data) {
        printf("====>ping_id:%d\n", *(int *) ping_user_data);

    } else {
        printf("====>no ping_id\n");
    }
}

void
xqc_client_conn_update_cid_notify(xqc_connection_t *conn, const xqc_cid_t *retire_cid, const xqc_cid_t *new_cid, void *user_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *) user_data;

    memcpy(&user_conn->cid, new_cid, sizeof(*new_cid));

    printf("====>RETIRE SCID:%s\n", xqc_scid_str(ctx.engine, retire_cid));
    printf("====>SCID:%s\n", xqc_scid_str(ctx.engine, new_cid));
    printf("====>DCID:%s\n", xqc_dcid_str_by_scid(ctx.engine, new_cid));

}

void
xqc_client_conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *conn_proto_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *) user_data;
    if (!g_test_qch_mode) {
        if (!g_mp_ping_on) {
            xqc_conn_send_ping(ctx.engine, &user_conn->cid, NULL);
            xqc_conn_send_ping(ctx.engine, &user_conn->cid, &g_ping_id);
        }  

        printf("====>DCID:%s\n", xqc_dcid_str_by_scid(ctx.engine, &user_conn->cid));
        printf("====>SCID:%s\n", xqc_scid_str(ctx.engine, &user_conn->cid));
    }

    hsk_completed = 1;

    user_conn->dgram_mss = xqc_datagram_get_mss(conn);
    if (user_conn->dgram_mss == 0) {
        user_conn->dgram_not_supported = 1; 
        if (g_test_case == 204) {
            user_conn->dgram_not_supported = 0;
            user_conn->dgram_mss = 1000;
        }
    }
    if (g_test_case == 200 || g_test_case == 201) {
        printf("[dgram-200]|1RTT|updated_mss:%zu|\n", user_conn->dgram_mss);
    }
    
    if (g_send_dgram && user_conn->dgram_retry_in_hs_cb) {
        xqc_client_datagram_send(user_conn);
    }
}

int
xqc_client_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *) user_data;

    user_conn->dgram_mss = xqc_h3_ext_datagram_get_mss(conn);
    user_conn->h3_conn = conn;

    if (g_test_case == 200 || g_test_case == 201) {
        printf("[h3-dgram-200]|0RTT|initial_mss:%zu|\n", user_conn->dgram_mss);
    }

    printf("xqc_h3_conn_is_ready_to_send_early_data:%d\n", xqc_h3_conn_is_ready_to_send_early_data(conn));
    return 0;
}



int
xqc_client_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *) user_data;
    printf("conn errno:%d\n", xqc_h3_conn_get_errno(conn));
    client_ctx_t *p_ctx;
    if (g_test_qch_mode) {
        p_ctx = user_conn->ctx;
    } else {
        p_ctx = &ctx;
    }

    xqc_int_t err = xqc_h3_conn_get_errno(conn);
    printf("should_clear_0rtt_ticket, conn_err:%d, clear_0rtt_ticket:%d\n", err, xqc_conn_should_clear_0rtt_ticket(err));

    xqc_conn_stats_t stats = xqc_conn_get_stats(p_ctx->engine, cid);
    printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" early_data_flag:%d, conn_err:%d, mp_state:%d, ack_info:%s, alpn:%s, conn_info:%s\n",
           stats.send_count, stats.lost_count, stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err, stats.mp_state, stats.ack_info, stats.alpn, stats.conn_info);

    if (!g_test_qch_mode) {
        printf("[h3-dgram]|recv_dgram_bytes:%zu|sent_dgram_bytes:%zu|lost_dgram_bytes:%zu|lost_cnt:%zu|\n", 
               user_conn->dgram_blk->data_recv, user_conn->dgram_blk->data_sent,
               user_conn->dgram_blk->data_lost, user_conn->dgram_blk->dgram_lost);
    }
    

    if (g_test_qch_mode) {
        if (p_ctx->cur_conn_num == 0) {
            event_base_loopbreak(p_ctx->eb);
        }
    } else {
        event_base_loopbreak(eb);
    }
    return 0;
}

void
xqc_client_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *) user_data;
    client_ctx_t *p_ctx;
    if (g_test_qch_mode) {
        p_ctx = user_conn->ctx;
    } else {
        p_ctx = &ctx;
    }

    if (!g_mp_ping_on) {
        xqc_h3_conn_send_ping(p_ctx->engine, &user_conn->cid, NULL);
        xqc_h3_conn_send_ping(p_ctx->engine, &user_conn->cid, &g_ping_id);
    }

    xqc_conn_stats_t stats = xqc_conn_get_stats(p_ctx->engine, &user_conn->cid);
    printf("0rtt_flag:%d\n", stats.early_data_flag);

    if (g_enable_multipath) {
        printf("transport_parameter:enable_multipath=%d\n", stats.enable_multipath);
    }

    printf("====>DCID:%s\n", xqc_dcid_str_by_scid(p_ctx->engine, &user_conn->cid));
    printf("====>SCID:%s\n", xqc_scid_str(p_ctx->engine, &user_conn->cid));

    hsk_completed = 1;

    user_conn->dgram_mss = xqc_h3_ext_datagram_get_mss(h3_conn);
    if (user_conn->dgram_mss == 0) {
        user_conn->dgram_not_supported = 1; 
        if (g_test_case == 204) {
            user_conn->dgram_not_supported = 0;
            user_conn->dgram_mss = 1000;
        }
    }

    if (g_test_case == 200 || g_test_case == 201) {
        printf("[h3-dgram-200]|1RTT|updated_mss:%zu|\n", user_conn->dgram_mss);
    }
    
    if (g_send_dgram && user_conn->dgram_retry_in_hs_cb) {
        xqc_client_h3_ext_datagram_send(user_conn);
    }
}

void
xqc_client_h3_conn_ping_acked_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *ping_user_data, void *user_data)
{
    DEBUG;
    if (ping_user_data) {
        printf("====>ping_id:%d\n", *(int *) ping_user_data);

    } else {
        printf("====>no ping_id\n");
    }
}

void
xqc_client_h3_conn_init_settings_notify(xqc_h3_conn_t *h3_conn, 
    xqc_h3_conn_settings_t *current_settings, void *h3c_user_data)
{
    current_settings->qpack_dec_max_table_capacity = 64 * 1024;
}

void
xqc_client_h3_conn_update_cid_notify(xqc_h3_conn_t *conn, const xqc_cid_t *retire_cid, const xqc_cid_t *new_cid, void *user_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *) user_data;

    memcpy(&user_conn->cid, new_cid, sizeof(*new_cid));

    printf("====>RETIRE SCID:%s\n", xqc_scid_str(ctx.engine, retire_cid));
    printf("====>SCID:%s\n", xqc_scid_str(ctx.engine, new_cid));
    printf("====>DCID:%s\n", xqc_dcid_str_by_scid(ctx.engine, new_cid));

}

int
xqc_client_stream_send(xqc_stream_t *stream, void *user_data)
{
    static int send_cnt = 0;
    size_t send_len;
    unsigned char *send_buf;
    printf("|xqc_client_stream_send|cnt:%d|\n", ++send_cnt);

    if (g_test_case == 99) {
        xqc_stream_send(stream, NULL, 0, 1);
        return 0;
    }

    ssize_t ret;
    user_stream_t *user_stream = (user_stream_t *) user_data;

    if (user_stream->start_time == 0) {
        user_stream->start_time = xqc_now();
    }

    if (xqc_test_cli_prepare_transport_send_body(user_stream) != 0) {
        return -1;
    }

    int fin = 1;
    if (g_test_case == 4) { /* test fin_only */
        fin = 0;
    }

    if (user_stream->send_offset < user_stream->send_body_len) {
        send_len = user_stream->send_body_len - user_stream->send_offset;
        send_buf = (unsigned char *) user_stream->send_body + user_stream->send_offset;
        if (user_stream->send_body_streaming) {
            send_len = xqc_min(send_len, user_stream->send_body_max);
            send_buf = (unsigned char *) user_stream->send_body;
            if (fin && user_stream->send_offset + send_len < user_stream->send_body_len) {
                fin = 0;
            }
        }

        ret = xqc_stream_send(stream, send_buf, send_len, fin);
        if (ret < 0) {
            printf("xqc_stream_send error %zd\n", ret);
            return 0;

        } else {
            user_stream->send_offset += ret;
            printf("xqc_stream_send offset=%"PRIu64"\n", user_stream->send_offset);
        }
    }

    if (g_test_case == 4) { /* test fin_only */
        if (user_stream->send_offset == user_stream->send_body_len) {
            fin = 1;
            usleep(200*1000);
            ret = xqc_stream_send(stream, NULL, 0, fin);
            printf("xqc_stream_send sent:%zd, offset=%"PRIu64", fin=1\n", ret, user_stream->send_offset);
        }
    }

    return 0;
}

int
xqc_client_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    static int write_notify_cnt = 0;
    printf("|xqc_client_stream_write_notify|cnt:%d|\n", ++write_notify_cnt);

    //DEBUG;
    int ret = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
    ret = xqc_client_stream_send(stream, user_stream);
    xqc_test_cli_log_stream_trace(stream, user_stream, "write_notify", 0, ret);
    return ret;
}

int
xqc_client_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    //DEBUG;
    unsigned char fin = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
    char buff[4096] = {0};
    size_t buff_size = 4096;
    int save = g_save_body;

    if (save && user_stream->recv_body_fp == NULL) {
        user_stream->recv_body_fp = fopen(g_write_file, "wb");
        if (user_stream->recv_body_fp == NULL) {
            printf("open error\n");
            return -1;
        }
    }

    if (g_echo_check && user_stream->recv_body == NULL) {
        user_stream->recv_body = malloc(user_stream->send_body_len);
        if (user_stream->recv_body == NULL) {
            printf("recv_body malloc error\n");
            return -1;
        }
    }

    ssize_t read;
    ssize_t read_sum = 0;

    do {
        read = xqc_stream_recv(stream, buff, buff_size, &fin);
        if (read == -XQC_EAGAIN) {
            break;

        } else if (read < 0) {
            printf("xqc_stream_recv error %zd\n", read);
            return 0;
        }

        if (save && fwrite(buff, 1, read, user_stream->recv_body_fp) != read) {
            printf("fwrite error\n");
            return -1;
        }
        if (save) fflush(user_stream->recv_body_fp);

        /* write received body to memory */
        if (g_echo_check && user_stream->recv_body_len + read <= user_stream->send_body_len) {
            memcpy(user_stream->recv_body + user_stream->recv_body_len, buff, read);
        }

        read_sum += read;
        user_stream->recv_body_len += read;
        user_stream->recv_log_bytes += read;

        xqc_usec_t curr_time = xqc_now();
        if ((curr_time - user_stream->last_recv_log_time) >= 200000) {
            printf("[qperf]|ts:%"PRIu64"|recv_size:%"PRIu64"|\n", curr_time, user_stream->recv_log_bytes);
            user_stream->last_recv_log_time = curr_time;
            user_stream->recv_log_bytes = 0;
        }

    } while (read > 0 && !fin);

    // mpshell
    // printf("xqc_stream_recv read:%zd, offset:%zu, fin:%d\n", read_sum, user_stream->recv_body_len, fin);

    /* test first frame rendering time */
    if (g_test_case == 14 && user_stream->first_frame_time == 0 && user_stream->recv_body_len >= 98*1024) {
        user_stream->first_frame_time = xqc_now();
    }

    /* test abnormal rate */
    if (g_test_case == 14) {
        xqc_usec_t tmp = xqc_now();
        if (tmp - user_stream->last_read_time > 150*1000 && user_stream->last_read_time != 0 ) {
            user_stream->abnormal_count++;
            printf("\033[33m!!!!!!!!!!!!!!!!!!!!abnormal!!!!!!!!!!!!!!!!!!!!!!!!\033[0m\n");
        }
        user_stream->last_read_time = tmp;
    }

    if (fin) {
        user_stream->recv_fin = 1;
        xqc_usec_t now_us = xqc_now();
        printf("\033[33m>>>>>>>> request time cost:%"PRIu64" us, speed:%"PRIu64" Kbit/s \n"
               ">>>>>>>> send_body_size:%zu, recv_body_size:%zu \033[0m\n",
               now_us - user_stream->start_time,
               (user_stream->send_body_len + user_stream->recv_body_len)*8000/(now_us - user_stream->start_time),
               user_stream->send_body_len, user_stream->recv_body_len);
        
        printf("test_result_speed: %"PRIu64" Kbit/s\n", 
                (user_stream->send_body_len + user_stream->recv_body_len)*8000/(now_us - user_stream->start_time));

        printf("[rr_benchmark]|request_time:%"PRIu64"|"
               "request_size:%zu|response_size:%zu|\n",
               now_us - user_stream->start_time,
               user_stream->send_body_len, user_stream->recv_body_len);


        /* write to eval file */
        /*{
            FILE* fp = NULL;
            fp = fopen("eval_result.txt", "a+");
            if (fp == NULL) {
                exit(1);
            }

            fprintf(fp, "recv_size: %lu; cost_time: %lu\n", stats.recv_body_size, (uint64_t)((now_us - user_stream->start_time)/1000));
            fclose(fp);

            exit(0);
        }*/

    }
    xqc_test_cli_log_stream_trace(stream, user_stream, "read_notify", fin ? 1 : 0, read_sum);
    return 0;
}

int
xqc_client_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    user_stream_t *user_stream = (user_stream_t*)user_data;
    xqc_test_cli_log_stream_trace(stream, user_stream, "close_notify", 0, 0);
    if (g_echo_check) {
        int pass = 0;
        printf("user_stream->recv_fin:%d, user_stream->send_body_len:%zu, user_stream->recv_body_len:%zd\n",
               user_stream->recv_fin, user_stream->send_body_len, user_stream->recv_body_len);
        if (user_stream->recv_fin && user_stream->send_body_len == user_stream->recv_body_len
            && memcmp(user_stream->send_body, user_stream->recv_body, user_stream->send_body_len) == 0) {
            pass = 1;
        }
        printf(">>>>>>>> pass:%d\n", pass);
    }

    /* test first frame rendering time */
    if (g_test_case == 14) {
        printf("first_frame_time: %"PRIu64", start_time: %"PRIu64"\n", user_stream->first_frame_time, user_stream->start_time);
        xqc_usec_t t = user_stream->first_frame_time - user_stream->start_time + 200000 /* server-side time consumption */;
        printf("\033[33m>>>>>>>> first_frame pass:%d time:%"PRIu64"\033[0m\n", t <= 1000000 ? 1 : 0, t);
    }

    /* test abnormal rate */
    if (g_test_case == 14) {
        printf("\033[33m>>>>>>>> abnormal pass:%d count:%d\033[0m\n", user_stream->abnormal_count == 0 ? 1 : 0, user_stream->abnormal_count);
    }
    free(user_stream->send_body);
    free(user_stream->recv_body);
    free(user_stream);
    return 0;
}

int
xqc_client_bytestream_send(xqc_h3_ext_bytestream_t *h3_bs, user_stream_t *user_stream)
{
    if (user_stream->start_time == 0) {
        user_stream->start_time = xqc_now();
    }
    ssize_t ret = 0;
    char content_len[10];

    if (g_test_case == 302 || g_test_case == 310) {
        //send pure fin on bytestream
        xqc_h3_ext_bytestream_finish(h3_bs);
        return 0;
    }

    if (g_test_case == 303) {
        //send pure fin on bytestream
        xqc_h3_ext_bytestream_send(h3_bs, NULL, 0, 1, g_dgram_qos_level);
        return 0;
    }

    if (user_stream->send_body == NULL) {
        user_stream->send_body_max = MAX_BUF_SIZE;
        user_stream->send_body_len = g_send_body_size > user_stream->send_body_max ? user_stream->send_body_max : g_send_body_size;
        user_stream->send_body = malloc(user_stream->send_body_len);
        char *p = user_stream->send_body;
        for (size_t i = 0; i < user_stream->send_body_len; i++) {
            *p++ = rand();
        }

        if (user_stream->send_body == NULL) {
            printf("send_body malloc error\n");
            return -1;
        }
    }

    int fin = 1;
    if (g_test_case == 304 || g_test_case == 305 
        || g_test_case == 311 || g_test_case == 312 
        || g_test_case == 313 || g_test_case == 314) {
        //do not send fin with data
        fin = 0;
        // will send fin in a timer
    }

    /* send body */
    if (user_stream->send_offset < user_stream->send_body_len) {
        ret = xqc_h3_ext_bytestream_send(h3_bs, user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, fin, g_dgram_qos_level);

        if (ret == -XQC_EAGAIN) {
            printf("xqc_h3_ext_bytestream_send eagain %zd\n", ret);
            return 0;

        } else if (ret < 0) {
            printf("xqc_h3_ext_bytestream_send error %zd\n", ret);
            return 0;

        } else {
            user_stream->snd_times++;
            user_stream->send_offset += ret;
            // printf("[bytestream]|send:%"PRIu64"|\n", user_stream->send_offset);
        }
    }

    return 0;
}

int xqc_h3_ext_bytestream_create_callback(xqc_h3_ext_bytestream_t *h3_ext_bs, 
	void *bs_user_data)
{
    user_stream_t *user_stream = (user_stream_t*)bs_user_data;
    struct timeval tv;
    if (g_test_case == 304 || g_test_case == 305) {
        user_stream->ev_bytestream_timer = event_new(eb, -1, 0, xqc_client_bytestream_timeout_callback, user_stream);
        tv.tv_sec = 0;
        tv.tv_usec = 100000; //100ms
        event_add(user_stream->ev_bytestream_timer, &tv);
    }
    return 0;
}

int xqc_h3_ext_bytestream_close_callback(xqc_h3_ext_bytestream_t *h3_ext_bs, 
	void *bs_user_data)
{
    //print stats
    xqc_h3_ext_bytestream_stats_t stats = xqc_h3_ext_bytestream_get_stats(h3_ext_bs);
    user_stream_t *user_stream = (user_stream_t*)bs_user_data;

    printf("[bytestream]|bytes_sent:%zu|bytes_rcvd:%zu|recv_fin:%d|snd_times:%d|rcv_times:%d|\n", stats.bytes_sent, stats.bytes_rcvd, user_stream->recv_fin, user_stream->snd_times, user_stream->rcv_times);

    //check content
    if (g_echo_check) {
        if (user_stream->send_body && user_stream->recv_body && !memcmp(user_stream->send_body, user_stream->recv_body, user_stream->send_body_len)) {
            printf("[bytestream]|same_content:yes|\n");

        } else {
            printf("[bytestream]|same_content:no|\n");
        }
    }

    if (user_stream->send_body) {
        free(user_stream->send_body);
    }

    if (user_stream->recv_body) {
        free(user_stream->recv_body);
    }

    if (g_test_case == 304 || g_test_case == 305) {
        if (user_stream->ev_bytestream_timer) {
            event_free(user_stream->ev_bytestream_timer);
        }
    }

    free(user_stream);

    return 0;
}

int xqc_h3_ext_bytestream_read_callback(xqc_h3_ext_bytestream_t *h3_ext_bs, 
	const void *data, size_t data_len, uint8_t fin, void *bs_user_data, uint64_t data_recv_time)
{
    user_stream_t *user_stream = (user_stream_t*)bs_user_data;
    int ret = 0;

    if (user_stream->recv_body == NULL) {
        user_stream->recv_body = calloc(1, user_stream->send_body_len);
        user_stream->recv_body_len = 0;
        user_stream->recv_fin = 0;
    }

    if (data_len > 0) {
        memcpy(user_stream->recv_body + user_stream->recv_body_len, data, data_len);
        user_stream->recv_body_len += data_len;
    }

    if (!user_stream->recv_fin) {
        user_stream->recv_fin = fin;
    }

    if (g_test_case == 311 || g_test_case == 312 || g_test_case == 313 || g_test_case == 314) {
        user_stream->send_offset = 0;
        user_stream->recv_body_len = 0;
        user_stream->recv_fin = 0;
        user_stream->send_body_len = 1000;
        g_test_case = 0;
        xqc_client_bytestream_send(h3_ext_bs, user_stream);
    }

    user_stream->rcv_times++;

    printf("[bytestream]|stream_id:%"PRIu64"|data_len:%zu|fin:%d|recv_time:%"PRIu64"|\n", xqc_h3_ext_bytestream_id(h3_ext_bs), data_len, fin, data_recv_time);

    return 0;
}

int xqc_h3_ext_bytestream_write_callback(xqc_h3_ext_bytestream_t *h3_ext_bs, 
	void *bs_user_data)
{
    user_stream_t *us = bs_user_data;
    int ret;
    // printf("[bytestream]|write callback|\n");
    ret = xqc_client_bytestream_send(h3_ext_bs, us);
    if (ret == -XQC_EAGAIN) {
        ret = 0;
        printf("[bytestream]|write blocked|\n");
    }
    return 0;
}

void
xqc_client_request_send_fin_only(int fd, short what, void *arg)
{
    user_stream_t *us = (user_stream_t *)arg;
    xqc_int_t ret = xqc_h3_request_finish(us->h3_request);
    if (ret < 0) {
        printf("xqc_h3_request_finish error %d\n", ret);

    } else {
        printf("xqc_h3_request_finish success\n");
    }
}

int
xqc_client_request_send(xqc_h3_request_t *h3_request, user_stream_t *user_stream)
{
    if (g_test_case == 99) {
        xqc_h3_request_finish(h3_request);
        return 0;
    }

    if (user_stream->start_time == 0) {
        user_stream->start_time = xqc_now();
    }
    ssize_t ret = 0;
    char content_len[10];

    if (user_stream->send_body == NULL && !g_is_get /* POST */) {
        user_stream->send_body_max = MAX_BUF_SIZE;
        if (g_read_body) {
            user_stream->send_body = malloc(user_stream->send_body_max);

        } else {
            if (g_send_body_size_from_cdf == 1) {
                g_send_body_size = get_random_from_cdf();
                printf("send_request, size_from_cdf:%zu\n", g_send_body_size);
            }
            user_stream->send_body = malloc(g_send_body_size);
            char *p = user_stream->send_body;
            for (size_t i = 0; i < g_send_body_size; i++) {
                *p++ = rand();
            }
        }

        if (user_stream->send_body == NULL) {
            printf("send_body malloc error\n");
            return -1;
        }

        /* specified size > specified file > default size */
        if (g_send_body_size_defined) {
            user_stream->send_body_len = g_send_body_size;

        } else if (g_read_body) {
            ret = read_file_data(user_stream->send_body, user_stream->send_body_max, g_read_file);
            if (ret < 0) {
                printf("read body error\n");
                return -1;

            } else {
                user_stream->send_body_len = ret;
            }

        } else {
            user_stream->send_body_len = g_send_body_size;
        }
    }

    if (g_is_get) {
        snprintf(content_len, sizeof(content_len), "%d", 0);

    } else {
        snprintf(content_len, sizeof(content_len), "%zu", user_stream->send_body_len);
    }
    int header_size = 6;
    xqc_http_header_t header[MAX_HEADER] = {
        {
            .name   = {.iov_base = ":method", .iov_len = 7},
            .value  = {.iov_base = "POST", .iov_len = 4},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = ":scheme", .iov_len = 7},
            .value  = {.iov_base = g_scheme, .iov_len = strlen(g_scheme)},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "host", .iov_len = 4},
            .value  = {.iov_base = g_host, .iov_len = strlen(g_host)},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = ":path", .iov_len = 5},
            .value  = {.iov_base = g_url_path, .iov_len = strlen(g_url_path)},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "content-type", .iov_len = 12},
            .value  = {.iov_base = "text/plain", .iov_len = 10},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "content-length", .iov_len = 14},
            .value  = {.iov_base = content_len, .iov_len = strlen(content_len)},
            .flags  = 0,
        },
    };

    if (g_test_case == 47) {
        header[header_size].name.iov_base = "test_null_hdr";
        header[header_size].name.iov_len = 13;
        header[header_size].value.iov_base = "";
        header[header_size].value.iov_len = 0;
        header_size++;
    }

    if (g_enable_fec) {
        xqc_h3_priority_t h3_prio = {
            .fec = 4 * 1024
        };
        xqc_h3_request_set_priority(h3_request, &h3_prio);

        h3_prio.fec = 20 * 1024;

        ret = xqc_write_http_priority(&h3_prio, g_priority, 64);
        if (ret < 0) {
            printf("xqc_write_http_priority error %zd\n", ret);
            return ret;
        }
        xqc_http_header_t priority_hdr = {
            .name   = {.iov_base = "priority", .iov_len = 8},
            .value  = {.iov_base = g_priority, .iov_len = ret},
            .flags  = 0,
        };
        header[header_size] = priority_hdr;
        header_size++;
    }

    if (g_mp_request_accelerate) {
        /* set local h3 priority */
        xqc_h3_priority_t h3_prio = {
            .urgency = 3,
            .incremental = 1,
            .schedule = 1,
            .reinject = 1,
            .fec = XQC_DEFAULT_SIZE_REQ,
            .fastpath = 1,
        };
        xqc_h3_request_set_priority(h3_request, &h3_prio);

        /* send h3 priority signals  */
        ret = xqc_write_http_priority(&h3_prio, g_priority, 64);
        if (ret < 0) {
            printf("xqc_write_http_priority error %zd\n", ret);
            return ret;
        }

        xqc_http_header_t priority_hdr = {
            .name   = {.iov_base = "priority", .iov_len = 8},
            .value  = {.iov_base = g_priority, .iov_len = ret},
            .flags  = 0,
        };
        header[header_size] = priority_hdr;
        header_size++;
    }

    if (g_test_case == 29) {
        memset(test_long_value, 'a', XQC_TEST_LONG_HEADER_LEN - 1);

        xqc_http_header_t test_long_hdr = {
            .name   = {.iov_base = "long_filed_line", .iov_len = 15},
            .value  = {.iov_base = test_long_value, .iov_len = strlen(test_long_value)},
            .flags  = 0,
        };

        header[header_size] = test_long_hdr;
        header_size++;
    }

    if (g_test_case == 34) {

        xqc_http_header_t uppercase_name_hdr = {
            .name   = {.iov_base = "UpperCaseFiledLineName", .iov_len = 22},
            .value  = {.iov_base = "UpperCaseFiledLineValue", .iov_len = 23},
            .flags  = 0,
        };
        header[header_size] = uppercase_name_hdr;
        header_size++;

        xqc_http_header_t lowcase_start_hdr = {
            .name   = {.iov_base = "filelineNamewithLowerCaseStart", .iov_len = 30},
            .value  = {.iov_base = "UpperCaseFiledLineValue", .iov_len = 23},
            .flags  = 0,
        };
        header[header_size] = lowcase_start_hdr;
        header_size++;

        memset(test_long_value, 'A', 1024);
    
        xqc_http_header_t test_long_hdr = {
            .name   = {.iov_base = test_long_value, .iov_len = 1024},
            .value  = {.iov_base = "header_with_long_name", .iov_len = 21},
            .flags  = 0,
        };

        header[header_size] = test_long_hdr;
        header_size++;

        header[header_size] = lowcase_start_hdr;
        header_size++;
    }

    if (g_header_cnt > 0) {
        for (int i = 0; i < g_header_cnt; i++) {
            char *pos = strchr(g_headers[i], ':');
            if (pos == NULL) {
                continue;
            }
            header[header_size].name.iov_base = g_headers[i];
            header[header_size].name.iov_len = pos - g_headers[i];
            header[header_size].value.iov_base = pos + 1;
            header[header_size].value.iov_len = strlen(pos+1);
            header[header_size].flags = 0;
            header_size++;
        }
    }

    while (header_size < g_header_num) {
        int m = 0, n = 0;
        m = rand();
        n = rand();
        header[header_size].name.iov_base = g_header_key;
        header[header_size].name.iov_len = m%(MAX_HEADER_KEY_LEN - 1) + 1;
        header[header_size].value.iov_base = g_header_value;
        header[header_size].value.iov_len = n%(MAX_HEADER_VALUE_LEN - 1) + 1;
        header[header_size].flags = 0;
        header_size++;
    }

    xqc_http_headers_t headers = {
        .headers = header,
        .count  = header_size,
    };

    int header_only = g_is_get;
    if (g_is_get) {
         header[0].value.iov_base = "GET";
         header[0].value.iov_len = sizeof("GET") - 1;
    }

    /* send header */
    if (user_stream->header_sent == 0) {
        if (g_test_case == 30 || g_test_case == 37 || g_test_case == 38) {
            ret = xqc_h3_request_send_headers(h3_request, &headers, 0);

        } else  {
            ret = xqc_h3_request_send_headers(h3_request, &headers, header_only);
        }

        if (ret < 0) {
            printf("xqc_h3_request_send_headers error %zd\n", ret);
            return ret;

        } else {
            printf("xqc_h3_request_send_headers success size=%zd\n", ret);
            user_stream->header_sent = 1;
        }

        if (g_test_case == 30) {
            usleep(200*1000);
            ret = xqc_h3_request_send_headers(h3_request, &headers, header_only);
            if (ret < 0) {
                printf("xqc_h3_request_send_headers error %zd\n", ret);
                return ret;

            } else {
                printf("xqc_h3_request_send_headers success size=%zd\n", ret);
            }
        }

        if (g_test_case == 37) {
            header_only = 1;
            struct timeval finish = {1, 0};
            ctx.ev_delay = event_new(eb, -1, 0, xqc_client_request_send_fin_only, user_stream);
            event_add(ctx.ev_delay, &finish);

        } else if (g_test_case == 38) {
            header_only = 1;
            ret = xqc_h3_request_finish(h3_request);
            if (ret < XQC_OK) {
                printf("xqc_h3_request_finish fail, error %zd\n", ret);
                return ret;
            }
            
        }
    }

    if (header_only) {
        return 0;
    }

    int fin = 1;
    if (g_test_case == 4 || g_test_case == 31 || g_test_case == 35 || g_test_case == 36) { /* test fin_only */
        fin = 0;
    }

    if (g_test_case == 109) {
        xqc_stream_settings_t settings = {.recv_rate_bytes_per_sec = 100000000};
        xqc_h3_request_update_settings(h3_request, &settings);
    }


    /* send body */
    if (user_stream->send_offset < user_stream->send_body_len) {
        if (g_test_case == 49) { /* test send 4K every time */
            do {
                size_t data_size = user_stream->send_body_len - user_stream->send_offset < 4096 ?
                        user_stream->send_body_len - user_stream->send_offset : 4096;
                fin = user_stream->send_offset + data_size == user_stream->send_body_len ? 1 : 0;
                ret = xqc_h3_request_send_body(h3_request, user_stream->send_body + user_stream->send_offset,
                                               data_size, fin);
                if (ret == -XQC_EAGAIN) {
                    return 0;

                } else if (ret < 0) {
                    printf("xqc_h3_request_send_body error %zd\n", ret);
                    return 0;

                } else {
                    user_stream->send_offset += ret;
                    printf("xqc_h3_request_send_body sent:%zd, offset=%"PRIu64"\n", ret, user_stream->send_offset);
                }
            } while (user_stream->send_offset < user_stream->send_body_len);
            goto next;
        }
        ret = xqc_h3_request_send_body(h3_request, user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, fin);
        if (ret == -XQC_EAGAIN) {
            printf("xqc_h3_request_send_body eagain %zd\n", ret);
            return 0;

        } else if (ret < 0) {
            printf("xqc_h3_request_send_body error %zd\n", ret);
            return 0;

        } else {
            user_stream->send_offset += ret;
            // mpshell
            // printf("xqc_h3_request_send_body sent:%zd, offset=%"PRIu64"\n", ret, user_stream->send_offset);
        }
    }
next:
    /* send trailer header */
    if (user_stream->send_offset == user_stream->send_body_len) {
        if (g_test_case == 31) {
            ret = xqc_h3_request_send_headers(h3_request, &headers, 1);
            if (ret < 0) {
                printf("xqc_h3_request_send_headers error %zd\n", ret);
                return ret;

            } else {
                printf("xqc_h3_request_send_headers success size=%zd\n", ret);
            }
        }

        /* no tailer header, fin only */
        if (g_test_case == 35) {
            struct timeval finish = {1, 0};
            ctx.ev_delay = event_new(eb, -1, 0, xqc_client_request_send_fin_only, user_stream);
            event_add(ctx.ev_delay, &finish);

        } else if (g_test_case == 36) {
            ret = xqc_h3_request_finish(h3_request);
            if (ret != XQC_OK) {
                printf("send request finish error, ret: %zd\n", ret);

            } else {
                printf("send request finish suc\n");
            }
        }
    }

    if (g_test_case == 4) { /* test fin_only */
        if (user_stream->send_offset == user_stream->send_body_len) {
            fin = 1;
            usleep(200*1000);
            ret = xqc_h3_request_send_body(h3_request, user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, fin);
            printf("xqc_h3_request_send_body sent:%zd, offset=%"PRIu64", fin=1\n", ret, user_stream->send_offset);
        }
    }

    if (g_test_case == 50) {
        ret = xqc_h3_request_send_body(h3_request, user_stream->send_body, 10, 0);
        printf("xqc_h3_request_send_body sent:%zd\n", ret);
    }

    if (g_test_case == 51) {
        ret = xqc_h3_request_send_headers(h3_request, &headers, 1);
        printf("xqc_h3_request_send_headers sent:%zd\n", ret);
    }

    if (g_test_case == 52) {
        ret = xqc_h3_request_finish(h3_request);
    }


    return 0;
}

int
xqc_client_request_write_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    //DEBUG;
    ssize_t ret = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
    if (g_test_case == 1) { /* reset stream */
        xqc_h3_request_close(h3_request);
        return 0;
    }

    if (g_test_case == 2) { /* user close connection */
        xqc_h3_conn_close(ctx.engine, &user_stream->user_conn->cid);
        return 0;
    }

    if (g_test_case == 3) { /* close connection with error */
        return -1;
    }

    printf("request write notify!:%"PRIu64"\n", xqc_h3_stream_id(h3_request));
    ret = xqc_client_request_send(h3_request, user_stream);
    xqc_test_cli_log_request_trace(h3_request, user_stream, "write_notify", XQC_REQ_NOTIFY_READ_NULL, ret);
    return ret;
}

int
xqc_client_request_read_notify(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag, void *user_data)
{
    //DEBUG;
    unsigned char fin = 0;
    ssize_t read_sum = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;

    if (g_test_case == 21) { /* reset stream */
        xqc_h3_request_close(h3_request);
        return 0;
    }

    if (g_test_case == 28) { /* Send header after reset stream */
        xqc_h3_request_close(h3_request);
        xqc_http_header_t header = {
            .name = {
                .iov_base = "name",
                .iov_len = sizeof("name")
            },
            .value = {
                .iov_base = "value",
                .iov_len = sizeof("value")
            },
        };
 
        xqc_http_headers_t headers = {
            .headers = &header,
            .count = 1,
        };

        ssize_t sent = xqc_h3_request_send_headers(h3_request, &headers, 1);
        if (sent < 0) {
            printf("send headers error\n");
        }

        return 0;
    }

    /* stream read notify fail */
    if (g_test_case == 12) {
        return -1;
    }

    if ((flag & XQC_REQ_NOTIFY_READ_HEADER) || (flag & XQC_REQ_NOTIFY_READ_TRAILER)) {
        xqc_http_headers_t *headers;
        headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers == NULL) {
            printf("xqc_h3_request_recv_headers error\n");
            return -1;
        }

        for (int i = 0; i < headers->count; i++) {
            printf("%s = %s\n", (char *)headers->headers[i].name.iov_base, (char *)headers->headers[i].value.iov_base);
        }

        user_stream->header_recvd = 1;

        if (fin) {
            /* only header, receive request completed */
            user_stream->recv_fin = 1;
            return 0;
        }

        /* continue to receive body */
    }

    if (flag & XQC_REQ_NOTIFY_READ_BODY) {

        char buff[4096] = {0};
        size_t buff_size = 4096;
        int save = g_save_body;

        if (save && user_stream->recv_body_fp == NULL) {
            user_stream->recv_body_fp = fopen(g_write_file, "wb");
            if (user_stream->recv_body_fp == NULL) {
                printf("open error\n");
                return -1;
            }
        }

        if (g_echo_check && user_stream->recv_body == NULL) {
            user_stream->recv_body = malloc(user_stream->send_body_len);
            if (user_stream->recv_body == NULL) {
                printf("recv_body malloc error\n");
                return -1;
            }
        }

        ssize_t read;
        do {
            read = xqc_h3_request_recv_body(h3_request, buff, buff_size, &fin);
            if (read == -XQC_EAGAIN) {
                break;

            } else if (read < 0) {
                printf("xqc_h3_request_recv_body error %zd\n", read);
                return 0;
            }

            if (save && fwrite(buff, 1, read, user_stream->recv_body_fp) != read) {
                printf("fwrite error\n");
                return -1;
            }

            if (save) {
                fflush(user_stream->recv_body_fp);
            }

            /* write received body to memory */
            if (g_echo_check && user_stream->recv_body_len + read <= user_stream->send_body_len) {
                memcpy(user_stream->recv_body + user_stream->recv_body_len, buff, read);
            }

            read_sum += read;
            user_stream->recv_body_len += read;
            mp_has_recved += read_sum;

        } while (read > 0 && !fin);

        if (flag & XQC_REQ_NOTIFY_READ_EMPTY_FIN) {
            fin = 1;
        }

        // mpshell: 批量测试，无需打印
        // printf("xqc_h3_request_recv_body read:%zd, offset:%zu, fin:%d\n", read_sum, user_stream->recv_body_len, fin);
    }


    if (flag & XQC_REQ_NOTIFY_READ_EMPTY_FIN) {
        fin = 1;

        printf("h3 fin only received\n");
    }


    if (fin) {
        user_stream->recv_fin = 1;
        xqc_request_stats_t stats;
        stats = xqc_h3_request_get_stats(h3_request);
        xqc_usec_t now_us = xqc_now();
        printf("\033[33m>>>>>>>> request time cost:%"PRIu64" us, speed:%"PRIu64" Kbit/s \n"
               ">>>>>>>> send_body_size:%zu, recv_body_size:%zu \033[0m\n",
               now_us - user_stream->start_time,
               (stats.send_body_size + stats.recv_body_size)*8000/(now_us - user_stream->start_time),
               stats.send_body_size, stats.recv_body_size);
        printf("test_result_speed: %"PRIu64" Kbit/s. request_cnt: %d.\n", (stats.send_body_size + stats.recv_body_size)*8000/(now_us - user_stream->start_time), g_req_cnt);

        printf("retx:%u, sent:%u, max_pto:%u\n", stats.retrans_cnt, stats.sent_pkt_cnt, stats.max_pto_backoff);

        printf("[rr_benchmark]|request_time:%"PRIu64"|"
               "request_size:%zu|response_size:%zu|\n",
               now_us - user_stream->start_time,
               user_stream->send_body_len, user_stream->recv_body_len);
        /* write to eval file */
        /*{
            FILE* fp = NULL;
            fp = fopen("eval_result.txt", "a+");
            if (fp == NULL) {
                exit(1);
            }

            fprintf(fp, "recv_size: %lu; cost_time: %lu\n", stats.recv_body_size, (uint64_t)((now_us - user_stream->start_time)/1000));
            fclose(fp);

            exit(0);
        }*/

    }
    xqc_test_cli_log_request_trace(h3_request, user_stream, "read_notify", flag, read_sum);
    return 0;
}

int
xqc_client_request_close_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    DEBUG;
    user_stream_t *user_stream = (user_stream_t *)user_data;
    user_conn_t *user_conn = user_stream->user_conn;
    client_ctx_t *p_ctx;
    if (g_test_qch_mode) {
        p_ctx = user_conn->ctx;
    } else {
        p_ctx = &ctx;
    }

    xqc_request_stats_t stats;
    stats = xqc_h3_request_get_stats(h3_request);
    printf("send_body_size:%zu, recv_body_size:%zu, send_header_size:%zu, recv_header_size:%zu, recv_fin:%d, err:%d, "
            "mp_state:%d, cellular_send_weight:%.2f, cellular_recv_weight:%.2f, stream_info:%s\n",
           stats.send_body_size, stats.recv_body_size,
           stats.send_header_size, stats.recv_header_size,
           user_stream->recv_fin, stats.stream_err,
           stats.mp_state,
           stats.mp_standby_path_send_weight, stats.mp_standby_path_recv_weight,
           stats.stream_info);

    printf("retx:%u, sent:%u, max_pto:%u\n", stats.retrans_cnt, stats.sent_pkt_cnt, stats.max_pto_backoff);
    xqc_test_cli_log_request_trace(h3_request, user_stream, "close_notify", XQC_REQ_NOTIFY_READ_NULL, 0);

    if (g_echo_check) {
        int pass = 0;
        if (user_stream->recv_fin && user_stream->send_body_len == user_stream->recv_body_len
            && memcmp(user_stream->send_body, user_stream->recv_body, user_stream->send_body_len) == 0)
        {
            pass = 1;

            /* large data read once for all */
            if (user_stream->send_body_len >= 1024 * 1024 && user_stream->body_read_notify_cnt == 1) {
                pass = 0;
                printf("large body received once for all");
            }
        }
        printf(">>>>>>>> pass:%d\n", pass);
    }

    free(user_stream->send_body);
    free(user_stream->recv_body);
    free(user_stream);

    if (g_req_cnt < g_req_max) {
        user_stream = calloc(1, sizeof(user_stream_t));
        user_stream->user_conn = user_conn;
        user_stream->h3_request = xqc_h3_request_create(p_ctx->engine, &user_conn->cid, NULL, user_stream);
        if (user_stream->h3_request == NULL) {
            printf("xqc_h3_request_create error\n");
            free(user_stream);
            return 0;
        }
        
        printf("***** xqc_client_request_send\n");
        xqc_client_request_send(user_stream->h3_request, user_stream);
        xqc_engine_main_logic(p_ctx->engine);
        g_req_cnt++;
    }
    return 0;
}

void
xqc_client_request_closing_notify(xqc_h3_request_t *h3_request, 
    xqc_int_t err, void *h3s_user_data)
{
    user_stream_t *user_stream = (user_stream_t *)h3s_user_data;

    printf("***** request closing notify triggered\n");
}

void
xqc_client_socket_write_handler(user_conn_t *user_conn)
{
    DEBUG
    client_ctx_t *p_ctx;
    if (g_test_qch_mode) {
        p_ctx = user_conn->ctx;
    } else {
        p_ctx = &ctx;
    }
    xqc_conn_continue_send(p_ctx->engine, &user_conn->cid);
}


void
xqc_client_socket_read_handler(user_conn_t *user_conn, int fd)
{
    //DEBUG;

    xqc_int_t ret;
    ssize_t recv_size = 0;
    ssize_t recv_sum = 0;
    uint64_t path_id = XQC_UNKNOWN_PATH_ID;
    xqc_user_path_t *path;
    int i;

    client_ctx_t *p_ctx;
    if (g_test_qch_mode) {
        p_ctx = user_conn->ctx;
    } else {
        p_ctx = &ctx;
    }

    for (i = 0; i < g_multi_interface_cnt; i++) {
        path = &g_client_path[i];
        if (path->path_fd == fd || path->rebinding_path_fd == fd) {
            path_id = path->path_id;
        }
    }

#ifdef __linux__
    int batch = 0;
    if (batch) {
#define VLEN 100
#define BUFSIZE XQC_PACKET_TMP_BUF_LEN
#define TIMEOUT 10
        struct sockaddr_in6 pa[VLEN];
        struct mmsghdr msgs[VLEN];
        struct iovec iovecs[VLEN];
        char bufs[VLEN][BUFSIZE+1];
        struct timespec timeout;
        int retval;

        do {
            memset(msgs, 0, sizeof(msgs));
            for (int i = 0; i < VLEN; i++) {
                iovecs[i].iov_base = bufs[i];
                iovecs[i].iov_len = BUFSIZE;
                msgs[i].msg_hdr.msg_iov = &iovecs[i];
                msgs[i].msg_hdr.msg_iovlen = 1;
                msgs[i].msg_hdr.msg_name = &pa[i];
                msgs[i].msg_hdr.msg_namelen = user_conn->peer_addrlen;
            }

            timeout.tv_sec = TIMEOUT;
            timeout.tv_nsec = 0;

            retval = recvmmsg(fd, msgs, VLEN, 0, &timeout);
            if (retval == -1) {
                break;
            }

            uint64_t recv_time = xqc_now();
            for (int i = 0; i < retval; i++) {
                recv_sum += msgs[i].msg_len;

                ret = xqc_engine_packet_process(p_ctx->engine, iovecs[i].iov_base, msgs[i].msg_len,
                                              user_conn->local_addr, user_conn->local_addrlen,
                                              user_conn->peer_addr, user_conn->peer_addrlen,
                                              (xqc_usec_t)recv_time, user_conn);                                             
                if (ret != XQC_OK)
                {
                    printf("xqc_server_read_handler: packet process err, ret: %d\n", ret);
                    return;
                }
            }
        } while (retval > 0);
        goto finish_recv;
    }
#endif

    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];

    static ssize_t last_rcv_sum = 0;
    static ssize_t rcv_sum = 0;

    do {
        recv_size = recvfrom(fd,
                             packet_buf, sizeof(packet_buf), 0, 
                             user_conn->peer_addr, &user_conn->peer_addrlen);
        if (recv_size < 0 && get_sys_errno() == EAGAIN) {
            break;
        }

        if (recv_size < 0) {
            printf("recvfrom: recvmsg = %zd(%s)\n", recv_size, strerror(get_sys_errno()));
            break;
        }

        /* if recv_size is 0, break while loop, */
        if (recv_size == 0) {
            break;
        }

        recv_sum += recv_size;
        rcv_sum += recv_size;

        if (user_conn->get_local_addr == 0) {
            user_conn->get_local_addr = 1;
            socklen_t tmp = sizeof(struct sockaddr_in6);
            int ret = getsockname(user_conn->fd, (struct sockaddr *) user_conn->local_addr, &tmp);
            if (ret < 0) {
                printf("getsockname error, errno: %d\n", get_sys_errno());
                break;
            }
            user_conn->local_addrlen = tmp;
        }

        uint64_t recv_time = xqc_now();
        g_last_sock_op_time = recv_time;


        if (TEST_DROP) continue;

        if (g_test_case == 6) { /* socket recv fail */
            g_test_case = -1;
            break;
        }

        if (g_test_case == 8) { /* packet with wrong cid */
            g_test_case = -1;
            recv_size = sizeof(XQC_TEST_SHORT_HEADER_PACKET_A) - 1;
            memcpy(packet_buf, XQC_TEST_SHORT_HEADER_PACKET_A, recv_size);
        }

        static char copy[XQC_PACKET_TMP_BUF_LEN];

        if (g_test_case == 9) { /* duplicate packet */
            memcpy(copy, packet_buf, recv_size);
            again:;
        }

        if (g_test_case == 10) { /* illegal packet */
            g_test_case = -1;
            recv_size = sizeof(XQC_TEST_SHORT_HEADER_PACKET_B) - 1;
            memcpy(packet_buf, XQC_TEST_SHORT_HEADER_PACKET_B, recv_size);
        }

        /* amplification limit */
        if (g_test_case == 25) {
            static int loss_num = 0;
            loss_num++;
            /* continuous loss to make server at amplification limit */
            if (loss_num >= 1 && loss_num <= 10) {
                continue;
            }
        }

        ret = xqc_engine_packet_process(p_ctx->engine, packet_buf, recv_size,
                                      user_conn->local_addr, user_conn->local_addrlen,
                                      user_conn->peer_addr, user_conn->peer_addrlen,
                                      (xqc_usec_t)recv_time, user_conn);                                     
        if (ret != XQC_OK) {
            printf("xqc_client_read_handler: packet process err, ret: %d\n", ret);
            return;
        }

        if (g_test_case == 9) { /* duplicate packet */
            g_test_case = -1;
            memcpy(packet_buf, copy, recv_size);
            goto again;
        }

    } while (recv_size > 0);

    if ((xqc_now() - last_recv_ts) > 200000) {
        // mpshell
        // printf("recving rate: %.3lf Kbps\n", (rcv_sum - last_rcv_sum) * 8.0 * 1000 / (xqc_now() - last_recv_ts));
        last_recv_ts = xqc_now();
        last_rcv_sum = rcv_sum;
    }

finish_recv:
    // mpshell: 批量测试，无需打印
    // printf("recvfrom size:%zu\n", recv_sum);
    xqc_engine_finish_recv(p_ctx->engine);
}


static void
xqc_client_socket_event_callback(int fd, short what, void *arg)
{
    //DEBUG;
    user_conn_t *user_conn = (user_conn_t *) arg;

    if (what & EV_WRITE) {
        xqc_client_socket_write_handler(user_conn);

    } else if (what & EV_READ) {
        xqc_client_socket_read_handler(user_conn, fd);

    } else {
        printf("event callback: what=%d\n", what);
        exit(1);
    }
}


static void
xqc_client_engine_callback(int fd, short what, void *arg)
{
    // mpshell: 批量测试，无需打印
    // printf("engine timer wakeup now:%"PRIu64"\n", xqc_now());
    client_ctx_t *ctx = (client_ctx_t *) arg;

    xqc_engine_main_logic(ctx->engine);
}

static void
xqc_client_abs_timeout_callback(int fd, short what, void *arg)
{
    user_conn_t *user_conn = (user_conn_t *) arg;
    int rc;
    printf("[qperf]|ts:%"PRIu64"|test_end|\n", xqc_now());
    printf("xqc_client_abs_timeout_callback | forced conn_close\n");
    rc = xqc_conn_close(ctx.engine, &user_conn->cid);
    if (rc) {
        printf("xqc_conn_close error\n");
        return;
    }
}

static void
xqc_client_bytestream_timeout_callback(int fd, short what, void *arg)
{
    user_stream_t *user_stream = (user_stream_t *) arg;
    int rc = 0;
    printf("xqc_client_bytestream_timeout_callback\n");
    if (user_stream->send_offset >= (user_stream->send_body_len)) {
        rc = 1;
    }
    if (g_test_case == 304) {
        if (rc == 1) {
            printf("xqc_client_bytestream_timeout_callback send fin\n");
            xqc_h3_ext_bytestream_finish(user_stream->h3_ext_bs);
        } else {
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 100000;
            event_add(user_stream->ev_bytestream_timer, &tv);
        }
        
    } else if (g_test_case == 305) {
        if (rc == 1) {
            printf("xqc_client_bytestream_timeout_callback close stream\n");
            xqc_h3_ext_bytestream_close(user_stream->h3_ext_bs);
        } else {
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 100000;
            event_add(user_stream->ev_bytestream_timer, &tv);
        }
    }
}

static void xqc_client_timeout_multi_process_callback(int fd, short what, void *arg)
{
    user_conn_t *user_conn = (user_conn_t *) arg;
    int rc;
    client_ctx_t *ctx = user_conn->ctx;

    rc = xqc_conn_close(ctx->engine, &user_conn->cid);
    if (rc) {
        printf("xqc_conn_close error\n");
        return;
    }
    ctx->cur_conn_num--;

    printf("xqc_conn_close, %d connetion rest\n", ctx->cur_conn_num);
}

static void
xqc_client_request_callback(int fd, short what, void *arg)
{
    user_conn_t *user_conn = (user_conn_t *) arg;
    int rc;
    client_ctx_t *ctx = user_conn->ctx;

    printf("--- xqc_client_request_callback\n");

    user_stream_t *user_stream = calloc(1, sizeof(user_stream_t));
    user_stream->user_conn = user_conn;
    if (user_conn->h3 == 0 || user_conn->h3 == 2) {
        user_stream->h3_request = xqc_h3_request_create(ctx->engine, &user_conn->cid, NULL, user_stream);
        if (user_stream->h3_request == NULL) {
            printf("xqc_h3_request_create error\n");
            return;
        }

        xqc_client_request_send(user_stream->h3_request, user_stream);
    }

    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    int ret = event_add(user_conn->ev_request, &tv);
}

static void
xqc_client_timeout_callback(int fd, short what, void *arg)
{
    // mpshell
    // printf("xqc_client_timeout_callback now %"PRIu64"\n", xqc_now());
    user_conn_t *user_conn = (user_conn_t *) arg;
    int rc;
    static int restart_after_a_while = 1;

    /* write to eval file */
    /*{
        FILE* fp = NULL;
        fp = fopen("eval_result.txt", "a+");
        if (fp == NULL) {
            exit(1);
        }

        fprintf(fp, "recv_size: %u; cost_time: %u\n", 11, 60 * 1000);
        fclose(fp);

    }*/

    if (xqc_now() - g_last_sock_op_time < (uint64_t)g_conn_timeout * 1000000) {
        struct timeval tv;
        tv.tv_sec = g_conn_timeout;
        tv.tv_usec = 0;
        event_add(user_conn->ev_timeout, &tv);
        return;
    }

    //Test case 15: testing restart from idle
    if (restart_after_a_while && g_test_case == 15) {
        restart_after_a_while--;
        //we don't care the memory leak caused by user_stream. It's just for one-shot testing. :D
        user_stream_t *user_stream = calloc(1, sizeof(user_stream_t));
        memset(user_stream, 0, sizeof(user_stream_t));
        user_stream->user_conn = user_conn;
        printf("gtest 15: restart from idle!\n");
        user_stream->stream = xqc_stream_create(ctx.engine, &(user_conn->cid), NULL, user_stream);
        if (user_stream->stream == NULL) {
            printf("xqc_stream_create error\n");
            goto conn_close;
        }
        xqc_client_stream_send(user_stream->stream, user_stream);
        struct timeval tv;
        tv.tv_sec = g_conn_timeout;
        tv.tv_usec = 0;
        event_add(user_conn->ev_timeout, &tv);
        printf("scheduled a new stream request\n");
        return;
    }

conn_close:
    if (g_send_dgram && g_echo_check) {
        if (g_test_case == 206 && g_no_crypt) {
            // swap the first & 2nd dgram
            printf("%zu %zu\n", dgram1_size, dgram2_size);
            if (dgram1_size && dgram2_size) {
                //printf("%x %x\n", user_conn->dgram_blk->recv_data[0], user_conn->dgram_blk->recv_data[dgram1_size]);
                memcpy(sock_op_buffer, user_conn->dgram_blk->recv_data, dgram1_size);
                memmove(user_conn->dgram_blk->recv_data, user_conn->dgram_blk->recv_data + dgram1_size, dgram2_size);
                memcpy(user_conn->dgram_blk->recv_data + dgram2_size, sock_op_buffer, dgram1_size);
            }
        }
        printf("[dgram]|echo_check|same_content:%s|\n", !memcmp(user_conn->dgram_blk->data, user_conn->dgram_blk->recv_data, user_conn->dgram_blk->data_len) ? "yes" : "no");
    }
    printf("xqc_client_timeout_callback | conn_close\n");
    g_timeout_flag = 1;
    rc = xqc_conn_close(ctx.engine, &user_conn->cid);
    if (rc) {
        printf("xqc_conn_close error\n");
        return;
    }
    //event_base_loopbreak(eb);
}


static void
xqc_client_path_callback(int fd, short what, void *arg)
{
    printf("***** on_path_debug_callback\n");
    user_conn_t *user_conn = (user_conn_t *) arg;

    // 判断conn状态
    // TODO
    if (g_test_case == 110) {
        g_test_case = -1;
    }

    int b_add_path = 0;

    for (int i = 0; i < g_multi_interface_cnt; i++) {
        if (g_client_path[i].is_in_used == 1) {
            continue;
        }
        b_add_path = 1;
        
        uint64_t path_id = 0;
        int ret = xqc_conn_create_path(ctx.engine, &(user_conn->cid), &path_id, 0);
        
        if (ret < 0) {
            printf("not support mp, xqc_conn_create_path err = %d\n", ret);
            xqc_client_set_path_debug_timer(user_conn);
            return;
        }

        printf("***** create a new path. index: %d, path_id: %" PRIu64 "\n", i, path_id);
        g_client_path[i].path_id = path_id;
        g_client_path[i].path_seq = i;
        g_client_path[i].is_in_used = 1;
        xqc_test_cli_log_path_map(&g_client_path[i]);

        xqc_engine_main_logic(ctx.engine);
        xqc_client_set_path_debug_timer(user_conn);
    }

    if (b_add_path == 0) {
        static int base = 0;
        int path_index = rand() % 2;
        base++;
        printf("***** remove a path. index: %d, path_id: %" PRIu64 ". now:%"PRIu64"\n", 
            path_index, g_client_path[path_index].path_id, xqc_now());
        xqc_conn_close_path(ctx.engine, &user_conn->cid, g_client_path[path_index].path_id);
        xqc_engine_main_logic(ctx.engine);
        // printf("***** finish call. now:%"PRIu64"\n", xqc_now());
    }
}

static void 
xqc_client_epoch_callback(int fd, short what, void *arg)
{
    user_conn_t *user_conn = (user_conn_t *) arg;
    int ret;

    g_cur_epoch++;
    printf("|xqc_client_epoch_callback|epoch:%d|\n", g_cur_epoch);

    if (g_send_dgram) {
        if (user_conn->h3 == 1) {
            xqc_client_datagram_send(user_conn);

        } else if (user_conn->h3 == 2) {
            xqc_client_h3_ext_datagram_send(user_conn);
        }

    } else {
        for (int i = 0; i < g_req_paral; i++) {
            g_req_cnt++;
            user_stream_t *user_stream = calloc(1, sizeof(user_stream_t));
            user_stream->user_conn = user_conn;
            user_stream->last_recv_log_time = xqc_now();
            user_stream->recv_log_bytes = 0;
            if (user_conn->h3 == 0 || user_conn->h3 == 2) {
                user_stream->h3_request = xqc_h3_request_create(ctx.engine, &user_conn->cid, NULL, user_stream);
                if (user_stream->h3_request == NULL) {
                    printf("xqc_h3_request_create error\n");
                    continue;
                }
                xqc_client_request_send(user_stream->h3_request, user_stream);
            } else {
                user_stream->stream = xqc_stream_create(ctx.engine, &user_conn->cid, NULL, user_stream);
                if (user_stream->stream == NULL) {
                    printf("xqc_stream_create error\n");
                    continue;
                }
                xqc_client_stream_send(user_stream->stream, user_stream);
            }
        }
    }

    if (g_mp_ping_on) {
        if (user_conn->h3 == 1) {
            xqc_conn_send_ping(ctx.engine, &user_conn->cid, NULL);
            xqc_conn_send_ping(ctx.engine, &user_conn->cid, &g_ping_id);

        } else {
            xqc_h3_conn_send_ping(ctx.engine, &user_conn->cid, NULL);
            xqc_h3_conn_send_ping(ctx.engine, &user_conn->cid, &g_ping_id);
        }
    }

    if (g_test_case == 107 && !g_recovery) {
        /* freeze the first path */
        ret = xqc_conn_mark_path_frozen(ctx.engine, &(user_conn->cid), 0);
        if (ret < 0) {
            printf("xqc_conn_mark_path_frozen err = %d\n", ret);
        }
        g_recovery = g_cur_epoch + 2;
    }

    if (g_test_case == 108 && !g_recovery) {
        /* freeze the second path */
        ret = xqc_conn_mark_path_frozen(ctx.engine, &(user_conn->cid), 1);
        if (ret < 0) {
            printf("xqc_conn_mark_path_frozen err = %d\n", ret);
        }
        g_recovery = g_cur_epoch + 2;
    }

    if (g_test_case == 107 && g_recovery == g_cur_epoch) {
        g_test_case = -1;
        /* freeze the first path */
        ret = xqc_conn_mark_path_standby(ctx.engine, &(user_conn->cid), 0);
        if (ret < 0) {
            printf("xqc_conn_mark_path_standby err = %d\n", ret);
        }
    }

    if (g_test_case == 108 && g_recovery == g_cur_epoch) {
        g_test_case = -1;
        /* freeze the second path */
        ret = xqc_conn_mark_path_standby(ctx.engine, &(user_conn->cid), 1);
        if (ret < 0) {
            printf("xqc_conn_mark_path_standby err = %d\n", ret);
        }
    }

        /* close initial path */
    if (g_test_case == 100 && g_cur_epoch > 3) {
        xqc_conn_close_path(ctx.engine, &user_conn->cid, 0);
    }

    /* close new path */
    if (g_test_case == 101 && g_cur_epoch > 3) {
        xqc_conn_close_path(ctx.engine, &user_conn->cid, 1);
    }

    /* close all path */
    if (g_test_case == 102 && g_cur_epoch > 3) {
        xqc_conn_close_path(ctx.engine, &user_conn->cid, 1);
        xqc_conn_close_path(ctx.engine, &user_conn->cid, 0);
    }

    if (g_cur_epoch < g_epoch) {
        struct timeval tv;
        tv.tv_sec = g_epoch_timeout / 1000000;
        tv.tv_usec = g_epoch_timeout % 1000000;
        event_add(user_conn->ev_epoch, &tv);
    }
    
    return;
}

int
xqc_client_open_log_file(void *engine_user_data)
{
    client_ctx_t *ctx = (client_ctx_t*)engine_user_data;
    //ctx->log_fd = open("/home/jiuhai.zjh/ramdisk/clog", (O_WRONLY | O_APPEND | O_CREAT), 0644);
    ctx->log_fd = open(g_log_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->log_fd <= 0) {
        return -1;
    }
    return 0;
}

int
xqc_client_close_log_file(void *engine_user_data)
{
    client_ctx_t *ctx = (client_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        return -1;
    }
    close(ctx->log_fd);
    return 0;
}


void 
xqc_client_write_log(xqc_log_level_t lvl, const void *buf, size_t count, void *engine_user_data)
{
    unsigned char log_buf[XQC_MAX_LOG_LEN + 1];

    client_ctx_t *ctx = (client_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        printf("xqc_client_write_log fd err\n");
        return;
    }

    int log_len = snprintf(log_buf, XQC_MAX_LOG_LEN + 1, "%s\n", (char *)buf);
    if (log_len < 0) {
        printf("xqc_client_write_log err\n");
        return;
    }

    int write_len = write(ctx->log_fd, log_buf, log_len);
    if (write_len < 0) {
        printf("write log failed, errno: %d\n", errno);
    }
}

void 
xqc_client_write_qlog(qlog_event_importance_t imp, const void *buf, size_t count, void *engine_user_data)
{
    unsigned char log_buf[XQC_MAX_LOG_LEN + 1];

    client_ctx_t *ctx = (client_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        printf("xqc_client_write_qlog fd err\n");
        return;
    }

    int log_len = snprintf(log_buf, XQC_MAX_LOG_LEN + 1, "%s\n", (char *)buf);
    if (log_len < 0) {
        printf("xqc_client_write_qlog err\n");
        return;
    }

    int write_len = write(ctx->log_fd, log_buf, log_len);
    if (write_len < 0) {
        printf("write qlog failed, errno: %d\n", errno);
    }
}


/**
 * key log functions
 */

int
xqc_client_open_keylog_file(client_ctx_t *ctx)
{
    ctx->keylog_fd = open("./ckeys.log", (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->keylog_fd <= 0) {
        return -1;
    }

    return 0;
}

int
xqc_client_close_keylog_file(client_ctx_t *ctx)
{
    if (ctx->keylog_fd <= 0) {
        return -1;
    }

    close(ctx->keylog_fd);
    ctx->keylog_fd = 0;
    return 0;
}


void 
xqc_keylog_cb(const xqc_cid_t *scid, const char *line, void *user_data)
{
    client_ctx_t *ctx = (client_ctx_t*)user_data;
    if (ctx->keylog_fd <= 0) {
        printf("write keys error!\n");
        return;
    }

    printf("scid:%s\n", xqc_scid_str(ctx->engine, scid));

    int write_len = write(ctx->keylog_fd, line, strlen(line));
    if (write_len < 0) {
        printf("write keys failed, errno: %d\n", errno);
        return;
    }

    write_len = write(ctx->keylog_fd, "\n", 1);
    if (write_len < 0) {
        printf("write keys failed, errno: %d\n", errno);
    }
}


int 
xqc_client_cert_verify(const unsigned char *certs[], 
    const size_t cert_len[], size_t certs_len, void *conn_user_data)
{
    /* self-signed cert used in test cases, return >= 0 means success */
    return 0;
}

void 
xqc_client_ready_to_create_path(const xqc_cid_t *cid, 
    void *conn_user_data)
{
    printf("***** on_ready_to_create_path\n");
    uint64_t path_id = 0;
    user_conn_t *user_conn = (user_conn_t *) conn_user_data;

    if (!g_enable_multipath) {
        return;
    }

    if (g_test_case != 110) {
        for (int i = 0; i < g_multi_interface_cnt; i++) {
            if (g_client_path[i].is_in_used == 1) {
                continue;
            }
        
            int ret = xqc_conn_create_path(ctx.engine, &(user_conn->cid), &path_id, 0);

            if (ret < 0) {
                printf("not support mp, xqc_conn_create_path err = %d\n", ret);
                return;
            }

            printf("***** create a new path. index: %d, path_id: %" PRIu64 "\n", i, path_id);
            g_client_path[i].path_id = path_id;
            g_client_path[i].path_seq = i;
            g_client_path[i].is_in_used = 1;
            xqc_test_cli_log_path_map(&g_client_path[i]);

            if (g_test_case == 104) {
                ret = xqc_conn_mark_path_standby(ctx.engine, &(user_conn->cid), 0);
                if (ret < 0) {
                    printf("xqc_conn_mark_path_standby err = %d\n", ret);
                }
                ret = xqc_conn_mark_path_available(ctx.engine, &(user_conn->cid), 1);
                if (ret < 0) {
                    printf("xqc_conn_mark_path_available err = %d\n", ret);
                }
            }

            if (g_mp_backup_mode || g_enable_fec) {
                ret = xqc_conn_mark_path_standby(ctx.engine, &(user_conn->cid), path_id);
                if (ret < 0) {
                    printf("xqc_conn_mark_path_standby err = %d\n", ret);
                }
            }

            xqc_client_set_path_debug_timer(user_conn);

        }
        
    } else {
        xqc_client_set_path_debug_timer(user_conn);
    }
}




static void
xqc_client_create_req_callback(int fd, short what, void *arg)
{
    user_conn_t *user_conn = (user_conn_t *)arg;
    if (user_conn->cur_stream_num < g_req_paral) {
        int i = 0;
        for (i = 0; i < g_req_per_time; i++) {
            user_stream_t *user_stream = calloc(1, sizeof(user_stream_t));
            //user_stream_t * user_stream = client_create_user_stream(user_conn->ctx->engine, user_conn, &user_conn->cid);
            if (user_stream == NULL) {
                printf("error create user_stream\n");
                return;
            }

            if (user_conn->h3 == 0 || user_conn->h3 == 2) {
                user_stream->h3_request = xqc_h3_request_create(user_conn->ctx->engine, &user_conn->cid, NULL, user_stream);
                if (user_stream->h3_request == NULL) {
                    printf("xqc_h3_request_create error\n");
                    free(user_stream);
                    continue;
                }
            }
            user_stream->user_conn = user_conn;
            xqc_client_request_send(user_stream->h3_request, user_stream);
            user_conn->cur_stream_num++;
            if (user_conn->cur_stream_num >= g_req_paral) {
                break;
            }
        }
    }
    if (user_conn->cur_stream_num < g_req_paral) {
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        event_add(user_conn->ev_request, &tv);
    }
}

static void xqc_client_concurrent_callback(int fd, short what, void *arg){
    client_ctx_t *ctx = (client_ctx_t *)arg;
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = (1000000/g_conn_num );
    int i = 0;

    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs = {
            .h3_conn_create_notify = xqc_client_h3_conn_create_notify,
            .h3_conn_close_notify = xqc_client_h3_conn_close_notify,
            .h3_conn_handshake_finished = xqc_client_h3_conn_handshake_finished,
            .h3_conn_ping_acked = xqc_client_h3_conn_ping_acked_notify,
        },
        .h3r_cbs = {
            .h3_request_close_notify = xqc_client_request_close_notify,
            .h3_request_read_notify = xqc_client_request_read_notify,
            .h3_request_write_notify = xqc_client_request_write_notify,
            .h3_request_closing_notify = xqc_client_request_closing_notify,
        }
    };

    /* init http3 context */
    int ret = xqc_h3_ctx_init(ctx->engine, &h3_cbs);
    if (ret != XQC_OK) {
        printf("init h3 context error, ret: %d\n", ret);
        return;
    }

    /* register transport callbacks */
    xqc_app_proto_callbacks_t ap_cbs = {
        .conn_cbs = {
            .conn_create_notify = xqc_client_conn_create_notify,
            .conn_close_notify = xqc_client_conn_close_notify,
            .conn_handshake_finished = xqc_client_conn_handshake_finished,
            .conn_ping_acked = xqc_client_conn_ping_acked_notify,
        },
        .stream_cbs = {
            .stream_write_notify = xqc_client_stream_write_notify,
            .stream_read_notify = xqc_client_stream_read_notify,
            .stream_close_notify = xqc_client_stream_close_notify,
        }
    };

    xqc_engine_register_alpn(ctx->engine, XQC_ALPN_TRANSPORT, 9, &ap_cbs, NULL);


    if (g_conn_count < g_max_conn_num) {
        event_add(ctx->ev_conc, &tv);
        user_conn_t *user_conn = xqc_client_user_conn_multi_process_create(ctx, g_server_addr, g_server_port, g_transport);
        
        if (user_conn == NULL) {
            printf("xqc_client_user_conn_multi_process_create error\n");
            return;
        }
        if (g_token_len > 0){
            user_conn->token = g_token;
            user_conn->token_len = g_token_len;
        }

        xqc_conn_ssl_config_t conn_ssl_config;
        memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));

        if (g_verify_cert) {
            conn_ssl_config.cert_verify_flag |= XQC_TLS_CERT_FLAG_NEED_VERIFY;
            if (g_verify_cert_allow_self_sign) {
                conn_ssl_config.cert_verify_flag |= XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;
            }
        }

        conn_ssl_config.session_ticket_data = NULL;
        conn_ssl_config.transport_parameter_data = NULL;

        const xqc_cid_t *cid;
        if (user_conn->h3 == 0) {
            cid = xqc_h3_connect(ctx->engine, g_conn_settings, user_conn->token, user_conn->token_len,
                             g_host, g_no_crypt, &conn_ssl_config, user_conn->peer_addr, 
                             user_conn->peer_addrlen, user_conn);
        } else if (user_conn->h3 == 2) {
            cid = xqc_connect(ctx->engine, g_conn_settings, user_conn->token, user_conn->token_len,
                             g_host, g_no_crypt, &conn_ssl_config, user_conn->peer_addr, 
                             user_conn->peer_addrlen, XQC_DEFINED_ALPN_H3_EXT, user_conn);
        } else {
            cid = xqc_connect(ctx->engine, g_conn_settings, user_conn->token, user_conn->token_len,
                          "127.0.0.1", g_no_crypt, &conn_ssl_config, user_conn->peer_addr, 
                          user_conn->peer_addrlen, XQC_ALPN_TRANSPORT, user_conn);

            if (cid == NULL) {
                printf("xqc_connect error\n");
                return;
            }
        }
        g_conn_count++;
        ctx->cur_conn_num++;
        memcpy(&user_conn->cid, cid, sizeof(*cid));
          

        if (g_req_per_time) {
            user_conn->ev_request = event_new(ctx->eb, -1, 0, xqc_client_create_req_callback, user_conn);
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 500000;
            event_add(user_conn->ev_request, &tv);

        } else {
            while (user_conn->cur_stream_num < g_req_paral) {
        
                user_stream_t *user_stream = calloc(1, sizeof(user_stream_t));
                user_stream->user_conn = user_conn;
                if (user_conn->h3 == 0 || user_conn->h3 == 2) {
                    user_stream->h3_request = xqc_h3_request_create(ctx->engine, cid, NULL, user_stream);
                    if (user_stream->h3_request == NULL) {
                        printf("xqc_h3_request_create error\n");
                        continue;
                    }

                    xqc_client_request_send(user_stream->h3_request, user_stream);

                } 
                user_conn->cur_stream_num++;
            }
        }
    }
    return;
}


#define XQC_CID_ARRAY_SIZE 10
char * g_cid_array[XQC_CID_ARRAY_SIZE] = {"123","234","345","456","567","678","789","890","901","012"};

#define XQC_FIRST_OCTET 1
static ssize_t
xqc_qch_ddos_cid_generate(const xqc_cid_t *ori_cid, uint8_t *cid_buf, size_t cid_buflen, void *engine_user_data)
{

    ssize_t              cid_buf_index = 0, i;
    cid_buf[0] = 0;
    cid_buf_index += XQC_FIRST_OCTET;
    if (g_random_cid == 0) {
        memcpy(cid_buf + cid_buf_index, "123", 3);
        cid_buf_index += 3;
        return cid_buf_index;
    } else {
        if (g_random_cid > XQC_CID_ARRAY_SIZE) {
            g_random_cid = XQC_CID_ARRAY_SIZE;
        }
        int index = xqc_random()%g_random_cid;
        printf("%s\n", g_cid_array[index]);
        memcpy(cid_buf + cid_buf_index, g_cid_array[index], 3);
        cid_buf_index += 3;
        return cid_buf_index;
    }
}

xqc_int_t
xqc_client_set_fec_scheme(uint64_t in, xqc_fec_schemes_e *out)
{
    switch (in) {
    case XQC_REED_SOLOMON_CODE:
        *out = XQC_REED_SOLOMON_CODE;
        return XQC_OK;
    case XQC_XOR_CODE:
        *out = XQC_XOR_CODE;
        return XQC_OK;
    case XQC_PACKET_MASK_CODE:
        *out = XQC_PACKET_MASK_CODE;
        return XQC_OK;
    default:
        break;
    }

    return -XQC_EFEC_SCHEME_ERROR;
}


client_ctx_t * client_create_ctx(xqc_engine_ssl_config_t *engine_ssl_config,
    xqc_transport_callbacks_t *tcbs, xqc_config_t *config)
{
    client_ctx_t * ctx = malloc(sizeof(client_ctx_t));
    memset(ctx, 0, sizeof(client_ctx_t));
    
    xqc_client_open_keylog_file(ctx);
    xqc_client_open_log_file(ctx);

    xqc_engine_callback_t callback = {
        .set_event_timer = xqc_client_set_event_timer, /* call xqc_engine_main_logic when the timer expires */
        .log_callbacks = {
            .xqc_log_write_err = xqc_client_write_log,
            .xqc_log_write_stat = xqc_client_write_log,
            .xqc_qlog_event_write = xqc_client_write_qlog,
        },
        .keylog_cb = xqc_keylog_cb,
        .cid_generate_cb = xqc_qch_ddos_cid_generate, /* 设置cid 生产的回调函数 */
    };

    ctx->eb = event_base_new();

    if(ctx->eb == NULL){
        return NULL;
    }
    ctx->ev_engine = event_new(ctx->eb, -1, 0, xqc_client_engine_callback, ctx);
    if(ctx->ev_engine == NULL){
        return NULL;
    }
    ctx->ev_conc = event_new(ctx->eb, -1, 0, xqc_client_concurrent_callback, ctx);
    if(ctx->ev_conc == NULL){
        return NULL;
    }
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    event_add(ctx->ev_conc, &tv);

    ctx->engine = xqc_engine_create(XQC_ENGINE_CLIENT, config, engine_ssl_config,
                                   &callback, tcbs, ctx);

    if(ctx->engine == NULL){
        return NULL;
    }
    return ctx;
}



void usage(int argc, char *argv[]) {
    char *prog = argv[0];
    char *const slash = strrchr(prog, '/');
    if (slash) {
        prog = slash + 1;
    }
    printf(
"Usage: %s [Options]\n"
"\n"
"Options:\n"
"   -a    Server addr.\n"
"   -p    Server port.\n"
"   -P    Number of Parallel requests per single connection. Default 1.\n"
"   -n    Total number of requests to send. Defaults 1.\n"
"   -c    Congestion Control Algorithm. r:reno b:bbr c:cubic B:bbr2 bbr+ bbr2+ P:copa\n"
"   -C    Pacing on.\n"
"   -t    Connection timeout. Default 3 seconds.\n"
"   -T    Transport protocol: 0 H3 (default), 1 Transport layer, 2 H3-ext.\n"
"   -1    Force 1RTT.\n"
"   -s    Body size to send.\n"
"   -F    Abs_timeout to close conn. >=0.\n"
"   -w    Write received body to file.\n"
"   -r    Read sending body from file. priority s > r\n"
"   -l    Log level. e:error d:debug.\n"
"   -E    Echo check on. Compare sent data with received data.\n"
"   -d    Drop rate ‰.\n"
"   -u    Url. default https://test.xquic.com/path/resource\n"
"   -H    Header. eg. key:value\n"
"   -h    Host & sni. eg. test.xquic.com\n"
"   -G    GET on. Default is POST\n"
"   -x    Test case ID\n"
"   -N    No encryption\n"
"   -6    IPv6\n"
"   -M    Enable multi-path on. |\n"
"   -v    Multipath Version Negotiation.\n"
"   -i    Multi-path interface. e.g. -i interface1 -i interface2.\n"
"   -R    Enable reinjection. Default is 0, no reinjection.\n"
"   -V    Force cert verification. 0: don't allow self-signed cert. 1: allow self-signed cert.\n"
"   -q    name-value pair num of request header, default and larger than 6\n"
"   -o    Output log file path, default ./clog\n"
"   -f    Debug endless loop.\n"
"   -e    Epoch, default is 0.\n"
"   -D    Process num. default is 2.\n"
"   -b    Create connection per second. default is 100.\n"
"   -B    Max connection num. default is 1000.\n"
"   -J    Random CID. default is 0.\n"
"   -Q    Multipath backup path standby, set backup_mode on(1). default backup_mode is 0(off).\n"
"   -A    Multipath request accelerate on. default is 0(off).\n"
"   -y    multipath backup path standby.\n"
"   -z    periodically send request.\n"
"   -S    request per second.\n"
"   --scheduler             Multipath scheduler: minrtt|backup|rap|rr|roundrobin|red|redundant|copy|csma_copy|xlink|blest|interop|backup_fec.\n"
"   --wifi-monitor          Enable transport Wi-Fi monitor and CSV traces.\n"
"   --wifi-monitor-out      Output directory for eBPF Wi-Fi artifacts.\n"
"   --wifi-monitor-config   Config path for the Wi-Fi monitor runtime.\n"
, prog);
}

static void
xqc_test_client_signal_stop_handler(int signo)
{
    g_stop_signal = signo;
    g_stop_requested = 1;

    if (g_stop_event_base != NULL) {
        event_base_loopbreak(g_stop_event_base);
    } else if (eb != NULL) {
        event_base_loopbreak(eb);
    }
}

static void
xqc_test_client_install_stop_handlers(void)
{
    signal(SIGINT, xqc_test_client_signal_stop_handler);
    signal(SIGTERM, xqc_test_client_signal_stop_handler);
}

static void
xqc_test_client_log_stop_reason(void)
{
    if (!g_stop_requested) {
        return;
    }

    printf("[signal] received %s, leaving event loop for graceful cleanup\n",
           g_stop_signal == SIGTERM ? "SIGTERM" : "SIGINT");
    fflush(stdout);
}

int main(int argc, char *argv[]) {
    xqc_test_client_install_stop_handlers();

    g_req_cnt = 0;
    g_bytestream_cnt = 0;
    g_req_max = 1;
    g_send_body_size = 1024*1024;
    g_send_body_size_defined = 0;
    g_send_body_size_from_cdf = 0;
    cdf_list_size  = 0;
    cdf_list = NULL;
    g_save_body = 0;
    g_read_body = 0;
    g_echo_check = 0;
    g_drop_rate = 0;
    g_spec_url = 0;
    g_is_get = 0;
    g_test_case = 0;
    g_ipv6 = 0;
    g_no_crypt = 0;
    g_max_dgram_size = 0;
    g_send_dgram = 0;
    g_req_paral = 1;
    g_copa_ai = 1.0;
    g_copa_delta = 0.05;
    g_dgram_qos_level = XQC_DATA_QOS_HIGH;
    g_pmtud_on = 0;

    char server_addr[64] = TEST_SERVER_ADDR;
    g_server_addr = server_addr;
    int server_port = TEST_SERVER_PORT;
    char c_cong_ctl = 'b';
    char c_log_level = 'd';
    int c_cong_plus = 0;
    int pacing_on = 0;
    int transport = 0;
    int use_1rtt = 0;
    uint64_t rate_limit = 0;
    char conn_options[XQC_CO_STR_MAX_LEN] = {0};
    int g_close_red_redundancy = 0;
    xqc_fec_schemes_e fec_encoder_scheme = 11;
    xqc_fec_schemes_e fec_decoder_scheme = 11;
    uint8_t c_qlog_disable = 0;
    char c_qlog_importance = 'r';
    xqc_usec_t fec_timeout = 0;
    user_conn_t *user_conn = NULL;
    const xqc_cid_t *cid = NULL;
    int exit_code = 0;

    strcpy(g_log_path, "./clog");

    srand(0); //fix the random seed

    int long_opt_index;

    const struct option long_opts[] = {
        {"copa_delta", required_argument, &long_opt_index, 1},
        {"copa_ai_unit", required_argument, &long_opt_index, 2},
        {"epoch_timeout", required_argument, &long_opt_index, 3},
        {"dgram_qos", required_argument, &long_opt_index, 4},
        {"pmtud", required_argument, &long_opt_index, 5},
        {"mp_ping", required_argument, &long_opt_index, 6},
        {"rate_limit", required_argument, &long_opt_index, 7},
        {"conn_options", required_argument, &long_opt_index, 8},
        {"fec_encoder", required_argument, &long_opt_index, 9},
        {"fec_decoder", required_argument, &long_opt_index, 10},
        {"close_dg_red", required_argument, &long_opt_index, 11},
        {"qlog_disable", no_argument, &long_opt_index, 12},
        {"qlog_importance", required_argument, &long_opt_index, 13},
        {"fec_timeout", required_argument, &long_opt_index, 14},
        {"scheduler", required_argument, &long_opt_index, 15},
        {"wifi-monitor", no_argument, &long_opt_index, 16},
        {"wifi-monitor-out", required_argument, &long_opt_index, 17},
        {"wifi-monitor-config", required_argument, &long_opt_index, 18},
        {0, 0, 0, 0}
    };

    int ch = 0;
    while ((ch = getopt_long(argc, argv, "a:p:P:n:c:Ct:T:1s:w:r:l:Ed:u:H:h:Gx:6NMR:i:V:v:q:o:fe:F:D:b:B:J:Q:U:AyzS:g", long_opts, NULL)) != -1) {
        switch (ch) {
        case 'U':
            printf("option send_datagram 0 (off), 1 (on), 2(on + batch): %s\n", optarg);
            g_send_dgram = atoi(optarg);
            break;
        case 'Q':
            /* max_datagram_frame_size */
            printf("option max_datagram_frame_size: %s\n", optarg);
            g_max_dgram_size = atoi(optarg);
            break;
        case 'a': /* Server addr. */
            printf("option addr :%s\n", optarg);
            snprintf(server_addr, sizeof(server_addr), optarg);
            break;
        case 'p': /* Server port. */
            printf("option port :%s\n", optarg);
            server_port = atoi(optarg);
            g_server_port = server_port;
            break;
        case 'P': /* Number of Parallel requests per single connection. Default 1. */
            printf("option req_paral :%s\n", optarg);
            g_req_paral = atoi(optarg);
            break;
        case 'n': /* Total number of requests to send. Defaults 1. */
            printf("option req_max :%s\n", optarg);
            g_req_max = atoi(optarg);
            break;
        case 'c': /* Congestion Control Algorithm. r:reno b:bbr c:cubic B:bbr2 bbr+ bbr2+ P:copa */
            c_cong_ctl = optarg[0];
            if (strncmp("bbr2", optarg, 4) == 0) {
                c_cong_ctl = 'B';
            }

            if (strncmp("bbr2+", optarg, 5) == 0
                || strncmp("bbr+", optarg, 4) == 0)
            {
                c_cong_plus = 1;
            }
            printf("option cong_ctl : %c: %s: plus? %d\n", c_cong_ctl, optarg, c_cong_plus);
            break;
        case 'C': /* Pacing on */
            printf("option pacing :%s\n", "on");
            pacing_on = 1;
            break;
        case 't': /* Connection timeout. Default 3 seconds. */
            printf("option g_conn_timeout :%s\n", optarg);
            g_conn_timeout = atoi(optarg);
            break;
        case 'T': /* Transport layer. No HTTP3. */
            printf("option transport :%s\n", "on");
            transport = atoi(optarg);
            g_transport = transport;
            break;
        case '1': /* Force 1RTT. */
            printf("option 1RTT :%s\n", "on");
            use_1rtt = 1;
            break;
        case 's': /* Body size to send. */
            printf("option send_body_size :%s\n", optarg);
            if (xqc_test_cli_parse_size_arg(optarg, &g_send_body_size) != 0) {
                if (load_cdf(optarg) != -1) {
                    g_send_body_size_from_cdf = 1;
                } else {
                    printf("the cdf file of send_body_size does not exist: %s\n", optarg);
                    exit(0);
                }
            } else {
                g_send_body_size_defined = 1;
            }
            break;
        case 'F':
            printf("option abs_timeout to close conn:%s\n", optarg);
            g_conn_abs_timeout = atoi(optarg);
            if (g_conn_abs_timeout < 0) {
                printf("timeout must be positive!\n");
                exit(0);
            }
            break;
        case 'w': /* Write received body to file. */
            printf("option save body :%s\n", optarg);
            snprintf(g_write_file, sizeof(g_write_file), optarg);
            g_save_body = 1;
            break;
        case 'r': /* Read sending body from file. priority s > r */
            printf("option read body :%s\n", optarg);
            snprintf(g_read_file, sizeof(g_read_file), optarg);
            g_read_body = 1;
            break;
        case 'l': /* Log level. e:error d:debug. */
            printf("option log level :%s\n", optarg);
            c_log_level = optarg[0];
            break;
        case 'E': /* Echo check on. Compare sent data with received data. */
            printf("option echo check :%s\n", "on");
            g_echo_check = 1;
            break;
        case 'd': /* Drop rate ‰. */
            printf("option drop rate :%s\n", optarg);
            g_drop_rate = atoi(optarg);
            break;
        case 'u': /* Url. default https://test.xquic.com/path/resource */
            printf("option url :%s\n", optarg);
            snprintf(g_url, sizeof(g_url), optarg);
            g_spec_url = 1;
            sscanf(g_url, "%[^://]://%[^/]%s", g_scheme, g_host, g_url_path);
            break;
        case 'H': /* Header. eg. key:value */
            printf("option header :%s\n", optarg);
            snprintf(g_headers[g_header_cnt], sizeof(g_headers[g_header_cnt]), "%s", optarg);
            g_header_cnt++;
            break;
        case 'h': /* Host & sni. eg. test.xquic.com */
            printf("option host & sni :%s\n", optarg);
            snprintf(g_host, sizeof(g_host), optarg);
            break;
        case 'G': /* GET on. Default is POST */
            printf("option get :%s\n", "on");
            g_is_get = 1;
            break;
        case 'x': /* Test case ID */
            printf("option test case id: %s\n", optarg);
            g_test_case = atoi(optarg);
            break;
        case '6': /* IPv6 */
            printf("option IPv6 :%s\n", "on");
            g_ipv6 = 1;
            break;
        case 'N': /* No encryption */
            printf("option No crypt: %s\n", "yes");
            g_no_crypt = 1;
            break;
        case 'M':
            printf("option enable multi-path: %s\n", optarg);
            g_enable_multipath = 1;
            break;

        case 'v': /* Negotiate multipath version. 4: Multipath-04. 5: Multipath-05*/
            printf("option multipath version: %s\n", optarg);
            if (atoi(optarg) == 10) {
                g_multipath_version = XQC_MULTIPATH_10;
            }
            break;
        case 'R':
            printf("option enable reinjection: %s\n", "on");
            g_enable_reinjection = atoi(optarg);
            break;
        case 'i':
            printf("option multi-path interface: %s\n", optarg);
            memset(g_multi_interface[g_multi_interface_cnt], 0, XQC_DEMO_INTERFACE_MAX_LEN);
            snprintf(g_multi_interface[g_multi_interface_cnt], 
                        XQC_DEMO_INTERFACE_MAX_LEN, optarg);
            ++g_multi_interface_cnt;
            break;
        case 'V': /* Force cert verification. 0: don't allow self-signed cert. 1: allow self-signed cert. */
            printf("option enable cert verify: %s\n", "yes");
            g_verify_cert = 1;
            g_verify_cert_allow_self_sign = atoi(optarg);
            break;
        case 'q': /* name-value pair num of request header, default and larger than 6. */
            printf("option name-value pair num: %s\n", optarg);
            g_header_num = atoi(optarg);
            break;
        case 'o':
            printf("option log path :%s\n", optarg);
            snprintf(g_log_path, sizeof(g_log_path), optarg);
            break;
        case 'f':
            printf("option debug endless loop\n");
            g_debug_path = 1;
            g_conn_timeout = 5;
            break;
        case 'e':
            printf("option epoch: %s\n", optarg);
            g_epoch = atoi(optarg);
            break;
        case 'D':
            printf("process num:%s\n", optarg);
            g_process_num = atoi(optarg);
            g_test_qch_mode = 1; /* -D 开关用于测试qch */
            break;
        case 'b':
            printf("create connection per second :%s\n", optarg);
            g_conn_num = atoi(optarg);
            break;
        case 'B':
            printf("MAX connection num:%s\n", optarg);
            g_max_conn_num = atoi(optarg);
            break;
        case 'J':
            printf("random cid:%s\n", optarg);
            g_random_cid = atoi(optarg);
            break;
        case 'y':
            printf("option multipath backup path standby :%s\n", "on");
            g_mp_backup_mode = 1;
            break;
        case 'A':
            printf("option multipath request accelerate :%s\n", "on");
            g_mp_request_accelerate = 1;
            break;
        case 'z':
            printf("option periodically send request :%s\n", "on");
            g_periodically_request = 1;
            break;
        case 'S':
            printf("option stream per second:%s\n", optarg);
            g_req_per_time = atoi(optarg);
            break;
        case 'g':
            printf("option enable fec mode :on\n");
            g_enable_fec = 1;
            break;
        /* long options */
        case 0:

            switch (long_opt_index)
            {
            case 1: /* copa_delta */
                g_copa_delta = atof(optarg);
                if (g_copa_delta <= 0 || g_copa_delta > 0.5) {
                    printf("option g_copa_delta must be in (0, 0.5]\n");
                    exit(0);
                } else {
                    printf("option g_copa_delta: %.4lf\n", g_copa_delta);
                }
                break;

            case 2: /* copa_ai_unit */

                g_copa_ai = atof(optarg);
                if (g_copa_ai < 1.0) {
                    printf("option g_copa_ai must be greater than 1.0\n");
                    exit(0);
                } else {
                    printf("option g_copa_ai: %.4lf\n", g_copa_ai);
                }
                break;
            
            case 3:
                g_epoch_timeout = atoi(optarg);
                if (g_epoch_timeout <= 0) {
                    printf("invalid epoch_timeout!\n");
                    exit(0);
                } else {
                    printf("option g_epoch_timeout: %d\n", g_epoch_timeout);
                }
                break;

            case 4:
                g_dgram_qos_level = atoi(optarg);
                if (g_dgram_qos_level < XQC_DATA_QOS_HIGHEST || g_dgram_qos_level > XQC_DATA_QOS_LOWEST) {
                    printf("invalid qos level!\n");
                    exit(0);
                } else {
                    printf("option g_dgram_qos_level: %d\n", g_dgram_qos_level);
                }
                break;

            case 5:
                g_pmtud_on = atoi(optarg);
                printf("option g_pmtud_on: %d\n", g_pmtud_on);
                break;

            case 6:
                g_mp_ping_on = atoi(optarg);
                printf("option g_mp_ping_on: %d\n", g_mp_ping_on);
                break;

            case 7:
                rate_limit = atoi(optarg);
                printf("option rate_limit: %"PRIu64" Bps\n", rate_limit);
                break;

            case 8:
                strncpy(conn_options, optarg, XQC_CO_STR_MAX_LEN - 1);
                conn_options[XQC_CO_STR_MAX_LEN - 1] = '\0';
                printf("option conn_options: %s\n", conn_options);
                break;

            case 9:
                fec_encoder_scheme = atoi(optarg);
                printf("option fec_encoder_scheme: %d\n", fec_encoder_scheme);
                break;
            
            case 10:
                fec_decoder_scheme = atoi(optarg);
                printf("option fec_decoder_schemes: %d\n", fec_decoder_scheme);
                break;

            case 11:
                g_close_red_redundancy = atoi(optarg) ? 1 : 0;
                printf("option close dgram redundancy: %d\n", g_close_red_redundancy);
                break;

            case 12:
                c_qlog_disable = 1;
                printf("option disable qlog\n");
                break;
            
            case 13:
                c_qlog_importance = optarg[0];
                printf("option qlog importance :%s\n", optarg);
                break;

            case 14:
                fec_timeout = atoi(optarg);
                printf("option fec_timeout: %"PRId64"\n", fec_timeout);
                break;

            case 15:
                snprintf(g_scheduler_name, sizeof(g_scheduler_name), "%s", optarg);
                printf("option scheduler:%s\n", g_scheduler_name);
                break;

            case 16:
                g_enable_wifi_monitor = 1;
                printf("option enable wifi monitor:on\n");
                break;

            case 17:
                g_enable_wifi_monitor = 1;
                snprintf(g_wifi_monitor_output_dir, sizeof(g_wifi_monitor_output_dir), "%s", optarg);
                printf("option wifi monitor output dir:%s\n", g_wifi_monitor_output_dir);
                break;

            case 18:
                g_enable_wifi_monitor = 1;
                snprintf(g_wifi_monitor_config_path, sizeof(g_wifi_monitor_config_path), "%s", optarg);
                printf("option wifi monitor config:%s\n", g_wifi_monitor_config_path);
                break;

            default:
                break;
            }

            break;

        default:
            printf("other option :%c\n", ch);
            usage(argc, argv);
            exit(0);
        }

    }

    xqc_test_cli_apply_scheduler_side_effects(g_scheduler_name);

    if (!g_send_body_size_from_cdf && g_send_body_size > MAX_BUF_SIZE && g_transport != 1) {
        printf("send_body_size:%zu exceeds in-memory limit:%d; large bodies are only supported in transport mode\n",
               g_send_body_size, MAX_BUF_SIZE);
        exit(0);
    }

    if (!g_send_body_size_from_cdf && g_send_body_size > MAX_BUF_SIZE && g_echo_check) {
        printf("echo check does not support large send_body_size:%zu beyond in-memory limit:%d\n",
               g_send_body_size, MAX_BUF_SIZE);
        exit(0);
    }

    if (!g_send_body_size_from_cdf && g_send_body_size > MAX_BUF_SIZE && g_send_dgram) {
        printf("datagram mode does not support send_body_size:%zu beyond in-memory limit:%d\n",
               g_send_body_size, MAX_BUF_SIZE);
        exit(0);
    }
    
    memset(g_header_key, 'k', sizeof(g_header_key));
    memset(g_header_value, 'v', sizeof(g_header_value));
    memset(&ctx, 0, sizeof(ctx));

    xqc_client_open_keylog_file(&ctx);
    xqc_client_open_log_file(&ctx);

    g_token_len = xqc_client_read_token(g_token, XQC_MAX_TOKEN_LEN);
 
    xqc_platform_init_env();

    xqc_engine_ssl_config_t  engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));
    /* client does not need to fill in private_key_file & cert_file */
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;

    if (g_test_case == 27) {
        engine_ssl_config.ciphers = "TLS_CHACHA20_POLY1305_SHA256";
    }

    xqc_engine_callback_t callback = {
        .set_event_timer = xqc_client_set_event_timer, /* call xqc_engine_main_logic when the timer expires */
        .log_callbacks = {
            .xqc_log_write_err = xqc_client_write_log,
            .xqc_log_write_stat = xqc_client_write_log,
            .xqc_qlog_event_write = xqc_client_write_qlog,
        },
        .keylog_cb = xqc_keylog_cb,
    };

    xqc_transport_callbacks_t tcbs = {
        .write_socket = xqc_client_write_socket,
        .write_socket_ex = xqc_client_write_socket_ex,
        .save_token = xqc_client_save_token,
        .save_session_cb = save_session_cb,
        .save_tp_cb = save_tp_cb,
        .cert_verify_cb = xqc_client_cert_verify,
        .conn_update_cid_notify = xqc_client_conn_update_cid_notify,
        .ready_to_create_path_notify = xqc_client_ready_to_create_path,
        .path_removed_notify = xqc_client_path_removed,
        .conn_closing = xqc_client_conn_closing_notify,
    };

    xqc_cong_ctrl_callback_t cong_ctrl;
    uint32_t cong_flags = 0;
    if (c_cong_ctl == 'b') {
        cong_ctrl = xqc_bbr_cb;
        cong_flags = XQC_BBR_FLAG_NONE;
#if XQC_BBR_RTTVAR_COMPENSATION_ENABLED
        if (c_cong_plus) {
            cong_flags |= XQC_BBR_FLAG_RTTVAR_COMPENSATION;
        }
#endif
    }
#ifdef XQC_ENABLE_RENO
    else if (c_cong_ctl == 'r') {
        cong_ctrl = xqc_reno_cb;
    }
#endif
    else if (c_cong_ctl == 'c') {
        cong_ctrl = xqc_cubic_cb;
    }
#ifdef XQC_ENABLE_BBR2
    else if (c_cong_ctl == 'B') {
        cong_ctrl = xqc_bbr2_cb;
        cong_flags = XQC_BBR2_FLAG_NONE;
#if XQC_BBR2_PLUS_ENABLED
        if (c_cong_plus) {
            cong_flags |= XQC_BBR2_FLAG_RTTVAR_COMPENSATION;
            cong_flags |= XQC_BBR2_FLAG_FAST_CONVERGENCE;
        }
#endif
    }
#endif
#ifdef XQC_ENABLE_UNLIMITED
    else if (c_cong_ctl == 'u') {
        cong_ctrl = xqc_unlimited_cc_cb;

    }
#endif
#ifdef XQC_ENABLE_COPA
    else if (c_cong_ctl == 'P') {
        cong_ctrl = xqc_copa_cb;

    } 
#endif
    else {
        printf("unknown cong_ctrl, option is b, r, c, B, bbr+, bbr2+, u\n");
        return -1;
    }
    printf("congestion control flags: %x\n", cong_flags);

    xqc_conn_settings_t conn_settings = {
        .pacing_on  =   pacing_on,
        .ping_on    =   0,
        .cong_ctrl_callback = cong_ctrl,
        .cc_params  =   {
            .customize_on = 1, 
            .init_cwnd = 32, 
            .cc_optimization_flags = cong_flags, 
            .copa_delta_ai_unit = g_copa_ai, 
            .copa_delta_base = g_copa_delta,
        },
        .spurious_loss_detect_on = 0,
        .keyupdate_pkt_threshold = 0,
        .max_datagram_frame_size = g_max_dgram_size,
        .enable_multipath = g_enable_multipath,
        .enable_encode_fec = g_enable_fec,
        .enable_decode_fec = g_enable_fec,
        .multipath_version = g_multipath_version,
        .marking_reinjection = 1,
        .mp_ping_on = g_mp_ping_on,
        .recv_rate_bytes_per_sec = rate_limit,
        .close_dgram_redundancy = XQC_RED_NOT_USE
    };

    strncpy(conn_settings.conn_option_str, conn_options, XQC_CO_STR_MAX_LEN - 1);
    conn_settings.conn_option_str[XQC_CO_STR_MAX_LEN - 1] = '\0';

#ifdef XQC_PROTECT_POOL_MEM
    if (g_test_case == 600) {
        conn_settings.protect_pool_mem = 1;
    }
#endif

    xqc_stream_settings_t stream_settings = { .recv_rate_bytes_per_sec = 0 };

    if (g_test_case == 109) {
        conn_settings.enable_stream_rate_limit = 1;
        stream_settings.recv_rate_bytes_per_sec = 500000;
    }
    
    if (g_test_case == 400) {
        //low_delay
        conn_settings = xqc_conn_get_conn_settings_template(XQC_CONN_SETTINGS_LOW_DELAY);
    }

    if (g_pmtud_on) {
        conn_settings.enable_pmtud = 3;
    }

    if (g_test_case == 450) {
        conn_settings.extended_ack_features = 2;
        conn_settings.max_receive_timestamps_per_ack = 45;
        conn_settings.receive_timestamps_exponent = 0;
    }

    if (g_test_case == 451) {
        conn_settings.extended_ack_features = 0;
        conn_settings.max_receive_timestamps_per_ack = 40;
        conn_settings.receive_timestamps_exponent = 0;
    }

    if (g_test_case == 452) {
        conn_settings.extended_ack_features = 2;
        /* negotiation fail test, because max_receive_timestamps_per_ack > 63 */
        conn_settings.max_receive_timestamps_per_ack = 64;
        conn_settings.receive_timestamps_exponent = 0;
    }

    if (g_test_case == 453) {
        conn_settings.extended_ack_features = 2;
        conn_settings.max_receive_timestamps_per_ack = 0;
        conn_settings.receive_timestamps_exponent = 0;
    }

    conn_settings.pacing_on = pacing_on;
    conn_settings.proto_version = XQC_VERSION_V1;
    conn_settings.max_datagram_frame_size = g_max_dgram_size;
    conn_settings.enable_multipath = g_enable_multipath;

    if (g_test_case == 208) {
        conn_settings.datagram_redundancy = 1;
    }

    if (g_test_case == 209) {
        conn_settings.datagram_redundant_probe = 30000;
    }

    if (g_test_case == 210) {
        conn_settings.datagram_redundancy = 2;
    }

    if (g_test_case == 211) {
        conn_settings.datagram_redundancy = 2;
        conn_settings.datagram_redundant_probe = 30000;
    }

    g_conn_settings = &conn_settings;

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) < 0) {
        return -1;
    }


    if (transport == 2 && g_test_case != 315) {
        config.enable_h3_ext = 1;
    }

    switch(c_log_level) {
        case 'e': config.cfg_log_level = XQC_LOG_ERROR; break;
        case 'i': config.cfg_log_level = XQC_LOG_INFO; break;
        case 'w': config.cfg_log_level = XQC_LOG_WARN; break;
        case 's': config.cfg_log_level = XQC_LOG_STATS; break;
        case 'd': config.cfg_log_level = XQC_LOG_DEBUG; break;
        default: config.cfg_log_level = XQC_LOG_DEBUG;
    }

    if (c_qlog_disable) {
        config.cfg_log_event = 0;
    }
    switch(c_qlog_importance) {
        case 's': config.cfg_qlog_importance = EVENT_IMPORTANCE_SELECTED; break;
        case 'c': config.cfg_qlog_importance = EVENT_IMPORTANCE_CORE; break;
        case 'b': config.cfg_qlog_importance = EVENT_IMPORTANCE_BASE; break;
        case 'e': config.cfg_qlog_importance = EVENT_IMPORTANCE_EXTRA; break;
        case 'r': config.cfg_qlog_importance = EVENT_IMPORTANCE_REMOVED; break;
        default: config.cfg_qlog_importance = EVENT_IMPORTANCE_EXTRA;
    }
    
    /* test different cid_len */
    if (g_test_case == 13) {
        config.cid_len = XQC_MAX_CID_LEN;
    }

    /* check draft-29 version */
    if (g_test_case == 17) {
        conn_settings.proto_version = XQC_IDRAFT_VER_29;
    }

#if defined(XQC_SUPPORT_SENDMMSG) && !defined(XQC_SYS_WINDOWS)
    if (g_test_case == 20) { /* test sendmmsg */
        printf("test sendmmsg!\n");
        tcbs.write_mmsg = xqc_client_write_mmsg;
        tcbs.write_mmsg_ex = xqc_client_mp_write_mmsg;
        config.sendmmsg_on = 1;
    }
#endif

    if (g_test_case == 24) {
        conn_settings.idle_time_out = 10000;
    }

    /* test spurious loss detect */
    if (g_test_case == 26) {
        conn_settings.spurious_loss_detect_on = 1;
    }

    /* test key update */
    if (g_test_case == 40) {
        conn_settings.keyupdate_pkt_threshold = 30;
    }

    if (g_test_case == 42) {
        conn_settings.max_pkt_out_size = 1400;
    }

    if (g_test_case == 201) {
        conn_settings.max_pkt_out_size = 1216;
    }
    

    if (g_test_qch_mode) {
#ifndef XQC_SYS_WINDOWS
        pid_t pid;
        int i;
        for (i = 1; i < g_process_num; i++) {   
            pid = fork();
            if (pid < 0) {
                printf("error create process, current process num:%d, need create process:%d\n", i+1, g_process_num);
            } else if (pid == 0) {
                printf("Current Pid = %d , Parent Pid = %d\n", getpid(), getppid());
                break;
            } else {
                sleep(1);
            }
        }
#endif
        client_ctx_t * ctx = NULL;
        ctx = client_create_ctx(&engine_ssl_config, &tcbs, &config);

        if(ctx == NULL){
            printf("ctx create error\n");
            exit(0);
        }

        g_stop_event_base = ctx->eb;
        event_base_dispatch(ctx->eb);
        xqc_test_client_log_stop_reason();
        return 0;    
    }


    eb = event_base_new();
    g_stop_event_base = eb;

    ctx.ev_engine = event_new(eb, -1, 0, xqc_client_engine_callback, &ctx);

    if (g_test_case == 44) {
        // turn off the log switch
        xqc_log_disable(XQC_TRUE);
    }

    ctx.engine = xqc_engine_create(XQC_ENGINE_CLIENT, &config, &engine_ssl_config,
                                   &callback, &tcbs, &ctx);
    if (ctx.engine == NULL) {
        printf("xqc_engine_create error\n");
        return -1;
    }

    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs = {
            .h3_conn_create_notify = xqc_client_h3_conn_create_notify,
            .h3_conn_close_notify = xqc_client_h3_conn_close_notify,
            .h3_conn_handshake_finished = xqc_client_h3_conn_handshake_finished,
            .h3_conn_ping_acked = xqc_client_h3_conn_ping_acked_notify,
        },
        .h3r_cbs = {
            .h3_request_close_notify = xqc_client_request_close_notify,
            .h3_request_read_notify = xqc_client_request_read_notify,
            .h3_request_write_notify = xqc_client_request_write_notify,
            .h3_request_closing_notify = xqc_client_request_closing_notify,
        },
        .h3_ext_dgram_cbs = {
            .dgram_read_notify = xqc_client_h3_ext_datagram_read_callback,
            .dgram_write_notify = xqc_client_h3_ext_datagram_write_callback,
            .dgram_acked_notify = xqc_client_h3_ext_datagram_acked_callback,
            .dgram_lost_notify = xqc_client_h3_ext_datagram_lost_callback,
            .dgram_mss_updated_notify = xqc_client_h3_ext_datagram_mss_updated_callback,
        },
        .h3_ext_bs_cbs = {
            .bs_read_notify = xqc_h3_ext_bytestream_read_callback,
            .bs_write_notify = xqc_h3_ext_bytestream_write_callback,
            .bs_create_notify = xqc_h3_ext_bytestream_create_callback,
            .bs_close_notify = xqc_h3_ext_bytestream_close_callback,
        },
    };

    if (g_test_case == 502) {
        /* test h3 init settings callback */
        h3_cbs.h3c_cbs.h3_conn_init_settings = xqc_client_h3_conn_init_settings_notify;
    }

    /* init http3 context */
    int ret = xqc_h3_ctx_init(ctx.engine, &h3_cbs);
    if (ret != XQC_OK) {
        printf("init h3 context error, ret: %d\n", ret);
        return ret;
    }

    if (g_enable_wifi_monitor) {
        xqc_test_cli_open_aux_trace_files(&ctx);
        xqc_test_cli_init_monitoring(&ctx);
    }

    if (g_test_case == 18) { /* test h3 settings */
        xqc_h3_conn_settings_t settings = {
            .max_field_section_size = 512,
            .qpack_enc_max_table_capacity = 4096,
            .qpack_dec_max_table_capacity = 4096,
            .qpack_blocked_streams = 32,
        };
        xqc_h3_engine_set_local_settings(ctx.engine, &settings);
    }

    if (g_test_case == 32) {
        xqc_h3_conn_settings_t settings = {
            .max_field_section_size = 10000000,
            .qpack_enc_max_table_capacity = 4096,
            .qpack_dec_max_table_capacity = 4096,
            .qpack_blocked_streams = 32,
        };
        xqc_h3_engine_set_local_settings(ctx.engine, &settings);
    }

    if (g_test_case == 19) { /* test header size constraints */
        xqc_h3_conn_settings_t settings = {
            .max_field_section_size = 100,
        };
        xqc_h3_engine_set_local_settings(ctx.engine, &settings);
    }

    if (g_test_case == 152) {
        conn_settings.proto_version = XQC_IDRAFT_VER_29;
        g_test_case = 150;
    }

    if (g_test_case == 153) {
        conn_settings.proto_version = XQC_IDRAFT_VER_29;
        g_test_case = 151;      
    }

    /* modify h3 default settings */
    if (g_test_case == 150) {
        xqc_h3_engine_set_dec_max_dtable_capacity(ctx.engine, 4096);
        xqc_h3_engine_set_enc_max_dtable_capacity(ctx.engine, 4096);
        xqc_h3_engine_set_max_field_section_size(ctx.engine, 512);
        xqc_h3_engine_set_qpack_blocked_streams(ctx.engine, 32);
#ifdef XQC_COMPAT_DUPLICATE
        xqc_h3_engine_set_qpack_compat_duplicate(ctx.engine, 1);
#endif
    }

    if (g_test_case == 151) {
        xqc_h3_engine_set_max_dtable_capacity(ctx.engine, 4096);
        xqc_h3_engine_set_max_field_section_size(ctx.engine, 512);
        xqc_h3_engine_set_qpack_blocked_streams(ctx.engine, 32);
#ifdef XQC_COMPAT_DUPLICATE
        xqc_h3_engine_set_qpack_compat_duplicate(ctx.engine, 1);
#endif
    }

    /* register transport callbacks */
    xqc_app_proto_callbacks_t ap_cbs = {
        .conn_cbs = {
            .conn_create_notify = xqc_client_conn_create_notify,
            .conn_close_notify = xqc_client_conn_close_notify,
            .conn_handshake_finished = xqc_client_conn_handshake_finished,
            .conn_ping_acked = xqc_client_conn_ping_acked_notify,
        },
        .stream_cbs = {
            .stream_write_notify = xqc_client_stream_write_notify,
            .stream_read_notify = xqc_client_stream_read_notify,
            .stream_close_notify = xqc_client_stream_close_notify,
        },
        .dgram_cbs = {
            .datagram_write_notify = xqc_client_datagram_write_callback,
            .datagram_read_notify = xqc_client_datagram_read_callback,
            .datagram_acked_notify = xqc_client_datagram_acked_callback,
            .datagram_lost_notify = xqc_client_datagram_lost_callback,
            .datagram_mss_updated_notify = xqc_client_datagram_mss_updated_callback,
        }
    };

    xqc_engine_register_alpn(ctx.engine, XQC_ALPN_TRANSPORT, 9, &ap_cbs, NULL);
    /* test alpn negotiation failure */
    xqc_engine_register_alpn(ctx.engine, XQC_ALPN_TRANSPORT_TEST, 14, &ap_cbs, NULL);

    user_conn = xqc_client_user_conn_create(server_addr, server_port, transport);
    if (user_conn == NULL) {
        printf("xqc_client_user_conn_create error\n");
        exit_code = -1;
        goto cleanup_main;
    }
    user_conn->ctx = &ctx;

    if (g_enable_multipath) {

        if (g_multi_interface_cnt < 1) {
            printf("Error: multi-path requires one path interfaces or more.\n");
            exit_code = -1;
            goto cleanup_main;
        }

        conn_settings.enable_multipath = g_enable_multipath;
        for (int i = 0; i < g_multi_interface_cnt; ++i) {
            if (xqc_client_create_path(&g_client_path[i], g_multi_interface[i], user_conn) != XQC_OK) {
                printf("xqc_client_create_path %d error\n", i);
                exit_code = -1;
                goto cleanup_main;
            }
            g_client_path[i].path_seq = i;
        }

        // 权宜之计，，
        g_client_path[0].path_id = 0;
        g_client_path[0].path_seq = 0;
        g_client_path[0].is_in_used = 1;
        xqc_test_cli_log_path_map(&g_client_path[0]);
        user_conn->fd = g_client_path[0].path_fd;
    }
    else {
        ret = xqc_client_create_conn_socket(user_conn);
        if (ret != XQC_OK) {
            printf("conn create socket error, ret: %d\n", ret);
            exit_code = -1;
            goto cleanup_main;
        }
    }

    /* enable_reinjection */
    if (g_enable_reinjection == 1) {
        conn_settings.reinj_ctl_callback    = xqc_default_reinj_ctl_cb;
        conn_settings.mp_enable_reinjection = 1;

    } else if (g_enable_reinjection == 2) {
        conn_settings.reinj_ctl_callback    = xqc_deadline_reinj_ctl_cb;
        conn_settings.mp_enable_reinjection = 2;

    } else if (g_enable_reinjection == 3) {
        conn_settings.reinj_ctl_callback    = xqc_dgram_reinj_ctl_cb;
        conn_settings.mp_enable_reinjection = 4;
        conn_settings.scheduler_callback    = xqc_rap_scheduler_cb;
    } else if (g_enable_reinjection == 4) {
        conn_settings.reinj_ctl_callback    = xqc_dgram_reinj_ctl_cb;
        conn_settings.mp_enable_reinjection = 4;
        conn_settings.scheduler_callback    = xqc_rap_scheduler_cb;
        conn_settings.datagram_redundant_probe = 30000;
    }

    if (g_enable_fec) {
        xqc_fec_params_t fec_params;
        if (xqc_client_set_fec_scheme(fec_encoder_scheme, &fec_params.fec_encoder_schemes[0]) == XQC_OK) {
            fec_params.fec_encoder_schemes_num = 1;
            // limit repair number if fec scheme is xor
            fec_params.fec_code_rate = 0.1;
            fec_params.fec_max_symbol_num_per_block = 3;
            fec_params.fec_mp_mode = XQC_FEC_MP_USE_STB;
            conn_settings.fec_conn_queue_rpr_timeout = fec_timeout;

        } else {
            conn_settings.enable_encode_fec = 0;
        }

        if (xqc_client_set_fec_scheme(fec_decoder_scheme, &fec_params.fec_decoder_schemes[0]) == XQC_OK) {
            fec_params.fec_decoder_schemes_num = 1;

        } else {
            conn_settings.enable_decode_fec = 0;
        }
        
        if (g_test_case == 80) {
            fec_params.fec_code_rate = 1;
        }

        conn_settings.fec_params = fec_params;
    }

    if (g_mp_backup_mode) {
        conn_settings.scheduler_callback  = xqc_backup_scheduler_cb;
    }

    if (g_close_red_redundancy) {
        conn_settings.close_dgram_redundancy = XQC_RED_SET_CLOSE;
    }

    if (g_test_case == 501) {
        conn_settings.scheduler_callback = xqc_backup_scheduler_cb;
        conn_settings.mp_enable_reinjection = 0;
        conn_settings.standby_path_probe_timeout = 500;
    }

    if (g_enable_fec) {
        conn_settings.scheduler_callback = xqc_backup_fec_scheduler_cb;
    }

    if (g_scheduler_name[0] != '\0') {
        if (xqc_test_cli_apply_scheduler_name(g_scheduler_name, &conn_settings) != 0) {
            printf("unknown scheduler: %s\n", g_scheduler_name);
            return -1;
        }
    }

   if (g_token_len > 0) {
        user_conn->token = g_token;
        user_conn->token_len = g_token_len;
    }

    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));

    if (g_verify_cert) {
        conn_ssl_config.cert_verify_flag |= XQC_TLS_CERT_FLAG_NEED_VERIFY;
        if (g_verify_cert_allow_self_sign) {
            conn_ssl_config.cert_verify_flag |= XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;
        }
    }

    char session_ticket_data[8192]={0};
    char tp_data[8192] = {0};

    int session_len = read_file_data(session_ticket_data, sizeof(session_ticket_data), "test_session");
    int tp_len = read_file_data(tp_data, sizeof(tp_data), "tp_localhost");

    if (session_len < 0 || tp_len < 0 || use_1rtt) {
        printf("sessoin data read error or use_1rtt\n");
        conn_ssl_config.session_ticket_data = NULL;
        conn_ssl_config.transport_parameter_data = NULL;

    } else {
        conn_ssl_config.session_ticket_data = session_ticket_data;
        conn_ssl_config.session_ticket_len = session_len;
        conn_ssl_config.transport_parameter_data = tp_data;
        conn_ssl_config.transport_parameter_data_len = tp_len;
    }

    printf("conn type: %d\n", user_conn->h3);

    if (user_conn->h3 == 0) {
        if (g_test_case == 7) {user_conn->token_len = -1;} /* create connection fail */
        cid = xqc_h3_connect(ctx.engine, &conn_settings, user_conn->token, user_conn->token_len,
                             g_host, g_no_crypt, &conn_ssl_config, user_conn->peer_addr, 
                             user_conn->peer_addrlen, user_conn);
    } else if (user_conn->h3 == 2) {
        cid = xqc_connect(ctx.engine, &conn_settings, user_conn->token, user_conn->token_len,
                             g_host, g_no_crypt, &conn_ssl_config, user_conn->peer_addr, 
                             user_conn->peer_addrlen, XQC_DEFINED_ALPN_H3_EXT, user_conn);
    } else {
        if (g_test_case == 43) {
            /* try a alpn not supported by server */
            cid = xqc_connect(ctx.engine, &conn_settings, user_conn->token, user_conn->token_len,
                            server_addr, g_no_crypt, &conn_ssl_config, user_conn->peer_addr, 
                            user_conn->peer_addrlen, XQC_ALPN_TRANSPORT_TEST, user_conn);

        } else {
            cid = xqc_connect(ctx.engine, &conn_settings, user_conn->token, user_conn->token_len,
                            server_addr, g_no_crypt, &conn_ssl_config, user_conn->peer_addr, 
                            user_conn->peer_addrlen, XQC_ALPN_TRANSPORT, user_conn);
        }
    }

    if (cid == NULL) {
        printf("xqc_connect error\n");
        exit_code = -1;
        goto cleanup_main;
    }

    /* copy cid to its own memory space to prevent crashes caused by internal cid being freed */
    memcpy(&user_conn->cid, cid, sizeof(*cid));

    user_conn->dgram_blk = calloc(1, sizeof(user_dgram_blk_t));
    user_conn->dgram_blk->data_sent = 0;
    user_conn->dgram_blk->data_recv = 0;
    user_conn->dgram_blk->dgram_id = 1;
    if (user_conn->quic_conn) {
        printf("[dgram]|prepare_dgram_user_data|\n");
        xqc_datagram_set_user_data(user_conn->quic_conn, user_conn);
 
    }

    if (user_conn->h3_conn) {
        printf("[h3-dgram]|prepare_dgram_user_data|\n");
        xqc_h3_ext_datagram_set_user_data(user_conn->h3_conn, user_conn);
 
    }

    if (g_test_case == 501) {
        goto skip_data;
    }

    if (g_test_case >= 300 && g_test_case < 400 && user_conn->h3 == 2) {
        // for h3 bytestream testcases
        // send h3 requests
        if (g_test_case != 306 && g_test_case != 307 && g_test_case != 308 && g_test_case != 310
            && g_test_case != 311 && g_test_case != 312 && g_test_case != 313) 
        {
            for (int i = 0; i < g_req_paral; i++) {
                g_req_cnt++;
                user_stream_t *user_stream = calloc(1, sizeof(user_stream_t));
                user_stream->user_conn = user_conn;
                user_stream->last_recv_log_time = xqc_now();
                user_stream->recv_log_bytes = 0;
                user_stream->h3_request = xqc_h3_request_create(ctx.engine, cid, NULL, user_stream);
                if (user_stream->h3_request == NULL) {
                    printf("xqc_h3_request_create error\n");
                    continue;
                }

                xqc_client_request_send(user_stream->h3_request, user_stream);

            }
        }

        // open bytestreams and send data
        for (int i = 0; i < g_req_paral; i++) {
            g_bytestream_cnt++;
            user_stream_t *user_stream = calloc(1, sizeof(user_stream_t));
            user_stream->user_conn = user_conn;
            user_stream->last_recv_log_time = xqc_now();
            user_stream->recv_log_bytes = 0;
            user_stream->h3_ext_bs = xqc_h3_ext_bytestream_create(ctx.engine, cid, user_stream);
            if (user_stream->h3_ext_bs == NULL) {
                printf("xqc_h3_ext_bytestream_create error\n");
                continue;
            }

            xqc_client_bytestream_send(user_stream->h3_ext_bs, user_stream);

        }

        // prepare to send datagrams
        if (g_test_case != 306 && g_test_case != 307 && g_test_case != 308 && g_test_case != 310
            && g_test_case != 311 && g_test_case != 312 && g_test_case != 313) 
        {
            if (g_send_dgram) {
                user_conn->dgram_blk->data = calloc(1, g_send_body_size);
                user_conn->dgram_blk->data[0] = 0x1;
                user_conn->dgram_blk->data_len = g_send_body_size;
                if (g_echo_check) {
                    user_conn->dgram_blk->recv_data = calloc(1, g_send_body_size << 4);
                    user_conn->dgram_blk->recv_data[0] = 0x2;
                }
                xqc_client_h3_ext_datagram_send(user_conn);
            }
        }

    } else if (!g_send_dgram && g_test_case != 500) {

        if (g_periodically_request) {
            user_conn->ev_request = event_new(eb, -1, 0, xqc_client_request_callback, user_conn);

            /* request once every 1 second */
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 500000;
            int ret = event_add(user_conn->ev_request, &tv);
            if (ret != 0) {
                printf("[ERROR] add request event ret: %d\n", ret);
            }
            

            printf("-----------  g_periodically_request: %d\n", g_periodically_request);

        } else {

            for (int i = 0; i < g_req_paral; i++) {
                g_req_cnt++;
                user_stream_t *user_stream = calloc(1, sizeof(user_stream_t));
                user_stream->user_conn = user_conn;
                user_stream->last_recv_log_time = xqc_now();
                user_stream->recv_log_bytes = 0;
                if (user_conn->h3 == 0 || user_conn->h3 == 2) {
                    if (g_test_case == 11) { /* create stream fail */
                        xqc_cid_t tmp;
                        xqc_h3_request_create(ctx.engine, &tmp, NULL, user_stream);
                        continue;
                    }

                    user_stream->h3_request = xqc_h3_request_create(ctx.engine, cid, &stream_settings, user_stream);
                    if (user_stream->h3_request == NULL) {
                        printf("xqc_h3_request_create error\n");
                        continue;
                    }

                    xqc_client_request_send(user_stream->h3_request, user_stream);

                } else {
                    user_stream->stream = xqc_stream_create(ctx.engine, cid, NULL, user_stream);
                    if (user_stream->stream == NULL) {
                        printf("xqc_stream_create error\n");
                        continue;
                    }
                    printf("[qperf]|ts:%"PRIu64"|test_start|\n", xqc_now());
                    xqc_client_stream_send(user_stream->stream, user_stream);
                }
            }
        }

        last_recv_ts = xqc_now();
        
    } else {
        user_conn->dgram_blk->data = calloc(1, g_send_body_size);
        user_conn->dgram_blk->data_len = g_send_body_size;
        if (g_echo_check) {
            user_conn->dgram_blk->recv_data = calloc(1, g_send_body_size << 4);
        }
        if (user_conn->h3 == 2) {
            xqc_client_h3_ext_datagram_send(user_conn);

        } else if (user_conn->h3 == 1) {
            xqc_client_datagram_send(user_conn);
        }
        
    }
skip_data:

    event_base_dispatch(eb);
    xqc_test_client_log_stop_reason();

cleanup_main:
    g_stop_event_base = NULL;
    if (g_enable_wifi_monitor) {
        xqc_test_cli_shutdown_monitoring(&ctx);
        xqc_test_cli_close_aux_trace_files(&ctx);
    }

    // TODO
    // 如果支持多路径，socket由path管
    if (user_conn != NULL && 0 == g_enable_multipath && user_conn->ev_socket != NULL) {
        event_free(user_conn->ev_socket);
    }
    if (user_conn != NULL && user_conn->ev_timeout != NULL) {
        event_free(user_conn->ev_timeout);
    }

    if (user_conn != NULL && user_conn->dgram_blk) {
        if (user_conn->dgram_blk->data) {
            free(user_conn->dgram_blk->data);
        }
        if (user_conn->dgram_blk->recv_data) {
            free(user_conn->dgram_blk->recv_data);
        }
        free(user_conn->dgram_blk);
    }

    if (user_conn != NULL) {
        free(user_conn->peer_addr);
        free(user_conn->local_addr);
        free(user_conn);
    }

    if (ctx.ev_delay) {
        event_free(ctx.ev_delay);
    }

    if (ctx.engine != NULL) {
        xqc_engine_destroy(ctx.engine);
    }
    xqc_client_close_keylog_file(&ctx);
    xqc_client_close_log_file(&ctx);
    destroy_cdf();

    return exit_code;
}
