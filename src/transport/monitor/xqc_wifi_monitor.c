#define _GNU_SOURCE

#include "xqc_wifi_monitor.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <net/if.h>

#ifndef __clang__
#define preserve_access_index
#endif

#define main xqc_wifi_monitor_standalone_main
#include "../../../../ebpf-wifi-insider/monitor.c"
#undef main

#define XQC_WIFI_MONITOR_MAX_IFACES 2
#define XQC_WIFI_MONITOR_MIN_SAMPLES 5
#define XQC_WIFI_MONITOR_LOG_INTERVAL_US 1000000ULL
#define XQC_WIFI_MONITOR_KEEP_STATUS INT_MIN
#define XQC_WIFI_MONITOR_START_WAIT_US 5000000ULL
#define XQC_WIFI_GTSD_WINDOW_SIZE 128
#define XQC_WIFI_GTSD_UPDATE_STRIDE 32
#define XQC_WIFI_GTSD_R0_MIN 1.2
#define XQC_WIFI_GTSD_R0_MAX 2.5
#define XQC_WIFI_GTSD_ON_DELTA 0.5
#define XQC_WIFI_GTSD_ON_THRESHOLD 3.0
#define XQC_WIFI_GTSD_ON_EXCESS_CAP 2.0
#define XQC_WIFI_GTSD_CLEAR_THRESHOLD 0.5
#define XQC_WIFI_GTSD_OFF_THRESHOLD 3.0
#define XQC_WIFI_GTSD_OFF_EVIDENCE_CAP 0.5
#define XQC_WIFI_GTSD_P95_REL_GUARD 2.0
#define XQC_WIFI_GTSD_P95_ABS_GUARD_US 5000ULL

typedef struct xqc_wifi_iface_state_s {
    char                        ifname[64];
    unsigned int                ifindex;
    xqc_wifi_state_snapshot_t   snapshot;
    double                      ewma_long_gap;
    uint64_t                    last_logged_ts_us;
    uint32_t                    gap_window[XQC_WIFI_GTSD_WINDOW_SIZE];
    uint32_t                    gap_window_count;
    uint32_t                    gap_window_idx;
    uint32_t                    gtsd_since_update;
    uint64_t                    gtsd_p95_baseline_us;
} xqc_wifi_iface_state_t;

struct xqc_wifi_monitor_s {
    pthread_t                   thread;
    pthread_mutex_t             lock;
    xqc_wifi_monitor_config_t   config;
    xqc_wifi_iface_state_t      ifaces[XQC_WIFI_MONITOR_MAX_IFACES];
    int                         iface_count;
    int                         running;
    int                         stop_requested;
    int                         start_rc;
    int                         start_done;
    char                        last_error[256];
    char                        output_dir[512];
    char                        config_path[512];
    char                        meta_path[512];
    char                        merged_mgmt_path[512];
};

static xqc_wifi_monitor_t *g_xqc_wifi_monitor = NULL;

static double
xqc_wifi_clip_prob(double value)
{
    if (value < 1e-9) {
        return 1e-9;
    }
    if (value > 1.0 - 1e-9) {
        return 1.0 - 1e-9;
    }
    return value;
}

static double
xqc_wifi_clip_double(double value, double low, double high)
{
    if (value < low) {
        return low;
    }
    if (value > high) {
        return high;
    }
    return value;
}

static int
xqc_wifi_u32_cmp(const void *a, const void *b)
{
    uint32_t av = *(const uint32_t *) a;
    uint32_t bv = *(const uint32_t *) b;

    if (av < bv) {
        return -1;
    }
    if (av > bv) {
        return 1;
    }
    return 0;
}

static uint32_t
xqc_wifi_quantile_u32(const uint32_t *values, uint32_t count, double q)
{
    uint32_t sorted[XQC_WIFI_GTSD_WINDOW_SIZE];
    uint32_t idx;

    if (values == NULL || count == 0) {
        return 0;
    }

    if (count > XQC_WIFI_GTSD_WINDOW_SIZE) {
        count = XQC_WIFI_GTSD_WINDOW_SIZE;
    }

    memcpy(sorted, values, count * sizeof(uint32_t));
    qsort(sorted, count, sizeof(uint32_t), xqc_wifi_u32_cmp);

    idx = (uint32_t) ceil(q * ((double) count - 1.0));
    if (idx >= count) {
        idx = count - 1;
    }

    return sorted[idx];
}

static int
xqc_wifi_gtsd_tail_guard(const xqc_wifi_iface_state_t *iface_state)
{
    uint64_t p95_guard;

    if (iface_state == NULL || iface_state->gtsd_p95_baseline_us == 0) {
        return 0;
    }

    p95_guard = iface_state->gtsd_p95_baseline_us * XQC_WIFI_GTSD_P95_REL_GUARD;
    if (p95_guard < iface_state->gtsd_p95_baseline_us + XQC_WIFI_GTSD_P95_ABS_GUARD_US) {
        p95_guard = iface_state->gtsd_p95_baseline_us + XQC_WIFI_GTSD_P95_ABS_GUARD_US;
    }

    return iface_state->snapshot.tail_p95_us >= p95_guard;
}

static void
xqc_wifi_gtsd_update(xqc_wifi_iface_state_t *iface_state, uint32_t gap_us)
{
    xqc_wifi_state_snapshot_t *snapshot;
    uint32_t p50;
    uint32_t p95;
    double ratio;
    double excess = 0.0;
    double evidence;
    int tail_guard;

    if (iface_state == NULL || gap_us == 0) {
        return;
    }

    snapshot = &iface_state->snapshot;
    iface_state->gap_window[iface_state->gap_window_idx] = gap_us;
    iface_state->gap_window_idx =
        (iface_state->gap_window_idx + 1) % XQC_WIFI_GTSD_WINDOW_SIZE;
    if (iface_state->gap_window_count < XQC_WIFI_GTSD_WINDOW_SIZE) {
        iface_state->gap_window_count++;
    }

    if (iface_state->gap_window_count < XQC_WIFI_GTSD_WINDOW_SIZE) {
        snapshot->state = XQC_WIFI_PATH_STATE_UNKNOWN;
        return;
    }

    if (snapshot->gtsd_calibrated && ++iface_state->gtsd_since_update < XQC_WIFI_GTSD_UPDATE_STRIDE) {
        return;
    }
    iface_state->gtsd_since_update = 0;

    p50 = xqc_wifi_quantile_u32(iface_state->gap_window,
        iface_state->gap_window_count, 0.50);
    p95 = xqc_wifi_quantile_u32(iface_state->gap_window,
        iface_state->gap_window_count, 0.95);
    ratio = p50 > 0 ? (double) p95 / (double) p50 : 0.0;

    snapshot->tail_p50_us = p50;
    snapshot->tail_p95_us = p95;
    snapshot->tail_ratio = ratio;

    if (!snapshot->gtsd_calibrated) {
        snapshot->gtsd_calibrated = 1;
        snapshot->tail_baseline =
            xqc_wifi_clip_double(ratio, XQC_WIFI_GTSD_R0_MIN, XQC_WIFI_GTSD_R0_MAX);
        iface_state->gtsd_p95_baseline_us = p95;
        snapshot->tail_excess = 0.0;
        snapshot->cusum_on = 0.0;
        snapshot->cusum_off = 0.0;
        snapshot->state = XQC_WIFI_PATH_STATE_REGULAR;
        return;
    }

    if (snapshot->tail_baseline > 0.0) {
        excess = ratio / snapshot->tail_baseline - 1.0;
    }
    snapshot->tail_excess = excess;

    tail_guard = xqc_wifi_gtsd_tail_guard(iface_state);
    if (snapshot->state != XQC_WIFI_PATH_STATE_DEGRADED_CSMA) {
        if (tail_guard) {
            evidence = xqc_wifi_clip_double(excess, -1.0, XQC_WIFI_GTSD_ON_EXCESS_CAP)
                       - XQC_WIFI_GTSD_ON_DELTA;
        } else {
            evidence = -XQC_WIFI_GTSD_ON_DELTA;
        }

        snapshot->cusum_on = xqc_wifi_clip_double(snapshot->cusum_on + evidence,
            0.0, XQC_WIFI_GTSD_ON_THRESHOLD);
        snapshot->cusum_off = 0.0;

        if (snapshot->cusum_on >= XQC_WIFI_GTSD_ON_THRESHOLD) {
            snapshot->state = XQC_WIFI_PATH_STATE_DEGRADED_CSMA;
            snapshot->cusum_off = 0.0;
        } else {
            snapshot->state = XQC_WIFI_PATH_STATE_REGULAR;
        }

        return;
    }

    if (!tail_guard && excess <= XQC_WIFI_GTSD_CLEAR_THRESHOLD) {
        evidence = xqc_wifi_clip_double(XQC_WIFI_GTSD_CLEAR_THRESHOLD - excess,
            0.0, XQC_WIFI_GTSD_OFF_EVIDENCE_CAP);
    } else {
        evidence = 0.0;
    }

    snapshot->cusum_off = xqc_wifi_clip_double(snapshot->cusum_off + evidence,
        0.0, XQC_WIFI_GTSD_OFF_THRESHOLD);
    snapshot->cusum_on = 0.0;

    if (snapshot->cusum_off >= XQC_WIFI_GTSD_OFF_THRESHOLD) {
        snapshot->state = XQC_WIFI_PATH_STATE_REGULAR;
        snapshot->cusum_on = 0.0;
    }
}

static xqc_wifi_iface_state_t *
xqc_wifi_find_iface_locked(xqc_wifi_monitor_t *monitor, unsigned int ifindex)
{
    int i;

    if (monitor == NULL) {
        return NULL;
    }

    for (i = 0; i < monitor->iface_count; i++) {
        if (monitor->ifaces[i].ifindex == ifindex) {
            return &monitor->ifaces[i];
        }
    }

    return NULL;
}

static void
xqc_wifi_monitor_update_status(xqc_wifi_monitor_t *monitor,
    int start_rc, int running, int start_done)
{
    if (monitor == NULL) {
        return;
    }

    pthread_mutex_lock(&monitor->lock);
    if (start_rc != XQC_WIFI_MONITOR_KEEP_STATUS) {
        monitor->start_rc = start_rc;
    }
    if (running != XQC_WIFI_MONITOR_KEEP_STATUS) {
        monitor->running = running;
    }
    if (start_done != XQC_WIFI_MONITOR_KEEP_STATUS) {
        monitor->start_done = start_done;
    }
    pthread_mutex_unlock(&monitor->lock);
}

static void
xqc_wifi_copy_cstr(char *dst, size_t dst_len, const char *src)
{
    if (dst == NULL || dst_len == 0) {
        return;
    }

    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    strncpy(dst, src, dst_len - 1);
    dst[dst_len - 1] = '\0';
}

static int
xqc_wifi_join_path(char *dst, size_t dst_len, const char *dir, const char *name)
{
    int ret;

    if (dst == NULL || dst_len == 0 || dir == NULL || name == NULL) {
        return -1;
    }

    ret = snprintf(dst, dst_len, "%s/%s", dir, name);
    if (ret < 0 || (size_t) ret >= dst_len) {
        if (dst_len > 0) {
            dst[dst_len - 1] = '\0';
        }
        return -1;
    }

    return 0;
}

static void
xqc_wifi_emit_state_locked(xqc_wifi_monitor_t *monitor,
    xqc_wifi_iface_state_t *iface_state, uint64_t ts_us, int force)
{
    xqc_wifi_state_snapshot_t snapshot;

    if (monitor == NULL || iface_state == NULL || monitor->config.state_update_cb == NULL) {
        return;
    }

    if (!force && iface_state->last_logged_ts_us != 0
        && ts_us < iface_state->last_logged_ts_us + XQC_WIFI_MONITOR_LOG_INTERVAL_US)
    {
        return;
    }

    snapshot = iface_state->snapshot;
    snapshot.ts_us = ts_us;
    iface_state->last_logged_ts_us = ts_us;

    pthread_mutex_unlock(&monitor->lock);
    monitor->config.state_update_cb(&snapshot, monitor->config.state_update_user_data);
    pthread_mutex_lock(&monitor->lock);
}

static void
xqc_wifi_update_iface_state(xqc_wifi_monitor_t *monitor,
    const struct event_wifi_pkt *event, long long offset)
{
    static const double tau_us = 20000.0;
    static const double p0 = 0.001;
    static const double p1 = 0.15;
    static const double q01 = 0.001;
    static const double q10 = 0.01;
    static const double ewma_alpha = 0.05;

    xqc_wifi_iface_state_t *iface_state;
    xqc_wifi_path_state_t old_state;
    unsigned long long sec = 0, nsec = 0;
    uint64_t ts_us;
    uint64_t burst_frames;
    double burst_bytes;
    double pi_pred;
    double log_odds;
    double log_lr;
    int long_gap;

    if (monitor == NULL || event == NULL || event->gap == 0) {
        return;
    }

    pthread_mutex_lock(&monitor->lock);
    iface_state = xqc_wifi_find_iface_locked(monitor, event->tx_ifindex);
    if (iface_state == NULL) {
        pthread_mutex_unlock(&monitor->lock);
        return;
    }

    get_tm(event->ts_ns, offset, &sec, &nsec);
    ts_us = sec * 1000000ULL + nsec / 1000ULL;
    long_gap = event->gap > tau_us ? 1 : 0;
    burst_frames = event->ampdu_ack_len ? event->ampdu_ack_len :
        (event->ampdu_len ? event->ampdu_len : 1);
    burst_bytes = (double) event->len * (double) burst_frames;

    old_state = iface_state->snapshot.state;
    iface_state->snapshot.last_gap_us = event->gap;
    iface_state->snapshot.last_mac_rtt_us = event->mac_rtt_us;
    iface_state->snapshot.last_update_ts_us = ts_us;
    iface_state->snapshot.sample_count++;

    if (iface_state->snapshot.sample_count == 1) {
        iface_state->snapshot.ewma_gap_us = event->gap;
        iface_state->snapshot.ewma_airtime_us = event->airtime;
        iface_state->snapshot.ewma_mac_rtt_us = event->mac_rtt_us;
        iface_state->snapshot.ewma_burst_bytes = burst_bytes;
        iface_state->ewma_long_gap = long_gap;
        iface_state->snapshot.pi_degraded = 0.0;

    } else {
        iface_state->snapshot.ewma_gap_us =
            ewma_alpha * (double) event->gap
            + (1.0 - ewma_alpha) * iface_state->snapshot.ewma_gap_us;
        iface_state->snapshot.ewma_airtime_us =
            ewma_alpha * (double) event->airtime
            + (1.0 - ewma_alpha) * iface_state->snapshot.ewma_airtime_us;
        iface_state->snapshot.ewma_mac_rtt_us =
            ewma_alpha * (double) event->mac_rtt_us
            + (1.0 - ewma_alpha) * iface_state->snapshot.ewma_mac_rtt_us;
        iface_state->snapshot.ewma_burst_bytes =
            ewma_alpha * burst_bytes
            + (1.0 - ewma_alpha) * iface_state->snapshot.ewma_burst_bytes;
        iface_state->ewma_long_gap =
            ewma_alpha * (double) long_gap
            + (1.0 - ewma_alpha) * iface_state->ewma_long_gap;
    }

    iface_state->snapshot.p_long_gap = iface_state->ewma_long_gap;
    if ((iface_state->snapshot.ewma_gap_us + iface_state->snapshot.ewma_airtime_us) > 0.0) {
        iface_state->snapshot.r_eff_Bpus =
            iface_state->snapshot.ewma_burst_bytes
            / (iface_state->snapshot.ewma_gap_us + iface_state->snapshot.ewma_airtime_us);
    }

    pi_pred = iface_state->snapshot.pi_degraded * (1.0 - q10)
        + (1.0 - iface_state->snapshot.pi_degraded) * q01;
    pi_pred = xqc_wifi_clip_prob(pi_pred);

    log_lr = long_gap ? log(p1 / p0) : log((1.0 - p1) / (1.0 - p0));
    log_odds = log(pi_pred / (1.0 - pi_pred)) + log_lr;
    iface_state->snapshot.pi_degraded = 1.0 / (1.0 + exp(-log_odds));

    xqc_wifi_gtsd_update(iface_state, event->gap);

    xqc_wifi_emit_state_locked(monitor, iface_state, ts_us,
        iface_state->snapshot.state != old_state);
    pthread_mutex_unlock(&monitor->lock);
}

static int
xqc_embedded_handle_wifi_pkt(void *ctx, void *data, size_t data_sz)
{
    int ret;

    ret = handle_wifi_pkt(ctx, data, data_sz);
    if (g_xqc_wifi_monitor != NULL && data_sz >= sizeof(struct event_wifi_pkt)) {
        xqc_wifi_update_iface_state(g_xqc_wifi_monitor,
            (const struct event_wifi_pkt *) data, *(long long *) ctx);
    }

    return ret;
}

static int
xqc_embedded_handle_wifi_rx(void *ctx, void *data, size_t data_sz)
{
    return handle_wifi_rx(ctx, data, data_sz);
}

static int
xqc_embedded_handle_mac_tx(void *ctx, void *data, size_t data_sz)
{
    return handle_mac_tx(ctx, data, data_sz);
}

static int
xqc_embedded_handle_drop(void *ctx, void *data, size_t data_sz)
{
    return handle_drop(ctx, data, data_sz);
}

static void
xqc_wifi_monitor_set_error(xqc_wifi_monitor_t *monitor, const char *message)
{
    if (monitor == NULL || message == NULL) {
        return;
    }

    snprintf(monitor->last_error, sizeof(monitor->last_error), "%s", message);
}

static int
xqc_wifi_monitor_open_outputs(xqc_wifi_monitor_t *monitor)
{
    char path_buf[512];
    int ret;
    const char *output_dir;

    if (monitor == NULL) {
        return -1;
    }

    output_dir = monitor->output_dir;

#define XQC_OPEN_FILE(fp, name, header) do { \
    ret = xqc_wifi_join_path(path_buf, sizeof(path_buf), output_dir, name); \
    if (ret == 0) { \
        fp = fopen(path_buf, "w"); \
        if (fp != NULL) { \
            fprintf(fp, "%s\n", header); \
        } \
    } \
} while (0)

    XQC_OPEN_FILE(fp_wifi_rx, "wifi_rx_trace.csv",
        "ts,skb_addr,len,frame_control,type,subtype,seq_ctrl,wifi_seq,frag,retry,more_frag,from_ds,to_ds,qos_tid,current_ap_known,current_bssid,bssid_match_src,ethertype,l3_proto,src_ip,src_port,dst_ip,dst_port,tcp_seq,skb_data_len,skb_head_len,skb_data_offset,skb_protocol_raw,network_header,transport_header,submit_stage,ip_parse_ok,tcp_parse_ok,data_first32_len,data_first32_hex,addr1,addr2,addr3");
    XQC_OPEN_FILE(fp_mac_tx, "mac80211_tx.csv",
        "flow_id,skb_addr,tx_ifindex,ts,src_ip,src_port,dst_ip,dst_port,protocol,tcp_seq,ampdu,len,quic_form,quic_type,quic_dcid,quic_pn_raw,quic_pn_len");
    XQC_OPEN_FILE(fp_drop, "drop_trace.csv",
        "ts,src_ip,src_port,dst_ip,dst_port,tcp_seq,location,drop_reason");

    {
        char mgmt_name[128];
        snprintf(mgmt_name, sizeof(mgmt_name), "mgmt_trace_%s.csv", g_ifname);
        XQC_OPEN_FILE(fp_mgmt, mgmt_name, "ts,type,event,rssi,snr,raw_msg");
    }

    if (g_ifname2[0] != '\0') {
        char mgmt_name[128];
        snprintf(mgmt_name, sizeof(mgmt_name), "mgmt_trace_%s.csv", g_ifname2);
        XQC_OPEN_FILE(fp_mgmt2, mgmt_name, "ts,type,event,rssi,snr,raw_msg");
    }

#undef XQC_OPEN_FILE
    (void) monitor;
    return 0;
}

static void
xqc_wifi_monitor_write_meta(xqc_wifi_monitor_t *monitor)
{
    FILE *fp;

    if (monitor == NULL || monitor->meta_path[0] == '\0') {
        return;
    }

    fp = fopen(monitor->meta_path, "w");
    if (fp == NULL) {
        return;
    }

    fprintf(fp, "{\n");
    fprintf(fp, "  \"running\": %s,\n", monitor->running ? "true" : "false");
    fprintf(fp, "  \"start_rc\": %d,\n", monitor->start_rc);
    fprintf(fp, "  \"output_dir\": \"%s\",\n", monitor->output_dir);
    fprintf(fp, "  \"config_path\": \"%s\",\n", monitor->config_path);
    fprintf(fp, "  \"ifname_primary\": \"%s\",\n",
        monitor->iface_count > 0 ? monitor->ifaces[0].ifname : "");
    fprintf(fp, "  \"ifname_secondary\": \"%s\",\n",
        monitor->iface_count > 1 ? monitor->ifaces[1].ifname : "");
    fprintf(fp, "  \"last_error\": \"%s\"\n", monitor->last_error);
    fprintf(fp, "}\n");
    fclose(fp);
}

static void
xqc_wifi_monitor_merge_mgmt(xqc_wifi_monitor_t *monitor)
{
    FILE *dst;
    int i;
    int ret;

    if (monitor == NULL || monitor->merged_mgmt_path[0] == '\0') {
        return;
    }

    dst = fopen(monitor->merged_mgmt_path, "w");
    if (dst == NULL) {
        return;
    }

    fprintf(dst, "ts,ifname,type,event,rssi,snr,raw_msg\n");
    for (i = 0; i < monitor->iface_count; i++) {
        char src_path[512];
        FILE *src;
        char line[1024];
        int line_no = 0;

        ret = snprintf(src_path, sizeof(src_path), "%s/mgmt_trace_%s.csv",
            monitor->output_dir, monitor->ifaces[i].ifname);
        if (ret < 0 || (size_t) ret >= sizeof(src_path)) {
            continue;
        }
        src = fopen(src_path, "r");
        if (src == NULL) {
            continue;
        }

        while (fgets(line, sizeof(line), src) != NULL) {
            char *first_comma;
            char *newline;
            line_no++;
            if (line_no == 1) {
                continue;
            }
            newline = strchr(line, '\n');
            if (newline) {
                *newline = '\0';
            }
            first_comma = strchr(line, ',');
            if (first_comma == NULL) {
                continue;
            }
            fprintf(dst, "%.*s,%s,%s\n",
                (int) (first_comma - line), line,
                monitor->ifaces[i].ifname,
                first_comma + 1);
        }

        fclose(src);
        unlink(src_path);
    }

    fclose(dst);
}

static void *
xqc_wifi_monitor_thread_main(void *arg)
{
    xqc_wifi_monitor_t *monitor = arg;
    struct monitor_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    struct timespec rt, mt;
    long long offset;
    pthread_t tid_mgmt;
    pthread_t tid_mgmt2;
    int mgmt1_started = 0;
    int mgmt2_started = 0;
    int err = 0;
    int config_map_fd;
    unsigned int key = 0;
    struct current_bssid_filter empty_bssid = {0};
    static struct mgmt_thread_ctx mgmt_ctx1;
    static struct mgmt_thread_ctx mgmt_ctx2;

    if (monitor == NULL) {
        return NULL;
    }

    g_xqc_wifi_monitor = monitor;
    exiting = false;
    g_rb = NULL;
    xqc_wifi_copy_cstr(output_dir, sizeof(output_dir), monitor->output_dir);
    xqc_wifi_copy_cstr(g_ifname, sizeof(g_ifname),
        monitor->iface_count > 0 ? monitor->ifaces[0].ifname : "");
    xqc_wifi_copy_cstr(g_ifname2, sizeof(g_ifname2),
        monitor->iface_count > 1 ? monitor->ifaces[1].ifname : "");

    if (parse_json_config(monitor->config_path) != 0) {
        xqc_wifi_monitor_set_error(monitor, "parse monitor config failed");
        xqc_wifi_monitor_update_status(monitor, -1, 0, 1);
        xqc_wifi_monitor_write_meta(monitor);
        g_xqc_wifi_monitor = NULL;
        return NULL;
    }

    if (mkdir(output_dir, 0755) != 0 && errno != EEXIST) {
        xqc_wifi_monitor_set_error(monitor, "create output dir failed");
        xqc_wifi_monitor_update_status(monitor, -1, 0, 1);
        xqc_wifi_monitor_write_meta(monitor);
        g_xqc_wifi_monitor = NULL;
        return NULL;
    }

    clock_gettime(CLOCK_REALTIME, &rt);
    clock_gettime(CLOCK_MONOTONIC, &mt);
    offset = ((long long) rt.tv_sec * 1000000000LL + rt.tv_nsec)
        - ((long long) mt.tv_sec * 1000000000LL + mt.tv_nsec);

    xqc_wifi_monitor_open_outputs(monitor);

    skel = monitor_bpf__open();
    if (skel == NULL) {
        xqc_wifi_monitor_set_error(monitor, "open BPF skeleton failed");
        xqc_wifi_monitor_update_status(monitor, -1, 0, 1);
        goto cleanup;
    }

    err = monitor_bpf__load(skel);
    if (err) {
        xqc_wifi_monitor_set_error(monitor, "load BPF skeleton failed");
        xqc_wifi_monitor_update_status(monitor, err, 0, 1);
        goto cleanup;
    }

    err = monitor_bpf__attach(skel);
    if (err) {
        xqc_wifi_monitor_set_error(monitor, "attach BPF skeleton failed");
        xqc_wifi_monitor_update_status(monitor, err, 0, 1);
        goto cleanup;
    }

    config_map_fd = bpf_map__fd(skel->maps.filter_config_map);
    if (config_map_fd >= 0) {
        bpf_map_update_elem(config_map_fd, &key, &g_filter_cfg, BPF_ANY);
    }

    g_bssid_filter_map_fd = bpf_map__fd(skel->maps.bssid_filter_map);
    if (g_bssid_filter_map_fd >= 0) {
        apply_current_bssid_filter(&empty_bssid);
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb_wifi_pkt),
        xqc_embedded_handle_wifi_pkt, &offset, NULL);
    g_rb = rb;
    if (rb == NULL) {
        xqc_wifi_monitor_set_error(monitor, "create ring buffer failed");
        xqc_wifi_monitor_update_status(monitor, -1, 0, 1);
        goto cleanup;
    }

    ring_buffer__add(rb, bpf_map__fd(skel->maps.rb_wifi_rx),
        xqc_embedded_handle_wifi_rx, &offset);
    ring_buffer__add(rb, bpf_map__fd(skel->maps.rb_mac_tx),
        xqc_embedded_handle_mac_tx, &offset);
    ring_buffer__add(rb, bpf_map__fd(skel->maps.rb_drop),
        xqc_embedded_handle_drop, &offset);

    strncpy(mgmt_ctx1.ifname, g_ifname, IF_NAMESIZE - 1);
    mgmt_ctx1.ifname[IF_NAMESIZE - 1] = '\0';
    mgmt_ctx1.fp_mgmt = fp_mgmt;
    if (pthread_create(&tid_mgmt, NULL, mgmt_thread, &mgmt_ctx1) == 0) {
        mgmt1_started = 1;
    }

    if (g_ifname2[0] != '\0') {
        strncpy(mgmt_ctx2.ifname, g_ifname2, IF_NAMESIZE - 1);
        mgmt_ctx2.ifname[IF_NAMESIZE - 1] = '\0';
        mgmt_ctx2.fp_mgmt = fp_mgmt2;
        if (pthread_create(&tid_mgmt2, NULL, mgmt_thread, &mgmt_ctx2) == 0) {
            mgmt2_started = 1;
        }
    }

    xqc_wifi_monitor_update_status(monitor, 0, 1, 1);
    xqc_wifi_monitor_write_meta(monitor);

    while (!monitor->stop_requested && !exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            xqc_wifi_monitor_set_error(monitor, "poll ring buffer failed");
            xqc_wifi_monitor_update_status(monitor, err,
                XQC_WIFI_MONITOR_KEEP_STATUS,
                XQC_WIFI_MONITOR_KEEP_STATUS);
            break;
        }
    }

cleanup:
    exiting = true;
    xqc_wifi_monitor_update_status(monitor,
        XQC_WIFI_MONITOR_KEEP_STATUS, 0, 1);
    if (mgmt1_started) {
        pthread_join(tid_mgmt, NULL);
    }
    if (mgmt2_started) {
        pthread_join(tid_mgmt2, NULL);
    }
    if (rb) {
        ring_buffer__free(rb);
    }
    g_rb = NULL;
    if (skel) {
        monitor_bpf__destroy(skel);
    }
    close_all_files();
    xqc_wifi_monitor_merge_mgmt(monitor);
    xqc_wifi_monitor_write_meta(monitor);
    g_xqc_wifi_monitor = NULL;
    return NULL;
}

int
xqc_wifi_monitor_start(xqc_wifi_monitor_t **monitor_out,
    const xqc_wifi_monitor_config_t *config)
{
    xqc_wifi_monitor_t *monitor;
    uint64_t waited_us = 0;
    int start_done;
    int start_rc;

    if (monitor_out == NULL || config == NULL || config->output_dir == NULL
        || config->ifname_primary == NULL)
    {
        return -1;
    }

    *monitor_out = NULL;

    monitor = calloc(1, sizeof(*monitor));
    if (monitor == NULL) {
        return -1;
    }

    pthread_mutex_init(&monitor->lock, NULL);
    monitor->config = *config;
    xqc_wifi_copy_cstr(monitor->output_dir, sizeof(monitor->output_dir), config->output_dir);
    xqc_wifi_copy_cstr(monitor->config_path, sizeof(monitor->config_path),
        config->config_path ? config->config_path : "ebpf-wifi-insider/config.json");
    xqc_wifi_join_path(monitor->meta_path, sizeof(monitor->meta_path),
        monitor->output_dir, "wifi_module_meta.json");
    xqc_wifi_join_path(monitor->merged_mgmt_path, sizeof(monitor->merged_mgmt_path),
        monitor->output_dir, "mgmt_trace.csv");

    xqc_wifi_copy_cstr(monitor->ifaces[0].ifname, sizeof(monitor->ifaces[0].ifname),
        config->ifname_primary);
    monitor->ifaces[0].ifindex = if_nametoindex(config->ifname_primary);
    xqc_wifi_copy_cstr(monitor->ifaces[0].snapshot.ifname,
        sizeof(monitor->ifaces[0].snapshot.ifname), config->ifname_primary);
    monitor->ifaces[0].snapshot.ifindex = monitor->ifaces[0].ifindex;
    monitor->ifaces[0].snapshot.state = XQC_WIFI_PATH_STATE_UNKNOWN;
    monitor->iface_count = 1;
    monitor->start_rc = -1;
    monitor->start_done = 0;

    if (config->ifname_secondary && config->ifname_secondary[0] != '\0') {
        xqc_wifi_copy_cstr(monitor->ifaces[1].ifname, sizeof(monitor->ifaces[1].ifname),
            config->ifname_secondary);
        monitor->ifaces[1].ifindex = if_nametoindex(config->ifname_secondary);
        xqc_wifi_copy_cstr(monitor->ifaces[1].snapshot.ifname,
            sizeof(monitor->ifaces[1].snapshot.ifname), config->ifname_secondary);
        monitor->ifaces[1].snapshot.ifindex = monitor->ifaces[1].ifindex;
        monitor->ifaces[1].snapshot.state = XQC_WIFI_PATH_STATE_UNKNOWN;
        monitor->iface_count = 2;
    }

    if (pthread_create(&monitor->thread, NULL, xqc_wifi_monitor_thread_main, monitor) != 0) {
        pthread_mutex_destroy(&monitor->lock);
        free(monitor);
        return -1;
    }

    while (waited_us < XQC_WIFI_MONITOR_START_WAIT_US) {
        pthread_mutex_lock(&monitor->lock);
        start_done = monitor->start_done;
        start_rc = monitor->start_rc;
        pthread_mutex_unlock(&monitor->lock);

        if (start_done) {
            break;
        }

        usleep(1000);
        waited_us += 1000;
    }

    if (!start_done || start_rc != 0) {
        xqc_wifi_monitor_stop(monitor);
        return -1;
    }

    *monitor_out = monitor;
    return 0;
}

void
xqc_wifi_monitor_stop(xqc_wifi_monitor_t *monitor)
{
    if (monitor == NULL) {
        return;
    }

    monitor->stop_requested = 1;
    exiting = true;
    pthread_join(monitor->thread, NULL);
    pthread_mutex_destroy(&monitor->lock);
    free(monitor);
}

int
xqc_wifi_monitor_get_snapshot(xqc_wifi_monitor_t *monitor,
    const char *ifname, xqc_wifi_state_snapshot_t *snapshot)
{
    int i;
    int ret = -1;

    if (monitor == NULL || ifname == NULL || snapshot == NULL) {
        return -1;
    }

    pthread_mutex_lock(&monitor->lock);
    for (i = 0; i < monitor->iface_count; i++) {
        if (strcmp(monitor->ifaces[i].ifname, ifname) == 0) {
            *snapshot = monitor->ifaces[i].snapshot;
            ret = 0;
            break;
        }
    }
    pthread_mutex_unlock(&monitor->lock);
    return ret;
}

int
xqc_wifi_monitor_is_running(xqc_wifi_monitor_t *monitor)
{
    int running = 0;

    if (monitor == NULL) {
        return 0;
    }

    pthread_mutex_lock(&monitor->lock);
    running = monitor->running;
    pthread_mutex_unlock(&monitor->lock);
    return running;
}

int
xqc_wifi_monitor_start_status(xqc_wifi_monitor_t *monitor)
{
    int start_rc = -1;

    if (monitor == NULL) {
        return -1;
    }

    pthread_mutex_lock(&monitor->lock);
    start_rc = monitor->start_rc;
    pthread_mutex_unlock(&monitor->lock);
    return start_rc;
}

const char *
xqc_wifi_monitor_last_error(xqc_wifi_monitor_t *monitor)
{
    return monitor ? monitor->last_error : "monitor-not-created";
}
