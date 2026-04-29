/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/transport/scheduler/xqc_scheduler_blest.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/scheduler/xqc_scheduler_observer.h"
#include "src/transport/xqc_send_ctl.h"

#define XQC_BLEST_LAMBDA_INIT      1200
#define XQC_BLEST_LAMBDA_MIN       1000
#define XQC_BLEST_LAMBDA_MAX       1300
#define XQC_BLEST_DYN_GOOD         10
#define XQC_BLEST_DYN_BAD          40

typedef struct {
    uint64_t    min_srtt_us[XQC_MAX_PATHS_COUNT];
    uint64_t    max_srtt_us[XQC_MAX_PATHS_COUNT];
    uint16_t    lambda_1000;
    xqc_usec_t  last_lambda_update;
    uint32_t    last_lost_count;
} xqc_blest_scheduler_t;

static size_t
xqc_blest_scheduler_size()
{
    return sizeof(xqc_blest_scheduler_t);
}

static void
xqc_blest_scheduler_init(void *scheduler, xqc_log_t *log, xqc_scheduler_params_t *param)
{
    xqc_blest_scheduler_t *blest = (xqc_blest_scheduler_t *) scheduler;
    uint32_t i;

    for (i = 0; i < XQC_MAX_PATHS_COUNT; i++) {
        blest->min_srtt_us[i] = XQC_MAX_UINT64_VALUE;
        blest->max_srtt_us[i] = 0;
    }

    blest->lambda_1000 = XQC_BLEST_LAMBDA_INIT;
}

static void
xqc_blest_update_path_rtt(xqc_blest_scheduler_t *blest, xqc_path_ctx_t *path)
{
    uint64_t srtt;

    if (path->path_id >= XQC_MAX_PATHS_COUNT) {
        return;
    }

    srtt = xqc_send_ctl_get_srtt(path->path_send_ctl);
    if (srtt == 0) {
        return;
    }

    blest->min_srtt_us[path->path_id] = xqc_min(blest->min_srtt_us[path->path_id], srtt);
    blest->max_srtt_us[path->path_id] = xqc_max(blest->max_srtt_us[path->path_id], srtt);
}

static uint64_t
xqc_blest_path_min_srtt(xqc_blest_scheduler_t *blest, xqc_path_ctx_t *path)
{
    uint64_t srtt = xqc_send_ctl_get_srtt(path->path_send_ctl);

    if (path->path_id >= XQC_MAX_PATHS_COUNT
        || blest->min_srtt_us[path->path_id] == XQC_MAX_UINT64_VALUE)
    {
        return srtt;
    }

    return blest->min_srtt_us[path->path_id];
}

static uint64_t
xqc_blest_path_max_srtt(xqc_blest_scheduler_t *blest, xqc_path_ctx_t *path)
{
    uint64_t srtt = xqc_send_ctl_get_srtt(path->path_send_ctl);

    if (path->path_id >= XQC_MAX_PATHS_COUNT
        || blest->max_srtt_us[path->path_id] == 0)
    {
        return srtt;
    }

    return blest->max_srtt_us[path->path_id];
}

static uint32_t
xqc_blest_conn_lost_count(xqc_connection_t *conn)
{
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    uint32_t lost = 0;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_send_ctl != NULL) {
            lost += path->path_send_ctl->ctl_lost_count;
        }
    }

    return lost;
}

static void
xqc_blest_update_lambda(xqc_blest_scheduler_t *blest, xqc_connection_t *conn,
    xqc_path_ctx_t *slow_path, xqc_usec_t now)
{
    uint64_t min_srtt = xqc_blest_path_min_srtt(blest, slow_path);
    uint32_t lost_count;

    if (min_srtt == 0) {
        min_srtt = XQC_kInitialRtt_us;
    }

    if (blest->last_lambda_update
        && now - blest->last_lambda_update < (min_srtt >> 3))
    {
        return;
    }

    lost_count = xqc_blest_conn_lost_count(conn);
    if (lost_count > blest->last_lost_count) {
        blest->lambda_1000 = xqc_min(blest->lambda_1000 + XQC_BLEST_DYN_BAD,
                                     XQC_BLEST_LAMBDA_MAX);

    } else {
        blest->lambda_1000 = xqc_max(blest->lambda_1000 - XQC_BLEST_DYN_GOOD,
                                     XQC_BLEST_LAMBDA_MIN);
    }

    blest->last_lost_count = lost_count;
    blest->last_lambda_update = now;
}

static uint64_t
xqc_blest_estimate_bytes(xqc_blest_scheduler_t *blest, xqc_path_ctx_t *path,
    uint64_t time_us)
{
    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    uint64_t min_srtt = xqc_blest_path_min_srtt(blest, path);
    uint64_t max_srtt = xqc_blest_path_max_srtt(blest, path);
    uint64_t avg_rtt = (min_srtt + max_srtt) / 2;
    uint64_t num_rtts;
    uint64_t cwnd = send_ctl->ctl_cong_callback->
        xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong);
    uint64_t bytes;
    uint64_t mss;

    if (avg_rtt == 0) {
        num_rtts = 1;

    } else {
        num_rtts = time_us / avg_rtt + 1;
    }

    if (send_ctl->ctl_cong_callback->xqc_cong_ctl_in_slow_start
        && send_ctl->ctl_cong_callback->xqc_cong_ctl_in_slow_start(send_ctl->ctl_cong))
    {
        /* Slow start: exponential growth, cap num_rtts to prevent overflow */
        if (num_rtts > 16) {
            num_rtts = 16;
        }
        bytes = cwnd * ((1ULL << num_rtts) - 1);

    } else {
        /* Congestion avoidance: Reno-like linear growth.
         * Each RTT the cwnd grows by ~1 MSS, so over num_rtts RTTs
         * the total bytes sent is:
         *   cwnd + (cwnd + mss) + (cwnd + 2*mss) + ... + (cwnd + (n-1)*mss)
         *   = cwnd * n + n*(n-1)/2 * mss
         *
         * This matches the Linux kernel mptcp_blest.c formula:
         *   packets = (ca_cwnd + (num_rtts - 1) / 2) * num_rtts
         */
        mss = xqc_conn_get_mss(send_ctl->ctl_conn);
        if (mss == 0) {
            mss = XQC_PACKET_OUT_SIZE;
        }
        bytes = cwnd * num_rtts + (num_rtts * (num_rtts - 1) / 2) * mss;
    }

    return bytes * blest->lambda_1000 / 1000;
}

static uint64_t
xqc_blest_estimate_linger_time(xqc_blest_scheduler_t *blest,
    xqc_path_ctx_t *path, xqc_packet_out_t *packet_out)
{
    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    uint64_t min_srtt = xqc_blest_path_min_srtt(blest, path);
    uint64_t max_srtt = xqc_blest_path_max_srtt(blest, path);
    uint64_t inflight = send_ctl->ctl_bytes_in_flight
                        + path->path_schedule_bytes
                        + packet_out->po_used_size;
    uint64_t cwnd = send_ctl->ctl_cong_callback->
        xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong);
    uint64_t slope, estimate;

    if (cwnd == 0) {
        cwnd = 1;
    }

    if (inflight >= cwnd) {
        estimate = max_srtt;

    } else {
        slope = max_srtt > min_srtt ? max_srtt - min_srtt : 0;
        estimate = min_srtt + (slope * inflight) / cwnd;
    }

    return xqc_max(xqc_send_ctl_get_srtt(path->path_send_ctl), estimate);
}

static xqc_path_ctx_t *
xqc_blest_pick_minrtt_path(xqc_blest_scheduler_t *blest, xqc_connection_t *conn,
    xqc_packet_out_t *packet_out, xqc_scheduler_observation_t *observation,
    int check_cwnd, int reinject, xqc_bool_t *reached_cwnd_check)
{
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path, *best = NULL;
    uint64_t best_srtt = XQC_MAX_UINT64_VALUE;
    int standby_pass;
    xqc_bool_t path_can_send;

    for (standby_pass = 0; standby_pass <= 1 && best == NULL; standby_pass++) {
        xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
            path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
            if (!xqc_scheduler_path_is_usable(path)) {
                continue;
            }

            if (standby_pass != (xqc_scheduler_path_is_standby(path) ? 1 : 0)) {
                continue;
            }

            if (reinject && packet_out->po_path_id == path->path_id) {
                continue;
            }

            *reached_cwnd_check = XQC_TRUE;
            path_can_send = xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd);
            if (observation->path_count > 0) {
                uint8_t i;
                for (i = 0; i < observation->path_count; i++) {
                    if (observation->paths[i].path_id == path->path_id) {
                        observation->paths[i].can_send = path_can_send;
                        break;
                    }
                }
            }

            if (!path_can_send) {
                continue;
            }

            if (best == NULL || xqc_send_ctl_get_srtt(path->path_send_ctl) < best_srtt) {
                best = path;
                best_srtt = xqc_send_ctl_get_srtt(path->path_send_ctl);
            }
        }
    }

    return best;
}

static xqc_path_ctx_t *
xqc_blest_find_fastest_usable_path(xqc_blest_scheduler_t *blest, xqc_connection_t *conn)
{
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path, *best = NULL;
    uint64_t best_srtt = XQC_MAX_UINT64_VALUE;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (!xqc_scheduler_path_is_usable(path)) {
            continue;
        }

        xqc_blest_update_path_rtt(blest, path);
        if (xqc_send_ctl_get_srtt(path->path_send_ctl) < best_srtt) {
            best = path;
            best_srtt = xqc_send_ctl_get_srtt(path->path_send_ctl);
        }
    }

    return best;
}

xqc_path_ctx_t *
xqc_blest_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, int check_cwnd,
    int reinject, xqc_bool_t *cc_blocked)
{
    xqc_blest_scheduler_t *blest = (xqc_blest_scheduler_t *) scheduler;
    xqc_scheduler_observation_t observation;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path, *fastest_path, *best_path;
    xqc_bool_t reached_cwnd_check = XQC_FALSE;
    xqc_usec_t now = xqc_monotonic_timestamp();

    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }

    xqc_scheduler_observation_init(&observation, "blest", conn,
        conn->user_data, packet_out->po_pkt.pkt_num, packet_out->po_used_size);
    observation.ts_us = now;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (xqc_scheduler_path_is_usable(path)) {
            xqc_blest_update_path_rtt(blest, path);
        }
        xqc_scheduler_observe_path(&observation, path, 0, xqc_path_get_perf_class(path));
    }

    fastest_path = xqc_blest_find_fastest_usable_path(blest, conn);
    best_path = xqc_blest_pick_minrtt_path(blest, conn, packet_out, &observation,
        check_cwnd, reinject, &reached_cwnd_check);

    if (best_path != NULL && fastest_path != NULL && best_path != fastest_path) {
        uint64_t slow_linger_time;
        uint64_t fast_bytes;
        uint64_t slow_bytes;
        uint64_t send_credit;
        uint64_t avail_space;

        xqc_blest_update_lambda(blest, conn, best_path, now);
        slow_linger_time = xqc_blest_estimate_linger_time(blest, best_path, packet_out);
        fast_bytes = xqc_blest_estimate_bytes(blest, fastest_path, slow_linger_time);
        slow_bytes = best_path->path_send_ctl->ctl_bytes_in_flight
                     + best_path->path_schedule_bytes
                     + packet_out->po_used_size;
        send_credit = conn->conn_flow_ctl.fc_max_data_can_send > conn->conn_flow_ctl.fc_data_sent
                      ? conn->conn_flow_ctl.fc_max_data_can_send - conn->conn_flow_ctl.fc_data_sent
                      : 0;
        avail_space = send_credit > slow_bytes ? send_credit - slow_bytes : 0;

        if (fast_bytes > avail_space) {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|blest_defer_slow_path|"
                    "slow_path:%ui|fast_path:%ui|slow_linger:%ui|"
                    "fast_bytes:%ui|avail_space:%ui|lambda:%ud|",
                    best_path->path_id, fastest_path->path_id, slow_linger_time,
                    fast_bytes, avail_space, blest->lambda_1000);
            xqc_scheduler_notify_observer(&observation);
            return NULL;
        }
    }

    if (best_path != NULL) {
        if (cc_blocked) {
            *cc_blocked = XQC_FALSE;
        }
        observation.has_selected_path = 1;
        observation.selected_path_id = best_path->path_id;
        xqc_scheduler_notify_observer(&observation);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|blest_best_path:%ui|frame_type:%s|"
                "pn:%ui|size:%ud|reinj:%d|lambda:%ud|",
                best_path->path_id, xqc_frame_type_2_str(conn->engine, packet_out->po_frame_types),
                packet_out->po_pkt.pkt_num, packet_out->po_used_size, reinject,
                blest->lambda_1000);
        return best_path;
    }

    if (cc_blocked && reached_cwnd_check) {
        *cc_blocked = XQC_TRUE;
    }

    xqc_scheduler_notify_observer(&observation);
    xqc_log(conn->log, XQC_LOG_DEBUG, "|blest_no_available_path|conn:%p|", conn);
    return NULL;
}

const xqc_scheduler_callback_t xqc_blest_scheduler_cb = {
    .xqc_scheduler_size             = xqc_blest_scheduler_size,
    .xqc_scheduler_init             = xqc_blest_scheduler_init,
    .xqc_scheduler_get_path         = xqc_blest_scheduler_get_path,
};
