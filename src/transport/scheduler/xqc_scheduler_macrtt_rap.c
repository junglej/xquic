/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/transport/scheduler/xqc_scheduler_macrtt_rap.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/scheduler/xqc_scheduler_mac_aware.h"
#include "src/transport/scheduler/xqc_scheduler_observer.h"
#include "src/transport/xqc_send_ctl.h"

static size_t
xqc_macrtt_rap_scheduler_size(void)
{
    return 0;
}

static void
xqc_macrtt_rap_scheduler_init(void *scheduler, xqc_log_t *log,
    xqc_scheduler_params_t *param)
{
    return;
}

static xqc_bool_t
xqc_macrtt_rap_path_better(xqc_path_ctx_t *path, uint64_t path_srtt,
    uint64_t path_mac_rtt, xqc_path_ctx_t *best_path, uint64_t best_srtt,
    uint64_t best_mac_rtt)
{
    if (best_path == NULL) {
        return XQC_TRUE;
    }

    if (path_mac_rtt > 0 && best_mac_rtt > 0 && path_mac_rtt != best_mac_rtt) {
        return path_mac_rtt < best_mac_rtt;
    }
    if (path_mac_rtt > 0 && best_mac_rtt == 0) {
        return XQC_TRUE;
    }
    if (path_mac_rtt == 0 && best_mac_rtt > 0) {
        return XQC_FALSE;
    }

    return path_srtt < best_srtt;
}

xqc_path_ctx_t *
xqc_macrtt_rap_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, int check_cwnd,
    int reinject, xqc_bool_t *cc_blocked)
{
    xqc_path_ctx_t *best_path = NULL;
    xqc_path_ctx_t *original_path = NULL;
    xqc_scheduler_observation_t observation;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_bool_t reached_cwnd_check = XQC_FALSE;
    uint64_t best_srtt = XQC_MAX_UINT64_VALUE;
    uint64_t best_mac_rtt = 0;
    uint64_t now;

    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }

    xqc_scheduler_observation_init(&observation, "macrtt_rap", conn,
        conn->user_data, packet_out->po_pkt.pkt_num, packet_out->po_used_size);
    now = xqc_monotonic_timestamp();
    observation.ts_us = now;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        xqc_wifi_state_snapshot_t wifi_snapshot;
        xqc_bool_t high_risk = XQC_FALSE;
        uint8_t risk_reason_bits = 0;
        xqc_bool_t path_can_send;
        uint64_t path_srtt;
        uint64_t path_mac_rtt = 0;

        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        path_srtt = xqc_send_ctl_get_srtt(path->path_send_ctl);
        if (xqc_mac_aware_scheduler_get_path_state(conn->user_data,
            path->path_id, now, &wifi_snapshot, &high_risk,
            &risk_reason_bits))
        {
            path_mac_rtt = (uint64_t) wifi_snapshot.ewma_mac_rtt_us;
        }

        xqc_scheduler_observe_path(&observation, path, 0,
            xqc_path_get_perf_class(path));

        if (!xqc_scheduler_path_is_usable(path)) {
            continue;
        }

        if (!reached_cwnd_check) {
            reached_cwnd_check = XQC_TRUE;
            if (cc_blocked) {
                *cc_blocked = XQC_TRUE;
            }
        }

        path_can_send = xqc_scheduler_check_path_can_send(path, packet_out,
            check_cwnd);
        if (observation.path_count > 0
            && observation.paths[observation.path_count - 1].path_id
               == path->path_id)
        {
            observation.paths[observation.path_count - 1].can_send =
                path_can_send;
        }
        if (!path_can_send) {
            continue;
        }

        if (cc_blocked) {
            *cc_blocked = XQC_FALSE;
        }

        if (reinject && packet_out->po_path_id == path->path_id) {
            original_path = path;
            continue;
        }

        if (xqc_macrtt_rap_path_better(path, path_srtt, path_mac_rtt,
            best_path, best_srtt, best_mac_rtt))
        {
            best_path = path;
            best_srtt = path_srtt;
            best_mac_rtt = path_mac_rtt;
        }
    }

    if (best_path == NULL && original_path != NULL
        && !(packet_out->po_flag & XQC_POF_REINJECT_DIFF_PATH))
    {
        best_path = original_path;
    }

    if (best_path != NULL) {
        observation.has_selected_path = 1;
        observation.selected_path_id = best_path->path_id;
        observation.decision_reason = best_mac_rtt > 0 ? "macrtt" : "srtt";
    } else {
        observation.decision_reason = "no_path";
        if (cc_blocked && !reached_cwnd_check) {
            *cc_blocked = XQC_FALSE;
        }
    }

    xqc_scheduler_notify_observer(&observation);
    return best_path;
}

const xqc_scheduler_callback_t xqc_macrtt_rap_scheduler_cb = {
    .xqc_scheduler_size             = xqc_macrtt_rap_scheduler_size,
    .xqc_scheduler_init             = xqc_macrtt_rap_scheduler_init,
    .xqc_scheduler_get_path         = xqc_macrtt_rap_scheduler_get_path,
};
