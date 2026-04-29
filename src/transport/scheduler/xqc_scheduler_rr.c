/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/transport/scheduler/xqc_scheduler_rr.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/scheduler/xqc_scheduler_observer.h"
#include "src/transport/xqc_send_ctl.h"

#define XQC_RR_DEFAULT_NUM_SEGMENTS 1

typedef struct {
    unsigned char   quota[XQC_MAX_PATHS_COUNT];
    unsigned char   num_segments;
    xqc_bool_t      cwnd_limited;
} xqc_rr_scheduler_t;

static size_t
xqc_rr_scheduler_size()
{
    return sizeof(xqc_rr_scheduler_t);
}

static void
xqc_rr_scheduler_init(void *scheduler, xqc_log_t *log, xqc_scheduler_params_t *param)
{
    xqc_rr_scheduler_t *rr = (xqc_rr_scheduler_t *) scheduler;

    rr->num_segments = XQC_RR_DEFAULT_NUM_SEGMENTS;
    rr->cwnd_limited = XQC_TRUE;
}

static unsigned char *
xqc_rr_path_quota(xqc_rr_scheduler_t *rr, xqc_path_ctx_t *path)
{
    if (path->path_id >= XQC_MAX_PATHS_COUNT) {
        return NULL;
    }

    return &rr->quota[path->path_id];
}

static xqc_bool_t
xqc_rr_path_can_be_used(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out, int reinject)
{
    if (!xqc_scheduler_path_is_usable(path)) {
        return XQC_FALSE;
    }

    if (reinject && packet_out->po_path_id == path->path_id) {
        return XQC_FALSE;
    }

    return XQC_TRUE;
}

static void
xqc_rr_reset_round(xqc_rr_scheduler_t *rr, xqc_connection_t *conn,
    xqc_packet_out_t *packet_out, int reinject)
{
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    unsigned char *quota;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (!xqc_rr_path_can_be_used(path, packet_out, reinject)) {
            continue;
        }

        quota = xqc_rr_path_quota(rr, path);
        if (quota != NULL) {
            *quota = 0;
        }
    }
}

static void
xqc_rr_charge_quota(xqc_rr_scheduler_t *rr, xqc_connection_t *conn,
    xqc_path_ctx_t *path, xqc_packet_out_t *packet_out)
{
    unsigned char *quota = xqc_rr_path_quota(rr, path);
    xqc_uint_t mss = xqc_conn_get_mss(conn);
    unsigned int segments;

    if (quota == NULL) {
        return;
    }

    if (mss == 0) {
        mss = XQC_PACKET_OUT_SIZE;
    }

    segments = (packet_out->po_used_size + mss - 1) / mss;
    if (segments == 0) {
        segments = 1;
    }

    if (segments > 255 - *quota) {
        *quota = 255;

    } else {
        *quota += segments;
    }
}

xqc_path_ctx_t *
xqc_rr_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, int check_cwnd,
    int reinject, xqc_bool_t *cc_blocked)
{
    xqc_rr_scheduler_t *rr = (xqc_rr_scheduler_t *) scheduler;
    xqc_scheduler_observation_t observation;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path, *chosen = NULL;
    unsigned char *quota;
    unsigned char split = rr->num_segments;
    uint32_t eligible = 0, full = 0;
    xqc_bool_t path_can_send;
    xqc_bool_t reached_cwnd_check = XQC_FALSE;
    int do_cwnd_check = check_cwnd && rr->cwnd_limited;

    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }

    xqc_scheduler_observation_init(&observation, "roundrobin", conn,
        conn->user_data, packet_out->po_pkt.pkt_num, packet_out->po_used_size);
    observation.ts_us = xqc_monotonic_timestamp();

retry:
    eligible = 0;
    full = 0;
    chosen = NULL;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        path_can_send = XQC_FALSE;

        if (observation.path_count < XQC_SCHED_OBS_MAX_PATHS) {
            xqc_scheduler_observe_path(&observation, path, 0, xqc_path_get_perf_class(path));
        }

        if (!xqc_rr_path_can_be_used(path, packet_out, reinject)) {
            goto skip_path;
        }

        if (!reached_cwnd_check) {
            reached_cwnd_check = XQC_TRUE;
            if (cc_blocked) {
                *cc_blocked = XQC_TRUE;
            }
        }

        path_can_send = xqc_scheduler_check_path_can_send(path, packet_out, do_cwnd_check);
        if (observation.path_count > 0
            && observation.paths[observation.path_count - 1].path_id == path->path_id)
        {
            observation.paths[observation.path_count - 1].can_send = path_can_send;
        }

        if (!path_can_send) {
            goto skip_path;
        }

        eligible++;
        quota = xqc_rr_path_quota(rr, path);
        if (quota == NULL) {
            if (chosen == NULL) {
                chosen = path;
            }
            goto skip_path;
        }

        if (*quota > 0 && *quota < rr->num_segments) {
            split = rr->num_segments - *quota;
            chosen = path;
            goto found;
        }

        if (*quota == 0 && chosen == NULL) {
            split = rr->num_segments;
            chosen = path;
        }

        if (*quota >= rr->num_segments) {
            full++;
        }

skip_path:
        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|rr_path|conn:%p|path_id:%ui|quota:%d|can_send:%d|"
                "reinj:%d|pkt_path_id:%ui|chosen:%i|",
                conn, path->path_id,
                path->path_id < XQC_MAX_PATHS_COUNT ? rr->quota[path->path_id] : -1,
                path_can_send, reinject, packet_out->po_path_id,
                chosen ? chosen->path_id : -1);
    }

    if (eligible > 0 && eligible == full) {
        xqc_rr_reset_round(rr, conn, packet_out, reinject);
        observation.path_count = 0;
        goto retry;
    }

found:
    if (chosen != NULL) {
        xqc_rr_charge_quota(rr, conn, chosen, packet_out);
        if (cc_blocked) {
            *cc_blocked = XQC_FALSE;
        }

        observation.has_selected_path = 1;
        observation.selected_path_id = chosen->path_id;
        xqc_scheduler_notify_observer(&observation);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|rr_best_path:%ui|frame_type:%s|"
                "pn:%ui|size:%ud|split:%d|quota:%d|reinj:%d|",
                chosen->path_id, xqc_frame_type_2_str(conn->engine, packet_out->po_frame_types),
                packet_out->po_pkt.pkt_num, packet_out->po_used_size, split,
                chosen->path_id < XQC_MAX_PATHS_COUNT ? rr->quota[chosen->path_id] : -1,
                reinject);
        return chosen;
    }

    xqc_scheduler_notify_observer(&observation);
    xqc_log(conn->log, XQC_LOG_DEBUG, "|rr_no_available_path|conn:%p|", conn);
    return NULL;
}

const xqc_scheduler_callback_t xqc_rr_scheduler_cb = {
    .xqc_scheduler_size             = xqc_rr_scheduler_size,
    .xqc_scheduler_init             = xqc_rr_scheduler_init,
    .xqc_scheduler_get_path         = xqc_rr_scheduler_get_path,
};
