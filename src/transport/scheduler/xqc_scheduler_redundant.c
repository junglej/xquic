/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/transport/scheduler/xqc_scheduler_redundant.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/scheduler/xqc_scheduler_observer.h"
#include "src/transport/xqc_send_ctl.h"

typedef struct {
    uint64_t    next_path_id;
} xqc_redundant_scheduler_t;

static size_t
xqc_redundant_scheduler_size()
{
    return sizeof(xqc_redundant_scheduler_t);
}

static void
xqc_redundant_scheduler_init(void *scheduler, xqc_log_t *log, xqc_scheduler_params_t *param)
{
    xqc_redundant_scheduler_t *red = (xqc_redundant_scheduler_t *) scheduler;

    red->next_path_id = 0;
}

static void
xqc_redundant_observation_set_can_send(xqc_scheduler_observation_t *observation,
    uint64_t path_id, xqc_bool_t can_send)
{
    uint8_t i;

    for (i = 0; i < observation->path_count; i++) {
        if (observation->paths[i].path_id == path_id) {
            observation->paths[i].can_send = can_send;
            return;
        }
    }
}

static xqc_bool_t
xqc_redundant_path_matches_pass(xqc_path_ctx_t *path, int standby_pass)
{
    if (standby_pass) {
        return xqc_scheduler_path_is_standby(path);
    }

    return !xqc_scheduler_path_is_standby(path);
}

static xqc_path_ctx_t *
xqc_redundant_pick_in_pass(xqc_redundant_scheduler_t *red,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out,
    xqc_scheduler_observation_t *observation, int check_cwnd, int reinject,
    int standby_pass, xqc_bool_t *reached_cwnd_check)
{
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path, *fallback = NULL;
    xqc_bool_t path_can_send;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        if (!xqc_scheduler_path_is_usable(path)
            || !xqc_redundant_path_matches_pass(path, standby_pass))
        {
            continue;
        }

        if (reinject && xqc_scheduler_packet_has_path(conn, packet_out, path->path_id)) {
            continue;
        }

        *reached_cwnd_check = XQC_TRUE;
        path_can_send = xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd);
        xqc_redundant_observation_set_can_send(observation, path->path_id, path_can_send);
        if (!path_can_send) {
            continue;
        }

        if (path->path_id >= red->next_path_id) {
            return path;
        }

        if (fallback == NULL) {
            fallback = path;
        }
    }

    return fallback;
}

xqc_path_ctx_t *
xqc_redundant_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, int check_cwnd,
    int reinject, xqc_bool_t *cc_blocked)
{
    xqc_redundant_scheduler_t *red = (xqc_redundant_scheduler_t *) scheduler;
    xqc_scheduler_observation_t observation;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path, *chosen = NULL;
    xqc_bool_t reached_cwnd_check = XQC_FALSE;

    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }

    xqc_scheduler_observation_init(&observation, "redundant", conn,
        conn->user_data, packet_out->po_pkt.pkt_num, packet_out->po_used_size);
    observation.ts_us = xqc_monotonic_timestamp();

    if (!reinject) {
        red->next_path_id = 0;
    }

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        xqc_scheduler_observe_path(&observation, path, 0, xqc_path_get_perf_class(path));
    }

    chosen = xqc_redundant_pick_in_pass(red, conn, packet_out, &observation,
        check_cwnd, reinject, 0, &reached_cwnd_check);
    if (chosen == NULL) {
        chosen = xqc_redundant_pick_in_pass(red, conn, packet_out, &observation,
            check_cwnd, reinject, 1, &reached_cwnd_check);
    }

    if (chosen != NULL) {
        red->next_path_id = chosen->path_id + 1;
        if (cc_blocked) {
            *cc_blocked = XQC_FALSE;
        }

        observation.has_selected_path = 1;
        observation.selected_path_id = chosen->path_id;
        xqc_scheduler_notify_observer(&observation);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|redundant_best_path:%ui|frame_type:%s|"
                "pn:%ui|size:%ud|reinj:%d|used_mask:%ui|",
                chosen->path_id, xqc_frame_type_2_str(conn->engine, packet_out->po_frame_types),
                packet_out->po_pkt.pkt_num, packet_out->po_used_size, reinject,
                xqc_scheduler_packet_path_mask(conn, packet_out));
        return chosen;
    }

    if (cc_blocked && reached_cwnd_check) {
        *cc_blocked = XQC_TRUE;
    }

    xqc_scheduler_notify_observer(&observation);
    xqc_log(conn->log, XQC_LOG_DEBUG, "|redundant_no_available_path|conn:%p|reinj:%d|", conn, reinject);
    return NULL;
}

const xqc_scheduler_callback_t xqc_redundant_scheduler_cb = {
    .xqc_scheduler_size             = xqc_redundant_scheduler_size,
    .xqc_scheduler_init             = xqc_redundant_scheduler_init,
    .xqc_scheduler_get_path         = xqc_redundant_scheduler_get_path,
};
