/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/transport/scheduler/xqc_scheduler_xlink.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/scheduler/xqc_scheduler_observer.h"
#include "src/transport/xqc_send_ctl.h"


static size_t
xqc_xlink_scheduler_size()
{
    return 0;
}

static void
xqc_xlink_scheduler_init(void *scheduler, xqc_log_t *log,
    xqc_scheduler_params_t *param)
{
    return;
}

static void
xqc_xlink_observation_set_can_send(xqc_scheduler_observation_t *observation,
    uint64_t path_id, xqc_bool_t can_send)
{
    uint8_t i;

    if (observation == NULL) {
        return;
    }

    for (i = 0; i < observation->path_count; i++) {
        if (observation->paths[i].path_id == path_id) {
            observation->paths[i].can_send = can_send;
            return;
        }
    }
}

xqc_path_ctx_t *
xqc_xlink_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, int check_cwnd,
    int reinject, xqc_bool_t *cc_blocked)
{
    xqc_path_ctx_t *best_path[XQC_PATH_CLASS_PERF_CLASS_SIZE];
    xqc_scheduler_observation_t observation;
    xqc_path_perf_class_t path_class;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_bool_t reached_cwnd_check = XQC_FALSE;
    xqc_bool_t path_can_send;
    uint64_t path_srtt;

    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }

    xqc_scheduler_observation_init(&observation, "xlink", conn,
        conn->user_data, packet_out->po_pkt.pkt_num, packet_out->po_used_size);
    observation.ts_us = xqc_monotonic_timestamp();

    for (path_class = XQC_PATH_CLASS_AVAILABLE_HIGH;
         path_class < XQC_PATH_CLASS_PERF_CLASS_SIZE;
         path_class++)
    {
        best_path[path_class] = NULL;
    }

    if (reinject && !xqc_scheduler_packet_redundancy_allowed(packet_out)) {
        xqc_scheduler_notify_observer(&observation);
        return NULL;
    }

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        path_class = xqc_path_get_perf_class(path);
        path_can_send = XQC_FALSE;
        path_srtt = 0;

        xqc_scheduler_observe_path(&observation, path, 0, path_class);

        if (!xqc_scheduler_path_is_usable(path)) {
            goto skip_path;
        }

        if (reinject
            && xqc_scheduler_packet_has_path(conn, packet_out, path->path_id))
        {
            goto skip_path;
        }

        reached_cwnd_check = XQC_TRUE;
        if (cc_blocked) {
            *cc_blocked = XQC_TRUE;
        }

        path_can_send = xqc_scheduler_check_path_can_send(path, packet_out,
                                                          check_cwnd);
        xqc_xlink_observation_set_can_send(&observation, path->path_id,
                                           path_can_send);
        if (!path_can_send) {
            goto skip_path;
        }

        if (cc_blocked) {
            *cc_blocked = XQC_FALSE;
        }

        path_srtt = xqc_send_ctl_get_srtt(path->path_send_ctl);
        if (best_path[path_class] == NULL
            || path_srtt < xqc_send_ctl_get_srtt(best_path[path_class]->path_send_ctl))
        {
            best_path[path_class] = path;
        }

skip_path:
        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|xlink_path|conn:%p|path_id:%ui|path_srtt:%ui|path_class:%d|"
                "can_send:%d|path_status:%d|path_state:%d|reinj:%d|"
                "pkt_path_id:%ui|best_path:%i|",
                conn, path->path_id, path_srtt, path_class, path_can_send,
                path->app_path_status, path->path_state, reinject,
                packet_out->po_path_id,
                best_path[path_class] ? best_path[path_class]->path_id : -1);
    }

    for (path_class = XQC_PATH_CLASS_AVAILABLE_HIGH;
         path_class < XQC_PATH_CLASS_PERF_CLASS_SIZE;
         path_class++)
    {
        if (best_path[path_class] != NULL) {
            observation.has_selected_path = 1;
            observation.selected_path_id = best_path[path_class]->path_id;
            xqc_scheduler_notify_observer(&observation);
            xqc_log(conn->log, XQC_LOG_DEBUG, "|xlink_best_path:%ui|"
                    "frame_type:%s|pn:%ui|size:%ud|reinj:%d|path_class:%d|"
                    "used_mask:%ui|",
                    best_path[path_class]->path_id,
                    xqc_frame_type_2_str(conn->engine, packet_out->po_frame_types),
                    packet_out->po_pkt.pkt_num,
                    packet_out->po_used_size, reinject, path_class,
                    xqc_scheduler_packet_path_mask(conn, packet_out));
            return best_path[path_class];
        }
    }

    if (cc_blocked && !reached_cwnd_check) {
        *cc_blocked = XQC_FALSE;
    }

    xqc_scheduler_notify_observer(&observation);
    xqc_log(conn->log, XQC_LOG_DEBUG, "|xlink_no_available_path|conn:%p|"
            "reinj:%d|", conn, reinject);
    return NULL;
}

const xqc_scheduler_callback_t xquic_scheduler_xlink = {
    .xqc_scheduler_size             = xqc_xlink_scheduler_size,
    .xqc_scheduler_init             = xqc_xlink_scheduler_init,
    .xqc_scheduler_get_path         = xqc_xlink_scheduler_get_path,
};
