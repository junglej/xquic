#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_reinjection.h"

xqc_bool_t
xqc_scheduler_check_path_can_send(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out, int check_cwnd)
{
    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    uint32_t schedule_bytes = path->path_schedule_bytes;

    /* normal packets in send list will be blocked by cc */
    if (check_cwnd && (!xqc_send_packet_cwnd_allows(send_ctl, packet_out, schedule_bytes, 0)))
    {
        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|path:%ui|blocked by cwnd|", path->path_id);
        return XQC_FALSE;
    }

    return XQC_TRUE;
}

xqc_bool_t
xqc_scheduler_path_is_usable(xqc_path_ctx_t *path)
{
    return path != NULL
           && path->path_state == XQC_PATH_STATE_ACTIVE
           && path->app_path_status != XQC_APP_PATH_STATUS_FROZEN;
}

xqc_bool_t
xqc_scheduler_path_is_standby(xqc_path_ctx_t *path)
{
    return path != NULL && path->app_path_status == XQC_APP_PATH_STATUS_STANDBY;
}

xqc_bool_t
xqc_scheduler_packet_redundancy_allowed(xqc_packet_out_t *packet_out)
{
    xqc_frame_type_bit_t eligible_frames;

    if (packet_out == NULL || packet_out->po_flag & XQC_POF_NOT_REINJECT) {
        return XQC_FALSE;
    }

    if (packet_out->po_flag & XQC_POF_REINJECTED_REPLICA) {
        return XQC_FALSE;
    }

    if (packet_out->po_frame_types & (XQC_FRAME_BIT_REPAIR_SYMBOL
                                      | XQC_FRAME_BIT_PATH_CHALLENGE
                                      | XQC_FRAME_BIT_PATH_RESPONSE
                                      | XQC_FRAME_BIT_PATH_ABANDON
                                      | XQC_FRAME_BIT_PATH_STATUS
                                      | XQC_FRAME_BIT_PATH_STANDBY
                                      | XQC_FRAME_BIT_PATH_AVAILABLE
                                      | XQC_FRAME_BIT_PATH_FROZEN
                                      | XQC_FRAME_BIT_MP_NEW_CONNECTION_ID
                                      | XQC_FRAME_BIT_MP_RETIRE_CONNECTION_ID
                                      | XQC_FRAME_BIT_MAX_PATH_ID))
    {
        return XQC_FALSE;
    }

    eligible_frames = XQC_FRAME_BIT_STREAM
                      | XQC_FRAME_BIT_RESET_STREAM
                      | XQC_FRAME_BIT_STOP_SENDING
                      | XQC_FRAME_BIT_MAX_DATA
                      | XQC_FRAME_BIT_MAX_STREAM_DATA
                      | XQC_FRAME_BIT_MAX_STREAMS
                      | XQC_FRAME_BIT_DATA_BLOCKED
                      | XQC_FRAME_BIT_STREAM_DATA_BLOCKED
                      | XQC_FRAME_BIT_STREAMS_BLOCKED;

    return (packet_out->po_frame_types & eligible_frames) ? XQC_TRUE : XQC_FALSE;
}

static xqc_packet_out_t *
xqc_scheduler_packet_root(xqc_packet_out_t *packet_out)
{
    return packet_out != NULL && packet_out->po_origin != NULL
           ? packet_out->po_origin : packet_out;
}

static xqc_bool_t
xqc_scheduler_packets_share_root(xqc_packet_out_t *a, xqc_packet_out_t *b)
{
    return xqc_scheduler_packet_root(a) == xqc_scheduler_packet_root(b);
}

static void
xqc_scheduler_add_packet_path_to_mask(xqc_packet_out_t *candidate,
    xqc_packet_out_t *packet_out, uint64_t *mask)
{
    if (candidate == NULL || packet_out == NULL || mask == NULL) {
        return;
    }

    if (!xqc_scheduler_packets_share_root(candidate, packet_out)) {
        return;
    }

    if (candidate->po_path_id < 64) {
        *mask |= (1ULL << candidate->po_path_id);
    }
}

static void
xqc_scheduler_scan_packet_list_for_paths(xqc_list_head_t *head,
    xqc_packet_out_t *packet_out, uint64_t *mask)
{
    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *candidate;

    xqc_list_for_each_safe(pos, next, head) {
        candidate = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        xqc_scheduler_add_packet_path_to_mask(candidate, packet_out, mask);
    }
}

uint64_t
xqc_scheduler_packet_path_mask(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    uint64_t mask = 0;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_send_type_t send_type;

    if (conn == NULL || packet_out == NULL) {
        return 0;
    }

    if (packet_out->po_path_id < 64) {
        mask |= (1ULL << packet_out->po_path_id);
    }

    xqc_scheduler_scan_packet_list_for_paths(
        &conn->conn_send_queue->sndq_unacked_packets[XQC_PNS_APP_DATA],
        packet_out, &mask);
    xqc_scheduler_scan_packet_list_for_paths(
        &conn->conn_send_queue->sndq_send_packets_high_pri,
        packet_out, &mask);
    xqc_scheduler_scan_packet_list_for_paths(
        &conn->conn_send_queue->sndq_send_packets,
        packet_out, &mask);

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        xqc_scheduler_scan_packet_list_for_paths(&path->path_reinj_tmp_buf,
            packet_out, &mask);

        for (send_type = XQC_SEND_TYPE_NORMAL; send_type < XQC_SEND_TYPE_N; send_type++) {
            xqc_scheduler_scan_packet_list_for_paths(&path->path_schedule_buf[send_type],
                packet_out, &mask);
        }
    }

    return mask;
}

xqc_bool_t
xqc_scheduler_packet_has_path(xqc_connection_t *conn, xqc_packet_out_t *packet_out, uint64_t path_id)
{
    uint64_t mask;

    if (path_id >= 64) {
        return XQC_FALSE;
    }

    mask = xqc_scheduler_packet_path_mask(conn, packet_out);
    return (mask & (1ULL << path_id)) ? XQC_TRUE : XQC_FALSE;
}

xqc_bool_t
xqc_scheduler_has_unsent_usable_path(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    uint64_t used_mask;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;

    if (conn == NULL || packet_out == NULL) {
        return XQC_FALSE;
    }

    used_mask = xqc_scheduler_packet_path_mask(conn, packet_out);

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (!xqc_scheduler_path_is_usable(path) || path->path_id >= 64) {
            continue;
        }

        if ((used_mask & (1ULL << path->path_id)) == 0) {
            return XQC_TRUE;
        }
    }

    return XQC_FALSE;
}

void
xqc_scheduler_observe_path(xqc_scheduler_observation_t *observation, xqc_path_ctx_t *path,
    uint8_t can_send, uint8_t path_class)
{
    if (observation == NULL || path == NULL || path->path_send_ctl == NULL) {
        return;
    }

    xqc_scheduler_observation_append_path(observation, path->path_id,
        xqc_send_ctl_get_srtt(path->path_send_ctl),
        path->path_send_ctl->ctl_cong_callback->
            xqc_cong_ctl_get_cwnd(path->path_send_ctl->ctl_cong),
        path->path_send_ctl->ctl_bytes_in_flight, can_send,
        path->path_state, path->app_path_status, path_class);
}
