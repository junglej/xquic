#include "src/transport/xqc_transport_trace.h"

#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_utils.h"

#include <string.h>

static xqc_transport_trace_observer_pt g_xqc_transport_trace_observer = NULL;
static void *g_xqc_transport_trace_observer_user_data = NULL;

void
xqc_transport_trace_register_observer(
    xqc_transport_trace_observer_pt observer, void *user_data)
{
    g_xqc_transport_trace_observer = observer;
    g_xqc_transport_trace_observer_user_data = user_data;
}

void
xqc_transport_trace_unregister_observer(void)
{
    g_xqc_transport_trace_observer = NULL;
    g_xqc_transport_trace_observer_user_data = NULL;
}

int
xqc_transport_trace_enabled(void)
{
    return g_xqc_transport_trace_observer != NULL;
}

void
xqc_transport_trace_observation_init(
    xqc_transport_trace_observation_t *observation, const char *event,
    const char *reason)
{
    if (observation == NULL) {
        return;
    }

    memset(observation, 0, sizeof(*observation));
    observation->ts_us = xqc_monotonic_timestamp();
    observation->event = event ? event : "-";
    observation->reason = reason ? reason : "-";
}

void
xqc_transport_trace_fill_conn(
    xqc_transport_trace_observation_t *observation, xqc_connection_t *conn)
{
    if (observation == NULL || conn == NULL) {
        return;
    }

    observation->conn = conn;
    observation->conn_user_data = conn->user_data;
}

void
xqc_transport_trace_fill_send_ctl(
    xqc_transport_trace_observation_t *observation, xqc_send_ctl_t *send_ctl)
{
    if (observation == NULL || send_ctl == NULL) {
        return;
    }

    xqc_transport_trace_fill_conn(observation, send_ctl->ctl_conn);
    if (send_ctl->ctl_path != NULL) {
        observation->has_path = 1;
        observation->path_id = send_ctl->ctl_path->path_id;
        observation->path_schedule_bytes_after =
            send_ctl->ctl_path->path_schedule_bytes;
    }

    if (send_ctl->ctl_cong_callback != NULL
        && send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd != NULL)
    {
        observation->cwnd_bytes =
            send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(
                send_ctl->ctl_cong);
    }
    observation->bytes_in_flight = send_ctl->ctl_bytes_in_flight;
    observation->pacing_rate_bytes_per_s =
        xqc_send_ctl_get_pacing_rate(send_ctl);
    observation->pacing_budget_bytes = send_ctl->ctl_pacing.bytes_budget;
    observation->pacing_on = send_ctl->ctl_pacing.pacing_on ? 1 : 0;
    observation->app_limited = send_ctl->ctl_app_limited > 0 ? 1 : 0;
    observation->delivered_bytes = send_ctl->ctl_delivered;
    observation->lost_pkts = send_ctl->ctl_lost_pkts_number;
    observation->srtt_us = send_ctl->ctl_srtt;
    observation->latest_rtt_us = send_ctl->ctl_latest_rtt;
    observation->bandwidth_bytes_per_s = xqc_send_ctl_get_est_bw(send_ctl);
}

void
xqc_transport_trace_fill_packet(
    xqc_transport_trace_observation_t *observation,
    xqc_packet_out_t *packet_out)
{
    if (observation == NULL || packet_out == NULL) {
        return;
    }

    observation->packet_size = packet_out->po_used_size;
    observation->po_cc_size = packet_out->po_cc_size;
    observation->packet_number = packet_out->po_pkt.pkt_num;
    observation->pkt_type = packet_out->po_pkt.pkt_type;
    observation->frame_types = packet_out->po_frame_types;
    observation->stream_id = packet_out->po_stream_id;
    observation->stream_offset = packet_out->po_stream_offset;
}

void
xqc_transport_trace_notify(
    const xqc_transport_trace_observation_t *observation)
{
    if (g_xqc_transport_trace_observer == NULL || observation == NULL) {
        return;
    }

    g_xqc_transport_trace_observer(observation,
        g_xqc_transport_trace_observer_user_data);
}
