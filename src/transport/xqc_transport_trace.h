#ifndef _XQC_TRANSPORT_TRACE_H_INCLUDED_
#define _XQC_TRANSPORT_TRACE_H_INCLUDED_

#include <stdint.h>
#include <xquic/xquic_typedef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct xqc_transport_trace_observation_s {
    uint64_t        ts_us;
    void           *conn;
    void           *conn_user_data;
    const char     *event;
    const char     *reason;

    uint8_t         has_path;
    uint64_t        path_id;
    uint64_t        stream_id;
    uint64_t        stream_offset;
    uint64_t        stream_bytes;

    uint64_t        packet_size;
    uint64_t        po_cc_size;
    uint64_t        packet_number;
    uint32_t        pkt_type;
    uint64_t        frame_types;
    uint32_t        send_type;

    uint64_t        schedule_bytes;
    uint64_t        path_schedule_bytes_before;
    uint64_t        path_schedule_bytes_after;

    uint64_t        cwnd_bytes;
    uint64_t        bytes_in_flight;
    uint64_t        pacing_rate_bytes_per_s;
    uint64_t        pacing_budget_bytes;
    uint8_t         pacing_on;
    uint8_t         cwnd_allowed;
    uint8_t         pacing_allowed;
    uint8_t         cc_allowed;

    uint8_t         app_limited;
    uint32_t        sample_type;
    uint8_t         sample_valid;
    uint64_t        acked_bytes;
    uint64_t        delivered_bytes;
    uint64_t        lost_pkts;
    uint64_t        srtt_us;
    uint64_t        latest_rtt_us;
    uint64_t        bandwidth_bytes_per_s;
    uint64_t        rate_sample_bytes_per_s;
} xqc_transport_trace_observation_t;

typedef void (*xqc_transport_trace_observer_pt)(
    const xqc_transport_trace_observation_t *observation,
    void *user_data);

void xqc_transport_trace_register_observer(
    xqc_transport_trace_observer_pt observer, void *user_data);

void xqc_transport_trace_unregister_observer(void);

int xqc_transport_trace_enabled(void);

void xqc_transport_trace_observation_init(
    xqc_transport_trace_observation_t *observation, const char *event,
    const char *reason);

void xqc_transport_trace_fill_conn(
    xqc_transport_trace_observation_t *observation, xqc_connection_t *conn);

void xqc_transport_trace_fill_send_ctl(
    xqc_transport_trace_observation_t *observation, xqc_send_ctl_t *send_ctl);

void xqc_transport_trace_fill_packet(
    xqc_transport_trace_observation_t *observation,
    xqc_packet_out_t *packet_out);

void xqc_transport_trace_notify(
    const xqc_transport_trace_observation_t *observation);

#ifdef __cplusplus
}
#endif

#endif
