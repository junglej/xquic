/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_SCHEDULER_MAC_AWARE_H_INCLUDED_
#define _XQC_SCHEDULER_MAC_AWARE_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>
#include "src/transport/monitor/xqc_wifi_monitor.h"
#include <stddef.h>

extern const xqc_scheduler_callback_t xqc_mac_aware_scheduler_cb;

xqc_path_ctx_t *xqc_mac_aware_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, int check_cwnd,
    int reinject, xqc_bool_t *cc_blocked);

xqc_path_ctx_t *xqc_mac_aware_offset_owner_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, int check_cwnd,
    xqc_bool_t *cc_blocked, xqc_bool_t *handled);

xqc_path_ctx_t *xqc_mac_aware_stream_budget_get_path(void *scheduler,
    xqc_connection_t *conn, size_t payload_left, uint64_t *budget_bytes);

xqc_path_ctx_t *xqc_mac_aware_path_intent_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, int check_cwnd,
    xqc_bool_t *cc_blocked, xqc_bool_t *handled);

xqc_bool_t xqc_mac_aware_stream_generation_enabled(xqc_connection_t *conn);

int xqc_mac_aware_scheduler_get_path_state(void *conn_user_data,
    uint64_t path_id, uint64_t now, xqc_wifi_state_snapshot_t *snapshot,
    xqc_bool_t *high_risk, uint8_t *risk_reason_bits);

XQC_EXPORT_PUBLIC_API
void xqc_mac_aware_scheduler_update_path_state(void *conn_user_data,
    uint64_t path_id, const xqc_wifi_state_snapshot_t *snapshot);

XQC_EXPORT_PUBLIC_API
void xqc_mac_aware_scheduler_clear_conn_state(void *conn_user_data);

#endif /* _XQC_SCHEDULER_MAC_AWARE_H_INCLUDED_ */
