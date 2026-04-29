#ifndef _XQC_SCHEDULER_COMMON_H_INCLUDED_
#define _XQC_SCHEDULER_COMMON_H_INCLUDED_

#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include "src/transport/scheduler/xqc_scheduler_observer.h"

xqc_bool_t xqc_scheduler_check_path_can_send(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out, int check_cwnd);

xqc_bool_t xqc_scheduler_path_is_usable(xqc_path_ctx_t *path);

xqc_bool_t xqc_scheduler_path_is_standby(xqc_path_ctx_t *path);

xqc_bool_t xqc_scheduler_packet_redundancy_allowed(xqc_packet_out_t *packet_out);

uint64_t xqc_scheduler_packet_path_mask(xqc_connection_t *conn, xqc_packet_out_t *packet_out);

xqc_bool_t xqc_scheduler_packet_has_path(xqc_connection_t *conn, xqc_packet_out_t *packet_out, uint64_t path_id);

xqc_bool_t xqc_scheduler_has_unsent_usable_path(xqc_connection_t *conn, xqc_packet_out_t *packet_out);

void xqc_scheduler_observe_path(xqc_scheduler_observation_t *observation, xqc_path_ctx_t *path,
    uint8_t can_send, uint8_t path_class);

#endif
