/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_CUBIC_H_INCLUDED_
#define _XQC_CUBIC_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_packet_out.h"

typedef enum {
    XQC_CUBIC_STATE_HYSTART = 0,
    XQC_CUBIC_STATE_STEADY,
    XQC_CUBIC_STATE_FAST_RECOVERY,
} xqc_cubic_state_t;

typedef enum {
    XQC_CUBIC_HYSTART_FOUND_NO = 0,
    XQC_CUBIC_HYSTART_FOUND_ACK_TRAIN,
    XQC_CUBIC_HYSTART_FOUND_DELAY,
} xqc_cubic_hystart_found_t;

typedef struct {
    uint32_t        min_cwnd;
    uint64_t        max_cwnd;
    uint64_t        init_cwnd;
    uint64_t        cwnd;
    uint64_t        ssthresh;

    xqc_cubic_state_t          state;

    xqc_usec_t                 recovery_end_time;
    uint8_t                    recovery_end_time_valid;

    uint8_t                    hystart_ack_train;
    uint8_t                    hystart_in_round;
    xqc_cubic_hystart_found_t  hystart_found;
    xqc_usec_t                 hystart_round_start;
    xqc_usec_t                 hystart_last_jiffy;
    xqc_usec_t                 hystart_curr_sampled_rtt;
    xqc_usec_t                 hystart_last_sampled_rtt;
    xqc_usec_t                 hystart_delay_min;
    xqc_usec_t                 hystart_round_end_time;
    uint8_t                    hystart_curr_sampled_rtt_valid;
    uint8_t                    hystart_last_sampled_rtt_valid;
    uint8_t                    hystart_delay_min_valid;
    uint8_t                    hystart_ack_count;

    double                     steady_time_to_origin;
    uint64_t                   steady_origin_point;
    uint8_t                    steady_origin_point_valid;
    uint64_t                   steady_last_max_cwnd;
    uint8_t                    steady_last_max_cwnd_valid;
    xqc_usec_t                 steady_last_reduction_time;
    uint8_t                    steady_last_reduction_time_valid;
    uint64_t                   steady_est_reno_cwnd;
    uint8_t                    steady_tcp_friendly;
    uint8_t                    steady_additive_after_hystart;

    xqc_usec_t                 quiescence_start;
    uint8_t                    quiescence_start_valid;

    xqc_send_ctl_t *ctl_ctx;
} xqc_cubic_t;

const char *xqc_cubic_semantics(void);

extern const xqc_cong_ctrl_callback_t xqc_cubic_cb;

#endif /* _XQC_CUBIC_H_INCLUDED_ */
