/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 *
 * CUBIC based on RFC 8312.
 *
 * This is a C-port of Meta mvfst QuicCubic default semantics (MIT License),
 * using XQUIC's congestion-control callback interface. Source reference:
 * facebook/mvfst QuicCubic at commit 8b9c11029dfad67f33335c919d092c718bc0f6cd.
 */

#include "src/congestion_control/xqc_cubic.h"
#include "src/common/xqc_config.h"
#include <math.h>

#define XQC_CUBIC_MSS                         XQC_MSS
#define XQC_CUBIC_INIT_CWND_MSS               10
#define XQC_CUBIC_MIN_CWND_MSS                2
#define XQC_CUBIC_MAX_CWND_MSS                2000
#define XQC_CUBIC_MAX_SSTHRESH                XQC_MAX_UINT64_VALUE

#define XQC_CUBIC_HYSTART_ACKS                8
#define XQC_CUBIC_HYSTART_LOW_CWND_MSS        16
#define XQC_CUBIC_HYSTART_ACK_TRAIN_GAP       2
#define XQC_CUBIC_HYSTART_DELAY_MIN           4000
#define XQC_CUBIC_HYSTART_DELAY_MAX           16000

#define XQC_CUBIC_TIME_SCALING_FACTOR         0.4
#define XQC_CUBIC_REDUCTION_FACTOR            0.7
#define XQC_CUBIC_LAST_MAX_REDUCTION_FACTOR   0.85
#define XQC_CUBIC_TCP_FRIENDLY_FACTOR         \
    (3.0 * (1.0 - XQC_CUBIC_REDUCTION_FACTOR) / (1.0 + XQC_CUBIC_REDUCTION_FACTOR))

#define XQC_CUBIC_PACING_GAIN_STEADY          100
#define XQC_CUBIC_PACING_GAIN_HYSTART         200
#define XQC_CUBIC_PACING_GAIN_RECOVERY        125

#define XQC_CUBIC_MVFST_SEMANTICS              "mvfst_default"
#define XQC_CUBIC_MVFST_SOURCE_COMMIT          "8b9c11029dfad67f33335c919d092c718bc0f6cd"
#define XQC_CUBIC_MVFST_ONLY_GROW_WHEN_LIMITED 0
#define XQC_CUBIC_MVFST_ENABLE_ACK_TRAIN       0
#define XQC_CUBIC_MVFST_ADDITIVE_AFTER_HYSTART 0
#define XQC_CUBIC_MVFST_TCP_FRIENDLY           1

const char *
xqc_cubic_semantics(void)
{
    return XQC_CUBIC_MVFST_SEMANTICS
           "|source=facebook/mvfst@"
           XQC_CUBIC_MVFST_SOURCE_COMMIT
           "|tcp_friendly=1"
           "|ack_train=0"
           "|additive_after_hystart=0"
           "|only_grow_when_limited=0";
}

static uint64_t
xqc_cubic_bound_cwnd(xqc_cubic_t *cubic, uint64_t cwnd)
{
    cwnd = xqc_max(cwnd, cubic->min_cwnd);
    cwnd = xqc_min(cwnd, cubic->max_cwnd);
    return cwnd;
}


static void
xqc_cubic_reset_hystart(xqc_cubic_t *cubic)
{
    cubic->hystart_in_round = 0;
    cubic->hystart_found = XQC_CUBIC_HYSTART_FOUND_NO;
    cubic->hystart_round_start = 0;
    cubic->hystart_last_jiffy = 0;
    cubic->hystart_curr_sampled_rtt = 0;
    cubic->hystart_last_sampled_rtt = 0;
    cubic->hystart_delay_min = 0;
    cubic->hystart_round_end_time = 0;
    cubic->hystart_curr_sampled_rtt_valid = 0;
    cubic->hystart_last_sampled_rtt_valid = 0;
    cubic->hystart_delay_min_valid = 0;
    cubic->hystart_ack_count = 0;
}


static void
xqc_cubic_start_hystart_round(xqc_cubic_t *cubic, xqc_usec_t now)
{
    cubic->hystart_round_start = now;
    cubic->hystart_last_jiffy = now;
    cubic->hystart_ack_count = 0;

    cubic->hystart_last_sampled_rtt = cubic->hystart_curr_sampled_rtt;
    cubic->hystart_last_sampled_rtt_valid =
        cubic->hystart_curr_sampled_rtt_valid;
    cubic->hystart_curr_sampled_rtt = 0;
    cubic->hystart_curr_sampled_rtt_valid = 0;

    cubic->hystart_round_end_time = now;
    cubic->hystart_in_round = 1;
    cubic->hystart_found = XQC_CUBIC_HYSTART_FOUND_NO;
}


static xqc_usec_t
xqc_cubic_hystart_delay_threshold(xqc_usec_t last_sampled_rtt)
{
    xqc_usec_t eta = last_sampled_rtt >> 4;
    eta = xqc_max(eta, XQC_CUBIC_HYSTART_DELAY_MIN);
    eta = xqc_min(eta, XQC_CUBIC_HYSTART_DELAY_MAX);
    return eta;
}


static void
xqc_cubic_enter_steady_from_hystart(xqc_cubic_t *cubic)
{
    cubic->hystart_in_round = 0;
    cubic->hystart_curr_sampled_rtt_valid = 0;

    if (!cubic->steady_additive_after_hystart) {
        cubic->ssthresh = cubic->cwnd;
    }

    cubic->steady_last_max_cwnd_valid = 0;
    cubic->steady_last_reduction_time_valid = 0;
    cubic->steady_origin_point_valid = 0;
    cubic->quiescence_start_valid = 0;
    cubic->state = XQC_CUBIC_STATE_STEADY;
}


static xqc_bool_t
xqc_cubic_hystart_maybe_exit(xqc_cubic_t *cubic)
{
    uint64_t low_ssthresh = XQC_CUBIC_HYSTART_LOW_CWND_MSS * XQC_CUBIC_MSS;

    if (cubic->cwnd >= cubic->ssthresh) {
        xqc_cubic_enter_steady_from_hystart(cubic);
        return XQC_TRUE;
    }

    if (cubic->hystart_found != XQC_CUBIC_HYSTART_FOUND_NO
        && cubic->cwnd >= low_ssthresh)
    {
        xqc_cubic_enter_steady_from_hystart(cubic);
        return XQC_TRUE;
    }

    return XQC_FALSE;
}


static void
xqc_cubic_update_time_to_origin(xqc_cubic_t *cubic)
{
    if (!cubic->steady_last_max_cwnd_valid) {
        cubic->steady_time_to_origin = 0.0;
        cubic->steady_origin_point = cubic->cwnd;
        cubic->steady_origin_point_valid = 1;
        return;
    }

    if (cubic->steady_last_max_cwnd <= cubic->cwnd) {
        cubic->steady_time_to_origin = 0.0;
        cubic->steady_origin_point = cubic->steady_last_max_cwnd;
        cubic->steady_origin_point_valid = 1;
        return;
    }

    double bytes_to_origin =
        (double)(cubic->steady_last_max_cwnd - cubic->cwnd);

    cubic->steady_time_to_origin =
        cbrt(bytes_to_origin * 1000.0 * 1000.0
             / (double)XQC_CUBIC_MSS
             * (XQC_CUBIC_TIME_SCALING_FACTOR * 1000.0));
    cubic->steady_origin_point = cubic->steady_last_max_cwnd;
    cubic->steady_origin_point_valid = 1;
}


static int64_t
xqc_cubic_calculate_cwnd_delta(xqc_cubic_t *cubic, xqc_usec_t now)
{
    if (!cubic->steady_last_reduction_time_valid
        || now < cubic->steady_last_reduction_time)
    {
        return 0;
    }

    xqc_usec_t elapsed_us = now - cubic->steady_last_reduction_time;
    double elapsed_ms = (double)((elapsed_us + 999) / 1000);
    double offset = elapsed_ms - cubic->steady_time_to_origin;
    double delta = (double)XQC_CUBIC_MSS * XQC_CUBIC_TIME_SCALING_FACTOR
                   * pow(offset, 3.0) / 1000.0 / 1000.0 / 1000.0;

    if (delta >= (double)INT64_MAX) {
        return INT64_MAX;
    }

    if (delta <= (double)INT64_MIN) {
        return INT64_MIN;
    }

    return (int64_t)floor(delta);
}


static uint64_t
xqc_cubic_calculate_cwnd(xqc_cubic_t *cubic, int64_t delta)
{
    uint64_t origin = cubic->steady_last_max_cwnd_valid
                      ? cubic->steady_last_max_cwnd : cubic->cwnd;

    if (delta >= 0) {
        uint64_t inc = (uint64_t)delta;
        if (XQC_MAX_UINT64_VALUE - origin < inc) {
            return cubic->max_cwnd;
        }
        return xqc_cubic_bound_cwnd(cubic, origin + inc);
    }

    if (delta == INT64_MIN || (uint64_t)(-delta) > origin) {
        return cubic->min_cwnd;
    }

    return xqc_cubic_bound_cwnd(cubic, origin - (uint64_t)(-delta));
}


static void
xqc_cubic_cubic_reduction(xqc_cubic_t *cubic, xqc_usec_t loss_time)
{
    if (!cubic->steady_last_max_cwnd_valid
        || cubic->cwnd >= cubic->steady_last_max_cwnd)
    {
        cubic->steady_last_max_cwnd = cubic->cwnd;

    } else {
        cubic->steady_last_max_cwnd =
            (uint64_t)((double)cubic->cwnd * XQC_CUBIC_LAST_MAX_REDUCTION_FACTOR);
    }

    cubic->steady_last_max_cwnd_valid = 1;
    cubic->steady_last_reduction_time = loss_time;
    cubic->steady_last_reduction_time_valid = 1;
    cubic->steady_origin_point_valid = 0;

    cubic->cwnd = xqc_cubic_bound_cwnd(cubic,
        (uint64_t)((double)cubic->cwnd * XQC_CUBIC_REDUCTION_FACTOR));

    if (cubic->steady_tcp_friendly) {
        cubic->steady_est_reno_cwnd = cubic->cwnd;
    }
}


static uint32_t
xqc_cubic_pacing_gain(xqc_cubic_t *cubic)
{
    switch (cubic->state) {
    case XQC_CUBIC_STATE_HYSTART:
        return XQC_CUBIC_PACING_GAIN_HYSTART;

    case XQC_CUBIC_STATE_FAST_RECOVERY:
        return XQC_CUBIC_PACING_GAIN_RECOVERY;

    case XQC_CUBIC_STATE_STEADY:
    default:
        return XQC_CUBIC_PACING_GAIN_STEADY;
    }
}


static void
xqc_cubic_on_ack_hystart(xqc_cubic_t *cubic, xqc_packet_out_t *po,
    uint32_t acked_bytes, xqc_usec_t latest_rtt, xqc_usec_t now)
{
    if (XQC_CUBIC_MVFST_ONLY_GROW_WHEN_LIMITED
        && cubic->ctl_ctx
        && !xqc_send_ctl_is_cwnd_limited(cubic->ctl_ctx))
    {
        return;
    }

    if (!cubic->hystart_in_round) {
        xqc_cubic_start_hystart_round(cubic, now);
    }

    cubic->cwnd = xqc_cubic_bound_cwnd(cubic, cubic->cwnd + acked_bytes);

    if (xqc_cubic_hystart_maybe_exit(cubic)) {
        return;
    }

    if (cubic->hystart_found == XQC_CUBIC_HYSTART_FOUND_NO
        && cubic->hystart_ack_train)
    {
        if (!cubic->hystart_delay_min_valid
            || latest_rtt < cubic->hystart_delay_min)
        {
            cubic->hystart_delay_min = latest_rtt;
            cubic->hystart_delay_min_valid = 1;
        }

        if (now >= cubic->hystart_last_jiffy
            && now - cubic->hystart_last_jiffy <= XQC_CUBIC_HYSTART_ACK_TRAIN_GAP)
        {
            cubic->hystart_last_jiffy = now;
            if (cubic->hystart_delay_min_valid
                && (now - cubic->hystart_round_start) * 2 >= cubic->hystart_delay_min)
            {
                cubic->hystart_found = XQC_CUBIC_HYSTART_FOUND_ACK_TRAIN;
            }
        }
    }

    if (cubic->hystart_found == XQC_CUBIC_HYSTART_FOUND_NO) {
        if (cubic->hystart_ack_count < XQC_CUBIC_HYSTART_ACKS) {
            if (!cubic->hystart_curr_sampled_rtt_valid
                || latest_rtt < cubic->hystart_curr_sampled_rtt)
            {
                cubic->hystart_curr_sampled_rtt = latest_rtt;
                cubic->hystart_curr_sampled_rtt_valid = 1;
            }

            cubic->hystart_ack_count++;
            if (cubic->hystart_ack_count < XQC_CUBIC_HYSTART_ACKS) {
                goto maybe_end_round;
            }
        }

        if (cubic->hystart_last_sampled_rtt_valid
            && cubic->hystart_curr_sampled_rtt_valid)
        {
            xqc_usec_t eta =
                xqc_cubic_hystart_delay_threshold(cubic->hystart_last_sampled_rtt);
            if (cubic->hystart_curr_sampled_rtt
                >= cubic->hystart_last_sampled_rtt + eta)
            {
                cubic->hystart_found = XQC_CUBIC_HYSTART_FOUND_DELAY;
            }
        }
    }

    if (xqc_cubic_hystart_maybe_exit(cubic)) {
        return;
    }

maybe_end_round:
    if (cubic->hystart_in_round
        && po->po_sent_time > cubic->hystart_round_end_time)
    {
        cubic->hystart_in_round = 0;
    }
}


static void
xqc_cubic_on_ack_steady(xqc_cubic_t *cubic, uint32_t acked_bytes, xqc_usec_t now)
{
    if (XQC_CUBIC_MVFST_ONLY_GROW_WHEN_LIMITED
        && cubic->ctl_ctx
        && !xqc_send_ctl_is_cwnd_limited(cubic->ctl_ctx))
    {
        return;
    }

    if (!cubic->steady_last_max_cwnd_valid) {
        cubic->steady_time_to_origin = 0.0;
        cubic->steady_last_max_cwnd = cubic->cwnd;
        cubic->steady_last_max_cwnd_valid = 1;
        cubic->steady_origin_point = cubic->cwnd;
        cubic->steady_origin_point_valid = 1;
        if (cubic->steady_tcp_friendly) {
            cubic->steady_est_reno_cwnd = cubic->cwnd;
        }
    }

    if (!cubic->steady_origin_point_valid
        || cubic->steady_origin_point != cubic->steady_last_max_cwnd)
    {
        xqc_cubic_update_time_to_origin(cubic);
    }

    if (!cubic->steady_last_reduction_time_valid) {
        cubic->steady_last_reduction_time = now;
        cubic->steady_last_reduction_time_valid = 1;
    }

    uint64_t new_cwnd =
        xqc_cubic_calculate_cwnd(cubic, xqc_cubic_calculate_cwnd_delta(cubic, now));

    if (cubic->steady_additive_after_hystart && new_cwnd < cubic->ssthresh) {
        uint64_t delta = acked_bytes / 10;
        if (new_cwnd < cubic->cwnd + delta) {
            new_cwnd = xqc_cubic_bound_cwnd(cubic, cubic->cwnd + delta);
        }
    }

    if (new_cwnd >= cubic->cwnd) {
        cubic->cwnd = new_cwnd;
    }

    if (cubic->steady_tcp_friendly && acked_bytes && cubic->steady_est_reno_cwnd) {
        double reno_cwnd = (double)cubic->steady_est_reno_cwnd
            + XQC_CUBIC_TCP_FRIENDLY_FACTOR
              * (double)acked_bytes
              * (double)XQC_CUBIC_MSS
              / (double)cubic->steady_est_reno_cwnd;

        if (reno_cwnd >= (double)XQC_MAX_UINT64_VALUE) {
            cubic->steady_est_reno_cwnd = cubic->max_cwnd;

        } else {
            cubic->steady_est_reno_cwnd =
                xqc_cubic_bound_cwnd(cubic, (uint64_t)reno_cwnd);
        }

        cubic->cwnd = xqc_max(cubic->cwnd, cubic->steady_est_reno_cwnd);
    }
}


static void
xqc_cubic_on_ack_recovery(xqc_cubic_t *cubic, xqc_packet_out_t *po, xqc_usec_t now)
{
    if (cubic->recovery_end_time_valid
        && po->po_sent_time > cubic->recovery_end_time)
    {
        cubic->state = XQC_CUBIC_STATE_STEADY;

        if (cubic->steady_last_max_cwnd_valid
            && cubic->steady_last_reduction_time_valid)
        {
            xqc_cubic_update_time_to_origin(cubic);
            cubic->cwnd = xqc_cubic_calculate_cwnd(cubic,
                xqc_cubic_calculate_cwnd_delta(cubic, now));
        }
    }
}


static size_t
xqc_cubic_size(void)
{
    return sizeof(xqc_cubic_t);
}


static void
xqc_cubic_init(void *cong_ctl, xqc_send_ctl_t *ctl_ctx, xqc_cc_params_t cc_params)
{
    xqc_cubic_t *cubic = (xqc_cubic_t *)(cong_ctl);

    cubic->init_cwnd = XQC_CUBIC_INIT_CWND_MSS * XQC_CUBIC_MSS;
    cubic->min_cwnd = XQC_CUBIC_MIN_CWND_MSS * XQC_CUBIC_MSS;
    cubic->max_cwnd = XQC_CUBIC_MAX_CWND_MSS * XQC_CUBIC_MSS;

    if (cc_params.customize_on) {
        uint64_t init_cwnd = cc_params.init_cwnd * XQC_CUBIC_MSS;
        uint64_t min_cwnd = cc_params.min_cwnd * XQC_CUBIC_MSS;

        if (init_cwnd >= cubic->min_cwnd && init_cwnd <= cubic->max_cwnd) {
            cubic->init_cwnd = init_cwnd;
        }

        if (min_cwnd > 0 && min_cwnd <= cubic->init_cwnd) {
            cubic->min_cwnd = min_cwnd;
        }
    }

    cubic->cwnd = xqc_cubic_bound_cwnd(cubic, cubic->init_cwnd);
    cubic->ssthresh = XQC_CUBIC_MAX_SSTHRESH;
    cubic->state = XQC_CUBIC_STATE_HYSTART;

    cubic->recovery_end_time = 0;
    cubic->recovery_end_time_valid = 0;

    cubic->hystart_ack_train = XQC_CUBIC_MVFST_ENABLE_ACK_TRAIN;
    xqc_cubic_reset_hystart(cubic);

    cubic->steady_time_to_origin = 0.0;
    cubic->steady_origin_point = 0;
    cubic->steady_origin_point_valid = 0;
    cubic->steady_last_max_cwnd = 0;
    cubic->steady_last_max_cwnd_valid = 0;
    cubic->steady_last_reduction_time = 0;
    cubic->steady_last_reduction_time_valid = 0;
    cubic->steady_est_reno_cwnd = cubic->cwnd;
    cubic->steady_tcp_friendly = XQC_CUBIC_MVFST_TCP_FRIENDLY;
    cubic->steady_additive_after_hystart = XQC_CUBIC_MVFST_ADDITIVE_AFTER_HYSTART;

    cubic->quiescence_start = 0;
    cubic->quiescence_start_valid = 0;
    cubic->ctl_ctx = ctl_ctx;
}


static void
xqc_cubic_on_lost(void *cong_ctl, xqc_usec_t lost_sent_time)
{
    xqc_cubic_t *cubic = (xqc_cubic_t *)(cong_ctl);
    xqc_usec_t now = xqc_monotonic_timestamp();

    if (!cubic->recovery_end_time_valid
        || lost_sent_time >= cubic->recovery_end_time)
    {
        cubic->recovery_end_time = now;
        cubic->recovery_end_time_valid = 1;

        xqc_cubic_cubic_reduction(cubic, now);

        if (cubic->state == XQC_CUBIC_STATE_HYSTART
            || cubic->state == XQC_CUBIC_STATE_STEADY)
        {
            cubic->state = XQC_CUBIC_STATE_FAST_RECOVERY;
        }

        cubic->ssthresh = cubic->cwnd;
    }
}


static void
xqc_cubic_on_ack(void *cong_ctl, xqc_packet_out_t *po, xqc_usec_t now)
{
    xqc_cubic_t *cubic = (xqc_cubic_t *)(cong_ctl);
    uint32_t acked_bytes = po->po_used_size;
    xqc_usec_t latest_rtt = now >= po->po_sent_time ? now - po->po_sent_time : 0;

    if (cubic->ctl_ctx && cubic->ctl_ctx->ctl_latest_rtt) {
        latest_rtt = cubic->ctl_ctx->ctl_latest_rtt;
    }

    if (cubic->recovery_end_time_valid
        && cubic->recovery_end_time >= po->po_sent_time)
    {
        return;
    }

    switch (cubic->state) {
    case XQC_CUBIC_STATE_HYSTART:
        xqc_cubic_on_ack_hystart(cubic, po, acked_bytes, latest_rtt, now);
        break;

    case XQC_CUBIC_STATE_STEADY:
        xqc_cubic_on_ack_steady(cubic, acked_bytes, now);
        break;

    case XQC_CUBIC_STATE_FAST_RECOVERY:
        xqc_cubic_on_ack_recovery(cubic, po, now);
        break;
    }
}


static uint64_t
xqc_cubic_get_cwnd(void *cong_ctl)
{
    xqc_cubic_t *cubic = (xqc_cubic_t *)(cong_ctl);
    return cubic->cwnd;
}


static void
xqc_cubic_reset_cwnd(void *cong_ctl)
{
    xqc_cubic_t *cubic = (xqc_cubic_t *)(cong_ctl);

    cubic->ssthresh = xqc_max(cubic->cwnd / 2, cubic->min_cwnd);
    cubic->cwnd = cubic->min_cwnd;
    cubic->state = XQC_CUBIC_STATE_HYSTART;

    cubic->steady_est_reno_cwnd = 0;
    cubic->steady_last_reduction_time_valid = 0;
    cubic->steady_last_max_cwnd_valid = 0;
    cubic->steady_origin_point_valid = 0;
    cubic->quiescence_start_valid = 0;
    cubic->recovery_end_time_valid = 0;
    xqc_cubic_reset_hystart(cubic);
}


static int
xqc_cubic_in_slow_start(void *cong_ctl)
{
    xqc_cubic_t *cubic = (xqc_cubic_t *)(cong_ctl);
    return cubic->state == XQC_CUBIC_STATE_HYSTART;
}


static void
xqc_cubic_restart_from_idle(void *cong_ctl, uint64_t arg)
{
    xqc_cubic_t *cubic = (xqc_cubic_t *)(cong_ctl);
    xqc_usec_t idle_start = (xqc_usec_t)arg;
    xqc_usec_t now = xqc_monotonic_timestamp();

    if (idle_start > 0
        && now > idle_start
        && cubic->steady_last_reduction_time_valid)
    {
        cubic->steady_last_reduction_time += now - idle_start;
    }

    cubic->quiescence_start_valid = 0;
}


static int
xqc_cubic_in_recovery(void *cong_ctl)
{
    xqc_cubic_t *cubic = (xqc_cubic_t *)(cong_ctl);
    return cubic->state == XQC_CUBIC_STATE_FAST_RECOVERY;
}


static uint32_t
xqc_cubic_get_pacing_rate(void *cong_ctl)
{
    xqc_cubic_t *cubic = (xqc_cubic_t *)(cong_ctl);

    if (cubic->ctl_ctx == NULL) {
        return 0;
    }

    xqc_usec_t srtt = cubic->ctl_ctx->ctl_srtt;
    if (srtt == 0) {
        srtt = cubic->ctl_ctx->ctl_conn->conn_settings.initial_rtt;
    }

    if (srtt == 0) {
        return 0;
    }

    uint64_t rate = cubic->cwnd * XQC_MICROS_PER_SECOND / srtt;
    rate = rate * xqc_cubic_pacing_gain(cubic) / 100;
    return rate > XQC_MAX_UINT32_VALUE ? XQC_MAX_UINT32_VALUE : (uint32_t)rate;
}


const xqc_cong_ctrl_callback_t xqc_cubic_cb = {
    .xqc_cong_ctl_size              = xqc_cubic_size,
    .xqc_cong_ctl_init              = xqc_cubic_init,
    .xqc_cong_ctl_on_lost           = xqc_cubic_on_lost,
    .xqc_cong_ctl_on_ack            = xqc_cubic_on_ack,
    .xqc_cong_ctl_get_cwnd          = xqc_cubic_get_cwnd,
    .xqc_cong_ctl_reset_cwnd        = xqc_cubic_reset_cwnd,
    .xqc_cong_ctl_in_slow_start     = xqc_cubic_in_slow_start,
    .xqc_cong_ctl_in_recovery       = xqc_cubic_in_recovery,
    .xqc_cong_ctl_restart_from_idle = xqc_cubic_restart_from_idle,
    .xqc_cong_ctl_get_pacing_rate   = xqc_cubic_get_pacing_rate,
};
