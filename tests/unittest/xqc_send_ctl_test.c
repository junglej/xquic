/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <stdio.h>
#include <string.h>

#include <CUnit/CUnit.h>
#include <xquic/xquic_typedef.h>

#include "xqc_common_test.h"
#include "xqc_send_ctl_test.h"

#include "src/common/xqc_malloc.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_transport_params.h"


void
xqc_test_pto_uses_remote_max_ack_delay(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    CU_ASSERT_FATAL(send_ctl != NULL);

    send_ctl->ctl_srtt = 1000;
    send_ctl->ctl_rttvar = 0;
    conn->local_settings.max_ack_delay = 25;
    conn->remote_settings.max_ack_delay = 100;

    xqc_usec_t got = xqc_send_ctl_calc_pto(send_ctl);
    xqc_usec_t expected_remote = 1000
        + XQC_kGranularity * 1000
        + conn->remote_settings.max_ack_delay * 1000;
    xqc_usec_t expected_local = 1000
        + XQC_kGranularity * 1000
        + conn->local_settings.max_ack_delay * 1000;

    CU_ASSERT_EQUAL(got, expected_remote);
    CU_ASSERT_NOT_EQUAL(got, expected_local);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_pto_remote_default_when_unset(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    CU_ASSERT_FATAL(send_ctl != NULL);

    CU_ASSERT_EQUAL(conn->remote_settings.max_ack_delay,
                    XQC_DEFAULT_MAX_ACK_DELAY);

    send_ctl->ctl_srtt = 1000;
    send_ctl->ctl_rttvar = 0;

    xqc_usec_t got = xqc_send_ctl_calc_pto(send_ctl);
    xqc_usec_t expected = 1000
        + XQC_kGranularity * 1000
        + XQC_DEFAULT_MAX_ACK_DELAY * 1000;

    CU_ASSERT_EQUAL(got, expected);
    CU_ASSERT(got > 0);

    xqc_engine_destroy(conn->engine);
}


typedef struct xqc_rtt_case_s {
    const char     *name;
    xqc_bool_t      hsk_confirmed;
    xqc_bool_t      first_sample;
    uint64_t        remote_max_ack_delay_ms;
    xqc_usec_t      input_ack_delay;
    xqc_usec_t      latest_rtt;
    xqc_usec_t      pre_minrtt;
    xqc_usec_t      pre_srtt;
    xqc_usec_t      pre_rttvar;
    xqc_usec_t      expected_srtt;
    xqc_usec_t      expected_rttvar;
    xqc_usec_t      expected_minrtt;
} xqc_rtt_case_t;


static void
xqc_test_send_ctl_run_rtt_case(xqc_connection_t *conn,
    const xqc_rtt_case_t *tc)
{
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;

    send_ctl->ctl_srtt = tc->pre_srtt;
    send_ctl->ctl_rttvar = tc->pre_rttvar;
    send_ctl->ctl_minrtt = tc->pre_minrtt;
    send_ctl->ctl_first_rtt_sample_time = tc->first_sample ? 0 : 1;

    if (tc->hsk_confirmed) {
        conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;

    } else {
        conn->conn_flag &= ~XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;
    }
    conn->remote_settings.max_ack_delay = tc->remote_max_ack_delay_ms;

    xqc_usec_t latest = tc->latest_rtt;
    xqc_send_ctl_update_rtt(send_ctl, &latest, tc->input_ack_delay);

    if (send_ctl->ctl_srtt != tc->expected_srtt
        || send_ctl->ctl_rttvar != tc->expected_rttvar
        || send_ctl->ctl_minrtt != tc->expected_minrtt)
    {
        fprintf(stderr,
                "case [%s] mismatch: srtt got=%llu want=%llu, "
                "rttvar got=%llu want=%llu, minrtt got=%llu want=%llu\n",
                tc->name,
                (unsigned long long) send_ctl->ctl_srtt,
                (unsigned long long) tc->expected_srtt,
                (unsigned long long) send_ctl->ctl_rttvar,
                (unsigned long long) tc->expected_rttvar,
                (unsigned long long) send_ctl->ctl_minrtt,
                (unsigned long long) tc->expected_minrtt);
    }

    CU_ASSERT_EQUAL(send_ctl->ctl_srtt, tc->expected_srtt);
    CU_ASSERT_EQUAL(send_ctl->ctl_rttvar, tc->expected_rttvar);
    CU_ASSERT_EQUAL(send_ctl->ctl_minrtt, tc->expected_minrtt);
}


void
xqc_test_send_ctl_update_rtt_ack_delay_cap(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path->path_send_ctl != NULL);

    xqc_rtt_case_t cases[] = {
        {
            .name = "hsk_not_confirmed_large_ack_delay",
            .hsk_confirmed = XQC_FALSE,
            .first_sample = XQC_FALSE,
            .remote_max_ack_delay_ms = 100,
            .input_ack_delay = 200000,
            .latest_rtt = 250000,
            .pre_minrtt = 10000,
            .pre_srtt = 200000,
            .pre_rttvar = 50000,
            .expected_srtt = 203125,
            .expected_rttvar = 43750,
            .expected_minrtt = 10000,
        },
        {
            .name = "hsk_confirmed_large_ack_delay",
            .hsk_confirmed = XQC_TRUE,
            .first_sample = XQC_FALSE,
            .remote_max_ack_delay_ms = 100,
            .input_ack_delay = 200000,
            .latest_rtt = 250000,
            .pre_minrtt = 10000,
            .pre_srtt = 200000,
            .pre_rttvar = 50000,
            .expected_srtt = 193750,
            .expected_rttvar = 50000,
            .expected_minrtt = 10000,
        },
        {
            .name = "hsk_not_confirmed_small_ack_delay",
            .hsk_confirmed = XQC_FALSE,
            .first_sample = XQC_FALSE,
            .remote_max_ack_delay_ms = 100,
            .input_ack_delay = 10000,
            .latest_rtt = 50000,
            .pre_minrtt = 10000,
            .pre_srtt = 200000,
            .pre_rttvar = 50000,
            .expected_srtt = 180000,
            .expected_rttvar = 77500,
            .expected_minrtt = 10000,
        },
        {
            .name = "hsk_confirmed_remote_smaller_than_default",
            .hsk_confirmed = XQC_TRUE,
            .first_sample = XQC_FALSE,
            .remote_max_ack_delay_ms = 5,
            .input_ack_delay = 30000,
            .latest_rtt = 50000,
            .pre_minrtt = 10000,
            .pre_srtt = 200000,
            .pre_rttvar = 50000,
            .expected_srtt = 180625,
            .expected_rttvar = 76250,
            .expected_minrtt = 10000,
        },
        {
            .name = "first_sample_skips_ack_delay_cap",
            .hsk_confirmed = XQC_FALSE,
            .first_sample = XQC_TRUE,
            .remote_max_ack_delay_ms = 100,
            .input_ack_delay = 200000,
            .latest_rtt = 50000,
            .pre_minrtt = 0,
            .pre_srtt = 0,
            .pre_rttvar = 0,
            .expected_srtt = 50000,
            .expected_rttvar = 25000,
            .expected_minrtt = 50000,
        },
        {
            .name = "ack_delay_zero",
            .hsk_confirmed = XQC_FALSE,
            .first_sample = XQC_FALSE,
            .remote_max_ack_delay_ms = 100,
            .input_ack_delay = 0,
            .latest_rtt = 50000,
            .pre_minrtt = 10000,
            .pre_srtt = 200000,
            .pre_rttvar = 50000,
            .expected_srtt = 181250,
            .expected_rttvar = 75000,
            .expected_minrtt = 10000,
        },
        {
            .name = "plausibility_blocks_subtraction",
            .hsk_confirmed = XQC_FALSE,
            .first_sample = XQC_FALSE,
            .remote_max_ack_delay_ms = 100,
            .input_ack_delay = 10000,
            .latest_rtt = 12000,
            .pre_minrtt = 11000,
            .pre_srtt = 12000,
            .pre_rttvar = 1000,
            .expected_srtt = 12000,
            .expected_rttvar = 750,
            .expected_minrtt = 11000,
        },
        {
            .name = "hsk_confirmed_remote_zero_cap",
            .hsk_confirmed = XQC_TRUE,
            .first_sample = XQC_FALSE,
            .remote_max_ack_delay_ms = 0,
            .input_ack_delay = 50000,
            .latest_rtt = 50000,
            .pre_minrtt = 10000,
            .pre_srtt = 200000,
            .pre_rttvar = 50000,
            .expected_srtt = 181250,
            .expected_rttvar = 75000,
            .expected_minrtt = 10000,
        },
    };

    size_t n = sizeof(cases) / sizeof(cases[0]);
    for (size_t i = 0; i < n; i++) {
        xqc_test_send_ctl_run_rtt_case(conn, &cases[i]);
    }

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_send_ctl_cwnd_usage_window_resets_after_ack(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    CU_ASSERT_FATAL(send_ctl != NULL);
    CU_ASSERT_FATAL(send_ctl->ctl_cong_callback != NULL);
    CU_ASSERT_FATAL(send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd != NULL);

    xqc_packet_out_t po;
    memset(&po, 0, sizeof(po));
    po.po_pkt.pkt_pns = XQC_PNS_APP_DATA;
    po.po_pkt.pkt_num = 100;

    uint64_t cwnd =
        send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong);
    CU_ASSERT_FATAL(cwnd > 0);

    send_ctl->ctl_bytes_in_flight = 10 * 1024 * 1024;
    xqc_send_ctl_update_cwnd_limited(send_ctl, &po, 1000);

    CU_ASSERT_EQUAL(send_ctl->ctl_max_bytes_in_flight, 10 * 1024 * 1024);
    CU_ASSERT_EQUAL(send_ctl->ctl_cwnd_usage_valid, 1);
    CU_ASSERT_EQUAL(send_ctl->ctl_cwnd_usage_pns, XQC_PNS_APP_DATA);
    CU_ASSERT_EQUAL(send_ctl->ctl_cwnd_usage_end_pn, 100);
    CU_ASSERT(xqc_send_ctl_is_cwnd_limited(send_ctl));

    send_ctl->ctl_bytes_in_flight = 2 * 1024;
    po.po_pkt.pkt_num = 101;
    send_ctl->ctl_largest_acked[XQC_PNS_APP_DATA] = 99;
    xqc_send_ctl_update_cwnd_limited(send_ctl, &po, 2000);

    CU_ASSERT_EQUAL(send_ctl->ctl_max_bytes_in_flight, 10 * 1024 * 1024);
    CU_ASSERT(!xqc_send_ctl_is_cwnd_limited(send_ctl));

    send_ctl->ctl_largest_acked[XQC_PNS_APP_DATA] = 100;
    xqc_send_ctl_update_cwnd_limited(send_ctl, &po, 3000);

    CU_ASSERT_EQUAL(send_ctl->ctl_max_bytes_in_flight, 2 * 1024);
    CU_ASSERT_EQUAL(send_ctl->ctl_cwnd_usage_end_pn, 101);
    CU_ASSERT(!xqc_send_ctl_is_cwnd_limited(send_ctl));

    xqc_engine_destroy(conn->engine);
}


static xqc_packet_out_t *
xqc_test_send_ctl_seed_lost_packet(xqc_connection_t *conn,
    xqc_packet_number_t pkt_num, xqc_usec_t po_sent_time)
{
    xqc_send_queue_t *sq = conn->conn_send_queue;
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;

    xqc_packet_out_t *po = xqc_packet_out_get(sq);
    if (po == NULL) {
        return NULL;
    }

    po->po_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    po->po_pkt.pkt_pns = XQC_PNS_APP_DATA;
    po->po_pkt.pkt_num = pkt_num;
    po->po_path_id = send_ctl->ctl_path->path_id;
    po->po_sent_time = po_sent_time;
    po->po_flag = XQC_POF_IN_FLIGHT;
    po->po_frame_types = XQC_FRAME_BIT_PING;
    po->po_used_size = 0;

    xqc_send_queue_insert_unacked(po,
        &sq->sndq_unacked_packets[XQC_PNS_APP_DATA], sq);
    return po;
}


static void
xqc_test_send_ctl_arm_pc_state(xqc_send_ctl_t *send_ctl,
    xqc_usec_t srtt, xqc_usec_t rttvar, xqc_usec_t minrtt,
    xqc_packet_number_t largest_acked)
{
    send_ctl->ctl_srtt = srtt;
    send_ctl->ctl_rttvar = rttvar;
    send_ctl->ctl_minrtt = minrtt;
    send_ctl->ctl_latest_rtt = srtt;
    send_ctl->ctl_first_rtt_sample_time = 1;
    send_ctl->ctl_pto_count = XQC_CONSECUTIVE_PTO_THRESH;
    send_ctl->ctl_largest_acked[XQC_PNS_APP_DATA] = largest_acked;
}


void
xqc_test_send_ctl_persistent_congestion_resets_rtt(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    CU_ASSERT_FATAL(send_ctl != NULL);
    CU_ASSERT_FATAL(send_ctl->ctl_cong_callback != NULL);
    CU_ASSERT_FATAL(send_ctl->ctl_cong_callback->xqc_cong_ctl_reset_cwnd != NULL);
    CU_ASSERT_FATAL(send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd != NULL);
    CU_ASSERT_FATAL(conn->conn_settings.initial_rtt > 0);

    conn->remote_settings.max_ack_delay = 25;
    xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 1);

    xqc_packet_out_t *po = xqc_test_send_ctl_seed_lost_packet(conn, 1, 1);
    CU_ASSERT_FATAL(po != NULL);

    uint64_t cwnd_before =
        send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong);
    CU_ASSERT_FATAL(cwnd_before > 0);

    xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                             XQC_PNS_APP_DATA, 1000000);

    CU_ASSERT_EQUAL(send_ctl->ctl_minrtt, XQC_MAX_UINT32_VALUE);
    CU_ASSERT_EQUAL(send_ctl->ctl_srtt, conn->conn_settings.initial_rtt);
    CU_ASSERT_EQUAL(send_ctl->ctl_rttvar, conn->conn_settings.initial_rtt / 2);
    CU_ASSERT_EQUAL(send_ctl->ctl_first_rtt_sample_time, 0);

    uint64_t cwnd_after =
        send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong);
    CU_ASSERT(cwnd_after < cwnd_before);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_send_ctl_persistent_congestion_rtt_reseeds_from_new_sample(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    CU_ASSERT_FATAL(send_ctl != NULL);
    CU_ASSERT_FATAL(conn->conn_settings.initial_rtt > 0);

    conn->remote_settings.max_ack_delay = 25;
    xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 1);

    xqc_packet_out_t *po = xqc_test_send_ctl_seed_lost_packet(conn, 1, 1);
    CU_ASSERT_FATAL(po != NULL);

    xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                             XQC_PNS_APP_DATA, 1000000);
    CU_ASSERT_FATAL(send_ctl->ctl_first_rtt_sample_time == 0);

    xqc_usec_t latest = 300000;
    xqc_send_ctl_update_rtt(send_ctl, &latest, 0);

    CU_ASSERT_EQUAL(send_ctl->ctl_minrtt, 300000);
    CU_ASSERT_EQUAL(send_ctl->ctl_srtt, 300000);
    CU_ASSERT_EQUAL(send_ctl->ctl_rttvar, 150000);
    CU_ASSERT(send_ctl->ctl_first_rtt_sample_time != 0);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_send_ctl_single_loss_does_not_reset_rtt(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    CU_ASSERT_FATAL(send_ctl != NULL);

    conn->remote_settings.max_ack_delay = 25;
    xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 1);
    send_ctl->ctl_pto_count = 0;

    xqc_packet_out_t *po = xqc_test_send_ctl_seed_lost_packet(conn, 1, 1);
    CU_ASSERT_FATAL(po != NULL);

    xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                             XQC_PNS_APP_DATA, 1000000);

    CU_ASSERT_EQUAL(send_ctl->ctl_srtt, 10000);
    CU_ASSERT_EQUAL(send_ctl->ctl_rttvar, 2000);
    CU_ASSERT_EQUAL(send_ctl->ctl_minrtt, 8000);
    CU_ASSERT(send_ctl->ctl_first_rtt_sample_time != 0);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_send_ctl_persistent_congestion_no_rtt_sample_early_return(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    CU_ASSERT_FATAL(send_ctl != NULL);

    conn->remote_settings.max_ack_delay = 25;
    xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 1);
    send_ctl->ctl_first_rtt_sample_time = 0;

    xqc_packet_out_t *po = xqc_test_send_ctl_seed_lost_packet(conn, 1, 1);
    CU_ASSERT_FATAL(po != NULL);

    xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                             XQC_PNS_APP_DATA, 1000000);

    CU_ASSERT_EQUAL(send_ctl->ctl_srtt, 10000);
    CU_ASSERT_EQUAL(send_ctl->ctl_rttvar, 2000);
    CU_ASSERT_EQUAL(send_ctl->ctl_minrtt, 8000);
    CU_ASSERT_EQUAL(send_ctl->ctl_first_rtt_sample_time, 0);

    xqc_engine_destroy(conn->engine);
}
