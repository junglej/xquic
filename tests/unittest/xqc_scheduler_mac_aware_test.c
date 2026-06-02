/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <stdlib.h>
#include <string.h>

#include <CUnit/CUnit.h>

#include "xqc_scheduler_mac_aware_test.h"
#include "src/common/xqc_time.h"
#include "src/transport/scheduler/xqc_scheduler_mac_aware.h"

static void
xqc_test_mac_aware_init_snapshot(xqc_wifi_state_snapshot_t *snapshot)
{
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->state = XQC_WIFI_PATH_STATE_REGULAR;
    snapshot->sample_count = 32;
    snapshot->ewma_mac_rtt_us = 5000.0;
    snapshot->service_rate_bytes_per_us = 1.0;
}

static xqc_bool_t
xqc_test_mac_aware_update_and_check(void *conn_user_data, uint64_t path_id,
    const xqc_wifi_state_snapshot_t *snapshot, uint8_t *risk_bits)
{
    xqc_wifi_state_snapshot_t out;
    xqc_bool_t high_risk = XQC_FALSE;
    uint8_t bits = 0;

    xqc_mac_aware_scheduler_update_path_state(conn_user_data, path_id,
        snapshot);
    CU_ASSERT_TRUE(xqc_mac_aware_scheduler_get_path_state(conn_user_data,
        path_id, xqc_monotonic_timestamp(), &out, &high_risk, &bits));
    if (risk_bits != NULL) {
        *risk_bits = bits;
    }
    return high_risk;
}

void
xqc_test_mac_aware_state_risk_detection(void)
{
    char conn_token;
    void *conn_user_data = &conn_token;
    xqc_wifi_state_snapshot_t snapshot;
    uint8_t risk_bits = 0;

    setenv("MAC_AWARE_MAC_RTT_THRESHOLD_US", "20000", 1);
    setenv("MAC_AWARE_TAIL_EXCESS_THRESHOLD", "1.0", 1);
    setenv("MAC_AWARE_LONG_TXOP_INTERVAL_HIGH", "0.50", 1);

    xqc_mac_aware_scheduler_clear_conn_state(conn_user_data);

    xqc_test_mac_aware_init_snapshot(&snapshot);
    CU_ASSERT_FALSE(xqc_test_mac_aware_update_and_check(conn_user_data, 1,
        &snapshot, &risk_bits));
    CU_ASSERT_EQUAL(risk_bits, 0);

    xqc_test_mac_aware_init_snapshot(&snapshot);
    snapshot.ewma_mac_rtt_us = 25000.0;
    CU_ASSERT_TRUE(xqc_test_mac_aware_update_and_check(conn_user_data, 2,
        &snapshot, &risk_bits));
    CU_ASSERT_NOT_EQUAL(risk_bits, 0);

    xqc_test_mac_aware_init_snapshot(&snapshot);
    snapshot.tail_excess = 1.2;
    CU_ASSERT_TRUE(xqc_test_mac_aware_update_and_check(conn_user_data, 3,
        &snapshot, &risk_bits));
    CU_ASSERT_NOT_EQUAL(risk_bits, 0);

    xqc_mac_aware_scheduler_clear_conn_state(conn_user_data);
}
