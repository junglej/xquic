#include "src/transport/scheduler/xqc_scheduler_mac_aware.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/scheduler/xqc_scheduler_observer.h"
#include "src/transport/xqc_send_ctl.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define XQC_MAC_AWARE_MAX_PATH_STATES 32
#define XQC_MAC_AWARE_STALE_US 2000000ULL
#define XQC_MAC_AWARE_PROBE_INTERVAL_US 500000ULL
#define XQC_MAC_AWARE_RISK_MAC_RTT_US 20000ULL
#define XQC_MAC_AWARE_RISK_TAIL_EXCESS 1.0
#define XQC_MAC_AWARE_DEFAULT_ENTER_BAD_SAMPLES 1U
#define XQC_MAC_AWARE_DEFAULT_EXIT_GOOD_SAMPLES 1U
#define XQC_MAC_AWARE_OFO_BUDGET_BYTES 1048576ULL
#define XQC_MAC_AWARE_RISK_INFLIGHT_BUDGET_BYTES 262144ULL
#define XQC_MAC_AWARE_RISK_INFLIGHT_BUDGET_PCT 75U
#define XQC_MAC_AWARE_DEBT_DECAY_GAIN_PCT 100U
#define XQC_MAC_AWARE_PROBE_BYTES 12000ULL
#define XQC_MAC_AWARE_PROBE_BUDGET_BYTES 65536ULL
#define XQC_MAC_AWARE_SERVICE_QUANTUM_CAP_BYTES 262144ULL
#define XQC_MAC_AWARE_TAIL_BUDGET_BYTES 8388608ULL
#define XQC_MAC_AWARE_RQ_LOW_FACTOR 1.0
#define XQC_MAC_AWARE_RQ_HIGH_FACTOR 2.0
#define XQC_MAC_AWARE_RTT_STALE_US 1000000ULL
#define XQC_MAC_AWARE_MIN_CC_HEADROOM_BYTES 1200ULL

#define XQC_MAC_AWARE_RISK_REASON_DEGRADED 0x01
#define XQC_MAC_AWARE_RISK_REASON_TAIL     0x02
#define XQC_MAC_AWARE_RISK_REASON_MAC_RTT  0x04

typedef enum xqc_mac_aware_mode_e {
    XQC_MAC_AWARE_MODE_STRICT_GUARD = 0,
    XQC_MAC_AWARE_MODE_TAIL_RESERVOIR = 1,
} xqc_mac_aware_mode_t;

typedef enum xqc_mac_aware_risk_state_e {
    XQC_MAC_AWARE_RISK_STATE_CLEAN = 0,
    XQC_MAC_AWARE_RISK_STATE_COLD = 1,
    XQC_MAC_AWARE_RISK_STATE_PROBING = 2,
    XQC_MAC_AWARE_RISK_STATE_WARM = 3,
    XQC_MAC_AWARE_RISK_STATE_CC_BLOCKED = 4,
    XQC_MAC_AWARE_RISK_STATE_RECOVERY = 5,
} xqc_mac_aware_risk_state_t;

typedef struct xqc_mac_aware_config_s {
    xqc_mac_aware_mode_t mode;
    uint64_t             probe_interval_us;
    uint64_t             mac_rtt_threshold_us;
    double               tail_excess_threshold;
    uint32_t             enter_bad_samples;
    uint32_t             exit_good_samples;
    uint64_t             ofo_budget_bytes;
    uint64_t             risk_inflight_budget_bytes;
    uint32_t             risk_inflight_budget_pct;
    uint32_t             debt_decay_gain_pct;
    uint8_t              tail_reservoir_enable;
    uint64_t             probe_bytes;
    uint64_t             probe_budget_bytes;
    uint64_t             min_probe_interval_us;
    uint64_t             service_quantum_cap_bytes;
    double               rq_low_factor;
    double               rq_high_factor;
    uint64_t             tail_budget_bytes;
    uint64_t             rtt_stale_us;
    uint64_t             min_cc_headroom_bytes;
} xqc_mac_aware_config_t;

typedef struct xqc_mac_aware_path_state_s {
    uint8_t                     used;
    void                       *conn_user_data;
    uint64_t                    path_id;
    xqc_wifi_state_snapshot_t   snapshot;
    uint64_t                    updated_at_us;
    uint64_t                    last_probe_at_us;
    uint8_t                     high_risk;
    uint8_t                     risk_reason_bits;
    uint32_t                    bad_sample_count;
    uint32_t                    clean_sample_count;
    double                      arrival_debt_bytes;
    uint64_t                    arrival_debt_updated_at_us;
    uint8_t                     risk_state;
    uint64_t                    rq_bytes;
    uint64_t                    rq_low_bytes;
    uint64_t                    rq_high_bytes;
    uint64_t                    service_quantum_bytes;
    uint64_t                    last_service_at_us;
    uint64_t                    outstanding_probe_bytes;
    uint64_t                    tail_admitted_bytes;
    uint64_t                    tail_budget_used_bytes;
} xqc_mac_aware_path_state_t;

typedef struct xqc_mac_aware_candidate_s {
    xqc_path_ctx_t             *path;
    xqc_wifi_state_snapshot_t   snapshot;
    xqc_bool_t                  has_snapshot;
    uint64_t                    srtt_us;
    uint64_t                    mac_rtt_us;
    uint64_t                    tail_p95_us;
    uint64_t                    service_bytes;
    double                      service_rate_bytes_per_us;
    uint8_t                     risk_reason_bits;
    uint8_t                     instant_risk_reason_bits;
    xqc_path_perf_class_t       path_class;
    uint8_t                     risk_state;
    uint64_t                    cwnd_bytes;
    uint64_t                    inflight_bytes;
    uint64_t                    cc_headroom_bytes;
    uint64_t                    latest_rtt_us;
    uint64_t                    ack_age_us;
    uint8_t                     rtt_stale;
    uint64_t                    rq_bytes;
    uint64_t                    rq_low_bytes;
    uint64_t                    rq_high_bytes;
    uint64_t                    service_quantum_bytes;
    uint64_t                    last_probe_at_us;
    uint64_t                    tail_budget_used_bytes;
    uint8_t                     recovery_probe_due;
} xqc_mac_aware_candidate_t;

static xqc_mac_aware_path_state_t g_mac_aware_path_states[XQC_MAC_AWARE_MAX_PATH_STATES];
static pthread_mutex_t g_mac_aware_path_states_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t g_mac_aware_config_once = PTHREAD_ONCE_INIT;
static xqc_mac_aware_config_t g_mac_aware_config;

static uint64_t
xqc_mac_aware_snapshot_service_bytes(const xqc_wifi_state_snapshot_t *snapshot);

static uint64_t
xqc_mac_aware_service_quantum_bytes(const xqc_wifi_state_snapshot_t *snapshot,
    const xqc_mac_aware_config_t *config);

static uint64_t
xqc_mac_aware_env_u64(const char *name, uint64_t default_value)
{
    const char *value = getenv(name);
    char *end = NULL;
    unsigned long long parsed;

    if (value == NULL || value[0] == '\0') {
        return default_value;
    }

    parsed = strtoull(value, &end, 10);
    if (end == value) {
        return default_value;
    }

    return (uint64_t) parsed;
}

static double
xqc_mac_aware_env_double(const char *name, double default_value)
{
    const char *value = getenv(name);
    char *end = NULL;
    double parsed;

    if (value == NULL || value[0] == '\0') {
        return default_value;
    }

    parsed = strtod(value, &end);
    if (end == value) {
        return default_value;
    }

    return parsed;
}

static xqc_mac_aware_mode_t
xqc_mac_aware_env_mode(void)
{
    const char *value = getenv("MAC_AWARE_MODE");

    if (value == NULL || value[0] == '\0') {
        return XQC_MAC_AWARE_MODE_STRICT_GUARD;
    }
    if (strcmp(value, "tail_reservoir") == 0
        || strcmp(value, "tail-reservoir") == 0)
    {
        return XQC_MAC_AWARE_MODE_TAIL_RESERVOIR;
    }

    return XQC_MAC_AWARE_MODE_STRICT_GUARD;
}

static void
xqc_mac_aware_config_init_once(void)
{
    memset(&g_mac_aware_config, 0, sizeof(g_mac_aware_config));
    g_mac_aware_config.mode = xqc_mac_aware_env_mode();
    g_mac_aware_config.probe_interval_us =
        xqc_mac_aware_env_u64("MAC_AWARE_PROBE_INTERVAL_US",
            XQC_MAC_AWARE_PROBE_INTERVAL_US);
    g_mac_aware_config.mac_rtt_threshold_us =
        xqc_mac_aware_env_u64("MAC_AWARE_MAC_RTT_THRESHOLD_US",
            xqc_mac_aware_env_u64("MAC_AWARE_RISK_MAC_RTT_US",
                XQC_MAC_AWARE_RISK_MAC_RTT_US));
    g_mac_aware_config.tail_excess_threshold =
        xqc_mac_aware_env_double("MAC_AWARE_TAIL_EXCESS_THRESHOLD",
            xqc_mac_aware_env_double("MAC_AWARE_RISK_TAIL_EXCESS",
                XQC_MAC_AWARE_RISK_TAIL_EXCESS));
    g_mac_aware_config.enter_bad_samples =
        (uint32_t) xqc_mac_aware_env_u64("MAC_AWARE_ENTER_BAD_SAMPLES",
            XQC_MAC_AWARE_DEFAULT_ENTER_BAD_SAMPLES);
    g_mac_aware_config.exit_good_samples =
        (uint32_t) xqc_mac_aware_env_u64("MAC_AWARE_EXIT_GOOD_SAMPLES",
            XQC_MAC_AWARE_DEFAULT_EXIT_GOOD_SAMPLES);
    g_mac_aware_config.ofo_budget_bytes =
        xqc_mac_aware_env_u64("MAC_AWARE_OFO_BUDGET_BYTES",
            xqc_mac_aware_env_u64("MAC_AWARE_REORDER_BUDGET_BYTES",
                XQC_MAC_AWARE_OFO_BUDGET_BYTES));
    g_mac_aware_config.risk_inflight_budget_bytes =
        xqc_mac_aware_env_u64("MAC_AWARE_RISK_INFLIGHT_BUDGET_BYTES",
            XQC_MAC_AWARE_RISK_INFLIGHT_BUDGET_BYTES);
    g_mac_aware_config.risk_inflight_budget_pct =
        (uint32_t) xqc_mac_aware_env_u64("MAC_AWARE_RISK_INFLIGHT_BUDGET_PCT",
            XQC_MAC_AWARE_RISK_INFLIGHT_BUDGET_PCT);
    g_mac_aware_config.debt_decay_gain_pct =
        (uint32_t) xqc_mac_aware_env_u64("MAC_AWARE_DEBT_DECAY_GAIN_PCT",
            XQC_MAC_AWARE_DEBT_DECAY_GAIN_PCT);
    g_mac_aware_config.tail_reservoir_enable =
        xqc_mac_aware_env_u64("MAC_AWARE_TAIL_RESERVOIR_ENABLE",
            g_mac_aware_config.mode == XQC_MAC_AWARE_MODE_TAIL_RESERVOIR
                ? 1 : 0) ? 1 : 0;
    g_mac_aware_config.probe_bytes =
        xqc_mac_aware_env_u64("MAC_AWARE_PROBE_BYTES",
            XQC_MAC_AWARE_PROBE_BYTES);
    g_mac_aware_config.probe_budget_bytes =
        xqc_mac_aware_env_u64("MAC_AWARE_PROBE_BUDGET_BYTES",
            XQC_MAC_AWARE_PROBE_BUDGET_BYTES);
    g_mac_aware_config.min_probe_interval_us =
        xqc_mac_aware_env_u64("MAC_AWARE_MIN_PROBE_INTERVAL_US",
            g_mac_aware_config.probe_interval_us);
    g_mac_aware_config.service_quantum_cap_bytes =
        xqc_mac_aware_env_u64("MAC_AWARE_SERVICE_QUANTUM_CAP_BYTES",
            XQC_MAC_AWARE_SERVICE_QUANTUM_CAP_BYTES);
    g_mac_aware_config.rq_low_factor =
        xqc_mac_aware_env_double("MAC_AWARE_RQ_LOW_FACTOR",
            XQC_MAC_AWARE_RQ_LOW_FACTOR);
    g_mac_aware_config.rq_high_factor =
        xqc_mac_aware_env_double("MAC_AWARE_RQ_HIGH_FACTOR",
            XQC_MAC_AWARE_RQ_HIGH_FACTOR);
    g_mac_aware_config.tail_budget_bytes =
        xqc_mac_aware_env_u64("MAC_AWARE_TAIL_BUDGET_BYTES",
            XQC_MAC_AWARE_TAIL_BUDGET_BYTES);
    g_mac_aware_config.rtt_stale_us =
        xqc_mac_aware_env_u64("MAC_AWARE_RTT_STALE_US",
            XQC_MAC_AWARE_RTT_STALE_US);
    g_mac_aware_config.min_cc_headroom_bytes =
        xqc_mac_aware_env_u64("MAC_AWARE_MIN_CC_HEADROOM_BYTES",
            XQC_MAC_AWARE_MIN_CC_HEADROOM_BYTES);

    if (g_mac_aware_config.probe_interval_us == 0) {
        g_mac_aware_config.probe_interval_us = XQC_MAC_AWARE_PROBE_INTERVAL_US;
    }
    if (g_mac_aware_config.enter_bad_samples == 0) {
        g_mac_aware_config.enter_bad_samples = 1;
    }
    if (g_mac_aware_config.exit_good_samples == 0) {
        g_mac_aware_config.exit_good_samples = 1;
    }
    if (g_mac_aware_config.risk_inflight_budget_pct > 100) {
        g_mac_aware_config.risk_inflight_budget_pct = 100;
    }
    if (g_mac_aware_config.probe_bytes == 0) {
        g_mac_aware_config.probe_bytes = XQC_MAC_AWARE_PROBE_BYTES;
    }
    if (g_mac_aware_config.min_probe_interval_us == 0) {
        g_mac_aware_config.min_probe_interval_us =
            g_mac_aware_config.probe_interval_us;
    }
    if (g_mac_aware_config.service_quantum_cap_bytes == 0) {
        g_mac_aware_config.service_quantum_cap_bytes =
            XQC_MAC_AWARE_SERVICE_QUANTUM_CAP_BYTES;
    }
    if (g_mac_aware_config.rq_low_factor <= 0.0) {
        g_mac_aware_config.rq_low_factor = XQC_MAC_AWARE_RQ_LOW_FACTOR;
    }
    if (g_mac_aware_config.rq_high_factor
        < g_mac_aware_config.rq_low_factor)
    {
        g_mac_aware_config.rq_high_factor =
            g_mac_aware_config.rq_low_factor;
    }
    if (g_mac_aware_config.rtt_stale_us == 0) {
        g_mac_aware_config.rtt_stale_us = XQC_MAC_AWARE_RTT_STALE_US;
    }
}

static const xqc_mac_aware_config_t *
xqc_mac_aware_get_config(void)
{
    pthread_once(&g_mac_aware_config_once, xqc_mac_aware_config_init_once);
    return &g_mac_aware_config;
}

static double
xqc_mac_aware_tail_risk(const xqc_wifi_state_snapshot_t *snapshot)
{
    if (snapshot == NULL || !snapshot->gtsd_calibrated) {
        return 0.0;
    }
    return snapshot->tail_excess > 0.0 ? snapshot->tail_excess : 0.0;
}

static uint8_t
xqc_mac_aware_snapshot_risk_bits(const xqc_wifi_state_snapshot_t *snapshot,
    const xqc_mac_aware_config_t *config)
{
    uint8_t bits = 0;
    uint64_t mac_rtt_us;

    if (snapshot == NULL || config == NULL) {
        return 0;
    }

    mac_rtt_us = (uint64_t) snapshot->ewma_mac_rtt_us;
    if (snapshot->state == XQC_WIFI_PATH_STATE_DEGRADED_CSMA) {
        bits |= XQC_MAC_AWARE_RISK_REASON_DEGRADED;
    }
    if (xqc_mac_aware_tail_risk(snapshot) >= config->tail_excess_threshold) {
        bits |= XQC_MAC_AWARE_RISK_REASON_TAIL;
    }
    if (mac_rtt_us >= config->mac_rtt_threshold_us) {
        bits |= XQC_MAC_AWARE_RISK_REASON_MAC_RTT;
    }

    return bits;
}

static const char *
xqc_mac_aware_risk_reason_label(uint8_t bits)
{
    switch (bits) {
    case 0:
        return "none";
    case XQC_MAC_AWARE_RISK_REASON_DEGRADED:
        return "degraded_state";
    case XQC_MAC_AWARE_RISK_REASON_TAIL:
        return "tail_excess";
    case XQC_MAC_AWARE_RISK_REASON_MAC_RTT:
        return "mac_rtt";
    default:
        return "combined";
    }
}

static int
xqc_mac_aware_find_state_slot_locked(void *conn_user_data, uint64_t path_id)
{
    int i;

    for (i = 0; i < XQC_MAC_AWARE_MAX_PATH_STATES; i++) {
        if (g_mac_aware_path_states[i].used
            && g_mac_aware_path_states[i].conn_user_data == conn_user_data
            && g_mac_aware_path_states[i].path_id == path_id)
        {
            return i;
        }
    }

    return -1;
}

static int
xqc_mac_aware_alloc_state_slot_locked(void)
{
    int i;

    for (i = 0; i < XQC_MAC_AWARE_MAX_PATH_STATES; i++) {
        if (!g_mac_aware_path_states[i].used) {
            return i;
        }
    }

    return 0;
}

static int
xqc_mac_aware_ensure_state_slot_locked(void *conn_user_data, uint64_t path_id)
{
    int i = xqc_mac_aware_find_state_slot_locked(conn_user_data, path_id);

    if (i >= 0) {
        return i;
    }

    i = xqc_mac_aware_alloc_state_slot_locked();
    memset(&g_mac_aware_path_states[i], 0,
        sizeof(g_mac_aware_path_states[i]));
    g_mac_aware_path_states[i].used = 1;
    g_mac_aware_path_states[i].conn_user_data = conn_user_data;
    g_mac_aware_path_states[i].path_id = path_id;
    return i;
}

XQC_EXPORT_PUBLIC_API void
xqc_mac_aware_scheduler_update_path_state(void *conn_user_data,
    uint64_t path_id, const xqc_wifi_state_snapshot_t *snapshot)
{
    int i;
    uint8_t high_risk = 0;
    uint8_t risk_reason_bits = 0;
    uint32_t bad_sample_count = 0;
    uint32_t clean_sample_count = 0;
    double arrival_debt_bytes = 0.0;
    uint64_t arrival_debt_updated_at_us = 0;
    uint64_t last_probe_at_us = 0;
    uint8_t risk_state = XQC_MAC_AWARE_RISK_STATE_CLEAN;
    uint64_t rq_bytes = 0;
    uint64_t rq_low_bytes = 0;
    uint64_t rq_high_bytes = 0;
    uint64_t service_quantum_bytes = 0;
    uint64_t last_service_at_us = 0;
    uint64_t outstanding_probe_bytes = 0;
    uint64_t tail_admitted_bytes = 0;
    uint64_t tail_budget_used_bytes = 0;
    uint64_t now;
    uint8_t current_risk_bits;
    const xqc_mac_aware_config_t *config;

    if (conn_user_data == NULL || snapshot == NULL) {
        return;
    }

    config = xqc_mac_aware_get_config();
    current_risk_bits = xqc_mac_aware_snapshot_risk_bits(snapshot, config);

    pthread_mutex_lock(&g_mac_aware_path_states_lock);
    i = xqc_mac_aware_find_state_slot_locked(conn_user_data, path_id);
    if (i < 0) {
        i = xqc_mac_aware_alloc_state_slot_locked();
        memset(&g_mac_aware_path_states[i], 0, sizeof(g_mac_aware_path_states[i]));
    } else {
        high_risk = g_mac_aware_path_states[i].high_risk;
        risk_reason_bits = g_mac_aware_path_states[i].risk_reason_bits;
        bad_sample_count = g_mac_aware_path_states[i].bad_sample_count;
        clean_sample_count = g_mac_aware_path_states[i].clean_sample_count;
        arrival_debt_bytes = g_mac_aware_path_states[i].arrival_debt_bytes;
        arrival_debt_updated_at_us =
            g_mac_aware_path_states[i].arrival_debt_updated_at_us;
        last_probe_at_us = g_mac_aware_path_states[i].last_probe_at_us;
        risk_state = g_mac_aware_path_states[i].risk_state;
        rq_bytes = g_mac_aware_path_states[i].rq_bytes;
        rq_low_bytes = g_mac_aware_path_states[i].rq_low_bytes;
        rq_high_bytes = g_mac_aware_path_states[i].rq_high_bytes;
        service_quantum_bytes =
            g_mac_aware_path_states[i].service_quantum_bytes;
        last_service_at_us = g_mac_aware_path_states[i].last_service_at_us;
        outstanding_probe_bytes =
            g_mac_aware_path_states[i].outstanding_probe_bytes;
        tail_admitted_bytes =
            g_mac_aware_path_states[i].tail_admitted_bytes;
        tail_budget_used_bytes =
            g_mac_aware_path_states[i].tail_budget_used_bytes;
    }

    if (current_risk_bits != 0) {
        bad_sample_count++;
        clean_sample_count = 0;
        risk_reason_bits = current_risk_bits;
        if (bad_sample_count >= config->enter_bad_samples) {
            high_risk = 1;
        }
    } else {
        clean_sample_count++;
        bad_sample_count = 0;
        if (clean_sample_count >= config->exit_good_samples) {
            high_risk = 0;
            risk_reason_bits = 0;
        }
    }

    now = xqc_monotonic_timestamp();
    service_quantum_bytes = xqc_mac_aware_service_quantum_bytes(snapshot,
        config);
    if (service_quantum_bytes > 0) {
        rq_low_bytes = (uint64_t) ((double) service_quantum_bytes
            * config->rq_low_factor);
        rq_high_bytes = (uint64_t) ((double) service_quantum_bytes
            * config->rq_high_factor);
        if (rq_high_bytes < rq_low_bytes) {
            rq_high_bytes = rq_low_bytes;
        }
        last_service_at_us = now;
    } else {
        rq_low_bytes = 0;
        rq_high_bytes = 0;
    }
    if (!high_risk) {
        risk_state = XQC_MAC_AWARE_RISK_STATE_CLEAN;
    } else if (current_risk_bits == 0) {
        risk_state = XQC_MAC_AWARE_RISK_STATE_RECOVERY;
    } else if (service_quantum_bytes > 0) {
        risk_state = XQC_MAC_AWARE_RISK_STATE_WARM;
    } else {
        risk_state = XQC_MAC_AWARE_RISK_STATE_COLD;
    }

    g_mac_aware_path_states[i].used = 1;
    g_mac_aware_path_states[i].conn_user_data = conn_user_data;
    g_mac_aware_path_states[i].path_id = path_id;
    g_mac_aware_path_states[i].snapshot = *snapshot;
    g_mac_aware_path_states[i].updated_at_us = now;
    g_mac_aware_path_states[i].high_risk = high_risk;
    g_mac_aware_path_states[i].risk_reason_bits = risk_reason_bits;
    g_mac_aware_path_states[i].bad_sample_count = bad_sample_count;
    g_mac_aware_path_states[i].clean_sample_count = clean_sample_count;
    g_mac_aware_path_states[i].arrival_debt_bytes = arrival_debt_bytes;
    g_mac_aware_path_states[i].arrival_debt_updated_at_us =
        arrival_debt_updated_at_us;
    g_mac_aware_path_states[i].last_probe_at_us = last_probe_at_us;
    g_mac_aware_path_states[i].risk_state = risk_state;
    g_mac_aware_path_states[i].rq_bytes = rq_bytes;
    g_mac_aware_path_states[i].rq_low_bytes = rq_low_bytes;
    g_mac_aware_path_states[i].rq_high_bytes = rq_high_bytes;
    g_mac_aware_path_states[i].service_quantum_bytes =
        service_quantum_bytes;
    g_mac_aware_path_states[i].last_service_at_us = last_service_at_us;
    g_mac_aware_path_states[i].outstanding_probe_bytes =
        outstanding_probe_bytes;
    g_mac_aware_path_states[i].tail_admitted_bytes = tail_admitted_bytes;
    g_mac_aware_path_states[i].tail_budget_used_bytes =
        tail_budget_used_bytes;
    pthread_mutex_unlock(&g_mac_aware_path_states_lock);
}

XQC_EXPORT_PUBLIC_API void
xqc_mac_aware_scheduler_clear_conn_state(void *conn_user_data)
{
    int i;

    if (conn_user_data == NULL) {
        return;
    }

    pthread_mutex_lock(&g_mac_aware_path_states_lock);
    for (i = 0; i < XQC_MAC_AWARE_MAX_PATH_STATES; i++) {
        if (g_mac_aware_path_states[i].used
            && g_mac_aware_path_states[i].conn_user_data == conn_user_data)
        {
            memset(&g_mac_aware_path_states[i], 0,
                sizeof(g_mac_aware_path_states[i]));
        }
    }
    pthread_mutex_unlock(&g_mac_aware_path_states_lock);
}

int
xqc_mac_aware_scheduler_get_path_state(void *conn_user_data, uint64_t path_id,
    uint64_t now, xqc_wifi_state_snapshot_t *snapshot,
    xqc_bool_t *high_risk, uint8_t *risk_reason_bits)
{
    int i;
    int found = XQC_FALSE;

    if (conn_user_data == NULL || snapshot == NULL) {
        return XQC_FALSE;
    }

    pthread_mutex_lock(&g_mac_aware_path_states_lock);
    i = xqc_mac_aware_find_state_slot_locked(conn_user_data, path_id);
    if (i >= 0
        && now >= g_mac_aware_path_states[i].updated_at_us
        && now - g_mac_aware_path_states[i].updated_at_us <= XQC_MAC_AWARE_STALE_US)
    {
        *snapshot = g_mac_aware_path_states[i].snapshot;
        if (high_risk != NULL) {
            *high_risk = g_mac_aware_path_states[i].high_risk
                ? XQC_TRUE : XQC_FALSE;
        }
        if (risk_reason_bits != NULL) {
            *risk_reason_bits = g_mac_aware_path_states[i].risk_reason_bits;
        }
        found = XQC_TRUE;
    }
    pthread_mutex_unlock(&g_mac_aware_path_states_lock);

    return found;
}

static double
xqc_mac_aware_snapshot_service_rate(const xqc_wifi_state_snapshot_t *snapshot)
{
    if (snapshot == NULL) {
        return 0.0;
    }
    if (snapshot->service_rate_bytes_per_us > 0.0) {
        return snapshot->service_rate_bytes_per_us;
    }
    if (snapshot->ewma_service_time_us > 0.0
        && snapshot->ewma_service_bytes > 0.0)
    {
        return snapshot->ewma_service_bytes / snapshot->ewma_service_time_us;
    }
    if (snapshot->ewma_gap_us + snapshot->ewma_airtime_us > 0.0
        && snapshot->ewma_burst_bytes > 0.0)
    {
        return snapshot->ewma_burst_bytes
               / (snapshot->ewma_gap_us + snapshot->ewma_airtime_us);
    }
    return 0.0;
}

static uint64_t
xqc_mac_aware_snapshot_service_bytes(const xqc_wifi_state_snapshot_t *snapshot)
{
    if (snapshot == NULL) {
        return 0;
    }
    if (snapshot->ewma_service_bytes > 0.0) {
        return (uint64_t) snapshot->ewma_service_bytes;
    }
    if (snapshot->last_service_bytes > 0) {
        return snapshot->last_service_bytes;
    }
    if (snapshot->ewma_burst_bytes > 0.0) {
        return (uint64_t) snapshot->ewma_burst_bytes;
    }
    return 0;
}

static uint64_t
xqc_mac_aware_service_quantum_bytes(const xqc_wifi_state_snapshot_t *snapshot,
    const xqc_mac_aware_config_t *config)
{
    uint64_t service_bytes = xqc_mac_aware_snapshot_service_bytes(snapshot);

    if (service_bytes == 0 || config == NULL) {
        return 0;
    }
    if (config->service_quantum_cap_bytes > 0
        && service_bytes > config->service_quantum_cap_bytes)
    {
        return config->service_quantum_cap_bytes;
    }
    return service_bytes;
}

static uint64_t
xqc_mac_aware_path_cwnd(xqc_path_ctx_t *path)
{
    if (path == NULL || path->path_send_ctl == NULL
        || path->path_send_ctl->ctl_cong_callback == NULL)
    {
        return 0;
    }

    return path->path_send_ctl->ctl_cong_callback->
        xqc_cong_ctl_get_cwnd(path->path_send_ctl->ctl_cong);
}

static void
xqc_mac_aware_candidate_update_transport(xqc_mac_aware_candidate_t *candidate,
    uint64_t now, const xqc_mac_aware_config_t *config)
{
    xqc_send_ctl_t *send_ctl;

    if (candidate == NULL || candidate->path == NULL
        || candidate->path->path_send_ctl == NULL || config == NULL)
    {
        return;
    }

    send_ctl = candidate->path->path_send_ctl;
    candidate->cwnd_bytes = xqc_mac_aware_path_cwnd(candidate->path);
    candidate->inflight_bytes = send_ctl->ctl_bytes_in_flight;
    candidate->cc_headroom_bytes =
        candidate->cwnd_bytes > candidate->inflight_bytes
        ? candidate->cwnd_bytes - candidate->inflight_bytes : 0;
    candidate->latest_rtt_us = send_ctl->ctl_latest_rtt;
    if (send_ctl->ctl_delivered_time > 0
        && now >= send_ctl->ctl_delivered_time)
    {
        candidate->ack_age_us = now - send_ctl->ctl_delivered_time;
    } else {
        candidate->ack_age_us = 0;
    }
    candidate->rtt_stale = candidate->latest_rtt_us == 0
        || candidate->ack_age_us > config->rtt_stale_us;
}

static void
xqc_mac_aware_candidate_load_scheduler_state(void *conn_user_data,
    xqc_mac_aware_candidate_t *candidate, uint64_t now,
    const xqc_mac_aware_config_t *config)
{
    int i;

    if (conn_user_data == NULL || candidate == NULL
        || candidate->path == NULL || config == NULL)
    {
        return;
    }

    pthread_mutex_lock(&g_mac_aware_path_states_lock);
    i = xqc_mac_aware_find_state_slot_locked(conn_user_data,
        candidate->path->path_id);
    if (i >= 0) {
        candidate->risk_state = g_mac_aware_path_states[i].risk_state;
        candidate->last_probe_at_us =
            g_mac_aware_path_states[i].last_probe_at_us;
        candidate->tail_budget_used_bytes =
            g_mac_aware_path_states[i].tail_budget_used_bytes;
    }
    pthread_mutex_unlock(&g_mac_aware_path_states_lock);

    candidate->recovery_probe_due =
        (candidate->risk_state == XQC_MAC_AWARE_RISK_STATE_RECOVERY
            || candidate->rtt_stale)
        && (candidate->last_probe_at_us == 0
            || now - candidate->last_probe_at_us
                >= config->min_probe_interval_us);
}

static uint64_t
xqc_mac_aware_effective_inflight_budget(xqc_path_ctx_t *path,
    const xqc_mac_aware_config_t *config)
{
    uint64_t budget;
    uint64_t cwnd_budget = 0;
    uint64_t cwnd;

    if (config == NULL) {
        return 0;
    }

    budget = config->risk_inflight_budget_bytes;
    cwnd = xqc_mac_aware_path_cwnd(path);
    if (cwnd > 0 && config->risk_inflight_budget_pct > 0) {
        cwnd_budget = cwnd * config->risk_inflight_budget_pct / 100;
    }

    if (budget == 0) {
        return cwnd_budget;
    }
    if (cwnd_budget > 0 && cwnd_budget < budget) {
        return cwnd_budget;
    }
    return budget;
}

static xqc_bool_t
xqc_mac_aware_reservoir_gate_allowed(xqc_mac_aware_candidate_t *risk,
    size_t packet_size, const xqc_mac_aware_config_t *config,
    const char **block_reason)
{
    if (risk == NULL || config == NULL) {
        if (block_reason != NULL) {
            *block_reason = "no_risky_candidate";
        }
        return XQC_FALSE;
    }

    if (!config->tail_reservoir_enable) {
        return XQC_TRUE;
    }

    if (risk->cc_headroom_bytes < packet_size
        || risk->cc_headroom_bytes < config->min_cc_headroom_bytes)
    {
        if (block_reason != NULL) {
            *block_reason = "cc_blocked";
        }
        return XQC_FALSE;
    }

    if (config->tail_budget_bytes > 0
        && risk->tail_budget_used_bytes + packet_size
            > config->tail_budget_bytes)
    {
        if (block_reason != NULL) {
            *block_reason = "tail_budget";
        }
        return XQC_FALSE;
    }

    if (!risk->recovery_probe_due) {
        if (risk->service_quantum_bytes == 0) {
            if (block_reason != NULL) {
                *block_reason = "no_service_quantum";
            }
            return XQC_FALSE;
        }
        if (risk->rq_high_bytes > 0
            && risk->rq_bytes + packet_size > risk->rq_high_bytes)
        {
            if (block_reason != NULL) {
                *block_reason = "reservoir_full";
            }
            return XQC_FALSE;
        }
    }

    return XQC_TRUE;
}

static void
xqc_mac_aware_note_risky_selection(void *conn_user_data,
    xqc_mac_aware_candidate_t *risk, uint64_t now, size_t packet_size,
    xqc_bool_t recovery_probe)
{
    int i;

    if (conn_user_data == NULL || risk == NULL || risk->path == NULL) {
        return;
    }

    pthread_mutex_lock(&g_mac_aware_path_states_lock);
    i = xqc_mac_aware_ensure_state_slot_locked(conn_user_data,
        risk->path->path_id);
    if (recovery_probe) {
        g_mac_aware_path_states[i].last_probe_at_us = now;
    }
    g_mac_aware_path_states[i].tail_admitted_bytes += packet_size;
    g_mac_aware_path_states[i].tail_budget_used_bytes += packet_size;
    pthread_mutex_unlock(&g_mac_aware_path_states_lock);
}

static void
xqc_mac_aware_decay_debt_locked(xqc_mac_aware_path_state_t *state,
    uint64_t now, double service_rate_bytes_per_us,
    const xqc_mac_aware_config_t *config)
{
    uint64_t elapsed_us;
    double decay_bytes;

    if (state == NULL || config == NULL) {
        return;
    }
    if (state->arrival_debt_updated_at_us == 0
        || now < state->arrival_debt_updated_at_us)
    {
        state->arrival_debt_updated_at_us = now;
        return;
    }

    elapsed_us = now - state->arrival_debt_updated_at_us;
    state->arrival_debt_updated_at_us = now;
    if (elapsed_us == 0 || service_rate_bytes_per_us <= 0.0) {
        return;
    }

    decay_bytes = service_rate_bytes_per_us * (double) elapsed_us
        * (double) config->debt_decay_gain_pct / 100.0;
    if (decay_bytes >= state->arrival_debt_bytes) {
        state->arrival_debt_bytes = 0.0;
    } else {
        state->arrival_debt_bytes -= decay_bytes;
    }
}

static xqc_bool_t
xqc_mac_aware_arrival_admission_allowed(void *conn_user_data,
    xqc_mac_aware_candidate_t *risk, uint64_t now, size_t packet_size,
    double predicted_ofo_bytes, const xqc_mac_aware_config_t *config,
    const char **block_reason, uint64_t *arrival_debt_bytes,
    uint64_t *risk_inflight_debt_bytes, uint64_t *risk_inflight_budget_bytes)
{
    int i;
    uint64_t inflight = 0;
    uint64_t inflight_budget = 0;
    double projected_debt;
    xqc_bool_t allowed = XQC_FALSE;

    if (block_reason != NULL) {
        *block_reason = "no_estimate";
    }
    if (arrival_debt_bytes != NULL) {
        *arrival_debt_bytes = 0;
    }
    if (risk_inflight_debt_bytes != NULL) {
        *risk_inflight_debt_bytes = 0;
    }
    if (risk_inflight_budget_bytes != NULL) {
        *risk_inflight_budget_bytes = 0;
    }

    if (conn_user_data == NULL || risk == NULL || risk->path == NULL
        || risk->path->path_send_ctl == NULL || config == NULL)
    {
        return XQC_FALSE;
    }

    inflight = risk->path->path_send_ctl->ctl_bytes_in_flight;
    inflight_budget = xqc_mac_aware_effective_inflight_budget(risk->path,
        config);
    if (risk_inflight_debt_bytes != NULL) {
        *risk_inflight_debt_bytes = inflight;
    }
    if (risk_inflight_budget_bytes != NULL) {
        *risk_inflight_budget_bytes = inflight_budget;
    }

    if (inflight_budget > 0 && inflight + packet_size > inflight_budget) {
        if (block_reason != NULL) {
            *block_reason = "inflight_budget";
        }
        return XQC_FALSE;
    }

    if (predicted_ofo_bytes > (double) config->ofo_budget_bytes) {
        if (block_reason != NULL) {
            *block_reason = "ofo_budget";
        }
        return XQC_FALSE;
    }

    pthread_mutex_lock(&g_mac_aware_path_states_lock);
    i = xqc_mac_aware_ensure_state_slot_locked(conn_user_data,
        risk->path->path_id);
    xqc_mac_aware_decay_debt_locked(&g_mac_aware_path_states[i], now,
        risk->service_rate_bytes_per_us, config);

    projected_debt = g_mac_aware_path_states[i].arrival_debt_bytes;
    if (predicted_ofo_bytes > projected_debt) {
        projected_debt = predicted_ofo_bytes;
    }
    projected_debt += (double) packet_size;

    if (projected_debt <= (double) config->ofo_budget_bytes) {
        g_mac_aware_path_states[i].arrival_debt_bytes = projected_debt;
        g_mac_aware_path_states[i].arrival_debt_updated_at_us = now;
        allowed = XQC_TRUE;
        if (block_reason != NULL) {
            *block_reason = "none";
        }
    } else if (block_reason != NULL) {
        *block_reason = "arrival_debt";
    }

    if (arrival_debt_bytes != NULL) {
        *arrival_debt_bytes =
            (uint64_t) g_mac_aware_path_states[i].arrival_debt_bytes;
    }
    pthread_mutex_unlock(&g_mac_aware_path_states_lock);

    return allowed;
}

static xqc_bool_t
xqc_mac_aware_clean_better(const xqc_mac_aware_candidate_t *candidate,
    const xqc_mac_aware_candidate_t *best)
{
    if (candidate == NULL || candidate->path == NULL) {
        return XQC_FALSE;
    }
    if (best == NULL || best->path == NULL) {
        return XQC_TRUE;
    }
    if (candidate->srtt_us != best->srtt_us) {
        return candidate->srtt_us < best->srtt_us;
    }
    if (candidate->mac_rtt_us > 0 && best->mac_rtt_us > 0
        && candidate->mac_rtt_us != best->mac_rtt_us)
    {
        return candidate->mac_rtt_us < best->mac_rtt_us;
    }
    return candidate->service_bytes > best->service_bytes;
}

static xqc_bool_t
xqc_mac_aware_risk_better(const xqc_mac_aware_candidate_t *candidate,
    const xqc_mac_aware_candidate_t *best)
{
    if (candidate == NULL || candidate->path == NULL) {
        return XQC_FALSE;
    }
    if (best == NULL || best->path == NULL) {
        return XQC_TRUE;
    }
    if (candidate->service_bytes > 0 && best->service_bytes > 0
        && candidate->service_bytes != best->service_bytes)
    {
        return candidate->service_bytes > best->service_bytes;
    }
    if (candidate->cc_headroom_bytes != best->cc_headroom_bytes) {
        return candidate->cc_headroom_bytes > best->cc_headroom_bytes;
    }
    if (candidate->mac_rtt_us > 0 && best->mac_rtt_us > 0
        && candidate->mac_rtt_us != best->mac_rtt_us)
    {
        return candidate->mac_rtt_us < best->mac_rtt_us;
    }
    if (candidate->tail_p95_us != best->tail_p95_us) {
        return candidate->tail_p95_us < best->tail_p95_us;
    }
    return candidate->srtt_us < best->srtt_us;
}

static uint64_t
xqc_mac_aware_max_u64(uint64_t a, uint64_t b)
{
    return a > b ? a : b;
}

static size_t
xqc_mac_aware_scheduler_size(void)
{
    return 0;
}

static void
xqc_mac_aware_scheduler_init(void *scheduler, xqc_log_t *log,
    xqc_scheduler_params_t *param)
{
    return;
}

static void
xqc_mac_aware_observation_set_can_send(xqc_scheduler_observation_t *observation,
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

static void
xqc_mac_aware_observation_set_path_risk(xqc_scheduler_observation_t *observation,
    uint64_t path_id, xqc_bool_t high_risk, const char *risk_reason)
{
    uint8_t i;

    if (observation == NULL) {
        return;
    }

    for (i = 0; i < observation->path_count; i++) {
        if (observation->paths[i].path_id == path_id) {
            observation->paths[i].scheduler_high_risk =
                high_risk ? 1 : 0;
            observation->paths[i].scheduler_risk_reason =
                risk_reason != NULL ? risk_reason : "none";
            return;
        }
    }
}

xqc_path_ctx_t *
xqc_mac_aware_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, int check_cwnd,
    int reinject, xqc_bool_t *cc_blocked)
{
    xqc_scheduler_observation_t observation;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_path_ctx_t *original_path = NULL;
    xqc_mac_aware_candidate_t clean;
    xqc_mac_aware_candidate_t risk;
    xqc_mac_aware_candidate_t risk_cc_blocked;
    xqc_mac_aware_candidate_t probe;
    xqc_mac_aware_candidate_t original;
    xqc_mac_aware_candidate_t selected;
    xqc_bool_t reached_cwnd_check = XQC_FALSE;
    xqc_bool_t selected_risky = XQC_FALSE;
    xqc_bool_t selected_admission = XQC_FALSE;
    xqc_bool_t selected_recovery_probe = XQC_FALSE;
    xqc_bool_t selected_reservoir_admit = XQC_FALSE;
    uint64_t now;
    uint64_t eta_clean_us = 0;
    uint64_t eta_risky_us = 0;
    uint64_t arrival_skew_us = 0;
    double predicted_ofo_bytes = 0.0;
    uint64_t arrival_debt_bytes = 0;
    uint64_t risk_inflight_debt_bytes = 0;
    uint64_t risk_inflight_budget_bytes = 0;
    const char *admission_block_reason = "no_estimate";
    const char *decision_reason = "normal";
    uint8_t selected_risk_reason_bits = 0;
    const xqc_mac_aware_config_t *config = xqc_mac_aware_get_config();

    memset(&clean, 0, sizeof(clean));
    memset(&risk, 0, sizeof(risk));
    memset(&risk_cc_blocked, 0, sizeof(risk_cc_blocked));
    memset(&probe, 0, sizeof(probe));
    memset(&original, 0, sizeof(original));
    memset(&selected, 0, sizeof(selected));

    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }

    xqc_scheduler_observation_init(&observation, "mac_aware", conn,
        conn->user_data, packet_out->po_pkt.pkt_num, packet_out->po_used_size);
    now = xqc_monotonic_timestamp();
    observation.ts_us = now;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        xqc_mac_aware_candidate_t candidate;
        xqc_bool_t path_can_send = XQC_FALSE;
        xqc_bool_t high_risk = XQC_FALSE;
        uint8_t risk_reason_bits = 0;

        memset(&candidate, 0, sizeof(candidate));
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        candidate.path = path;
        candidate.path_class = xqc_path_get_perf_class(path);
        candidate.srtt_us = xqc_send_ctl_get_srtt(path->path_send_ctl);
        xqc_mac_aware_candidate_update_transport(&candidate, now, config);
        candidate.has_snapshot =
            xqc_mac_aware_scheduler_get_path_state(conn->user_data,
                path->path_id, now, &candidate.snapshot, &high_risk,
                &risk_reason_bits);
        if (candidate.has_snapshot) {
            candidate.instant_risk_reason_bits =
                xqc_mac_aware_snapshot_risk_bits(&candidate.snapshot,
                    config);
            candidate.mac_rtt_us =
                (uint64_t) candidate.snapshot.ewma_mac_rtt_us;
            candidate.tail_p95_us = candidate.snapshot.tail_p95_us;
            candidate.service_bytes =
                xqc_mac_aware_snapshot_service_bytes(&candidate.snapshot);
            candidate.service_rate_bytes_per_us =
                xqc_mac_aware_snapshot_service_rate(&candidate.snapshot);
            candidate.risk_reason_bits = risk_reason_bits;
            candidate.service_quantum_bytes =
                xqc_mac_aware_service_quantum_bytes(&candidate.snapshot,
                    config);
            candidate.rq_bytes = path->path_send_ctl != NULL
                ? path->path_send_ctl->ctl_bytes_in_flight : 0;
            candidate.rq_low_bytes = (uint64_t)
                ((double) candidate.service_quantum_bytes
                    * config->rq_low_factor);
            candidate.rq_high_bytes = (uint64_t)
                ((double) candidate.service_quantum_bytes
                    * config->rq_high_factor);
            if (candidate.rq_high_bytes < candidate.rq_low_bytes) {
                candidate.rq_high_bytes = candidate.rq_low_bytes;
            }
            if (!high_risk) {
                candidate.risk_state = XQC_MAC_AWARE_RISK_STATE_CLEAN;
            } else if (candidate.instant_risk_reason_bits == 0) {
                candidate.risk_state = XQC_MAC_AWARE_RISK_STATE_RECOVERY;
            } else if (candidate.service_quantum_bytes > 0) {
                candidate.risk_state = XQC_MAC_AWARE_RISK_STATE_WARM;
            } else {
                candidate.risk_state = XQC_MAC_AWARE_RISK_STATE_COLD;
            }
            xqc_mac_aware_candidate_load_scheduler_state(conn->user_data,
                &candidate, now, config);
        }

        xqc_scheduler_observe_path(&observation, path, 0,
            candidate.path_class);
        xqc_mac_aware_observation_set_path_risk(&observation, path->path_id,
            !reinject && candidate.has_snapshot && high_risk,
            xqc_mac_aware_risk_reason_label(risk_reason_bits));

        if (!xqc_scheduler_path_is_usable(path)) {
            continue;
        }

        if (!reached_cwnd_check) {
            reached_cwnd_check = XQC_TRUE;
            if (cc_blocked) {
                *cc_blocked = XQC_TRUE;
            }
        }

        path_can_send = xqc_scheduler_check_path_can_send(path, packet_out,
            check_cwnd);
        xqc_mac_aware_observation_set_can_send(&observation, path->path_id,
            path_can_send);
        if (!path_can_send) {
            if (!reinject && candidate.has_snapshot && high_risk
                && xqc_mac_aware_risk_better(&candidate, &risk_cc_blocked))
            {
                risk_cc_blocked = candidate;
                risk_cc_blocked.risk_state =
                    XQC_MAC_AWARE_RISK_STATE_CC_BLOCKED;
            }
            continue;
        }

        if (cc_blocked) {
            *cc_blocked = XQC_FALSE;
        }

        if (reinject && packet_out->po_path_id == path->path_id) {
            original_path = path;
            original = candidate;
            continue;
        }

        if (!reinject && candidate.has_snapshot && high_risk) {
            if (xqc_mac_aware_risk_better(&candidate, &risk)) {
                risk = candidate;
            }
            if (xqc_mac_aware_risk_better(&candidate, &probe)) {
                probe = candidate;
            }
            continue;
        }

        if (xqc_mac_aware_clean_better(&candidate, &clean)) {
            clean = candidate;
        }
    }

    if (clean.path != NULL) {
        observation.has_base_candidate = 1;
        observation.base_candidate_path_id = clean.path->path_id;
    }
    if (risk.path != NULL) {
        observation.has_admission_candidate = 1;
        observation.admission_candidate_path_id = risk.path->path_id;
    } else if (risk_cc_blocked.path != NULL) {
        observation.has_admission_candidate = 1;
        observation.admission_candidate_path_id =
            risk_cc_blocked.path->path_id;
    }

    if (!reinject && clean.path != NULL && risk.path != NULL) {
        eta_clean_us = clean.srtt_us;
        eta_risky_us = xqc_mac_aware_max_u64(risk.srtt_us, risk.mac_rtt_us);
        if (!risk.rtt_stale && risk.latest_rtt_us > eta_risky_us) {
            eta_risky_us = risk.latest_rtt_us;
        }
        if (risk.tail_p95_us > 0) {
            eta_risky_us += risk.tail_p95_us;
        }
        arrival_skew_us = eta_risky_us > eta_clean_us
            ? eta_risky_us - eta_clean_us : 0;

        if (!xqc_mac_aware_reservoir_gate_allowed(&risk,
                packet_out->po_used_size, config, &admission_block_reason))
        {
            /* block_reason is set by the reservoir gate. */

        } else if (clean.service_rate_bytes_per_us > 0.0) {
            predicted_ofo_bytes =
                clean.service_rate_bytes_per_us * (double) arrival_skew_us;
            if (xqc_mac_aware_arrival_admission_allowed(conn->user_data,
                &risk, now, packet_out->po_used_size, predicted_ofo_bytes,
                config, &admission_block_reason, &arrival_debt_bytes,
                &risk_inflight_debt_bytes, &risk_inflight_budget_bytes))
            {
                selected = risk;
                selected_risky = XQC_TRUE;
                selected_admission = XQC_TRUE;
                selected_recovery_probe = risk.recovery_probe_due
                    ? XQC_TRUE : XQC_FALSE;
                selected_reservoir_admit =
                    config->tail_reservoir_enable ? XQC_TRUE : XQC_FALSE;
                selected_risk_reason_bits = risk.risk_reason_bits;
                if (selected_recovery_probe) {
                    decision_reason = "recovery_probe";
                } else if (config->tail_reservoir_enable) {
                    decision_reason = "reservoir_admit";
                } else {
                    decision_reason = "arrival_admission";
                }
            }
        } else {
            admission_block_reason = "no_clean_service_rate";
        }
    } else if (clean.path == NULL) {
        admission_block_reason = "no_clean_candidate";
    } else if (risk_cc_blocked.path != NULL) {
        admission_block_reason = "cc_blocked";
    } else {
        admission_block_reason = "no_risky_candidate";
    }

    if (selected.path == NULL && clean.path != NULL) {
        selected = clean;
        decision_reason = "clean";
    }

    if (!reinject && selected.path == NULL && probe.path != NULL) {
        selected = probe;
        selected_risky = XQC_TRUE;
        selected_risk_reason_bits = probe.risk_reason_bits;
        decision_reason = "risk_fallback";
    }

    if (selected.path == NULL && original_path != NULL
        && !(packet_out->po_flag & XQC_POF_REINJECT_DIFF_PATH))
    {
        selected = original;
        decision_reason = "reinject_original";
    }

    if (selected_admission && selected_risky) {
        xqc_mac_aware_note_risky_selection(conn->user_data, &selected, now,
            packet_out->po_used_size, selected_recovery_probe);
    }

    observation.eta_clean_us = eta_clean_us;
    observation.eta_risky_us = eta_risky_us;
    observation.eta_delta_us = arrival_skew_us;
    observation.arrival_skew_us = arrival_skew_us;
    observation.predicted_ofo_bytes = predicted_ofo_bytes;
    observation.selected_srtt_us = selected.srtt_us;
    observation.selected_latest_rtt_us = selected.latest_rtt_us;
    observation.selected_rtt_age_us = selected.ack_age_us;
    observation.ofo_budget_bytes = config->ofo_budget_bytes;
    observation.arrival_debt_bytes = arrival_debt_bytes;
    observation.risk_inflight_debt_bytes = risk_inflight_debt_bytes;
    observation.risk_inflight_budget_bytes = risk_inflight_budget_bytes;
    observation.admission_allowed = selected_admission ? 1 : 0;
    observation.service_admission_selected = selected_admission ? 1 : 0;
    observation.reservoir_admit_selected = selected_reservoir_admit ? 1 : 0;
    observation.recovery_probe_selected = selected_recovery_probe ? 1 : 0;
    observation.admission_block_reason = admission_block_reason;
    if (risk.path != NULL) {
        observation.risky_service_bytes = risk.service_bytes;
        observation.risky_service_rate_bytes_per_us =
            risk.service_rate_bytes_per_us;
        observation.risky_cwnd_bytes = risk.cwnd_bytes;
        observation.risky_inflight_bytes = risk.inflight_bytes;
        observation.risky_cc_headroom_bytes = risk.cc_headroom_bytes;
        observation.risky_latest_rtt_us = risk.latest_rtt_us;
        observation.risky_rtt_age_us = risk.ack_age_us;
        observation.risky_rtt_stale = risk.rtt_stale;
        observation.risky_reservoir_bytes = risk.rq_bytes;
        observation.risky_reservoir_low_bytes = risk.rq_low_bytes;
        observation.risky_reservoir_high_bytes = risk.rq_high_bytes;
        observation.risky_service_quantum_bytes =
            risk.service_quantum_bytes;
        observation.risky_last_probe_at_us = risk.last_probe_at_us;
        observation.risky_tail_budget_used_bytes =
            risk.tail_budget_used_bytes;

    } else if (risk_cc_blocked.path != NULL) {
        observation.risky_service_bytes = risk_cc_blocked.service_bytes;
        observation.risky_service_rate_bytes_per_us =
            risk_cc_blocked.service_rate_bytes_per_us;
        observation.risky_cwnd_bytes = risk_cc_blocked.cwnd_bytes;
        observation.risky_inflight_bytes = risk_cc_blocked.inflight_bytes;
        observation.risky_cc_headroom_bytes =
            risk_cc_blocked.cc_headroom_bytes;
        observation.risky_latest_rtt_us = risk_cc_blocked.latest_rtt_us;
        observation.risky_rtt_age_us = risk_cc_blocked.ack_age_us;
        observation.risky_rtt_stale = risk_cc_blocked.rtt_stale;
        observation.risky_reservoir_bytes = risk_cc_blocked.rq_bytes;
        observation.risky_reservoir_low_bytes =
            risk_cc_blocked.rq_low_bytes;
        observation.risky_reservoir_high_bytes =
            risk_cc_blocked.rq_high_bytes;
        observation.risky_service_quantum_bytes =
            risk_cc_blocked.service_quantum_bytes;
        observation.risky_last_probe_at_us =
            risk_cc_blocked.last_probe_at_us;
        observation.risky_tail_budget_used_bytes =
            risk_cc_blocked.tail_budget_used_bytes;
    }

    if (selected.path != NULL) {
        observation.has_selected_path = 1;
        observation.selected_path_id = selected.path->path_id;
        observation.decision_reason = decision_reason;
        observation.risk_reason =
            xqc_mac_aware_risk_reason_label(selected_risk_reason_bits);
        observation.selected_service_bytes = selected.service_bytes;
        observation.selected_service_rate_bytes_per_us =
            selected.service_rate_bytes_per_us;
        xqc_scheduler_notify_observer(&observation);

        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|mac_aware_best_path:%ui|scheduler:%s|decision:%s|"
                "risk:%d|service_bytes:%ui|service_rate_bytes_per_us:%.6f|"
                "arrival_skew_us:%ui|predicted_ofo_bytes:%.3f|"
                "ofo_budget:%ui|block_reason:%s|used_mask:%ui|",
                selected.path->path_id, "mac_aware", decision_reason,
                selected_risky, selected.service_bytes,
                selected.service_rate_bytes_per_us, arrival_skew_us,
                predicted_ofo_bytes, config->ofo_budget_bytes,
                admission_block_reason,
                xqc_scheduler_packet_path_mask(conn, packet_out));
        return selected.path;
    }

    if (cc_blocked && !reached_cwnd_check) {
        *cc_blocked = XQC_FALSE;
    }

    observation.decision_reason = "no_path";
    observation.risk_reason = "none";
    xqc_scheduler_notify_observer(&observation);
    xqc_log(conn->log, XQC_LOG_DEBUG,
            "|mac_aware_no_available_path|conn:%p|scheduler:%s|reinj:%d|",
            conn, "mac_aware", reinject);
    return NULL;
}

const xqc_scheduler_callback_t xqc_mac_aware_scheduler_cb = {
    .xqc_scheduler_size             = xqc_mac_aware_scheduler_size,
    .xqc_scheduler_init             = xqc_mac_aware_scheduler_init,
    .xqc_scheduler_get_path         = xqc_mac_aware_scheduler_get_path,
};
