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
#define XQC_MAC_AWARE_QUOTA_WINDOW_US 100000ULL
#define XQC_MAC_AWARE_DEFAULT_ENTER_BAD_SAMPLES 1U
#define XQC_MAC_AWARE_DEFAULT_EXIT_GOOD_SAMPLES 1U
#define XQC_MAC_AWARE_DEFAULT_QUOTA_PCT 0U
#define XQC_MAC_AWARE_REORDER_BUDGET_BYTES 1048576ULL
#define XQC_MAC_AWARE_RISK_INFLIGHT_BUDGET_BYTES 262144ULL
#define XQC_MAC_AWARE_RISK_INFLIGHT_BUDGET_PCT 75U
#define XQC_MAC_AWARE_SERVICE_TOKEN_CAP_BYTES 65536ULL
#define XQC_MAC_AWARE_SERVICE_TOKEN_REFILL_GAIN_PCT 25U
#define XQC_MAC_AWARE_REORDER_DEBT_DECAY_GAIN_PCT 100U

#define XQC_MAC_AWARE_RISK_REASON_DEGRADED 0x01
#define XQC_MAC_AWARE_RISK_REASON_TAIL     0x02
#define XQC_MAC_AWARE_RISK_REASON_MAC_RTT  0x04

typedef enum xqc_mac_aware_mode_e {
    XQC_MAC_AWARE_MODE_STRICT_GUARD = 0,
    XQC_MAC_AWARE_MODE_SOFT_QUOTA = 1,
    XQC_MAC_AWARE_MODE_SERVICE_ADMISSION = 2,
} xqc_mac_aware_mode_t;

typedef enum xqc_mac_aware_base_policy_e {
    XQC_MAC_AWARE_BASE_POLICY_RAP = 0,
    XQC_MAC_AWARE_BASE_POLICY_MACRTT = 1,
} xqc_mac_aware_base_policy_t;

typedef struct xqc_mac_aware_config_s {
    xqc_mac_aware_mode_t mode;
    xqc_mac_aware_base_policy_t base_policy;
    uint64_t             probe_interval_us;
    uint64_t             mac_rtt_threshold_us;
    double               tail_excess_threshold;
    uint32_t             enter_bad_samples;
    uint32_t             exit_good_samples;
    uint32_t             quota_pct;
    uint64_t             quota_window_us;
    uint64_t             reorder_budget_bytes;
    uint64_t             risk_inflight_budget_bytes;
    uint32_t             risk_inflight_budget_pct;
    uint64_t             service_token_cap_bytes;
    uint32_t             service_token_refill_gain_pct;
    uint32_t             reorder_debt_decay_gain_pct;
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
    uint64_t                    quota_window_id;
    uint64_t                    quota_total_bytes;
    uint64_t                    quota_risk_bytes;
    double                      service_tokens_bytes;
    double                      reorder_debt_bytes;
    uint64_t                    service_token_updated_at_us;
    uint64_t                    last_service_admission_at_us;
} xqc_mac_aware_path_state_t;

static xqc_mac_aware_path_state_t g_mac_aware_path_states[XQC_MAC_AWARE_MAX_PATH_STATES];
static pthread_mutex_t g_mac_aware_path_states_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t g_mac_aware_config_once = PTHREAD_ONCE_INIT;
static xqc_mac_aware_config_t g_mac_aware_config;

static uint64_t
xqc_mac_aware_env_u64(const char *name, uint64_t default_value)
{
    const char *value;
    char *end = NULL;
    unsigned long long parsed;

    value = getenv(name);
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
    const char *value;
    char *end = NULL;
    double parsed;

    value = getenv(name);
    if (value == NULL || value[0] == '\0') {
        return default_value;
    }

    parsed = strtod(value, &end);
    if (end == value) {
        return default_value;
    }

    return parsed;
}

static void
xqc_mac_aware_config_init_once(void)
{
    const char *mode;
    const char *base_policy;
    uint64_t quota_pct;

    memset(&g_mac_aware_config, 0, sizeof(g_mac_aware_config));
    g_mac_aware_config.mode = XQC_MAC_AWARE_MODE_STRICT_GUARD;
    g_mac_aware_config.base_policy = XQC_MAC_AWARE_BASE_POLICY_RAP;
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
    quota_pct = xqc_mac_aware_env_u64("MAC_AWARE_QUOTA_PCT",
        XQC_MAC_AWARE_DEFAULT_QUOTA_PCT);
    g_mac_aware_config.quota_pct = quota_pct > 100 ? 100 : (uint32_t) quota_pct;
    g_mac_aware_config.quota_window_us =
        xqc_mac_aware_env_u64("MAC_AWARE_QUOTA_WINDOW_US",
            XQC_MAC_AWARE_QUOTA_WINDOW_US);
    g_mac_aware_config.reorder_budget_bytes =
        xqc_mac_aware_env_u64("MAC_AWARE_REORDER_BUDGET_BYTES",
            XQC_MAC_AWARE_REORDER_BUDGET_BYTES);
    g_mac_aware_config.risk_inflight_budget_bytes =
        xqc_mac_aware_env_u64("MAC_AWARE_RISK_INFLIGHT_BUDGET_BYTES",
            XQC_MAC_AWARE_RISK_INFLIGHT_BUDGET_BYTES);
    g_mac_aware_config.risk_inflight_budget_pct =
        (uint32_t) xqc_mac_aware_env_u64("MAC_AWARE_RISK_INFLIGHT_BUDGET_PCT",
            XQC_MAC_AWARE_RISK_INFLIGHT_BUDGET_PCT);
    g_mac_aware_config.service_token_cap_bytes =
        xqc_mac_aware_env_u64("MAC_AWARE_SERVICE_TOKEN_CAP_BYTES",
            XQC_MAC_AWARE_SERVICE_TOKEN_CAP_BYTES);
    g_mac_aware_config.service_token_refill_gain_pct =
        (uint32_t) xqc_mac_aware_env_u64(
            "MAC_AWARE_SERVICE_TOKEN_REFILL_GAIN_PCT",
            XQC_MAC_AWARE_SERVICE_TOKEN_REFILL_GAIN_PCT);
    g_mac_aware_config.reorder_debt_decay_gain_pct =
        (uint32_t) xqc_mac_aware_env_u64(
            "MAC_AWARE_REORDER_DEBT_DECAY_GAIN_PCT",
            XQC_MAC_AWARE_REORDER_DEBT_DECAY_GAIN_PCT);

    if (g_mac_aware_config.probe_interval_us == 0) {
        g_mac_aware_config.probe_interval_us = XQC_MAC_AWARE_PROBE_INTERVAL_US;
    }
    if (g_mac_aware_config.enter_bad_samples == 0) {
        g_mac_aware_config.enter_bad_samples = 1;
    }
    if (g_mac_aware_config.exit_good_samples == 0) {
        g_mac_aware_config.exit_good_samples = 1;
    }
    if (g_mac_aware_config.quota_window_us == 0) {
        g_mac_aware_config.quota_window_us = XQC_MAC_AWARE_QUOTA_WINDOW_US;
    }
    if (g_mac_aware_config.risk_inflight_budget_pct > 100) {
        g_mac_aware_config.risk_inflight_budget_pct = 100;
    }
    if (g_mac_aware_config.service_token_cap_bytes == 0) {
        g_mac_aware_config.service_token_cap_bytes =
            XQC_MAC_AWARE_SERVICE_TOKEN_CAP_BYTES;
    }

    mode = getenv("MAC_AWARE_MODE");
    if (mode != NULL
        && (strcmp(mode, "soft_quota") == 0
            || strcmp(mode, "quota") == 0))
    {
        g_mac_aware_config.mode = XQC_MAC_AWARE_MODE_SOFT_QUOTA;
    }
    if (mode != NULL
        && (strcmp(mode, "service_admission") == 0
            || strcmp(mode, "admission") == 0))
    {
        g_mac_aware_config.mode = XQC_MAC_AWARE_MODE_SERVICE_ADMISSION;
    }

    base_policy = getenv("MAC_AWARE_BASE_POLICY");
    if (base_policy != NULL
        && (strcmp(base_policy, "macrtt") == 0
            || strcmp(base_policy, "mac_rtt") == 0
            || strcmp(base_policy, "min_macrtt") == 0))
    {
        g_mac_aware_config.base_policy = XQC_MAC_AWARE_BASE_POLICY_MACRTT;
    }
}

static const xqc_mac_aware_config_t *
xqc_mac_aware_get_config(void)
{
    pthread_once(&g_mac_aware_config_once, xqc_mac_aware_config_init_once);
    return &g_mac_aware_config;
}

static int
xqc_mac_aware_state_rank(xqc_wifi_path_state_t state)
{
    switch (state) {
    case XQC_WIFI_PATH_STATE_REGULAR:
        return 0;
    case XQC_WIFI_PATH_STATE_UNKNOWN:
        return 1;
    case XQC_WIFI_PATH_STATE_DEGRADED_CSMA:
    default:
        return 2;
    }
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
    double tail_risk;

    if (snapshot == NULL || config == NULL) {
        return 0;
    }

    mac_rtt_us = (uint64_t) snapshot->ewma_mac_rtt_us;
    tail_risk = xqc_mac_aware_tail_risk(snapshot);

    if (snapshot->state == XQC_WIFI_PATH_STATE_DEGRADED_CSMA) {
        bits |= XQC_MAC_AWARE_RISK_REASON_DEGRADED;
    }
    if (tail_risk >= config->tail_excess_threshold) {
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
xqc_mac_aware_alloc_state_slot_locked()
{
    int i;

    for (i = 0; i < XQC_MAC_AWARE_MAX_PATH_STATES; i++) {
        if (!g_mac_aware_path_states[i].used) {
            return i;
        }
    }

    return 0;
}

XQC_EXPORT_PUBLIC_API void
xqc_mac_aware_scheduler_update_path_state(void *conn_user_data,
    uint64_t path_id, const xqc_wifi_state_snapshot_t *snapshot)
{
    int i;
    uint64_t last_probe_at_us = 0;
    uint8_t high_risk = 0;
    uint8_t risk_reason_bits = 0;
    uint32_t bad_sample_count = 0;
    uint32_t clean_sample_count = 0;
    uint64_t quota_window_id = 0;
    uint64_t quota_total_bytes = 0;
    uint64_t quota_risk_bytes = 0;
    double service_tokens_bytes = 0.0;
    double reorder_debt_bytes = 0.0;
    uint64_t service_token_updated_at_us = 0;
    uint64_t last_service_admission_at_us = 0;
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
        last_probe_at_us = g_mac_aware_path_states[i].last_probe_at_us;
        high_risk = g_mac_aware_path_states[i].high_risk;
        risk_reason_bits = g_mac_aware_path_states[i].risk_reason_bits;
        bad_sample_count = g_mac_aware_path_states[i].bad_sample_count;
        clean_sample_count = g_mac_aware_path_states[i].clean_sample_count;
        quota_window_id = g_mac_aware_path_states[i].quota_window_id;
        quota_total_bytes = g_mac_aware_path_states[i].quota_total_bytes;
        quota_risk_bytes = g_mac_aware_path_states[i].quota_risk_bytes;
        service_tokens_bytes = g_mac_aware_path_states[i].service_tokens_bytes;
        reorder_debt_bytes = g_mac_aware_path_states[i].reorder_debt_bytes;
        service_token_updated_at_us =
            g_mac_aware_path_states[i].service_token_updated_at_us;
        last_service_admission_at_us =
            g_mac_aware_path_states[i].last_service_admission_at_us;
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

    g_mac_aware_path_states[i].used = 1;
    g_mac_aware_path_states[i].conn_user_data = conn_user_data;
    g_mac_aware_path_states[i].path_id = path_id;
    g_mac_aware_path_states[i].snapshot = *snapshot;
    g_mac_aware_path_states[i].updated_at_us = xqc_monotonic_timestamp();
    g_mac_aware_path_states[i].last_probe_at_us = last_probe_at_us;
    g_mac_aware_path_states[i].high_risk = high_risk;
    g_mac_aware_path_states[i].risk_reason_bits = risk_reason_bits;
    g_mac_aware_path_states[i].bad_sample_count = bad_sample_count;
    g_mac_aware_path_states[i].clean_sample_count = clean_sample_count;
    g_mac_aware_path_states[i].quota_window_id = quota_window_id;
    g_mac_aware_path_states[i].quota_total_bytes = quota_total_bytes;
    g_mac_aware_path_states[i].quota_risk_bytes = quota_risk_bytes;
    g_mac_aware_path_states[i].service_tokens_bytes = service_tokens_bytes;
    g_mac_aware_path_states[i].reorder_debt_bytes = reorder_debt_bytes;
    g_mac_aware_path_states[i].service_token_updated_at_us =
        service_token_updated_at_us;
    g_mac_aware_path_states[i].last_service_admission_at_us =
        last_service_admission_at_us;

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
            memset(&g_mac_aware_path_states[i], 0, sizeof(g_mac_aware_path_states[i]));
        }
    }

    pthread_mutex_unlock(&g_mac_aware_path_states_lock);
}

static xqc_bool_t
xqc_mac_aware_get_path_state(void *conn_user_data, uint64_t path_id,
    uint64_t now, xqc_wifi_state_snapshot_t *snapshot,
    xqc_bool_t *high_risk, uint8_t *risk_reason_bits)
{
    int i;
    xqc_bool_t found = XQC_FALSE;

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

static xqc_bool_t
xqc_mac_aware_probe_due(void *conn_user_data, uint64_t path_id, uint64_t now)
{
    int i;
    uint64_t last_probe_at_us = 0;
    const xqc_mac_aware_config_t *config = xqc_mac_aware_get_config();

    if (conn_user_data == NULL) {
        return XQC_FALSE;
    }

    pthread_mutex_lock(&g_mac_aware_path_states_lock);
    i = xqc_mac_aware_find_state_slot_locked(conn_user_data, path_id);
    if (i >= 0) {
        last_probe_at_us = g_mac_aware_path_states[i].last_probe_at_us;
    }
    pthread_mutex_unlock(&g_mac_aware_path_states_lock);

    return last_probe_at_us == 0 || now < last_probe_at_us
           || now - last_probe_at_us >= config->probe_interval_us;
}

static void
xqc_mac_aware_mark_probe(void *conn_user_data, uint64_t path_id, uint64_t now)
{
    int i;

    if (conn_user_data == NULL) {
        return;
    }

    pthread_mutex_lock(&g_mac_aware_path_states_lock);
    i = xqc_mac_aware_find_state_slot_locked(conn_user_data, path_id);
    if (i < 0) {
        i = xqc_mac_aware_alloc_state_slot_locked();
        memset(&g_mac_aware_path_states[i], 0, sizeof(g_mac_aware_path_states[i]));
        g_mac_aware_path_states[i].used = 1;
        g_mac_aware_path_states[i].conn_user_data = conn_user_data;
        g_mac_aware_path_states[i].path_id = path_id;
    }
    g_mac_aware_path_states[i].last_probe_at_us = now;
    pthread_mutex_unlock(&g_mac_aware_path_states_lock);
}

static uint64_t
xqc_mac_aware_eta_path_us(uint64_t srtt_us, uint64_t mac_rtt_us)
{
    return mac_rtt_us > 0 ? mac_rtt_us : srtt_us;
}

static double
xqc_mac_aware_service_cost_us_per_kib(uint64_t eta_us, double r_eff_Bpus)
{
    if (r_eff_Bpus > 0.0) {
        return 1024.0 / r_eff_Bpus;
    }

    return (double) eta_us;
}

static xqc_bool_t
xqc_mac_aware_macrtt_path_better(uint64_t mac_rtt_us, uint64_t srtt_us,
    xqc_path_ctx_t *best_path, uint64_t best_mac_rtt_us)
{
    uint64_t best_srtt_us;

    if (best_path == NULL) {
        return XQC_TRUE;
    }

    if (mac_rtt_us > 0 && best_mac_rtt_us > 0 && mac_rtt_us != best_mac_rtt_us) {
        return mac_rtt_us < best_mac_rtt_us;
    }
    if (mac_rtt_us > 0 && best_mac_rtt_us == 0) {
        return XQC_TRUE;
    }
    if (mac_rtt_us == 0 && best_mac_rtt_us > 0) {
        return XQC_FALSE;
    }

    best_srtt_us = xqc_send_ctl_get_srtt(best_path->path_send_ctl);
    return srtt_us < best_srtt_us;
}

static xqc_bool_t
xqc_mac_aware_srtt_path_better(uint64_t mac_rtt_us, uint64_t srtt_us,
    xqc_path_ctx_t *best_path, uint64_t best_mac_rtt_us)
{
    uint64_t best_srtt_us;

    if (best_path == NULL) {
        return XQC_TRUE;
    }

    best_srtt_us = xqc_send_ctl_get_srtt(best_path->path_send_ctl);
    if (srtt_us != best_srtt_us) {
        return srtt_us < best_srtt_us;
    }

    if (mac_rtt_us > 0 && best_mac_rtt_us > 0 && mac_rtt_us != best_mac_rtt_us) {
        return mac_rtt_us < best_mac_rtt_us;
    }
    if (mac_rtt_us > 0 && best_mac_rtt_us == 0) {
        return XQC_TRUE;
    }

    return XQC_FALSE;
}

static xqc_bool_t
xqc_mac_aware_clean_path_better(uint64_t mac_rtt_us, uint64_t srtt_us,
    xqc_path_ctx_t *best_path, uint64_t best_mac_rtt_us,
    const xqc_mac_aware_config_t *config)
{
    if (config != NULL
        && config->base_policy == XQC_MAC_AWARE_BASE_POLICY_MACRTT)
    {
        return xqc_mac_aware_macrtt_path_better(mac_rtt_us, srtt_us,
            best_path, best_mac_rtt_us);
    }

    return xqc_mac_aware_srtt_path_better(mac_rtt_us, srtt_us, best_path,
        best_mac_rtt_us);
}

static xqc_bool_t
xqc_mac_aware_risk_path_better(uint64_t mac_rtt_us, uint64_t srtt_us,
    double r_eff_Bpus, xqc_path_ctx_t *best_path, uint64_t best_mac_rtt_us,
    double best_r_eff_Bpus)
{
    if (best_path == NULL) {
        return XQC_TRUE;
    }

    if (r_eff_Bpus > 0.0 && best_r_eff_Bpus > 0.0
        && r_eff_Bpus != best_r_eff_Bpus)
    {
        return r_eff_Bpus > best_r_eff_Bpus;
    }
    if (r_eff_Bpus > 0.0 && best_r_eff_Bpus <= 0.0) {
        return XQC_TRUE;
    }
    if (r_eff_Bpus <= 0.0 && best_r_eff_Bpus > 0.0) {
        return XQC_FALSE;
    }

    return xqc_mac_aware_macrtt_path_better(mac_rtt_us, srtt_us, best_path,
        best_mac_rtt_us);
}

static void
xqc_mac_aware_quota_reset_if_needed(xqc_mac_aware_path_state_t *state,
    uint64_t now, const xqc_mac_aware_config_t *config)
{
    uint64_t window_id;

    if (state == NULL || config == NULL || config->quota_window_us == 0) {
        return;
    }

    window_id = now / config->quota_window_us;
    if (state->quota_window_id != window_id) {
        state->quota_window_id = window_id;
        state->quota_total_bytes = 0;
        state->quota_risk_bytes = 0;
    }
}

static xqc_bool_t
xqc_mac_aware_quota_allowed(void *conn_user_data, uint64_t path_id,
    uint64_t now, size_t packet_size, const xqc_mac_aware_config_t *config)
{
    int i;
    xqc_bool_t allowed = XQC_FALSE;
    uint64_t projected_total;
    uint64_t projected_risk;

    if (conn_user_data == NULL || config == NULL || config->quota_pct == 0) {
        return XQC_FALSE;
    }

    pthread_mutex_lock(&g_mac_aware_path_states_lock);
    i = xqc_mac_aware_find_state_slot_locked(conn_user_data, path_id);
    if (i >= 0) {
        xqc_mac_aware_quota_reset_if_needed(&g_mac_aware_path_states[i], now,
            config);
        projected_total = g_mac_aware_path_states[i].quota_total_bytes
            + (uint64_t) packet_size;
        projected_risk = g_mac_aware_path_states[i].quota_risk_bytes
            + (uint64_t) packet_size;
        if (g_mac_aware_path_states[i].quota_total_bytes > 0
            && projected_risk * 100 <= projected_total * config->quota_pct)
        {
            allowed = XQC_TRUE;
        }
    }
    pthread_mutex_unlock(&g_mac_aware_path_states_lock);

    return allowed;
}

static void
xqc_mac_aware_quota_record(void *conn_user_data, uint64_t path_id,
    uint64_t now, size_t packet_size, xqc_bool_t risk_selected,
    const xqc_mac_aware_config_t *config)
{
    int i;

    if (conn_user_data == NULL || config == NULL || config->quota_pct == 0) {
        return;
    }

    pthread_mutex_lock(&g_mac_aware_path_states_lock);
    i = xqc_mac_aware_find_state_slot_locked(conn_user_data, path_id);
    if (i >= 0) {
        xqc_mac_aware_quota_reset_if_needed(&g_mac_aware_path_states[i], now,
            config);
        g_mac_aware_path_states[i].quota_total_bytes += (uint64_t) packet_size;
        if (risk_selected) {
            g_mac_aware_path_states[i].quota_risk_bytes +=
                (uint64_t) packet_size;
        }
    }
    pthread_mutex_unlock(&g_mac_aware_path_states_lock);
}

static uint64_t
xqc_mac_aware_effective_inflight_budget(xqc_path_ctx_t *path,
    const xqc_mac_aware_config_t *config)
{
    uint64_t budget = 0;
    uint64_t cwnd_budget = 0;
    uint64_t cwnd = 0;

    if (config == NULL) {
        return 0;
    }

    budget = config->risk_inflight_budget_bytes;
    if (path != NULL && path->path_send_ctl != NULL
        && path->path_send_ctl->ctl_cong_callback != NULL)
    {
        cwnd = path->path_send_ctl->ctl_cong_callback->
            xqc_cong_ctl_get_cwnd(path->path_send_ctl->ctl_cong);
    }

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

static void
xqc_mac_aware_service_refresh_locked(xqc_mac_aware_path_state_t *state,
    uint64_t now, double r_eff_Bpus, const xqc_mac_aware_config_t *config)
{
    uint64_t elapsed_us;
    double refill_bytes;
    double decay_bytes;

    if (state == NULL || config == NULL) {
        return;
    }

    if (state->service_token_updated_at_us == 0
        || now < state->service_token_updated_at_us)
    {
        state->service_token_updated_at_us = now;
        return;
    }

    elapsed_us = now - state->service_token_updated_at_us;
    state->service_token_updated_at_us = now;
    if (elapsed_us == 0 || r_eff_Bpus <= 0.0) {
        return;
    }

    refill_bytes = r_eff_Bpus * (double) elapsed_us
        * (double) config->service_token_refill_gain_pct / 100.0;
    if (refill_bytes > 0.0) {
        state->service_tokens_bytes += refill_bytes;
        if (state->service_tokens_bytes
            > (double) config->service_token_cap_bytes)
        {
            state->service_tokens_bytes =
                (double) config->service_token_cap_bytes;
        }
    }

    decay_bytes = r_eff_Bpus * (double) elapsed_us
        * (double) config->reorder_debt_decay_gain_pct / 100.0;
    if (decay_bytes >= state->reorder_debt_bytes) {
        state->reorder_debt_bytes = 0.0;

    } else {
        state->reorder_debt_bytes -= decay_bytes;
    }
}

static int
xqc_mac_aware_ensure_state_slot_locked(void *conn_user_data,
    uint64_t path_id)
{
    int i;

    i = xqc_mac_aware_find_state_slot_locked(conn_user_data, path_id);
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

static xqc_bool_t
xqc_mac_aware_service_refresh_state(void *conn_user_data,
    xqc_path_ctx_t *risk_path, uint64_t now, double risky_r_eff_Bpus,
    const xqc_mac_aware_config_t *config, uint64_t *service_tokens_bytes,
    uint64_t *reorder_debt_bytes, uint64_t *risk_inflight_debt_bytes,
    uint64_t *risk_inflight_budget_bytes)
{
    int i;
    uint64_t inflight;
    uint64_t inflight_budget;

    if (conn_user_data == NULL || risk_path == NULL
        || risk_path->path_send_ctl == NULL || config == NULL)
    {
        return XQC_FALSE;
    }

    inflight = risk_path->path_send_ctl->ctl_bytes_in_flight;
    inflight_budget = xqc_mac_aware_effective_inflight_budget(risk_path,
        config);

    if (risk_inflight_debt_bytes != NULL) {
        *risk_inflight_debt_bytes = inflight;
    }
    if (risk_inflight_budget_bytes != NULL) {
        *risk_inflight_budget_bytes = inflight_budget;
    }

    pthread_mutex_lock(&g_mac_aware_path_states_lock);
    i = xqc_mac_aware_ensure_state_slot_locked(conn_user_data,
        risk_path->path_id);
    xqc_mac_aware_service_refresh_locked(&g_mac_aware_path_states[i], now,
        risky_r_eff_Bpus, config);

    if (service_tokens_bytes != NULL) {
        *service_tokens_bytes =
            (uint64_t) g_mac_aware_path_states[i].service_tokens_bytes;
    }
    if (reorder_debt_bytes != NULL) {
        *reorder_debt_bytes =
            (uint64_t) g_mac_aware_path_states[i].reorder_debt_bytes;
    }
    pthread_mutex_unlock(&g_mac_aware_path_states_lock);

    return XQC_TRUE;
}

static xqc_bool_t
xqc_mac_aware_service_admission_allowed(void *conn_user_data,
    xqc_path_ctx_t *risk_path, uint64_t now, size_t packet_size,
    double predicted_reorder_bytes, double risky_r_eff_Bpus,
    const xqc_mac_aware_config_t *config, const char **block_reason,
    uint64_t *service_tokens_bytes, uint64_t *reorder_debt_bytes,
    uint64_t *risk_inflight_debt_bytes, uint64_t *risk_inflight_budget_bytes)
{
    int i;
    uint64_t inflight = 0;
    uint64_t inflight_budget = 0;
    double projected_reorder_debt;
    xqc_bool_t allowed = XQC_FALSE;

    if (block_reason != NULL) {
        *block_reason = "no_estimate";
    }
    if (risk_inflight_debt_bytes != NULL) {
        *risk_inflight_debt_bytes = 0;
    }
    if (risk_inflight_budget_bytes != NULL) {
        *risk_inflight_budget_bytes = 0;
    }

    if (conn_user_data == NULL || risk_path == NULL
        || risk_path->path_send_ctl == NULL || config == NULL)
    {
        return XQC_FALSE;
    }

    inflight = risk_path->path_send_ctl->ctl_bytes_in_flight;
    inflight_budget = xqc_mac_aware_effective_inflight_budget(risk_path,
        config);
    if (risk_inflight_debt_bytes != NULL) {
        *risk_inflight_debt_bytes = inflight;
    }
    if (risk_inflight_budget_bytes != NULL) {
        *risk_inflight_budget_bytes = inflight_budget;
    }

    if (inflight_budget > 0
        && inflight + (uint64_t) packet_size > inflight_budget)
    {
        if (block_reason != NULL) {
            *block_reason = "inflight_debt";
        }
        return XQC_FALSE;
    }

    if (predicted_reorder_bytes > (double) config->reorder_budget_bytes) {
        if (block_reason != NULL) {
            *block_reason = "reorder_budget";
        }
        return XQC_FALSE;
    }

    pthread_mutex_lock(&g_mac_aware_path_states_lock);
    i = xqc_mac_aware_ensure_state_slot_locked(conn_user_data,
        risk_path->path_id);
    xqc_mac_aware_service_refresh_locked(&g_mac_aware_path_states[i], now,
        risky_r_eff_Bpus, config);

    projected_reorder_debt = g_mac_aware_path_states[i].reorder_debt_bytes;
    if (predicted_reorder_bytes > projected_reorder_debt) {
        projected_reorder_debt = predicted_reorder_bytes;
    }
    projected_reorder_debt += (double) packet_size;

    if (projected_reorder_debt > (double) config->reorder_budget_bytes) {
        if (block_reason != NULL) {
            *block_reason = "reorder_debt";
        }

    } else if (g_mac_aware_path_states[i].service_tokens_bytes
               < (double) packet_size)
    {
        if (block_reason != NULL) {
            *block_reason = "service_tokens";
        }

    } else {
        g_mac_aware_path_states[i].service_tokens_bytes -=
            (double) packet_size;
        g_mac_aware_path_states[i].reorder_debt_bytes =
            projected_reorder_debt;
        g_mac_aware_path_states[i].last_service_admission_at_us = now;
        allowed = XQC_TRUE;
        if (block_reason != NULL) {
            *block_reason = "none";
        }
    }

    if (service_tokens_bytes != NULL) {
        *service_tokens_bytes =
            (uint64_t) g_mac_aware_path_states[i].service_tokens_bytes;
    }
    if (reorder_debt_bytes != NULL) {
        *reorder_debt_bytes =
            (uint64_t) g_mac_aware_path_states[i].reorder_debt_bytes;
    }
    pthread_mutex_unlock(&g_mac_aware_path_states_lock);

    return allowed;
}

static size_t
xqc_mac_aware_scheduler_size()
{
    return 0;
}

static void
xqc_mac_aware_scheduler_init(void *scheduler, xqc_log_t *log, xqc_scheduler_params_t *param)
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
    xqc_path_ctx_t *best_path = NULL;
    xqc_path_ctx_t *probe_path = NULL;
    xqc_path_ctx_t *risk_path = NULL;
    xqc_path_ctx_t *quota_path = NULL;
    xqc_path_ctx_t *blocked_risk_path = NULL;
    xqc_path_ctx_t *base_candidate_path = NULL;
    xqc_path_ctx_t *admission_candidate_path = NULL;
    xqc_path_ctx_t *service_admission_path = NULL;
    xqc_path_ctx_t *original_path = NULL;
    xqc_scheduler_observation_t observation;
    xqc_path_perf_class_t path_class;
    xqc_path_perf_class_t best_path_class = XQC_PATH_CLASS_PERF_CLASS_SIZE;
    xqc_path_perf_class_t probe_path_class = XQC_PATH_CLASS_PERF_CLASS_SIZE;
    xqc_path_perf_class_t risk_path_class = XQC_PATH_CLASS_PERF_CLASS_SIZE;
    xqc_path_perf_class_t quota_path_class = XQC_PATH_CLASS_PERF_CLASS_SIZE;
    xqc_path_perf_class_t original_path_class = XQC_PATH_CLASS_PERF_CLASS_SIZE;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_bool_t reached_cwnd_check = XQC_FALSE;
    xqc_bool_t path_can_send;
    uint64_t path_srtt;
    uint64_t now;
    xqc_bool_t selected_probe = XQC_FALSE;
    xqc_bool_t selected_risk_fallback = XQC_FALSE;
    xqc_bool_t selected_quota = XQC_FALSE;
    xqc_bool_t selected_service_admission = XQC_FALSE;
    xqc_bool_t selected_risky_path = XQC_FALSE;
    xqc_wifi_state_snapshot_t wifi_snapshot;
    xqc_bool_t has_wifi_snapshot;
    xqc_bool_t path_high_risk;
    xqc_bool_t path_probe_due;
    uint8_t path_risk_reason_bits;
    int state_rank;
    int best_state_rank = xqc_mac_aware_state_rank(XQC_WIFI_PATH_STATE_UNKNOWN);
    int probe_state_rank = xqc_mac_aware_state_rank(XQC_WIFI_PATH_STATE_UNKNOWN);
    int risk_state_rank = xqc_mac_aware_state_rank(XQC_WIFI_PATH_STATE_UNKNOWN);
    int quota_state_rank = xqc_mac_aware_state_rank(XQC_WIFI_PATH_STATE_UNKNOWN);
    double tail_risk;
    double best_tail_risk = 0.0;
    double probe_tail_risk = 0.0;
    double risk_tail_risk = 0.0;
    double quota_tail_risk = 0.0;
    double pi_degraded;
    double best_pi_degraded = 0.0;
    double probe_pi_degraded = 0.0;
    double risk_pi_degraded = 0.0;
    double quota_pi_degraded = 0.0;
    double r_eff_Bpus;
    double best_r_eff_Bpus = 0.0;
    double probe_r_eff_Bpus = 0.0;
    double risk_r_eff_Bpus = 0.0;
    double quota_r_eff_Bpus = 0.0;
    double blocked_risk_r_eff_Bpus = 0.0;
    double base_candidate_r_eff_Bpus = 0.0;
    double admission_candidate_r_eff_Bpus = 0.0;
    uint64_t mac_rtt_us;
    uint64_t best_mac_rtt_us = 0;
    uint64_t probe_mac_rtt_us = 0;
    uint64_t risk_mac_rtt_us = 0;
    uint64_t quota_mac_rtt_us = 0;
    uint64_t blocked_risk_mac_rtt_us = 0;
    uint64_t base_candidate_mac_rtt_us = 0;
    uint64_t admission_candidate_mac_rtt_us = 0;
    uint64_t risk_srtt_us = 0;
    uint64_t blocked_risk_srtt_us = 0;
    uint64_t base_candidate_srtt_us = 0;
    uint64_t admission_candidate_srtt_us = 0;
    uint8_t probe_risk_reason_bits = 0;
    uint8_t risk_risk_reason_bits = 0;
    uint8_t quota_risk_reason_bits = 0;
    uint8_t selected_risk_reason_bits = 0;
    int original_state_rank = xqc_mac_aware_state_rank(XQC_WIFI_PATH_STATE_UNKNOWN);
    double original_tail_risk = 0.0;
    double original_pi_degraded = 0.0;
    double original_r_eff_Bpus = 0.0;
    uint64_t original_mac_rtt_us = 0;
    uint8_t original_risk_reason_bits = 0;
    xqc_bool_t admission_candidate_can_send = XQC_FALSE;
    xqc_bool_t estimate_available = XQC_FALSE;
    uint64_t eta_clean_us = 0;
    uint64_t eta_risky_us = 0;
    uint64_t eta_delta_us = 0;
    double predicted_reorder_bytes = 0.0;
    double risky_service_cost_us_per_kib = 0.0;
    uint64_t quota_tokens_bytes = 0;
    uint64_t service_tokens_bytes = 0;
    uint64_t reorder_debt_bytes = 0;
    uint64_t risk_inflight_debt_bytes = 0;
    uint64_t risk_inflight_budget_bytes = 0;
    const char *admission_block_reason = "no_estimate";
    const char *decision_reason = "normal";
    const xqc_mac_aware_config_t *config = xqc_mac_aware_get_config();

    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }

    xqc_scheduler_observation_init(&observation, "mac_aware", conn,
        conn->user_data, packet_out->po_pkt.pkt_num, packet_out->po_used_size);
    now = xqc_monotonic_timestamp();
    observation.ts_us = now;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        path_class = xqc_path_get_perf_class(path);
        path_can_send = XQC_FALSE;
        path_srtt = 0;
        path_high_risk = XQC_FALSE;
        path_probe_due = XQC_FALSE;
        path_risk_reason_bits = 0;
        has_wifi_snapshot = xqc_mac_aware_get_path_state(conn->user_data,
            path->path_id, now, &wifi_snapshot, &path_high_risk,
            &path_risk_reason_bits);
        state_rank = has_wifi_snapshot
            ? xqc_mac_aware_state_rank(wifi_snapshot.state)
            : xqc_mac_aware_state_rank(XQC_WIFI_PATH_STATE_UNKNOWN);
        tail_risk = has_wifi_snapshot ? xqc_mac_aware_tail_risk(&wifi_snapshot) : 0.0;
        pi_degraded = has_wifi_snapshot ? wifi_snapshot.pi_degraded : 0.0;
        r_eff_Bpus = has_wifi_snapshot ? wifi_snapshot.r_eff_Bpus : 0.0;
        mac_rtt_us = has_wifi_snapshot ? (uint64_t) wifi_snapshot.ewma_mac_rtt_us : 0;

        xqc_scheduler_observe_path(&observation, path, 0, path_class);
        xqc_mac_aware_observation_set_path_risk(&observation, path->path_id,
            !reinject && has_wifi_snapshot && path_high_risk,
            xqc_mac_aware_risk_reason_label(path_risk_reason_bits));

        if (!xqc_scheduler_path_is_usable(path)) {
            goto skip_path;
        }

        reached_cwnd_check = XQC_TRUE;
        if (cc_blocked) {
            *cc_blocked = XQC_TRUE;
        }

        path_srtt = xqc_send_ctl_get_srtt(path->path_send_ctl);
        path_high_risk = !reinject && has_wifi_snapshot && path_high_risk;
        path_can_send = xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd);
        xqc_mac_aware_observation_set_can_send(&observation, path->path_id,
            path_can_send);
        if (!path_can_send) {
            if (path_high_risk
                && xqc_mac_aware_risk_path_better(mac_rtt_us, path_srtt,
                    r_eff_Bpus, blocked_risk_path, blocked_risk_mac_rtt_us,
                    blocked_risk_r_eff_Bpus))
            {
                blocked_risk_path = path;
                blocked_risk_r_eff_Bpus = r_eff_Bpus;
                blocked_risk_mac_rtt_us = mac_rtt_us;
                blocked_risk_srtt_us = path_srtt;
            }
            goto skip_path;
        }

        if (cc_blocked) {
            *cc_blocked = XQC_FALSE;
        }

        if (reinject && packet_out->po_path_id == path->path_id) {
            original_path = path;
            original_path_class = path_class;
            original_state_rank = state_rank;
            original_tail_risk = tail_risk;
            original_pi_degraded = pi_degraded;
            original_r_eff_Bpus = r_eff_Bpus;
            original_mac_rtt_us = mac_rtt_us;
            original_risk_reason_bits = path_risk_reason_bits;
            goto skip_path;
        }

        if (path_high_risk) {
            if (xqc_mac_aware_risk_path_better(mac_rtt_us, path_srtt,
                r_eff_Bpus, risk_path, risk_mac_rtt_us, risk_r_eff_Bpus))
            {
                risk_path = path;
                risk_state_rank = state_rank;
                risk_tail_risk = tail_risk;
                risk_pi_degraded = pi_degraded;
                risk_r_eff_Bpus = r_eff_Bpus;
                risk_mac_rtt_us = mac_rtt_us;
                risk_risk_reason_bits = path_risk_reason_bits;
                risk_srtt_us = path_srtt;
                risk_path_class = path_class;
            }

            if (config->mode == XQC_MAC_AWARE_MODE_SOFT_QUOTA
                && config->quota_pct > 0
                && xqc_mac_aware_risk_path_better(mac_rtt_us, path_srtt,
                    r_eff_Bpus, quota_path, quota_mac_rtt_us,
                    quota_r_eff_Bpus))
            {
                quota_path = path;
                quota_state_rank = state_rank;
                quota_tail_risk = tail_risk;
                quota_pi_degraded = pi_degraded;
                quota_r_eff_Bpus = r_eff_Bpus;
                quota_mac_rtt_us = mac_rtt_us;
                quota_risk_reason_bits = path_risk_reason_bits;
                quota_path_class = path_class;
            }

            path_probe_due = xqc_mac_aware_probe_due(conn->user_data,
                path->path_id, now);
            if (path_probe_due
                && xqc_mac_aware_risk_path_better(mac_rtt_us, path_srtt,
                    r_eff_Bpus, probe_path, probe_mac_rtt_us,
                    probe_r_eff_Bpus))
            {
                probe_path = path;
                probe_state_rank = state_rank;
                probe_tail_risk = tail_risk;
                probe_pi_degraded = pi_degraded;
                probe_r_eff_Bpus = r_eff_Bpus;
                probe_mac_rtt_us = mac_rtt_us;
                probe_risk_reason_bits = path_risk_reason_bits;
                probe_path_class = path_class;
            }
            goto skip_path;
        }

        if (xqc_mac_aware_clean_path_better(mac_rtt_us, path_srtt,
            best_path, best_mac_rtt_us, config))
        {
            best_path = path;
            best_state_rank = state_rank;
            best_tail_risk = tail_risk;
            best_pi_degraded = pi_degraded;
            best_r_eff_Bpus = r_eff_Bpus;
            best_mac_rtt_us = mac_rtt_us;
            best_path_class = path_class;
        }

skip_path:
        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|mac_aware_path|conn:%p|scheduler:%s|path_id:%ui|path_srtt:%ui|path_class:%d|"
                "can_send:%d|path_status:%d|path_state:%d|reinj:%d|"
                "pkt_path_id:%ui|wifi_valid:%d|wifi_state:%d|tail_excess:%.6f|"
                "pi_degraded:%.6f|r_eff_Bpus:%.6f|mac_rtt:%ui|risk:%d|"
                "probe_due:%d|best_path:%i|probe_path:%i|risk_path:%i|"
                "best_state_rank:%d|",
                conn, "mac_aware", path->path_id, path_srtt, path_class, path_can_send,
                path->app_path_status, path->path_state, reinject,
                packet_out->po_path_id, has_wifi_snapshot,
                has_wifi_snapshot ? wifi_snapshot.state : XQC_WIFI_PATH_STATE_UNKNOWN,
                tail_risk, pi_degraded, r_eff_Bpus, mac_rtt_us, path_high_risk,
                path_probe_due, best_path ? best_path->path_id : -1,
                probe_path ? probe_path->path_id : -1,
                risk_path ? risk_path->path_id : -1, best_state_rank);
    }

    base_candidate_path = best_path;
    if (base_candidate_path != NULL) {
        base_candidate_srtt_us =
            xqc_send_ctl_get_srtt(base_candidate_path->path_send_ctl);
        base_candidate_mac_rtt_us = best_mac_rtt_us;
        base_candidate_r_eff_Bpus = best_r_eff_Bpus;
        observation.has_base_candidate = 1;
        observation.base_candidate_path_id = base_candidate_path->path_id;
    }

    if (risk_path != NULL) {
        admission_candidate_path = risk_path;
        admission_candidate_can_send = XQC_TRUE;
        admission_candidate_srtt_us = risk_srtt_us;
        admission_candidate_mac_rtt_us = risk_mac_rtt_us;
        admission_candidate_r_eff_Bpus = risk_r_eff_Bpus;

    } else if (blocked_risk_path != NULL) {
        admission_candidate_path = blocked_risk_path;
        admission_candidate_can_send = XQC_FALSE;
        admission_candidate_srtt_us = blocked_risk_srtt_us;
        admission_candidate_mac_rtt_us = blocked_risk_mac_rtt_us;
        admission_candidate_r_eff_Bpus = blocked_risk_r_eff_Bpus;
    }

    if (admission_candidate_path != NULL) {
        observation.has_admission_candidate = 1;
        observation.admission_candidate_path_id =
            admission_candidate_path->path_id;
    }

    if (base_candidate_path == NULL) {
        admission_block_reason = "no_clean_candidate";

    } else if (admission_candidate_path == NULL) {
        admission_block_reason = "no_risky_candidate";

    } else {
        eta_clean_us = xqc_mac_aware_eta_path_us(base_candidate_srtt_us,
            base_candidate_mac_rtt_us);
        eta_risky_us = xqc_mac_aware_eta_path_us(admission_candidate_srtt_us,
            admission_candidate_mac_rtt_us);
        eta_delta_us = eta_risky_us > eta_clean_us
            ? eta_risky_us - eta_clean_us : 0;
        risky_service_cost_us_per_kib =
            xqc_mac_aware_service_cost_us_per_kib(eta_risky_us,
                admission_candidate_r_eff_Bpus);

        if (eta_clean_us > 0 && eta_risky_us > 0
            && base_candidate_r_eff_Bpus > 0.0)
        {
            estimate_available = XQC_TRUE;
            predicted_reorder_bytes =
                base_candidate_r_eff_Bpus * (double) eta_delta_us;

            if (!admission_candidate_can_send) {
                admission_block_reason = "risky_not_sendable";

            } else if (predicted_reorder_bytes <=
                (double) config->reorder_budget_bytes)
            {
                admission_block_reason = "none";
                observation.admission_allowed = 1;
                quota_tokens_bytes =
                    (uint64_t) ((double) config->reorder_budget_bytes
                                - predicted_reorder_bytes);

            } else {
                admission_block_reason = "reorder_budget";
            }

        } else {
            admission_block_reason = "no_estimate";
        }
    }

    if (!reinject
        && config->mode == XQC_MAC_AWARE_MODE_SERVICE_ADMISSION
        && admission_candidate_path != NULL && estimate_available)
    {
        xqc_mac_aware_service_refresh_state(conn->user_data,
            admission_candidate_path, now, admission_candidate_r_eff_Bpus,
            config, &service_tokens_bytes, &reorder_debt_bytes,
            &risk_inflight_debt_bytes, &risk_inflight_budget_bytes);
    }

    if (!reinject
        && config->mode == XQC_MAC_AWARE_MODE_SERVICE_ADMISSION)
    {
        observation.admission_allowed = 0;
        quota_tokens_bytes = 0;

        if (base_candidate_path == NULL) {
            admission_block_reason = "no_clean_candidate";

        } else if (admission_candidate_path == NULL) {
            admission_block_reason = "no_risky_candidate";

        } else if (!estimate_available) {
            admission_block_reason = "no_estimate";

        } else if (!admission_candidate_can_send || risk_path == NULL
                   || admission_candidate_path != risk_path)
        {
            admission_block_reason = "risky_not_sendable";

        } else if (xqc_mac_aware_service_admission_allowed(conn->user_data,
                   risk_path, now, packet_out->po_used_size,
                   predicted_reorder_bytes, admission_candidate_r_eff_Bpus,
                   config, &admission_block_reason, &service_tokens_bytes,
                   &reorder_debt_bytes, &risk_inflight_debt_bytes,
                   &risk_inflight_budget_bytes))
        {
            service_admission_path = risk_path;
            observation.admission_allowed = 1;
        }
    }

    observation.eta_clean_us = eta_clean_us;
    observation.eta_risky_us = eta_risky_us;
    observation.eta_delta_us = eta_delta_us;
    observation.predicted_reorder_bytes =
        estimate_available ? predicted_reorder_bytes : 0.0;
    observation.risky_service_cost_us_per_kib = risky_service_cost_us_per_kib;
    observation.quota_tokens_bytes = quota_tokens_bytes;
    observation.service_tokens_bytes = service_tokens_bytes;
    observation.reorder_debt_bytes = reorder_debt_bytes;
    observation.risk_inflight_debt_bytes = risk_inflight_debt_bytes;
    observation.risk_inflight_budget_bytes = risk_inflight_budget_bytes;
    observation.admission_block_reason = admission_block_reason;

    if (!reinject && service_admission_path != NULL) {
        best_path = service_admission_path;
        best_path_class = risk_path_class;
        best_state_rank = risk_state_rank;
        best_tail_risk = risk_tail_risk;
        best_pi_degraded = risk_pi_degraded;
        best_r_eff_Bpus = risk_r_eff_Bpus;
        best_mac_rtt_us = risk_mac_rtt_us;
        selected_service_admission = XQC_TRUE;
        selected_risky_path = XQC_TRUE;
        selected_risk_reason_bits = risk_risk_reason_bits;
        decision_reason = "service_admission";
    }

    if (!reinject && best_path != NULL && quota_path != NULL
        && xqc_mac_aware_quota_allowed(conn->user_data, quota_path->path_id,
            now, packet_out->po_used_size, config))
    {
        best_path = quota_path;
        best_path_class = quota_path_class;
        best_state_rank = quota_state_rank;
        best_tail_risk = quota_tail_risk;
        best_pi_degraded = quota_pi_degraded;
        best_r_eff_Bpus = quota_r_eff_Bpus;
        best_mac_rtt_us = quota_mac_rtt_us;
        selected_quota = XQC_TRUE;
        selected_risky_path = XQC_TRUE;
        selected_risk_reason_bits = quota_risk_reason_bits;
        decision_reason = "quota";
    }

    if (!reinject && best_path == NULL && probe_path != NULL) {
        best_path = probe_path;
        best_path_class = probe_path_class;
        best_state_rank = probe_state_rank;
        best_tail_risk = probe_tail_risk;
        best_pi_degraded = probe_pi_degraded;
        best_r_eff_Bpus = probe_r_eff_Bpus;
        best_mac_rtt_us = probe_mac_rtt_us;
        selected_probe = XQC_TRUE;
        selected_risky_path = XQC_TRUE;
        selected_risk_reason_bits = probe_risk_reason_bits;
        decision_reason = "probe";
        xqc_mac_aware_mark_probe(conn->user_data, best_path->path_id, now);
    }

    if (!reinject && best_path == NULL && risk_path != NULL) {
        best_path = risk_path;
        best_path_class = risk_path_class;
        best_state_rank = risk_state_rank;
        best_tail_risk = risk_tail_risk;
        best_pi_degraded = risk_pi_degraded;
        best_r_eff_Bpus = risk_r_eff_Bpus;
        best_mac_rtt_us = risk_mac_rtt_us;
        selected_risk_fallback = XQC_TRUE;
        selected_risky_path = XQC_TRUE;
        selected_risk_reason_bits = risk_risk_reason_bits;
        decision_reason = "risk_fallback";
    }

    if (best_path == NULL && original_path != NULL
        && !(packet_out->po_flag & XQC_POF_REINJECT_DIFF_PATH))
    {
        best_path = original_path;
        best_path_class = original_path_class;
        best_state_rank = original_state_rank;
        best_tail_risk = original_tail_risk;
        best_pi_degraded = original_pi_degraded;
        best_r_eff_Bpus = original_r_eff_Bpus;
        best_mac_rtt_us = original_mac_rtt_us;
        selected_risk_reason_bits = original_risk_reason_bits;
        decision_reason = "reinject_original";
    }

    if (best_path != NULL) {
        if (!reinject && risk_path != NULL) {
            xqc_mac_aware_quota_record(conn->user_data, risk_path->path_id,
                now, packet_out->po_used_size,
                selected_risky_path && best_path == risk_path, config);
        }
        if (!reinject && selected_risky_path && risk_path != best_path) {
            xqc_mac_aware_quota_record(conn->user_data, best_path->path_id,
                now, packet_out->po_used_size, XQC_TRUE, config);
        }
        observation.has_selected_path = 1;
        observation.selected_path_id = best_path->path_id;
        observation.service_admission_selected =
            selected_service_admission ? 1 : 0;
        observation.selected_service_cost_us_per_kib =
            xqc_mac_aware_service_cost_us_per_kib(
                xqc_mac_aware_eta_path_us(
                    xqc_send_ctl_get_srtt(best_path->path_send_ctl),
                    best_mac_rtt_us),
                best_r_eff_Bpus);
        observation.decision_reason = decision_reason;
        observation.risk_reason =
            xqc_mac_aware_risk_reason_label(selected_risk_reason_bits);
        xqc_scheduler_notify_observer(&observation);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|mac_aware_best_path:%ui|scheduler:%s|"
                "frame_type:%s|pn:%ui|size:%ud|reinj:%d|path_class:%d|"
                "state_rank:%d|tail_excess:%.6f|pi_degraded:%.6f|"
                "r_eff_Bpus:%.6f|mac_rtt:%ui|probe:%d|risk_fallback:%d|"
                "quota:%d|service_admission:%d|decision:%s|risk_reason:%s|"
                "used_mask:%ui|",
                best_path->path_id, "mac_aware",
                xqc_frame_type_2_str(conn->engine, packet_out->po_frame_types),
                packet_out->po_pkt.pkt_num,
                packet_out->po_used_size, reinject, best_path_class,
                best_state_rank, best_tail_risk, best_pi_degraded,
                best_r_eff_Bpus, best_mac_rtt_us, selected_probe,
                selected_risk_fallback, selected_quota,
                selected_service_admission, decision_reason, observation.risk_reason,
                xqc_scheduler_packet_path_mask(conn, packet_out));
        return best_path;
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
