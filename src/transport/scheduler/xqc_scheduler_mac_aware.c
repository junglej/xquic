#include "src/transport/scheduler/xqc_scheduler_mac_aware.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/scheduler/xqc_scheduler_observer.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_transport_trace.h"

#include <pthread.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define XQC_MAC_AWARE_MAX_PATH_STATES 32
#define XQC_MAC_AWARE_MAX_CANDIDATES 8
#define XQC_MAC_AWARE_STALE_US 2000000ULL

#define XQC_MAC_AWARE_DEFAULT_BURST_K 2.0
#define XQC_MAC_AWARE_DEFAULT_MIN_BURST_BYTES 12000ULL
#define XQC_MAC_AWARE_DEFAULT_MAX_BURST_BYTES 262144ULL
#define XQC_MAC_AWARE_DEFAULT_BOOTSTRAP_BURST_BYTES 49152ULL
#define XQC_MAC_AWARE_DEFAULT_MIN_MAC_SAMPLES 8ULL
#define XQC_MAC_AWARE_DEFAULT_SERVICE_QUANTUM_CAP_BYTES 262144ULL
#define XQC_MAC_AWARE_DEFAULT_OFO_BUDGET_BYTES 1073741824ULL
#define XQC_MAC_AWARE_DEFAULT_RQ_LOW_FACTOR 1.0
#define XQC_MAC_AWARE_DEFAULT_RQ_HIGH_FACTOR 2.0
#define XQC_MAC_AWARE_OFFSET_OWNER_SLOTS 16
#define XQC_MAC_AWARE_DEFAULT_OFFSET_OWNER 1
#define XQC_MAC_AWARE_DEFAULT_STREAM_PLANNER 0
#define XQC_MAC_AWARE_DEFAULT_OFFSET_CHUNK_BYTES 262144ULL
#define XQC_MAC_AWARE_DEFAULT_OFFSET_MAX_CHUNK_BYTES 1048576ULL
#define XQC_MAC_AWARE_DEFAULT_RECOVERY_PROBE_INTERVAL_US 100000ULL
#define XQC_MAC_AWARE_DEFAULT_MAINT_PROBE_INTERVAL_US 500000ULL
#define XQC_MAC_AWARE_DEFAULT_RECOVERY_PROMOTE_SAMPLES 3ULL
#define XQC_MAC_AWARE_DEFAULT_LONG_GAP_HIGH 0.50
#define XQC_MAC_AWARE_DEFAULT_MIN_SERVICE_RATE_BYTES_PER_US 0.05
#define XQC_MAC_AWARE_DEFAULT_ACTIVE_EXPLORE_BYTES 67108864ULL

typedef struct xqc_mac_aware_config_s {
    double      burst_k;
    uint64_t    min_burst_bytes;
    uint64_t    max_burst_bytes;
    uint64_t    bootstrap_burst_bytes;
    uint64_t    min_mac_samples;
    uint64_t    service_quantum_cap_bytes;
    uint64_t    ofo_budget_bytes;
    double      rq_low_factor;
    double      rq_high_factor;
    uint8_t     use_gap_in_eta;
    uint8_t     offset_owner_enabled;
    uint8_t     stream_planner_enabled;
    uint64_t    offset_chunk_bytes;
    uint64_t    offset_max_chunk_bytes;
    uint64_t    recovery_probe_bytes;
    uint64_t    recovery_probe_interval_us;
    uint64_t    maint_probe_interval_us;
    uint64_t    recovery_promote_samples;
    double      long_gap_high;
    double      min_service_rate_bytes_per_us;
    uint64_t    active_explore_bytes;
} xqc_mac_aware_config_t;

typedef struct xqc_mac_aware_path_state_s {
    uint8_t                     used;
    void                       *conn_user_data;
    uint64_t                    path_id;
    xqc_wifi_state_snapshot_t   snapshot;
    uint64_t                    updated_at_us;
    uint64_t                    sample_count;
    uint64_t                    service_quantum_bytes;
    uint64_t                    observed_service_bytes;
    uint64_t                    mac_rtt_us;
    uint64_t                    gap_us;
    uint64_t                    last_selected_at_us;
    uint64_t                    last_probe_at_us;
    uint8_t                     recovery_good_count;
} xqc_mac_aware_path_state_t;

typedef struct xqc_mac_aware_offset_owner_s {
    uint8_t     used;
    uint64_t    stream_id;
    uint64_t    next_offset;
    uint64_t    path_id;
    uint64_t    remaining_bytes;
} xqc_mac_aware_offset_owner_t;

typedef struct xqc_mac_aware_scheduler_s {
    uint64_t    burst_path_id;
    uint64_t    burst_remaining_bytes;
    uint8_t     has_primary_path;
    uint64_t    primary_path_id;
    xqc_mac_aware_offset_owner_t
                offset_owners[XQC_MAC_AWARE_OFFSET_OWNER_SLOTS];
} xqc_mac_aware_scheduler_t;

typedef struct xqc_mac_aware_candidate_s {
    xqc_path_ctx_t             *path;
    xqc_wifi_state_snapshot_t   snapshot;
    xqc_bool_t                  has_snapshot;
    uint64_t                    sample_count;
    uint64_t                    srtt_us;
    uint64_t                    latest_rtt_us;
    uint64_t                    ack_age_us;
    uint64_t                    cwnd_bytes;
    uint64_t                    inflight_bytes;
    uint64_t                    cc_headroom_bytes;
    uint64_t                    backlog_bytes;
    uint64_t                    pending_intent_bytes;
    uint64_t                    service_quantum_bytes;
    uint64_t                    observed_service_bytes;
    uint64_t                    mac_rtt_us;
    uint64_t                    gap_us;
    double                      service_rate_bytes_per_us;
    uint64_t                    queue_quanta;
    uint64_t                    eta_us;
    uint64_t                    burst_budget_bytes;
    uint64_t                    last_selected_at_us;
    uint64_t                    last_probe_at_us;
    uint64_t                    selected_bytes;
    uint8_t                     recovery_good_count;
    xqc_path_perf_class_t       path_class;
} xqc_mac_aware_candidate_t;

static xqc_mac_aware_path_state_t g_mac_aware_path_states[XQC_MAC_AWARE_MAX_PATH_STATES];
static pthread_mutex_t g_mac_aware_path_states_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t g_mac_aware_config_once = PTHREAD_ONCE_INIT;
static xqc_mac_aware_config_t g_mac_aware_config;

static xqc_mac_aware_candidate_t *xqc_mac_aware_select_candidate(
    xqc_mac_aware_candidate_t *candidates, uint8_t candidate_count,
    const xqc_mac_aware_config_t *config, const char **decision_reason);
static xqc_mac_aware_candidate_t *xqc_mac_aware_select_candidate_v2(
    xqc_mac_aware_scheduler_t *ctx, xqc_mac_aware_candidate_t *candidates,
    uint8_t candidate_count, const xqc_mac_aware_config_t *config,
    uint64_t now, const char **decision_reason,
    xqc_bool_t *recovery_probe_selected,
    xqc_mac_aware_candidate_t **base_candidate,
    xqc_mac_aware_candidate_t **admission_candidate);
static xqc_mac_aware_candidate_t *xqc_mac_aware_alt_candidate(
    xqc_mac_aware_candidate_t *candidates, uint8_t candidate_count,
    const xqc_mac_aware_candidate_t *selected);
static uint64_t xqc_mac_aware_selected_burst_budget(
    const xqc_mac_aware_candidate_t *selected,
    const xqc_mac_aware_config_t *config, uint64_t packet_size,
    xqc_bool_t recovery_probe);
static void xqc_mac_aware_scheduler_note_primary(
    xqc_mac_aware_scheduler_t *ctx,
    const xqc_mac_aware_candidate_t *selected,
    const xqc_mac_aware_config_t *config, const char *decision_reason);

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

static void
xqc_mac_aware_config_init_once(void)
{
    memset(&g_mac_aware_config, 0, sizeof(g_mac_aware_config));

    g_mac_aware_config.burst_k =
        xqc_mac_aware_env_double("SQP_BURST_K",
            XQC_MAC_AWARE_DEFAULT_BURST_K);
    g_mac_aware_config.min_burst_bytes =
        xqc_mac_aware_env_u64("SQP_MIN_BURST_BYTES",
            XQC_MAC_AWARE_DEFAULT_MIN_BURST_BYTES);
    g_mac_aware_config.max_burst_bytes =
        xqc_mac_aware_env_u64("SQP_MAX_BURST_BYTES",
            XQC_MAC_AWARE_DEFAULT_MAX_BURST_BYTES);
    g_mac_aware_config.bootstrap_burst_bytes =
        xqc_mac_aware_env_u64("SQP_BOOTSTRAP_BURST_BYTES",
            xqc_mac_aware_env_u64("MAC_AWARE_PROBE_BYTES",
                XQC_MAC_AWARE_DEFAULT_BOOTSTRAP_BURST_BYTES));
    g_mac_aware_config.min_mac_samples =
        xqc_mac_aware_env_u64("SQP_MIN_MAC_SAMPLES",
            XQC_MAC_AWARE_DEFAULT_MIN_MAC_SAMPLES);
    g_mac_aware_config.service_quantum_cap_bytes =
        xqc_mac_aware_env_u64("SQP_SERVICE_QUANTUM_CAP_BYTES",
            xqc_mac_aware_env_u64("MAC_AWARE_SERVICE_QUANTUM_CAP_BYTES",
                XQC_MAC_AWARE_DEFAULT_SERVICE_QUANTUM_CAP_BYTES));
    g_mac_aware_config.ofo_budget_bytes =
        xqc_mac_aware_env_u64("SQP_OFO_BUDGET_BYTES",
            xqc_mac_aware_env_u64("MAC_AWARE_OFO_BUDGET_BYTES",
                XQC_MAC_AWARE_DEFAULT_OFO_BUDGET_BYTES));
    g_mac_aware_config.rq_low_factor =
        xqc_mac_aware_env_double("SQP_RQ_LOW_FACTOR",
            xqc_mac_aware_env_double("MAC_AWARE_RQ_LOW_FACTOR",
                XQC_MAC_AWARE_DEFAULT_RQ_LOW_FACTOR));
    g_mac_aware_config.rq_high_factor =
        xqc_mac_aware_env_double("SQP_RQ_HIGH_FACTOR",
            xqc_mac_aware_env_double("MAC_AWARE_RQ_HIGH_FACTOR",
                XQC_MAC_AWARE_DEFAULT_RQ_HIGH_FACTOR));
    g_mac_aware_config.use_gap_in_eta =
        xqc_mac_aware_env_u64("SQP_USE_GAP_IN_ETA", 0) ? 1 : 0;
    g_mac_aware_config.offset_owner_enabled =
        xqc_mac_aware_env_u64("MAC_AWARE_OFFSET_OWNER",
            XQC_MAC_AWARE_DEFAULT_OFFSET_OWNER) ? 1 : 0;
    g_mac_aware_config.stream_planner_enabled =
        xqc_mac_aware_env_u64("MAC_AWARE_PACKET_ONLY", 0) ? 0 :
        (xqc_mac_aware_env_u64("MAC_AWARE_STREAM_PLANNER",
            XQC_MAC_AWARE_DEFAULT_STREAM_PLANNER) ? 1 : 0);
    g_mac_aware_config.offset_chunk_bytes =
        xqc_mac_aware_env_u64("MAC_AWARE_OFFSET_CHUNK_BYTES",
            XQC_MAC_AWARE_DEFAULT_OFFSET_CHUNK_BYTES);
    g_mac_aware_config.offset_max_chunk_bytes =
        xqc_mac_aware_env_u64("MAC_AWARE_OFFSET_MAX_CHUNK_BYTES",
            XQC_MAC_AWARE_DEFAULT_OFFSET_MAX_CHUNK_BYTES);
    g_mac_aware_config.recovery_probe_bytes =
        xqc_mac_aware_env_u64("MAC_AWARE_RECOVERY_PROBE_BYTES",
            g_mac_aware_config.bootstrap_burst_bytes);
    g_mac_aware_config.recovery_probe_interval_us =
        xqc_mac_aware_env_u64("MAC_AWARE_RECOVERY_PROBE_INTERVAL_US",
            XQC_MAC_AWARE_DEFAULT_RECOVERY_PROBE_INTERVAL_US);
    g_mac_aware_config.maint_probe_interval_us =
        xqc_mac_aware_env_u64("MAC_AWARE_MAINT_PROBE_INTERVAL_US",
            XQC_MAC_AWARE_DEFAULT_MAINT_PROBE_INTERVAL_US);
    g_mac_aware_config.recovery_promote_samples =
        xqc_mac_aware_env_u64("MAC_AWARE_RECOVERY_PROMOTE_SAMPLES",
            XQC_MAC_AWARE_DEFAULT_RECOVERY_PROMOTE_SAMPLES);
    g_mac_aware_config.long_gap_high =
        xqc_mac_aware_env_double("MAC_AWARE_LONG_GAP_HIGH",
            XQC_MAC_AWARE_DEFAULT_LONG_GAP_HIGH);
    g_mac_aware_config.min_service_rate_bytes_per_us =
        xqc_mac_aware_env_double("MAC_AWARE_MIN_SERVICE_RATE_BYTES_PER_US",
            XQC_MAC_AWARE_DEFAULT_MIN_SERVICE_RATE_BYTES_PER_US);
    g_mac_aware_config.active_explore_bytes =
        xqc_mac_aware_env_u64("MAC_AWARE_ACTIVE_EXPLORE_BYTES",
            XQC_MAC_AWARE_DEFAULT_ACTIVE_EXPLORE_BYTES);
    if (g_mac_aware_config.burst_k <= 0.0) {
        g_mac_aware_config.burst_k = XQC_MAC_AWARE_DEFAULT_BURST_K;
    }
    if (g_mac_aware_config.min_burst_bytes == 0) {
        g_mac_aware_config.min_burst_bytes =
            XQC_MAC_AWARE_DEFAULT_MIN_BURST_BYTES;
    }
    if (g_mac_aware_config.max_burst_bytes
        < g_mac_aware_config.min_burst_bytes)
    {
        g_mac_aware_config.max_burst_bytes =
            g_mac_aware_config.min_burst_bytes;
    }
    if (g_mac_aware_config.bootstrap_burst_bytes
        < g_mac_aware_config.min_burst_bytes)
    {
        g_mac_aware_config.bootstrap_burst_bytes =
            g_mac_aware_config.min_burst_bytes;
    }
    if (g_mac_aware_config.bootstrap_burst_bytes
        > g_mac_aware_config.max_burst_bytes)
    {
        g_mac_aware_config.bootstrap_burst_bytes =
            g_mac_aware_config.max_burst_bytes;
    }
    if (g_mac_aware_config.min_mac_samples == 0) {
        g_mac_aware_config.min_mac_samples = 1;
    }
    if (g_mac_aware_config.service_quantum_cap_bytes == 0) {
        g_mac_aware_config.service_quantum_cap_bytes =
            XQC_MAC_AWARE_DEFAULT_SERVICE_QUANTUM_CAP_BYTES;
    }
    if (g_mac_aware_config.rq_low_factor <= 0.0) {
        g_mac_aware_config.rq_low_factor =
            XQC_MAC_AWARE_DEFAULT_RQ_LOW_FACTOR;
    }
    if (g_mac_aware_config.rq_high_factor
        < g_mac_aware_config.rq_low_factor)
    {
        g_mac_aware_config.rq_high_factor =
            g_mac_aware_config.rq_low_factor;
    }
    if (g_mac_aware_config.offset_chunk_bytes == 0) {
        g_mac_aware_config.offset_chunk_bytes =
            XQC_MAC_AWARE_DEFAULT_OFFSET_CHUNK_BYTES;
    }
    if (g_mac_aware_config.offset_max_chunk_bytes == 0) {
        g_mac_aware_config.offset_max_chunk_bytes =
            g_mac_aware_config.offset_chunk_bytes;
    }
    if (g_mac_aware_config.offset_chunk_bytes
        > g_mac_aware_config.offset_max_chunk_bytes)
    {
        g_mac_aware_config.offset_chunk_bytes =
            g_mac_aware_config.offset_max_chunk_bytes;
    }
    if (g_mac_aware_config.recovery_probe_bytes == 0) {
        g_mac_aware_config.recovery_probe_bytes =
            g_mac_aware_config.min_burst_bytes;
    }
    if (g_mac_aware_config.recovery_probe_bytes
        < g_mac_aware_config.min_burst_bytes)
    {
        g_mac_aware_config.recovery_probe_bytes =
            g_mac_aware_config.min_burst_bytes;
    }
    if (g_mac_aware_config.recovery_probe_bytes
        > g_mac_aware_config.max_burst_bytes)
    {
        g_mac_aware_config.recovery_probe_bytes =
            g_mac_aware_config.max_burst_bytes;
    }
    if (g_mac_aware_config.recovery_probe_interval_us == 0) {
        g_mac_aware_config.recovery_probe_interval_us =
            XQC_MAC_AWARE_DEFAULT_RECOVERY_PROBE_INTERVAL_US;
    }
    if (g_mac_aware_config.maint_probe_interval_us == 0) {
        g_mac_aware_config.maint_probe_interval_us =
            XQC_MAC_AWARE_DEFAULT_MAINT_PROBE_INTERVAL_US;
    }
    if (g_mac_aware_config.recovery_promote_samples == 0) {
        g_mac_aware_config.recovery_promote_samples = 1;
    }
    if (g_mac_aware_config.long_gap_high <= 0.0
        || g_mac_aware_config.long_gap_high > 1.0)
    {
        g_mac_aware_config.long_gap_high =
            XQC_MAC_AWARE_DEFAULT_LONG_GAP_HIGH;
    }
    if (g_mac_aware_config.min_service_rate_bytes_per_us < 0.0) {
        g_mac_aware_config.min_service_rate_bytes_per_us =
            XQC_MAC_AWARE_DEFAULT_MIN_SERVICE_RATE_BYTES_PER_US;
    }
}

static const xqc_mac_aware_config_t *
xqc_mac_aware_get_config(void)
{
    pthread_once(&g_mac_aware_config_once, xqc_mac_aware_config_init_once);
    return &g_mac_aware_config;
}

static uint64_t
xqc_mac_aware_min_u64(uint64_t a, uint64_t b)
{
    return a < b ? a : b;
}

static uint64_t
xqc_mac_aware_max_u64(uint64_t a, uint64_t b)
{
    return a > b ? a : b;
}

static uint64_t
xqc_mac_aware_ceil_div_u64(uint64_t a, uint64_t b)
{
    if (b == 0) {
        return 1;
    }
    if (a == 0) {
        return 1;
    }
    return a / b + (a % b != 0);
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
xqc_mac_aware_cap_service_quantum(uint64_t service_bytes,
    const xqc_mac_aware_config_t *config)
{
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
xqc_mac_aware_update_capacity_quantum(uint64_t current, uint64_t observed,
    const xqc_mac_aware_config_t *config)
{
    uint64_t decayed;

    observed = xqc_mac_aware_cap_service_quantum(observed, config);
    if (observed == 0) {
        return current;
    }
    if (current == 0) {
        return observed;
    }

    decayed = current - current / 32;
    if (decayed == current && decayed > 0) {
        decayed--;
    }

    if (observed > decayed) {
        return observed;
    }
    return xqc_mac_aware_max_u64(decayed, observed);
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
    uint64_t now;
    uint64_t observed_service_bytes;
    const xqc_mac_aware_config_t *config;

    if (conn_user_data == NULL || snapshot == NULL) {
        return;
    }

    config = xqc_mac_aware_get_config();
    observed_service_bytes = xqc_mac_aware_snapshot_service_bytes(snapshot);
    now = xqc_monotonic_timestamp();

    pthread_mutex_lock(&g_mac_aware_path_states_lock);
    i = xqc_mac_aware_ensure_state_slot_locked(conn_user_data, path_id);
    g_mac_aware_path_states[i].snapshot = *snapshot;
    g_mac_aware_path_states[i].updated_at_us = now;
    g_mac_aware_path_states[i].sample_count = snapshot->sample_count;
    if (g_mac_aware_path_states[i].sample_count == 0) {
        g_mac_aware_path_states[i].sample_count++;
    }
    g_mac_aware_path_states[i].observed_service_bytes =
        observed_service_bytes;
    g_mac_aware_path_states[i].service_quantum_bytes =
        xqc_mac_aware_update_capacity_quantum(
            g_mac_aware_path_states[i].service_quantum_bytes,
            observed_service_bytes, config);
    if (snapshot->ewma_mac_rtt_us > 0.0) {
        g_mac_aware_path_states[i].mac_rtt_us =
            (uint64_t) snapshot->ewma_mac_rtt_us;
    } else if (snapshot->last_mac_rtt_us > 0) {
        g_mac_aware_path_states[i].mac_rtt_us =
            snapshot->last_mac_rtt_us;
    }
    if (snapshot->ewma_gap_us > 0.0) {
        g_mac_aware_path_states[i].gap_us = (uint64_t) snapshot->ewma_gap_us;
    } else if (snapshot->last_gap_us > 0) {
        g_mac_aware_path_states[i].gap_us = snapshot->last_gap_us;
    }
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
        && now - g_mac_aware_path_states[i].updated_at_us
            <= XQC_MAC_AWARE_STALE_US)
    {
        *snapshot = g_mac_aware_path_states[i].snapshot;
        found = XQC_TRUE;
    }
    pthread_mutex_unlock(&g_mac_aware_path_states_lock);

    if (high_risk != NULL) {
        *high_risk = XQC_FALSE;
    }
    if (risk_reason_bits != NULL) {
        *risk_reason_bits = 0;
    }

    return found;
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
    return 0.0;
}

static void
xqc_mac_aware_candidate_update_transport(xqc_mac_aware_candidate_t *candidate,
    uint64_t now, int check_cwnd)
{
    xqc_send_ctl_t *send_ctl;
    uint64_t used_bytes;

    if (candidate == NULL || candidate->path == NULL
        || candidate->path->path_send_ctl == NULL)
    {
        return;
    }

    send_ctl = candidate->path->path_send_ctl;
    candidate->srtt_us = xqc_send_ctl_get_srtt(send_ctl);
    candidate->latest_rtt_us = send_ctl->ctl_latest_rtt;
    candidate->cwnd_bytes = xqc_mac_aware_path_cwnd(candidate->path);
    candidate->inflight_bytes = send_ctl->ctl_bytes_in_flight;
    candidate->backlog_bytes = candidate->path->path_schedule_bytes;
    candidate->selected_bytes =
        candidate->path->send_avail_stats.scheduler_selected_bytes;
    if (send_ctl->ctl_delivered_time > 0
        && now >= send_ctl->ctl_delivered_time)
    {
        candidate->ack_age_us = now - send_ctl->ctl_delivered_time;
    }

    used_bytes = candidate->inflight_bytes + candidate->backlog_bytes;
    if (!check_cwnd) {
        candidate->cc_headroom_bytes = UINT64_MAX;
    } else if (candidate->cwnd_bytes > used_bytes) {
        candidate->cc_headroom_bytes = candidate->cwnd_bytes - used_bytes;
    } else {
        candidate->cc_headroom_bytes = 0;
    }
}

static void
xqc_mac_aware_candidate_load_state(void *conn_user_data,
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
        candidate->last_selected_at_us =
            g_mac_aware_path_states[i].last_selected_at_us;
        candidate->last_probe_at_us =
            g_mac_aware_path_states[i].last_probe_at_us;
        candidate->recovery_good_count =
            g_mac_aware_path_states[i].recovery_good_count;
        if (now >= g_mac_aware_path_states[i].updated_at_us
            && now - g_mac_aware_path_states[i].updated_at_us
                <= XQC_MAC_AWARE_STALE_US)
        {
            candidate->has_snapshot = XQC_TRUE;
            candidate->snapshot = g_mac_aware_path_states[i].snapshot;
            candidate->sample_count = g_mac_aware_path_states[i].sample_count;
            candidate->service_quantum_bytes =
                g_mac_aware_path_states[i].service_quantum_bytes;
            candidate->observed_service_bytes =
                g_mac_aware_path_states[i].observed_service_bytes;
            candidate->mac_rtt_us = g_mac_aware_path_states[i].mac_rtt_us;
            candidate->gap_us = g_mac_aware_path_states[i].gap_us;
        }
    }
    pthread_mutex_unlock(&g_mac_aware_path_states_lock);

    if (candidate->has_snapshot) {
        candidate->service_rate_bytes_per_us =
            xqc_mac_aware_snapshot_service_rate(&candidate->snapshot);
    }
    if (candidate->service_quantum_bytes == 0) {
        candidate->service_quantum_bytes = config->min_burst_bytes;
    }
    candidate->service_quantum_bytes =
        xqc_mac_aware_max_u64(candidate->service_quantum_bytes,
            config->min_burst_bytes);
    if (candidate->service_quantum_bytes
        > config->service_quantum_cap_bytes)
    {
        candidate->service_quantum_bytes =
            config->service_quantum_cap_bytes;
    }
}

static void
xqc_mac_aware_candidate_compute_budget(xqc_mac_aware_candidate_t *candidate,
    const xqc_mac_aware_config_t *config, size_t packet_size)
{
    uint64_t desired;
    uint64_t q;

    if (candidate == NULL || config == NULL) {
        return;
    }

    q = candidate->service_quantum_bytes > 0
        ? candidate->service_quantum_bytes : config->min_burst_bytes;

    if (candidate->sample_count < config->min_mac_samples) {
        desired = config->bootstrap_burst_bytes;
    } else {
        desired = (uint64_t) ((double) q * config->burst_k);
    }

    desired = xqc_mac_aware_max_u64(desired, config->min_burst_bytes);
    desired = xqc_mac_aware_min_u64(desired, config->max_burst_bytes);
    if (candidate->cc_headroom_bytes != UINT64_MAX) {
        desired = xqc_mac_aware_min_u64(desired,
            candidate->cc_headroom_bytes);
    }
    if (desired < packet_size) {
        desired = 0;
    }

    candidate->burst_budget_bytes = desired;
}

static void
xqc_mac_aware_candidate_compute_eta(xqc_mac_aware_candidate_t *candidate,
    const xqc_mac_aware_config_t *config)
{
    uint64_t q;
    uint64_t service_time_us;

    if (candidate == NULL || config == NULL) {
        return;
    }

    if (candidate->sample_count < config->min_mac_samples) {
        candidate->queue_quanta = 1;
        candidate->eta_us = candidate->srtt_us;
        return;
    }

    q = candidate->service_quantum_bytes > 0
        ? candidate->service_quantum_bytes : config->min_burst_bytes;
    service_time_us = candidate->mac_rtt_us > 0
        ? candidate->mac_rtt_us : candidate->srtt_us;
    if (config->use_gap_in_eta) {
        service_time_us += candidate->gap_us;
    }

    candidate->queue_quanta =
        xqc_mac_aware_ceil_div_u64(candidate->backlog_bytes, q);
    candidate->eta_us = candidate->queue_quanta * service_time_us
        + candidate->srtt_us / 2;
}

static xqc_bool_t
xqc_mac_aware_cold_better(const xqc_mac_aware_candidate_t *candidate,
    const xqc_mac_aware_candidate_t *best)
{
    if (candidate == NULL || candidate->path == NULL) {
        return XQC_FALSE;
    }
    if (best == NULL || best->path == NULL) {
        return XQC_TRUE;
    }
    if (candidate->sample_count != best->sample_count) {
        return candidate->sample_count < best->sample_count;
    }
    if (candidate->backlog_bytes != best->backlog_bytes) {
        return candidate->backlog_bytes < best->backlog_bytes;
    }
    if (candidate->last_selected_at_us != best->last_selected_at_us) {
        return candidate->last_selected_at_us < best->last_selected_at_us;
    }
    return candidate->srtt_us < best->srtt_us;
}

static xqc_bool_t
xqc_mac_aware_starved_better(const xqc_mac_aware_candidate_t *candidate,
    const xqc_mac_aware_candidate_t *best)
{
    uint64_t lhs;
    uint64_t rhs;

    if (candidate == NULL || candidate->path == NULL) {
        return XQC_FALSE;
    }
    if (best == NULL || best->path == NULL) {
        return XQC_TRUE;
    }

    lhs = candidate->backlog_bytes * best->service_quantum_bytes;
    rhs = best->backlog_bytes * candidate->service_quantum_bytes;
    if (lhs != rhs) {
        return lhs < rhs;
    }
    if (candidate->eta_us != best->eta_us) {
        return candidate->eta_us < best->eta_us;
    }
    if (candidate->last_selected_at_us != best->last_selected_at_us) {
        return candidate->last_selected_at_us < best->last_selected_at_us;
    }
    return candidate->srtt_us < best->srtt_us;
}

static xqc_bool_t
xqc_mac_aware_eta_better(const xqc_mac_aware_candidate_t *candidate,
    const xqc_mac_aware_candidate_t *best)
{
    if (candidate == NULL || candidate->path == NULL) {
        return XQC_FALSE;
    }
    if (best == NULL || best->path == NULL) {
        return XQC_TRUE;
    }
    if (candidate->eta_us != best->eta_us) {
        return candidate->eta_us < best->eta_us;
    }
    if (candidate->backlog_bytes != best->backlog_bytes) {
        return candidate->backlog_bytes < best->backlog_bytes;
    }
    if (candidate->service_quantum_bytes != best->service_quantum_bytes) {
        return candidate->service_quantum_bytes
            > best->service_quantum_bytes;
    }
    if (candidate->last_selected_at_us != best->last_selected_at_us) {
        return candidate->last_selected_at_us < best->last_selected_at_us;
    }
    return candidate->srtt_us < best->srtt_us;
}

static const char *
xqc_mac_aware_candidate_risk_reason(
    const xqc_mac_aware_candidate_t *candidate,
    const xqc_mac_aware_config_t *config)
{
    if (candidate == NULL || config == NULL || !candidate->has_snapshot) {
        return "none";
    }

    if (candidate->snapshot.state == XQC_WIFI_PATH_STATE_DEGRADED_CSMA) {
        return "degraded_csma";
    }

    if (candidate->sample_count < config->min_mac_samples) {
        return "none";
    }

    if (candidate->snapshot.p_long_gap >= config->long_gap_high) {
        return "long_gap";
    }

    if (config->min_service_rate_bytes_per_us > 0.0
        && candidate->service_rate_bytes_per_us
            <= config->min_service_rate_bytes_per_us)
    {
        return "service_collapse";
    }

    return "none";
}

static xqc_bool_t
xqc_mac_aware_candidate_high_risk(
    const xqc_mac_aware_candidate_t *candidate,
    const xqc_mac_aware_config_t *config)
{
    return strcmp(xqc_mac_aware_candidate_risk_reason(candidate, config),
                  "none") != 0;
}

static xqc_bool_t
xqc_mac_aware_candidate_recovery_ready(
    const xqc_mac_aware_candidate_t *candidate,
    const xqc_mac_aware_config_t *config)
{
    if (candidate == NULL || config == NULL) {
        return XQC_FALSE;
    }

    return candidate->sample_count >= config->min_mac_samples
           && !xqc_mac_aware_candidate_high_risk(candidate, config);
}

static void
xqc_mac_aware_note_selection(void *conn_user_data, uint64_t path_id,
    uint64_t now)
{
    int i;

    if (conn_user_data == NULL) {
        return;
    }

    pthread_mutex_lock(&g_mac_aware_path_states_lock);
    i = xqc_mac_aware_ensure_state_slot_locked(conn_user_data, path_id);
    g_mac_aware_path_states[i].last_selected_at_us = now;
    pthread_mutex_unlock(&g_mac_aware_path_states_lock);
}

static void
xqc_mac_aware_note_candidate_selection(void *conn_user_data,
    const xqc_mac_aware_candidate_t *candidate, uint64_t now,
    const xqc_mac_aware_config_t *config, xqc_bool_t recovery_probe)
{
    int i;
    xqc_bool_t ready;
    xqc_bool_t high_risk;

    if (conn_user_data == NULL || candidate == NULL
        || candidate->path == NULL || config == NULL)
    {
        return;
    }

    ready = xqc_mac_aware_candidate_recovery_ready(candidate, config);
    high_risk = xqc_mac_aware_candidate_high_risk(candidate, config);

    pthread_mutex_lock(&g_mac_aware_path_states_lock);
    i = xqc_mac_aware_ensure_state_slot_locked(conn_user_data,
        candidate->path->path_id);
    g_mac_aware_path_states[i].last_selected_at_us = now;
    if (recovery_probe) {
        g_mac_aware_path_states[i].last_probe_at_us = now;
    }
    if (ready) {
        if (g_mac_aware_path_states[i].recovery_good_count < UINT8_MAX) {
            g_mac_aware_path_states[i].recovery_good_count++;
        }
    } else if (high_risk) {
        g_mac_aware_path_states[i].recovery_good_count = 0;
    }
    pthread_mutex_unlock(&g_mac_aware_path_states_lock);
}

xqc_bool_t
xqc_mac_aware_stream_generation_enabled(xqc_connection_t *conn)
{
    const xqc_mac_aware_config_t *config = xqc_mac_aware_get_config();

    if (conn == NULL || conn->scheduler_callback == NULL) {
        return XQC_FALSE;
    }
    return config != NULL
           && config->stream_planner_enabled
           && conn->scheduler_callback->xqc_scheduler_get_path
           == xqc_mac_aware_scheduler_get_path;
}

static uint64_t
xqc_mac_aware_unscheduled_intent_bytes_on_list(xqc_list_head_t *head,
    uint64_t path_id)
{
    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *packet_out;
    uint64_t bytes = 0;

    if (head == NULL) {
        return 0;
    }

    xqc_list_for_each_safe(pos, next, head) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (!packet_out->po_path_intent
            || packet_out->po_path_intent_id != path_id
            || !XQC_IS_ACK_ELICITING(packet_out->po_frame_types))
        {
            continue;
        }
        bytes += packet_out->po_cc_size > 0
            ? packet_out->po_cc_size : packet_out->po_used_size;
    }

    return bytes;
}

static uint64_t
xqc_mac_aware_unscheduled_intent_bytes(xqc_connection_t *conn,
    uint64_t path_id)
{
    uint64_t bytes = 0;

    if (conn == NULL || conn->conn_send_queue == NULL) {
        return 0;
    }

    bytes += xqc_mac_aware_unscheduled_intent_bytes_on_list(
        &conn->conn_send_queue->sndq_send_packets, path_id);
    bytes += xqc_mac_aware_unscheduled_intent_bytes_on_list(
        &conn->conn_send_queue->sndq_send_packets_high_pri, path_id);

    return bytes;
}

static void
xqc_mac_aware_stream_budget_trace_candidate(xqc_connection_t *conn,
    xqc_path_ctx_t *path, const xqc_mac_aware_candidate_t *candidate,
    const char *reason, uint64_t pending_bytes, uint64_t budget_bytes,
    uint64_t packet_size, uint8_t cc_allowed)
{
    xqc_transport_trace_observation_t trace;
    uint64_t path_schedule_bytes = 0;
    const char *trace_reason = reason;

    if (!xqc_transport_trace_enabled()) {
        return;
    }

    if (candidate != NULL && reason != NULL
        && (!candidate->has_snapshot || candidate->sample_count == 0))
    {
        if (strcmp(reason, "candidate_ok") == 0) {
            trace_reason = "candidate_ok_cold";

        } else if (strcmp(reason, "selected") == 0) {
            trace_reason = "selected_cold";
        }
    }

    xqc_transport_trace_observation_init(&trace, "stream_budget_candidate",
                                         trace_reason);
    if (path != NULL && path->path_send_ctl != NULL) {
        xqc_transport_trace_fill_send_ctl(&trace, path->path_send_ctl);
    } else {
        xqc_transport_trace_fill_conn(&trace, conn);
        if (path != NULL) {
            trace.has_path = 1;
            trace.path_id = path->path_id;
        }
    }

    if (path != NULL) {
        path_schedule_bytes = path->path_schedule_bytes;
        trace.has_path = 1;
        trace.path_id = path->path_id;
    }

    trace.stream_bytes = budget_bytes;
    trace.packet_size = packet_size;
    trace.po_cc_size = budget_bytes;
    trace.schedule_bytes = pending_bytes;
    trace.path_schedule_bytes_before = path_schedule_bytes;
    trace.path_schedule_bytes_after = candidate != NULL
        ? candidate->backlog_bytes : path_schedule_bytes;
    trace.cwnd_allowed = cc_allowed ? 1 : 0;
    trace.pacing_allowed = path != NULL
        && path->path_state == XQC_PATH_STATE_ACTIVE ? 1 : 0;
    trace.cc_allowed = cc_allowed ? 1 : 0;

    xqc_transport_trace_notify(&trace);
}

static uint64_t
xqc_mac_aware_stream_reservoir_high_bytes(
    const xqc_mac_aware_candidate_t *candidate,
    const xqc_mac_aware_config_t *config)
{
    uint64_t q;
    uint64_t high;

    if (candidate == NULL || config == NULL) {
        return 0;
    }

    q = candidate->service_quantum_bytes > 0
        ? candidate->service_quantum_bytes : config->min_burst_bytes;
    high = (uint64_t) ((double) q * config->rq_high_factor);
    high = xqc_mac_aware_max_u64(high, config->min_burst_bytes);
    return high;
}

static uint64_t
xqc_mac_aware_stream_candidate_budget(
    const xqc_mac_aware_candidate_t *candidate,
    const xqc_mac_aware_config_t *config, uint64_t packet_size,
    xqc_bool_t apply_reservoir_gate)
{
    uint64_t budget;
    uint64_t high;

    if (candidate == NULL || config == NULL || candidate->path == NULL
        || candidate->burst_budget_bytes == 0)
    {
        return 0;
    }

    budget = candidate->burst_budget_bytes;
    if (apply_reservoir_gate
        && candidate->sample_count >= config->min_mac_samples)
    {
        high = xqc_mac_aware_stream_reservoir_high_bytes(candidate, config);
        if (candidate->backlog_bytes >= high) {
            return 0;
        }
        budget = xqc_mac_aware_min_u64(budget,
            high - candidate->backlog_bytes);
    }

    if (budget < packet_size) {
        return 0;
    }
    return budget;
}

static uint64_t
xqc_mac_aware_stream_primary_budget(
    const xqc_mac_aware_candidate_t *candidate,
    const xqc_mac_aware_config_t *config, uint64_t packet_size)
{
    uint64_t budget;

    if (candidate == NULL || config == NULL || candidate->path == NULL) {
        return 0;
    }

    budget = config->offset_max_chunk_bytes;
    if (budget < config->offset_chunk_bytes) {
        budget = config->offset_chunk_bytes;
    }
    if (candidate->cc_headroom_bytes != UINT64_MAX) {
        budget = xqc_mac_aware_min_u64(budget,
            candidate->cc_headroom_bytes);
    }
    if (budget < packet_size) {
        return 0;
    }
    return budget;
}

static xqc_bool_t
xqc_mac_aware_stream_warm_better(
    const xqc_mac_aware_candidate_t *candidate,
    const xqc_mac_aware_candidate_t *best)
{
    uint64_t lhs;
    uint64_t rhs;
    uint64_t candidate_q;
    uint64_t best_q;

    if (candidate == NULL || candidate->path == NULL) {
        return XQC_FALSE;
    }
    if (best == NULL || best->path == NULL) {
        return XQC_TRUE;
    }

    candidate_q = candidate->service_quantum_bytes > 0
        ? candidate->service_quantum_bytes : 1;
    best_q = best->service_quantum_bytes > 0
        ? best->service_quantum_bytes : 1;
    lhs = candidate->backlog_bytes * best_q;
    rhs = best->backlog_bytes * candidate_q;
    if (lhs != rhs) {
        return lhs < rhs;
    }
    if (candidate->eta_us != best->eta_us) {
        return candidate->eta_us < best->eta_us;
    }
    if (candidate->last_selected_at_us != best->last_selected_at_us) {
        return candidate->last_selected_at_us < best->last_selected_at_us;
    }
    return candidate->srtt_us < best->srtt_us;
}

static xqc_mac_aware_candidate_t *
xqc_mac_aware_stream_select_candidate(xqc_mac_aware_candidate_t *candidates,
    uint8_t candidate_count, const xqc_mac_aware_config_t *config,
    uint64_t packet_size, uint64_t *selected_budget,
    const char **decision_reason)
{
    uint8_t i;
    uint64_t budget;
    xqc_mac_aware_candidate_t *cold = NULL;
    xqc_mac_aware_candidate_t *warm = NULL;
    xqc_mac_aware_candidate_t *fallback = NULL;

    if (selected_budget != NULL) {
        *selected_budget = 0;
    }
    if (decision_reason != NULL) {
        *decision_reason = "stream_no_path";
    }

    for (i = 0; i < candidate_count; i++) {
        xqc_mac_aware_candidate_t *candidate = &candidates[i];

        if (candidate->path == NULL || candidate->burst_budget_bytes == 0) {
            continue;
        }

        if (candidate->sample_count < config->min_mac_samples) {
            budget = xqc_mac_aware_stream_candidate_budget(candidate, config,
                packet_size, XQC_FALSE);
            if (budget > 0 && xqc_mac_aware_cold_better(candidate, cold)) {
                cold = candidate;
            }
            continue;
        }

        budget = xqc_mac_aware_stream_candidate_budget(candidate, config,
            packet_size, XQC_TRUE);
        if (budget > 0 && xqc_mac_aware_stream_warm_better(candidate, warm)) {
            warm = candidate;
        }
    }

    if (cold != NULL) {
        if (selected_budget != NULL) {
            *selected_budget = xqc_mac_aware_stream_candidate_budget(cold,
                config, packet_size, XQC_FALSE);
        }
        if (decision_reason != NULL) {
            *decision_reason = "bootstrap_probe";
        }
        return cold;
    }

    if (warm != NULL) {
        if (selected_budget != NULL) {
            *selected_budget = xqc_mac_aware_stream_candidate_budget(warm,
                config, packet_size, XQC_TRUE);
        }
        if (decision_reason != NULL) {
            *decision_reason = "service_fill";
        }
        return warm;
    }

    for (i = 0; i < candidate_count; i++) {
        if (candidates[i].path == NULL || candidates[i].burst_budget_bytes == 0) {
            continue;
        }
        if (xqc_mac_aware_eta_better(&candidates[i], fallback)) {
            fallback = &candidates[i];
        }
    }

    if (fallback != NULL) {
        budget = xqc_mac_aware_min_u64(fallback->burst_budget_bytes,
            config->min_burst_bytes);
        if (budget < packet_size) {
            budget = fallback->burst_budget_bytes;
        }
        if (budget >= packet_size) {
            if (selected_budget != NULL) {
                *selected_budget = budget;
            }
            if (decision_reason != NULL) {
                *decision_reason = "reservoir_fallback";
            }
            return fallback;
        }
    }

    return NULL;
}

static xqc_mac_aware_candidate_t *
xqc_mac_aware_stream_select_candidate_v2(xqc_mac_aware_scheduler_t *ctx,
    xqc_mac_aware_candidate_t *candidates, uint8_t candidate_count,
    const xqc_mac_aware_config_t *config, uint64_t now,
    uint64_t packet_size, uint64_t *selected_budget,
    const char **decision_reason, xqc_bool_t *recovery_probe_selected)
{
    xqc_bool_t probe = XQC_FALSE;
    uint64_t budget;
    xqc_mac_aware_candidate_t *selected;

    if (selected_budget != NULL) {
        *selected_budget = 0;
    }
    if (recovery_probe_selected != NULL) {
        *recovery_probe_selected = XQC_FALSE;
    }

    if (ctx == NULL) {
        return xqc_mac_aware_stream_select_candidate(candidates,
            candidate_count, config, packet_size, selected_budget,
            decision_reason);
    }

    selected = xqc_mac_aware_select_candidate_v2(ctx, candidates,
        candidate_count, config, now, decision_reason, &probe, NULL, NULL);
    if (selected == NULL || selected->path == NULL) {
        return NULL;
    }

    if (probe || xqc_mac_aware_candidate_high_risk(selected, config)) {
        budget = xqc_mac_aware_selected_burst_budget(selected, config,
            packet_size, probe);
    } else if (xqc_mac_aware_candidate_recovery_ready(selected, config)) {
        budget = xqc_mac_aware_stream_primary_budget(selected, config,
            packet_size);
    } else {
        budget = xqc_mac_aware_stream_candidate_budget(selected, config,
            packet_size, XQC_FALSE);
    }

    if (budget < packet_size) {
        return NULL;
    }
    if (selected_budget != NULL) {
        *selected_budget = budget;
    }
    if (recovery_probe_selected != NULL) {
        *recovery_probe_selected = probe;
    }
    return selected;
}

xqc_path_ctx_t *
xqc_mac_aware_stream_budget_get_path(void *scheduler, xqc_connection_t *conn,
    size_t payload_left, uint64_t *budget_bytes)
{
    xqc_mac_aware_scheduler_t *ctx = scheduler;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_mac_aware_candidate_t candidates[XQC_MAC_AWARE_MAX_CANDIDATES];
    xqc_mac_aware_candidate_t *selected;
    const xqc_mac_aware_config_t *config = xqc_mac_aware_get_config();
    uint8_t candidate_count = 0;
    uint64_t now;
    uint64_t packet_size;
    uint64_t pending_bytes;
    uint64_t selected_budget;
    xqc_bool_t recovery_probe_selected = XQC_FALSE;
    const char *decision_reason = "stream_no_path";

    if (budget_bytes != NULL) {
        *budget_bytes = 0;
    }
    if (!xqc_mac_aware_stream_generation_enabled(conn)
        || config == NULL || payload_left == 0)
    {
        return NULL;
    }

    packet_size = payload_left > XQC_PACKET_OUT_SIZE
        ? XQC_PACKET_OUT_SIZE : (uint64_t) payload_left;
    if (packet_size == 0) {
        packet_size = 1;
    }

    now = xqc_monotonic_timestamp();
    memset(candidates, 0, sizeof(candidates));

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        xqc_mac_aware_candidate_t candidate;
        uint64_t cc_headroom_before_pending;

        memset(&candidate, 0, sizeof(candidate));
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (!xqc_scheduler_path_is_usable(path)) {
            xqc_mac_aware_stream_budget_trace_candidate(conn, path, NULL,
                path != NULL && path->path_state != XQC_PATH_STATE_ACTIVE
                ? "path_not_established" : "not_usable",
                0, 0, packet_size, 0);
            continue;
        }

        candidate.path = path;
        candidate.path_class = xqc_path_get_perf_class(path);
        xqc_mac_aware_candidate_update_transport(&candidate, now, XQC_TRUE);
        cc_headroom_before_pending = candidate.cc_headroom_bytes;
        pending_bytes = xqc_mac_aware_unscheduled_intent_bytes(conn,
            path->path_id);
        candidate.pending_intent_bytes = pending_bytes;
        candidate.backlog_bytes += pending_bytes;
        if (candidate.cc_headroom_bytes != UINT64_MAX) {
            if (candidate.cc_headroom_bytes > pending_bytes) {
                candidate.cc_headroom_bytes -= pending_bytes;
            } else {
                candidate.cc_headroom_bytes = 0;
            }
        }
        if (pending_bytes > 0
            && cc_headroom_before_pending != UINT64_MAX
            && cc_headroom_before_pending <= pending_bytes)
        {
            xqc_mac_aware_stream_budget_trace_candidate(conn, path,
                &candidate, "pending_intent_over_budget", pending_bytes,
                0, packet_size, 0);
            continue;
        }
        if (candidate.cc_headroom_bytes != UINT64_MAX
            && candidate.cc_headroom_bytes == 0)
        {
            xqc_mac_aware_stream_budget_trace_candidate(conn, path,
                &candidate, "cc_headroom_zero", pending_bytes, 0,
                packet_size, 0);
            continue;
        }
        xqc_mac_aware_candidate_load_state(conn->user_data, &candidate, now,
            config);
        xqc_mac_aware_candidate_compute_eta(&candidate, config);
        xqc_mac_aware_candidate_compute_budget(&candidate, config,
            (size_t) packet_size);

        if (candidate.burst_budget_bytes == 0) {
            xqc_mac_aware_stream_budget_trace_candidate(conn, path,
                &candidate, "budget_zero", pending_bytes, 0, packet_size,
                0);
            continue;
        }
        if (candidate_count < XQC_MAC_AWARE_MAX_CANDIDATES) {
            xqc_mac_aware_stream_budget_trace_candidate(conn, path,
                &candidate, "candidate_ok", pending_bytes,
                candidate.burst_budget_bytes, packet_size, 1);
            candidates[candidate_count++] = candidate;
        }
    }

    if (candidate_count == 0) {
        if (xqc_transport_trace_enabled()) {
            xqc_transport_trace_observation_t trace;

            xqc_transport_trace_observation_init(&trace,
                "stream_budget_none", "no_candidate");
            xqc_transport_trace_fill_conn(&trace, conn);
            trace.stream_bytes = payload_left;
            trace.packet_size = packet_size;
            xqc_transport_trace_notify(&trace);
        }
        return NULL;
    }

    selected = xqc_mac_aware_stream_select_candidate_v2(ctx, candidates,
        candidate_count, config, now, packet_size, &selected_budget,
        &decision_reason, &recovery_probe_selected);

    if (selected == NULL || selected->path == NULL
        || selected_budget == 0)
    {
        if (xqc_transport_trace_enabled()) {
            xqc_transport_trace_observation_t trace;

            xqc_transport_trace_observation_init(&trace,
                "stream_budget_none", "no_selected_budget");
            xqc_transport_trace_fill_conn(&trace, conn);
            trace.stream_bytes = payload_left;
            trace.packet_size = packet_size;
            xqc_transport_trace_notify(&trace);
        }
        return NULL;
    }

    if (selected_budget < packet_size) {
        selected_budget = packet_size;
    }
    if (selected_budget > payload_left) {
        selected_budget = (uint64_t) payload_left;
    }
    if (selected_budget == 0) {
        if (xqc_transport_trace_enabled()) {
            xqc_transport_trace_observation_t trace;

            xqc_transport_trace_observation_init(&trace,
                "stream_budget_none", "zero_selected_budget");
            xqc_transport_trace_fill_conn(&trace, conn);
            trace.has_path = 1;
            trace.path_id = selected->path->path_id;
            trace.stream_bytes = payload_left;
            trace.packet_size = packet_size;
            xqc_transport_trace_notify(&trace);
        }
        return NULL;
    }

    if (budget_bytes != NULL) {
        *budget_bytes = selected_budget;
    }
    xqc_mac_aware_note_candidate_selection(conn->user_data, selected, now,
        config, recovery_probe_selected);
    xqc_mac_aware_scheduler_note_primary(ctx, selected, config,
        decision_reason);
    xqc_mac_aware_stream_budget_trace_candidate(conn, selected->path,
        selected, decision_reason, selected->pending_intent_bytes,
        selected_budget, packet_size, 1);
    xqc_log(conn->log, XQC_LOG_DEBUG,
            "|mac_aware_stream_budget|decision:%s|path:%ui|budget:%ui|"
            "q:%ui|eta_us:%ui|backlog:%ui|headroom:%ui|",
            decision_reason,
            selected->path->path_id,
            selected_budget,
            selected->service_quantum_bytes,
            selected->eta_us,
            selected->backlog_bytes,
            selected->cc_headroom_bytes == UINT64_MAX
            ? 0 : selected->cc_headroom_bytes);
    return selected->path;
}

xqc_path_ctx_t *
xqc_mac_aware_path_intent_get_path(void *scheduler, xqc_connection_t *conn,
    xqc_packet_out_t *packet_out, int check_cwnd, xqc_bool_t *cc_blocked,
    xqc_bool_t *handled)
{
    xqc_path_ctx_t *path;
    xqc_bool_t path_can_send;

    (void) scheduler;

    if (handled != NULL) {
        *handled = XQC_FALSE;
    }
    if (conn == NULL || packet_out == NULL || !packet_out->po_path_intent
        || !xqc_mac_aware_stream_generation_enabled(conn))
    {
        return NULL;
    }

    path = xqc_conn_find_path_by_path_id(conn,
        packet_out->po_path_intent_id);
    if (path == NULL || !xqc_scheduler_path_is_usable(path)) {
        packet_out->po_path_intent = 0;
        return NULL;
    }

    if (cc_blocked != NULL) {
        *cc_blocked = XQC_TRUE;
    }
    path_can_send = xqc_scheduler_check_path_can_send(path, packet_out,
        check_cwnd);
    if (!path_can_send) {
        return NULL;
    }

    if (cc_blocked != NULL) {
        *cc_blocked = XQC_FALSE;
    }
    if (handled != NULL) {
        *handled = XQC_TRUE;
    }
    xqc_mac_aware_note_selection(conn->user_data, path->path_id,
        xqc_monotonic_timestamp());
    return path;
}

static xqc_bool_t
xqc_mac_aware_packet_stream_range(xqc_packet_out_t *packet_out,
    uint64_t *stream_id, uint64_t *start_offset, uint64_t *end_offset,
    uint64_t *payload_bytes)
{
    uint64_t id = 0;
    uint64_t start = 0;
    uint64_t end = 0;
    uint64_t bytes = 0;
    unsigned int i;
    uint8_t have = 0;

    if (packet_out == NULL
        || !(packet_out->po_frame_types & XQC_FRAME_BIT_STREAM))
    {
        return XQC_FALSE;
    }
    if (packet_out->po_origin != NULL
        || (packet_out->po_flag & (XQC_POF_REINJECTED_ORIGIN
                                   | XQC_POF_REINJECTED_REPLICA
                                   | XQC_POF_REINJECT_DIFF_PATH
                                   | XQC_POF_TLP
                                   | XQC_POF_LOST
                                   | XQC_POF_PMTUD_PROBING)))
    {
        return XQC_FALSE;
    }

    for (i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
        xqc_po_stream_frame_t *frame = &packet_out->po_stream_frames[i];

        if (!frame->ps_is_used) {
            continue;
        }
        if (frame->ps_is_reset || frame->ps_length == 0) {
            return XQC_FALSE;
        }
        if (!have) {
            id = frame->ps_stream_id;
            start = frame->ps_offset;
            end = frame->ps_offset + frame->ps_length;
            bytes = frame->ps_length;
            have = 1;
            continue;
        }
        if (frame->ps_stream_id != id || frame->ps_offset != end) {
            return XQC_FALSE;
        }
        end = frame->ps_offset + frame->ps_length;
        bytes += frame->ps_length;
    }

    if (!have || end <= start || bytes == 0) {
        return XQC_FALSE;
    }

    if (stream_id != NULL) {
        *stream_id = id;
    }
    if (start_offset != NULL) {
        *start_offset = start;
    }
    if (end_offset != NULL) {
        *end_offset = end;
    }
    if (payload_bytes != NULL) {
        *payload_bytes = bytes;
    }
    return XQC_TRUE;
}

static xqc_mac_aware_offset_owner_t *
xqc_mac_aware_find_offset_owner(xqc_mac_aware_scheduler_t *ctx,
    uint64_t stream_id, uint64_t start_offset)
{
    uint8_t i;

    if (ctx == NULL) {
        return NULL;
    }

    for (i = 0; i < XQC_MAC_AWARE_OFFSET_OWNER_SLOTS; i++) {
        if (ctx->offset_owners[i].used
            && ctx->offset_owners[i].stream_id == stream_id
            && ctx->offset_owners[i].next_offset == start_offset
            && ctx->offset_owners[i].remaining_bytes > 0)
        {
            return &ctx->offset_owners[i];
        }
    }

    return NULL;
}

static xqc_mac_aware_offset_owner_t *
xqc_mac_aware_alloc_offset_owner(xqc_mac_aware_scheduler_t *ctx,
    uint64_t stream_id)
{
    uint8_t i;

    if (ctx == NULL) {
        return NULL;
    }

    for (i = 0; i < XQC_MAC_AWARE_OFFSET_OWNER_SLOTS; i++) {
        if (!ctx->offset_owners[i].used) {
            return &ctx->offset_owners[i];
        }
    }

    for (i = 0; i < XQC_MAC_AWARE_OFFSET_OWNER_SLOTS; i++) {
        if (ctx->offset_owners[i].stream_id == stream_id) {
            return &ctx->offset_owners[i];
        }
    }

    return &ctx->offset_owners[0];
}

static void
xqc_mac_aware_update_offset_owner(xqc_mac_aware_offset_owner_t *owner,
    uint64_t stream_id, uint64_t path_id, uint64_t end_offset,
    uint64_t payload_bytes, uint64_t chunk_bytes)
{
    uint64_t remaining = 0;

    if (owner == NULL) {
        return;
    }

    if (chunk_bytes > payload_bytes) {
        remaining = chunk_bytes - payload_bytes;
    }

    owner->used = remaining > 0 ? 1 : 0;
    owner->stream_id = stream_id;
    owner->path_id = path_id;
    owner->next_offset = end_offset;
    owner->remaining_bytes = remaining;
}

static uint64_t
xqc_mac_aware_offset_chunk_bytes(const xqc_mac_aware_candidate_t *candidate,
    const xqc_mac_aware_config_t *config, uint64_t packet_bytes)
{
    uint64_t chunk;

    if (config == NULL) {
        return packet_bytes;
    }

    chunk = config->offset_chunk_bytes;
    if (candidate != NULL && candidate->burst_budget_bytes > chunk) {
        chunk = candidate->burst_budget_bytes;
    }
    if (chunk > config->offset_max_chunk_bytes) {
        chunk = config->offset_max_chunk_bytes;
    }
    if (chunk < packet_bytes) {
        chunk = packet_bytes;
    }
    return chunk;
}

static void
xqc_mac_aware_offset_observation_init(xqc_scheduler_observation_t *observation,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, uint64_t now)
{
    if (observation == NULL || conn == NULL || packet_out == NULL) {
        return;
    }

    xqc_scheduler_observation_init(observation, "mac_aware", conn,
        conn->user_data, packet_out->po_pkt.pkt_num, packet_out->po_used_size);
    observation->ts_us = now;
    observation->risk_reason = "none";
}

static void
xqc_mac_aware_offset_observe_path(xqc_scheduler_observation_t *observation,
    const xqc_mac_aware_candidate_t *candidate, xqc_bool_t path_can_send)
{
    if (observation == NULL || candidate == NULL || candidate->path == NULL) {
        return;
    }

    xqc_scheduler_observe_path(observation, candidate->path, path_can_send,
        candidate->path_class);
}

static void
xqc_mac_aware_offset_observation_selected(
    xqc_scheduler_observation_t *observation,
    const xqc_mac_aware_candidate_t *selected,
    const xqc_mac_aware_candidate_t *alt, const xqc_mac_aware_config_t *config,
    const char *decision_reason, uint64_t owner_remaining_bytes,
    uint64_t chunk_bytes)
{
    if (observation == NULL || selected == NULL || selected->path == NULL
        || config == NULL)
    {
        return;
    }

    observation->has_selected_path = 1;
    observation->selected_path_id = selected->path->path_id;
    observation->decision_reason = decision_reason;
    observation->selected_srtt_us = selected->srtt_us;
    observation->selected_latest_rtt_us = selected->latest_rtt_us;
    observation->selected_rtt_age_us = selected->ack_age_us;
    observation->selected_service_bytes = selected->service_quantum_bytes;
    observation->selected_service_rate_bytes_per_us =
        selected->service_rate_bytes_per_us;
    observation->ofo_budget_bytes = config->ofo_budget_bytes;
    observation->admission_allowed = 1;
    observation->service_admission_selected =
        strcmp(decision_reason, "offset_continue") == 0 ? 0 : 1;
    observation->admission_block_reason = "none";
    observation->arrival_debt_bytes = owner_remaining_bytes;
    observation->risk_inflight_debt_bytes = selected->inflight_bytes;
    observation->risk_inflight_budget_bytes =
        selected->cc_headroom_bytes == UINT64_MAX
        ? 0 : selected->cc_headroom_bytes;
    observation->risky_cwnd_bytes = selected->cwnd_bytes;
    observation->risky_inflight_bytes = selected->inflight_bytes;
    observation->risky_cc_headroom_bytes =
        selected->cc_headroom_bytes == UINT64_MAX
        ? 0 : selected->cc_headroom_bytes;
    observation->risky_latest_rtt_us = selected->latest_rtt_us;
    observation->risky_rtt_age_us = selected->ack_age_us;
    observation->risky_reservoir_bytes = selected->backlog_bytes;
    observation->risky_reservoir_low_bytes =
        (uint64_t) ((double) selected->service_quantum_bytes
            * config->rq_low_factor);
    observation->risky_reservoir_high_bytes =
        (uint64_t) ((double) selected->service_quantum_bytes
            * config->rq_high_factor);
    observation->risky_service_quantum_bytes =
        selected->service_quantum_bytes;
    observation->risky_service_bytes = selected->observed_service_bytes;
    observation->risky_service_rate_bytes_per_us =
        selected->service_rate_bytes_per_us;
    observation->eta_clean_us = selected->eta_us;
    observation->has_base_candidate = 1;
    observation->base_candidate_path_id = selected->path->path_id;
    observation->predicted_ofo_bytes = (double) chunk_bytes;
    if (alt != NULL && alt->path != NULL) {
        observation->has_admission_candidate = 1;
        observation->admission_candidate_path_id = alt->path->path_id;
        observation->eta_risky_us = alt->eta_us;
        observation->arrival_skew_us =
            selected->eta_us > alt->eta_us
            ? selected->eta_us - alt->eta_us
            : alt->eta_us - selected->eta_us;
    }
}

xqc_path_ctx_t *
xqc_mac_aware_offset_owner_get_path(void *scheduler, xqc_connection_t *conn,
    xqc_packet_out_t *packet_out, int check_cwnd, xqc_bool_t *cc_blocked,
    xqc_bool_t *handled)
{
    xqc_mac_aware_scheduler_t *ctx = scheduler;
    xqc_mac_aware_offset_owner_t *owner;
    xqc_path_ctx_t *owned_path;
    xqc_path_ctx_t *path;
    xqc_list_head_t *pos, *next;
    xqc_scheduler_observation_t observation;
    xqc_mac_aware_candidate_t candidates[XQC_MAC_AWARE_MAX_CANDIDATES];
    xqc_mac_aware_candidate_t owned_candidate;
    xqc_mac_aware_candidate_t *selected = NULL;
    xqc_mac_aware_candidate_t *alt = NULL;
    xqc_bool_t reached_cwnd_check = XQC_FALSE;
    xqc_bool_t observation_ready = XQC_FALSE;
    uint8_t candidate_count = 0;
    uint64_t now;
    uint64_t stream_id = 0;
    uint64_t start_offset = 0;
    uint64_t end_offset = 0;
    uint64_t payload_bytes = 0;
    uint64_t chunk_bytes;
    const char *decision_reason = "offset_new";
    const char *block_reason = "no_sendable_path";
    const xqc_mac_aware_config_t *config = xqc_mac_aware_get_config();

    if (handled != NULL) {
        *handled = XQC_FALSE;
    }
    if (cc_blocked != NULL) {
        *cc_blocked = XQC_FALSE;
    }
    if (ctx == NULL || conn == NULL || packet_out == NULL || config == NULL
        || !config->offset_owner_enabled)
    {
        return NULL;
    }
    if (!xqc_mac_aware_packet_stream_range(packet_out, &stream_id,
            &start_offset, &end_offset, &payload_bytes))
    {
        return NULL;
    }
    if (handled != NULL) {
        *handled = XQC_TRUE;
    }

    now = xqc_monotonic_timestamp();
    memset(&observation, 0, sizeof(observation));
    xqc_mac_aware_offset_observation_init(&observation, conn, packet_out, now);
    observation_ready = XQC_TRUE;
    owner = xqc_mac_aware_find_offset_owner(ctx, stream_id, start_offset);
    if (owner != NULL) {
        owned_path = xqc_conn_find_path_by_path_id(conn, owner->path_id);
        memset(&owned_candidate, 0, sizeof(owned_candidate));
        if (owned_path != NULL) {
            owned_candidate.path = owned_path;
            owned_candidate.path_class = xqc_path_get_perf_class(owned_path);
            xqc_mac_aware_candidate_update_transport(&owned_candidate, now,
                check_cwnd);
            xqc_mac_aware_candidate_load_state(conn->user_data,
                &owned_candidate, now, config);
            xqc_mac_aware_candidate_compute_eta(&owned_candidate, config);
            xqc_mac_aware_candidate_compute_budget(&owned_candidate, config,
                packet_out->po_used_size);
        }
        if (owned_path != NULL
            && xqc_scheduler_path_is_usable(owned_path))
        {
            xqc_bool_t path_can_send = xqc_scheduler_check_path_can_send(
                owned_path, packet_out, check_cwnd);
            xqc_mac_aware_offset_observe_path(&observation,
                &owned_candidate, path_can_send);
            if (path_can_send) {
                chunk_bytes = owner->remaining_bytes > payload_bytes
                    ? owner->remaining_bytes : payload_bytes;
                xqc_mac_aware_update_offset_owner(owner, stream_id,
                    owned_path->path_id, end_offset, payload_bytes,
                    chunk_bytes);
                xqc_mac_aware_note_selection(conn->user_data,
                    owned_path->path_id, now);
                xqc_mac_aware_offset_observation_selected(&observation,
                    &owned_candidate, NULL, config, "offset_continue",
                    owner->remaining_bytes, chunk_bytes);
                xqc_scheduler_notify_observer(&observation);
                xqc_log(conn->log, XQC_LOG_DEBUG,
                        "|mac_aware_offset_owner|decision:continue|path:%ui|"
                        "stream:%ui|range:%ui-%ui|remaining:%ui|",
                        owned_path->path_id, stream_id, start_offset,
                        end_offset, owner->remaining_bytes);
                return owned_path;
            }
        }
        owner->used = 0;
    }

    memset(candidates, 0, sizeof(candidates));
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        xqc_mac_aware_candidate_t candidate;
        xqc_bool_t path_can_send;

        memset(&candidate, 0, sizeof(candidate));
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        candidate.path = path;
        candidate.path_class = xqc_path_get_perf_class(path);
        xqc_mac_aware_candidate_update_transport(&candidate, now, check_cwnd);
        xqc_mac_aware_candidate_load_state(conn->user_data, &candidate, now,
            config);
        xqc_mac_aware_candidate_compute_eta(&candidate, config);
        xqc_mac_aware_candidate_compute_budget(&candidate, config,
            packet_out->po_used_size);

        if (!xqc_scheduler_path_is_usable(path)) {
            xqc_mac_aware_offset_observe_path(&observation, &candidate,
                XQC_FALSE);
            continue;
        }
        if (!reached_cwnd_check) {
            reached_cwnd_check = XQC_TRUE;
            if (cc_blocked != NULL) {
                *cc_blocked = XQC_TRUE;
            }
        }
        path_can_send = xqc_scheduler_check_path_can_send(path, packet_out,
            check_cwnd);
        xqc_mac_aware_offset_observe_path(&observation, &candidate,
            path_can_send);
        if (!path_can_send) {
            continue;
        }
        if (cc_blocked != NULL) {
            *cc_blocked = XQC_FALSE;
        }
        if (candidate_count < XQC_MAC_AWARE_MAX_CANDIDATES) {
            candidates[candidate_count++] = candidate;
        }
    }

    selected = xqc_mac_aware_select_candidate(candidates, candidate_count,
        config, &decision_reason);
    if (selected != NULL && selected->path != NULL) {
        owner = xqc_mac_aware_alloc_offset_owner(ctx, stream_id);
        chunk_bytes = xqc_mac_aware_offset_chunk_bytes(selected, config,
            payload_bytes);
        xqc_mac_aware_update_offset_owner(owner, stream_id,
            selected->path->path_id, end_offset, payload_bytes, chunk_bytes);
        xqc_mac_aware_note_selection(conn->user_data,
            selected->path->path_id, now);
        alt = xqc_mac_aware_alt_candidate(candidates, candidate_count,
            selected);
        xqc_mac_aware_offset_observation_selected(&observation, selected, alt,
            config, decision_reason, owner != NULL
            ? owner->remaining_bytes : 0, chunk_bytes);
        xqc_scheduler_notify_observer(&observation);
        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|mac_aware_offset_owner|decision:%s|path:%ui|"
                "stream:%ui|range:%ui-%ui|chunk:%ui|remaining:%ui|",
                decision_reason, selected->path->path_id, stream_id,
                start_offset, end_offset, chunk_bytes,
                owner != NULL ? owner->remaining_bytes : 0);
        return selected->path;
    }

    if (cc_blocked != NULL && !reached_cwnd_check) {
        *cc_blocked = XQC_FALSE;
    }
    if (candidate_count > 0) {
        block_reason = "offset_candidate_blocked";
    }
    if (observation_ready) {
        observation.decision_reason = "offset_no_path";
        observation.admission_block_reason = block_reason;
        xqc_scheduler_notify_observer(&observation);
    }
    xqc_log(conn->log, XQC_LOG_DEBUG,
            "|mac_aware_offset_owner_no_path|conn:%p|stream:%ui|"
            "offset:%ui|reason:%s|",
            conn, stream_id, start_offset, block_reason);
    return NULL;
}

static size_t
xqc_mac_aware_scheduler_size(void)
{
    return sizeof(xqc_mac_aware_scheduler_t);
}

static void
xqc_mac_aware_scheduler_init(void *scheduler, xqc_log_t *log,
    xqc_scheduler_params_t *param)
{
    if (scheduler != NULL) {
        memset(scheduler, 0, sizeof(xqc_mac_aware_scheduler_t));
    }
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
xqc_mac_aware_observation_set_risk(xqc_scheduler_observation_t *observation,
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

static int
xqc_mac_aware_find_candidate(xqc_mac_aware_candidate_t *candidates,
    uint8_t candidate_count, uint64_t path_id)
{
    uint8_t i;

    for (i = 0; i < candidate_count; i++) {
        if (candidates[i].path != NULL
            && candidates[i].path->path_id == path_id)
        {
            return i;
        }
    }

    return -1;
}

static xqc_bool_t
xqc_mac_aware_probe_interval_elapsed(
    const xqc_mac_aware_candidate_t *candidate, uint64_t now,
    uint64_t interval_us)
{
    if (candidate == NULL || candidate->last_probe_at_us == 0) {
        return XQC_TRUE;
    }
    if (now < candidate->last_probe_at_us) {
        return XQC_TRUE;
    }
    return now - candidate->last_probe_at_us >= interval_us;
}

static xqc_bool_t
xqc_mac_aware_probe_candidate_eligible(
    const xqc_mac_aware_candidate_t *candidate,
    const xqc_mac_aware_config_t *config)
{
    if (candidate == NULL || config == NULL || candidate->path == NULL
        || candidate->burst_budget_bytes == 0)
    {
        return XQC_FALSE;
    }

    if (candidate->sample_count >= config->min_mac_samples
        && xqc_mac_aware_candidate_high_risk(candidate, config))
    {
        return XQC_FALSE;
    }

    return XQC_TRUE;
}

static xqc_bool_t
xqc_mac_aware_probe_candidate_better(
    const xqc_mac_aware_candidate_t *candidate,
    const xqc_mac_aware_candidate_t *best,
    const xqc_mac_aware_config_t *config)
{
    xqc_bool_t candidate_ready;
    xqc_bool_t best_ready;

    if (candidate == NULL || candidate->path == NULL) {
        return XQC_FALSE;
    }
    if (best == NULL || best->path == NULL) {
        return XQC_TRUE;
    }

    candidate_ready = xqc_mac_aware_candidate_recovery_ready(candidate, config);
    best_ready = xqc_mac_aware_candidate_recovery_ready(best, config);
    if (candidate_ready != best_ready) {
        return candidate_ready;
    }
    if (candidate->recovery_good_count != best->recovery_good_count) {
        return candidate->recovery_good_count > best->recovery_good_count;
    }
    return xqc_mac_aware_eta_better(candidate, best);
}

static xqc_mac_aware_candidate_t *
xqc_mac_aware_best_probe_candidate(xqc_mac_aware_candidate_t *candidates,
    uint8_t candidate_count, const xqc_mac_aware_candidate_t *primary,
    const xqc_mac_aware_config_t *config, uint64_t now,
    xqc_bool_t primary_high_risk)
{
    uint8_t i;
    uint64_t interval_us;
    xqc_mac_aware_candidate_t *best = NULL;

    if (candidates == NULL || config == NULL) {
        return NULL;
    }

    interval_us = primary_high_risk
        ? config->recovery_probe_interval_us
        : config->maint_probe_interval_us;

    for (i = 0; i < candidate_count; i++) {
        xqc_mac_aware_candidate_t *candidate = &candidates[i];

        if (primary != NULL && candidate->path != NULL
            && primary->path != NULL
            && candidate->path->path_id == primary->path->path_id)
        {
            continue;
        }
        if (!xqc_mac_aware_probe_candidate_eligible(candidate, config)) {
            continue;
        }
        if (!xqc_mac_aware_probe_interval_elapsed(candidate, now,
                interval_us))
        {
            continue;
        }
        if (xqc_mac_aware_probe_candidate_better(candidate, best, config)) {
            best = candidate;
        }
    }

    return best;
}

static uint64_t
xqc_mac_aware_candidate_good_after_probe(
    const xqc_mac_aware_candidate_t *candidate,
    const xqc_mac_aware_config_t *config)
{
    uint64_t good_count;

    if (candidate == NULL || config == NULL) {
        return 0;
    }

    good_count = candidate->recovery_good_count;
    if (xqc_mac_aware_candidate_recovery_ready(candidate, config)) {
        good_count++;
    }
    return good_count;
}

static xqc_bool_t
xqc_mac_aware_needs_active_exploration(
    const xqc_mac_aware_candidate_t *candidates, uint8_t candidate_count,
    const xqc_mac_aware_config_t *config)
{
    uint8_t i;

    if (candidates == NULL || config == NULL || candidate_count < 2
        || config->active_explore_bytes == 0)
    {
        return XQC_FALSE;
    }

    for (i = 0; i < candidate_count; i++) {
        if (candidates[i].path == NULL) {
            continue;
        }
        if (candidates[i].selected_bytes < config->active_explore_bytes) {
            return XQC_TRUE;
        }
    }

    return XQC_FALSE;
}

static xqc_mac_aware_candidate_t *
xqc_mac_aware_select_candidate_v2(xqc_mac_aware_scheduler_t *ctx,
    xqc_mac_aware_candidate_t *candidates, uint8_t candidate_count,
    const xqc_mac_aware_config_t *config, uint64_t now,
    const char **decision_reason, xqc_bool_t *recovery_probe_selected,
    xqc_mac_aware_candidate_t **base_candidate,
    xqc_mac_aware_candidate_t **admission_candidate)
{
    int primary_idx;
    xqc_bool_t primary_high_risk;
    xqc_mac_aware_candidate_t *primary = NULL;
    xqc_mac_aware_candidate_t *probe = NULL;
    xqc_mac_aware_candidate_t *selected = NULL;

    if (decision_reason != NULL) {
        *decision_reason = "no_path";
    }
    if (recovery_probe_selected != NULL) {
        *recovery_probe_selected = XQC_FALSE;
    }
    if (base_candidate != NULL) {
        *base_candidate = NULL;
    }
    if (admission_candidate != NULL) {
        *admission_candidate = NULL;
    }

    if (candidate_count == 0 || candidates == NULL || config == NULL) {
        return NULL;
    }

    if (xqc_mac_aware_needs_active_exploration(candidates, candidate_count,
            config))
    {
        if (ctx != NULL) {
            ctx->has_primary_path = 0;
            ctx->primary_path_id = 0;
        }
        selected = xqc_mac_aware_select_candidate(candidates,
            candidate_count, config, decision_reason);
        if (selected != NULL && selected->path != NULL) {
            if (decision_reason != NULL) {
                *decision_reason = "active_explore";
            }
            if (base_candidate != NULL) {
                *base_candidate = selected;
            }
        }
        return selected;
    }

    /* Clean-condition balanced mode: when no path shows degradation,
     * bypass primary/probe and use the balanced v1 selector to keep
     * both paths active for aggregation throughput. */
    {
        uint8_t j;
        xqc_bool_t any_risk = XQC_FALSE;

        for (j = 0; j < candidate_count; j++) {
            if (candidates[j].path != NULL
                && candidates[j].sample_count >= config->min_mac_samples
                && xqc_mac_aware_candidate_high_risk(&candidates[j], config))
            {
                any_risk = XQC_TRUE;
                break;
            }
        }
        if (!any_risk) {
            if (ctx != NULL) {
                ctx->has_primary_path = 0;
                ctx->primary_path_id = 0;
            }
            selected = xqc_mac_aware_select_candidate(candidates,
                candidate_count, config, decision_reason);
            if (selected != NULL && selected->path != NULL) {
                if (decision_reason != NULL) {
                    *decision_reason = "balanced";
                }
                if (base_candidate != NULL) {
                    *base_candidate = selected;
                }
            }
            return selected;
        }
    }

    if (ctx != NULL && ctx->has_primary_path) {
        primary_idx = xqc_mac_aware_find_candidate(candidates,
            candidate_count, ctx->primary_path_id);
        if (primary_idx >= 0) {
            primary = &candidates[primary_idx];
        } else {
            ctx->has_primary_path = 0;
            ctx->primary_path_id = 0;
            ctx->burst_remaining_bytes = 0;
            ctx->burst_path_id = 0;
        }
    }

    if (primary == NULL) {
        selected = xqc_mac_aware_select_candidate(candidates,
            candidate_count, config, decision_reason);
        if (base_candidate != NULL) {
            *base_candidate = selected;
        }
        return selected;
    }

    primary_high_risk =
        xqc_mac_aware_candidate_high_risk(primary, config);
    probe = xqc_mac_aware_best_probe_candidate(candidates, candidate_count,
        primary, config, now, primary_high_risk);

    if (primary_high_risk) {
        if (base_candidate != NULL) {
            *base_candidate = primary;
        }
        if (probe != NULL) {
            if (recovery_probe_selected != NULL) {
                *recovery_probe_selected = XQC_TRUE;
            }
            if (admission_candidate != NULL) {
                *admission_candidate = probe;
            }
            if (decision_reason != NULL) {
                *decision_reason =
                    xqc_mac_aware_candidate_good_after_probe(probe, config)
                        >= config->recovery_promote_samples
                    ? "recovery_promote" : "recovery_probe";
            }
            return probe;
        }
        if (decision_reason != NULL) {
            *decision_reason = "primary_degraded_no_probe";
        }
        return primary;
    }

    if (probe != NULL) {
        if (base_candidate != NULL) {
            *base_candidate = primary;
        }
        if (admission_candidate != NULL) {
            *admission_candidate = probe;
        }
        if (recovery_probe_selected != NULL) {
            *recovery_probe_selected = XQC_TRUE;
        }
        if (decision_reason != NULL) {
            *decision_reason = "maintenance_probe";
        }
        return probe;
    }

    if (base_candidate != NULL) {
        *base_candidate = primary;
    }
    if (decision_reason != NULL) {
        *decision_reason = "primary";
    }
    return primary;
}

static uint64_t
xqc_mac_aware_selected_burst_budget(
    const xqc_mac_aware_candidate_t *selected,
    const xqc_mac_aware_config_t *config, uint64_t packet_size,
    xqc_bool_t recovery_probe)
{
    uint64_t budget;

    if (selected == NULL || config == NULL) {
        return 0;
    }

    budget = selected->burst_budget_bytes;
    if (recovery_probe) {
        budget = xqc_mac_aware_min_u64(budget,
            config->recovery_probe_bytes);
    } else if (xqc_mac_aware_candidate_high_risk(selected, config)) {
        budget = xqc_mac_aware_min_u64(budget,
            config->min_burst_bytes);
    }
    if (budget < packet_size) {
        budget = packet_size;
    }
    return budget;
}

static void
xqc_mac_aware_scheduler_note_primary(xqc_mac_aware_scheduler_t *ctx,
    const xqc_mac_aware_candidate_t *selected,
    const xqc_mac_aware_config_t *config, const char *decision_reason)
{
    if (ctx == NULL || selected == NULL || selected->path == NULL
        || config == NULL)
    {
        return;
    }

    if (!ctx->has_primary_path
        || (decision_reason != NULL
            && strcmp(decision_reason, "recovery_promote") == 0))
    {
        if (decision_reason != NULL
            && (strcmp(decision_reason, "active_explore") == 0
                || strcmp(decision_reason, "balanced") == 0))
        {
            return;
        }
        ctx->has_primary_path = 1;
        ctx->primary_path_id = selected->path->path_id;
        ctx->burst_remaining_bytes = 0;
        ctx->burst_path_id = 0;
        return;
    }

    if (ctx->primary_path_id == selected->path->path_id
        && !xqc_mac_aware_candidate_high_risk(selected, config))
    {
        ctx->has_primary_path = 1;
    }
}

static xqc_mac_aware_candidate_t *
xqc_mac_aware_select_candidate(xqc_mac_aware_candidate_t *candidates,
    uint8_t candidate_count, const xqc_mac_aware_config_t *config,
    const char **decision_reason)
{
    uint8_t i;
    xqc_mac_aware_candidate_t *cold = NULL;
    xqc_mac_aware_candidate_t *starved = NULL;
    xqc_mac_aware_candidate_t *eta = NULL;

    for (i = 0; i < candidate_count; i++) {
        xqc_mac_aware_candidate_t *candidate = &candidates[i];

        if (candidate->path == NULL || candidate->burst_budget_bytes == 0) {
            continue;
        }

        if (candidate->sample_count < config->min_mac_samples) {
            if (xqc_mac_aware_cold_better(candidate, cold)) {
                cold = candidate;
            }
            continue;
        }

        if (candidate->backlog_bytes < candidate->service_quantum_bytes) {
            if (xqc_mac_aware_starved_better(candidate, starved)) {
                starved = candidate;
            }
            continue;
        }

        if (xqc_mac_aware_eta_better(candidate, eta)) {
            eta = candidate;
        }
    }

    if (cold != NULL) {
        *decision_reason = "bootstrap";
        return cold;
    }
    if (starved != NULL) {
        *decision_reason = "anti_starvation";
        return starved;
    }
    if (eta != NULL) {
        *decision_reason = "eta";
        return eta;
    }

    *decision_reason = "fallback";
    for (i = 0; i < candidate_count; i++) {
        if (candidates[i].path != NULL
            && xqc_mac_aware_eta_better(&candidates[i], eta))
        {
            eta = &candidates[i];
        }
    }
    return eta;
}

static xqc_mac_aware_candidate_t *
xqc_mac_aware_alt_candidate(xqc_mac_aware_candidate_t *candidates,
    uint8_t candidate_count, const xqc_mac_aware_candidate_t *selected)
{
    uint8_t i;
    xqc_mac_aware_candidate_t *best = NULL;

    for (i = 0; i < candidate_count; i++) {
        if (&candidates[i] == selected) {
            continue;
        }
        if (candidates[i].path == NULL) {
            continue;
        }
        if (xqc_mac_aware_eta_better(&candidates[i], best)) {
            best = &candidates[i];
        }
    }

    return best;
}

xqc_path_ctx_t *
xqc_mac_aware_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, int check_cwnd,
    int reinject, xqc_bool_t *cc_blocked)
{
    xqc_mac_aware_scheduler_t *ctx = scheduler;
    xqc_scheduler_observation_t observation;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_mac_aware_candidate_t candidates[XQC_MAC_AWARE_MAX_CANDIDATES];
    xqc_mac_aware_candidate_t original;
    xqc_mac_aware_candidate_t *selected = NULL;
    xqc_mac_aware_candidate_t *alt = NULL;
    xqc_mac_aware_candidate_t *base_candidate = NULL;
    xqc_mac_aware_candidate_t *admission_candidate = NULL;
    xqc_bool_t reached_cwnd_check = XQC_FALSE;
    xqc_bool_t recovery_probe_selected = XQC_FALSE;
    uint8_t candidate_count = 0;
    uint64_t now;
    const char *decision_reason = "no_path";
    const char *block_reason = "no_sendable_path";
    const xqc_mac_aware_config_t *config = xqc_mac_aware_get_config();

    memset(candidates, 0, sizeof(candidates));
    memset(&original, 0, sizeof(original));

    if (cc_blocked != NULL) {
        *cc_blocked = XQC_FALSE;
    }

    xqc_scheduler_observation_init(&observation, "mac_aware", conn,
        conn->user_data, packet_out->po_pkt.pkt_num, packet_out->po_used_size);
    now = xqc_monotonic_timestamp();
    observation.ts_us = now;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        xqc_mac_aware_candidate_t candidate;
        xqc_bool_t path_can_send;

        memset(&candidate, 0, sizeof(candidate));
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        candidate.path = path;
        candidate.path_class = xqc_path_get_perf_class(path);
        xqc_mac_aware_candidate_update_transport(&candidate, now, check_cwnd);
        xqc_mac_aware_candidate_load_state(conn->user_data, &candidate, now,
            config);
        xqc_mac_aware_candidate_compute_eta(&candidate, config);
        xqc_mac_aware_candidate_compute_budget(&candidate, config,
            packet_out->po_used_size);

        xqc_scheduler_observe_path(&observation, path, 0,
            candidate.path_class);
        xqc_mac_aware_observation_set_risk(&observation, path->path_id,
            xqc_mac_aware_candidate_high_risk(&candidate, config),
            xqc_mac_aware_candidate_risk_reason(&candidate, config));

        if (!xqc_scheduler_path_is_usable(path)) {
            continue;
        }

        if (!reached_cwnd_check) {
            reached_cwnd_check = XQC_TRUE;
            if (cc_blocked != NULL) {
                *cc_blocked = XQC_TRUE;
            }
        }

        path_can_send = xqc_scheduler_check_path_can_send(path, packet_out,
            check_cwnd);
        xqc_mac_aware_observation_set_can_send(&observation, path->path_id,
            path_can_send);
        if (!path_can_send) {
            continue;
        }

        if (cc_blocked != NULL) {
            *cc_blocked = XQC_FALSE;
        }

        if (reinject && packet_out->po_path_id == path->path_id) {
            original = candidate;
            continue;
        }

        if (candidate_count < XQC_MAC_AWARE_MAX_CANDIDATES) {
            candidates[candidate_count++] = candidate;
        }
    }

    if (ctx != NULL && ctx->burst_remaining_bytes > 0) {
        int burst_idx = xqc_mac_aware_find_candidate(candidates,
            candidate_count, ctx->burst_path_id);
        if (burst_idx >= 0
            && !xqc_mac_aware_candidate_high_risk(&candidates[burst_idx],
                config))
        {
            selected = &candidates[burst_idx];
            decision_reason = "burst_continue";
        } else {
            ctx->burst_remaining_bytes = 0;
            ctx->burst_path_id = 0;
        }
    }

    if (selected == NULL) {
        selected = xqc_mac_aware_select_candidate_v2(ctx, candidates,
            candidate_count, config, now, &decision_reason,
            &recovery_probe_selected, &base_candidate, &admission_candidate);
    }

    if (selected == NULL && original.path != NULL
        && !(packet_out->po_flag & XQC_POF_REINJECT_DIFF_PATH))
    {
        selected = &original;
        decision_reason = "reinject_original";
        recovery_probe_selected = XQC_FALSE;
        base_candidate = selected;
        admission_candidate = NULL;
    }

    if (selected != NULL && selected->path != NULL) {
        uint64_t packet_size = packet_out->po_used_size;
        uint64_t selected_burst_budget;
        uint64_t remaining = 0;

        selected_burst_budget = xqc_mac_aware_selected_burst_budget(selected,
            config, packet_size, recovery_probe_selected);
        if (ctx != NULL) {
            if (strcmp(decision_reason, "burst_continue") == 0) {
                if (ctx->burst_remaining_bytes > packet_size) {
                    ctx->burst_remaining_bytes -= packet_size;
                } else {
                    ctx->burst_remaining_bytes = 0;
                    ctx->burst_path_id = 0;
                }
            } else {
                if (selected_burst_budget > packet_size) {
                    remaining = selected_burst_budget - packet_size;
                }
                ctx->burst_path_id = selected->path->path_id;
                ctx->burst_remaining_bytes = remaining;
            }
        }

        xqc_mac_aware_note_candidate_selection(conn->user_data, selected,
            now, config, recovery_probe_selected);
        xqc_mac_aware_scheduler_note_primary(ctx, selected, config,
            decision_reason);
        alt = admission_candidate != NULL ? admission_candidate
            : xqc_mac_aware_alt_candidate(candidates, candidate_count,
                selected);
        if (base_candidate == NULL) {
            base_candidate = selected;
        }

        observation.has_selected_path = 1;
        observation.selected_path_id = selected->path->path_id;
        observation.decision_reason = decision_reason;
        observation.risk_reason =
            xqc_mac_aware_candidate_risk_reason(selected, config);
        observation.selected_srtt_us = selected->srtt_us;
        observation.selected_latest_rtt_us = selected->latest_rtt_us;
        observation.selected_rtt_age_us = selected->ack_age_us;
        observation.selected_service_bytes =
            selected->service_quantum_bytes;
        observation.selected_service_rate_bytes_per_us =
            selected->service_rate_bytes_per_us;
        observation.ofo_budget_bytes = config->ofo_budget_bytes;
        observation.admission_allowed = 1;
        observation.service_admission_selected =
            strcmp(decision_reason, "burst_continue") == 0 ? 0 : 1;
        observation.admission_block_reason = "none";
        observation.arrival_debt_bytes = ctx != NULL
            ? ctx->burst_remaining_bytes : 0;
        observation.risk_inflight_debt_bytes = selected->inflight_bytes;
        observation.risk_inflight_budget_bytes =
            selected->cc_headroom_bytes == UINT64_MAX
            ? 0 : selected->cc_headroom_bytes;
        observation.risky_cwnd_bytes = selected->cwnd_bytes;
        observation.risky_inflight_bytes = selected->inflight_bytes;
        observation.risky_cc_headroom_bytes =
            selected->cc_headroom_bytes == UINT64_MAX
            ? 0 : selected->cc_headroom_bytes;
        observation.risky_latest_rtt_us = selected->latest_rtt_us;
        observation.risky_rtt_age_us = selected->ack_age_us;
        observation.risky_reservoir_bytes = selected->backlog_bytes;
        observation.risky_reservoir_low_bytes =
            (uint64_t) ((double) selected->service_quantum_bytes
                * config->rq_low_factor);
        observation.risky_reservoir_high_bytes =
            (uint64_t) ((double) selected->service_quantum_bytes
                * config->rq_high_factor);
        observation.risky_service_quantum_bytes =
            selected->service_quantum_bytes;
        observation.risky_last_probe_at_us = selected->last_probe_at_us;
        observation.risky_service_bytes =
            selected->observed_service_bytes;
        observation.risky_service_rate_bytes_per_us =
            selected->service_rate_bytes_per_us;
        observation.recovery_probe_selected =
            recovery_probe_selected ? 1 : 0;
        observation.eta_clean_us = base_candidate != NULL
            ? base_candidate->eta_us : selected->eta_us;
        observation.has_base_candidate = 1;
        observation.base_candidate_path_id =
            base_candidate != NULL && base_candidate->path != NULL
            ? base_candidate->path->path_id : selected->path->path_id;
        if (alt != NULL) {
            uint64_t base_eta = base_candidate != NULL
                ? base_candidate->eta_us : selected->eta_us;

            observation.has_admission_candidate = 1;
            observation.admission_candidate_path_id = alt->path->path_id;
            observation.eta_risky_us = alt->eta_us;
            observation.arrival_skew_us =
                base_eta > alt->eta_us
                ? base_eta - alt->eta_us
                : alt->eta_us - base_eta;
        }
        observation.predicted_ofo_bytes =
            (double) selected_burst_budget;

        xqc_scheduler_notify_observer(&observation);

        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|mac_aware_clean_path:%ui|decision:%s|q:%ui|"
                "backlog:%ui|eta_us:%ui|burst_budget:%ui|"
                "burst_remaining:%ui|samples:%ui|used_mask:%ui|",
                selected->path->path_id, decision_reason,
                selected->service_quantum_bytes, selected->backlog_bytes,
                selected->eta_us, selected_burst_budget,
                ctx != NULL ? ctx->burst_remaining_bytes : 0,
                selected->sample_count,
                xqc_scheduler_packet_path_mask(conn, packet_out));
        return selected->path;
    }

    if (cc_blocked != NULL && !reached_cwnd_check) {
        *cc_blocked = XQC_FALSE;
    }

    if (candidate_count > 0) {
        block_reason = "burst_budget_blocked";
    }
    observation.decision_reason = "no_path";
    observation.risk_reason = "none";
    observation.admission_block_reason = block_reason;
    xqc_scheduler_notify_observer(&observation);
    xqc_log(conn->log, XQC_LOG_DEBUG,
            "|mac_aware_no_available_path|conn:%p|reinj:%d|reason:%s|",
            conn, reinject, block_reason);
    return NULL;
}

const xqc_scheduler_callback_t xqc_mac_aware_scheduler_cb = {
    .xqc_scheduler_size             = xqc_mac_aware_scheduler_size,
    .xqc_scheduler_init             = xqc_mac_aware_scheduler_init,
    .xqc_scheduler_get_path         = xqc_mac_aware_scheduler_get_path,
};
