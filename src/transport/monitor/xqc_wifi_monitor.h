#ifndef _XQC_WIFI_MONITOR_H_INCLUDED_
#define _XQC_WIFI_MONITOR_H_INCLUDED_

#include <stdint.h>

typedef enum xqc_wifi_path_state_e {
    XQC_WIFI_PATH_STATE_UNKNOWN = 0,
    XQC_WIFI_PATH_STATE_REGULAR = 1,
    XQC_WIFI_PATH_STATE_DEGRADED_CSMA = 2,
} xqc_wifi_path_state_t;

typedef struct xqc_wifi_state_snapshot_s {
    uint64_t                ts_us;
    char                    ifname[64];
    unsigned int            ifindex;
    xqc_wifi_path_state_t   state;
    double                  pi_degraded;
    double                  p_long_gap;
    double                  r_eff_Bpus;
    uint64_t                last_gap_us;
    uint64_t                last_mac_rtt_us;
    double                  ewma_gap_us;
    double                  ewma_airtime_us;
    double                  ewma_mac_rtt_us;
    double                  ewma_burst_bytes;
    uint64_t                sample_count;
    uint64_t                last_update_ts_us;
    uint8_t                 gtsd_calibrated;
    uint64_t                tail_p50_us;
    uint64_t                tail_p95_us;
    double                  tail_ratio;
    double                  tail_baseline;
    double                  tail_excess;
    double                  cusum_on;
    double                  cusum_off;
} xqc_wifi_state_snapshot_t;

typedef void (*xqc_wifi_state_update_pt)(
    const xqc_wifi_state_snapshot_t *snapshot,
    void *user_data);

typedef struct xqc_wifi_monitor_config_s {
    const char                  *output_dir;
    const char                  *config_path;
    const char                  *ifname_primary;
    const char                  *ifname_secondary;
    xqc_wifi_state_update_pt    state_update_cb;
    void                        *state_update_user_data;
} xqc_wifi_monitor_config_t;

typedef struct xqc_wifi_monitor_s xqc_wifi_monitor_t;

int
xqc_wifi_monitor_start(xqc_wifi_monitor_t **monitor_out,
    const xqc_wifi_monitor_config_t *config);

void
xqc_wifi_monitor_stop(xqc_wifi_monitor_t *monitor);

int
xqc_wifi_monitor_get_snapshot(xqc_wifi_monitor_t *monitor,
    const char *ifname, xqc_wifi_state_snapshot_t *snapshot);

int
xqc_wifi_monitor_is_running(xqc_wifi_monitor_t *monitor);

int
xqc_wifi_monitor_start_status(xqc_wifi_monitor_t *monitor);

const char *
xqc_wifi_monitor_last_error(xqc_wifi_monitor_t *monitor);

#endif
