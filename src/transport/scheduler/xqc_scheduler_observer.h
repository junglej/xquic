#ifndef _XQC_SCHEDULER_OBSERVER_H_INCLUDED_
#define _XQC_SCHEDULER_OBSERVER_H_INCLUDED_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XQC_SCHED_OBS_MAX_PATHS 8

typedef struct xqc_scheduler_path_snapshot_s {
    uint64_t    path_id;
    uint64_t    srtt_us;
    uint64_t    cwnd_bytes;
    uint64_t    bytes_in_flight;
    uint8_t     can_send;
    uint8_t     path_state;
    uint8_t     app_path_status;
    uint8_t     path_class;
} xqc_scheduler_path_snapshot_t;

typedef struct xqc_scheduler_observation_s {
    uint64_t                        ts_us;
    void                            *conn;
    void                            *conn_user_data;
    const char                      *scheduler_name;
    uint64_t                        packet_number;
    size_t                          packet_size;
    uint64_t                        selected_path_id;
    uint8_t                         has_selected_path;
    uint8_t                         path_count;
    xqc_scheduler_path_snapshot_t   paths[XQC_SCHED_OBS_MAX_PATHS];
} xqc_scheduler_observation_t;

typedef void (*xqc_scheduler_observer_pt)(
    const xqc_scheduler_observation_t *observation,
    void *user_data);

void
xqc_scheduler_register_observer(xqc_scheduler_observer_pt observer,
    void *user_data);

void
xqc_scheduler_unregister_observer(void);

void
xqc_scheduler_notify_observer(
    const xqc_scheduler_observation_t *observation);

void
xqc_scheduler_observation_init(xqc_scheduler_observation_t *observation,
    const char *scheduler_name, void *conn, void *conn_user_data,
    uint64_t packet_number, size_t packet_size);

void
xqc_scheduler_observation_append_path(xqc_scheduler_observation_t *observation,
    uint64_t path_id, uint64_t srtt_us, uint64_t cwnd_bytes,
    uint64_t bytes_in_flight, uint8_t can_send, uint8_t path_state,
    uint8_t app_path_status, uint8_t path_class);

#ifdef __cplusplus
}
#endif

#endif
