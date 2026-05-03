#include "src/transport/scheduler/xqc_scheduler_observer.h"

#include <string.h>

static xqc_scheduler_observer_pt g_xqc_scheduler_observer = NULL;
static void *g_xqc_scheduler_observer_user_data = NULL;

void
xqc_scheduler_register_observer(xqc_scheduler_observer_pt observer,
    void *user_data)
{
    g_xqc_scheduler_observer = observer;
    g_xqc_scheduler_observer_user_data = user_data;
}

void
xqc_scheduler_unregister_observer(void)
{
    g_xqc_scheduler_observer = NULL;
    g_xqc_scheduler_observer_user_data = NULL;
}

void
xqc_scheduler_notify_observer(
    const xqc_scheduler_observation_t *observation)
{
    if (g_xqc_scheduler_observer == NULL || observation == NULL) {
        return;
    }

    g_xqc_scheduler_observer(observation, g_xqc_scheduler_observer_user_data);
}

void
xqc_scheduler_observation_init(xqc_scheduler_observation_t *observation,
    const char *scheduler_name, void *conn, void *conn_user_data,
    uint64_t packet_number, size_t packet_size)
{
    if (observation == NULL) {
        return;
    }

    memset(observation, 0, sizeof(*observation));
    observation->ts_us = 0;
    observation->conn = conn;
    observation->conn_user_data = conn_user_data;
    observation->scheduler_name = scheduler_name;
    observation->packet_number = packet_number;
    observation->packet_size = packet_size;
    observation->decision_reason = "normal";
    observation->risk_reason = "none";
    observation->admission_block_reason = "no_estimate";
}

void
xqc_scheduler_observation_append_path(xqc_scheduler_observation_t *observation,
    uint64_t path_id, uint64_t srtt_us, uint64_t cwnd_bytes,
    uint64_t bytes_in_flight, uint8_t can_send, uint8_t path_state,
    uint8_t app_path_status, uint8_t path_class)
{
    xqc_scheduler_path_snapshot_t *snapshot;

    if (observation == NULL || observation->path_count >= XQC_SCHED_OBS_MAX_PATHS) {
        return;
    }

    snapshot = &observation->paths[observation->path_count++];
    snapshot->path_id = path_id;
    snapshot->srtt_us = srtt_us;
    snapshot->cwnd_bytes = cwnd_bytes;
    snapshot->bytes_in_flight = bytes_in_flight;
    snapshot->can_send = can_send;
    snapshot->path_state = path_state;
    snapshot->app_path_status = app_path_status;
    snapshot->path_class = path_class;
}
