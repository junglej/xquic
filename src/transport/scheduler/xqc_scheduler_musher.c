/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/transport/scheduler/xqc_scheduler_musher.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/scheduler/xqc_scheduler_observer.h"
#include "src/transport/xqc_send_ctl.h"

#include <stdlib.h>
#include <string.h>

#define XQC_MUSHER_DEFAULT_RATIO_PCT 50
#define XQC_MUSHER_RATIO_STEP_PCT 5
#define XQC_MUSHER_REGULAR_INTERVAL_US 100000ULL
#define XQC_MUSHER_SEARCH_INTERVAL_US 200000ULL
#define XQC_MUSHER_TRIGGER_COOLDOWN_US 3000000ULL
#define XQC_MUSHER_RATE_DIFF_THRESHOLD_BPS 200000ULL
#define XQC_MUSHER_BUFFER_DIFF_THRESHOLD_BYTES 75000LL
#define XQC_MUSHER_TRIGGER_COUNT 5
#define XQC_MUSHER_REF_COUNT 5
#define XQC_MUSHER_RATE_IMPROVE_THRESHOLD_BPS 5000ULL

typedef enum xqc_musher_search_state_e {
    XQC_MUSHER_INIT_RIGHT = 0,
    XQC_MUSHER_RIGHT_RATIO_SET,
    XQC_MUSHER_INIT_LEFT,
    XQC_MUSHER_LEFT_RATIO_SET,
    XQC_MUSHER_SEARCH_RATE,
} xqc_musher_search_state_t;

typedef struct xqc_musher_scheduler_s {
    unsigned char              quota[XQC_MAX_PATHS_COUNT];
    unsigned char              ratio_pct_first;
    uint64_t                   interval_us;
    uint64_t                   last_tstamp_us;
    uint64_t                   last_app_bytes;
    uint64_t                   last_rate_bps;
    uint64_t                   last_buf_size;
    int64_t                    rate_diff;
    int64_t                    buf_size_diff;
    unsigned char              rate_cnt;
    unsigned char              buf_size_cnt;
    unsigned char              ref_cnt;
    uint64_t                   ref_rate_bps;
    uint64_t                   ref_buf_size;
    uint8_t                    in_search;
    uint64_t                   last_trigger_ts_us;
    uint64_t                   cur_rate_bps;
    uint64_t                   search_prev_rate_bps;
    int                        step_pct;
    unsigned char              search_init_ratio;
    xqc_musher_search_state_t  state;
} xqc_musher_scheduler_t;

static size_t
xqc_musher_scheduler_size(void)
{
    return sizeof(xqc_musher_scheduler_t);
}

static void
xqc_musher_scheduler_init(void *scheduler, xqc_log_t *log,
    xqc_scheduler_params_t *param)
{
    xqc_musher_scheduler_t *musher = (xqc_musher_scheduler_t *) scheduler;

    memset(musher, 0, sizeof(*musher));
    musher->ratio_pct_first = XQC_MUSHER_DEFAULT_RATIO_PCT;
    musher->interval_us = XQC_MUSHER_REGULAR_INTERVAL_US;
}

static void
xqc_musher_end_search(xqc_musher_scheduler_t *musher)
{
    musher->in_search = 0;
    musher->interval_us = XQC_MUSHER_REGULAR_INTERVAL_US;
}

static void
xqc_musher_clamp_ratio(xqc_musher_scheduler_t *musher)
{
    if (musher->ratio_pct_first < 5) {
        musher->ratio_pct_first = 5;
    }
    if (musher->ratio_pct_first > 95) {
        musher->ratio_pct_first = 95;
    }
}

static void
xqc_musher_set_ratio(xqc_musher_scheduler_t *musher, int ratio_pct)
{
    if (ratio_pct < 5) {
        ratio_pct = 5;
    }
    if (ratio_pct > 95) {
        ratio_pct = 95;
    }
    musher->ratio_pct_first = (unsigned char) ratio_pct;
}

static void
xqc_musher_trigger_search(xqc_musher_scheduler_t *musher, uint64_t now)
{
    musher->rate_cnt = 0;
    musher->buf_size_cnt = 0;
    musher->last_rate_bps = 0;
    musher->last_buf_size = 0;
    musher->rate_diff = 0;
    musher->buf_size_diff = 0;
    musher->ref_cnt = 0;
    musher->ref_rate_bps = 0;
    musher->ref_buf_size = 0;

    if (musher->last_trigger_ts_us == 0
        || now < musher->last_trigger_ts_us
        || now - musher->last_trigger_ts_us >= XQC_MUSHER_TRIGGER_COOLDOWN_US)
    {
        musher->in_search = 1;
        musher->interval_us = XQC_MUSHER_SEARCH_INTERVAL_US;
        musher->step_pct = XQC_MUSHER_RATIO_STEP_PCT;
        musher->last_trigger_ts_us = now;
        musher->state = XQC_MUSHER_INIT_RIGHT;
        musher->search_init_ratio = musher->ratio_pct_first;
    }
}

static void
xqc_musher_find_ratio(xqc_musher_scheduler_t *musher)
{
    switch (musher->state) {
    case XQC_MUSHER_INIT_RIGHT:
        if (musher->search_init_ratio + musher->step_pct <= 95) {
            musher->search_prev_rate_bps = musher->cur_rate_bps;
            xqc_musher_set_ratio(musher,
                musher->search_init_ratio + musher->step_pct);
            musher->state = XQC_MUSHER_RIGHT_RATIO_SET;
        } else {
            musher->state = XQC_MUSHER_INIT_LEFT;
        }
        break;

    case XQC_MUSHER_RIGHT_RATIO_SET:
        if (musher->cur_rate_bps
            > musher->search_prev_rate_bps
              + XQC_MUSHER_RATE_IMPROVE_THRESHOLD_BPS)
        {
            xqc_musher_set_ratio(musher,
                musher->ratio_pct_first + musher->step_pct);
            musher->search_prev_rate_bps = musher->cur_rate_bps;
            musher->state = XQC_MUSHER_SEARCH_RATE;
        } else {
            musher->state = XQC_MUSHER_INIT_LEFT;
        }
        break;

    case XQC_MUSHER_INIT_LEFT:
        if (musher->search_init_ratio >= musher->step_pct + 5) {
            musher->search_prev_rate_bps = musher->cur_rate_bps;
            xqc_musher_set_ratio(musher,
                musher->search_init_ratio - musher->step_pct);
            musher->state = XQC_MUSHER_LEFT_RATIO_SET;
        } else {
            xqc_musher_end_search(musher);
        }
        break;

    case XQC_MUSHER_LEFT_RATIO_SET:
        if (musher->cur_rate_bps
            > musher->search_prev_rate_bps
              + XQC_MUSHER_RATE_IMPROVE_THRESHOLD_BPS)
        {
            musher->step_pct = -XQC_MUSHER_RATIO_STEP_PCT;
            xqc_musher_set_ratio(musher,
                musher->ratio_pct_first + musher->step_pct);
            musher->search_prev_rate_bps = musher->cur_rate_bps;
            musher->state = XQC_MUSHER_SEARCH_RATE;
        } else {
            xqc_musher_set_ratio(musher,
                musher->ratio_pct_first + XQC_MUSHER_RATIO_STEP_PCT);
            xqc_musher_end_search(musher);
        }
        break;

    case XQC_MUSHER_SEARCH_RATE:
    default:
        if (musher->cur_rate_bps < musher->search_prev_rate_bps) {
            xqc_musher_set_ratio(musher,
                musher->ratio_pct_first - musher->step_pct);
            xqc_musher_end_search(musher);

        } else if ((musher->step_pct > 0 && musher->ratio_pct_first >= 95)
                   || (musher->step_pct < 0 && musher->ratio_pct_first <= 5))
        {
            xqc_musher_end_search(musher);

        } else {
            musher->search_prev_rate_bps = musher->cur_rate_bps;
            xqc_musher_set_ratio(musher,
                musher->ratio_pct_first + musher->step_pct);
        }
        break;
    }

    xqc_musher_clamp_ratio(musher);
}

static void
xqc_musher_update_control(xqc_musher_scheduler_t *musher,
    xqc_connection_t *conn, uint64_t now)
{
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    uint64_t total_app_bytes = 0;
    uint64_t total_buf_size = 0;
    uint64_t elapsed_us;
    uint64_t cur_rate_bps = 0;

    if (musher == NULL || conn == NULL) {
        return;
    }

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_send_ctl == NULL) {
            continue;
        }
        total_app_bytes += path->path_send_ctl->ctl_app_bytes_send;
        total_buf_size += path->path_send_ctl->ctl_bytes_in_flight;
    }

    if (musher->last_tstamp_us == 0 || now < musher->last_tstamp_us) {
        musher->last_tstamp_us = now;
        musher->last_app_bytes = total_app_bytes;
        return;
    }

    elapsed_us = now - musher->last_tstamp_us;
    if (elapsed_us < musher->interval_us) {
        return;
    }

    if (total_app_bytes >= musher->last_app_bytes && elapsed_us > 0) {
        cur_rate_bps =
            (total_app_bytes - musher->last_app_bytes) * 8000000ULL
            / elapsed_us;
    }
    musher->cur_rate_bps = cur_rate_bps;
    musher->last_app_bytes = total_app_bytes;
    musher->last_tstamp_us = now;

    if (!musher->in_search && musher->last_rate_bps == 0) {
        if (musher->ref_cnt >= XQC_MUSHER_REF_COUNT) {
            musher->last_rate_bps =
                musher->ref_rate_bps / XQC_MUSHER_REF_COUNT;
            musher->last_buf_size =
                musher->ref_buf_size / XQC_MUSHER_REF_COUNT;
            musher->ref_rate_bps = 0;
            musher->ref_buf_size = 0;
            musher->ref_cnt = 0;
        } else {
            musher->ref_rate_bps += cur_rate_bps;
            musher->ref_buf_size += total_buf_size;
            musher->ref_cnt++;
        }
        return;
    }

    musher->rate_diff += (int64_t) cur_rate_bps
                         - (int64_t) musher->last_rate_bps;
    musher->buf_size_diff += (int64_t) total_buf_size
                             - (int64_t) musher->last_buf_size;

    if (!musher->in_search) {
        if (llabs(musher->rate_diff)
            > (long long) XQC_MUSHER_RATE_DIFF_THRESHOLD_BPS)
        {
            musher->buf_size_cnt = 0;
            musher->rate_cnt++;
            if (musher->rate_cnt >= XQC_MUSHER_TRIGGER_COUNT) {
                xqc_musher_trigger_search(musher, now);
                return;
            }
        } else if (musher->buf_size_diff
                   < -XQC_MUSHER_BUFFER_DIFF_THRESHOLD_BYTES)
        {
            musher->rate_cnt = 0;
            musher->buf_size_cnt++;
            if (musher->buf_size_cnt >= XQC_MUSHER_TRIGGER_COUNT) {
                xqc_musher_trigger_search(musher, now);
                return;
            }
        } else {
            musher->rate_cnt = 0;
            musher->buf_size_cnt = 0;
        }

        musher->last_rate_bps = cur_rate_bps;
        musher->last_buf_size = total_buf_size;
    } else {
        xqc_musher_find_ratio(musher);
    }
}

static unsigned char *
xqc_musher_path_quota(xqc_musher_scheduler_t *musher, xqc_path_ctx_t *path)
{
    if (path->path_id >= XQC_MAX_PATHS_COUNT) {
        return NULL;
    }
    return &musher->quota[path->path_id];
}

static void
xqc_musher_charge_quota(xqc_musher_scheduler_t *musher,
    xqc_connection_t *conn, xqc_path_ctx_t *path, xqc_packet_out_t *packet_out)
{
    unsigned char *quota = xqc_musher_path_quota(musher, path);
    xqc_uint_t mss = xqc_conn_get_mss(conn);
    unsigned int segments;

    if (quota == NULL) {
        return;
    }

    if (mss == 0) {
        mss = XQC_PACKET_OUT_SIZE;
    }

    segments = (packet_out->po_used_size + mss - 1) / mss;
    if (segments == 0) {
        segments = 1;
    }

    if (segments > 255 - *quota) {
        *quota = 255;
    } else {
        *quota += segments;
    }
}

static void
xqc_musher_reset_round(xqc_musher_scheduler_t *musher)
{
    memset(musher->quota, 0, sizeof(musher->quota));
}

xqc_path_ctx_t *
xqc_musher_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, int check_cwnd,
    int reinject, xqc_bool_t *cc_blocked)
{
    xqc_musher_scheduler_t *musher = (xqc_musher_scheduler_t *) scheduler;
    xqc_scheduler_observation_t observation;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_path_ctx_t *paths[2] = {NULL, NULL};
    unsigned char target[2];
    unsigned char *quota;
    int path_count = 0;
    int chosen_idx = -1;
    int full_count = 0;
    xqc_bool_t reached_cwnd_check = XQC_FALSE;
    uint64_t now = xqc_monotonic_timestamp();

    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }

    xqc_musher_update_control(musher, conn, now);

    xqc_scheduler_observation_init(&observation, "musher", conn,
        conn->user_data, packet_out->po_pkt.pkt_num, packet_out->po_used_size);
    observation.ts_us = now;

retry:
    path_count = 0;
    chosen_idx = -1;
    full_count = 0;
    observation.path_count = 0;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        xqc_bool_t path_can_send = XQC_FALSE;

        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        xqc_scheduler_observe_path(&observation, path, 0,
            xqc_path_get_perf_class(path));

        if (!xqc_scheduler_path_is_usable(path)) {
            continue;
        }

        if (reinject && xqc_scheduler_packet_has_path(conn, packet_out, path->path_id)) {
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
        if (observation.path_count > 0
            && observation.paths[observation.path_count - 1].path_id
               == path->path_id)
        {
            observation.paths[observation.path_count - 1].can_send =
                path_can_send;
        }
        if (!path_can_send) {
            continue;
        }

        if (path_count < 2) {
            paths[path_count++] = path;
        }
    }

    if (path_count == 0) {
        if (cc_blocked && !reached_cwnd_check) {
            *cc_blocked = XQC_FALSE;
        }
        observation.decision_reason = "no_path";
        xqc_scheduler_notify_observer(&observation);
        return NULL;
    }

    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }

    if (path_count == 1) {
        chosen_idx = 0;
    } else {
        target[0] = musher->ratio_pct_first;
        target[1] = 100 - musher->ratio_pct_first;

        for (int i = 0; i < 2; i++) {
            quota = xqc_musher_path_quota(musher, paths[i]);
            if (quota == NULL) {
                chosen_idx = i;
                break;
            }
            if (*quota < target[i] && chosen_idx < 0) {
                chosen_idx = i;
            }
            if (*quota >= target[i]) {
                full_count++;
            }
        }

        if (full_count == 2) {
            xqc_musher_reset_round(musher);
            goto retry;
        }
    }

    if (chosen_idx < 0) {
        chosen_idx = 0;
    }

    path = paths[chosen_idx];
    xqc_musher_charge_quota(musher, conn, path, packet_out);

    observation.has_selected_path = 1;
    observation.selected_path_id = path->path_id;
    observation.decision_reason = musher->in_search ? "ratio_search" : "ratio";
    xqc_scheduler_notify_observer(&observation);

    xqc_log(conn->log, XQC_LOG_DEBUG,
            "|musher_best_path:%ui|ratio_first:%d|quota:%d|rate_bps:%ui|"
            "in_search:%d|",
            path->path_id, musher->ratio_pct_first,
            path->path_id < XQC_MAX_PATHS_COUNT ? musher->quota[path->path_id] : 0,
            musher->cur_rate_bps, musher->in_search);

    return path;
}

const xqc_scheduler_callback_t xqc_musher_scheduler_cb = {
    .xqc_scheduler_size             = xqc_musher_scheduler_size,
    .xqc_scheduler_init             = xqc_musher_scheduler_init,
    .xqc_scheduler_get_path         = xqc_musher_scheduler_get_path,
};
