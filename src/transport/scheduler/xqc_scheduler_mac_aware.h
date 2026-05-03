/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_SCHEDULER_MAC_AWARE_H_INCLUDED_
#define _XQC_SCHEDULER_MAC_AWARE_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>
#include "src/transport/monitor/xqc_wifi_monitor.h"

extern const xqc_scheduler_callback_t xqc_mac_aware_scheduler_cb;

XQC_EXPORT_PUBLIC_API
void xqc_mac_aware_scheduler_update_path_state(void *conn_user_data,
    uint64_t path_id, const xqc_wifi_state_snapshot_t *snapshot);

XQC_EXPORT_PUBLIC_API
void xqc_mac_aware_scheduler_clear_conn_state(void *conn_user_data);

#endif /* _XQC_SCHEDULER_MAC_AWARE_H_INCLUDED_ */
