/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/transport/reinjection_control/xqc_reinj_redundant.h"

#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_reinjection.h"
#include "src/transport/xqc_packet_out.h"

static size_t
xqc_redundant_reinj_ctl_size()
{
    return sizeof(xqc_redundant_reinj_ctl_t);
}

static void
xqc_redundant_reinj_ctl_init(void *reinj_ctl, xqc_connection_t *conn)
{
    xqc_redundant_reinj_ctl_t *rctl = (xqc_redundant_reinj_ctl_t *) reinj_ctl;

    rctl->log = conn->log;
    rctl->conn = conn;
}

static xqc_bool_t
xqc_redundant_reinj_can_reinject(void *ctl,
    xqc_packet_out_t *po, xqc_reinjection_mode_t mode)
{
    xqc_redundant_reinj_ctl_t *rctl = (xqc_redundant_reinj_ctl_t *) ctl;

    if (rctl == NULL || rctl->conn == NULL || po == NULL) {
        return XQC_FALSE;
    }

    if (mode != XQC_REINJ_UNACK_AFTER_SEND) {
        return XQC_FALSE;
    }

    if (!(po->po_flag & XQC_POF_IN_FLIGHT) || po->po_origin != NULL) {
        return XQC_FALSE;
    }

    if (!xqc_scheduler_packet_redundancy_allowed(po)) {
        return XQC_FALSE;
    }

    return xqc_scheduler_has_unsent_usable_path(rctl->conn, po);
}

const xqc_reinj_ctl_callback_t xqc_redundant_reinj_ctl_cb = {
    .xqc_reinj_ctl_size             = xqc_redundant_reinj_ctl_size,
    .xqc_reinj_ctl_init             = xqc_redundant_reinj_ctl_init,
    .xqc_reinj_ctl_can_reinject     = xqc_redundant_reinj_can_reinject,
};
