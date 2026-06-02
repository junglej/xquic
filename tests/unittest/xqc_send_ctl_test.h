/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_SEND_CTL_TEST_H
#define XQC_SEND_CTL_TEST_H

void xqc_test_pto_uses_remote_max_ack_delay(void);
void xqc_test_pto_remote_default_when_unset(void);
void xqc_test_send_ctl_update_rtt_ack_delay_cap(void);
void xqc_test_send_ctl_cwnd_usage_window_resets_after_ack(void);
void xqc_test_send_ctl_persistent_congestion_resets_rtt(void);
void xqc_test_send_ctl_persistent_congestion_rtt_reseeds_from_new_sample(void);
void xqc_test_send_ctl_single_loss_does_not_reset_rtt(void);
void xqc_test_send_ctl_persistent_congestion_no_rtt_sample_early_return(void);

#endif
