/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2019-2020, The Linux Foundation. All rights reserved.
 */

#ifndef _CAM_CUSTOM_CSID_480_H_
#define _CAM_CUSTOM_CSID_480_H_

#include "cam_ife_csid_core.h"

#define CAM_CSID_VERSION_V480                 0x40080000

static struct cam_ife_csid_udi_reg_offset
	cam_custom_csid_480_udi_0_reg_offset = {
	.csid_udi_irq_status_addr                 = 0x30,
	.csid_udi_irq_mask_addr                   = 0x34,
	.csid_udi_irq_clear_addr                  = 0x38,
	.csid_udi_irq_set_addr                    = 0x3c,
	.csid_udi_cfg0_addr                       = 0x200,
	.csid_udi_cfg1_addr                       = 0x204,
	.csid_udi_ctrl_addr                       = 0x208,
	.csid_udi_frm_drop_pattern_addr           = 0x20c,
	.csid_udi_frm_drop_period_addr            = 0x210,
	.csid_udi_irq_subsample_pattern_addr      = 0x214,
	.csid_udi_irq_subsample_period_addr       = 0x218,
	.csid_udi_rpp_hcrop_addr                  = 0x21c,
	.csid_udi_rpp_vcrop_addr                  = 0x220,
	.csid_udi_rpp_pix_drop_pattern_addr       = 0x224,
	.csid_udi_rpp_pix_drop_period_addr        = 0x228,
	.csid_udi_rpp_line_drop_pattern_addr      = 0x22c,
	.csid_udi_rpp_line_drop_period_addr       = 0x230,
	.csid_udi_rst_strobes_addr                = 0x240,
	.csid_udi_status_addr                     = 0x250,
	.csid_udi_misr_val0_addr                  = 0x254,
	.csid_udi_misr_val1_addr                  = 0x258,
	.csid_udi_misr_val2_addr                  = 0x25c,
	.csid_udi_misr_val3_addr                  = 0x260,
	.csid_udi_format_measure_cfg0_addr        = 0x270,
	.csid_udi_format_measure_cfg1_addr        = 0x274,
	.csid_udi_format_measure0_addr            = 0x278,
	.csid_udi_format_measure1_addr            = 0x27c,
	.csid_udi_format_measure2_addr            = 0x280,
	.csid_udi_timestamp_curr0_sof_addr        = 0x290,
	.csid_udi_timestamp_curr1_sof_addr        = 0x294,
	.csid_udi_timestamp_prev0_sof_addr        = 0x298,
	.csid_udi_timestamp_prev1_sof_addr        = 0x29c,
	.csid_udi_timestamp_curr0_eof_addr        = 0x2a0,
	.csid_udi_timestamp_curr1_eof_addr        = 0x2a4,
	.csid_udi_timestamp_prev0_eof_addr        = 0x2a8,
	.csid_udi_timestamp_prev1_eof_addr        = 0x2ac,
	.csid_udi_err_recovery_cfg0_addr          = 0x2b0,
	.csid_udi_err_recovery_cfg1_addr          = 0x2b4,
	.csid_udi_err_recovery_cfg2_addr          = 0x2b8,
	.csid_udi_multi_vcdt_cfg0_addr            = 0x2bc,
	.csid_udi_byte_cntr_ping_addr             = 0x2e0,
	.csid_udi_byte_cntr_pong_addr             = 0x2e4,
	/* configurations */
	.ccif_violation_en                        = 1,
#ifdef CONFIG_MACH_XIAOMI
	.overflow_ctrl_en                         = 1,
#else
	.overflow_ctrl_en                         = 0,
#endif
};

static struct cam_ife_csid_udi_reg_offset
	cam_custom_csid_480_udi_1_reg_offset = {
	.csid_udi_irq_status_addr                 = 0x40,
	.csid_udi_irq_mask_addr                   = 0x44,
	.csid_udi_irq_clear_addr                  = 0x48,
	.csid_udi_irq_set_addr                    = 0x4c,
	.csid_udi_cfg0_addr                       = 0x300,
	.csid_udi_cfg1_addr                       = 0x304,
	.csid_udi_ctrl_addr                       = 0x308,
	.csid_udi_frm_drop_pattern_addr           = 0x30c,
	.csid_udi_frm_drop_period_addr            = 0x310,
	.csid_udi_irq_subsample_pattern_addr      = 0x314,
	.csid_udi_irq_subsample_period_addr       = 0x318,
	.csid_udi_rpp_hcrop_addr                  = 0x31c,
	.csid_udi_rpp_vcrop_addr                  = 0x320,
	.csid_udi_rpp_pix_drop_pattern_addr       = 0x324,
	.csid_udi_rpp_pix_drop_period_addr        = 0x328,
	.csid_udi_rpp_line_drop_pattern_addr      = 0x32c,
	.csid_udi_rpp_line_drop_period_addr       = 0x330,
	.csid_udi_rst_strobes_addr                = 0x340,
	.csid_udi_status_addr                     = 0x350,
	.csid_udi_misr_val0_addr                  = 0x354,
	.csid_udi_misr_val1_addr                  = 0x358,
	.csid_udi_misr_val2_addr                  = 0x35c,
	.csid_udi_misr_val3_addr                  = 0x360,
	.csid_udi_format_measure_cfg0_addr        = 0x370,
	.csid_udi_format_measure_cfg1_addr        = 0x374,
	.csid_udi_format_measure0_addr            = 0x378,
	.csid_udi_format_measure1_addr            = 0x37c,
	.csid_udi_format_measure2_addr            = 0x380,
	.csid_udi_timestamp_curr0_sof_addr        = 0x390,
	.csid_udi_timestamp_curr1_sof_addr        = 0x394,
	.csid_udi_timestamp_prev0_sof_addr        = 0x398,
	.csid_udi_timestamp_prev1_sof_addr        = 0x39c,
	.csid_udi_timestamp_curr0_eof_addr        = 0x3a0,
	.csid_udi_timestamp_curr1_eof_addr        = 0x3a4,
	.csid_udi_timestamp_prev0_eof_addr        = 0x3a8,
	.csid_udi_timestamp_prev1_eof_addr        = 0x3ac,
	.csid_udi_err_recovery_cfg0_addr          = 0x3b0,
	.csid_udi_err_recovery_cfg1_addr          = 0x3b4,
	.csid_udi_err_recovery_cfg2_addr          = 0x3b8,
	.csid_udi_multi_vcdt_cfg0_addr            = 0x3bc,
	.csid_udi_byte_cntr_ping_addr             = 0x3e0,
	.csid_udi_byte_cntr_pong_addr             = 0x3e4,
	/* configurations */
	.ccif_violation_en                        = 1,
#ifdef CONFIG_MACH_XIAOMI
	.overflow_ctrl_en                         = 1,
#else
	.overflow_ctrl_en                         = 0,
#endif
};

static struct cam_ife_csid_udi_reg_offset
	cam_custom_csid_480_udi_2_reg_offset = {
	.csid_udi_irq_status_addr                 = 0x50,
	.csid_udi_irq_mask_addr                   = 0x54,
	.csid_udi_irq_clear_addr                  = 0x58,
	.csid_udi_irq_set_addr                    = 0x5c,
	.csid_udi_cfg0_addr                       = 0x400,
	.csid_udi_cfg1_addr                       = 0x404,
	.csid_udi_ctrl_addr                       = 0x408,
	.csid_udi_frm_drop_pattern_addr           = 0x40c,
	.csid_udi_frm_drop_period_addr            = 0x410,
	.csid_udi_irq_subsample_pattern_addr      = 0x414,
	.csid_udi_irq_subsample_period_addr       = 0x418,
	.csid_udi_rpp_hcrop_addr                  = 0x41c,
	.csid_udi_rpp_vcrop_addr                  = 0x420,
	.csid_udi_rpp_pix_drop_pattern_addr       = 0x424,
	.csid_udi_rpp_pix_drop_period_addr        = 0x428,
	.csid_udi_rpp_line_drop_pattern_addr      = 0x42c,
	.csid_udi_rpp_line_drop_period_addr       = 0x430,
	.csid_udi_yuv_chroma_conversion_addr      = 0x434,
	.csid_udi_rst_strobes_addr                = 0x440,
	.csid_udi_status_addr                     = 0x450,
	.csid_udi_misr_val0_addr                  = 0x454,
	.csid_udi_misr_val1_addr                  = 0x458,
	.csid_udi_misr_val2_addr                  = 0x45c,
	.csid_udi_misr_val3_addr                  = 0x460,
	.csid_udi_format_measure_cfg0_addr        = 0x470,
	.csid_udi_format_measure_cfg1_addr        = 0x474,
	.csid_udi_format_measure0_addr            = 0x478,
	.csid_udi_format_measure1_addr            = 0x47c,
	.csid_udi_format_measure2_addr            = 0x480,
	.csid_udi_timestamp_curr0_sof_addr        = 0x490,
	.csid_udi_timestamp_curr1_sof_addr        = 0x494,
	.csid_udi_timestamp_prev0_sof_addr        = 0x498,
	.csid_udi_timestamp_prev1_sof_addr        = 0x49c,
	.csid_udi_timestamp_curr0_eof_addr        = 0x4a0,
	.csid_udi_timestamp_curr1_eof_addr        = 0x4a4,
	.csid_udi_timestamp_prev0_eof_addr        = 0x4a8,
	.csid_udi_timestamp_prev1_eof_addr        = 0x4ac,
	.csid_udi_err_recovery_cfg0_addr          = 0x4b0,
	.csid_udi_err_recovery_cfg1_addr          = 0x4b4,
	.csid_udi_err_recovery_cfg2_addr          = 0x4b8,
	.csid_udi_multi_vcdt_cfg0_addr            = 0x4bc,
	.csid_udi_byte_cntr_ping_addr             = 0x4e0,
	.csid_udi_byte_cntr_pong_addr             = 0x4e4,
	/* configurations */
	.ccif_violation_en                        = 1,
#ifdef CONFIG_MACH_XIAOMI
	.overflow_ctrl_en                         = 1,
#else
	.overflow_ctrl_en                         = 0,
#endif
};

static struct cam_ife_csid_csi2_rx_reg_offset
			cam_custom_csid_480_csi2_reg_offset = {
	.csid_csi2_rx_irq_status_addr                 = 0x20,
	.csid_csi2_rx_irq_mask_addr                   = 0x24,
	.csid_csi2_rx_irq_clear_addr                  = 0x28,
	.csid_csi2_rx_irq_set_addr                    = 0x2c,

	/*CSI2 rx control */
	.csid_csi2_rx_cfg0_addr                       = 0x100,
	.csid_csi2_rx_cfg1_addr                       = 0x104,
	.csid_csi2_rx_capture_ctrl_addr               = 0x108,
	.csid_csi2_rx_rst_strobes_addr                = 0x110,
	.csid_csi2_rx_de_scramble_cfg0_addr           = 0x114,
	.csid_csi2_rx_de_scramble_cfg1_addr           = 0x118,
	.csid_csi2_rx_cap_unmap_long_pkt_hdr_0_addr   = 0x120,
	.csid_csi2_rx_cap_unmap_long_pkt_hdr_1_addr   = 0x124,
	.csid_csi2_rx_captured_short_pkt_0_addr       = 0x128,
	.csid_csi2_rx_captured_short_pkt_1_addr       = 0x12c,
	.csid_csi2_rx_captured_long_pkt_0_addr        = 0x130,
	.csid_csi2_rx_captured_long_pkt_1_addr        = 0x134,
	.csid_csi2_rx_captured_long_pkt_ftr_addr      = 0x138,
	.csid_csi2_rx_captured_cphy_pkt_hdr_addr      = 0x13c,
	.csid_csi2_rx_lane0_misr_addr                 = 0x150,
	.csid_csi2_rx_lane1_misr_addr                 = 0x154,
	.csid_csi2_rx_lane2_misr_addr                 = 0x158,
	.csid_csi2_rx_lane3_misr_addr                 = 0x15c,
	.csid_csi2_rx_total_pkts_rcvd_addr            = 0x160,
	.csid_csi2_rx_stats_ecc_addr                  = 0x164,
	.csid_csi2_rx_total_crc_err_addr              = 0x168,

	.csi2_rst_srb_all                             = 0x3FFF,
	.csi2_rst_done_shift_val                      = 27,
	.csi2_irq_mask_all                            = 0xFFFFFFF,
	.csi2_misr_enable_shift_val                   = 6,
	.csi2_vc_mode_shift_val                       = 2,
	.csi2_capture_long_pkt_en_shift               = 0,
	.csi2_capture_short_pkt_en_shift              = 1,
	.csi2_capture_cphy_pkt_en_shift               = 2,
	.csi2_capture_long_pkt_dt_shift               = 4,
	.csi2_capture_long_pkt_vc_shift               = 10,
	.csi2_capture_short_pkt_vc_shift              = 15,
	.csi2_capture_cphy_pkt_dt_shift               = 20,
	.csi2_capture_cphy_pkt_vc_shift               = 26,
	.csi2_rx_phy_num_mask                         = 0x3,
};

static struct cam_ife_csid_common_reg_offset
			cam_custom_csid_480_cmn_reg_offset = {
	.csid_hw_version_addr                         = 0x0,
	.csid_cfg0_addr                               = 0x4,
	.csid_ctrl_addr                               = 0x8,
	.csid_reset_addr                              = 0xc,
	.csid_rst_strobes_addr                        = 0x10,

	.csid_test_bus_ctrl_addr                      = 0x14,
	.csid_top_irq_status_addr                     = 0x70,
	.csid_top_irq_mask_addr                       = 0x74,
	.csid_top_irq_clear_addr                      = 0x78,
	.csid_top_irq_set_addr                        = 0x7c,
	.csid_irq_cmd_addr                            = 0x80,

	/*configurations */
	.major_version                                = 1,
	.minor_version                                = 7,
	.version_incr                                 = 0,
	.num_udis                                     = 3,
	.num_rdis                                     = 0,
	.num_pix                                      = 0,
	.num_ppp                                      = 0,
	.csid_reg_rst_stb                             = 1,
	.csid_rst_stb                                 = 0x1e,
	.csid_rst_stb_sw_all                          = 0x1f,
	.path_rst_stb_all                             = 0x7f,
	.path_rst_done_shift_val                      = 1,
	.path_en_shift_val                            = 31,
	.dt_id_shift_val                              = 27,
	.vc_shift_val                                 = 22,
	.dt_shift_val                                 = 16,
	.fmt_shift_val                                = 12,
	.plain_fmt_shit_val                           = 10,
	.crop_v_en_shift_val                          = 6,
	.crop_h_en_shift_val                          = 5,
	.crop_shift                                   = 16,
	.ipp_irq_mask_all                             = 0,
	.rdi_irq_mask_all                             = 0,
	.ppp_irq_mask_all                             = 0,
	.udi_irq_mask_all                             = 0x7FFF,
	.measure_en_hbi_vbi_cnt_mask                  = 0xC,
	.format_measure_en_val                        = 1,
	.num_bytes_out_shift_val                      = 3,
};

static struct cam_ife_csid_reg_offset cam_custom_csid_480_reg_offset = {
	.cmn_reg          = &cam_custom_csid_480_cmn_reg_offset,
	.csi2_reg         = &cam_custom_csid_480_csi2_reg_offset,
	.ipp_reg          = NULL,
	.ppp_reg          = NULL,
	.rdi_reg = {
		NULL,
		NULL,
		NULL,
		NULL,
	},
	.udi_reg = {
		&cam_custom_csid_480_udi_0_reg_offset,
		&cam_custom_csid_480_udi_1_reg_offset,
		&cam_custom_csid_480_udi_2_reg_offset,
	},
	.tpg_reg = NULL,
};

#endif /*_CAM_IFE_CSID_480_H_ */
