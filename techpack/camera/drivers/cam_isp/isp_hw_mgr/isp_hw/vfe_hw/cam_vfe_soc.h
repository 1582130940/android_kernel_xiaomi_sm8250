/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2017-2021, The Linux Foundation. All rights reserved.
 */

#ifndef _CAM_VFE_SOC_H_
#define _CAM_VFE_SOC_H_

#include "cam_soc_util.h"
#include "cam_isp_hw.h"

#define CAM_VFE_DSP_CLK_NAME "ife_dsp_clk"

#define UBWC_STATIC_CONFIG_MAX 2

/*
 * struct cam_vfe_soc_private:
 *
 * @Brief:                   Private SOC data specific to VFE HW Driver
 *
 * @cpas_handle:             Handle returned on registering with CPAS driver.
 *                           This handle is used for all further interface
 *                           with CPAS.
 * @cpas_version:            Has cpas version read from Hardware
 * @ubwc_static_ctrl:        UBWC static control configuration
 * @is_ife_lite:             Flag to indicate full vs lite IFE
 * @dsp_disabled:            Flag to indicate DSP is not supported for VFE
 * @ife_clk_src:             IFE source clock
 */
struct cam_vfe_soc_private {
	uint32_t    cpas_handle;
	uint32_t    cpas_version;
	struct clk *dsp_clk;
	int32_t     dsp_clk_index;
	int32_t     dsp_clk_rate;
	uint32_t    ubwc_static_ctrl[UBWC_STATIC_CONFIG_MAX];
	bool        is_ife_lite;
#ifndef CONFIG_MACH_XIAOMI
	bool        dsp_disabled;
	uint64_t    ife_clk_src;
#endif
};

/*
 * cam_vfe_init_soc_resources()
 *
 * @Brief:                   Initialize SOC resources including private data
 *
 * @soc_info:                Device soc information
 * @handler:                 Irq handler function pointer
 * @irq_data:                Irq handler function Callback data
 *
 * @Return:                  0: Success
 *                           Non-zero: Failure
 */
int cam_vfe_init_soc_resources(struct cam_hw_soc_info *soc_info,
	irq_handler_t vfe_irq_handler, void *irq_data);

/*
 * cam_vfe_deinit_soc_resources()
 *
 * @Brief:                   Deinitialize SOC resources including private data
 *
 * @soc_info:                Device soc information
 *
 * @Return:                  0: Success
 *                           Non-zero: Failure
 */
int cam_vfe_deinit_soc_resources(struct cam_hw_soc_info *soc_info);

/*
 * cam_vfe_enable_soc_resources()
 *
 * @brief:                   Enable regulator, irq resources, start CPAS
 *
 * @soc_info:                Device soc information
 *
 * @num_pix_rsrc:            Number of pix resource in input port
 *
 * @num_pd_rsrc:             Number of pdaf resource in input port
 *
 * @num_rdi_rsrc:            Number of rdi resource in input port
 *
 * @Return:                  0: Success
 *                           Non-zero: Failure
 */
#ifdef CONFIG_MACH_XIAOMI
int cam_vfe_enable_soc_resources(struct cam_hw_soc_info *soc_info);
#else
int cam_vfe_enable_soc_resources(struct cam_hw_soc_info *soc_info,
	int num_pix_rsrc, int num_pd_rsrc, int num_rdi_rsrc);
#endif

/*
 * cam_vfe_disable_soc_resources()
 *
 * @brief:                   Disable regulator, irq resources, stop CPAS
 *
 * @soc_info:                Device soc information
 *
 * @Return:                  0: Success
 *                           Non-zero: Failure
 */
int cam_vfe_disable_soc_resources(struct cam_hw_soc_info *soc_info);

/*
 * cam_vfe_soc_enable_clk()
 *
 * @brief:                   Enable clock with given name
 *
 * @soc_info:                Device soc information
 * @clk_name:                Name of clock to enable
 *
 * @Return:                  0: Success
 *                           Non-zero: Failure
 */
int cam_vfe_soc_enable_clk(struct cam_hw_soc_info *soc_info,
	const char *clk_name);

/*
 * cam_vfe_soc_disable_dsp_clk()
 *
 * @brief:                   Disable clock with given name
 *
 * @soc_info:                Device soc information
 * @clk_name:                Name of clock to enable
 *
 * @Return:                  0: Success
 *                           Non-zero: Failure
 */
int cam_vfe_soc_disable_clk(struct cam_hw_soc_info *soc_info,
	const char *clk_name);

#endif /* _CAM_VFE_SOC_H_ */
