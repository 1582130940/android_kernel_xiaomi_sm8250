// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2017-2020, The Linux Foundation. All rights reserved.
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/module.h>
#include "cam_csiphy_core.h"
#include "cam_csiphy_dev.h"
#include "cam_csiphy_soc.h"
#include "cam_common_util.h"
#include "cam_packet_util.h"

#include <dt-bindings/msm/msm-camera.h>

#include <soc/qcom/scm.h>
#include <cam_mem_mgr.h>
#include <cam_cpas_api.h>

#define SCM_SVC_CAMERASS 0x18
#define SECURE_SYSCALL_ID 0x6
#define SECURE_SYSCALL_ID_2 0x7

#define LANE_MASK_2PH 0x1F
#define LANE_MASK_3PH 0x7

#ifndef CONFIG_MACH_XIAOMI
#define SKEW_CAL_MASK 0x2
#endif

static int csiphy_dump;
module_param(csiphy_dump, int, 0644);

static int cam_csiphy_notify_secure_mode(struct csiphy_device *csiphy_dev,
	bool protect, int32_t offset)
{
	struct scm_desc desc = {0};

#ifdef CONFIG_MACH_XIAOMI
	if (offset >= CSIPHY_MAX_INSTANCES) {
#else
	if (offset >= CSIPHY_MAX_INSTANCES_PER_PHY) {
#endif
		CAM_ERR(CAM_CSIPHY, "Invalid CSIPHY offset");
		return -EINVAL;
	}

	desc.arginfo = SCM_ARGS(2, SCM_VAL, SCM_VAL);
	desc.args[0] = protect;
#ifdef CONFIG_MACH_XIAOMI
	desc.args[1] = csiphy_dev->csiphy_cpas_cp_reg_mask[offset];
#else
	desc.args[1] = csiphy_dev->csiphy_info[offset].csiphy_cpas_cp_reg_mask;
#endif

	if (scm_call2(SCM_SIP_FNID(SCM_SVC_CAMERASS, SECURE_SYSCALL_ID_2),
		&desc)) {
		CAM_ERR(CAM_CSIPHY, "scm call to hypervisor failed");
		return -EINVAL;
	}

	return 0;
}

int32_t cam_csiphy_get_instance_offset(
	struct csiphy_device *csiphy_dev,
	int32_t dev_handle)
{
#ifdef CONFIG_MACH_XIAOMI
	int32_t i;

	if (csiphy_dev->acquire_count >
		CSIPHY_MAX_INSTANCES) {
		CAM_ERR(CAM_CSIPHY, "Invalid acquire count");
#else
	int32_t i = 0;

	if ((csiphy_dev->acquire_count >
		csiphy_dev->session_max_device_support) ||
		(csiphy_dev->acquire_count < 0)) {
		CAM_ERR(CAM_CSIPHY,
			"Invalid acquire count: %d, Max supported device for session: %u",
			csiphy_dev->acquire_count,
			csiphy_dev->session_max_device_support);
#endif
		return -EINVAL;
	}

	for (i = 0; i < csiphy_dev->acquire_count; i++) {
		if (dev_handle ==
#ifdef CONFIG_MACH_XIAOMI
			csiphy_dev->bridge_intf.device_hdl[i])
#else
			csiphy_dev->csiphy_info[i].hdl_data.device_hdl)
#endif
			break;
	}

	return i;
}

void cam_csiphy_query_cap(struct csiphy_device *csiphy_dev,
	struct cam_csiphy_query_cap *csiphy_cap)
{
	struct cam_hw_soc_info *soc_info = &csiphy_dev->soc_info;

	csiphy_cap->slot_info = soc_info->index;
	csiphy_cap->version = csiphy_dev->hw_version;
	csiphy_cap->clk_lane = csiphy_dev->clk_lane;
}

void cam_csiphy_reset(struct csiphy_device *csiphy_dev)
{
	int32_t  i;
	void __iomem *base = NULL;
	uint32_t size =
		csiphy_dev->ctrl_reg->csiphy_reg.csiphy_reset_array_size;
	struct cam_hw_soc_info *soc_info = &csiphy_dev->soc_info;

	base = soc_info->reg_map[0].mem_base;

	for (i = 0; i < size; i++) {
		cam_io_w_mb(
			csiphy_dev->ctrl_reg->csiphy_reset_reg[i].reg_data,
			base +
			csiphy_dev->ctrl_reg->csiphy_reset_reg[i].reg_addr);

		usleep_range(csiphy_dev->ctrl_reg->csiphy_reset_reg[i].delay
			* 1000,	csiphy_dev->ctrl_reg->csiphy_reset_reg[i].delay
			* 1000 + 10);
	}
}

int32_t cam_csiphy_update_secure_info(
#ifdef CONFIG_MACH_XIAOMI
	struct csiphy_device *csiphy_dev,
	struct cam_csiphy_info  *cam_cmd_csiphy_info,
	struct cam_config_dev_cmd *cfg_dev)
#else
	struct csiphy_device *csiphy_dev, int32_t index)
#endif
{
#ifdef CONFIG_MACH_XIAOMI
	uint32_t clock_lane, adj_lane_mask, temp;
	int32_t offset;

	if (csiphy_dev->acquire_count >=
		CSIPHY_MAX_INSTANCES) {
		CAM_ERR(CAM_CSIPHY, "Invalid acquire count");
		return -EINVAL;
	}

	offset = cam_csiphy_get_instance_offset(csiphy_dev,
		cfg_dev->dev_handle);
	if (offset < 0 || offset >= CSIPHY_MAX_INSTANCES) {
		CAM_ERR(CAM_CSIPHY, "Invalid offset");
		return -EINVAL;
	}

	if (cam_cmd_csiphy_info->combo_mode)
		clock_lane =
			csiphy_dev->ctrl_reg->csiphy_reg.csiphy_2ph_combo_ck_ln;
	else
		clock_lane =
			csiphy_dev->ctrl_reg->csiphy_reg.csiphy_2ph_clock_lane;

	adj_lane_mask = cam_cmd_csiphy_info->lane_mask & LANE_MASK_2PH &
		~clock_lane;
	temp = adj_lane_mask & (clock_lane - 1);
	adj_lane_mask =
		((adj_lane_mask & (~(clock_lane - 1))) >> 1) | temp;

	if (cam_cmd_csiphy_info->csiphy_3phase)
		adj_lane_mask = cam_cmd_csiphy_info->lane_mask & LANE_MASK_3PH;

	csiphy_dev->csiphy_info.secure_mode[offset] = 1;
#else
	uint32_t adj_lane_mask = 0;
	uint16_t lane_assign = 0;
	uint8_t lane_cnt = 0;

	lane_assign = csiphy_dev->csiphy_info[index].lane_assign;
	lane_cnt = csiphy_dev->csiphy_info[index].lane_cnt;

	while (lane_cnt--) {
		if ((lane_assign & 0xF) == 0x0)
			adj_lane_mask |= 0x1;
		else
			adj_lane_mask |= (1 << (lane_assign & 0xF));

		lane_assign >>= 4;
		}
#endif

#ifdef CONFIG_MACH_XIAOMI
	csiphy_dev->csiphy_cpas_cp_reg_mask[offset] =
#else
	/* Logic to identify the secure bit */
	csiphy_dev->csiphy_info[index].csiphy_cpas_cp_reg_mask =
#endif
		adj_lane_mask << (csiphy_dev->soc_info.index *
		(CAM_CSIPHY_MAX_DPHY_LANES + CAM_CSIPHY_MAX_CPHY_LANES) +
#ifdef CONFIG_MACH_XIAOMI
		(!cam_cmd_csiphy_info->csiphy_3phase) *
#else
		(!csiphy_dev->csiphy_info[index].csiphy_3phase) *
#endif
		(CAM_CSIPHY_MAX_CPHY_LANES));

#ifndef CONFIG_MACH_XIAOMI
	CAM_DBG(CAM_CSIPHY, "csi phy idx:%d, cp_reg_mask:0x%lx",
		csiphy_dev->soc_info.index,
		csiphy_dev->csiphy_info[index].csiphy_cpas_cp_reg_mask);
#endif

	return 0;
}

#ifndef CONFIG_MACH_XIAOMI
static int cam_csiphy_get_lane_enable(
	struct csiphy_device *csiphy, int index, uint32_t *lane_enable)
{
	uint32_t lane_select = 0;
	uint16_t lane_assign = csiphy->csiphy_info[index].lane_assign;
	uint8_t lane_cnt = csiphy->csiphy_info[index].lane_cnt;
	int rc = 0;

	while (lane_cnt--) {
		if (csiphy->csiphy_info[index].csiphy_3phase) {
			switch (lane_assign & 0xF) {
			case 0x0:
				lane_select |= CPHY_LANE_0;
				break;
			case 0x1:
				lane_select |= CPHY_LANE_1;
				break;
			case 0x2:
				lane_select |= CPHY_LANE_2;
				break;
			default:
				CAM_ERR(CAM_CSIPHY,
					"Wrong lane configuration for CPHY : %d",
					lane_assign);
				*lane_enable = 0;
				return -EINVAL;
			}
		} else {
			switch (lane_assign & 0xF) {
			case 0x0:
				lane_select |= DPHY_LANE_0;
				lane_select |= DPHY_CLK_LN;
				break;
			case 0x1:
				lane_select |= DPHY_LANE_1;
				lane_select |= DPHY_CLK_LN;
				break;
			case 0x2:
				lane_select |= DPHY_LANE_2;
				if (csiphy->combo_mode)
					lane_select |= DPHY_LANE_3;
				else
					lane_select |= DPHY_CLK_LN;
				break;
			case 0x3:
				if (csiphy->combo_mode) {
					CAM_ERR(CAM_CSIPHY,
						"Wrong lane configuration for DPHYCombo: %d",
						lane_assign);
					*lane_enable = 0;
					return -EINVAL;
				}
				lane_select |= DPHY_LANE_3;
				lane_select |= DPHY_CLK_LN;
				break;
			default:
				CAM_ERR(CAM_CSIPHY,
					"Wrong lane configuration for DPHY: %d",
					lane_assign);
				*lane_enable = 0;
				return -EINVAL;
			}
		}
		lane_assign >>= 4;
	}

	CAM_DBG(CAM_CSIPHY, "Lane_enable: 0x%x", lane_enable);
	*lane_enable = lane_select;

	return rc;
}
#endif

int32_t cam_cmd_buf_parser(struct csiphy_device *csiphy_dev,
	struct cam_config_dev_cmd *cfg_dev)
{
#ifdef CONFIG_MACH_XIAOMI
	int32_t                 rc = 0;
#else
	int                      rc = 0;
#endif
	uintptr_t                generic_ptr;
	uintptr_t                generic_pkt_ptr;
	struct cam_packet       *csl_packet = NULL;
	struct cam_cmd_buf_desc *cmd_desc = NULL;
	uint32_t                *cmd_buf = NULL;
	struct cam_csiphy_info  *cam_cmd_csiphy_info = NULL;
	size_t                  len;
	size_t                  remain_len;
#ifndef CONFIG_MACH_XIAOMI
	int                     index;
	uint32_t                lane_enable = 0;
#endif

	if (!cfg_dev || !csiphy_dev) {
		CAM_ERR(CAM_CSIPHY, "Invalid Args");
		return -EINVAL;
	}

	rc = cam_mem_get_cpu_buf((int32_t) cfg_dev->packet_handle,
		&generic_pkt_ptr, &len);
	if (rc < 0) {
		CAM_ERR(CAM_CSIPHY, "Failed to get packet Mem address: %d", rc);
		return rc;
	}

	remain_len = len;
	if ((sizeof(struct cam_packet) > len) ||
		((size_t)cfg_dev->offset >= len - sizeof(struct cam_packet))) {
		CAM_ERR(CAM_CSIPHY,
			"Inval cam_packet strut size: %zu, len_of_buff: %zu",
			 sizeof(struct cam_packet), len);
		rc = -EINVAL;
		cam_mem_put_cpu_buf(cfg_dev->packet_handle);
		return rc;
	}

	remain_len -= (size_t)cfg_dev->offset;
	csl_packet = (struct cam_packet *)
		(generic_pkt_ptr + (uint32_t)cfg_dev->offset);

	if (cam_packet_util_validate_packet(csl_packet,
		remain_len)) {
		CAM_ERR(CAM_CSIPHY, "Invalid packet params");
		rc = -EINVAL;
		cam_mem_put_cpu_buf(cfg_dev->packet_handle);
		return rc;
	}

	if (csl_packet->num_cmd_buf)
		cmd_desc = (struct cam_cmd_buf_desc *)
			((uint32_t *)&csl_packet->payload +
			csl_packet->cmd_buf_offset / 4);
	else {
		CAM_ERR(CAM_CSIPHY, "num_cmd_buffers = %d",
			csl_packet->num_cmd_buf);
		rc = -EINVAL;
		cam_mem_put_cpu_buf(cfg_dev->packet_handle);
		return rc;
	}

	rc = cam_packet_util_validate_cmd_desc(cmd_desc);
	if (rc) {
		CAM_ERR(CAM_CSIPHY, "Invalid cmd desc ret: %d", rc);
		cam_mem_put_cpu_buf(cfg_dev->packet_handle);
		return rc;
	}

	rc = cam_mem_get_cpu_buf(cmd_desc->mem_handle,
		&generic_ptr, &len);
	if (rc < 0) {
		CAM_ERR(CAM_CSIPHY,
			"Failed to get cmd buf Mem address : %d", rc);
		cam_mem_put_cpu_buf(cfg_dev->packet_handle);
		return rc;
	}

	if ((len < sizeof(struct cam_csiphy_info)) ||
		(cmd_desc->offset > (len - sizeof(struct cam_csiphy_info)))) {
		CAM_ERR(CAM_CSIPHY,
			"Not enough buffer provided for cam_cisphy_info");
		rc = -EINVAL;
		cam_mem_put_cpu_buf(cmd_desc->mem_handle);
		cam_mem_put_cpu_buf(cfg_dev->packet_handle);
		return rc;
	}

	cmd_buf = (uint32_t *)generic_ptr;
	cmd_buf += cmd_desc->offset / 4;
	cam_cmd_csiphy_info = (struct cam_csiphy_info *)cmd_buf;

#ifdef CONFIG_MACH_XIAOMI
	csiphy_dev->config_count++;
	csiphy_dev->csiphy_info.lane_cnt += cam_cmd_csiphy_info->lane_cnt;
	csiphy_dev->csiphy_info.lane_mask |= cam_cmd_csiphy_info->lane_mask;
	csiphy_dev->csiphy_info.csiphy_3phase =
		cam_cmd_csiphy_info->csiphy_3phase;
	csiphy_dev->csiphy_info.combo_mode |= cam_cmd_csiphy_info->combo_mode;
	if (cam_cmd_csiphy_info->combo_mode == 1) {
		csiphy_dev->csiphy_info.settle_time_combo_sensor =
			cam_cmd_csiphy_info->settle_time;
		csiphy_dev->csiphy_info.data_rate_combo_sensor =
			cam_cmd_csiphy_info->data_rate;
	} else {
		csiphy_dev->csiphy_info.settle_time =
			cam_cmd_csiphy_info->settle_time;
		csiphy_dev->csiphy_info.data_rate =
			cam_cmd_csiphy_info->data_rate;
	}
#else
	index = cam_csiphy_get_instance_offset(csiphy_dev, cfg_dev->dev_handle);
	if (index < 0 || index  >= csiphy_dev->session_max_device_support) {
		CAM_ERR(CAM_CSIPHY, "index is invalid: %d", index);
		cam_mem_put_cpu_buf(cmd_desc->mem_handle);
		cam_mem_put_cpu_buf(cfg_dev->packet_handle);
		return -EINVAL;
	}

	csiphy_dev->csiphy_info[index].lane_cnt = cam_cmd_csiphy_info->lane_cnt;
	csiphy_dev->csiphy_info[index].lane_assign =
		cam_cmd_csiphy_info->lane_assign;

	csiphy_dev->csiphy_info[index].settle_time =
		cam_cmd_csiphy_info->settle_time;
	csiphy_dev->csiphy_info[index].data_rate =
		cam_cmd_csiphy_info->data_rate;
	csiphy_dev->csiphy_info[index].secure_mode =
		cam_cmd_csiphy_info->secure_mode;
	csiphy_dev->csiphy_info[index].mipi_flags =
		cam_cmd_csiphy_info->mipi_flags;
	csiphy_dev->csiphy_info[index].csiphy_3phase =
		cam_cmd_csiphy_info->csiphy_3phase;

	rc = cam_csiphy_get_lane_enable(csiphy_dev, index, &lane_enable);
	if (rc) {
		CAM_ERR(CAM_CSIPHY, "Wrong lane configuration: %d",
			csiphy_dev->csiphy_info[index].lane_assign);
		if (csiphy_dev->combo_mode) {
			CAM_DBG(CAM_CSIPHY,
				"Resetting error to zero for other devices to configure");
			rc = 0;
		}
		lane_enable = 0;
		csiphy_dev->csiphy_info[index].lane_enable = lane_enable;
		goto reset_settings;
	}
#endif

#ifndef CONFIG_MACH_XIAOMI
	csiphy_dev->csiphy_info[index].lane_enable = lane_enable;
#endif

	if (cam_cmd_csiphy_info->secure_mode == 1)
		cam_csiphy_update_secure_info(csiphy_dev,
#ifdef CONFIG_MACH_XIAOMI
			cam_cmd_csiphy_info, cfg_dev);
#else
			index);

	csiphy_dev->config_count++;

	CAM_DBG(CAM_CSIPHY,
		"phy version:%d, phy_idx: %d",
		csiphy_dev->hw_version,
		csiphy_dev->soc_info.index);
	CAM_DBG(CAM_CSIPHY,
		"phy_idx: %d, 3phase:%d, combo mode:%d, secure mode:%d",
		csiphy_dev->soc_info.index,
		csiphy_dev->csiphy_info[index].csiphy_3phase,
		csiphy_dev->combo_mode,
		cam_cmd_csiphy_info->secure_mode);
	CAM_DBG(CAM_CSIPHY,
		"lane_cnt: 0x%x, lane_assign: 0x%x, lane_enable: 0x%x",
		csiphy_dev->csiphy_info[index].lane_cnt,
		csiphy_dev->csiphy_info[index].lane_assign,
		csiphy_dev->csiphy_info[index].lane_enable);

	CAM_DBG(CAM_CSIPHY,
		"settle time:%llu, datarate:%llu, mipi flags: 0x%x",
		csiphy_dev->csiphy_info[index].settle_time,
		csiphy_dev->csiphy_info[index].data_rate,
		csiphy_dev->csiphy_info[index].mipi_flags);

	cam_mem_put_cpu_buf(cmd_desc->mem_handle);
	cam_mem_put_cpu_buf(cfg_dev->packet_handle);
	return rc;

reset_settings:
	csiphy_dev->csiphy_info[index].lane_cnt = 0;
	csiphy_dev->csiphy_info[index].lane_assign = 0;
	csiphy_dev->csiphy_info[index].lane_enable = 0;
	csiphy_dev->csiphy_info[index].settle_time = 0;
	csiphy_dev->csiphy_info[index].data_rate = 0;
	csiphy_dev->csiphy_info[index].mipi_flags = 0;
	csiphy_dev->csiphy_info[index].secure_mode = 0;
	csiphy_dev->csiphy_info[index].hdl_data.device_hdl = -1;
	cam_mem_put_cpu_buf(cfg_dev->packet_handle);
	cam_mem_put_cpu_buf(cmd_desc->mem_handle);
#endif
	return rc;
}

void cam_csiphy_cphy_irq_config(struct csiphy_device *csiphy_dev)
{
	int32_t i;
	void __iomem *csiphybase =
		csiphy_dev->soc_info.reg_map[0].mem_base;

	for (i = 0; i < csiphy_dev->num_irq_registers; i++)
		cam_io_w_mb(
			csiphy_dev->ctrl_reg->csiphy_irq_reg[i].reg_data,
			csiphybase +
			csiphy_dev->ctrl_reg->csiphy_irq_reg[i].reg_addr);
}

#ifdef CONFIG_MACH_XIAOMI
void cam_csiphy_cphy_data_rate_config(struct csiphy_device *csiphy_device)
#else
static void cam_csiphy_cphy_data_rate_config(
	struct csiphy_device *csiphy_device, int32_t idx)
#endif
{
	int i = 0, j = 0;
	uint64_t phy_data_rate = 0;
	void __iomem *csiphybase = NULL;
	ssize_t num_table_entries = 0;
	struct data_rate_settings_t *settings_table = NULL;

	if ((csiphy_device == NULL) ||
		(csiphy_device->ctrl_reg == NULL) ||
		(csiphy_device->ctrl_reg->data_rates_settings_table == NULL)) {
		CAM_DBG(CAM_CSIPHY,
			"Data rate specific register table not found");
		return;
	}

#ifdef CONFIG_MACH_XIAOMI
	phy_data_rate = csiphy_device->csiphy_info.data_rate;
#else
	phy_data_rate = csiphy_device->csiphy_info[idx].data_rate;
#endif
	csiphybase =
		csiphy_device->soc_info.reg_map[0].mem_base;
	settings_table =
		csiphy_device->ctrl_reg->data_rates_settings_table;
	num_table_entries =
		settings_table->num_data_rate_settings;

	CAM_DBG(CAM_CSIPHY, "required data rate : %llu", phy_data_rate);
	for (i = 0; i < num_table_entries; i++) {
		struct data_rate_reg_info_t *drate_settings =
			settings_table->data_rate_settings;
		uint64_t bandwidth =
			drate_settings[i].bandwidth;
		ssize_t  num_reg_entries =
		drate_settings[i].data_rate_reg_array_size;

		if (phy_data_rate > bandwidth) {
			CAM_DBG(CAM_CSIPHY,
					"Skipping table [%d] %llu required: %llu",
					i, bandwidth, phy_data_rate);
			continue;
		}

		CAM_DBG(CAM_CSIPHY,
			"table[%d] BW : %llu Selected", i, bandwidth);
		for (j = 0; j < num_reg_entries; j++) {
			uint32_t reg_addr =
			drate_settings[i].csiphy_data_rate_regs[j].reg_addr;

			uint32_t reg_data =
			drate_settings[i].csiphy_data_rate_regs[j].reg_data;

			CAM_DBG(CAM_CSIPHY,
				"writing reg : %x val : %x",
						reg_addr, reg_data);
			cam_io_w_mb(reg_data,
				csiphybase + reg_addr);
		}
		break;
	}
}

void cam_csiphy_cphy_irq_disable(struct csiphy_device *csiphy_dev)
{
	int32_t i;
	void __iomem *csiphybase =
		csiphy_dev->soc_info.reg_map[0].mem_base;

	for (i = 0; i < csiphy_dev->num_irq_registers; i++)
		cam_io_w_mb(0x0, csiphybase +
			csiphy_dev->ctrl_reg->csiphy_irq_reg[i].reg_addr);
}

irqreturn_t cam_csiphy_irq(int irq_num, void *data)
{
	uint32_t irq;
	uint8_t i;
	struct csiphy_device *csiphy_dev =
		(struct csiphy_device *)data;
	struct cam_hw_soc_info *soc_info = NULL;
	struct csiphy_reg_parms_t *csiphy_reg = NULL;
	void __iomem *base = NULL;

	if (!csiphy_dev) {
		CAM_ERR(CAM_CSIPHY, "Invalid Args");
		return IRQ_NONE;
	}

	soc_info = &csiphy_dev->soc_info;
	base =  csiphy_dev->soc_info.reg_map[0].mem_base;
	csiphy_reg = &csiphy_dev->ctrl_reg->csiphy_reg;

	for (i = 0; i < csiphy_dev->num_irq_registers; i++) {
		irq = cam_io_r(base +
			csiphy_reg->mipi_csiphy_interrupt_status0_addr +
			(0x4 * i));
		cam_io_w_mb(irq, base +
			csiphy_reg->mipi_csiphy_interrupt_clear0_addr +
			(0x4 * i));
		CAM_ERR_RATE_LIMIT(CAM_CSIPHY,
			"CSIPHY%d_IRQ_STATUS_ADDR%d = 0x%x",
			soc_info->index, i, irq);
		cam_io_w_mb(0x0, base +
			csiphy_reg->mipi_csiphy_interrupt_clear0_addr +
			(0x4 * i));
	}
	cam_io_w_mb(0x1, base + csiphy_reg->mipi_csiphy_glbl_irq_cmd_addr);
	cam_io_w_mb(0x0, base + csiphy_reg->mipi_csiphy_glbl_irq_cmd_addr);

	return IRQ_HANDLED;
}

#ifdef CONFIG_MACH_XIAOMI
int32_t cam_csiphy_config_dev(struct csiphy_device *csiphy_dev)
#else
int32_t cam_csiphy_config_dev(struct csiphy_device *csiphy_dev,
	int32_t dev_handle)
#endif
{
	int32_t      rc = 0;
#ifdef CONFIG_MACH_XIAOMI
	uint32_t     lane_enable = 0, mask = 1, size = 0;
	uint16_t     lane_mask = 0, i = 0, cfg_size = 0, temp = 0;
	uint8_t      lane_cnt, lane_pos = 0;
#else
	uint32_t     lane_enable = 0;
	uint32_t     size = 0;
	uint16_t     i = 0, cfg_size = 0;
	uint16_t     lane_assign = 0;
	uint8_t      lane_cnt;
	int          max_lanes = 0;
#endif
	uint16_t     settle_cnt = 0;
	uint64_t     intermediate_var;
#ifndef CONFIG_MACH_XIAOMI
	uint8_t      skew_cal_enable = 0;
	uint8_t      lane_pos = 0;
	int          index;
#endif
	void __iomem *csiphybase;
	struct csiphy_reg_t *csiphy_common_reg = NULL;
	struct csiphy_reg_t (*reg_array)[MAX_SETTINGS_PER_LANE];
#ifdef CONFIG_MACH_XIAOMI
	lane_cnt = csiphy_dev->csiphy_info.lane_cnt;
#else
	bool         is_3phase = false;
#endif
	csiphybase = csiphy_dev->soc_info.reg_map[0].mem_base;

#ifndef CONFIG_MACH_XIAOMI
	CAM_DBG(CAM_CSIPHY, "ENTER");
#endif
	if (!csiphybase) {
		CAM_ERR(CAM_CSIPHY, "csiphybase NULL");
		return -EINVAL;
	}

#ifdef CONFIG_MACH_XIAOMI
	if (!csiphy_dev->csiphy_info.csiphy_3phase) {
		if (csiphy_dev->csiphy_info.combo_mode == 1)
			reg_array =
				csiphy_dev->ctrl_reg->csiphy_2ph_combo_mode_reg;
		else
			reg_array =
				csiphy_dev->ctrl_reg->csiphy_2ph_reg;
		csiphy_dev->num_irq_registers = 11;
		cfg_size =
		csiphy_dev->ctrl_reg->csiphy_reg.csiphy_2ph_config_array_size;

		lane_mask = csiphy_dev->csiphy_info.lane_mask & LANE_MASK_2PH;
		for (i = 0; i < MAX_DPHY_DATA_LN; i++) {
			if (mask == 0x2) {
				if (lane_mask & mask)
					lane_enable |= 0x80;
				i--;
			} else if (lane_mask & mask) {
				lane_enable |= 0x1 << (i<<1);
			}
			mask <<= 1;
		}
	} else {
		if (csiphy_dev->csiphy_info.combo_mode == 1) {
			if (csiphy_dev->ctrl_reg->csiphy_2ph_3ph_mode_reg)
				reg_array =
				csiphy_dev->ctrl_reg->csiphy_2ph_3ph_mode_reg;
			else {
				reg_array =
					csiphy_dev->ctrl_reg->csiphy_3ph_reg;
				CAM_ERR(CAM_CSIPHY,
					"Unsupported configuration, Falling back to CPHY mode");
			}
		} else
			reg_array =
				csiphy_dev->ctrl_reg->csiphy_3ph_reg;
		csiphy_dev->num_irq_registers = 11;
		cfg_size =
		csiphy_dev->ctrl_reg->csiphy_reg.csiphy_3ph_config_array_size;

		lane_mask = csiphy_dev->csiphy_info.lane_mask & LANE_MASK_3PH;
		mask = lane_mask;
		while (mask != 0) {
			temp = (i << 1)+1;
			lane_enable |= ((mask & 0x1) << temp);
			mask >>= 1;
			i++;
		}
	}
#else
	index = cam_csiphy_get_instance_offset(csiphy_dev, dev_handle);
	if (index < 0 || index >= csiphy_dev->session_max_device_support) {
		CAM_ERR(CAM_CSIPHY, "index is invalid: %d", index);
		return -EINVAL;
	}

	CAM_DBG(CAM_CSIPHY,
		"Index: %d: expected dev_hdl: 0x%x : derived dev_hdl: 0x%x",
			index, dev_handle,
			csiphy_dev->csiphy_info[index].hdl_data.device_hdl);
	csiphy_dev->num_irq_registers = 11;

	if (csiphy_dev->csiphy_info[index].csiphy_3phase)
		is_3phase = true;

	if (csiphy_dev->combo_mode) {
		if (is_3phase) {
			if (csiphy_dev->ctrl_reg->csiphy_2ph_3ph_mode_reg) {
				reg_array = csiphy_dev->ctrl_reg
					->csiphy_2ph_3ph_mode_reg;
			} else {
				CAM_WARN(CAM_CSIPHY,
					"CPHY combo mode reg settings not found");
				reg_array =
					csiphy_dev->ctrl_reg->csiphy_3ph_reg;
			}
			cfg_size = csiphy_dev->ctrl_reg->csiphy_reg
				.csiphy_3ph_config_array_size;
			max_lanes = CAM_CSIPHY_MAX_CPHY_LANES;
		} else {
			/* DPHY combo mode*/
			if (csiphy_dev->ctrl_reg->csiphy_2ph_combo_mode_reg) {
				reg_array = csiphy_dev
					->ctrl_reg->csiphy_2ph_combo_mode_reg;
			} else {
				CAM_WARN(CAM_CSIPHY,
					"DPHY combo mode reg settings not found");
				reg_array = csiphy_dev
					->ctrl_reg->csiphy_2ph_reg;
			}
			cfg_size = csiphy_dev->ctrl_reg->csiphy_reg
					.csiphy_2ph_config_array_size;
			max_lanes = MAX_LANES;
		}

		skew_cal_enable = csiphy_dev->csiphy_info[index].mipi_flags &
			SKEW_CAL_MASK;
	} else {
		/* for CPHY(3Phase) or DPHY(2Phase) Non combe mode selection */
		if (is_3phase) {
			reg_array = csiphy_dev->ctrl_reg->csiphy_3ph_reg;
			max_lanes = CAM_CSIPHY_MAX_CPHY_LANES;
			cfg_size = csiphy_dev->ctrl_reg->csiphy_reg
				.csiphy_3ph_config_array_size;
		} else {
			reg_array = csiphy_dev->ctrl_reg->csiphy_2ph_reg;
			cfg_size = csiphy_dev->ctrl_reg->csiphy_reg
				.csiphy_2ph_config_array_size;
			max_lanes = MAX_LANES;
		}
	}
#endif

#ifndef CONFIG_MACH_XIAOMI
	lane_cnt = csiphy_dev->csiphy_info[index].lane_cnt;
	lane_assign = csiphy_dev->csiphy_info[index].lane_assign;
	lane_enable = csiphy_dev->csiphy_info[index].lane_enable;
#endif

	size = csiphy_dev->ctrl_reg->csiphy_reg.csiphy_common_array_size;
	for (i = 0; i < size; i++) {
		csiphy_common_reg = &csiphy_dev->ctrl_reg->csiphy_common_reg[i];
		switch (csiphy_common_reg->csiphy_param_type) {
		case CSIPHY_LANE_ENABLE:
			cam_io_w_mb(lane_enable,
				csiphybase + csiphy_common_reg->reg_addr);
			usleep_range(csiphy_common_reg->delay * 1000,
				csiphy_common_reg->delay * 1000 + 10);
			break;
		case CSIPHY_DEFAULT_PARAMS:
			cam_io_w_mb(csiphy_common_reg->reg_data,
				csiphybase + csiphy_common_reg->reg_addr);
			usleep_range(csiphy_common_reg->delay * 1000,
				csiphy_common_reg->delay * 1000 + 10);
			break;
		case CSIPHY_2PH_REGS:
#ifdef CONFIG_MACH_XIAOMI
			if (!csiphy_dev->csiphy_info.csiphy_3phase) {
#else
			if (!is_3phase) {
#endif
				cam_io_w_mb(csiphy_common_reg->reg_data,
					csiphybase +
					csiphy_common_reg->reg_addr);
				usleep_range(csiphy_common_reg->delay * 1000,
					csiphy_common_reg->delay * 1000 + 10);
			}
			break;
		case CSIPHY_3PH_REGS:
#ifdef CONFIG_MACH_XIAOMI
			if (csiphy_dev->csiphy_info.csiphy_3phase) {
#else
			if (is_3phase) {
#endif
				cam_io_w_mb(csiphy_common_reg->reg_data,
					csiphybase +
					csiphy_common_reg->reg_addr);
				usleep_range(csiphy_common_reg->delay * 1000,
					csiphy_common_reg->delay * 1000 + 10);
			}
			break;
		default:
			break;
		}
	}

#ifdef CONFIG_MACH_XIAOMI
	while (lane_mask) {
		if (!(lane_mask & 0x1)) {
			lane_pos++;
			lane_mask >>= 1;
			continue;
		}

		intermediate_var = csiphy_dev->csiphy_info.settle_time;
		do_div(intermediate_var, 200000000);
		settle_cnt = intermediate_var;
		if (csiphy_dev->csiphy_info.combo_mode == 1 &&
			(lane_pos >= 3)) {
			intermediate_var =
			csiphy_dev->csiphy_info.settle_time_combo_sensor;
			do_div(intermediate_var, 200000000);
			settle_cnt = intermediate_var;
		}
#else
	intermediate_var = csiphy_dev->csiphy_info[index].settle_time;
	do_div(intermediate_var, 200000000);
	settle_cnt = intermediate_var;

	for (lane_pos = 0; lane_pos < max_lanes; lane_pos++) {
		CAM_DBG(CAM_CSIPHY, "lane_pos: %d is configuring", lane_pos);
#endif
		for (i = 0; i < cfg_size; i++) {
			switch (reg_array[lane_pos][i].csiphy_param_type) {
			case CSIPHY_LANE_ENABLE:
				cam_io_w_mb(lane_enable,
					csiphybase +
					reg_array[lane_pos][i].reg_addr);
			break;
			case CSIPHY_DEFAULT_PARAMS:
				cam_io_w_mb(reg_array[lane_pos][i].reg_data,
					csiphybase +
					reg_array[lane_pos][i].reg_addr);
			break;
			case CSIPHY_SETTLE_CNT_LOWER_BYTE:
				cam_io_w_mb(settle_cnt & 0xFF,
					csiphybase +
					reg_array[lane_pos][i].reg_addr);
			break;
			case CSIPHY_SETTLE_CNT_HIGHER_BYTE:
				cam_io_w_mb((settle_cnt >> 8) & 0xFF,
					csiphybase +
					reg_array[lane_pos][i].reg_addr);
			break;
#ifndef CONFIG_MACH_XIAOMI
			case CSIPHY_SKEW_CAL:
			if (skew_cal_enable)
				cam_io_w_mb(reg_array[lane_pos][i].reg_data,
					csiphybase +
					reg_array[lane_pos][i].reg_addr);
			break;
#endif
			default:
				CAM_DBG(CAM_CSIPHY, "Do Nothing");
			break;
			}
			if (reg_array[lane_pos][i].delay > 0) {
				usleep_range(reg_array[lane_pos][i].delay*1000,
					reg_array[lane_pos][i].delay*1000 + 10);
			}
		}
#ifdef CONFIG_MACH_XIAOMI
		lane_mask >>= 1;
		lane_pos++;
#endif
	}

#ifdef CONFIG_MACH_XIAOMI
	if (csiphy_dev->csiphy_info.csiphy_3phase)
		cam_csiphy_cphy_data_rate_config(csiphy_dev);
#else
	if (csiphy_dev->csiphy_info[index].csiphy_3phase)
		cam_csiphy_cphy_data_rate_config(csiphy_dev, index);
#endif

	cam_csiphy_cphy_irq_config(csiphy_dev);

	return rc;
}

void cam_csiphy_shutdown(struct csiphy_device *csiphy_dev)
{
	struct cam_hw_soc_info *soc_info;
	int32_t i = 0;

	if (csiphy_dev->csiphy_state == CAM_CSIPHY_INIT)
		return;

#ifndef CONFIG_MACH_XIAOMI
	if (!csiphy_dev->acquire_count)
		return;

	if (csiphy_dev->acquire_count >= CSIPHY_MAX_INSTANCES_PER_PHY) {
		CAM_WARN(CAM_CSIPHY, "acquire count is invalid: %u",
			csiphy_dev->acquire_count);
		csiphy_dev->acquire_count =
			CSIPHY_MAX_INSTANCES_PER_PHY;
	}
#endif

	if (csiphy_dev->csiphy_state == CAM_CSIPHY_START) {
		soc_info = &csiphy_dev->soc_info;

		for (i = 0; i < csiphy_dev->acquire_count; i++) {
#ifdef CONFIG_MACH_XIAOMI
			if (csiphy_dev->csiphy_info.secure_mode[i])
#else
			if (csiphy_dev->csiphy_info[i].secure_mode)
#endif
				cam_csiphy_notify_secure_mode(
					csiphy_dev,
					CAM_SECURE_MODE_NON_SECURE, i);

#ifdef CONFIG_MACH_XIAOMI
			csiphy_dev->csiphy_info.secure_mode[i] =
#else
			csiphy_dev->csiphy_info[i].secure_mode =
#endif
				CAM_SECURE_MODE_NON_SECURE;

#ifdef CONFIG_MACH_XIAOMI
			csiphy_dev->csiphy_cpas_cp_reg_mask[i] = 0;
#else
			csiphy_dev->csiphy_info[i].csiphy_cpas_cp_reg_mask = 0;
			csiphy_dev->csiphy_info[i].settle_time = 0;
			csiphy_dev->csiphy_info[i].data_rate = 0;
#endif
		}

		cam_csiphy_reset(csiphy_dev);
		cam_soc_util_disable_platform_resource(soc_info, true, true);

		cam_cpas_stop(csiphy_dev->cpas_handle);
		csiphy_dev->csiphy_state = CAM_CSIPHY_ACQUIRE;
	}

	if (csiphy_dev->csiphy_state == CAM_CSIPHY_ACQUIRE) {
#ifdef CONFIG_MACH_XIAOMI
		if (csiphy_dev->bridge_intf.device_hdl[0] != -1)
			cam_destroy_device_hdl(
				csiphy_dev->bridge_intf.device_hdl[0]);
		if (csiphy_dev->bridge_intf.device_hdl[1] != -1)
			cam_destroy_device_hdl(
				csiphy_dev->bridge_intf.device_hdl[1]);
		csiphy_dev->bridge_intf.device_hdl[0] = -1;
		csiphy_dev->bridge_intf.device_hdl[1] = -1;
		csiphy_dev->bridge_intf.link_hdl[0] = -1;
		csiphy_dev->bridge_intf.link_hdl[1] = -1;
		csiphy_dev->bridge_intf.session_hdl[0] = -1;
		csiphy_dev->bridge_intf.session_hdl[1] = -1;
#else
		for (i = 0; i < csiphy_dev->acquire_count; i++) {
			if (csiphy_dev->csiphy_info[i].hdl_data.device_hdl
				!= -1)
				cam_destroy_device_hdl(
				csiphy_dev->csiphy_info[i]
				.hdl_data.device_hdl);
			csiphy_dev->csiphy_info[i].hdl_data.device_hdl = -1;
		csiphy_dev->csiphy_info[i].hdl_data.session_hdl = -1;
		}
#endif
	}

	csiphy_dev->ref_count = 0;
#ifdef CONFIG_MACH_XIAOMI
	csiphy_dev->is_acquired_dev_combo_mode = 0;
#endif
	csiphy_dev->acquire_count = 0;
	csiphy_dev->start_dev_count = 0;
	csiphy_dev->csiphy_state = CAM_CSIPHY_INIT;
}

static int32_t cam_csiphy_external_cmd(struct csiphy_device *csiphy_dev,
	struct cam_config_dev_cmd *p_submit_cmd)
{
	struct cam_csiphy_info cam_cmd_csiphy_info;
	int32_t rc = 0;
#ifndef CONFIG_MACH_XIAOMI
	int32_t  index = -1;
#endif

	if (copy_from_user(&cam_cmd_csiphy_info,
		u64_to_user_ptr(p_submit_cmd->packet_handle),
		sizeof(struct cam_csiphy_info))) {
		CAM_ERR(CAM_CSIPHY, "failed to copy cam_csiphy_info\n");
		rc = -EFAULT;
	} else {
#ifdef CONFIG_MACH_XIAOMI
		csiphy_dev->csiphy_info.lane_cnt =
			cam_cmd_csiphy_info.lane_cnt;
		csiphy_dev->csiphy_info.lane_cnt =
			cam_cmd_csiphy_info.lane_cnt;
		csiphy_dev->csiphy_info.lane_mask =
			cam_cmd_csiphy_info.lane_mask;
		csiphy_dev->csiphy_info.csiphy_3phase =
			cam_cmd_csiphy_info.csiphy_3phase;
		csiphy_dev->csiphy_info.combo_mode =
			cam_cmd_csiphy_info.combo_mode;
		csiphy_dev->csiphy_info.settle_time =
			cam_cmd_csiphy_info.settle_time;
		csiphy_dev->csiphy_info.data_rate =
			cam_cmd_csiphy_info.data_rate;
		CAM_DBG(CAM_CSIPHY,
			"%s CONFIG_DEV_EXT settle_time= %lld lane_cnt=%d lane_mask=0x%x",
			__func__,
			csiphy_dev->csiphy_info.settle_time,
			csiphy_dev->csiphy_info.lane_cnt,
			csiphy_dev->csiphy_info.lane_mask);
#else
		index = cam_csiphy_get_instance_offset(csiphy_dev,
			p_submit_cmd->dev_handle);
		if (index < 0 ||
			index >= csiphy_dev->session_max_device_support) {
			CAM_ERR(CAM_CSIPHY, "index is invalid: %d", index);
			return -EINVAL;
		}

		csiphy_dev->csiphy_info[index].lane_cnt =
			cam_cmd_csiphy_info.lane_cnt;
		csiphy_dev->csiphy_info[index].lane_assign =
			cam_cmd_csiphy_info.lane_assign;
		csiphy_dev->csiphy_info[index].csiphy_3phase =
			cam_cmd_csiphy_info.csiphy_3phase;
		csiphy_dev->combo_mode =
			cam_cmd_csiphy_info.combo_mode;
		csiphy_dev->csiphy_info[index].settle_time =
			cam_cmd_csiphy_info.settle_time;
		csiphy_dev->csiphy_info[index].data_rate =
			cam_cmd_csiphy_info.data_rate;
		CAM_DBG(CAM_CSIPHY,
			"%s CONFIG_DEV_EXT settle_time= %lld lane_cnt=%d",
			__func__,
			csiphy_dev->csiphy_info[index].settle_time,
			csiphy_dev->csiphy_info[index].lane_cnt);
#endif
	}

	return rc;
}

#ifndef CONFIG_MACH_XIAOMI
static int cam_csiphy_update_lane(
	struct csiphy_device *csiphy, int index, bool enable)
{
	int i = 0;
	uint32_t lane_enable = 0;
	uint32_t size = 0;
	uint16_t lane_assign;
	void __iomem *base_address;
	struct csiphy_reg_t *csiphy_common_reg = NULL;

	base_address = csiphy->soc_info.reg_map[0].mem_base;
	size = csiphy->ctrl_reg->csiphy_reg.csiphy_common_array_size;

	for (i = 0; i < size; i++) {
		csiphy_common_reg = &csiphy->ctrl_reg->csiphy_common_reg[i];
		switch (csiphy_common_reg->csiphy_param_type) {
		case CSIPHY_LANE_ENABLE:
			CAM_DBG(CAM_CSIPHY, "LANE_ENABLE: %d", lane_enable);
			lane_enable = cam_io_r(base_address +
				csiphy_common_reg->reg_addr);
			break;
		}
	}

	lane_assign = csiphy->csiphy_info[index].lane_assign;

	if (enable)
		lane_enable |= csiphy->csiphy_info[index].lane_enable;
	else
		lane_enable &= ~csiphy->csiphy_info[index].lane_enable;

	CAM_DBG(CAM_CSIPHY, "lane_assign: 0x%x, lane_enable: 0x%x",
		lane_assign, lane_enable);
	for (i = 0; i < size; i++) {
		csiphy_common_reg = &csiphy->ctrl_reg->csiphy_common_reg[i];
		switch (csiphy_common_reg->csiphy_param_type) {
		case CSIPHY_LANE_ENABLE:
			CAM_DBG(CAM_CSIPHY, "LANE_ENABLE: %d", lane_enable);
			cam_io_w_mb(lane_enable,
				base_address + csiphy_common_reg->reg_addr);
			if (csiphy_common_reg->delay)
				usleep_range(csiphy_common_reg->delay,
					csiphy_common_reg->delay + 5);
			break;
		}
	}

	return 0;
}
#endif

int32_t cam_csiphy_core_cfg(void *phy_dev,
			void *arg)
{
	struct csiphy_device *csiphy_dev =
		(struct csiphy_device *)phy_dev;
#ifdef CONFIG_MACH_XIAOMI
	struct intf_params   *bridge_intf = NULL;
#endif
	struct cam_control   *cmd = (struct cam_control *)arg;
	int32_t              rc = 0;

	if (!csiphy_dev || !cmd) {
		CAM_ERR(CAM_CSIPHY, "Invalid input args");
		return -EINVAL;
	}

	if (cmd->handle_type != CAM_HANDLE_USER_POINTER) {
		CAM_ERR(CAM_CSIPHY, "Invalid handle type: %d",
			cmd->handle_type);
		return -EINVAL;
	}

	CAM_DBG(CAM_CSIPHY, "Opcode received: %d", cmd->op_code);
	mutex_lock(&csiphy_dev->mutex);
	switch (cmd->op_code) {
	case CAM_ACQUIRE_DEV: {
		struct cam_sensor_acquire_dev csiphy_acq_dev;
		struct cam_csiphy_acquire_dev_info csiphy_acq_params;
#ifndef CONFIG_MACH_XIAOMI
		int index;
#endif
		struct cam_create_dev_hdl bridge_params;

#ifdef CONFIG_MACH_XIAOMI
		if (csiphy_dev->csiphy_state == CAM_CSIPHY_START) {
			CAM_ERR(CAM_CSIPHY,
				"Not in right state to acquire : %d",
				csiphy_dev->csiphy_state);
#else
		CAM_DBG(CAM_CSIPHY, "ACQUIRE_CNT: %d COMBO_MODE: %d",
			csiphy_dev->acquire_count,
			csiphy_dev->combo_mode);
		if ((csiphy_dev->csiphy_state == CAM_CSIPHY_START) &&
			(csiphy_dev->combo_mode == 0) &&
			(csiphy_dev->acquire_count > 0)) {
			CAM_ERR(CAM_CSIPHY,
				"NonComboMode does not support multiple acquire: Acquire_count: %d",
				csiphy_dev->acquire_count);
			rc = -EINVAL;
			goto release_mutex;
		}

		if ((csiphy_dev->acquire_count) &&
			(csiphy_dev->acquire_count >=
			csiphy_dev->session_max_device_support)) {
			CAM_ERR(CAM_CSIPHY,
				"Max acquires are allowed in combo mode: %d",
				csiphy_dev->session_max_device_support);
#endif
			rc = -EINVAL;
			goto release_mutex;
		}

		rc = copy_from_user(&csiphy_acq_dev,
			u64_to_user_ptr(cmd->handle),
			sizeof(csiphy_acq_dev));
		if (rc < 0) {
			CAM_ERR(CAM_CSIPHY, "Failed copying from User");
			goto release_mutex;
		}

		csiphy_acq_params.combo_mode = 0;

		if (copy_from_user(&csiphy_acq_params,
			u64_to_user_ptr(csiphy_acq_dev.info_handle),
			sizeof(csiphy_acq_params))) {
			CAM_ERR(CAM_CSIPHY,
				"Failed copying from User");
			goto release_mutex;
		}

#ifdef CONFIG_MACH_XIAOMI
		if (csiphy_dev->acquire_count == 2) {
			CAM_ERR(CAM_CSIPHY,
					"CSIPHY device do not allow more than 2 acquires");
			rc = -EINVAL;
			goto release_mutex;
		}

		if ((csiphy_acq_params.combo_mode == 1) &&
			(csiphy_dev->is_acquired_dev_combo_mode == 1)) {
			CAM_ERR(CAM_CSIPHY,
				"Multiple Combo Acq are not allowed: cm: %d, acm: %d",
				csiphy_acq_params.combo_mode,
				csiphy_dev->is_acquired_dev_combo_mode);
			rc = -EINVAL;
			goto release_mutex;
		}

		if ((csiphy_acq_params.combo_mode != 1) &&
			(csiphy_dev->is_acquired_dev_combo_mode != 1) &&
			(csiphy_dev->acquire_count == 1)) {
			CAM_ERR(CAM_CSIPHY,
				"Multiple Acquires are not allowed cm: %d acm: %d",
				csiphy_acq_params.combo_mode,
				csiphy_dev->is_acquired_dev_combo_mode);
			rc = -EINVAL;
			goto release_mutex;
		}
#else
		if (csiphy_acq_params.combo_mode == 1) {
			CAM_DBG(CAM_CSIPHY, "combo mode stream detected");
			csiphy_dev->combo_mode = 1;
			csiphy_dev->session_max_device_support =
					CSIPHY_MAX_INSTANCES_PER_PHY;
		}

		if (!csiphy_acq_params.combo_mode) {
			CAM_DBG(CAM_CSIPHY, "Non Combo Mode stream");
			csiphy_dev->session_max_device_support = 1;
		}
#endif

		bridge_params.ops = NULL;
		bridge_params.session_hdl = csiphy_acq_dev.session_handle;
		bridge_params.v4l2_sub_dev_flag = 0;
		bridge_params.media_entity_flag = 0;
		bridge_params.priv = csiphy_dev;
#ifdef CONFIG_MACH_XIAOMI
		if (csiphy_acq_params.combo_mode >= 2) {
			CAM_ERR(CAM_CSIPHY, "Invalid combo_mode %d",
				csiphy_acq_params.combo_mode);
			rc = -EINVAL;
			goto release_mutex;
		}
#else
		index = csiphy_dev->acquire_count;
		csiphy_acq_dev.device_handle =
			cam_create_device_hdl(&bridge_params);
		if (csiphy_acq_dev.device_handle <= 0) {
			rc = -EFAULT;
			CAM_ERR(CAM_CSIPHY, "Can not create device handle");
			goto release_mutex;
		}
#endif

#ifdef CONFIG_MACH_XIAOMI
		bridge_intf = &csiphy_dev->bridge_intf;
		bridge_intf->device_hdl[csiphy_acq_params.combo_mode]
			= csiphy_acq_dev.device_handle;
		bridge_intf->session_hdl[csiphy_acq_params.combo_mode] =
#else
		csiphy_dev->csiphy_info[index].hdl_data.device_hdl =
			csiphy_acq_dev.device_handle;
		csiphy_dev->csiphy_info[index].hdl_data.session_hdl =
#endif
			csiphy_acq_dev.session_handle;

#ifndef CONFIG_MACH_XIAOMI
		CAM_DBG(CAM_CSIPHY, "Add dev_handle:0x%x at index: %d ",
			csiphy_dev->csiphy_info[index].hdl_data.device_hdl,
			index);
#endif
		if (copy_to_user(u64_to_user_ptr(cmd->handle),
				&csiphy_acq_dev,
				sizeof(struct cam_sensor_acquire_dev))) {
			CAM_ERR(CAM_CSIPHY, "Failed copying from User");
			rc = -EINVAL;
			goto release_mutex;
		}
#ifdef CONFIG_MACH_XIAOMI
		if (csiphy_acq_params.combo_mode == 1)
			csiphy_dev->is_acquired_dev_combo_mode = 1;
#endif

		csiphy_dev->acquire_count++;
#ifdef CONFIG_MACH_XIAOMI
		csiphy_dev->csiphy_state = CAM_CSIPHY_ACQUIRE;
#else
		CAM_DBG(CAM_CSIPHY, "ACQUIRE_CNT: %d",
			csiphy_dev->acquire_count);
		if (csiphy_dev->csiphy_state == CAM_CSIPHY_INIT)
			csiphy_dev->csiphy_state = CAM_CSIPHY_ACQUIRE;
#endif
	}
		break;
	case CAM_QUERY_CAP: {
		struct cam_csiphy_query_cap csiphy_cap = {0};

		cam_csiphy_query_cap(csiphy_dev, &csiphy_cap);
		if (copy_to_user(u64_to_user_ptr(cmd->handle),
			&csiphy_cap, sizeof(struct cam_csiphy_query_cap))) {
			CAM_ERR(CAM_CSIPHY, "Failed copying from User");
			rc = -EINVAL;
			goto release_mutex;
		}
	}
		break;
	case CAM_STOP_DEV: {
		int32_t offset, rc = 0;
		struct cam_start_stop_dev_cmd config;

		rc = copy_from_user(&config, (void __user *)cmd->handle,
					sizeof(config));
		if (rc < 0) {
			CAM_ERR(CAM_CSIPHY, "Failed copying from User");
			goto release_mutex;
		}

#ifdef CONFIG_MACH_XIAOMI
		if ((csiphy_dev->csiphy_state != CAM_CSIPHY_START) ||
			!csiphy_dev->start_dev_count) {
#else
		if (csiphy_dev->csiphy_state != CAM_CSIPHY_START) {
#endif
			CAM_ERR(CAM_CSIPHY, "Not in right state to stop : %d",
				csiphy_dev->csiphy_state);
			goto release_mutex;
		}

		offset = cam_csiphy_get_instance_offset(csiphy_dev,
			config.dev_handle);
#ifdef CONFIG_MACH_XIAOMI
		if (offset < 0 || offset >= CSIPHY_MAX_INSTANCES) {
			CAM_ERR(CAM_CSIPHY, "Invalid offset");
#else
		if (offset < 0 ||
			offset >= csiphy_dev->session_max_device_support) {
			CAM_ERR(CAM_CSIPHY, "Index is invalid: %d", offset);
#endif
			goto release_mutex;
		}

#ifndef CONFIG_MACH_XIAOMI
		CAM_INFO(CAM_CSIPHY,
			"STOP_DEV: CSIPHY_IDX: %d, Device_slot: %d, Datarate: %llu, Settletime: %llu",
			csiphy_dev->soc_info.index, offset,
			csiphy_dev->csiphy_info[offset].data_rate,
			csiphy_dev->csiphy_info[offset].settle_time);
#endif

		if (--csiphy_dev->start_dev_count) {
			CAM_DBG(CAM_CSIPHY, "Stop Dev ref Cnt: %d",
				csiphy_dev->start_dev_count);
#ifdef CONFIG_MACH_XIAOMI
			if (csiphy_dev->csiphy_info.secure_mode[offset])
#else
			if (csiphy_dev->csiphy_info[offset].secure_mode)
#endif
				cam_csiphy_notify_secure_mode(
					csiphy_dev,
					CAM_SECURE_MODE_NON_SECURE, offset);

#ifdef CONFIG_MACH_XIAOMI
			csiphy_dev->csiphy_info.secure_mode[offset] =
#else
			csiphy_dev->csiphy_info[offset].secure_mode =
#endif
				CAM_SECURE_MODE_NON_SECURE;
#ifdef CONFIG_MACH_XIAOMI
			csiphy_dev->csiphy_cpas_cp_reg_mask[offset] = 0;
#else
			csiphy_dev->csiphy_info[offset].csiphy_cpas_cp_reg_mask
				= 0;

			cam_csiphy_update_lane(csiphy_dev, offset, false);
#endif
			goto release_mutex;
		}

#ifdef CONFIG_MACH_XIAOMI
		if (csiphy_dev->csiphy_info.secure_mode[offset])
#else
		if (csiphy_dev->csiphy_info[offset].secure_mode)
#endif
			cam_csiphy_notify_secure_mode(
				csiphy_dev,
				CAM_SECURE_MODE_NON_SECURE, offset);

#ifdef CONFIG_MACH_XIAOMI
		csiphy_dev->csiphy_info.secure_mode[offset] =
#else
		csiphy_dev->csiphy_info[offset].secure_mode =
#endif
			CAM_SECURE_MODE_NON_SECURE;

#ifdef CONFIG_MACH_XIAOMI
		csiphy_dev->csiphy_cpas_cp_reg_mask[offset] = 0x0;
#else
		csiphy_dev->csiphy_info[offset].csiphy_cpas_cp_reg_mask = 0x0;
#endif

		rc = cam_csiphy_disable_hw(csiphy_dev);
		if (rc < 0)
			CAM_ERR(CAM_CSIPHY, "Failed in csiphy release");

		rc = cam_cpas_stop(csiphy_dev->cpas_handle);
		if (rc < 0)
			CAM_ERR(CAM_CSIPHY, "de-voting CPAS: %d", rc);

#ifndef CONFIG_MACH_XIAOMI
		CAM_DBG(CAM_CSIPHY, "All PHY devices stopped");
#endif
		csiphy_dev->csiphy_state = CAM_CSIPHY_ACQUIRE;
	}
		break;
	case CAM_RELEASE_DEV: {
#ifndef CONFIG_MACH_XIAOMI
		int32_t offset;
#endif
		struct cam_release_dev_cmd release;

		if (!csiphy_dev->acquire_count) {
			CAM_ERR(CAM_CSIPHY, "No valid devices to release");
			rc = -EINVAL;
			goto release_mutex;
		}

		if (copy_from_user(&release,
			u64_to_user_ptr(cmd->handle),
			sizeof(release))) {
			rc = -EFAULT;
			goto release_mutex;
		}

#ifndef CONFIG_MACH_XIAOMI
		offset = cam_csiphy_get_instance_offset(csiphy_dev,
			release.dev_handle);
		if (offset < 0 ||
			offset >= csiphy_dev->session_max_device_support) {
			CAM_ERR(CAM_CSIPHY, "index is invalid: %d", offset);
			goto release_mutex;
		}

		if (csiphy_dev->csiphy_info[offset].secure_mode)
			cam_csiphy_notify_secure_mode(
				csiphy_dev,
				CAM_SECURE_MODE_NON_SECURE, offset);

		csiphy_dev->csiphy_info[offset].secure_mode =
			CAM_SECURE_MODE_NON_SECURE;

		csiphy_dev->csiphy_cpas_cp_reg_mask[offset] = 0x0;
#endif

		rc = cam_destroy_device_hdl(release.dev_handle);
		if (rc < 0)
			CAM_ERR(CAM_CSIPHY, "destroying the device hdl");
#ifdef CONFIG_MACH_XIAOMI
		if (release.dev_handle ==
			csiphy_dev->bridge_intf.device_hdl[0]) {
			csiphy_dev->bridge_intf.device_hdl[0] = -1;
			csiphy_dev->bridge_intf.link_hdl[0] = -1;
			csiphy_dev->bridge_intf.session_hdl[0] = -1;
		} else {
			csiphy_dev->bridge_intf.device_hdl[1] = -1;
			csiphy_dev->bridge_intf.link_hdl[1] = -1;
			csiphy_dev->bridge_intf.session_hdl[1] = -1;
			csiphy_dev->is_acquired_dev_combo_mode = 0;
		}
#else
		csiphy_dev->csiphy_info[offset].hdl_data.device_hdl = -1;
		csiphy_dev->csiphy_info[offset].hdl_data.session_hdl = -1;
#endif

		csiphy_dev->config_count--;
#ifdef CONFIG_MACH_XIAOMI
		csiphy_dev->acquire_count--;
#else
		if (csiphy_dev->acquire_count) {
			csiphy_dev->acquire_count--;
			CAM_DBG(CAM_CSIPHY, "Acquire_cnt: %d",
				csiphy_dev->acquire_count);
		}
#endif

#ifdef CONFIG_MACH_XIAOMI
		if (csiphy_dev->acquire_count == 0)
			csiphy_dev->csiphy_state = CAM_CSIPHY_INIT;
#else
		if (csiphy_dev->start_dev_count == 0) {
			CAM_DBG(CAM_CSIPHY, "All PHY devices released");
			csiphy_dev->csiphy_state = CAM_CSIPHY_INIT;
		}
#endif
		if (csiphy_dev->config_count == 0) {
			CAM_DBG(CAM_CSIPHY, "reset csiphy_info");
#ifdef CONFIG_MACH_XIAOMI
			csiphy_dev->csiphy_info.lane_mask = 0;
			csiphy_dev->csiphy_info.lane_cnt = 0;
			csiphy_dev->csiphy_info.combo_mode = 0;
#else
			csiphy_dev->csiphy_info[offset].lane_cnt = 0;
			csiphy_dev->csiphy_info[offset].lane_assign = 0;
			csiphy_dev->csiphy_info[offset].csiphy_3phase = -1;
			csiphy_dev->combo_mode = 0;
#endif
		}
#ifndef CONFIG_MACH_XIAOMI
		break;
#endif
	}
#ifdef CONFIG_MACH_XIAOMI
		break;
#endif
	case CAM_CONFIG_DEV: {
		struct cam_config_dev_cmd config;

		if (copy_from_user(&config,
			u64_to_user_ptr(cmd->handle),
					sizeof(config))) {
			rc = -EFAULT;
		} else {
			rc = cam_cmd_buf_parser(csiphy_dev, &config);
			if (rc < 0) {
				CAM_ERR(CAM_CSIPHY, "Fail in cmd buf parser");
				goto release_mutex;
			}
		}
		break;
	}
	case CAM_START_DEV: {
		struct cam_ahb_vote ahb_vote;
		struct cam_axi_vote axi_vote = {0};
		struct cam_start_stop_dev_cmd config;
		int32_t offset;
#ifndef CONFIG_MACH_XIAOMI
		int clk_vote_level = -1;
#endif

		rc = copy_from_user(&config, (void __user *)cmd->handle,
			sizeof(config));
		if (rc < 0) {
			CAM_ERR(CAM_CSIPHY, "Failed copying from User");
			goto release_mutex;
		}

#ifdef CONFIG_MACH_XIAOMI
		if (csiphy_dev->csiphy_state == CAM_CSIPHY_START) {
			csiphy_dev->start_dev_count++;
#else
		if ((csiphy_dev->csiphy_state == CAM_CSIPHY_START) &&
			(csiphy_dev->start_dev_count >
			csiphy_dev->session_max_device_support)) {
			CAM_ERR(CAM_CSIPHY,
				"Invalid start count: %d, Max supported devices: %u",
				csiphy_dev->start_dev_count,
				csiphy_dev->session_max_device_support);
			rc = -EINVAL;
#endif
			goto release_mutex;
		}

		offset = cam_csiphy_get_instance_offset(csiphy_dev,
			config.dev_handle);
#ifdef CONFIG_MACH_XIAOMI
		if (offset < 0 || offset >= CSIPHY_MAX_INSTANCES) {
			CAM_ERR(CAM_CSIPHY, "Invalid offset");
#else
		if (offset < 0 ||
			offset >= csiphy_dev->session_max_device_support) {
			CAM_ERR(CAM_CSIPHY, "index is invalid: %d", offset);
#endif
			goto release_mutex;
		}

#ifndef CONFIG_MACH_XIAOMI
		CAM_INFO(CAM_CSIPHY,
			"START_DEV: CSIPHY_IDX: %d, Device_slot: %d, Datarate: %llu, Settletime: %llu",
			csiphy_dev->soc_info.index, offset,
			csiphy_dev->csiphy_info[offset].data_rate,
			csiphy_dev->csiphy_info[offset].settle_time);

		if (csiphy_dev->start_dev_count) {
			clk_vote_level =
				csiphy_dev->ctrl_reg->getclockvoting(
					csiphy_dev, offset);
			rc = cam_soc_util_set_clk_rate_level(
				&csiphy_dev->soc_info, clk_vote_level);
			if (rc) {
				CAM_WARN(CAM_CSIPHY,
					"Failed to set the clk_rate level: %d",
					clk_vote_level);
				rc = 0;
			}

			if (csiphy_dev->csiphy_info[offset].secure_mode == 1) {
				if (cam_cpas_is_feature_supported(
					CAM_CPAS_SECURE_CAMERA_ENABLE) != 1) {
					CAM_WARN(CAM_CSIPHY,
						"sec_cam: camera fuse bit not set");
					rc = 0;
					goto release_mutex;
				}

				rc = cam_csiphy_notify_secure_mode(csiphy_dev,
					CAM_SECURE_MODE_SECURE, offset);
				if (rc < 0) {
					csiphy_dev->csiphy_info[offset]
						.secure_mode =
						CAM_SECURE_MODE_NON_SECURE;
					CAM_WARN(CAM_CSIPHY,
						"sec_cam: notify failed: rc: %d",
						rc);
					rc = 0;
					goto release_mutex;
				}
			}
			if (csiphy_dev->csiphy_info[offset].csiphy_3phase)
				cam_csiphy_cphy_data_rate_config(
					csiphy_dev, offset);

			rc = cam_csiphy_update_lane(csiphy_dev, offset, true);
			if (csiphy_dump == 1)
				cam_csiphy_mem_dmp(&csiphy_dev->soc_info);
			if (rc) {
				CAM_WARN(CAM_CSIPHY,
					"csiphy_config_dev failed");
				goto release_mutex;
			}

			csiphy_dev->start_dev_count++;
			goto release_mutex;
		}

		CAM_DBG(CAM_CSIPHY, "Start_dev_cnt: %d",
			csiphy_dev->start_dev_count);
#endif

		ahb_vote.type = CAM_VOTE_ABSOLUTE;
		ahb_vote.vote.level = CAM_LOWSVS_VOTE;
		axi_vote.num_paths = 1;
		axi_vote.axi_path[0].path_data_type = CAM_AXI_PATH_DATA_ALL;
		axi_vote.axi_path[0].transac_type = CAM_AXI_TRANSACTION_WRITE;
		axi_vote.axi_path[0].camnoc_bw = CAM_CPAS_DEFAULT_AXI_BW;
		axi_vote.axi_path[0].mnoc_ab_bw = CAM_CPAS_DEFAULT_AXI_BW;
		axi_vote.axi_path[0].mnoc_ib_bw = CAM_CPAS_DEFAULT_AXI_BW;

		rc = cam_cpas_start(csiphy_dev->cpas_handle,
			&ahb_vote, &axi_vote);
		if (rc < 0) {
			CAM_ERR(CAM_CSIPHY, "voting CPAS: %d", rc);
#ifdef CONFIG_MACH_XIAOMI
			if (rc == -EALREADY)
				cam_cpas_stop(csiphy_dev->cpas_handle);
#endif
			goto release_mutex;
		}

#ifdef CONFIG_MACH_XIAOMI
		if (csiphy_dev->csiphy_info.secure_mode[offset] == 1) {
#else
		if (csiphy_dev->csiphy_info[offset].secure_mode == 1) {
#endif
			if (cam_cpas_is_feature_supported(
					CAM_CPAS_SECURE_CAMERA_ENABLE) != 1) {
				CAM_ERR(CAM_CSIPHY,
					"sec_cam: camera fuse bit not set");
				cam_cpas_stop(csiphy_dev->cpas_handle);
				rc = -1;
				goto release_mutex;
			}

			rc = cam_csiphy_notify_secure_mode(
				csiphy_dev,
				CAM_SECURE_MODE_SECURE, offset);
			if (rc < 0) {
#ifdef CONFIG_MACH_XIAOMI
				csiphy_dev->csiphy_info.secure_mode[offset] =
#else
				csiphy_dev->csiphy_info[offset].secure_mode =
#endif
					CAM_SECURE_MODE_NON_SECURE;
				cam_cpas_stop(csiphy_dev->cpas_handle);
				goto release_mutex;
			}
		}

#ifdef CONFIG_MACH_XIAOMI
		rc = cam_csiphy_enable_hw(csiphy_dev);
#else
		rc = cam_csiphy_enable_hw(csiphy_dev, offset);
#endif
		if (rc != 0) {
			CAM_ERR(CAM_CSIPHY, "cam_csiphy_enable_hw failed");
			cam_cpas_stop(csiphy_dev->cpas_handle);
			goto release_mutex;
		}
#ifdef CONFIG_MACH_XIAOMI
		rc = cam_csiphy_config_dev(csiphy_dev);
#else
		rc = cam_csiphy_config_dev(csiphy_dev, config.dev_handle);
#endif
		if (csiphy_dump == 1)
			cam_csiphy_mem_dmp(&csiphy_dev->soc_info);

		if (rc < 0) {
			CAM_ERR(CAM_CSIPHY, "cam_csiphy_config_dev failed");
			cam_csiphy_disable_hw(csiphy_dev);
			cam_cpas_stop(csiphy_dev->cpas_handle);
			goto release_mutex;
		}
		csiphy_dev->start_dev_count++;
#ifndef CONFIG_MACH_XIAOMI
		CAM_DBG(CAM_CSIPHY, "START DEV CNT: %d",
			csiphy_dev->start_dev_count);
#endif
		csiphy_dev->csiphy_state = CAM_CSIPHY_START;
	}
		break;
	case CAM_CONFIG_DEV_EXTERNAL: {
		struct cam_config_dev_cmd submit_cmd;

		if (copy_from_user(&submit_cmd,
			u64_to_user_ptr(cmd->handle),
			sizeof(struct cam_config_dev_cmd))) {
			CAM_ERR(CAM_CSIPHY, "failed copy config ext\n");
			rc = -EFAULT;
		} else {
			rc = cam_csiphy_external_cmd(csiphy_dev, &submit_cmd);
		}
		break;
	}
	default:
		CAM_ERR(CAM_CSIPHY, "Invalid Opcode: %d", cmd->op_code);
		rc = -EINVAL;
		goto release_mutex;
	}

release_mutex:
	mutex_unlock(&csiphy_dev->mutex);

	return rc;
}
