/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2017-2019, The Linux Foundation. All rights reserved.
 */

#ifndef _CAM_JPEG_DEV_H_
#define _CAM_JPEG_DEV_H_

#include "cam_subdev.h"
#include "cam_hw_mgr_intf.h"
#include "cam_context.h"
#include "cam_jpeg_context.h"

/**
 * struct cam_jpeg_dev - Camera JPEG V4l2 device node
 *
 * @sd: Commone camera subdevice node
 * @node: Pointer to jpeg subdevice
 * @ctx: JPEG base context storage
 * @ctx_jpeg: JPEG private context storage
 * @jpeg_mutex: Jpeg dev mutex
 * @open_cnt: Open device count
 */
struct cam_jpeg_dev {
	struct cam_subdev sd;
	struct cam_node *node;
#ifdef CONFIG_MACH_XIAOMI
	struct cam_context ctx[CAM_CTX_MAX];
	struct cam_jpeg_context ctx_jpeg[CAM_CTX_MAX];
#else
	struct cam_context ctx[CAM_JPEG_CTX_MAX];
	struct cam_jpeg_context ctx_jpeg[CAM_JPEG_CTX_MAX];
#endif
	struct mutex jpeg_mutex;
	int32_t open_cnt;
};
#endif /* __CAM_JPEG_DEV_H__ */
