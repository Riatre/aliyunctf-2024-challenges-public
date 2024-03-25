/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005, 2006 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2005 PathScale, Inc.  All rights reserved.
 * Copyright (c) 2020 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef INFINIBAND_DRIVER_H
#define INFINIBAND_DRIVER_H

#include "container_of.h"
#include <infiniband/verbs.h>
#include <stdatomic.h>
#include <sys/types.h>

enum {
  VERBS_LOG_LEVEL_NONE,
  VERBS_LOG_ERR,
  VERBS_LOG_WARN,
  VERBS_LOG_INFO,
  VERBS_LOG_DEBUG,
};

void __verbs_log(struct verbs_context *ctx, uint32_t level, const char *fmt,
                 ...);

#define verbs_log(ctx, level, format, arg...)                                  \
  do {                                                                         \
    int tmp = errno;                                                           \
    __verbs_log(ctx, level, "%s: %s:%d: " format, (ctx)->context.device->name, \
                __func__, __LINE__, ##arg);                                    \
    errno = tmp;                                                               \
  } while (0)

#define verbs_debug(ctx, format, arg...)                                       \
  verbs_log(ctx, VERBS_LOG_DEBUG, format, ##arg)

#define verbs_info(ctx, format, arg...)                                        \
  verbs_log(ctx, VERBS_LOG_INFO, format, ##arg)

#define verbs_warn(ctx, format, arg...)                                        \
  verbs_log(ctx, VERBS_LOG_WARN, format, ##arg)

#define verbs_err(ctx, format, arg...)                                         \
  verbs_log(ctx, VERBS_LOG_ERR, format, ##arg)

#ifdef VERBS_DEBUG
#define verbs_log_datapath(ctx, level, format, arg...)                         \
  verbs_log(ctx, level, format, ##arg)
#else
#define verbs_log_datapath(ctx, level, format, arg...)                         \
  {}
#endif

#define verbs_debug_datapath(ctx, format, arg...)                              \
  verbs_log_datapath(ctx, VERBS_LOG_DEBUG, format, ##arg)

#define verbs_info_datapath(ctx, format, arg...)                               \
  verbs_log_datapath(ctx, VERBS_LOG_INFO, format, ##arg)

#define verbs_warn_datapath(ctx, format, arg...)                               \
  verbs_log_datapath(ctx, VERBS_LOG_WARN, format, ##arg)

#define verbs_err_datapath(ctx, format, arg...)                                \
  verbs_log_datapath(ctx, VERBS_LOG_ERR, format, ##arg)

enum verbs_xrcd_mask {
  VERBS_XRCD_HANDLE = 1 << 0,
  VERBS_XRCD_RESERVED = 1 << 1
};

enum create_cq_cmd_flags {
  CREATE_CQ_CMD_FLAGS_TS_IGNORED_EX = 1 << 0,
};

struct verbs_xrcd {
  struct ibv_xrcd xrcd;
  uint32_t comp_mask;
  uint32_t handle;
};

struct verbs_srq {
  struct ibv_srq srq;
  enum ibv_srq_type srq_type;
  struct verbs_xrcd *xrcd;
  struct ibv_cq *cq;
  uint32_t srq_num;
};

enum verbs_qp_mask {
  VERBS_QP_XRCD = 1 << 0,
  VERBS_QP_EX = 1 << 1,
};

enum ibv_gid_type_sysfs {
  IBV_GID_TYPE_SYSFS_IB_ROCE_V1,
  IBV_GID_TYPE_SYSFS_ROCE_V2,
};

enum verbs_query_gid_attr_mask {
  VERBS_QUERY_GID_ATTR_GID = 1 << 0,
  VERBS_QUERY_GID_ATTR_TYPE = 1 << 1,
  VERBS_QUERY_GID_ATTR_NDEV_IFINDEX = 1 << 2,
};

enum ibv_mr_type {
  IBV_MR_TYPE_MR,
  IBV_MR_TYPE_NULL_MR,
  IBV_MR_TYPE_IMPORTED_MR,
  IBV_MR_TYPE_DMABUF_MR,
};

struct verbs_mr {
  struct ibv_mr ibv_mr;
  enum ibv_mr_type mr_type;
  int access;
};

static inline struct verbs_mr *verbs_get_mr(struct ibv_mr *mr) {
  return container_of(mr, struct verbs_mr, ibv_mr);
}

struct verbs_qp {
  union {
    struct ibv_qp qp;
    struct ibv_qp_ex qp_ex;
  };
  uint32_t comp_mask;
  struct verbs_xrcd *xrcd;
};
static_assert(offsetof(struct ibv_qp_ex, qp_base) == 0, "Invalid qp layout");

struct verbs_cq {
  union {
    struct ibv_cq cq;
    struct ibv_cq_ex cq_ex;
  };
};

enum ibv_flow_action_type {
  IBV_FLOW_ACTION_UNSPECIFIED,
  IBV_FLOW_ACTION_ESP = 1,
};

struct verbs_flow_action {
  struct ibv_flow_action action;
  uint32_t handle;
  enum ibv_flow_action_type type;
};

struct verbs_dm {
  struct ibv_dm dm;
  uint32_t handle;
};

enum {
  VERBS_MATCH_SENTINEL = 0,
  VERBS_MATCH_PCI = 1,
  VERBS_MATCH_MODALIAS = 2,
  VERBS_MATCH_DRIVER_ID = 3,
};

struct verbs_match_ent {
  void *driver_data;
  union {
    const char *modalias;
    uint64_t driver_id;
  } u;
  uint16_t vendor;
  uint16_t device;
  uint8_t kind;
};
#define VERBS_DRIVER_ID(_id)                                                   \
  { .u.driver_id = (_id), .kind = VERBS_MATCH_DRIVER_ID, }
/* Note: New drivers should only use VERBS_DRIVER_ID, the below are for legacy
 * drivers
 */
#define VERBS_PCI_MATCH(_vendor, _device, _data)                               \
  {                                                                            \
    .driver_data = (void *)(_data), .vendor = (_vendor), .device = (_device),  \
    .kind = VERBS_MATCH_PCI,                                                   \
  }

#define VERBS_MODALIAS_MATCH(_mod_str, _data)                                  \
  {                                                                            \
    .driver_data = (void *)(_data), .u.modalias = (_mod_str),                  \
    .kind = VERBS_MATCH_MODALIAS,                                              \
  }

/* Matching on the IB device name is STRONGLY discouraged. This will only
 * match if there is no device/modalias file available, and it will eventually
 * be disabled entirely if the kernel supports renaming. Use is strongly
 * discouraged.
 */
#define VERBS_NAME_MATCH(_name_prefix, _data)                                  \
  {                                                                            \
    .driver_data = (_data), .u.modalias = "rdma_device:*N" _name_prefix "*",   \
    .kind = VERBS_MATCH_MODALIAS,                                              \
  }

enum {
  VSYSFS_READ_MODALIAS = 1 << 0,
  VSYSFS_READ_NODE_GUID = 1 << 1,
};

struct list_node {
  struct list_node *next;
  struct list_node *prev;
};

/* An rdma device detected in sysfs */
struct verbs_sysfs_dev {
  struct list_node entry;
  void *provider_data;
  const struct verbs_match_ent *match;
  unsigned int flags;
  char sysfs_name[IBV_SYSFS_NAME_MAX];
  dev_t sysfs_cdev;
  char ibdev_name[IBV_SYSFS_NAME_MAX];
  char ibdev_path[IBV_SYSFS_PATH_MAX];
  char modalias[512];
  uint64_t node_guid;
  uint32_t driver_id;
  enum ibv_node_type node_type;
  int ibdev_idx;
  uint32_t num_ports;
  uint32_t abi_ver;
  struct timespec time_created;
};

struct verbs_device {
  struct ibv_device device; /* Must be first */
  const struct verbs_device_ops *ops;
  int refcount;
  struct list_node entry;
  struct verbs_sysfs_dev *sysfs;
  uint64_t core_support;
};

static inline struct verbs_device *
verbs_get_device(const struct ibv_device *dev) {
  return container_of(dev, struct verbs_device, device);
}

#endif /* INFINIBAND_DRIVER_H */
