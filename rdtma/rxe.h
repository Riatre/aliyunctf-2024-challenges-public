/*
 * Copyright (c) 2009 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2009 System Fabric Works, Inc. All rights reserved.
 * Copyright (c) 2006-2007 QLogic Corp. All rights reserved.
 * Copyright (c) 2005. PathScale, Inc. All rights reserved.
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
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
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

#ifndef RXE_H
#define RXE_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <rdma/rdma_user_rxe.h>
#include "driver.h"

struct rxe_context {
	struct verbs_context	ibv_ctx;
};

/* common between cq and cq_ex */
struct rxe_cq {
	struct verbs_cq		vcq;
	struct mminfo		mmap_info;
	struct rxe_queue_buf	*queue;
	pthread_spinlock_t	lock;

	/* new API support */
	struct ib_uverbs_wc	*wc;
	size_t			wc_size;
	uint32_t		cur_index;
};

struct rxe_ah {
	struct ibv_ah		ibv_ah;
	struct rxe_av		av;
	int			ah_num;
};

struct rxe_wq {
	struct rxe_queue_buf	*queue;
	pthread_spinlock_t	lock;
	unsigned int		max_sge;
	unsigned int		max_inline;
};

struct rxe_qp {
	struct verbs_qp		vqp;
	struct mminfo		rq_mmap_info;
	struct rxe_wq		rq;
	struct mminfo		sq_mmap_info;
	struct rxe_wq		sq;

	/* new API support */
	uint32_t		cur_index;
	int			err;
};

struct rxe_srq {
	struct verbs_srq	vsrq;
	struct mminfo		mmap_info;
	struct rxe_wq		rq;
	uint32_t		srq_num;
};

#define to_rxxx(xxx, type) container_of(ib##xxx, struct rxe_##type, ibv_##xxx)

static inline struct rxe_context *to_rctx(struct ibv_context *ibctx)
{
	return container_of(ibctx, struct rxe_context, ibv_ctx.context);
}

static inline struct rxe_cq *to_rcq(struct ibv_cq *ibcq)
{
	return container_of(ibcq, struct rxe_cq, vcq.cq);
}

static inline struct rxe_qp *to_rqp(struct ibv_qp *ibqp)
{
	return container_of(ibqp, struct rxe_qp, vqp.qp);
}

static inline struct rxe_srq *to_rsrq(struct ibv_srq *ibsrq)
{
	return container_of(ibsrq, struct rxe_srq, vsrq.srq);
}

static inline struct rxe_ah *to_rah(struct ibv_ah *ibah)
{
	return to_rxxx(ah, ah);
}

static inline enum ibv_qp_type qp_type(struct rxe_qp *qp)
{
	return qp->vqp.qp.qp_type;
}

#endif /* RXE_H */
