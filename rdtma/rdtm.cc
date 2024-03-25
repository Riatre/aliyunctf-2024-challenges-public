#include "rdtm.h"

#include "common.h"
#include "rxe_queue.h"
#include <cstddef>
#include <cstdint>
#include <pthread.h>

namespace {

void ChangeRemoteAddressTo(ibv_send_wr &wr, uintptr_t new_addr) {
  switch (wr.opcode) {
  case IBV_WR_RDMA_WRITE:
  case IBV_WR_RDMA_WRITE_WITH_IMM:
  case IBV_WR_RDMA_READ:
    wr.wr.rdma.remote_addr = new_addr;
    break;
  case IBV_WR_ATOMIC_CMP_AND_SWP:
  case IBV_WR_ATOMIC_FETCH_AND_ADD:
    wr.wr.atomic.remote_addr = new_addr;
    break;
  default:
    CHECK(false && "Invalid opcode");
  }
}

void ConvertSendWR(struct rxe_qp *qp, struct rxe_send_wr *kwr,
                   struct ibv_send_wr *uwr) {
  struct ibv_mw *ibmw;
  struct ibv_mr *ibmr;

  memset(kwr, 0, sizeof(*kwr));

  kwr->wr_id = uwr->wr_id;
  kwr->opcode = uwr->opcode;
  kwr->send_flags = uwr->send_flags;
  kwr->ex.imm_data = uwr->imm_data;

  switch (uwr->opcode) {
  case IBV_WR_RDMA_WRITE:
  case IBV_WR_RDMA_WRITE_WITH_IMM:
  case IBV_WR_RDMA_READ:
    kwr->wr.rdma.remote_addr = uwr->wr.rdma.remote_addr;
    kwr->wr.rdma.rkey = uwr->wr.rdma.rkey;
    break;

  case IBV_WR_SEND:
  case IBV_WR_SEND_WITH_IMM:
    if (qp_type(qp) == IBV_QPT_UD) {
      struct rxe_ah *ah = to_rah(uwr->wr.ud.ah);

      kwr->wr.ud.remote_qpn = uwr->wr.ud.remote_qpn;
      kwr->wr.ud.remote_qkey = uwr->wr.ud.remote_qkey;
      kwr->wr.ud.ah_num = ah->ah_num;
    }
    break;

  case IBV_WR_ATOMIC_CMP_AND_SWP:
  case IBV_WR_ATOMIC_FETCH_AND_ADD:
    kwr->wr.atomic.remote_addr = uwr->wr.atomic.remote_addr;
    kwr->wr.atomic.compare_add = uwr->wr.atomic.compare_add;
    kwr->wr.atomic.swap = uwr->wr.atomic.swap;
    kwr->wr.atomic.rkey = uwr->wr.atomic.rkey;
    break;

  case IBV_WR_BIND_MW:
    ibmr = uwr->bind_mw.bind_info.mr;
    ibmw = uwr->bind_mw.mw;

    kwr->wr.mw.addr = uwr->bind_mw.bind_info.addr;
    kwr->wr.mw.length = uwr->bind_mw.bind_info.length;
    kwr->wr.mw.mr_lkey = ibmr->lkey;
    kwr->wr.mw.mw_rkey = ibmw->rkey;
    kwr->wr.mw.rkey = uwr->bind_mw.rkey;
    kwr->wr.mw.access = uwr->bind_mw.bind_info.mw_access_flags;
    break;

  default:
    break;
  }
}

int InitSendWQE(struct rxe_qp *qp, struct rxe_wq *sq, struct ibv_send_wr *ibwr,
                unsigned int length, struct rxe_send_wqe *wqe) {
  int num_sge = ibwr->num_sge;
  int i;
  unsigned int opcode = ibwr->opcode;

  ConvertSendWR(qp, &wqe->wr, ibwr);

  if (qp_type(qp) == IBV_QPT_UD) {
    struct rxe_ah *ah = to_rah(ibwr->wr.ud.ah);

    if (!ah->ah_num)
      /* old kernels only */
      memcpy(&wqe->wr.wr.ud.av, &ah->av, sizeof(struct rxe_av));
  }

  if (ibwr->send_flags & IBV_SEND_INLINE) {
    uint8_t *inline_data = wqe->dma.inline_data;

    for (i = 0; i < num_sge; i++) {
      memcpy(inline_data, (uint8_t *)(long)ibwr->sg_list[i].addr,
             ibwr->sg_list[i].length);
      inline_data += ibwr->sg_list[i].length;
    }
  } else
    memcpy(wqe->dma.sge, ibwr->sg_list, num_sge * sizeof(struct ibv_sge));

  if ((opcode == IBV_WR_ATOMIC_CMP_AND_SWP) ||
      (opcode == IBV_WR_ATOMIC_FETCH_AND_ADD))
    wqe->iova = ibwr->wr.atomic.remote_addr;
  else
    wqe->iova = ibwr->wr.rdma.remote_addr;

  wqe->dma.length = length;
  wqe->dma.resid = length;
  wqe->dma.num_sge = num_sge;
  wqe->dma.cur_sge = 0;
  wqe->dma.sge_offset = 0;
  wqe->state = 0;

  return 0;
}

/* send a null post send as a doorbell */
int SendDoorBell(struct ibv_qp *ibqp) {
  struct ibv_post_send {
    struct ib_uverbs_cmd_hdr hdr;
    struct ib_uverbs_post_send cmd;
  } cmd;
  struct ib_uverbs_post_send_resp resp;

  cmd.hdr.command = IB_USER_VERBS_CMD_POST_SEND;
  cmd.hdr.in_words = sizeof(cmd) / 4;
  cmd.hdr.out_words = sizeof(resp) / 4;
  cmd.cmd.response = (uintptr_t)&resp;
  cmd.cmd.qp_handle = ibqp->handle;
  cmd.cmd.wr_count = 0;
  cmd.cmd.sge_count = 0;
  cmd.cmd.wqe_size = sizeof(struct ibv_send_wr);

  if (write(ibqp->context->cmd_fd, &cmd, sizeof(cmd)) != sizeof(cmd))
    return errno;

  return 0;
}

} // namespace

constexpr int kAllowEverythingAccess =
    IBV_ACCESS_REMOTE_READ | IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE |
    IBV_ACCESS_REMOTE_ATOMIC | IBV_ACCESS_FLUSH_GLOBAL;

RDTM::RDTM(ibv_context *ctx, uint32_t max_send_wr, uint32_t max_recv_wr)
    : ctx(ctx) {
  CHECK_NOTNULL(ctx);
  pd = ibv_alloc_pd(ctx);
  CHECK_NOTNULL(pd);
  cq = ibv_create_cq(ctx, 10, nullptr, nullptr, 0);
  CHECK_NOTNULL(cq);
  qp = CreateQueuePair(pd, cq, max_send_wr, max_recv_wr);
  CHECK_NOTNULL(qp);
}

RDTM::~RDTM() {
  if (qp)
    ibv_destroy_qp(qp);
  if (cq)
    ibv_destroy_cq(cq);
  if (pd)
    ibv_dealloc_pd(pd);
}

ibv_qp *RDTM::CreateQueuePair(struct ibv_pd *pd, struct ibv_cq *cq,
                              uint32_t max_send_wr, uint32_t max_recv_wr) {
  struct ibv_qp_init_attr qp_init_attr;
  memset(&qp_init_attr, 0, sizeof(qp_init_attr));
  qp_init_attr.send_cq = cq;
  qp_init_attr.recv_cq = cq;
  qp_init_attr.qp_type = IBV_QPT_RC;
  qp_init_attr.cap.max_send_wr = 1024;
  qp_init_attr.cap.max_recv_wr = 16;
  qp_init_attr.cap.max_send_sge = 1;
  qp_init_attr.cap.max_recv_sge = 1;
  qp_init_attr.sq_sig_all = 0;
  return ibv_create_qp(pd, &qp_init_attr);
}

ibv_mr *RDTM::RegisterMemoryRegion(void *addr, size_t length) {
  return ibv_reg_mr(pd, addr, length, kAllowEverythingAccess);
}

int RDTM::Setup(uint32_t src_psn, uint32_t dest_qp_num, uint32_t dest_psn,
                const ibv_gid &gid) {
  struct ibv_qp_attr init_attr = {
      .qp_state = IBV_QPS_INIT,
      .qp_access_flags = kAllowEverythingAccess,
      .pkey_index = 0,
      .port_num = 1,
  };
  int ret = ibv_modify_qp(qp, &init_attr,
                          IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT |
                              IBV_QP_ACCESS_FLAGS);
  if (ret != 0) {
    return ret;
  }
  struct ibv_qp_attr attr = {
      .qp_state = IBV_QPS_RTR,
      .path_mtu = IBV_MTU_1024,
      .rq_psn = dest_psn,
      .dest_qp_num = dest_qp_num,
      .ah_attr =
          {
              .grh =
                  {
                      .dgid = gid,
                      .sgid_index = 1,
                      .hop_limit = 1,
                  },
              .dlid = 0,
              .sl = 0,
              .src_path_bits = 0,
              .is_global = 1,
              .port_num = 1,
          },
      .max_dest_rd_atomic = 128,
      .min_rnr_timer = 0,
  };

  ret = ibv_modify_qp(qp, &attr,
                      IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU |
                          IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
                          IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER);
  if (ret != 0) {
    return ret;
  }

  attr.qp_state = IBV_QPS_RTS;
  attr.timeout = 14;
  attr.retry_cnt = 7;
  attr.rnr_retry = 7;
  attr.sq_psn = src_psn;
  attr.max_rd_atomic = 128;
  ret = ibv_modify_qp(qp, &attr,
                      IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
                          IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN |
                          IBV_QP_MAX_QP_RD_ATOMIC);
  return ret;
}

std::pair<uintptr_t, uintptr_t> RDTM::GetSendQueueBufferRange() const {
  auto *rqp = to_rqp(qp);
  return {reinterpret_cast<uintptr_t>(rqp->sq.queue), rqp->sq_mmap_info.size};
}

void RDTM::ExecuteFancyWRs(std::span<FancyWR> fancy_wrs) {
  auto *rqp = to_rqp(qp);
  CHECK(fancy_wrs.size() <= rqp->sq.queue->index_mask);
  uint32_t index_mask = rqp->sq.queue->index_mask;
  pthread_spin_lock(&rqp->sq.lock);
  while (!queue_empty(rqp->sq.queue)) {
    // Wait for the queue to be drained by kernel.
  }
  uint32_t tail = load_producer_index(rqp->sq.queue);
  for (size_t i = 0; i < fancy_wrs.size(); i++) {
    auto *wqe =
        static_cast<rxe_send_wqe *>(addr_from_index(rqp->sq.queue, tail + i));
    ibv_send_wr ibwr = fancy_wrs[i].wr;
    uint32_t field_offset =
        static_cast<uint32_t>(fancy_wrs[i].field_offset);
    if (field_offset) {
      auto target_address = reinterpret_cast<uintptr_t>(addr_from_index(
          rqp->sq.queue, tail + fancy_wrs[i].index));
      ChangeRemoteAddressTo(ibwr, target_address + field_offset);
    }
    uint32_t length = 0;
    for (int j = 0; j < fancy_wrs[i].wr.num_sge; j++) {
      length += fancy_wrs[i].wr.sg_list[j].length;
    }
    ibwr.send_flags |= IBV_SEND_FENCE;
    if (i == fancy_wrs.size() - 1) {
      ibwr.send_flags |= IBV_SEND_SIGNALED;
    }
    CHECK_OK(InitSendWQE(rqp, &rqp->sq, &ibwr, length, wqe));
  }
  // for (size_t i = 0; i < fancy_wrs.size(); i++) {
  //   advance_producer(rqp->sq.queue);
  //   CHECK_OK(SendDoorBell(qp));
  //   ibv_wc wc;
  //   ibv_poll_cq(cq, 1, &wc);
  //   fprintf(stderr, "Completion status: %s\n", ibv_wc_status_str(wc.status));
  //   CHECK(wc.status == IBV_WC_SUCCESS);
  // }
  pthread_spin_unlock(&rqp->sq.lock);
  store_producer_index(rqp->sq.queue, (tail + fancy_wrs.size()) & index_mask);
  pthread_spin_unlock(&rqp->sq.lock);
  CHECK_OK(SendDoorBell(qp));
  ibv_wc wc;
  // CHECK(ibv_poll_cq(cq, 1, &wc) == 1);
  ibv_poll_cq(cq, 1, &wc);
  // printf("Completion status: %s\n", ibv_wc_status_str(wc.status));
  CHECK(wc.status == IBV_WC_SUCCESS);
}
