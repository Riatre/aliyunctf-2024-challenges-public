#pragma once

#include "rxe.h"
#include "rxe_queue.h"
#include <infiniband/verbs.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/rdma_user_rxe.h>
#include <span>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum class FieldOffset : uint32_t {
  kNone = 0,
  kAtomicCompareOldValue = offsetof(rxe_send_wqe, wr.wr.atomic.compare_add),
  kAtomicCompareNewValue = offsetof(rxe_send_wqe, wr.wr.atomic.swap),
  kFetchAddImm = kAtomicCompareOldValue,
  kDestAddress = offsetof(rxe_send_wqe, iova),
};

struct FancyWR {
  ibv_send_wr wr;
  FieldOffset field_offset = FieldOffset::kNone;
  uint32_t index;
  ibv_sge sge;

  FancyWR() { memset(&wr, 0, sizeof(wr)); }
};

struct RDTM {
  ibv_context *ctx;
  ibv_qp *qp;
  ibv_pd *pd;
  ibv_cq *cq;

  // Borrows the context. It has to outlive the RDTM object.
  RDTM(ibv_context *ctx, uint32_t max_send_wr = 1024,
       uint32_t max_recv_wr = 16);
  ~RDTM();
  // Move-only.
  RDTM(const RDTM &) = delete;
  RDTM &operator=(const RDTM &) = delete;
  RDTM(RDTM &&r) {
    ctx = r.ctx;
    qp = r.qp;
    pd = r.pd;
    cq = r.cq;
    r.ctx = nullptr;
    r.qp = nullptr;
    r.pd = nullptr;
    r.cq = nullptr;
  }
  RDTM &operator=(RDTM &&r) {
    ctx = r.ctx;
    qp = r.qp;
    pd = r.pd;
    cq = r.cq;
    r.ctx = nullptr;
    r.qp = nullptr;
    r.pd = nullptr;
    r.cq = nullptr;
    return *this;
  }

  ibv_mr *RegisterMemoryRegion(void *addr, size_t length);
  int Setup(uint32_t src_psn, uint32_t dest_qp_num, uint32_t dest_psn,
            const ibv_gid &gid);
  // Synchonous.
  void ExecuteFancyWRs(std::span<FancyWR> fancy_wrs);
  std::pair<uintptr_t, uintptr_t> GetSendQueueBufferRange() const;

private:
  ibv_qp *CreateQueuePair(struct ibv_pd *pd, struct ibv_cq *cq,
                          uint32_t max_send_wr = 1024,
                          uint32_t max_recv_wr = 16);
};
