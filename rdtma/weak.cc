#include <cstdint>
#include <infiniband/ib_user_ioctl_verbs.h>
#include <infiniband/verbs.h>
#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "driver.h"
#include "rdtm.h"

char g_flag[256];

void GlobalInit() {
  setvbuf(stdin, nullptr, _IONBF, 0);
  setvbuf(stdout, nullptr, _IONBF, 0);
  setvbuf(stderr, nullptr, _IONBF, 0);

  // Initialize the random number generator with seed from /dev/urandom.
  FILE *urandom = fopen("/dev/urandom", "r");
  if (!urandom) {
    perror("fopen");
    exit(1);
  }
  unsigned int seed;
  if (fread(&seed, sizeof(seed), 1, urandom) != 1) {
    perror("fread");
    exit(1);
  }
  fclose(urandom);
  srand(seed);
}

ibv_context *AcquireRXEContext() {
  ibv_device **dev = ibv_get_device_list(nullptr);
  if (dev == nullptr) {
    return nullptr;
  }

  ibv_context *ret = nullptr;
  for (int i = 0; dev[i]; i++) {
    auto *sysfs = verbs_get_device(dev[i])->sysfs;
    if (sysfs->driver_id == RDMA_DRIVER_RXE && sysfs->abi_ver == 2) {
      ret = ibv_open_device(dev[i]);
      break;
    }
  }
  ibv_free_device_list(dev);
  return ret;
}

std::pair<RDTM, RDTM> CreateConnectedRDTMPair(ibv_context *ctx) {
  RDTM master(ctx), slave(ctx, 16);
  uint32_t master_psn = rand() & 0xFFFFF;
  uint32_t slave_psn = rand() & 0xFFFFF;
  ibv_gid gid;
  memset(&gid, 0, sizeof(gid));
  CHECK_OK(ibv_query_gid(ctx, 1, 1, &gid));
  CHECK_OK(master.Setup(master_psn, slave.qp->qp_num, slave_psn, gid));
  CHECK_OK(slave.Setup(slave_psn, master.qp->qp_num, master_psn, gid));
  return {std::move(master), std::move(slave)};
}

struct WRBuilder {
  std::unique_ptr<FancyWR[]> wrs;
  ibv_sge dummy_sge;
  ibv_mr *qmr;
  size_t tail = 0;

  WRBuilder(uint64_t dummy_local_addr, uint32_t dummy_local_key, ibv_mr *qmr) {
    memset(&dummy_sge, 0, sizeof(dummy_sge));
    dummy_sge.addr = dummy_local_addr;
    dummy_sge.length = 8;
    dummy_sge.lkey = dummy_local_key;
    this->qmr = qmr;
  }

  void Resize(size_t new_size) {
    wrs = std::make_unique<FancyWR[]>(new_size);
    tail = 0;
  }

  template <FieldOffset FTO = FieldOffset::kNone>
  __attribute__((always_inline)) void Copy(uint64_t dest, uint32_t dkey,
                                           uint64_t src, uint32_t skey,
                                           uint32_t size) {
    FancyWR &ret = wrs[tail++];
    ret.wr.wr_id = tail;
    ret.wr.num_sge = 1;
    ret.wr.sg_list = &ret.sge;
    ret.sge.addr = src;
    ret.sge.length = size;
    ret.sge.lkey = skey;
    ret.wr.opcode = IBV_WR_RDMA_WRITE;
    ret.field_offset = FTO;
    if constexpr (FTO == FieldOffset::kNone) {
      ret.wr.wr.rdma.remote_addr = dest;
      ret.wr.wr.rdma.rkey = dkey;
    } else {
      ret.index = dest;
      ret.wr.wr.rdma.rkey = qmr->rkey;
    }
  }

  template <FieldOffset FTO = FieldOffset::kNone>
  __attribute__((always_inline)) void Add(uint64_t addr, uint64_t delta,
                                          uint32_t rkey = 0) {
    FancyWR &ret = wrs[tail++];
    ret.wr.wr_id = tail;
    ret.wr.num_sge = 1;
    ret.wr.sg_list = &dummy_sge;
    ret.wr.opcode = IBV_WR_ATOMIC_FETCH_AND_ADD;
    ret.wr.wr.atomic.compare_add = delta;
    ret.field_offset = FTO;
    if constexpr (FTO == FieldOffset::kNone) {
      ret.wr.wr.atomic.remote_addr = addr;
      ret.wr.wr.atomic.rkey = rkey;
    } else {
      ret.wr.wr.atomic.rkey = qmr->rkey;
      ret.index = addr;
    }
  }

  template <FieldOffset FTO = FieldOffset::kNone>
  __attribute__((always_inline)) void CAS(uintptr_t addr, uint64_t oldval,
                                          uint64_t newval, uint32_t rkey = 0) {
    FancyWR &ret = wrs[tail++];
    ret.wr.wr_id = tail;
    ret.wr.num_sge = 1;
    ret.wr.sg_list = &dummy_sge;
    ret.wr.opcode = IBV_WR_ATOMIC_CMP_AND_SWP;
    ret.wr.wr.atomic.compare_add = oldval;
    ret.wr.wr.atomic.swap = newval;
    ret.field_offset = FTO;
    if constexpr (FTO == FieldOffset::kNone) {
      ret.wr.wr.atomic.remote_addr = addr;
      ret.wr.wr.atomic.rkey = rkey;
    } else {
      ret.index = addr;
      ret.wr.wr.atomic.rkey = qmr->rkey;
    }
  }
  __attribute__((always_inline)) void Copy(void *dest, uint32_t dkey, void *src,
                                           uint32_t skey, uint32_t size) {
    Copy((uintptr_t)dest, dkey, (uintptr_t)src, skey, size);
  }
  __attribute__((always_inline)) void Add(void *addr, uint64_t delta,
                                          uint32_t rkey) {
    Add((uintptr_t)addr, delta, rkey);
  }
  __attribute__((always_inline)) void CAS(void *addr, uint64_t oldval,
                                          uint64_t newval, uint32_t rkey) {
    CAS((uintptr_t)addr, oldval, newval, rkey);
  }
};

void Magic(RDTM &master, RDTM &slave) {
  char dummy[8] = {0};
  char buf[256] = {0};
  auto *dummy_mr = master.RegisterMemoryRegion(dummy, sizeof(dummy));
  auto *buf_src = master.RegisterMemoryRegion(buf, sizeof(buf));
  auto *buf_dst = slave.RegisterMemoryRegion(buf, sizeof(buf));
  auto *flag_src = master.RegisterMemoryRegion(g_flag, sizeof(g_flag));
  auto *flag_dst = slave.RegisterMemoryRegion(g_flag, sizeof(g_flag));
  auto [sq_base, sq_size] = master.GetSendQueueBufferRange();
  auto *qmr = slave.RegisterMemoryRegion((void *)sq_base, sq_size);
  WRBuilder B((uint64_t)dummy, dummy_mr->lkey, qmr);
#define CAS B.CAS
#define Add B.Add
#define Copy B.Copy
#define OV FieldOffset::kAtomicCompareOldValue
#define NV FieldOffset::kAtomicCompareNewValue
#define DA FieldOffset::kDestAddress
#include "weak-magic.inl"
#undef CAS
#undef Add
#undef Copy
#undef OV
#undef NV
#undef DA
  master.ExecuteFancyWRs({B.wrs.get(), B.tail});
  CHECK_OK(ibv_dereg_mr(qmr));
  CHECK_OK(ibv_dereg_mr(flag_dst));
  CHECK_OK(ibv_dereg_mr(flag_src));
  CHECK_OK(ibv_dereg_mr(buf_dst));
  CHECK_OK(ibv_dereg_mr(buf_src));
  // fwrite(buf, 1, sizeof(buf), stdout);
}

int main(int argc, char *argv[]) {
  GlobalInit();

  ibv_context *ctx = AcquireRXEContext();
  if (!ctx) {
    fprintf(stderr, "Error: flag checker must run on genuine hardware "
                    "manufactured in 2032 AD.\n");
    return 1;
  }
  auto [master, slave] = CreateConnectedRDTMPair(ctx);

  printf("Input flag: ");
  scanf("%255s", g_flag);
  if (strlen(g_flag) == 0 || strncmp(g_flag, "aliyunctf{", 10) != 0 ||
      g_flag[strlen(g_flag) - 1] != '}') {
    puts("I appreciate your creativity, but the flag needs to be correct, not "
         "imaginative.");
    return 2;
  }
  Magic(master, slave);
  puts(g_flag);
  // fwrite(g_flag, 1, sizeof(g_flag), stdout);
  ibv_close_device(ctx);
  return 0;
}
