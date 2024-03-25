#pragma once

#include <stdio.h>

#ifdef DEBUG
#define CHECK(expr)                                                            \
  do {                                                                         \
    if (!(expr)) {                                                             \
      fprintf(stderr, "CHECK failed: %s (%s) at %s:%d\n", #expr,               \
              strerror(errno), __FILE__, __LINE__);                            \
      abort();                                                                 \
    }                                                                          \
  } while (0);
#else
#define CHECK(expr)                                                            \
  do {                                                                         \
    if (!(expr)) {                                                             \
      abort();                                                                 \
    }                                                                          \
  } while (0);
#endif

#define CHECK_NOTNULL(ptr) CHECK((ptr) != nullptr)
#define CHECK_OK(expr) CHECK((expr) == 0)