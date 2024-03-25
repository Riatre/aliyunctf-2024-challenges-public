#include <stdio.h>

__attribute__((section(".text."))) int main() {
  puts("incorrect flag :p");
  return 0;
}

asm(".section \".eh_frame.\",\"a\",@nobits\n"
    ".space 33554432-2048\n");
