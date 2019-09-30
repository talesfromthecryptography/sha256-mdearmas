#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include "sha256.h"

int main() {
  uint8_t data[17] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0x23, 0x45, 0x67, 0x89, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5};

  uint32_t hash[8];
  memset(hash, 0, sizeof(uint32_t)*8);

  sha256_state s;

  sha256_init(&s);
  sha256_update(&s, data, 17);
  buffer_print(&s);
  sha256_final(&s, hash);
  buffer_print(&s);
}
