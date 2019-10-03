#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include "sha256.h"

int main() {
  uint8_t data[3] = {0x61, 0x62, 0x63};

  uint32_t hash[8];
  memset(hash, 0, sizeof(uint32_t)*8);

  sha256_state s;

  sha256_init(&s);
  sha256_update(&s, data, 3);
  sha256_final(&s, hash);
  printf("\n");

  for(int i = 0; i < 8; i++)
		printf("%x ", hash[i]);
	printf("\n");
}
