#include <string.h>

#include "keccak256.h"

int main() {
  uint8_t *input = (uint8_t *)"Hello, World!";
  //printf(NULL);
  uint8_t *hash = compute_keccak256(input, strlen((char *)input));
  for (int i = 0; i < 32; i++) {
    printf("%02x", hash[i]);
  }
  printf("\n");
  free(hash);
  return 0;
}