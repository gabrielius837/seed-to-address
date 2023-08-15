#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define MAX_RATE 168
#define RATE 136
#define A_LENGTH 25
#define WORD 64

typedef enum : uint32_t {
  spongeAbsorbing = 0,
  spongeSqueezing = 1
} spongeDirection;

struct keccak256_ctx {
  uint64_t a[A_LENGTH];
  uint8_t *buf;
  int bufLen;
  int rate;
  uint8_t dsbyte;
  uint64_t storage[MAX_RATE / 8];
  int outputLen;
  spongeDirection state;
};

struct keccak256_ctx *init_keccak256();
void write_keccak256(struct keccak256_ctx *ctx, uint8_t *input, int length);
void sum_keccak256(struct keccak256_ctx *ctx, uint8_t *hash);

uint8_t *compute_keccak256(uint8_t *input, int length);