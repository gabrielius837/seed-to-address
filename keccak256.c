#include "keccak256.h"
#include <stdlib.h>

// print
/*
void printCtx(char *comment, struct keccak257_ctx *ctx) {
  printf("%s\n", comment);
  printf("--- ctx\n");

  printf("a >\n");
  for (int i = 0; i < A_LENGTH; i++) {
    printf("%lu\n", ctx->a[i]);
  }

  printf("bufLen: %d\n", ctx->bufLen);
  if (ctx->bufLen > 0) {
    printf("buf: ");
    for (int i = 0; i < ctx->bufLen; i++) {
      printf("%02x", ctx->buf[i]);
    }
    printf("\n");
  }

  printf("rate: %d\n", ctx->rate);
  printf("dsbyte: %u\n", ctx->dsbyte);

  printf("storage >\n");
  for (int i = 0; i < MAX_RATE / 8; i++) {
    printf("%lu\n", ctx->storage[i]);
  }

  printf("outputLen: %d\n", ctx->outputLen);

  printf("state: %u\n", ctx->state);
  printf("---\n");
}
*/

// init
struct keccak256_ctx *init_keccak256() {
  struct keccak256_ctx *ctx = malloc(sizeof(struct keccak256_ctx));

  for (int i = 0; i < A_LENGTH; i++)
    ctx->a[i] = 0;

  ctx->buf = NULL;
  ctx->bufLen = 0;
  ctx->rate = RATE;
  ctx->dsbyte = 0x01;

  for (int i = 0; i < MAX_RATE / 8; i++)
    ctx->storage[i] = 0;

  ctx->outputLen = 32;
  ctx->state = spongeAbsorbing;

  //printCtx("return init_keccak256 output", ctx);
  return ctx;
}

void xorIn(struct keccak256_ctx *ctx, uint8_t *input, int length) {
  uint64_t *bw = (uint64_t *)input;
  if (length >= 72) {
    ctx->a[0] ^= bw[0];
    ctx->a[1] ^= bw[1];
    ctx->a[2] ^= bw[2];
    ctx->a[3] ^= bw[3];
    ctx->a[4] ^= bw[4];
    ctx->a[5] ^= bw[5];
    ctx->a[6] ^= bw[6];
    ctx->a[7] ^= bw[7];
    ctx->a[8] ^= bw[8];
  }
  if (length >= 104) {
    ctx->a[9] ^= bw[9];
    ctx->a[10] ^= bw[10];
    ctx->a[11] ^= bw[11];
    ctx->a[12] ^= bw[12];
  }
  if (length >= 136) {
    ctx->a[13] ^= bw[13];
    ctx->a[14] ^= bw[14];
    ctx->a[15] ^= bw[15];
    ctx->a[16] ^= bw[16];
  }
  if (length >= 144) {
    ctx->a[17] ^= bw[17];
  }
  if (length >= 168) {
    ctx->a[18] ^= bw[18];
    ctx->a[19] ^= bw[19];
    ctx->a[20] ^= bw[20];
  }
}

uint64_t rotateLeft64(uint64_t x, int k) {
  uint64_t s = (uint32_t)k & (WORD - 1);
  return x << s | x >> (WORD - s);
}

// rc stores the round constants for use in the ι step.
static const uint64_t rc[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

// assumption: size is 8 * 25
void keccakF1600(struct keccak256_ctx *ctx) {
  uint64_t *a = &(ctx->a[0]);
  // Implementation translated from Keccak-inplace.c
  // in the keccak reference code.
  uint64_t t, bc0, bc1, bc2, bc3, bc4, d0, d1, d2, d3, d4 = 0;

  for (int i = 0; i < 24; i += 4) {
    // Combines the 5 steps in each round into 2 steps.
    // Unrolls 4 rounds per loop and spreads some steps across rounds.

    // Round 1
    bc0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
    bc1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
    bc2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
    bc3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
    bc4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
    d0 = bc4 ^ (bc1 << 1 | bc1 >> 63);
    d1 = bc0 ^ (bc2 << 1 | bc2 >> 63);
    d2 = bc1 ^ (bc3 << 1 | bc3 >> 63);
    d3 = bc2 ^ (bc4 << 1 | bc4 >> 63);
    d4 = bc3 ^ (bc0 << 1 | bc0 >> 63);

    bc0 = a[0] ^ d0;
    t = a[6] ^ d1;
    bc1 = rotateLeft64(t, 44);
    t = a[12] ^ d2;
    bc2 = rotateLeft64(t, 43);
    t = a[18] ^ d3;
    bc3 = rotateLeft64(t, 21);
    t = a[24] ^ d4;
    bc4 = rotateLeft64(t, 14);
    a[0] = bc0 ^ (bc2 & (~bc1)) ^ rc[i];
    a[6] = bc1 ^ (bc3 & (~bc2));
    a[12] = bc2 ^ (bc4 & (~bc3));
    a[18] = bc3 ^ (bc0 & (~bc4));
    a[24] = bc4 ^ (bc1 & (~bc0));

    t = a[10] ^ d0;
    bc2 = rotateLeft64(t, 3);
    t = a[16] ^ d1;
    bc3 = rotateLeft64(t, 45);
    t = a[22] ^ d2;
    bc4 = rotateLeft64(t, 61);
    t = a[3] ^ d3;
    bc0 = rotateLeft64(t, 28);
    t = a[9] ^ d4;
    bc1 = rotateLeft64(t, 20);
    a[10] = bc0 ^ (bc2 & (~bc1));
    a[16] = bc1 ^ (bc3 & (~bc2));
    a[22] = bc2 ^ (bc4 & (~bc3));
    a[3] = bc3 ^ (bc0 & (~bc4));
    a[9] = bc4 ^ (bc1 & (~bc0));

    t = a[20] ^ d0;
    bc4 = rotateLeft64(t, 18);
    t = a[1] ^ d1;
    bc0 = rotateLeft64(t, 1);
    t = a[7] ^ d2;
    bc1 = rotateLeft64(t, 6);
    t = a[13] ^ d3;
    bc2 = rotateLeft64(t, 25);
    t = a[19] ^ d4;
    bc3 = rotateLeft64(t, 8);
    a[20] = bc0 ^ (bc2 & (~bc1));
    a[1] = bc1 ^ (bc3 & (~bc2));
    a[7] = bc2 ^ (bc4 & (~bc3));
    a[13] = bc3 ^ (bc0 & (~bc4));
    a[19] = bc4 ^ (bc1 & (~bc0));

    t = a[5] ^ d0;
    bc1 = rotateLeft64(t, 36);
    t = a[11] ^ d1;
    bc2 = rotateLeft64(t, 10);
    t = a[17] ^ d2;
    bc3 = rotateLeft64(t, 15);
    t = a[23] ^ d3;
    bc4 = rotateLeft64(t, 56);
    t = a[4] ^ d4;
    bc0 = rotateLeft64(t, 27);
    a[5] = bc0 ^ (bc2 & (~bc1));
    a[11] = bc1 ^ (bc3 & (~bc2));
    a[17] = bc2 ^ (bc4 & (~bc3));
    a[23] = bc3 ^ (bc0 & (~bc4));
    a[4] = bc4 ^ (bc1 & (~bc0));

    t = a[15] ^ d0;
    bc3 = rotateLeft64(t, 41);
    t = a[21] ^ d1;
    bc4 = rotateLeft64(t, 2);
    t = a[2] ^ d2;
    bc0 = rotateLeft64(t, 62);
    t = a[8] ^ d3;
    bc1 = rotateLeft64(t, 55);
    t = a[14] ^ d4;
    bc2 = rotateLeft64(t, 39);
    a[15] = bc0 ^ (bc2 & (~bc1));
    a[21] = bc1 ^ (bc3 & (~bc2));
    a[2] = bc2 ^ (bc4 & (~bc3));
    a[8] = bc3 ^ (bc0 & (~bc4));
    a[14] = bc4 ^ (bc1 & (~bc0));

    // Round 2
    bc0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
    bc1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
    bc2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
    bc3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
    bc4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
    d0 = bc4 ^ (bc1 << 1 | bc1 >> 63);
    d1 = bc0 ^ (bc2 << 1 | bc2 >> 63);
    d2 = bc1 ^ (bc3 << 1 | bc3 >> 63);
    d3 = bc2 ^ (bc4 << 1 | bc4 >> 63);
    d4 = bc3 ^ (bc0 << 1 | bc0 >> 63);

    bc0 = a[0] ^ d0;
    t = a[16] ^ d1;
    bc1 = rotateLeft64(t, 44);
    t = a[7] ^ d2;
    bc2 = rotateLeft64(t, 43);
    t = a[23] ^ d3;
    bc3 = rotateLeft64(t, 21);
    t = a[14] ^ d4;
    bc4 = rotateLeft64(t, 14);
    a[0] = bc0 ^ (bc2 & (~bc1)) ^ rc[i + 1];
    a[16] = bc1 ^ (bc3 & (~bc2));
    a[7] = bc2 ^ (bc4 & (~bc3));
    a[23] = bc3 ^ (bc0 & (~bc4));
    a[14] = bc4 ^ (bc1 & (~bc0));

    t = a[20] ^ d0;
    bc2 = rotateLeft64(t, 3);
    t = a[11] ^ d1;
    bc3 = rotateLeft64(t, 45);
    t = a[2] ^ d2;
    bc4 = rotateLeft64(t, 61);
    t = a[18] ^ d3;
    bc0 = rotateLeft64(t, 28);
    t = a[9] ^ d4;
    bc1 = rotateLeft64(t, 20);
    a[20] = bc0 ^ (bc2 & (~bc1));
    a[11] = bc1 ^ (bc3 & (~bc2));
    a[2] = bc2 ^ (bc4 & (~bc3));
    a[18] = bc3 ^ (bc0 & (~bc4));
    a[9] = bc4 ^ (bc1 & (~bc0));

    t = a[15] ^ d0;
    bc4 = rotateLeft64(t, 18);
    t = a[6] ^ d1;
    bc0 = rotateLeft64(t, 1);
    t = a[22] ^ d2;
    bc1 = rotateLeft64(t, 6);
    t = a[13] ^ d3;
    bc2 = rotateLeft64(t, 25);
    t = a[4] ^ d4;
    bc3 = rotateLeft64(t, 8);
    a[15] = bc0 ^ (bc2 & (~bc1));
    a[6] = bc1 ^ (bc3 & (~bc2));
    a[22] = bc2 ^ (bc4 & (~bc3));
    a[13] = bc3 ^ (bc0 & (~bc4));
    a[4] = bc4 ^ (bc1 & (~bc0));

    t = a[10] ^ d0;
    bc1 = rotateLeft64(t, 36);
    t = a[1] ^ d1;
    bc2 = rotateLeft64(t, 10);
    t = a[17] ^ d2;
    bc3 = rotateLeft64(t, 15);
    t = a[8] ^ d3;
    bc4 = rotateLeft64(t, 56);
    t = a[24] ^ d4;
    bc0 = rotateLeft64(t, 27);
    a[10] = bc0 ^ (bc2 & (~bc1));
    a[1] = bc1 ^ (bc3 & (~bc2));
    a[17] = bc2 ^ (bc4 & (~bc3));
    a[8] = bc3 ^ (bc0 & (~bc4));
    a[24] = bc4 ^ (bc1 & (~bc0));

    t = a[5] ^ d0;
    bc3 = rotateLeft64(t, 41);
    t = a[21] ^ d1;
    bc4 = rotateLeft64(t, 2);
    t = a[12] ^ d2;
    bc0 = rotateLeft64(t, 62);
    t = a[3] ^ d3;
    bc1 = rotateLeft64(t, 55);
    t = a[19] ^ d4;
    bc2 = rotateLeft64(t, 39);
    a[5] = bc0 ^ (bc2 & (~bc1));
    a[21] = bc1 ^ (bc3 & (~bc2));
    a[12] = bc2 ^ (bc4 & (~bc3));
    a[3] = bc3 ^ (bc0 & (~bc4));
    a[19] = bc4 ^ (bc1 & (~bc0));

    // Round 3
    bc0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
    bc1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
    bc2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
    bc3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
    bc4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
    d0 = bc4 ^ (bc1 << 1 | bc1 >> 63);
    d1 = bc0 ^ (bc2 << 1 | bc2 >> 63);
    d2 = bc1 ^ (bc3 << 1 | bc3 >> 63);
    d3 = bc2 ^ (bc4 << 1 | bc4 >> 63);
    d4 = bc3 ^ (bc0 << 1 | bc0 >> 63);

    bc0 = a[0] ^ d0;
    t = a[11] ^ d1;
    bc1 = rotateLeft64(t, 44);
    t = a[22] ^ d2;
    bc2 = rotateLeft64(t, 43);
    t = a[8] ^ d3;
    bc3 = rotateLeft64(t, 21);
    t = a[19] ^ d4;
    bc4 = rotateLeft64(t, 14);
    a[0] = bc0 ^ (bc2 & (~bc1)) ^ rc[i + 2];
    a[11] = bc1 ^ (bc3 & (~bc2));
    a[22] = bc2 ^ (bc4 & (~bc3));
    a[8] = bc3 ^ (bc0 & (~bc4));
    a[19] = bc4 ^ (bc1 & (~bc0));

    t = a[15] ^ d0;
    bc2 = rotateLeft64(t, 3);
    t = a[1] ^ d1;
    bc3 = rotateLeft64(t, 45);
    t = a[12] ^ d2;
    bc4 = rotateLeft64(t, 61);
    t = a[23] ^ d3;
    bc0 = rotateLeft64(t, 28);
    t = a[9] ^ d4;
    bc1 = rotateLeft64(t, 20);
    a[15] = bc0 ^ (bc2 & (~bc1));
    a[1] = bc1 ^ (bc3 & (~bc2));
    a[12] = bc2 ^ (bc4 & (~bc3));
    a[23] = bc3 ^ (bc0 & (~bc4));
    a[9] = bc4 ^ (bc1 & (~bc0));

    t = a[5] ^ d0;
    bc4 = rotateLeft64(t, 18);
    t = a[16] ^ d1;
    bc0 = rotateLeft64(t, 1);
    t = a[2] ^ d2;
    bc1 = rotateLeft64(t, 6);
    t = a[13] ^ d3;
    bc2 = rotateLeft64(t, 25);
    t = a[24] ^ d4;
    bc3 = rotateLeft64(t, 8);
    a[5] = bc0 ^ (bc2 & (~bc1));
    a[16] = bc1 ^ (bc3 & (~bc2));
    a[2] = bc2 ^ (bc4 & (~bc3));
    a[13] = bc3 ^ (bc0 & (~bc4));
    a[24] = bc4 ^ (bc1 & (~bc0));

    t = a[20] ^ d0;
    bc1 = rotateLeft64(t, 36);
    t = a[6] ^ d1;
    bc2 = rotateLeft64(t, 10);
    t = a[17] ^ d2;
    bc3 = rotateLeft64(t, 15);
    t = a[3] ^ d3;
    bc4 = rotateLeft64(t, 56);
    t = a[14] ^ d4;
    bc0 = rotateLeft64(t, 27);
    a[20] = bc0 ^ (bc2 & (~bc1));
    a[6] = bc1 ^ (bc3 & (~bc2));
    a[17] = bc2 ^ (bc4 & (~bc3));
    a[3] = bc3 ^ (bc0 & (~bc4));
    a[14] = bc4 ^ (bc1 & (~bc0));

    t = a[10] ^ d0;
    bc3 = rotateLeft64(t, 41);
    t = a[21] ^ d1;
    bc4 = rotateLeft64(t, 2);
    t = a[7] ^ d2;
    bc0 = rotateLeft64(t, 62);
    t = a[18] ^ d3;
    bc1 = rotateLeft64(t, 55);
    t = a[4] ^ d4;
    bc2 = rotateLeft64(t, 39);
    a[10] = bc0 ^ (bc2 & (~bc1));
    a[21] = bc1 ^ (bc3 & (~bc2));
    a[7] = bc2 ^ (bc4 & (~bc3));
    a[18] = bc3 ^ (bc0 & (~bc4));
    a[4] = bc4 ^ (bc1 & (~bc0));

    // Round 4
    bc0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
    bc1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
    bc2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
    bc3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
    bc4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
    d0 = bc4 ^ (bc1 << 1 | bc1 >> 63);
    d1 = bc0 ^ (bc2 << 1 | bc2 >> 63);
    d2 = bc1 ^ (bc3 << 1 | bc3 >> 63);
    d3 = bc2 ^ (bc4 << 1 | bc4 >> 63);
    d4 = bc3 ^ (bc0 << 1 | bc0 >> 63);

    bc0 = a[0] ^ d0;
    t = a[1] ^ d1;
    bc1 = rotateLeft64(t, 44);
    t = a[2] ^ d2;
    bc2 = rotateLeft64(t, 43);
    t = a[3] ^ d3;
    bc3 = rotateLeft64(t, 21);
    t = a[4] ^ d4;
    bc4 = rotateLeft64(t, 14);
    a[0] = bc0 ^ (bc2 & (~bc1)) ^ rc[i + 3];
    a[1] = bc1 ^ (bc3 & (~bc2));
    a[2] = bc2 ^ (bc4 & (~bc3));
    a[3] = bc3 ^ (bc0 & (~bc4));
    a[4] = bc4 ^ (bc1 & (~bc0));

    t = a[5] ^ d0;
    bc2 = rotateLeft64(t, 3);
    t = a[6] ^ d1;
    bc3 = rotateLeft64(t, 45);
    t = a[7] ^ d2;
    bc4 = rotateLeft64(t, 61);
    t = a[8] ^ d3;
    bc0 = rotateLeft64(t, 28);
    t = a[9] ^ d4;
    bc1 = rotateLeft64(t, 20);
    a[5] = bc0 ^ (bc2 & (~bc1));
    a[6] = bc1 ^ (bc3 & (~bc2));
    a[7] = bc2 ^ (bc4 & (~bc3));
    a[8] = bc3 ^ (bc0 & (~bc4));
    a[9] = bc4 ^ (bc1 & (~bc0));

    t = a[10] ^ d0;
    bc4 = rotateLeft64(t, 18);
    t = a[11] ^ d1;
    bc0 = rotateLeft64(t, 1);
    t = a[12] ^ d2;
    bc1 = rotateLeft64(t, 6);
    t = a[13] ^ d3;
    bc2 = rotateLeft64(t, 25);
    t = a[14] ^ d4;
    bc3 = rotateLeft64(t, 8);
    a[10] = bc0 ^ (bc2 & (~bc1));
    a[11] = bc1 ^ (bc3 & (~bc2));
    a[12] = bc2 ^ (bc4 & (~bc3));
    a[13] = bc3 ^ (bc0 & (~bc4));
    a[14] = bc4 ^ (bc1 & (~bc0));

    t = a[15] ^ d0;
    bc1 = rotateLeft64(t, 36);
    t = a[16] ^ d1;
    bc2 = rotateLeft64(t, 10);
    t = a[17] ^ d2;
    bc3 = rotateLeft64(t, 15);
    t = a[18] ^ d3;
    bc4 = rotateLeft64(t, 56);
    t = a[19] ^ d4;
    bc0 = rotateLeft64(t, 27);
    a[15] = bc0 ^ (bc2 & (~bc1));
    a[16] = bc1 ^ (bc3 & (~bc2));
    a[17] = bc2 ^ (bc4 & (~bc3));
    a[18] = bc3 ^ (bc0 & (~bc4));
    a[19] = bc4 ^ (bc1 & (~bc0));

    t = a[20] ^ d0;
    bc3 = rotateLeft64(t, 41);
    t = a[21] ^ d1;
    bc4 = rotateLeft64(t, 2);
    t = a[22] ^ d2;
    bc0 = rotateLeft64(t, 62);
    t = a[23] ^ d3;
    bc1 = rotateLeft64(t, 55);
    t = a[24] ^ d4;
    bc2 = rotateLeft64(t, 39);
    a[20] = bc0 ^ (bc2 & (~bc1));
    a[21] = bc1 ^ (bc3 & (~bc2));
    a[22] = bc2 ^ (bc4 & (~bc3));
    a[23] = bc3 ^ (bc0 & (~bc4));
    a[24] = bc4 ^ (bc1 & (~bc0));
  }
}

void copyOut(struct keccak256_ctx *ctx) {
  uint8_t *a = (uint8_t *)&(ctx->a[0]);
  for (int i = 0; i < MAX_RATE; i++)
    ctx->buf[i] = a[i];
  ctx->bufLen = MAX_RATE;
}

void permute(struct keccak256_ctx *ctx) {
  switch (ctx->state) {
  case spongeAbsorbing:
    xorIn(ctx, ctx->buf, ctx->bufLen);
    //printCtx("xorIn spongeAbsorbing branch in permute", ctx);
    ctx->buf = (uint8_t *)&(ctx->storage[0]);
    ctx->bufLen = 0;
    keccakF1600(ctx);
    //printCtx("keccakF1600 spongeAbsorbing branch in permute", ctx);
    break;
  case spongeSqueezing:
    keccakF1600(ctx);
    //printCtx("keccakF1600 spongeSqueezing branch in permute", ctx);
    ctx->buf = (uint8_t *)&(ctx->storage[0]);
    ctx->bufLen = ctx->rate;
    copyOut(ctx);
    //printCtx("copyOut spongeSqueezing branch in permute", ctx);
    break;
  }
}

// write
void write_keccak256(struct keccak256_ctx *ctx, uint8_t *input, int length) {
  /* I guess useless
  if (ctx->state != spongeAbsorbing)
    return WRONG_SPONGE_DIRECTION;
  */

  if (ctx->buf == NULL) {
    ctx->buf = (uint8_t *)&(ctx->storage[0]);
    ctx->bufLen = 0;
    //printf("ctx->buf was null\n");
  }

  //printf("while (length > 0)\n");
  while (length > 0) {
    //printf("%d > 0\n", length);
    if (ctx->bufLen == 0 && length >= ctx->rate) {
      //printf("if case todo: more definition\n");
      xorIn(ctx, input, ctx->rate);
      //printCtx("xorIn", ctx);
      input += ctx->rate;
      length -= ctx->rate;
      keccakF1600(ctx);
      //printCtx("keccakF1600", ctx);
    } else {
      //printf("else case todo: more definition\n");
      int todo = ctx->rate - ctx->bufLen;
      if (todo > length) {
        todo = length;
      }

      for (int i = 0; i < todo; i++) {
        ctx->buf[ctx->bufLen + i] = input[i];
      }
      ctx->bufLen += todo;
      input += todo;
      length -= todo;
      //printCtx("input appended to ctx->buf", ctx);

      if (ctx->bufLen == ctx->rate) {
        permute(ctx);
        //printCtx("permute due to len(ctx.buf) == ctx.rate", ctx);
      }
    }
  }
}

// sum

// pads appends the domain separation bits in dsbyte, applies
// the multi-bitrate 10..1 padding rule, and permutes the state.
void padAndPermute(struct keccak256_ctx *ctx) {
  if (ctx->buf == NULL) {
    ctx->buf = (uint8_t *)&(ctx->storage[0]);
    ctx->bufLen = 0;
  }

  // Pad with this instance's domain-separator bits. We know that there's
  // at least one byte of space in d.buf because, if it were full,
  // permute would have been called to empty it. dsbyte also contains the
  // first one bit for the padding. See the comment in the state struct.
  ctx->buf[ctx->bufLen] = ctx->dsbyte;
  ctx->bufLen++;
  int start = ctx->bufLen;

  // is it necessary??
  ctx->buf = (uint8_t *)&(ctx->storage[0]);
  ctx->bufLen = ctx->rate;
  for (int i = start; i < ctx->rate; i++) {
    ctx->buf[i] = 0;
  }

  // This adds the final one bit for the padding. Because of the way that
  // bits are numbered from the LSB upwards, the final bit is the MSB of
  // the last byte.
  ctx->buf[ctx->rate - 1] ^= 0x80;
  /*
    fine
  */
  // Apply the permutation
  /*
    content of ctx is not matching after permute as in go
  */
  permute(ctx);
  //printCtx("permute in padAndPermute", ctx);
  ctx->state = spongeSqueezing;
  // is it necessary??
  ctx->buf = (uint8_t *)&(ctx->storage[0]);
  ctx->bufLen = ctx->rate;
  copyOut(ctx);
}

void sum_keccak256(struct keccak256_ctx *ctx, uint8_t *hash) {
  //printf("sum_keccak256()\n");
  int n = ctx->outputLen;
  // If we're still absorbing, pad and apply the permutation.
  if (ctx->state == spongeAbsorbing) {
    padAndPermute(ctx);
    //printCtx("ctx->state == spongeAbsorbing", ctx);
  }

  // Now, do the squeezing.
  while (n > 0) {
    int copyLen = (n < ctx->bufLen) ? n : ctx->bufLen;
    for (int i = 0; i < copyLen; i++) {
      hash[i] = ctx->buf[i];
    }
    ctx->buf += copyLen;
    hash += copyLen;
    n -= copyLen;

    // Apply the permutation if we've squeezed the sponge dry.
    if (ctx->bufLen == 0) {
      permute(ctx);
    }
  }
  //printCtx("finished Summing", ctx);
}

uint8_t *compute_keccak256(uint8_t *input, int length) {
  struct keccak256_ctx *ctx = init_keccak256();
  write_keccak256(ctx, input, length);
  uint8_t *hash = malloc(ctx->outputLen);
  sum_keccak256(ctx, hash);
  free(ctx);
  return hash;
}
