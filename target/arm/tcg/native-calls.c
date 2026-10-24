/*
 * Native calls: work a guest hands to the host through the PSCI conduit
 *
 * Copyright (C) 2026, mKonic <mkonic676@gmail.com>
 *
 * A guest that runs under TCG pays ten times or more for plain computation
 * than the host does. For a few bulk operations whose inputs and outputs are
 * buffers in the guest's memory, it can ask the host to do them instead: an
 * SMCCC call in the vendor-specific hypervisor service range (owner 6, SMC64)
 * on the PSCI conduit. A guest finds out whether they are there with
 * NATIVE_CALL_QUERY, which answers NATIVE_CALL_MAGIC; any QEMU without them,
 * and SMCCC firmware in general, answers NOT_SUPPORTED to an unknown call.
 *
 *   NATIVE_CALL_QUERY    () -> NATIVE_CALL_MAGIC
 *   NATIVE_CALL_SHA256   (x1 state, x2 data, x3 blocks) -> 0 or -1
 *       the SHA-256 compression function over x3 blocks of 64 bytes at x2,
 *       on the eight 32-bit words of state at x1 (in the guest's order)
 *   NATIVE_CALL_INFLATE  (x1 dst, x2 dst_len, x3 src, x4 src_len) -> length or -1
 *       a zlib stream at x3 inflated into the buffer at x1; -1 if the stream
 *       is not whole and valid or does not fit
 *
 * Addresses are virtual, in the translation regime the call is made from.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "internals.h"
#include "exec/cpu-common.h"
#include "hw/core/cpu.h"
#include "qemu/bitops.h"
#include "qemu/bswap.h"
#include <zlib.h>

#define NATIVE_CALL_QUERY       0xc6000000
#define NATIVE_CALL_SHA256      0xc6000001
#define NATIVE_CALL_INFLATE     0xc6000002
#define NATIVE_CALL_MAGIC       0x5265647775644e43ULL      /* "RedwudNC" */

/* (the largest buffer a call may name: a compressed file's piece is 64 KB) */
#define NATIVE_CALL_MAX         (1024 * 1024)

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static void sha256_compress(uint32_t s[8], const uint8_t *p, size_t blocks)
{
    for (; blocks--; p += 64) {
        uint32_t w[64], a = s[0], b = s[1], c = s[2], d = s[3];
        uint32_t e = s[4], f = s[5], g = s[6], h = s[7];

        for (int i = 0; i < 16; i++) {
            w[i] = ldl_be_p(p + 4 * i);
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^
                          (w[i - 15] >> 3);
            uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^
                          (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = h + (ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25)) +
                          (g ^ (e & (f ^ g))) + sha256_k[i] + w[i];
            uint32_t t2 = (ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22)) +
                          ((a & b) | (c & (a | b)));

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        s[0] += a;
        s[1] += b;
        s[2] += c;
        s[3] += d;
        s[4] += e;
        s[5] += f;
        s[6] += g;
        s[7] += h;
    }
}

static int64_t native_sha256(CPUState *cs, uint64_t state, uint64_t data,
                             uint64_t blocks)
{
    uint32_t s[8];
    g_autofree uint8_t *buf = NULL;

    if (blocks == 0 || blocks > NATIVE_CALL_MAX / 64) {
        return -1;
    }
    buf = g_malloc(blocks * 64);
    if (cpu_memory_rw_debug(cs, state, s, sizeof(s), false) ||
        cpu_memory_rw_debug(cs, data, buf, blocks * 64, false)) {
        return -1;
    }
    sha256_compress(s, buf, blocks);
    return cpu_memory_rw_debug(cs, state, s, sizeof(s), true) ? -1 : 0;
}

static int64_t native_inflate(CPUState *cs, uint64_t dst, uint64_t dst_len,
                              uint64_t src, uint64_t src_len)
{
    g_autofree uint8_t *in = NULL, *out = NULL;
    z_stream zs = { 0 };
    int ret;

    if (src_len == 0 || src_len > NATIVE_CALL_MAX || dst_len == 0 ||
        dst_len > NATIVE_CALL_MAX) {
        return -1;
    }
    in = g_malloc(src_len);
    out = g_malloc(dst_len);
    if (cpu_memory_rw_debug(cs, src, in, src_len, false)) {
        return -1;
    }
    zs.next_in = in;
    zs.avail_in = src_len;
    zs.next_out = out;
    zs.avail_out = dst_len;
    if (inflateInit(&zs) != Z_OK) {
        return -1;
    }
    ret = inflate(&zs, Z_FINISH);
    inflateEnd(&zs);
    if (ret != Z_STREAM_END) {
        return -1;
    }
    if (cpu_memory_rw_debug(cs, dst, out, zs.total_out, true)) {
        return -1;
    }
    return zs.total_out;
}

bool arm_handle_native_call(ARMCPU *cpu)
{
    CPUARMState *env = &cpu->env;
    uint64_t *x = env->xregs;
    int64_t ret;

    if (!is_a64(env)) {
        return false;
    }
    switch (x[0]) {
    case NATIVE_CALL_QUERY:
        ret = NATIVE_CALL_MAGIC;
        break;
    case NATIVE_CALL_SHA256:
        ret = native_sha256(CPU(cpu), x[1], x[2], x[3]);
        break;
    case NATIVE_CALL_INFLATE:
        ret = native_inflate(CPU(cpu), x[1], x[2], x[3], x[4]);
        break;
    default:
        return false;
    }
    x[0] = ret;
    return true;
}
