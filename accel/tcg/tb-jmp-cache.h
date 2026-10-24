/*
 * The per-CPU TranslationBlock jump cache.
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ACCEL_TCG_TB_JMP_CACHE_H
#define ACCEL_TCG_TB_JMP_CACHE_H

#include "qemu/rcu.h"
#include "exec/cpu-common.h"

#define TB_JMP_CACHE_BITS 16
#define TB_JMP_CACHE_SIZE (1 << TB_JMP_CACHE_BITS)

/*
 * Invalidated in parallel; all accesses to 'tb' must be atomic.
 * A valid entry is read/written by a single CPU, therefore there is
 * no need for qatomic_rcu_read() and pc is always consistent with a
 * non-NULL value of 'tb'.  Strictly speaking pc is only needed for
 * CF_PCREL, but it's used always for simplicity.  It holds the key of
 * tb_jmp_cache_key(), the pc tagged with the address space.
 */
typedef struct CPUJumpCache {
    struct rcu_head rcu;
    struct {
        TranslationBlock *tb;
        vaddr pc;
    } array[TB_JMP_CACHE_SIZE];
} CPUJumpCache;

/*
 * The key an entry for @pc is kept under: @pc, and for addresses in the
 * lower half of the address space, @pc tagged with the address space they
 * are looked up in (CPUState::tb_jmp_tag).
 */
static inline vaddr tb_jmp_cache_key(vaddr tag, vaddr pc)
{
    return pc ^ (tag & ~(vaddr)((int64_t)pc >> 63));
}

#endif /* ACCEL_TCG_TB_JMP_CACHE_H */
