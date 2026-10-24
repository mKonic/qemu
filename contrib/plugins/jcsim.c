/*
 * Copyright (C) 2026, mKonic <mkonic676@gmail.com>
 *
 * Simulate jump caches of several shapes on the blocks an aarch64 guest
 * reaches through a lookup: those that follow a block ending in a branch to
 * a register (BR, BLR, RET, ERET and their authenticated forms). For each
 * shape, how many of those lookups would have missed. Shapes:
 *
 *   flush N    direct-mapped, 2^N entries, emptied whenever the ASID in
 *              TTBR0_EL1 changes (what QEMU does)
 *   asid N     direct-mapped, 2^N entries, entries tagged with the ASID
 *   2way N     2-way set-associative (LRU), 2^N entries, ASID-tagged
 *
 * Output at exit, one line a shape: SHAPE N LOOKUPS MISSES PERCENT.
 *
 * Arguments:
 *   out=PATH       where the results go (default jcsim.out)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

enum { FLUSH, ASID, TWOWAY, KINDS };
static const char *kind_names[KINDS] = { "flush", "asid", "2way" };
static const unsigned sizes[] = { 12, 14, 16, 18, 20 };
#define NSIZES G_N_ELEMENTS(sizes)

typedef struct {
    uint64_t key;       /* pc | asid << 48 for user addresses; 0 when empty */
    uint64_t gen;       /* the flush generation it was filled in */
} Entry;

typedef struct {
    Entry *table;
    uint8_t *lru;       /* for 2-way: which way of a set to replace next */
    uint64_t misses;
} Cache;

typedef struct {
    struct qemu_plugin_register *ttbr0;
    GByteArray *buf;
    Cache caches[KINDS][NSIZES];
    uint64_t lookups, gen, asid;
    bool after_indirect;
} VCPU;

static VCPU *vcpus;
static int max_vcpus;
static const char *path = "jcsim.out";

static unsigned hash(uint64_t pc, unsigned bits)
{
    return (pc ^ (pc >> bits)) & ((1u << bits) - 1);
}

static struct qemu_plugin_register *find_register(GArray *regs, const char *name)
{
    for (guint i = 0; i < regs->len; i++) {
        qemu_plugin_reg_descriptor *r =
            &g_array_index(regs, qemu_plugin_reg_descriptor, i);
        if (g_ascii_strcasecmp(r->name, name) == 0) {
            return r->handle;
        }
    }
    return NULL;
}

static void vcpu_init(unsigned int index, void *unused)
{
    GArray *regs = qemu_plugin_get_registers();
    VCPU *v = &vcpus[index];

    v->ttbr0 = find_register(regs, "TTBR0_EL1");
    v->buf = g_byte_array_new();
    g_array_free(regs, true);
    for (int k = 0; k < KINDS; k++) {
        for (unsigned s = 0; s < NSIZES; s++) {
            v->caches[k][s].table = g_new0(Entry, 1u << sizes[s]);
            v->caches[k][s].lru = g_new0(uint8_t, 1u << sizes[s]);
        }
    }
}

static uint64_t read_u64(VCPU *v, struct qemu_plugin_register *reg)
{
    uint64_t value = 0;

    g_byte_array_set_size(v->buf, 0);
    if (reg && qemu_plugin_read_register(reg, v->buf)) {
        memcpy(&value, v->buf->data, MIN(v->buf->len, sizeof(value)));
    }
    return GUINT64_FROM_LE(value);
}

static void lookup(VCPU *v, uint64_t pc)
{
    bool kernel = pc >> 63;
    uint64_t asid = kernel ? 0 : read_u64(v, v->ttbr0) >> 48;
    uint64_t tagged = kernel ? pc : (pc & 0xffffffffffffULL) | asid << 48;

    v->lookups++;
    if (!kernel && asid != v->asid) {
        v->asid = asid;
        v->gen++;
    }
    for (unsigned s = 0; s < NSIZES; s++) {
        unsigned bits = sizes[s], i = hash(pc, bits);
        Cache *c;
        Entry *e;

        /* QEMU's: keyed by the PC alone, emptied at each switch */
        c = &v->caches[FLUSH][s];
        e = &c->table[i];
        if (e->key != pc || e->gen != v->gen) {
            c->misses++;
            e->key = pc;
            e->gen = v->gen;
        }

        c = &v->caches[ASID][s];
        e = &c->table[i];
        if (e->key != tagged) {
            c->misses++;
            e->key = tagged;
        }

        c = &v->caches[TWOWAY][s];
        i = hash(pc, bits - 1) << 1;
        if (c->table[i].key == tagged) {
            c->lru[i >> 1] = 1;
        } else if (c->table[i + 1].key == tagged) {
            c->lru[i >> 1] = 0;
        } else {
            unsigned way = c->lru[i >> 1];

            c->misses++;
            c->table[i + way].key = tagged;
            c->lru[i >> 1] = !way;
        }
    }
}

static void tb_exec(unsigned int index, void *udata)
{
    VCPU *v = &vcpus[index];
    uint64_t info = (uintptr_t)udata;

    if (v->after_indirect) {
        lookup(v, info & ~1ULL);
    }
    v->after_indirect = info & 1;
}

static void tb_trans(struct qemu_plugin_tb *tb, void *unused)
{
    size_t n = qemu_plugin_tb_n_insns(tb);
    struct qemu_plugin_insn *last = qemu_plugin_tb_get_insn(tb, n - 1);
    uint32_t insn = 0;
    uint64_t info = qemu_plugin_tb_vaddr(tb);

    if (qemu_plugin_insn_data(last, &insn, sizeof(insn)) == sizeof(insn) &&
        (insn & 0xfe000000) == 0xd6000000) {
        info |= 1;      /* PCs are 4-aligned: bit 0 says "ends indirect" */
    }
    qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec, QEMU_PLUGIN_CB_R_REGS,
                                         (void *)(uintptr_t)info);
}

static void plugin_exit(void *unused)
{
    FILE *out = fopen(path, "w");

    if (!out) {
        return;
    }
    for (int k = 0; k < KINDS; k++) {
        for (unsigned s = 0; s < NSIZES; s++) {
            uint64_t lookups = 0, misses = 0;

            for (int i = 0; i < max_vcpus; i++) {
                if (vcpus[i].buf) {
                    lookups += vcpus[i].lookups;
                    misses += vcpus[i].caches[k][s].misses;
                }
            }
            fprintf(out, "%s %u %" PRIu64 " %" PRIu64 " %.2f\n", kind_names[k],
                    sizes[s], lookups, misses,
                    lookups ? 100.0 * misses / lookups : 0.0);
        }
    }
    fclose(out);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    for (int i = 0; i < argc; i++) {
        if (g_str_has_prefix(argv[i], "out=")) {
            path = argv[i] + 4;
        } else {
            fprintf(stderr, "jcsim: unknown option %s\n", argv[i]);
            return -1;
        }
    }
    max_vcpus = info->system.max_vcpus;
    vcpus = g_new0(VCPU, max_vcpus);
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init, NULL);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans, NULL);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
