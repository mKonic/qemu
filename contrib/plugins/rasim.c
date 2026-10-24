/*
 * Copyright (C) 2026, mKonic <mkonic676@gmail.com>
 *
 * How the indirect branches of an aarch64 guest divide between returns (RET
 * and its authenticated forms), calls through a register (BLR...) and other
 * jumps through a register (BR...), and how often a return-address stack of
 * a few depths would have predicted the returns: a stack per vCPU, pushed by
 * every BL and BLR with the address after it, popped by every RET. Also how
 * often a BLR or a BR went where it went the last time from the same place
 * (a cache of one target a branch), and how often such a cache shared by all
 * vCPUs could have been trusted: filled in the same address space (the ASID
 * in TTBR0_EL1, for a target in the lower half) and with no TLBI since.
 *
 * Output at exit: the counts, then one line a depth: DEPTH RETURNS HITS PERCENT,
 * then KIND BRANCHES SAME-TARGET PERCENT SITES TRUSTED PERCENT for blr and br,
 * then the number of TLBIs.
 *
 * Arguments:
 *   out=PATH       where the results go (default rasim.out)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

enum { END_OTHER, END_CALL, END_BLR, END_BR, END_RET };
static const unsigned depths[] = { 4, 8, 16, 32, 64 };
#define NDEPTHS G_N_ELEMENTS(depths)
#define MAXDEPTH 64

typedef struct {
    uint64_t stack[NDEPTHS][MAXDEPTH];
    unsigned top[NDEPTHS];
    uint64_t hits[NDEPTHS];
    uint64_t counts[5];
    int pending;                /* how the last block ended */
    uint64_t pending_site;      /* ... and where its last instruction is */
    uint64_t same[2];           /* BLR, BR: went where the site went last */
    uint64_t trusted[2];        /* ... and the cache could have said so */
    struct qemu_plugin_register *ttbr0;
    GByteArray *buf;
} VCPU;

typedef struct {
    uint64_t target, asid, gen;
} Last;

static VCPU *vcpus;
static GHashTable *last_target[2];     /* site -> its last target, for BLR and BR */
static GMutex lock;
static uint64_t tlbi_gen;              /* TLBIs executed, by any vCPU */
static int max_vcpus;
static const char *path = "rasim.out";

static void tb_exec(unsigned int index, void *udata)
{
    VCPU *v = &vcpus[index];
    uint64_t info = (uintptr_t)udata;
    uint64_t pc = info >> 3;

    if (v->pending == END_BLR || v->pending == END_BR) {
        int k = v->pending == END_BR;
        gpointer key = (gpointer)(uintptr_t)v->pending_site;
        uint64_t asid = 0, gen = __atomic_load_n(&tlbi_gen, __ATOMIC_RELAXED);
        bool kernel = pc >> 63;
        Last *last;

        if (!kernel) {
            g_byte_array_set_size(v->buf, 0);
            if (v->ttbr0 && qemu_plugin_read_register(v->ttbr0, v->buf)) {
                memcpy(&asid, v->buf->data, MIN(v->buf->len, sizeof(asid)));
            }
            asid = GUINT64_FROM_LE(asid) >> 48;
        }
        g_mutex_lock(&lock);
        last = g_hash_table_lookup(last_target[k], key);
        if (!last) {
            last = g_new0(Last, 1);
            g_hash_table_insert(last_target[k], key, last);
        } else if (last->target == pc) {
            v->same[k]++;
            if (last->gen == gen && (kernel || last->asid == asid)) {
                v->trusted[k]++;
            }
        }
        last->target = pc;
        last->asid = asid;
        last->gen = gen;
        g_mutex_unlock(&lock);
    } else if (v->pending == END_RET) {
        for (unsigned d = 0; d < NDEPTHS; d++) {
            unsigned t = v->top[d];

            if (t > 0 && v->stack[d][(t - 1) % depths[d]] == pc) {
                v->hits[d]++;
            }
            v->top[d] = t > 0 ? t - 1 : 0;
        }
    }
    v->pending = info & 7;
    v->counts[v->pending]++;
}

static void insn_tlbi(unsigned int index, void *udata)
{
    __atomic_fetch_add(&tlbi_gen, 1, __ATOMIC_RELAXED);
}

static void tb_exec_site(unsigned int index, void *udata)
{
    vcpus[index].pending_site = (uintptr_t)udata;
}

static void tb_exec_call(unsigned int index, void *udata)
{
    VCPU *v = &vcpus[index];
    uint64_t ret = (uintptr_t)udata;

    for (unsigned d = 0; d < NDEPTHS; d++) {
        v->stack[d][v->top[d] % depths[d]] = ret;
        v->top[d]++;
    }
}

static void vcpu_init(unsigned int index, void *unused)
{
    GArray *regs = qemu_plugin_get_registers();
    VCPU *v = &vcpus[index];

    for (guint i = 0; i < regs->len; i++) {
        qemu_plugin_reg_descriptor *r =
            &g_array_index(regs, qemu_plugin_reg_descriptor, i);
        if (g_ascii_strcasecmp(r->name, "TTBR0_EL1") == 0) {
            v->ttbr0 = r->handle;
        }
    }
    v->buf = g_byte_array_new();
    g_array_free(regs, true);
}

static void tb_trans(struct qemu_plugin_tb *tb, void *unused)
{
    size_t n = qemu_plugin_tb_n_insns(tb);
    struct qemu_plugin_insn *last = qemu_plugin_tb_get_insn(tb, n - 1);
    uint32_t insn = 0;
    uint64_t end = END_OTHER, vaddr = qemu_plugin_insn_vaddr(last);

    if (qemu_plugin_insn_data(last, &insn, sizeof(insn)) == sizeof(insn)) {
        if ((insn & 0xfc000000) == 0x94000000) {
            end = END_CALL;                                 /* BL */
        } else if ((insn & 0xfe000000) == 0xd6000000) {
            unsigned opc = (insn >> 21) & 0xf;

            end = opc == 1 ? END_BLR : opc == 2 ? END_RET : END_BR;
        }
    }
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *in = qemu_plugin_tb_get_insn(tb, i);
        uint32_t w = 0;

        /* TLBI: SYS with CRn 8 */
        if (qemu_plugin_insn_data(in, &w, sizeof(w)) == sizeof(w) &&
            (w & 0xfff8f000) == 0xd5088000) {
            qemu_plugin_register_vcpu_insn_exec_cb(in, insn_tlbi,
                                                   QEMU_PLUGIN_CB_NO_REGS,
                                                   NULL);
        }
    }
    qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec, QEMU_PLUGIN_CB_R_REGS,
                                         (void *)(uintptr_t)
                                         (qemu_plugin_tb_vaddr(tb) << 3 | end));
    if (end == END_BLR || end == END_BR) {
        qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec_site,
                                             QEMU_PLUGIN_CB_NO_REGS,
                                             (void *)(uintptr_t)vaddr);
    }
    if (end == END_CALL || end == END_BLR) {
        qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec_call,
                                             QEMU_PLUGIN_CB_NO_REGS,
                                             (void *)(uintptr_t)(vaddr + 4));
    }
}

static void plugin_exit(void *unused)
{
    FILE *out = fopen(path, "w");
    uint64_t counts[5] = { 0 }, hits[NDEPTHS] = { 0 }, same[2] = { 0 };
    uint64_t trusted[2] = { 0 };

    if (!out) {
        return;
    }
    for (int i = 0; i < max_vcpus; i++) {
        for (int k = 0; k < 5; k++) {
            counts[k] += vcpus[i].counts[k];
        }
        for (unsigned d = 0; d < NDEPTHS; d++) {
            hits[d] += vcpus[i].hits[d];
        }
        for (int k = 0; k < 2; k++) {
            same[k] += vcpus[i].same[k];
            trusted[k] += vcpus[i].trusted[k];
        }
    }
    fprintf(out, "blocks ending: other %" PRIu64 " bl %" PRIu64 " blr %" PRIu64
            " br %" PRIu64 " ret %" PRIu64 "\n", counts[0], counts[1],
            counts[2], counts[3], counts[4]);
    for (unsigned d = 0; d < NDEPTHS; d++) {
        fprintf(out, "%u %" PRIu64 " %" PRIu64 " %.2f\n", depths[d], counts[4],
                hits[d], counts[4] ? 100.0 * hits[d] / counts[4] : 0.0);
    }
    for (int k = 0; k < 2; k++) {
        uint64_t n = counts[k ? END_BR : END_BLR];

        fprintf(out, "%s %" PRIu64 " %" PRIu64 " %.2f %u %" PRIu64 " %.2f\n",
                k ? "br" : "blr", n, same[k], n ? 100.0 * same[k] / n : 0.0,
                g_hash_table_size(last_target[k]), trusted[k],
                n ? 100.0 * trusted[k] / n : 0.0);
    }
    fprintf(out, "tlbi %" PRIu64 "\n", tlbi_gen);
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
            fprintf(stderr, "rasim: unknown option %s\n", argv[i]);
            return -1;
        }
    }
    max_vcpus = info->system.max_vcpus;
    vcpus = g_new0(VCPU, max_vcpus);
    for (int k = 0; k < 2; k++) {
        last_target[k] = g_hash_table_new_full(NULL, NULL, NULL, g_free);
    }
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init, NULL);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans, NULL);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
