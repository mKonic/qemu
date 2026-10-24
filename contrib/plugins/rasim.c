/*
 * Copyright (C) 2026, mKonic <mkonic676@gmail.com>
 *
 * How the indirect branches of an aarch64 guest divide between returns (RET
 * and its authenticated forms), calls through a register (BLR...) and other
 * jumps through a register (BR...), and how often a return-address stack of
 * a few depths would have predicted the returns: a stack per vCPU, pushed by
 * every BL and BLR with the address after it, popped by every RET.
 *
 * Output at exit: the counts, then one line a depth: DEPTH RETURNS HITS PERCENT.
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
    uint64_t pending_ret;       /* ... and, for a call, the address after it */
} VCPU;

static VCPU *vcpus;
static int max_vcpus;
static const char *path = "rasim.out";

static void tb_exec(unsigned int index, void *udata)
{
    VCPU *v = &vcpus[index];
    uint64_t info = (uintptr_t)udata;
    uint64_t pc = info >> 3;

    if (v->pending == END_RET) {
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

static void tb_exec_call(unsigned int index, void *udata)
{
    VCPU *v = &vcpus[index];
    uint64_t ret = (uintptr_t)udata;

    for (unsigned d = 0; d < NDEPTHS; d++) {
        v->stack[d][v->top[d] % depths[d]] = ret;
        v->top[d]++;
    }
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
    qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec, QEMU_PLUGIN_CB_NO_REGS,
                                         (void *)(uintptr_t)
                                         (qemu_plugin_tb_vaddr(tb) << 3 | end));
    if (end == END_CALL || end == END_BLR) {
        qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec_call,
                                             QEMU_PLUGIN_CB_NO_REGS,
                                             (void *)(uintptr_t)(vaddr + 4));
    }
}

static void plugin_exit(void *unused)
{
    FILE *out = fopen(path, "w");
    uint64_t counts[5] = { 0 }, hits[NDEPTHS] = { 0 };

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
    }
    fprintf(out, "blocks ending: other %" PRIu64 " bl %" PRIu64 " blr %" PRIu64
            " br %" PRIu64 " ret %" PRIu64 "\n", counts[0], counts[1],
            counts[2], counts[3], counts[4]);
    for (unsigned d = 0; d < NDEPTHS; d++) {
        fprintf(out, "%u %" PRIu64 " %" PRIu64 " %.2f\n", depths[d], counts[4],
                hits[d], counts[4] ? 100.0 * hits[d] / counts[4] : 0.0);
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
            fprintf(stderr, "rasim: unknown option %s\n", argv[i]);
            return -1;
        }
    }
    max_vcpus = info->system.max_vcpus;
    vcpus = g_new0(VCPU, max_vcpus);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans, NULL);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
