/*
 * Copyright (C) 2026, mKonic <mkonic676@gmail.com>
 *
 * A sampling profiler for system emulation: a host thread asks every vCPU
 * for a sample each period, and the next translation block that vCPU runs
 * records where it is. Between samples the cost is one inline compare per
 * block. Each sample is a line of the output file:
 *
 *   MSEC VCPU CONTEXT EL PC LR FRAME...
 *
 * MSEC is host time since the plugin started, CONTEXT the CONTEXTIDR_EL1
 * the guest set (a thread or process number, if the guest keeps one there),
 * EL the exception level, and the FRAMEs the return addresses found by
 * following the frame pointer chain (x29), pointer authentication stripped.
 * A vCPU that is halted when its next sample is due counts as idle; the
 * idle counts are the last line of the file.
 *
 * Arguments:
 *   out=PATH       where the samples go (default sampler.out)
 *   period=USEC    how often each vCPU is sampled (default 1000)
 *   depth=N        frame pointer chain depth (default 32)
 *
 * Aimed at aarch64 guests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

typedef struct {
    struct qemu_plugin_register *fp, *lr, *cpsr, *context;
    GByteArray *buf;
    uint64_t idle;
} VCPU;

static struct qemu_plugin_scoreboard *wanted;
static qemu_plugin_u64 wanted_entry;
static VCPU *vcpus;
static int nvcpus;
static FILE *out;
static GMutex out_lock;
static GThread *ticker;
static volatile bool stopping;
static uint64_t period_us = 1000;
static unsigned depth = 32;
static gint64 start_us;

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

static uint64_t read_u64(VCPU *v, struct qemu_plugin_register *reg)
{
    uint64_t value = 0;

    if (!reg) {
        return 0;
    }
    g_byte_array_set_size(v->buf, 0);
    if (qemu_plugin_read_register(reg, v->buf)) {
        memcpy(&value, v->buf->data, MIN(v->buf->len, sizeof(value)));
    }
    return GUINT64_FROM_LE(value);
}

/* Return addresses carry a pointer authentication code in their top bits. */
static uint64_t strip(uint64_t address, bool kernel)
{
    return kernel ? address | 0xffffff8000000000ULL
                  : address & 0x0000007fffffffffULL;
}

static void vcpu_init(unsigned int index, void *unused)
{
    GArray *regs = qemu_plugin_get_registers();
    VCPU *v = &vcpus[index];

    v->fp = find_register(regs, "x29");
    v->lr = find_register(regs, "x30");
    if (!v->lr) {
        v->lr = find_register(regs, "lr");
    }
    v->cpsr = find_register(regs, "cpsr");
    v->context = find_register(regs, "CONTEXTIDR_EL1");
    v->buf = g_byte_array_new();
    g_array_free(regs, true);
}

static void sample(unsigned int index, void *udata)
{
    VCPU *v = &vcpus[index];
    uint64_t pc = (uintptr_t)udata;
    uint64_t el = (read_u64(v, v->cpsr) >> 2) & 3;
    uint64_t fp = read_u64(v, v->fp);
    uint64_t lr = read_u64(v, v->lr);
    bool kernel = el > 0;
    GString *line = g_string_new(NULL);

    qemu_plugin_u64_set(wanted_entry, index, 0);
    g_string_append_printf(line, "%" PRId64 " %u %" PRIu64 " %" PRIu64
                           " %" PRIx64 " %" PRIx64,
                           (g_get_monotonic_time() - start_us) / 1000, index,
                           read_u64(v, v->context) & 0xffffffff, el, pc,
                           lr ? strip(lr, kernel) : 0);
    for (unsigned i = 0; i < depth && fp && !(fp & 7); i++) {
        uint64_t frame[2];

        g_byte_array_set_size(v->buf, 0);
        if (!qemu_plugin_read_memory_vaddr(fp, v->buf, sizeof(frame))) {
            break;
        }
        memcpy(frame, v->buf->data, sizeof(frame));
        frame[0] = GUINT64_FROM_LE(frame[0]);
        frame[1] = GUINT64_FROM_LE(frame[1]);
        if (!frame[1]) {
            break;
        }
        frame[1] = strip(frame[1], kernel);
        g_string_append_printf(line, " %" PRIx64, frame[1]);
        if (frame[0] <= fp) {
            break;
        }
        fp = frame[0];
    }
    g_string_append_c(line, '\n');
    g_mutex_lock(&out_lock);
    fputs(line->str, out);
    g_mutex_unlock(&out_lock);
    g_string_free(line, true);
}

static void tb_trans(struct qemu_plugin_tb *tb, void *unused)
{
    qemu_plugin_register_vcpu_tb_exec_cond_cb(
        tb, sample, QEMU_PLUGIN_CB_R_REGS, QEMU_PLUGIN_COND_NE, wanted_entry,
        0, (void *)(uintptr_t)qemu_plugin_tb_vaddr(tb));
}

static gpointer tick(gpointer unused)
{
    while (!stopping) {
        /* the scoreboard grows as vCPUs come up: only touch those that are */
        int n = qemu_plugin_num_vcpus();

        g_usleep(period_us);
        for (int i = 0; i < n; i++) {
            if (qemu_plugin_u64_get(wanted_entry, i)) {
                vcpus[i].idle++;
            } else {
                qemu_plugin_u64_set(wanted_entry, i, 1);
            }
        }
    }
    return NULL;
}

static void plugin_exit(void *unused)
{
    stopping = true;
    g_thread_join(ticker);
    g_mutex_lock(&out_lock);
    fprintf(out, "idle");
    for (int i = 0; i < qemu_plugin_num_vcpus(); i++) {
        fprintf(out, " %" PRIu64, vcpus[i].idle);
    }
    fprintf(out, "\n");
    fclose(out);
    g_mutex_unlock(&out_lock);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    const char *path = "sampler.out";

    if (!info->system_emulation) {
        fprintf(stderr, "sampler: system emulation only\n");
        return -1;
    }
    for (int i = 0; i < argc; i++) {
        g_auto(GStrv) kv = g_strsplit(argv[i], "=", 2);
        if (!kv[1]) {
            fprintf(stderr, "sampler: option %s has no value\n", argv[i]);
            return -1;
        }
        if (g_strcmp0(kv[0], "out") == 0) {
            path = g_strdup(kv[1]);
        } else if (g_strcmp0(kv[0], "period") == 0) {
            period_us = MAX(g_ascii_strtoull(kv[1], NULL, 0), 50);
        } else if (g_strcmp0(kv[0], "depth") == 0) {
            depth = g_ascii_strtoull(kv[1], NULL, 0);
        } else {
            fprintf(stderr, "sampler: unknown option %s\n", argv[i]);
            return -1;
        }
    }
    out = fopen(path, "w");
    if (!out) {
        fprintf(stderr, "sampler: cannot write %s\n", path);
        return -1;
    }
    nvcpus = info->system.max_vcpus;
    vcpus = g_new0(VCPU, nvcpus);
    wanted = qemu_plugin_scoreboard_new(sizeof(uint64_t));
    wanted_entry = qemu_plugin_scoreboard_u64(wanted);
    start_us = g_get_monotonic_time();
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init, NULL);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans, NULL);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    ticker = g_thread_new("sampler", tick, NULL);
    return 0;
}
