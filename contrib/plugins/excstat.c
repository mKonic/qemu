/*
 * Copyright (C) 2026, mKonic <mkonic676@gmail.com>
 *
 * Count the exceptions and interrupts an aarch64 guest takes, by kind: the
 * exception class from ESR_EL1, the fault status code and write bit for
 * aborts, and whether it came from EL0 or EL1. Each period the counts since
 * the last period are a block of the output file:
 *
 *   @ MSEC
 *   COUNT FROM-EL KIND
 *
 * and at exit the PCs that took the most aborts, and the system calls (SVC
 * from EL0) by thread and number and by number and caller:
 *
 *   pc COUNT FROM-EL KIND PC
 *   svc COUNT THREAD NUMBER
 *   svccall COUNT NUMBER LR
 *
 * THREAD is CONTEXTIDR_EL1 (the thread ID on our DEVELOPMENT kernel), NUMBER
 * x16 (negative for Mach traps), LR the return address in x30.
 *
 * Arguments:
 *   out=PATH       where the counts go (default excstat.out)
 *   period=MSEC    how often a block is written (default 5000)
 *   from=MSEC      count PCs and system calls only after this (default 0)
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
    struct qemu_plugin_register *esr, *x16, *lr, *context;
    GByteArray *buf;
} VCPU;

static VCPU *vcpus;
static GHashTable *kinds, *pcs, *svcs, *svc_calls;
static GMutex lock;
static FILE *out;
static GThread *ticker;
static volatile bool stopping;
static uint64_t period_ms = 5000;
static gint64 start_us, from_us;

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

    vcpus[index].esr = find_register(regs, "ESR_EL1");
    vcpus[index].x16 = find_register(regs, "x16");
    vcpus[index].lr = find_register(regs, "x30");
    vcpus[index].context = find_register(regs, "CONTEXTIDR_EL1");
    vcpus[index].buf = g_byte_array_new();
    g_array_free(regs, true);
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

static const char *fault(unsigned fsc)
{
    switch (fsc & 0x3c) {
    case 0x04: return "translation";
    case 0x08: return "access-flag";
    case 0x0c: return "permission";
    case 0x00: return "address-size";
    }
    return fsc == 0x21 ? "alignment" : "other";
}

/* A key: bits 0-5 FSC, 6 WnR, 8-13 EC, 16 from EL1, 17 interrupt. */
static void describe(GString *s, uint32_t key)
{
    unsigned ec = (key >> 8) & 0x3f, fsc = key & 0x3f;

    g_string_append_printf(s, "EL%u ", (key >> 16) & 1);
    if (key & (1 << 17)) {
        g_string_append(s, "irq");
    } else if (ec == 0x20 || ec == 0x21) {
        g_string_append_printf(s, "inst-abort %s L%u", fault(fsc), fsc & 3);
    } else if (ec == 0x24 || ec == 0x25) {
        g_string_append_printf(s, "data-abort %s L%u %s", fault(fsc), fsc & 3,
                               key & 0x40 ? "write" : "read");
    } else {
        g_string_append_printf(s, "ec=%#x", ec);
    }
}

static void bump(GHashTable *t, gpointer key)
{
    g_hash_table_insert(t, key,
                        GSIZE_TO_POINTER(GPOINTER_TO_SIZE(
                            g_hash_table_lookup(t, key)) + 1));
}

/* For the tables keyed by a 64-bit value, with a counter each. */
static void bump64(GHashTable *t, uint64_t key)
{
    gsize *count = g_hash_table_lookup(t, &key);

    if (!count) {
        count = g_new0(gsize, 1);
        g_hash_table_insert(t, g_memdup2(&key, sizeof(key)), count);
    }
    (*count)++;
}

static void discon(unsigned int index, enum qemu_plugin_discon_type type,
                   uint64_t from_pc, uint64_t to_pc, void *unused)
{
    uint32_t key = (from_pc >> 63) << 16;

    if (type == QEMU_PLUGIN_DISCON_INTERRUPT) {
        key |= 1 << 17;
    } else if (type == QEMU_PLUGIN_DISCON_EXCEPTION) {
        VCPU *v = &vcpus[index];
        uint64_t esr = read_u64(v, v->esr);
        unsigned ec = (esr >> 26) & 0x3f;

        key |= ec << 8;
        if (ec == 0x15 && !(from_pc >> 63) &&
            g_get_monotonic_time() >= from_us) {
            uint32_t nr = read_u64(v, v->x16);
            uint64_t tid = read_u64(v, v->context) & 0xffffffff;
            uint64_t lr = read_u64(v, v->lr) & 0x7fffffffffULL;

            g_mutex_lock(&lock);
            bump64(svcs, tid << 32 | nr);
            /* 24 bits of the number (sign included) and 40 of the address */
            bump64(svc_calls, (uint64_t)(nr & 0xffffff) << 40 | lr);
            g_mutex_unlock(&lock);
        }
        if (ec == 0x20 || ec == 0x21 || ec == 0x24 || ec == 0x25) {
            key |= esr & 0x3f;
            if (ec >= 0x24) {
                key |= esr & 0x40;
            }
        }
    } else {
        return;
    }
    g_mutex_lock(&lock);
    bump(kinds, GUINT_TO_POINTER(key));
    if (!(key & (1 << 17)) && (key & 0x3f)) {
        /* the PC's low 44 bits and the key share one 64-bit hash key */
        if (g_get_monotonic_time() >= from_us) {
            bump64(pcs, (from_pc & 0xfffffffffffULL) | ((uint64_t)key << 44));
        }
    }
    g_mutex_unlock(&lock);
}

static gsize count_of(GHashTable *table, gpointer key)
{
    gpointer value = g_hash_table_lookup(table, key);

    return table == kinds ? GPOINTER_TO_SIZE(value) : *(gsize *)value;
}

static gint by_count(gconstpointer a, gconstpointer b, gpointer table)
{
    gsize ca = count_of(table, *(gpointer *)a);
    gsize cb = count_of(table, *(gpointer *)b);
    return ca < cb ? 1 : ca > cb ? -1 : 0;
}

/* Write the counts since the last block; called with the lock held. */
static void flush_block(void)
{
    GList *keys = g_hash_table_get_keys(kinds);
    GPtrArray *sorted = g_ptr_array_new();
    GString *s = g_string_new(NULL);

    for (GList *k = keys; k; k = k->next) {
        g_ptr_array_add(sorted, k->data);
    }
    g_ptr_array_sort_with_data(sorted, by_count, kinds);
    fprintf(out, "@ %" PRId64 "\n", (g_get_monotonic_time() - start_us) / 1000);
    for (guint i = 0; i < sorted->len; i++) {
        g_string_truncate(s, 0);
        describe(s, GPOINTER_TO_UINT(sorted->pdata[i]));
        fprintf(out, "%zu %s\n",
                GPOINTER_TO_SIZE(g_hash_table_lookup(kinds, sorted->pdata[i])),
                s->str);
    }
    fflush(out);
    g_hash_table_remove_all(kinds);
    g_list_free(keys);
    g_ptr_array_free(sorted, true);
    g_string_free(s, true);
}

static gpointer tick(gpointer unused)
{
    while (!stopping) {
        g_usleep(period_ms * 1000);
        g_mutex_lock(&lock);
        flush_block();
        g_mutex_unlock(&lock);
    }
    return NULL;
}

/* The keys of a 64-bit-keyed table, most counted first. */
static GPtrArray *top(GHashTable *t)
{
    GPtrArray *sorted = g_ptr_array_new();
    GHashTableIter it;
    gpointer key;

    g_hash_table_iter_init(&it, t);
    while (g_hash_table_iter_next(&it, &key, NULL)) {
        g_ptr_array_add(sorted, key);
    }
    g_ptr_array_sort_with_data(sorted, by_count, t);
    return sorted;
}

static void plugin_exit(void *unused)
{
    GPtrArray *sorted;
    GString *s = g_string_new(NULL);

    stopping = true;
    g_thread_join(ticker);
    g_mutex_lock(&lock);
    flush_block();
    sorted = top(pcs);
    for (guint i = 0; i < sorted->len && i < 200; i++) {
        uint64_t pk = *(uint64_t *)sorted->pdata[i];
        uint32_t key = (pk >> 44) & 0x3ffff;
        uint64_t pc = pk & 0xfffffffffffULL;

        /* kernel PCs lost their top bits to the key: put them back */
        if (key & (1 << 16)) {
            pc |= 0xfffff00000000000ULL;
        }
        g_string_truncate(s, 0);
        describe(s, key);
        fprintf(out, "pc %zu %s %" PRIx64 "\n",
                count_of(pcs, sorted->pdata[i]), s->str, pc);
    }
    g_ptr_array_free(sorted, true);
    sorted = top(svcs);
    for (guint i = 0; i < sorted->len && i < 300; i++) {
        uint64_t k = *(uint64_t *)sorted->pdata[i];

        fprintf(out, "svc %zu %" PRIu64 " %d\n", count_of(svcs, sorted->pdata[i]),
                k >> 32, (int32_t)(uint32_t)k);
    }
    g_ptr_array_free(sorted, true);
    sorted = top(svc_calls);
    for (guint i = 0; i < sorted->len && i < 300; i++) {
        uint64_t k = *(uint64_t *)sorted->pdata[i];
        /* sign-extend the 24-bit number */
        int32_t nr = (int32_t)((uint32_t)(k >> 40) << 8) >> 8;

        fprintf(out, "svccall %zu %d %" PRIx64 "\n",
                count_of(svc_calls, sorted->pdata[i]), nr, (uint64_t)(k & 0xffffffffffULL));
    }
    g_ptr_array_free(sorted, true);
    fclose(out);
    g_mutex_unlock(&lock);
    g_string_free(s, true);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    const char *path = "excstat.out";

    if (!info->system_emulation) {
        fprintf(stderr, "excstat: system emulation only\n");
        return -1;
    }
    for (int i = 0; i < argc; i++) {
        g_auto(GStrv) kv = g_strsplit(argv[i], "=", 2);
        if (!kv[1]) {
            fprintf(stderr, "excstat: option %s has no value\n", argv[i]);
            return -1;
        }
        if (g_strcmp0(kv[0], "out") == 0) {
            path = argv[i] + 4;
        } else if (g_strcmp0(kv[0], "from") == 0) {
            from_us = g_ascii_strtoull(kv[1], NULL, 10) * 1000;
        } else if (g_strcmp0(kv[0], "period") == 0) {
            period_ms = g_ascii_strtoull(kv[1], NULL, 10);
        } else {
            fprintf(stderr, "excstat: unknown option %s\n", kv[0]);
            return -1;
        }
    }
    out = fopen(path, "w");
    if (!out) {
        fprintf(stderr, "excstat: cannot write %s\n", path);
        return -1;
    }
    vcpus = g_new0(VCPU, info->system.max_vcpus);
    kinds = g_hash_table_new(NULL, NULL);
    pcs = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free);
    start_us = g_get_monotonic_time();
    from_us += start_us;
    svcs = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free);
    svc_calls = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free,
                                      g_free);
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init, NULL);
    qemu_plugin_register_vcpu_discon_cb(id, QEMU_PLUGIN_DISCON_ALL, discon,
                                        NULL);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    ticker = g_thread_new("excstat", tick, NULL);
    return 0;
}
