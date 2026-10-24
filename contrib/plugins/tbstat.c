/*
 * Copyright (C) 2026, mKonic <mkonic676@gmail.com>
 *
 * Count translations: how many blocks were translated, and how many of them
 * were code already translated before (the same guest physical address),
 * by virtual address range. Each period a line of the output file:
 *
 *   MSEC TRANSLATIONS AGAIN DISTINCT VADDRS
 *
 * TRANSLATIONS and AGAIN since the last line, DISTINCT in total and VADDRS
 * the distinct virtual addresses among them; and at exit
 * the physical addresses translated most often:
 *
 *   again COUNT VADDR INSNS
 *
 * and how many blocks were translated once, twice and so on:
 *
 *   times N BLOCKS
 *
 * Arguments:
 *   out=PATH       where the counts go (default tbstat.out)
 *   period=MSEC    how often a line is written (default 5000)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <glib.h>
#include <inttypes.h>
#include <stdio.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

typedef struct {
    uint64_t vaddr;
    gsize count;
    size_t size;
} Seen;

static GHashTable *seen, *vaddrs;
static GMutex lock;
static FILE *out;
static GThread *ticker;
static volatile bool stopping;
static uint64_t period_ms = 5000;
static gint64 start_us;
static uint64_t translations, again;

static void tb_trans(struct qemu_plugin_tb *tb, void *unused)
{
    struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, 0);
    uint64_t paddr = (uintptr_t)qemu_plugin_insn_haddr(insn);
    Seen *s;

    g_mutex_lock(&lock);
    translations++;
    s = g_hash_table_lookup(seen, &paddr);
    if (s) {
        again++;
        s->count++;
    } else {
        s = g_new0(Seen, 1);
        s->vaddr = qemu_plugin_tb_vaddr(tb);
        s->count = 1;
        s->size = qemu_plugin_tb_n_insns(tb);
        g_hash_table_insert(seen, g_memdup2(&paddr, sizeof(paddr)), s);
        if (!g_hash_table_contains(vaddrs, &s->vaddr)) {
            g_hash_table_add(vaddrs, g_memdup2(&s->vaddr, sizeof(s->vaddr)));
        }
    }
    g_mutex_unlock(&lock);
}

static void line(void)
{
    fprintf(out, "%" PRId64 " %" PRIu64 " %" PRIu64 " %u %u\n",
            (g_get_monotonic_time() - start_us) / 1000, translations, again,
            g_hash_table_size(seen), g_hash_table_size(vaddrs));
    fflush(out);
    translations = again = 0;
}

static gpointer tick(gpointer unused)
{
    while (!stopping) {
        g_usleep(period_ms * 1000);
        g_mutex_lock(&lock);
        line();
        g_mutex_unlock(&lock);
    }
    return NULL;
}

static gint by_count(gconstpointer a, gconstpointer b)
{
    gsize ca = (*(Seen **)a)->count, cb = (*(Seen **)b)->count;
    return ca < cb ? 1 : ca > cb ? -1 : 0;
}

static void plugin_exit(void *unused)
{
    GPtrArray *all = g_ptr_array_new();
    GHashTableIter it;
    gpointer key, value;
    GHashTable *by_count_hist = g_hash_table_new(NULL, NULL);

    stopping = true;
    g_thread_join(ticker);
    g_mutex_lock(&lock);
    line();
    g_hash_table_iter_init(&it, seen);
    while (g_hash_table_iter_next(&it, &key, &value)) {
        Seen *s = value;
        gsize n = MIN(s->count, 64);

        g_ptr_array_add(all, value);
        g_hash_table_insert(by_count_hist, GSIZE_TO_POINTER(n),
                            GSIZE_TO_POINTER(GPOINTER_TO_SIZE(
                                g_hash_table_lookup(by_count_hist,
                                                    GSIZE_TO_POINTER(n))) + 1));
    }
    for (gsize n = 1; n <= 64; n++) {
        gsize c = GPOINTER_TO_SIZE(g_hash_table_lookup(by_count_hist,
                                                       GSIZE_TO_POINTER(n)));
        if (c) {
            fprintf(out, "times %zu%s %zu\n", n, n == 64 ? "+" : "", c);
        }
    }
    g_ptr_array_sort(all, by_count);
    for (guint i = 0; i < all->len && i < 300; i++) {
        Seen *s = all->pdata[i];
        fprintf(out, "again %zu %" PRIx64 " %zu\n", s->count, s->vaddr,
                s->size);
    }
    fclose(out);
    g_mutex_unlock(&lock);
    g_ptr_array_free(all, true);
    g_hash_table_destroy(by_count_hist);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    const char *path = "tbstat.out";

    for (int i = 0; i < argc; i++) {
        g_auto(GStrv) kv = g_strsplit(argv[i], "=", 2);
        if (!kv[1]) {
            fprintf(stderr, "tbstat: option %s has no value\n", argv[i]);
            return -1;
        }
        if (g_strcmp0(kv[0], "out") == 0) {
            path = argv[i] + 4;
        } else if (g_strcmp0(kv[0], "period") == 0) {
            period_ms = g_ascii_strtoull(kv[1], NULL, 10);
        } else {
            fprintf(stderr, "tbstat: unknown option %s\n", kv[0]);
            return -1;
        }
    }
    out = fopen(path, "w");
    if (!out) {
        fprintf(stderr, "tbstat: cannot write %s\n", path);
        return -1;
    }
    seen = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free);
    vaddrs = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);
    start_us = g_get_monotonic_time();
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans, NULL);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    ticker = g_thread_new("tbstat", tick, NULL);
    return 0;
}
