#include "infra/btf_parser.h"

#if defined(MODULE) && defined(CONFIG_DEBUG_INFO_BTF)
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/string.h>

#include "klog.h"
#include "infra/symbol_resolver.h"

static const struct btf *(*btf_vmlinux_fn)(void);
static s32 (*btf_find_by_name_kind_fn)(const struct btf *, const char *, u32);
static const struct btf_type *(*btf_type_by_id_fn)(const struct btf *, u32);
static const char *(*btf_name_by_offset_fn)(const struct btf *, u32);
static const struct btf_type *(*btf_type_skip_modifiers_fn)(const struct btf *, u32, u32 *);

static int btf_parser_resolve(void)
{
    static const char *const names[] = {
        "bpf_get_btf_vmlinux", "btf_find_by_name_kind", "btf_type_by_id",
        "btf_name_by_offset", "btf_type_skip_modifiers",
    };
    unsigned long addrs[ARRAY_SIZE(names)] = {};
    int ret;

    if (btf_vmlinux_fn)
        return 0;
    ret = ksu_lookup_kernel_symbols(names, addrs, ARRAY_SIZE(names));
    if (ret < 0)
        return ret;
    btf_vmlinux_fn = (void *)addrs[0];
    btf_find_by_name_kind_fn = (void *)addrs[1];
    btf_type_by_id_fn = (void *)addrs[2];
    btf_name_by_offset_fn = (void *)addrs[3];
    btf_type_skip_modifiers_fn = (void *)addrs[4];
    return 0;
}

int ksu_btf_field(const char *structure, const char *member, u32 kind, u32 size, struct ksu_btf_field *field)
{
    int res = btf_parser_resolve();
    if (res < 0) { pr_err("BTF: symbol resolve failed %d\n", res); return res; }
    const struct btf *btf;
    const struct btf_type *type;
    const struct btf_member *m;
    s32 id;
    u32 i;

    pr_info("BTF: acquiring vmlinux metadata for %s.%s\n", structure, member);
    btf = btf_vmlinux_fn();
    if (IS_ERR_OR_NULL(btf)) {
        pr_err("BTF: vmlinux metadata unavailable (%ld)\n", btf ? PTR_ERR(btf) : -ENOENT);
        return btf ? PTR_ERR(btf) : -ENOENT;
    }

    pr_info("BTF: looking up struct %s\n", structure);
    id = btf_find_by_name_kind_fn(btf, structure, BTF_KIND_STRUCT);
    if (id < 0)
        return id;
    type = btf_type_by_id_fn(btf, id);
    if (!type)
        return -EINVAL;

    for_each_member (i, type, m) {
        const struct btf_type *member_type;
        const char *name = btf_name_by_offset_fn(btf, m->name_off);
        u32 bits, bytes, bitfield_size;

        if (!name)
            return -EINVAL;
        if (strcmp(name, member))
            continue;
        bits = m->offset;
        bitfield_size = 0;
        if (BTF_INFO_KFLAG(type->info)) {
            bitfield_size = BTF_MEMBER_BITFIELD_SIZE(bits);
            bits = BTF_MEMBER_BIT_OFFSET(bits);
        }
        bytes = bits / 8;
        if (bitfield_size || !size || (bits & 7) || bytes % size || bytes > type->size || size > type->size - bytes)
            return -EINVAL;
        member_type = btf_type_skip_modifiers_fn(btf, m->type, NULL);
        if (!member_type || BTF_INFO_KIND(member_type->info) != kind)
            return -EINVAL;
        if (kind == BTF_KIND_INT) {
            u32 info = *(const u32 *)(member_type + 1);

            if (member_type->size != size || BTF_INT_OFFSET(info) || BTF_INT_BITS(info) != size * 8 ||
                (BTF_INT_ENCODING(info) & (BTF_INT_CHAR | BTF_INT_BOOL)))
                return -EINVAL;
        } else if (kind != BTF_KIND_PTR || size != sizeof(void *)) {
            return -EINVAL;
        }
        field->offset = bytes;
        field->struct_size = type->size;
        pr_info("BTF: resolved %s.%s at %u, struct size %u\n", structure, member, bytes, type->size);
        return 0;
    }
    return -ENOENT;
}
#endif
