#include <hooks.h>
#include <mmio.h>
#include <debug.h>

enum {
    TRAMP_STR_LR  = 0xF81F0FFE,
    TRAMP_LDR_X16 = 0x58000090,
    TRAMP_BLR_X16 = 0xD63F0200,
    TRAMP_LDR_LR  = 0xF84107FE,
    TRAMP_RET     = 0xD65F03C0,
};

bool hook_install(const hook_t *hook) {
    if (!hook || !hook->handler)
        return false;

    uint32_t bl_insn = encode_bl(hook->site, hook->trampoline);
    if (bl_insn == 0) {
        printf("%-30s out of range\n", hook->name);
        return false;
    }

    uintptr_t target = (uintptr_t)hook->handler;

    writel(TRAMP_STR_LR,                    hook->trampoline + 0x00);
    writel(TRAMP_LDR_X16,                   hook->trampoline + 0x04);
    writel(TRAMP_BLR_X16,                   hook->trampoline + 0x08);
    writel(TRAMP_LDR_LR,                    hook->trampoline + 0x0C);
    writel(TRAMP_RET,                       hook->trampoline + 0x10);
    writel((uint32_t)(target & 0xFFFFFFFF), hook->trampoline + 0x14);
    writel((uint32_t)(target >> 32),        hook->trampoline + 0x18);

    writel(bl_insn, hook->site);

    flush_dcache_range(hook->trampoline, HOOK_TRAMPOLINE_SIZE);
    flush_dcache_range(hook->site, sizeof(uint32_t));
    invalidate_icache();

    printf("%-30s 0x%08x -> 0x%08x\n", hook->name, hook->site, hook->trampoline);
    return true;
}

static void da1_load_hook(void) {
    static int i = 0;
    i++;

    if (i != 2)
        return;

    /* force log level to DEBUG regardless of host request */
    writel(0x52800028, 0x40200EC4);
    
    flush_dcache_range(0x40200EC4, 4);
    invalidate_icache();
}

static const hook_t hooks[] = {
    HOOK(0x02047F70, 0x0206C49C, da1_load_hook, "Hook after DA1 load"),
};

void hook_install_all(void) {
    for (size_t i = 0; i < ARRAY_SIZE(hooks); i++)
        hook_install(&hooks[i]);
}