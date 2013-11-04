#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/moduleloader.h>
#include <linux/kallsyms.h>

#include "udis86.h"

#define debug(fmt...)			\
	pr_info("[" KBUILD_MODNAME "] " fmt)

typedef typeof(module_free) module_free_t;
module_free_t * pfnModuleFree = NULL;

typedef typeof(module_alloc) module_alloc_t;
module_alloc_t * pfnModuleAlloc = NULL;

static void raise_div0_exception(void)
{
	debug("  %s enter\n", __func__);

	{ volatile int x = 1 / 0; (x); }

	debug("  %s leave\n", __func__);
}

static void raise_null_pointer_dereference(void)
{
	debug("  %s enter\n", __func__);

	((int *)0)[0] = 0xdeadbeef;

	debug("  %s leave\n", __func__);
}

static void extable_make_insn(struct exception_table_entry * entry, unsigned long addr)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
	entry->insn = (unsigned int)((addr - (unsigned long)&entry->insn));
#else
	entry->insn = addr;
#endif
}

static void extable_make_fixup(struct exception_table_entry * entry, unsigned long addr)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
	entry->fixup = (unsigned int)((addr - (unsigned long)&entry->fixup));
#else
	entry->fixup = addr;
#endif
}

static void build_extable(void)
{
	ud_t ud;

	int num_exentries = 0;
	struct exception_table_entry * entry;

	entry = (struct exception_table_entry *)pfnModuleAlloc(sizeof(*entry) * 2);

	/* raise_div0_exception */

	ud_initialize(&ud, BITS_PER_LONG, UD_VENDOR_ANY, \
		      (void *)raise_div0_exception, 128);

	while (ud_disassemble(&ud) && ud.mnemonic != UD_Iret) {
		if (ud.mnemonic == UD_Idiv || ud.mnemonic == UD_Iidiv)
		{
			struct exception_table_entry * this = &entry[num_exentries++];

			unsigned long address = \
				(unsigned long)raise_div0_exception + ud_insn_off(&ud);

			extable_make_insn(this, address);
			extable_make_fixup(this, address + ud_insn_len(&ud));

			break;
		}
	}

	/* raise_null_pointer_dereference */

	ud_initialize(&ud, BITS_PER_LONG, UD_VENDOR_ANY, \
		      (void *)raise_null_pointer_dereference, 128);

	while (ud_disassemble(&ud) && ud.mnemonic != UD_Iret) {
		if (ud.mnemonic == UD_Imov && \
		    ud.operand[0].type == UD_OP_MEM && ud.operand[1].type == UD_OP_IMM)
		{
			struct exception_table_entry * this = &entry[num_exentries++];

			unsigned long address = \
				(unsigned long)raise_null_pointer_dereference + ud_insn_off(&ud);

			extable_make_insn(this, address);
			extable_make_fixup(this, address + ud_insn_len(&ud));

			break;
		}
	}

	THIS_MODULE->extable = entry;
	THIS_MODULE->num_exentries = num_exentries;
}

static void flush_extable(void)
{
	THIS_MODULE->num_exentries = 0;
	pfnModuleFree(THIS_MODULE, THIS_MODULE->extable);
	THIS_MODULE->extable = NULL;
}

static int test_extable(void)
{
	debug("test for extable\n");

	build_extable();

	raise_div0_exception();
	raise_null_pointer_dereference();

	flush_extable();

	debug("test passed\n");

	return 0;
}

int kallsyms_callback(void * data, const char * name, struct module * module, unsigned long address)
{
	if (module)
		return 0;

	if (strcmp(name, "module_free") == 0) {
		pfnModuleFree = (module_free_t *)address;
	} else if (strcmp(name, "module_alloc") == 0) {
		pfnModuleAlloc = (module_alloc_t *)address;
	}

	return 0;
}

int init_module(void)
{
	kallsyms_on_each_symbol(kallsyms_callback, NULL);

	if (!pfnModuleFree || !pfnModuleAlloc) {
		return -EINVAL;
	}

	debug("found module_free @ %pK\n", pfnModuleFree);
	debug("found module_alloc @ %pK\n", pfnModuleAlloc);

	if (test_extable())
		return -EINVAL;

	debug("completed\n");

	return -EAGAIN;
}

void cleanup_module(void)
{
	flush_extable();
}

MODULE_LICENSE	("GPL");
MODULE_AUTHOR	("Ilya V. Matveychikov <matvejchikov@gmail.com>");
