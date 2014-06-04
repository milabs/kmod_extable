#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/moduleloader.h>
#include <linux/kallsyms.h>
#include <linux/sort.h>

#include "udis86.h"

#define debug(fmt...)			\
	pr_info("[" KBUILD_MODNAME "] " fmt)

typedef typeof(module_free) module_free_t;
module_free_t * pfnModuleFree = NULL;

typedef typeof(module_alloc) module_alloc_t;
module_alloc_t * pfnModuleAlloc = NULL;

typedef typeof(sort_extable) sort_extable_t;
sort_extable_t * pfnSortExtable = NULL;

/*
 * extable helpers
 */

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

/*
 * sample exceptions
 */

static void raise_div0_error(void)
{
	debug("    %s enter\n", __func__);

	{ volatile int x = 1 / 0; (x); }

	debug("    %s leave\n", __func__);
}

static int fixup_div0_error(struct exception_table_entry * entry)
{
	ud_t ud;

	ud_initialize(&ud, BITS_PER_LONG, \
		      UD_VENDOR_ANY, (void *)raise_div0_error, 128);

	while (ud_disassemble(&ud) && ud.mnemonic != UD_Iret) {
		if (ud.mnemonic == UD_Idiv || ud.mnemonic == UD_Iidiv)
		{
			unsigned long address = \
				(unsigned long)raise_div0_error + ud_insn_off(&ud);

			extable_make_insn(entry, address);
			extable_make_fixup(entry, address + ud_insn_len(&ud));

			return 0;
		}
	}

	return -EINVAL;
}

static void raise_undefined_opcode(void)
{
	debug("    %s enter\n", __func__);

	asm volatile ( "ud2" );

	debug("    %s leave\n", __func__);
}

static int fixup_undefined_opcode(struct exception_table_entry * entry)
{
	ud_t ud;

	ud_initialize(&ud, BITS_PER_LONG, \
		      UD_VENDOR_ANY, (void *)raise_undefined_opcode, 128);

	while (ud_disassemble(&ud) && ud.mnemonic != UD_Iret) {
		if (ud.mnemonic == UD_Iud2)
		{
			unsigned long address = \
				(unsigned long)raise_undefined_opcode + ud_insn_off(&ud);

			extable_make_insn(entry, address);
			extable_make_fixup(entry, address + ud_insn_len(&ud));

			return 0;
		}
	}

	return -EINVAL;
}

static void raise_general_protection(void)
{
	debug("    %s enter\n", __func__);

	((int *)0xffff800000000000)[0] = 0xdeadbeef;

	debug("    %s leave\n", __func__);
}

static int fixup_general_protection(struct exception_table_entry * entry)
{
	ud_t ud;

	ud_initialize(&ud, BITS_PER_LONG, \
		      UD_VENDOR_ANY, (void *)raise_general_protection, 128);

	while (ud_disassemble(&ud) && ud.mnemonic != UD_Iret) {
		if (ud.mnemonic == UD_Imov && \
		    ud.operand[1].type == UD_OP_REG && ud.operand[0].type == UD_OP_MEM)
		{
			unsigned long address = \
				(unsigned long)raise_general_protection + ud_insn_off(&ud);

			extable_make_insn(entry, address);
			extable_make_fixup(entry, address + ud_insn_len(&ud));

			return 0;
		}
	}

	return -EINVAL;
}

static void raise_page_fault(void)
{
	debug("    %s enter\n", __func__);

	((int *)0)[0] = 0xdeadbeef;

	debug("    %s leave\n", __func__);
}

static int fixup_page_fault(struct exception_table_entry * entry)
{
	ud_t ud;

	ud_initialize(&ud, BITS_PER_LONG, \
		      UD_VENDOR_ANY, (void *)raise_page_fault, 128);

	while (ud_disassemble(&ud) && ud.mnemonic != UD_Iret) {
		if (ud.mnemonic == UD_Imov && \
		    ud.operand[0].type == UD_OP_MEM && ud.operand[1].type == UD_OP_IMM)
		{
			unsigned long address = \
				(unsigned long)raise_page_fault + ud_insn_off(&ud);

			extable_make_insn(entry, address);
			extable_make_fixup(entry, address + ud_insn_len(&ud));

			return 0;
		}
	}

	return -EINVAL;
}

struct {
	const char * name;
	int (* fixup)(struct exception_table_entry *);
	void (* raise)(void);

} exceptions[] = {
	{
		.name = "0x00 - div0 error (#DE)",
		.fixup = fixup_div0_error,
		.raise = raise_div0_error,
	},
	{
		.name = "0x06 - undefined opcode (#UD)",
		.fixup = fixup_undefined_opcode,
		.raise = raise_undefined_opcode,
	},
	{
		.name = "0x0D - general protection (#GP)",
		.fixup = fixup_general_protection,
		.raise = raise_general_protection,
	},
	{
		.name = "0x14 - page fault (#PF)",
		.fixup = fixup_page_fault,
		.raise = raise_page_fault,
	},
};

static int build_extable(void)
{
	int i, num_exentries = 0;
	struct exception_table_entry * extable;

	extable = (void *)pfnModuleAlloc(sizeof(*extable) * ARRAY_SIZE(exceptions));

	if (extable == NULL) {
		debug("Memory allocation failed\n");
		return -ENOMEM;
	}

	debug("Building extable for:\n");

	for (i = 0; i < ARRAY_SIZE(exceptions); i++) {

		if (exceptions[i].fixup(&extable[num_exentries])) {
			exceptions[i].raise = NULL;
		} else {
			num_exentries++;
		}

		debug("  %s%s\n", exceptions[i].name, \
		      exceptions[i].raise ? "" : " (failed)");
	}

	debug("Building extable succeeded for %d/%lu items\n", \
	      num_exentries, ARRAY_SIZE(exceptions));

	pfnSortExtable(extable, extable + num_exentries);

	THIS_MODULE->extable = extable;
	THIS_MODULE->num_exentries = num_exentries;

	return 0;
}

static void flush_extable(void)
{
	THIS_MODULE->num_exentries = 0;
	pfnModuleFree(THIS_MODULE, THIS_MODULE->extable);
	THIS_MODULE->extable = NULL;
}

void try_to_crash_the_system(void)
{
	int i;

	debug("Trying to crash the system with:\n");

	for (i = 0; i < ARRAY_SIZE(exceptions); i++) {
		if (!exceptions[i].raise)
			continue;

		debug("  %s\n", exceptions[i].name);

		exceptions[i].raise();
	}

	debug("Congratulations, your system still alive\n");
}

int kallsyms_callback(void * data, const char * name, struct module * module, unsigned long address)
{
	if (module)
		return 0;

	if (strcmp(name, "module_free") == 0) {
		pfnModuleFree = (module_free_t *)address;
	} else if (strcmp(name, "module_alloc") == 0) {
		pfnModuleAlloc = (module_alloc_t *)address;
	} else if (strcmp(name, "sort_extable") == 0) {
		pfnSortExtable = (sort_extable_t *)address;
	}

	return 0;
}

int init_module(void)
{
	kallsyms_on_each_symbol(kallsyms_callback, NULL);

	if (!pfnModuleFree || !pfnModuleAlloc || !pfnSortExtable) {
		return -EINVAL;
	}

	if (build_extable())
		return -ENOMEM;

	try_to_crash_the_system();

	flush_extable();

	return -EAGAIN;
}

void cleanup_module(void)
{
	flush_extable();
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ilya V. Matveychikov <i.matveychikov@milabs.ru>");
MODULE_DESCRIPTION("Linux kernel exception handling exmple");
