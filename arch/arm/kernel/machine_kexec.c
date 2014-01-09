/*
 * machine_kexec.c - handle transition of Linux booting another kernel
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/kexec.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/kallsyms.h>

#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/mmu_context.h>
#include <asm/cacheflush.h>
#include <asm/mach-types.h>
#include <asm/system_misc.h>
#include <asm/outercache.h>

extern const unsigned char relocate_new_kernel[];
extern const unsigned int relocate_new_kernel_size;

void (*kexec_setup_mm_for_reboot)(void);
void (*kexec_gic_raise_softirq)(const struct cpumask *mask, unsigned int irq);
int (*kexec_msm_pm_wait_cpu_shutdown)(unsigned int cpu);

extern unsigned long kexec_start_address;
extern unsigned long kexec_indirection_page;
extern unsigned long kexec_mach_type;
extern unsigned long kexec_boot_atags;

void kexec_cpu_v7_proc_fin(void);

//static atomic_t waiting_for_crash_ipi;

extern void kexec_call_with_stack(void (*fn)(void *), void *arg, void *sp);
typedef void (*phys_reset_t)(unsigned long);

static void kexec_idmap_add_pmd(pud_t *pud, unsigned long addr, unsigned long end,
	unsigned long prot)
{
	pmd_t *pmd = pmd_offset(pud, addr);

	addr = (addr & PMD_MASK) | prot;
	pmd[0] = __pmd(addr);
	addr += SECTION_SIZE;
	pmd[1] = __pmd(addr);
	flush_pmd_entry(pmd);
}

static void kexec_idmap_add_pud(pgd_t *pgd, unsigned long addr, unsigned long end,
	unsigned long prot)
{
	pud_t *pud = pud_offset(pgd, addr);
	unsigned long next;

	do {
		next = pud_addr_end(addr, end);
		kexec_idmap_add_pmd(pud, addr, next, prot);
	} while (pud++, addr = next, addr != end);
}

void kexec_identity_mapping_add(pgd_t *pgd, unsigned long addr, unsigned long end)
{
	unsigned long prot, next;

	prot = PMD_TYPE_SECT | PMD_SECT_AP_WRITE | PMD_SECT_AF;
//	if (cpu_architecture() <= CPU_ARCH_ARMv5TEJ && !cpu_is_xscale())
//		prot |= PMD_BIT4;

	pgd += pgd_index(addr);
	do {
		next = pgd_addr_end(addr, end);
		kexec_idmap_add_pud(pgd, addr, next, prot);
		// HASH: flush
//		local_flush_tlb_all();
	} while (pgd++, addr = next, addr != end);
	printk(KERN_EMERG "MKEXEC: end mappings end==0x%08lx\n", end);
}

/*
 * In order to soft-boot, we need to insert a 1:1 mapping in place of
 * the user-mode pages.  This will then ensure that we have predictable
 * results when turning the mmu off
 */
void kexec_identity_map(unsigned long phys_addr)
{
	pgd_t *pgd;
	pmd_t *pmd;

	int prot = PMD_SECT_AP_WRITE | PMD_SECT_AP_READ | PMD_TYPE_SECT;
	unsigned long phys = phys_addr & PMD_MASK;

//	if (cpu_architecture() <= CPU_ARCH_ARMv5TEJ && !cpu_is_xscale())
//		prot |= PMD_BIT4;

	/*
	 * We need to access to user-mode page tables here. For kernel threads
	 * we don't have any user-mode mappings so we use the context that we
	 * "borrowed".
	 */

	pgd = pgd_offset(current->active_mm, phys);
	pmd = pmd_offset(pud_offset(pgd, phys), phys);
	pmd[0] = __pmd(phys | prot);
	pmd[1] = __pmd((phys + (1 << (PGDIR_SHIFT - 1))) | prot);

	flush_pmd_entry(pmd);

	local_flush_tlb_all();
}

/*
 * A temporary stack to use for CPU reset. This is static so that we
 * don't clobber it with the identity mapping. When running with this
 * stack, any references to the current task *will not work* so you
 * should really do as little as possible before jumping to your reset
 * code.
 */
static u64 soft_restart_stack[16];

#define MSM_DEBUG_UART_PHYS	0x16440000
#define UART_CSR      		(*(volatile uint32_t *)(MSM_DEBUG_UART_PHYS + 0x08))
#define UART_TF       		(*(volatile uint32_t *)(MSM_DEBUG_UART_PHYS + 0x0c))

#define SERIAL_WRITE(c)		while (UART_CSR == 0) {}; UART_TF = c;

static void __soft_restart(void *addr)
{
	phys_reset_t phys_reset = (phys_reset_t)addr;

	/* Clean and invalidate caches */
	flush_cache_all();

	/* Turn off caching */
//	cpu_proc_fin();
	kexec_cpu_v7_proc_fin();

	/* Push out any further dirty data, and ensure cache is empty */
	flush_cache_all();

	/* Push out the dirty data from external caches */
	outer_disable();

	/* Switch to the identity mapping. */
//	phys_reset = (phys_reset_t)(unsigned long)virt_to_phys(kexec_cpu_v7_reset);
//	phys_reset((unsigned long)addr);
	phys_reset(0);

	/* Should never get here. */
	BUG();
}

void soft_restart(unsigned long addr)
{
	u64 *stack = soft_restart_stack + ARRAY_SIZE(soft_restart_stack);

	/* Disable the L2 if we're the last man standing. */
	if (num_online_cpus() == 1) {
		printk(KERN_EMERG "MKEXEC: outer_flush_all\n");
		outer_flush_all();
		printk(KERN_EMERG "MKEXEC: outer_disable\n");
		outer_disable();
	}

	printk(KERN_EMERG "MKEXEC: kexec_identity_mapping_add (TASK_SIZE=0x%8lx, PAGE_OFFSET=0x%8lx\n", TASK_SIZE, PAGE_OFFSET);
	/* http://review.omapzoom.org/#/c/32213/ */
	kexec_identity_mapping_add(current->active_mm->pgd, 0, TASK_SIZE);
	kexec_identity_mapping_add(current->active_mm->pgd, TASK_SIZE, PAGE_OFFSET);

	printk(KERN_EMERG "MKEXEC: kexec_setup_mm_for_reboot\n");
	/* Take out a flat memory mapping. */
	kexec_setup_mm_for_reboot();

	printk(KERN_EMERG "MKEXEC: kexec_call_with_stack (kexec_call_with_stack=0x%8lx, __soft_reset=0x%8lx, addr=0x%8lx, stack=0x%8lx)\n", (unsigned long)kexec_call_with_stack, (unsigned long)__soft_restart, addr, (unsigned long)stack);
	/* Change to the new stack and continue with the reset. */
	kexec_call_with_stack(__soft_restart, (void *)addr, (void *)stack);

	printk(KERN_EMERG "MKEXEC: ARRRRGGGGHH! NOT SUPPOSED TO BE HERE.\n");
	/* Should never get here. */
	BUG();
}

/*
 * Provide a dummy crash_notes definition while crash dump arrives to arm.
 * This prevents breakage of crash_notes attribute in kernel/ksysfs.c.
 */

int machine_kexec_prepare(struct kimage *image)
{
	return 0;
}
EXPORT_SYMBOL(machine_kexec_prepare);

void machine_kexec_cleanup(struct kimage *image)
{
}
EXPORT_SYMBOL(machine_kexec_cleanup);

enum ipi_msg_type {
	IPI_CPU_START = 1,
	IPI_TIMER = 2,
	IPI_RESCHEDULE,
	IPI_CALL_FUNC,
	IPI_CALL_FUNC_SINGLE,
	IPI_CPU_STOP,
	IPI_CPU_BACKTRACE,
};

static void kexec_smp_kill_cpus(cpumask_t *mask)
{
	unsigned int cpu;
	for_each_cpu(cpu, mask) {
		kexec_msm_pm_wait_cpu_shutdown(cpu);
	}
}

void machine_shutdown(void)
{
	unsigned long timeout;
	struct cpumask mask;

	kexec_gic_raise_softirq = (void *)kallsyms_lookup_name("gic_raise_softirq");
	kexec_msm_pm_wait_cpu_shutdown = (void *)kallsyms_lookup_name("msm_pm_wait_cpu_shutdown");
	if (!kexec_msm_pm_wait_cpu_shutdown) {
		printk(KERN_EMERG "MKEXEC: msm_pm_wait_cpu_shutdown NOT FOUND!\n");
		return;
	}

	if (kexec_gic_raise_softirq) {
		printk(KERN_EMERG "MKEXEC: found gic_raise_softirq: %p\n", kexec_gic_raise_softirq);

		cpumask_copy(&mask, cpu_online_mask);
		cpumask_clear_cpu(smp_processor_id(), &mask);
		if (!cpumask_empty(&mask)) {
			printk(KERN_EMERG "MKEXEC: Sending STOP to extra CPUs ...\n");
			kexec_gic_raise_softirq(&mask, IPI_CPU_STOP);
		}

		/* Wait up to five seconds for other CPUs to stop */
		timeout = USEC_PER_SEC;
		printk(KERN_EMERG "MKEXEC: waiting for CPUs ...(%lu)\n", timeout);
		while (num_online_cpus() > 1 && timeout--)
			udelay(1);

		if (num_online_cpus() > 1)
			pr_warning("MKEXEC: SMP: failed to stop secondary CPUs\n");

		kexec_smp_kill_cpus(&mask);
	}
	else {
		pr_warning("MKEXEC: SMP: failed to stop secondary CPUs\n");
	}
}
EXPORT_SYMBOL(machine_shutdown);

void machine_crash_nonpanic_core(void *unused)
{
#if 0
	struct pt_regs regs;

	crash_setup_regs(&regs, NULL);
	printk(KERN_DEBUG "CPU %u will stop doing anything useful since another CPU has crashed\n",
	       smp_processor_id());
	crash_save_cpu(&regs, smp_processor_id());
	flush_cache_all();

	atomic_dec(&waiting_for_crash_ipi);
	while (1)
		cpu_relax();
#endif
}

#if 0
static void machine_kexec_mask_interrupts(void)
{
	unsigned int i;
	struct irq_desc *desc;

	for_each_irq_desc(i, desc) {
		struct irq_chip *chip;

		chip = irq_desc_get_chip(desc);
		if (!chip)
			continue;

		if (chip->irq_eoi && irqd_irq_inprogress(&desc->irq_data))
			chip->irq_eoi(&desc->irq_data);

		if (chip->irq_mask)
			chip->irq_mask(&desc->irq_data);

		if (chip->irq_disable && !irqd_irq_disabled(&desc->irq_data))
			chip->irq_disable(&desc->irq_data);
	}
}
#endif

void machine_crash_shutdown(struct pt_regs *regs)
{
#if 0
	unsigned long msecs;

	local_irq_disable();

	atomic_set(&waiting_for_crash_ipi, num_online_cpus() - 1);
	smp_call_function(machine_crash_nonpanic_core, NULL, false);
	msecs = 1000; /* Wait at most a second for the other cpus to stop */
	while ((atomic_read(&waiting_for_crash_ipi) > 0) && msecs) {
		mdelay(1);
		msecs--;
	}
	if (atomic_read(&waiting_for_crash_ipi) > 0)
		printk(KERN_WARNING "Non-crashing CPUs did not react to IPI\n");

	crash_save_cpu(regs, smp_processor_id());
	machine_kexec_mask_interrupts();

	printk(KERN_INFO "Loading crashdump kernel...\n");
#endif
}

/*
 * Function pointer to optional machine-specific reinitialization
 */
void (*kexec_reinit)(void);

void machine_kexec(struct kimage *image)
{
	unsigned long page_list;
	unsigned long reboot_code_buffer_phys;
	void *reboot_code_buffer;


	page_list = image->head & PAGE_MASK;

	/* we need both effective and real address here */
	reboot_code_buffer_phys =
	    page_to_pfn(image->control_code_page) << PAGE_SHIFT;
	reboot_code_buffer = page_address(image->control_code_page);

	printk(KERN_EMERG "MKEXEC: va: %08x\n", (int)reboot_code_buffer);
	printk(KERN_EMERG "MKEXEC: pa: %08x\n", (int)reboot_code_buffer_phys);

	/* Prepare parameters for reboot_code_buffer*/
	kexec_start_address = image->start;
	kexec_indirection_page = page_list;
	kexec_mach_type = machine_arch_type;
	kexec_boot_atags = image->start - KEXEC_ARM_ZIMAGE_OFFSET + KEXEC_ARM_ATAGS_OFFSET;

	printk(KERN_EMERG "MKEXEC: kexec_start_address: %08lx\n", kexec_start_address);
	printk(KERN_EMERG "MKEXEC: kexec_indirection_page: %08lx\n", kexec_indirection_page);
	printk(KERN_EMERG "MKEXEC: kexec_mach_type: %08lx\n", kexec_mach_type);
	printk(KERN_EMERG "MKEXEC: kexec_boot_atags: %08lx\n", kexec_boot_atags);

	kexec_identity_map(reboot_code_buffer_phys);

	/* copy our kernel relocation code to the control code page */
	printk(KERN_EMERG "MKEXEC: copy relocate code: addr=0x%08lx, len==%d\n", (long unsigned int)reboot_code_buffer, relocate_new_kernel_size);
	memcpy(reboot_code_buffer,
	       relocate_new_kernel, relocate_new_kernel_size);


	printk(KERN_EMERG "MKEXEC: flush_icache_range\n");
	flush_icache_range((unsigned long) reboot_code_buffer,
			   (unsigned long) reboot_code_buffer + KEXEC_CONTROL_PAGE_SIZE);

	printk(KERN_EMERG "MKEXEC: kexec_reinit\n");
	if (kexec_reinit)
		kexec_reinit();

	printk(KERN_EMERG "MKEXEC: soft_restart\n");
	soft_restart(reboot_code_buffer_phys);
}
EXPORT_SYMBOL(machine_kexec);

static int __init arm_kexec_init(void)
{
	void (*set_cpu_online_ptr)(unsigned int cpu, bool online) = (void *)kallsyms_lookup_name("set_cpu_online");
	void (*set_cpu_present_ptr)(unsigned int cpu, bool present) = (void *)kallsyms_lookup_name("set_cpu_present");
	void (*set_cpu_possible_ptr)(unsigned int cpu, bool possible) = (void *)kallsyms_lookup_name("set_cpu_possible");
	int (*disable_nonboot_cpus)(void) = (void *)kallsyms_lookup_name("disable_nonboot_cpus");
	int nbcval = 0;
	nbcval = disable_nonboot_cpus();
	if (nbcval < 0)
		printk(KERN_INFO "MKEXEC: !!!WARNING!!! disable_nonboot_cpus have FAILED!\n \
				  Continuing to boot anyway: something can go wrong!\n");

	kexec_setup_mm_for_reboot = (void *)kallsyms_lookup_name("setup_mm_for_reboot");
	if (kexec_setup_mm_for_reboot == NULL)
		printk(KERN_EMERG "MKEXEC: !!!ERROR!!! FAILED TO FIND 'setup_mm_for_reboot'!\n");

	set_cpu_online_ptr(1, false);
	set_cpu_present_ptr(1, false);
	set_cpu_possible_ptr(1, false);

	set_cpu_online_ptr(2, false);
	set_cpu_present_ptr(2, false);
	set_cpu_possible_ptr(2, false);

	set_cpu_online_ptr(2, false);
	set_cpu_present_ptr(2, false);
	set_cpu_possible_ptr(2, false);

	return 0;
}

static void __exit arm_kexec_exit(void)
{
}

module_init(arm_kexec_init);
module_exit(arm_kexec_exit);

MODULE_LICENSE("GPL");
