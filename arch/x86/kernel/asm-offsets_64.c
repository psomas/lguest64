#include <asm/ia32.h>

#include <linux/lguest.h>
#include "../../../drivers/lguest/lg.h"

#define __NO_STUBS 1
#undef __SYSCALL
#undef _ASM_X86_UNISTD_64_H
#define __SYSCALL(nr, sym) [nr] = 1,
static char syscalls[] = {
#include <asm/unistd.h>
};

int main(void)
{
#ifdef CONFIG_PARAVIRT
	OFFSET(PV_IRQ_adjust_exception_frame, pv_irq_ops, adjust_exception_frame);
	OFFSET(PV_CPU_usergs_sysret32, pv_cpu_ops, usergs_sysret32);
	OFFSET(PV_CPU_usergs_sysret64, pv_cpu_ops, usergs_sysret64);
	OFFSET(PV_CPU_swapgs, pv_cpu_ops, swapgs);
	BLANK();
#endif

#ifdef CONFIG_IA32_EMULATION
	OFFSET(TI_sysenter_return, thread_info, sysenter_return);
	BLANK();

#define ENTRY(entry) OFFSET(IA32_SIGCONTEXT_ ## entry, sigcontext_ia32, entry)
	ENTRY(ax);
	ENTRY(bx);
	ENTRY(cx);
	ENTRY(dx);
	ENTRY(si);
	ENTRY(di);
	ENTRY(bp);
	ENTRY(sp);
	ENTRY(ip);
	BLANK();
#undef ENTRY

	OFFSET(IA32_RT_SIGFRAME_sigcontext, rt_sigframe_ia32, uc.uc_mcontext);
	BLANK();
#endif

#define ENTRY(entry) OFFSET(pt_regs_ ## entry, pt_regs, entry)
	ENTRY(bx);
	ENTRY(bx);
	ENTRY(cx);
	ENTRY(dx);
	ENTRY(sp);
	ENTRY(bp);
	ENTRY(si);
	ENTRY(di);
	ENTRY(r8);
	ENTRY(r9);
	ENTRY(r10);
	ENTRY(r11);
	ENTRY(r12);
	ENTRY(r13);
	ENTRY(r14);
	ENTRY(r15);
	ENTRY(flags);
	BLANK();
#undef ENTRY

#define ENTRY(entry) OFFSET(saved_context_ ## entry, saved_context, entry)
	ENTRY(cr0);
	ENTRY(cr2);
	ENTRY(cr3);
	ENTRY(cr4);
	ENTRY(cr8);
	BLANK();
#undef ENTRY

	OFFSET(TSS_ist, tss_struct, x86_tss.ist);
	BLANK();

<<<<<<< HEAD
	DEFINE(__NR_syscall_max, sizeof(syscalls) - 1);

=======
	BLANK();
	DEFINE(PAGE_SIZE_asm, PAGE_SIZE);
#ifdef CONFIG_XEN
	BLANK();
	OFFSET(XEN_vcpu_info_mask, vcpu_info, evtchn_upcall_mask);
	OFFSET(XEN_vcpu_info_pending, vcpu_info, evtchn_upcall_pending);
#undef ENTRY
#endif
#if defined(CONFIG_LGUEST) || defined(CONFIG_LGUEST_GUEST) || defined(CONFIG_LGUEST_MODULE)
	BLANK();
	OFFSET(LGUEST_DATA_irq_enabled, lguest_data, irq_enabled);
	OFFSET(LGUEST_DATA_irq_pending, lguest_data, irq_pending);
	OFFSET(LGUEST_DATA_pgdir, lguest_data, pgdir);

	BLANK();
	OFFSET(LGUEST_PAGES_host_gdt_desc, lguest_pages, state.host_gdt_desc);
	OFFSET(LGUEST_PAGES_host_idt_desc, lguest_pages, state.host_idt_desc);
	OFFSET(LGUEST_PAGES_host_cr3, lguest_pages, state.host_cr3);
	OFFSET(LGUEST_PAGES_host_sp, lguest_pages, state.host_sp);
	OFFSET(LGUEST_PAGES_guest_gdt_desc, lguest_pages,state.guest_gdt_desc);
	OFFSET(LGUEST_PAGES_guest_idt_desc, lguest_pages,state.guest_idt_desc);
	OFFSET(LGUEST_PAGES_guest_gdt, lguest_pages, state.guest_gdt);
	OFFSET(LGUEST_PAGES_regs_trapnum, lguest_pages, regs.trapnum);
	OFFSET(LGUEST_PAGES_regs_errcode, lguest_pages, regs.errcode);
	OFFSET(LGUEST_PAGES_regs, lguest_pages, regs);
#endif
>>>>>>> Initial boot files and launcher for 64bit (stripped down)
	return 0;
}
