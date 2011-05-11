#include <linux/linkage.h>
#include <linux/lguest.h>
#include <asm/lguest_hcall.h>
#include <asm/asm-offsets.h>
#include <asm/thread_info.h>
#include <asm/processor-flags.h>

/* Our story starts with the kernel booting into startup_64 in
 * arch/x86/kernel/head_64.S.  It expects a boot header, which is created by
 * the bootloader (the Launcher in our case).
 *
 * The startup_64 function does very little: it clears the uninitialized global
 * C variables which we expect to be zero (ie. BSS) and then copies the boot
 * header and kernel command line somewhere safe.  Finally it checks the
 * 'hardware_subarch' field.  This was introduced in 2.6.24 for lguest and Xen:
 * if it's set to '1' (lguest's assigned number), then it calls us here.
 *
 * WARNING: be very careful here!  We're running at addresses equal to physical
 * addesses (around 0), not above __START_KERNEL_map as most code expectes
 * (eg. 0xffffffff80000000). Jumps are relative, so they're OK, but we can't 
 * touch any data without remembering to subtract __START_KERNEL_map!
 *
 * The .section line puts this code in .init.text so it will be discarded after
 * boot.
 */
.section .init.text, "ax", @progbits
ENTRY(lguest_entry)
	/*
	 * We make the "initialization" hypercall now to tell the Host about
	 * us, and also find out where it put our page tables.
	 */
	movq $LHCALL_LGUEST_INIT, %rax
	movq $lguest_data - __START_KERNEL_map, %rbx
	int $LGUEST_TRAP_ENTRY

	/* FIXME */
	/* Set up the initial stack so we can run C code. */
	movq stack_start(%rip), %rsp

	/* Jumps are relative: we're running __PAGE_OFFSET too low. */
	jmp lguest_init + __START_KERNEL_map

.text
#define LGUEST_PATCH(name, insns...)			\
	lgstart_##name:	insns; lgend_##name:;		\
	.globl lgstart_##name; .globl lgend_##name

LGUEST_PATCH(cli, movl $0, lguest_data+LGUEST_DATA_irq_enabled)
LGUEST_PATCH(pushf, movl lguest_data+LGUEST_DATA_irq_enabled, %eax)

ENTRY(lg_irq_enable)
	movq $X86_EFLAGS_IF, lguest_data+LGUEST_DATA_irq_enabled
	
	testq $0, lguest_data+LGUEST_DATA_irq_pending
	jnz send_interrupts

	ret

send_interrupts:
	pushq %rax
	movq $LHCALL_SEND_INTERRUPTS, %rax

	.byte 0x0f,0x01,0xc1 

	popq %rax
	ret

ENTRY(lg_restore_fl)
	movq %rax, lguest_data+LGUEST_DATA_irq_enabled

	testq lguest_data+LGUEST_DATA_irq_pending, %rax
	jnz send_interrupts

	ret

.global lguest_noirq_start
.global lguest_noirq_end

ENTRY(lguest_iret)
	pushq	%rax
	movq	12(%rsp), %rax
lguest_noirq_start:
