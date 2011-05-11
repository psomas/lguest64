#include <linux/kernel.h>
#include <linux/start_kernel.h>
#include <linux/string.h>
#include <linux/console.h>
#include <linux/screen_info.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/clocksource.h>
#include <linux/clockchips.h>
#include <linux/lguest.h>
#include <linux/lguest_launcher.h>
#include <linux/virtio_console.h>
#include <linux/pm.h>
#include <asm/apic.h>
#include <asm/lguest.h>
#include <asm/paravirt.h>
#include <asm/param.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/desc.h>
#include <asm/setup.h>
#include <asm/e820.h>
#include <asm/mce.h>
#include <asm/io.h>
#include <asm/i387.h>
#include <asm/stackprotector.h>
#include <asm/reboot.h>		/* for struct machine_ops */

struct lguest_data lguest_data = {
	.hcall_status = { [0 ... LHCALL_RING_SIZE-1] = 0xFF },
	.noirq_start = (u64)lguest_noirq_start,
	.noirq_end = (u64)lguest_noirq_end,
	.kernel_address = __START_KERNEL_map,
	.blocked_interrupts = { 1 }, /* Block timer interrupts */
	.syscall_vec = IA32_SYSCALL_VECTOR /* FIX ME */
};

__init void lguest_init(void)
{

}
