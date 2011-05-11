/*P:100
 * This is the Launcher code, a simple program which lays out the "physical"
 * memory for the new Guest by mapping the kernel image and the virtual
 * devices, then opens /dev/lguest to tell the kernel about the Guest and
 * control it.
:*/
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <stdint.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/eventfd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <errno.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <time.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <linux/if_tun.h>
#include <sys/uio.h>
#include <termios.h>
#include <getopt.h>
#include <assert.h>
#include <sched.h>
#include <limits.h>
#include <stddef.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>

#include <linux/virtio_config.h>
#include <linux/virtio_net.h>
#include <linux/virtio_blk.h>
#include <linux/virtio_console.h>
#include <linux/virtio_rng.h>
#include <linux/virtio_ring.h>
#include <asm/bootparam.h>
#include "../../include/linux/lguest_launcher.h"
/*L:110
 * We can ignore the 42 include files we need for this program, but I do want
 * to draw attention to the use of kernel-style types.
 *
 * As Linus said, "C is a Spartan language, and so should your naming be."  I
 * like these abbreviations, so we define them here.  Note that u64 is always
 * unsigned long long, which works on all Linux systems: this means that we can
 * use %llu in printf for any u64.
 */
typedef unsigned long long u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
/*:*/

#define PAGE_PRESENT 0x7 	/* Present, RW, Execute */

/*L:120
 * verbose is both a global flag and a macro.  The C preprocessor allows
 * this, and although I wouldn't recommend it, it works quite nicely here.
 */
static bool verbose;
#define verbose(args...) \
	do { if (verbose) printf(args); } while(0)
/*:*/

/* The pointer to the start of guest memory. */
static void *guest_base;
/* The maximum guest physical address allowed, and maximum possible. */
static unsigned long guest_limit, guest_max;
/* The /dev/lguest file descriptor. */
static int lguest_fd;

/* a per-cpu variable indicating whose vcpu is currently running */
static unsigned int __thread cpu_id;

/* Wrapper for the last available index.  Makes it easier to change. */
#define lg_last_avail(vq)	((vq)->last_avail_idx)

/*
 * The virtio configuration space is defined to be little-endian.  x86 is
 * little-endian too, but it's nice to be explicit so we have these helpers.
 */
#define cpu_to_le16(v16) (v16)
#define cpu_to_le32(v32) (v32)
#define cpu_to_le64(v64) (v64)
#define le16_to_cpu(v16) (v16)
#define le32_to_cpu(v32) (v32)
#define le64_to_cpu(v64) (v64)

/*L:100
 * The Launcher code itself takes us out into userspace, that scary place where
 * pointers run wild and free!  Unfortunately, like most userspace programs,
 * it's quite boring (which is why everyone likes to hack on the kernel!).
 * Perhaps if you make up an Lguest Drinking Game at this point, it will get
 * you through this section.  Or, maybe not.
 *
 * The Launcher sets up a big chunk of memory to be the Guest's "physical"
 * memory and stores it in "guest_base".  In other words, Guest physical ==
 * Launcher virtual with an offset.
 *
 * This can be tough to get your head around, but usually it just means that we
 * use these trivial conversion functions when the Guest gives us its
 * "physical" addresses:
 */
static void *from_guest_phys(unsigned long addr)
{
	return guest_base + addr;
}

static unsigned long to_guest_phys(const void *addr)
{
	return (addr - guest_base);
}

/*L:130
 * Loading the Kernel.
 *
 * We start with couple of simple helper routines.  open_or_die() avoids
 * error-checking code cluttering the callers:
 */
static int open_or_die(const char *name, int flags)
{
	int fd = open(name, flags);
	if (fd < 0)
		err(1, "Failed to open %s", name);
	return fd;
}

/* map_zeroed_pages() takes a number of pages. */
static void *map_zeroed_pages(unsigned int num)
{
	int fd = open_or_die("/dev/zero", O_RDONLY);
	void *addr;

	/*
	 * We use a private mapping (ie. if we write to the page, it will be
	 * copied). We allocate an extra two pages PROT_NONE to act as guard
	 * pages against read/write attempts that exceed allocated space.
	 */
	addr = mmap(NULL, getpagesize() * (num+2),
		    PROT_NONE, MAP_PRIVATE, fd, 0);

	if (addr == MAP_FAILED)
		err(1, "Mmapping %u pages of /dev/zero", num);

	if (mprotect(addr + getpagesize(), getpagesize() * num,
		     PROT_READ|PROT_WRITE) == -1)
		err(1, "mprotect rw %u pages failed", num);

	/*
	 * One neat mmap feature is that you can close the fd, and it
	 * stays mapped.
	 */
	close(fd);

	/* Return address after PROT_NONE page */
	return addr + getpagesize();
}

/*
 * This routine is used to load the kernel or initrd.  It tries mmap, but if
 * that fails (Plan 9's kernel file isn't nicely aligned on page boundaries),
 * it falls back to reading the memory in.
 */
static void map_at(int fd, void *addr, unsigned long offset, unsigned long len)
{
	ssize_t r;

	/*
	 * We map writable even though for some segments are marked read-only.
	 * The kernel really wants to be writable: it patches its own
	 * instructions.
	 *
	 * MAP_PRIVATE means that the page won't be copied until a write is
	 * done to it.  This allows us to share untouched memory between
	 * Guests.
	 */
	if (mmap(addr, len, PROT_READ|PROT_WRITE,
		 MAP_FIXED|MAP_PRIVATE, fd, offset) != MAP_FAILED)
		return;

	/* pread does a seek and a read in one shot: saves a few lines. */
	r = pread(fd, addr, len, offset);
	if (r != len)
		err(1, "Reading offset %lu len %lu gave %zi", offset, len, r);
}

/*
 * This routine takes an open vmlinux image, which is in ELF, and maps it into
 * the Guest memory.  ELF = Embedded Linking Format, which is the format used
 * by all modern binaries on Linux including the kernel.
 *
 * The ELF headers give *two* addresses: a physical address, and a virtual
 * address.  We use the physical address; the Guest will map itself to the
 * virtual address.
 *
 * We return the starting address.
 */
static unsigned long map_elf(int elf_fd, const Elf32_Ehdr *ehdr)
{
	Elf32_Phdr phdr[ehdr->e_phnum];
	unsigned int i;

	/*
	 * Sanity checks on the main ELF header: an x86 executable with a
	 * reasonable number of correctly-sized program headers.
	 */
	if (ehdr->e_type != ET_EXEC
	    || ehdr->e_machine != EM_386
	    || ehdr->e_phentsize != sizeof(Elf32_Phdr)
	    || ehdr->e_phnum < 1 || ehdr->e_phnum > 65536U/sizeof(Elf32_Phdr))
		errx(1, "Malformed elf header");

	/*
	 * An ELF executable contains an ELF header and a number of "program"
	 * headers which indicate which parts ("segments") of the program to
	 * load where.
	 */

	/* We read in all the program headers at once: */
	if (lseek(elf_fd, ehdr->e_phoff, SEEK_SET) < 0)
		err(1, "Seeking to program headers");
	if (read(elf_fd, phdr, sizeof(phdr)) != sizeof(phdr))
		err(1, "Reading program headers");

	/*
	 * Try all the headers: there are usually only three.  A read-only one,
	 * a read-write one, and a "note" section which we don't load.
	 */
	for (i = 0; i < ehdr->e_phnum; i++) {
		/* If this isn't a loadable segment, we ignore it */
		if (phdr[i].p_type != PT_LOAD)
			continue;

		verbose("Section %i: size %i addr %p\n",
			i, phdr[i].p_memsz, (void *)phdr[i].p_paddr);

		/* We map this section of the file at its physical address. */
		map_at(elf_fd, from_guest_phys(phdr[i].p_paddr),
		       phdr[i].p_offset, phdr[i].p_filesz);
	}

	/* The entry point is given in the ELF header. */
	return ehdr->e_entry;
}

/*L:150
 * A bzImage, unlike an ELF file, is not meant to be loaded.  You're supposed
 * to jump into it and it will unpack itself.  We used to have to perform some
 * hairy magic because the unpacking code scared me.
 *
 * Fortunately, Jeremy Fitzhardinge convinced me it wasn't that hard and wrote
 * a small patch to jump over the tricky bits in the Guest, so now we just read
 * the funky header so we know where in the file to load, and away we go!
 */
static unsigned long load_bzimage(int fd)
{
	struct boot_params boot;
	int r;
	/* Modern bzImages get loaded at 1M. */
	void *p = from_guest_phys(0x100000);

	/*
	 * Go back to the start of the file and read the header.  It should be
	 * a Linux boot header (see Documentation/x86/i386/boot.txt)
	 */
	lseek(fd, 0, SEEK_SET);
	read(fd, &boot, sizeof(boot));

	/* Inside the setup_hdr, we expect the magic "HdrS" */
	if (memcmp(&boot.hdr.header, "HdrS", 4) != 0)
		errx(1, "This doesn't look like a bzImage to me");

	/* Skip over the extra sectors of the header. */
	lseek(fd, (boot.hdr.setup_sects+1) * 512, SEEK_SET);

	/* Now read everything into memory. in nice big chunks. */
	while ((r = read(fd, p, 65536)) > 0)
		p += r;

	/* Finally, code32_start tells us where to enter the kernel. */
	return boot.hdr.code32_start;
}

/*L:140
 * Loading the kernel is easy when it's a "vmlinux", but most kernels
 * come wrapped up in the self-decompressing "bzImage" format.  With a little
 * work, we can load those, too.
 */
static unsigned long load_kernel(int fd)
{
	Elf32_Ehdr hdr;

	/* Read in the first few bytes. */
	if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr))
		err(1, "Reading kernel");

	/* If it's an ELF file, it starts with "\177ELF" */
	if (memcmp(hdr.e_ident, ELFMAG, SELFMAG) == 0)
		return map_elf(fd, &hdr);

	/* Otherwise we assume it's a bzImage, and try to load it. */
	return load_bzimage(fd);
}

/*
 * This is a trivial little helper to align pages.  Andi Kleen hated it because
 * it calls getpagesize() twice: "it's dumb code."
 *
 * Kernel guys get really het up about optimization, even when it's not
 * necessary.  I leave this code as a reaction against that.
 */
static inline unsigned long page_align(unsigned long addr)
{
	/* Add upwards and truncate downwards. */
	return ((addr + getpagesize()-1) & ~(getpagesize()-1));
}

/*L:180
 * An "initial ram disk" is a disk image loaded into memory along with the
 * kernel which the kernel can use to boot from without needing any drivers.
 * Most distributions now use this as standard: the initrd contains the code to
 * load the appropriate driver modules for the current machine.
 *
 * Importantly, James Morris works for RedHat, and Fedora uses initrds for its
 * kernels.  He sent me this (and tells me when I break it).
 */
static unsigned long load_initrd(const char *name, unsigned long mem)
{
	int ifd;
	struct stat st;
	unsigned long len;

	ifd = open_or_die(name, O_RDONLY);
	/* fstat() is needed to get the file size. */
	if (fstat(ifd, &st) < 0)
		err(1, "fstat() on initrd '%s'", name);

	/*
	 * We map the initrd at the top of memory, but mmap wants it to be
	 * page-aligned, so we round the size up for that.
	 */
	len = page_align(st.st_size);
	map_at(ifd, from_guest_phys(mem - len), 0, st.st_size);
	/*
	 * Once a file is mapped, you can close the file descriptor.  It's a
	 * little odd, but quite useful.
	 */
	close(ifd);
	verbose("mapped initrd %s size=%lu @ %p\n", name, len, (void*)mem-len);

	/* We return the initrd size. */
	return len;
}
/*:*/

/*
 * Simple routine to roll all the commandline arguments together with spaces
 * between them.
 */
static void concat(char *dst, char *args[])
{
	unsigned int i, len = 0;

	for (i = 0; args[i]; i++) {
		if (i) {
			strcat(dst+len, " ");
			len++;
		}
		strcpy(dst+len, args[i]);
		len += strlen(args[i]);
	}
	/* In case it's empty. */
	dst[len] = '\0';
}

/*L:185
 * This is where we actually tell the kernel to initialize the Guest.  We
 * saw the arguments it expects when we looked at initialize() in lguest_user.c:
 * the base of Guest "physical" memory, the top physical page to allow and the
 * entry point for the Guest.
 */
static void tell_kernel(unsigned long start)
{
	unsigned long args[] = { LHREQ_INITIALIZE,
				 (unsigned long)guest_base,
				 guest_limit / getpagesize(), start };
	verbose("Guest: %p - %p (%#lx)\n",
		guest_base, guest_base + guest_limit, guest_limit);
	lguest_fd = open_or_die("/dev/lguest", O_RDWR);
	if (write(lguest_fd, args, sizeof(args)) < 0)
		err(1, "Writing to /dev/lguest");
}
/*:*/

/*L:220
 * Finally we reach the core of the Launcher which runs the Guest, serves
 * its input and output, and finally, lays it to rest.
 */
static void __attribute__((noreturn)) run_guest(void)
{
	for (;;) {
		unsigned long notify_addr;
		int readval;

		/* We read from the /dev/lguest device to run the Guest. */
		readval = pread(lguest_fd, &notify_addr,
				sizeof(notify_addr), cpu_id);

		/* ENOENT means the Guest died.  Reading tells us why. */
		if (errno == ENOENT) {
			char reason[1024] = { 0 };
			pread(lguest_fd, reason, sizeof(reason)-1, cpu_id);
			errx(1, "%s", reason);
		/* Anything else means a bug or incompatible change. */
		} else
			err(1, "Running guest failed");
	}
}
/*L:240
 * This is the end of the Launcher.  The good news: we are over halfway
 * through!  The bad news: the most fiendish part of the code still lies ahead
 * of us.
 *
 * Are you ready?  Take a deep breath and join me in the core of the Host, in
 * "make Host".
:*/

static struct option opts[] = {
	{ "verbose", 0, NULL, 'v' },
	{ "initrd", 1, NULL, 'i' },
	{ "username", 1, NULL, 'u' },
	{ "chroot", 1, NULL, 'c' },
	{ NULL },
};
static void usage(void)
{
	errx(1, "Usage: lguest [--verbose] "
	     "[--initrd=<filename>]...\n"
	     "<mem-in-mb> vmlinux [args...]");
}

/*L:105 The main routine is where the real work begins: */
int main(int argc, char *argv[])
{
	/* Memory, code startpoint and size of the (optional) initrd. */
	unsigned long mem = 0, start, initrd_size = 0;
	/* Two temporaries. */
	int i, c;
	/* The boot information for the Guest. */
	struct boot_params *boot;
	/* If they specify an initrd file to load. */
	const char *initrd_name = NULL;

	/* Password structure for initgroups/setres[gu]id */
	struct passwd *user_details = NULL;

	/* Directory to chroot to */
	char *chroot_path = NULL;

	/* We're CPU 0.  In fact, that's the only CPU possible right now. */
	cpu_id = 0;

	/*
	 * We need to know how much memory so we can set up the device
	 * descriptor and memory pages for the devices as we parse the command
	 * line.  So we quickly look through the arguments to find the amount
	 * of memory now.
	 */
	for (i = 1; i < argc; i++) {
		if (argv[i][0] != '-') {
			mem = atoi(argv[i]) * 1024 * 1024;
			/*
			 * We start by mapping anonymous pages over all of
			 * guest-physical memory range.  This fills it with 0,
			 * and ensures that the Guest won't be killed when it
			 * tries to access it.
			 */
			guest_base = map_zeroed_pages(mem / getpagesize());
			guest_limit = mem;
			guest_max = mem;
			break;
		}
	}

	/* The options are fairly straight-forward */
	while ((c = getopt_long(argc, argv, "v", opts, NULL)) != EOF) {
		switch (c) {
		case 'v':
			verbose = true;
			break;
		case 'i':
			initrd_name = optarg;
			break;
		case 'u':
			user_details = getpwnam(optarg);
			if (!user_details)
				err(1, "getpwnam failed, incorrect username?");
			break;
		case 'c':
			chroot_path = optarg;
			break;
		default:
			warnx("Unknown argument %s", argv[optind]);
			usage();
		}
	}
	/*
	 * After the other arguments we expect memory and kernel image name,
	 * followed by command line arguments for the kernel.
	 */
	if (optind + 2 > argc)
		usage();

	verbose("Guest base is at %p\n", guest_base);

	/* Now we load the kernel */
	start = load_kernel(open_or_die(argv[optind+1], O_RDONLY));

	/* Boot information is stashed at physical address 0 */
	boot = from_guest_phys(0);

	/* Map the initrd image if requested (at top of physical memory) */
	if (initrd_name) {
		initrd_size = load_initrd(initrd_name, mem);
		/*
		 * These are the location in the Linux boot header where the
		 * start and size of the initrd are expected to be found.
		 */
		boot->hdr.ramdisk_image = mem - initrd_size;
		boot->hdr.ramdisk_size = initrd_size;
		/* The bootloader type 0xFF means "unknown"; that's OK. */
		boot->hdr.type_of_loader = 0xFF;
	}

	/*
	 * The Linux boot header contains an "E820" memory map: ours is a
	 * simple, single region.
	 */
	boot->e820_entries = 1;
	boot->e820_map[0] = ((struct e820entry) { 0, mem, E820_RAM });
	/*
	 * The boot header contains a command line pointer: we put the command
	 * line after the boot header.
	 */
	boot->hdr.cmd_line_ptr = to_guest_phys(boot + 1);
	/* We use a simple helper to copy the arguments separated by spaces. */
	concat((char *)(boot + 1), argv+optind+2);

	/* Boot protocol version: 2.07 supports the fields for lguest. */
	boot->hdr.version = 0x207;

	/* The hardware_subarch value of "1" tells the Guest it's an lguest. */
	boot->hdr.hardware_subarch = 1;

	/* Tell the entry path not to try to reload segment registers. */
	boot->hdr.loadflags |= KEEP_SEGMENTS;

	/*
	 * We tell the kernel to initialize the Guest: this returns the open
	 * /dev/lguest file descriptor.
	 */
	tell_kernel(start);

	/* If requested, chroot to a directory */
	if (chroot_path) {
		if (chroot(chroot_path) != 0)
			err(1, "chroot(\"%s\") failed", chroot_path);

		if (chdir("/") != 0)
			err(1, "chdir(\"/\") failed");

		verbose("chroot done\n");
	}

	/* If requested, drop privileges */
	if (user_details) {
		uid_t u;
		gid_t g;

		u = user_details->pw_uid;
		g = user_details->pw_gid;

		if (initgroups(user_details->pw_name, g) != 0)
			err(1, "initgroups failed");

		if (setresgid(g, g, g) != 0)
			err(1, "setresgid failed");

		if (setresuid(u, u, u) != 0)
			err(1, "setresuid failed");

		verbose("Dropping privileges completed\n");
	}

	/* Finally, run the Guest.  This doesn't return. */
	run_guest();
}
/*:*/

/*M:999
 * Mastery is done: you now know everything I do.
 *
 * But surely you have seen code, features and bugs in your wanderings which
 * you now yearn to attack?  That is the real game, and I look forward to you
 * patching and forking lguest into the Your-Name-Here-visor.
 *
 * Farewell, and good coding!
 * Rusty Russell.
 */
