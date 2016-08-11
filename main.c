/*-
 * Copyright (c) 2016 Victor Gomes
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/param.h>
#include <sys/stat.h>

#define LIBMEMSTAT	/* Cause vm_page.h not to include opt_vmpage.h */
#include <vm/vm.h>
#include <vm/vm_page.h>

#include <vm/uma.h>
#include <vm/uma_int.h>

#include <err.h>
#include <kvm.h>
#include <limits.h>
#include <sysexits.h>
#include <memstat.h>
#include <paths.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "umascan.h"

struct kthr *curkthr;
static cpuset_t stopped_cpus;
static uintptr_t dumppcb;

char k_name[MEMTYPE_MAXNAME];
static int verbose;

struct umascan_args {
	const char *vmcore; // Core dump file name
	const char *kernel; // Kernel image (symbol)
	FILE *fd;  		      // Extra input file argument (depends on mode)
	int mode; 					// Application mode
	kvm_t *kd;					// kvm description
	int verbose;				// Verbose mode
	int debug;					// Debug level (usually 0)
};

struct pointer {
  uintptr_t addr;
  int fullcount;
  int partcount;
  int freecount;
  int zonefull;
  int fullcache;
  int freecache;
  uint64_t refc;
	SLIST_ENTRY(pointer) p_link;
};

typedef struct pointer pointer_t;

SLIST_HEAD(pointerlist, pointer);

static void
create_pointerlist(FILE * addrfd, struct pointerlist * head)
{
  uintptr_t addr;
	SLIST_INIT(head);
  while (fscanf(addrfd, "%lx", &addr) != EOF) {
    pointer_t * p = malloc(sizeof(pointer_t));
    p->addr = addr;
    p->fullcount = 0;
    p->freecount = 0;
    p->zonefull = 0;
    p->fullcache = 0;
    p->freecache = 0;
    p->refc = -1;
		SLIST_INSERT_HEAD(head, p, p_link);
	}
}

static void
free_pointerlist(struct pointerlist * head)
{
	pointer_t * p;
	SLIST_FOREACH(p, head, p_link) {
		free(p);	
	}
}

static void
print_pointerlist(struct pointerlist *head)
{
	pointer_t * p;
	SLIST_FOREACH(p, head, p_link) {
    printf("0x%lx:\n", p->addr);
    printf("\t\tReference count: %ld\n", p->refc);
    printf("\t\tfullcount: %d\n", p->fullcount);
    printf("\t\tpartcount: %d\n", p->partcount);
    printf("\t\tfreecount: %d\n", p->freecount);
    printf("\t\tzonefull: %d\n", p->zonefull);
    printf("\t\tfullcache: %d\n", p->fullcache);
    printf("\t\tfreecache: %d\n", p->freecache);
  }
}

static void
usage()
{
	fprintf(stderr,
					"usage: %s [-v] [-n dumpnr | -c core] [-k kernel] addrs\n",
					getprogname());
	exit(EX_USAGE);
}

#define fn_update(field) \
	void update_##field (uintptr_t data, void *args) \
	{ \
		struct pointerlist *ps = (struct pointerlist *)args; \
		pointer_t * p; \
		SLIST_FOREACH(p, ps, p_link) { \
			if (data == p->addr && verbose) { \
				printf("%s\n", k_name); \
				p->field++; \
			} \
		} \
	}

#define POINTER_TH 0xFFFFF80000000000lu
static void
print_pointer (uintptr_t data, void *args)
{
	if (data > POINTER_TH)
		printf("0x%lx\n", data);
}

static fn_update(fullcount)
static fn_update(freecount)
static fn_update(partcount)
static fn_update(zonefull)
static fn_update(fullcache)
static fn_update(freecache)

static const char *
vmcore_from_dumpnr (int dumpnr)
{
  char path[PATH_MAX];
  struct stat st;
  if (dumpnr > 0)
    snprintf(path, sizeof(path), "%s/vmcore.%d", CRASHDIR, dumpnr);
  else
    snprintf(path, sizeof(path), "%s/vmcore.last", CRASHDIR);
  if (stat(path, &st) == -1)
    err(EX_NOINPUT, "%s", path);    
  if (!S_ISREG(st.st_mode))
    errx(EX_NOINPUT, "%s: not a regular file", path);
  return strdup(path);
}

static const char *
kernel_from_vmcore(const char * vmcore)
{
	char path[PATH_MAX];
	char *crashdir = strdup(vmcore);
	FILE *info;
	char *s;
	struct stat st;
	int ret, nr, l;

	s = strrchr(crashdir, '/');
	
	if (s) {
		/* truncate crash path */
		*s = '\0';
		vmcore = s+1;
	} else {
		free(crashdir);
		crashdir = "";
	}

	s = strrchr(vmcore, '.');
	// No dump number, impossible to get kernel image
	if (!s)
		return NULL;

	ret = sscanf(strrchr(vmcore, '.')+1, "%d", &nr);
	if (ret < 1)
		return NULL;

	/*
   * Copied from kgdb/main.c
   **/
 	
	/*
	 * If there's a kernel image right here in the crash directory, then
	 * use it.  The kernel image is either called kernel.<nr> or is in a
	 * subdirectory kernel.<nr> and called kernel.  The latter allows us
	 * to collect the modules in the same place.
	 */
	snprintf(path, sizeof(path), "%s/kernel.%d", crashdir, nr);
	if (stat(path, &st) == 0) {
		if (S_ISREG(st.st_mode)) {
			return strdup(path);
		}
		if (S_ISDIR(st.st_mode)) {
			snprintf(path, sizeof(path), "%s/kernel.%d/kernel",
			    crashdir, nr);
			if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
				return strdup(path);
			}
		}
	}

	/*
	 * No kernel image here.  Parse the dump header.  The kernel object
	 * directory can be found there and we probably have the kernel
	 * image still in it.  The object directory may also have a kernel
	 * with debugging info (called kernel.debug).  If we have a debug
	 * kernel, use it.
	 */
	snprintf(path, sizeof(path), "%s/info.%d", crashdir, nr);
	info = fopen(path, "r");
	if (info == NULL) {
		warn("%s", path);
		return NULL;
	}
	while (fgets(path, sizeof(path), info) != NULL) {
		l = strlen(path);
		if (l > 0 && path[l - 1] == '\n')
			path[--l] = '\0';
		if (strncmp(path, "    ", 4) == 0) {
			s = strchr(path, ':');
			s = (s == NULL) ? path + 4 : s + 1;
			l = snprintf(path, sizeof(path), "%s/kernel.debug", s);
			if (stat(path, &st) == -1 || !S_ISREG(st.st_mode)) {
				path[l - 6] = '\0';
				if (stat(path, &st) == -1 ||
				    !S_ISREG(st.st_mode))
					break;
			}
			break;
		}
	}
	fclose(info);
	
	if (!strcmp(crashdir, ""))
		free(crashdir);

	return strdup(path);
}

int
main(int argc, char *argv[])
{
	kvm_t *kd;
	int ch, dumpnr = -1;
  
  struct umascan_args args = { 
		.vmcore = NULL,
		.kernel = NULL,
		.verbose = 0,
		.debug = 0
	};

  while ((ch = getopt(argc, argv, "hvn:c:k:")) != -1) {
    switch (ch) {
    case 'v':
      args.verbose = 1;
      break;
    case 'n': {
			char *s;
      dumpnr = strtol(optarg, &s, 0);
      if (dumpnr < 0 || *s == '\0') {
        warnx("option %c: invalid kernel dump number", optopt);
        usage();
      }}
      break;
    case 'k':
      args.kernel = strdup(optarg);
      break;
    case 'c':
      args.vmcore = strdup(optarg);
      break;
    case 'h':
    case '?':
    default:
      usage();
    }
  }

	// incompatible  argumetns
  if (dumpnr >= 0 && args.vmcore != NULL) {
    warnx("option -n and -c are mutually exclusive");
    usage();      
  }

	// try to get core from dump number
  if (args.vmcore == NULL && dumpnr >= 0)
    args.vmcore = vmcore_from_dumpnr(dumpnr);
	
	// if still no core, use live memory
	if (args.vmcore == NULL)
		args.vmcore = _PATH_MEM;

	// try to get kernel image from core
	if (args.kernel == NULL)
		args.kernel = kernel_from_vmcore(args.vmcore);

	// if no kernel image, use the one from boot
	if (args.kernel == NULL)
		args.kernel = getbootfile();

	// open argument file
  if (argc > optind) {
		char * path = strdup(argv[optind++]); 
    args.fd = fopen(path, "r");
		if (args.fd && verbose)
  		warnx("input file: %s", path);
	}

	// if no argument file, use stdin
  if (args.fd == NULL)
    args.fd = stdin;

	kd = kvm_open(args.kernel, args.vmcore, NULL, 0, "kvm");
	if (kd == NULL)
		errx(EX_NOINPUT, "kvm_open: %s", kvm_geterr(kd));

	if (args.verbose) {
  	warnx("core file: %s", args.vmcore);
  	warnx("kernel image: %s", args.kernel);
	}

	if (kvm_nlist(kd, ksymbols) != 0)
		err(EX_NOINPUT, "kvm_nlist");

	if (ksymbols[KSYM_UMA_KEGS].n_type == 0 ||
	    ksymbols[KSYM_UMA_KEGS].n_value == 0)
		errx(EX_DATAERR, "kvm_nlist return");

	uintptr_t paddr;

	kread_symbol(kd, KSYM_ALLPROC, &paddr, sizeof(paddr));
	printf("allproc addr: 0x%lx\n", paddr);

	kread_symbol(kd, KSYM_DUMPPCB, &dumppcb, sizeof(dumppcb));
	printf("dumppcb addr: 0x%lx\n", dumppcb);

	int dumptid;	
	kread_symbol(kd, KSYM_DUMPTID, &dumptid, sizeof(dumptid));
	printf("dumptid: %d\n", dumptid);

	CPU_ZERO(&stopped_cpus);
	long cpusetsize = sysconf(_SC_CPUSET_SIZE);
	if (cpusetsize != -1 && (u_long)cpusetsize <= sizeof(cpuset_t))
		kread_symbol(kd, KSYM_STOPPED_CPUS, &stopped_cpus, cpusetsize);

	{

	struct proc p;
	struct thread td;
	struct kthr *kt;
	uintptr_t addr;

	while (paddr != 0) {
		kread(kd, (void *)paddr, &p, sizeof(p));
		addr = (uintptr_t)TAILQ_FIRST(&p.p_threads);

		while (addr != 0) {
			kread(kd, (void *)addr, &td, sizeof(td));

			kt = malloc(sizeof(struct kthr));

			if (td.td_tid == dumptid)
				kt->pcb = dumppcb;
			else if (td.td_state == TDS_RUNNING &&
								CPU_ISSET(td.td_oncpu, &stopped_cpus))
				; // pcb on running cpus (only when online)
			else
				kt->pcb = (uintptr_t)td.td_pcb;

			kt->kstack = td.td_kstack;
			kt->tid = td.td_tid;
			kt->pid = p.p_pid;
			kt->paddr = paddr;
			kt->cpu = td.td_oncpu;

			printf("kthread {\n");
			printf("\t address: 0x%lx\n", kt->paddr);
			printf("\t stack address: 0x%lx\n", kt->kstack);
			printf("\t PCB address: 0x%lx\n", kt->pcb);
			printf("\t tid: %d\n", kt->tid);
			printf("\t pid: %d\n", kt->pid);
			printf("\t cpu: %d\n", kt->cpu);
			printf("}\n");

			addr = (uintptr_t)TAILQ_NEXT(&td, td_plist);
		}
		paddr = (uintptr_t)LIST_NEXT(&p, p_list);
	}

	
	}


	kread_symbol(kd, KSYM_ZOMBPROC, &paddr, sizeof(paddr));
	printf("zombproc addr: 0x%lx\n", paddr);
	
	

	// INTERRUPUT: NLIST TESTING
	//return 0;
	struct pointerlist ps;

	// fill pointer list
	create_pointerlist(args.fd, &ps);

	struct scan sc = {
		.fullslabs = &update_fullcount,
		.partslabs = &update_partcount,
		.freeslabs = &update_freecount,
		.buckets = &update_zonefull,
		.allocbuckets = &update_fullcache,
		.freebuckets = &update_freecache
	};

	scan_uma(kd, &sc, &ps);

	pointer_t * p;
	SLIST_FOREACH(p, &ps, p_link) {
		kread(kd, (void*)p->addr, &p->refc, sizeof(int64_t));
	}

	print_pointerlist(&ps);
	free_pointerlist(&ps);
/*
	struct scan sc = {
		.fullslabs = &print_pointer,
		.partslabs = &print_pointer,
		.freeslabs = &print_pointer,
		.buckets = &print_pointer,
		.allocbuckets = &print_pointer,
		.freebuckets = &print_pointer
	};
	scan_uma(kd, &sc, NULL);

*/

	return (0);
}
