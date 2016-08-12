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
#include <sys/cpuset.h>
#include <sys/proc.h>

#include <machine/pcb.h>

#define LIBMEMSTAT  /* Cause vm_page.h not to include opt_vmpage.h */
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <vm/uma_int.h>

#include <err.h>
#include <kvm.h>
#include <limits.h>
#include <sysexits.h>
#include <memstat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "umascan.h"

extern int debug;

struct nlist ksymbols[] = {
#define KSYM_UMA_KEGS     0
  { .n_name = "_uma_kegs", .n_value = 0 },
#define KSYM_MP_MAXCPUS   1
  { .n_name = "_mp_maxcpus" },
#define KSYM_MP_MAXID     2 
  { .n_name = "_mp_maxid" },
#define KSYM_ALLCPUS      3
  { .n_name = "_all_cpus" },
#define KSYM_ALLPROC      4
  { .n_name = "_allproc" },
#define KSYM_DUMPPCB      5
  { .n_name = "_dumppcb" },
#define KSYM_DUMPTID      6
  { .n_name = "_dumptid" },
#define KSYM_STOPPED_CPUS 7
  { .n_name = "_stopped_cpus" },
#define KSYM_ZOMBPROC     8
  { .n_name = "_zombproc" },
  { .n_name = "" },
};

#define KSYM_INITIALISED (ksymbols[0].n_value != 0)

#define SLIST_FIRSTP(head)    ((uintptr_t)SLIST_FIRST(head))
#define SLIST_NEXTP(p, link)  ((uintptr_t)SLIST_NEXT(p, link))

#define LIST_FIRSTP(head)     ((uintptr_t)LIST_FIRST(head))
#define LIST_NEXTP(p, link)   ((uintptr_t)LIST_NEXT(p, link))

#define TAILQ_FIRSTP(head)     ((uintptr_t)TAILQ_FIRST(head))
#define TAILQ_NEXTP(p, link)   ((uintptr_t)TAILQ_NEXT(p, link))

int
kread(kvm_t *kd, uintptr_t addr, void *buf, size_t size)
{
  ssize_t ret;
  ret = kvm_read(kd, addr, buf, size);
  if (ret < 0)
    err(MEMSTAT_ERROR_KVM, "kvm_read: %s", kvm_geterr(kd));
  if ((size_t)ret != size)
    err(MEMSTAT_ERROR_KVM_SHORTREAD, "kvm_read: %s", kvm_geterr(kd));
  return (0);
}

int
kread_symbol(kvm_t *kd, int index, void *buf, size_t size)
{
  ssize_t ret;
  uintptr_t addr = ksymbols[index].n_value;
  if (addr == 0)
    err(-1, "symbol address null");
  ret = kvm_read(kd, addr, buf, size);
  if (ret < 0)
    err(MEMSTAT_ERROR_KVM, "kvm_read: %s", kvm_geterr(kd));
  if ((size_t)ret != size)
    err(MEMSTAT_ERROR_KVM_SHORTREAD, "kvm_read: %s", kvm_geterr(kd));
  return (0);
}

int
kread_string(kvm_t *kd, const void *addr, char *buf, int buflen)
{
  ssize_t ret;
  int i;

  for (i = 0; i < buflen; i++) {
    ret = kvm_read(kd, (unsigned long)addr + i,
        &(buf[i]), sizeof(char));
    if (ret < 0)
      err(MEMSTAT_ERROR_KVM, "kvm_read: %s", kvm_geterr(kd));
    if ((size_t)ret != sizeof(char))
      err(MEMSTAT_ERROR_KVM_SHORTREAD, "kvm_read: %s", kvm_geterr(kd));
    if (buf[i] == '\0')
      return (0);
  }
  /* Truncate. */
  buf[i-1] = '\0';
  return (0);
}

static void
init_ksym(kvm_t *kd)
{
  if (kvm_nlist(kd, ksymbols) != 0)
    err(EX_NOINPUT, "kvm_nlist");

  if (ksymbols[KSYM_UMA_KEGS].n_type == 0 ||
      ksymbols[KSYM_UMA_KEGS].n_value == 0)
    errx(EX_DATAERR, "kvm_nlist return");
}

int
init_masterkeg(kvm_t *kd, struct uma_keg* uk)
{
  if (!KSYM_INITIALISED)
    init_ksym(kd);
  kread_symbol(kd, KSYM_UMA_KEGS, uk, sizeof(struct uma_keg));
  return 0;
}

int
init_coreinfo(kvm_t *kd, struct coreinfo* cinfo)
{
  int cpusetsize;

  if (!KSYM_INITIALISED)
    init_ksym(kd);
  cinfo->kd = kd;

  kread_symbol(kd, KSYM_ALLPROC, &cinfo->allproc, sizeof(cinfo->allproc));
  if (debug > 0)
    printf("allproc addr: 0x%lx\n", cinfo->allproc);

  kread_symbol(kd, KSYM_DUMPPCB, &cinfo->dumppcb, sizeof(cinfo->dumppcb));
  if (debug > 0)
    printf("dumppcb addr: 0x%lx\n", cinfo->dumppcb);

  kread_symbol(kd, KSYM_DUMPTID, &cinfo->dumptid, sizeof(cinfo->dumptid));
  if (debug > 0)
    printf("dumptid: %d\n", cinfo->dumptid);

  CPU_ZERO(&cinfo->stopped_cpus);
  cpusetsize = sysconf(_SC_CPUSET_SIZE);
  if (cpusetsize != -1 && (u_long)cpusetsize <= sizeof(cpuset_t))
    kread_symbol(kd, KSYM_STOPPED_CPUS, &cinfo->stopped_cpus, cpusetsize);

/* TODO: zombproc unused
  kread_symbol(kd, KSYM_ZOMBPROC, &paddr, sizeof(paddr));
  printf("zombproc addr: 0x%lx\n", paddr);
*/

  return 0;
}

void
kread_kthr(kvm_t *kd, struct coreinfo *cinfo)
{
  struct proc p;
  struct thread td;
  struct kthr *kt;
  uintptr_t addr, paddr = cinfo->allproc;
  
  SLIST_INIT(&cinfo->kthrs);

  while (paddr != 0) {
    kread(kd, paddr, &p, sizeof(p));
    addr = TAILQ_FIRSTP(&p.p_threads);

    while (addr != 0) {
      kread(kd, addr, &td, sizeof(td));

      kt = malloc(sizeof(struct kthr));

      if (td.td_tid == cinfo->dumptid)
        kt->pcb = cinfo->dumppcb;
      else if (td.td_state == TDS_RUNNING &&
                CPU_ISSET(td.td_oncpu, &cinfo->stopped_cpus))
        err(-1, "pcb on running cpus (only when online)");
      else
        kt->pcb = (uintptr_t)td.td_pcb;

      kt->kstack = td.td_kstack;
      kt->kstack_pages = td.td_kstack_pages;
      kt->tid = td.td_tid;
      kt->pid = p.p_pid;
      kt->paddr = paddr;
      kt->cpu = td.td_oncpu;

      SLIST_INSERT_HEAD(&cinfo->kthrs, kt, k_link);
      addr = TAILQ_NEXTP(&td, td_plist);
    }
    paddr = LIST_NEXTP(&p, p_list);
  }

}

void
print_kthr(struct coreinfo *cinfo)
{
  struct kthr *kt;
  SLIST_FOREACH (kt, &cinfo->kthrs, k_link) {
      struct pcb pcb;
      kread(cinfo->kd, kt->pcb, &pcb, sizeof(struct pcb));
    
      printf("kthread {\n"
              "\taddress: 0x%lx\n"
              "\tkstack: 0x%lx\n"
              "\tkstack pages: %d\n"
              "\tPCB address: 0x%lx\n"
              "\ttid: %d\n"
              "\tpid: %d\n"
              "\tcpu: %d\n"
              "\trsp: %lx\n"
              "\trbp: %lx\n"
              "}\n",
        kt->paddr, kt->kstack, kt->kstack_pages, kt->pcb, kt->tid, kt->pid,
        kt->cpu, pcb.pcb_rsp, pcb.pcb_rbp);
  }
}

void
scan_slab(kvm_t *kd, uintptr_t usp, size_t slabsize,
          scan_update update, void *args)
{
  struct uma_slab us;

  if (update == NULL)
    return;

  while (usp != 0) {
    
    if (debug > 1)
      printf("\t\tslab: 0x%lx\n", (uintptr_t) usp);
    
    kread(kd, usp, &us, sizeof(struct uma_slab));

    uint us_len = slabsize/sizeof(uintptr_t);
    uintptr_t us_data [us_len];

    kread(kd, (uintptr_t) us.us_data, &us_data, slabsize);

    for (uint i = 0; i < us_len; i++)
    {
      (*update)(us_data[i], args);
    }

    usp = LIST_NEXTP(&us, us_link);
  }
}

void
scan_bucket(kvm_t *kd, uintptr_t ubp, struct uma_bucket *ub1,
            size_t bucketsize, scan_update update, void *args)
{
  struct uma_bucket * ub2;
  size_t ub_len;

  if (ubp == 0 || update == NULL)
    return;

  // get a bucket (without data table)
  kread (kd, ubp, ub1, sizeof(struct uma_bucket));

  // if no data, leave
  if (ub1->ub_cnt == 0)
      return;

  // get new bucket (with data table)
  ub_len = sizeof(struct uma_bucket) + ub1->ub_cnt*sizeof(uintptr_t);
  ub2 = malloc(ub_len);
  kread (kd, ubp, ub2, ub_len);

  // read the data of each bucket
  for (uint16_t i = 0; i < ub2->ub_cnt; i++) {
    uint32_t ub_num = bucketsize/sizeof(uintptr_t);
    uintptr_t ub_data[ub_num];
    kread(kd, (uintptr_t)ub2->ub_bucket[i], &ub_data, bucketsize);

    uint32_t j;
    for (j = 0; j < ub_num; j++) {
      (*update)(ub_data[j], args);
    }
  }
  
  free(ub2);
}

void
scan_bucketlist(kvm_t *kd, uintptr_t ubp, size_t bucketsize,
                scan_update update, void *args)
{
  struct uma_bucket ub;
  if (update == NULL)
    return;

  while (ubp != 0) {
    scan_bucket(kd, ubp, &ub, bucketsize, update, args);
    ubp = LIST_NEXTP(&ub, ub_link);
  }
}

void
scan_uma(kvm_t *kd, struct scan *update, void *args) {
  int all_cpus, mp_maxcpus, mp_maxid;
  LIST_HEAD(, uma_keg) uma_kegs;

  // Read symbols
  init_ksym(kd);
  kread_symbol(kd, KSYM_ALLCPUS, &all_cpus, sizeof(all_cpus));
  kread_symbol(kd, KSYM_MP_MAXCPUS, &mp_maxcpus, sizeof(mp_maxcpus));
  kread_symbol(kd, KSYM_MP_MAXID, &mp_maxid, sizeof(mp_maxid));
  kread_symbol(kd, KSYM_UMA_KEGS, &uma_kegs, sizeof(uma_kegs));

  /**
   * uma_zone ends in an array of mp_maxid cache entries.
   * but it is declared as an array of size 1
   * aditional space is hence needed.  
   **/
  uint uz_len = sizeof(struct uma_zone) + mp_maxid * sizeof(struct uma_cache);
  struct uma_zone * uz = malloc(uz_len);

  uintptr_t kzp;
  struct uma_keg kz;
  for (kzp = LIST_FIRSTP(&uma_kegs); kzp != 0; kzp =
      LIST_NEXTP(&kz, uk_link)) {

    kread(kd, kzp, &kz, sizeof(kz));
   
    if (debug > 1) {
      printf("keg: 0x%lx\n", (uintptr_t)kzp);
      printf("\tslab size: %hu\n", kz.uk_slabsize);
      printf("\tobject size: %d\n", kz.uk_size);
    }

    char k_name [MEMTYPE_MAXNAME];
    kread_string(kd, kz.uk_name, k_name, MEMTYPE_MAXNAME);

    // full/part/free slabs
    scan_slab(kd, LIST_FIRSTP(&kz.uk_full_slab),
              kz.uk_slabsize, update->fullslabs, args);
    scan_slab(kd, LIST_FIRSTP(&kz.uk_part_slab),
              kz.uk_slabsize, update->partslabs, args);
    scan_slab(kd, LIST_FIRSTP(&kz.uk_free_slab),
              kz.uk_slabsize, update->freeslabs, args);

    // zones
    uintptr_t uzp;
    for (uzp = LIST_FIRSTP(&kz.uk_zones); uzp != 0;
         uzp = LIST_NEXTP(uz, uz_link)) {

      // get zone (without or with caches)
      kread (kd, uzp, uz, 
        (kz.uk_flags & UMA_ZFLAG_INTERNAL) ?
          sizeof(struct uma_zone) : uz_len);
    
      char z_name[MEMTYPE_MAXNAME];
      kread_string(kd, uz->uz_name, z_name, MEMTYPE_MAXNAME);

      scan_bucketlist(kd, LIST_FIRSTP(&uz->uz_buckets),
                  uz->uz_size, update->buckets, args);

      // if zone has caches
      if (!(kz.uk_flags & UMA_ZFLAG_INTERNAL)) {
        int cpu;
        for (cpu = 0; cpu <= mp_maxid; cpu++) {
          // If CPU_ABSENT(cpu)
          if ((all_cpus & (1 << cpu)) == 0)
            continue;
          
          struct uma_cache * uc = &uz->uz_cpu[cpu];
          struct uma_bucket ub;
          scan_bucket(kd, (uintptr_t)uc->uc_allocbucket, &ub,
                      uz->uz_size, update->allocbuckets, args);
          scan_bucket(kd, (uintptr_t)uc->uc_freebucket, &ub,
                      uz->uz_size, update->freebuckets, args);
          
        }
      }

    } // zones
  } // kegs
}
