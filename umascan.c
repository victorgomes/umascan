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

#include <assert.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "umascan.h"

extern int debug;

struct usc_hdl {
  kvm_t *usc_kd;
  struct uma_keg *usc_masterkeg;
  int usc_maxcpus;
  int usc_maxid;
  struct proc* usc_allproc;
  struct proc* usc_zombproc; // unused
  struct pcb* usc_dumppcb;
  int usc_dumptid;
  cpuset_t usc_stopped_cpus;

  /* TODO: this shouldn't be here */
  SLIST_HEAD(, kthr) usc_kthrs;
};

enum us_type {
  FULL_SLABS,
  PART_SLABS,
  FREE_SLABS
};

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

static void
kread(kvm_t *kd, const void* addr, void *buf, size_t size)
{
  ssize_t ret;
  ret = kvm_read(kd, (uintptr_t) addr, buf, size);
  if (ret < 0)
    err(MEMSTAT_ERROR_KVM, "kvm_read: %s", kvm_geterr(kd));
  if ((size_t)ret != size)
    err(MEMSTAT_ERROR_KVM_SHORTREAD, "kvm_read: %s", kvm_geterr(kd));
}

static void
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
}

static void
kread_string(kvm_t *kd, const void *addr, char *buf, int buflen)
{
  ssize_t ret;
  int i;

  for (i = 0; i < buflen; i++) {
    ret = kvm_read(kd, (uintptr_t)addr + i,
        &(buf[i]), sizeof(char));
    if (ret < 0)
      err(MEMSTAT_ERROR_KVM, "kvm_read: %s", kvm_geterr(kd));
    if ((size_t)ret != sizeof(char))
      err(MEMSTAT_ERROR_KVM_SHORTREAD, "kvm_read: %s", kvm_geterr(kd));
    if (buf[i] == '\0')
      return;
  }
  /* Truncate. */
  buf[i-1] = '\0';
}

void
memread (usc_hdl_t hdl, const void *addr, void *buf, size_t size)
{
  kread (hdl->usc_kd, addr, buf, size);
}

static void
init_ksym(kvm_t *kd)
{
  if (kvm_nlist(kd, ksymbols) != 0)
    err(EX_NOINPUT, "kvm_nlist: %s", kvm_geterr(kd));

  if (ksymbols[KSYM_UMA_KEGS].n_type == 0 ||
      ksymbols[KSYM_UMA_KEGS].n_value == 0)
    errx(EX_DATAERR, "kvm_nlist return");
}

usc_hdl_t
create_usc_hdl (const char *kernel, const char *core)
{
  kvm_t* kd;
  usc_hdl_t hdl;
  int cpusetsize;

  kd = kvm_openfiles(kernel, core, NULL, 0, "kvm");
  if (kd == NULL)
    errx(EX_NOINPUT, "kvm_open: %s", kvm_geterr(kd));

  hdl = malloc(sizeof(struct usc_hdl));
  hdl->usc_kd = kd;


  if (!KSYM_INITIALISED)
    init_ksym(kd);

  kread_symbol(kd, KSYM_ALLPROC, &hdl->usc_allproc, sizeof(hdl->usc_allproc));
  if (debug > 0)
    printf("allproc addr: 0x%lx\n", (uintptr_t)hdl->usc_allproc);

  kread_symbol(kd, KSYM_DUMPPCB, &hdl->usc_dumppcb, sizeof(hdl->usc_dumppcb));
  if (debug > 0)
    printf("dumppcb addr: 0x%lx\n", (uintptr_t)hdl->usc_dumppcb);

  kread_symbol(kd, KSYM_DUMPTID, &hdl->usc_dumptid, sizeof(hdl->usc_dumptid));
  if (debug > 0)
    printf("dumptid: %d\n",  hdl->usc_dumptid);

  CPU_ZERO(&hdl->usc_stopped_cpus);
  cpusetsize = sysconf(_SC_CPUSET_SIZE);
  if (cpusetsize != -1 && (u_long)cpusetsize <= sizeof(cpuset_t))
    kread_symbol(kd, KSYM_STOPPED_CPUS, &hdl->usc_stopped_cpus, cpusetsize);

/* TODO: zombproc unused
  kread_symbol(kd, KSYM_ZOMBPROC, &paddr, sizeof(paddr));
  printf("zombproc addr: 0x%lx\n", paddr);
*/

  return hdl;
}

void
delete_usc_hdl(usc_hdl_t hdl)
{
  kvm_close(hdl->usc_kd);
  free(hdl);
}

struct kthr {
  struct proc* paddr;
  uintptr_t kaddr;
  uintptr_t kstack;
  int kstack_pages;
  struct pcb* pcb;
  int tid;
  int pid;
  u_char cpu;
  SLIST_ENTRY(kthr) k_link;
};

void
kread_kthr(usc_hdl_t hdl)
{
  struct proc *p_addr, p;
  struct thread *td_addr, td;
  struct kthr *kt;
  kvm_t *kd = hdl->usc_kd;
  
  p_addr = hdl->usc_allproc;
  
  SLIST_INIT(&hdl->usc_kthrs);

  while (p_addr != 0) {
    kread(kd, p_addr, &p, sizeof(p));
    td_addr = TAILQ_FIRST(&p.p_threads);

    while (td_addr != 0) {
      kread(kd, td_addr, &td, sizeof(td));

      kt = malloc(sizeof(struct kthr));

      if (td.td_tid == hdl->usc_dumptid)
        kt->pcb = hdl->usc_dumppcb;
      else if (td.td_state == TDS_RUNNING &&
                CPU_ISSET(td.td_oncpu, &hdl->usc_stopped_cpus))
        err(-1, "pcb on running cpus (only when online)");
      else
        kt->pcb = td.td_pcb;

      kt->kstack = td.td_kstack;
      kt->kstack_pages = td.td_kstack_pages;
      kt->tid = td.td_tid;
      kt->pid = p.p_pid;
      kt->paddr = p_addr;
      kt->cpu = td.td_oncpu;

      SLIST_INSERT_HEAD(&hdl->usc_kthrs, kt, k_link);
      td_addr = TAILQ_NEXT(&td, td_plist);
    }
    p_addr = LIST_NEXT(&p, p_list);
  }

}

void
print_kthr(usc_hdl_t hdl)
{
  struct kthr *kt;
  SLIST_FOREACH (kt, &hdl->usc_kthrs, k_link) {
      struct pcb pcb;
      kread(hdl->usc_kd, kt->pcb, &pcb, sizeof(struct pcb));
    
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
        (uintptr_t)kt->paddr, kt->kstack, kt->kstack_pages, (uintptr_t)kt->pcb, kt->tid, kt->pid,
        kt->cpu, pcb.pcb_rsp, pcb.pcb_rbp);
  }
}

static void
print_slab_flags (uint8_t flag)
{
#define slab_flag(mask) if (flag & UMA_SLAB_##mask) printf("UMA_SLAB_%s", #mask);
  slab_flag(BOOT)
  slab_flag(KMEM)
  slab_flag(KERNEL)
  slab_flag(PRIV)
  slab_flag(OFFP)
  slab_flag(MALLOC)
}

static int
scan_slab(kvm_t *kd, struct uma_slab *usp, usc_info_t si, umascan_t upd, enum us_type ust)
{
  struct uma_slab us;
  size_t isize, irsize, ussize;
  int i, ipers, uk_freecount = 0, us_freecount = 0;
  uintptr_t *iptr, *iend;
  uint8_t * us_data;
  
  ipers = si->usi_uk->uk_ipers;
  isize = si->usi_uk->uk_size;
  irsize = si->usi_uk->uk_rsize;

  /* array of items in the slabs */
  ussize = ipers * isize;
  us_data = malloc(ussize);

  while (usp != NULL) {
    us_freecount = 0;
    
    kread(kd, usp, &us, sizeof(struct uma_slab));
    si->usi_us = &us;

    kread(kd, us.us_data, us_data, ussize);

    if (ust == FREE_SLABS) {

    }

    for (i = 0; i < ipers; i++) {
      // is it a free item?
      if (BIT_ISSET(SLAB_SETSIZE, i, &us.us_free)) {
        us_freecount++;
        continue;
      }

      si->usi_iaddr = (uintptr_t) us.us_data + i*isize;
      iptr = (uintptr_t*) (us_data + i*isize);
      iend = iptr + irsize;

      /* let's be sure to not go beyound the size of the array */
      assert (iptr < (uintptr_t*) (us_data + ussize));
      
      if (!upd)
        continue;
      
      while (iptr < iend) {
        si->usi_data = *iptr;
        (*upd)(si);
        iptr += sizeof(uintptr_t);
      }
    }

    /* free slabs do not seem to be using us_freecount field */
    if (ust != FREE_SLABS)
      assert (us_freecount == us.us_freecount);

    uk_freecount += us_freecount;
    usp = LIST_NEXT(&us, us_link);
  }
  
  free (us_data);
  return uk_freecount;
}

static int
scan_bucket(kvm_t *kd, struct uma_bucket *ubp, struct uma_bucket *ub, usc_info_t si, umascan_t upd)
{
  size_t ub_size, isize;
  void ** ub_bucket;
//  uintptr_t *iptr, *iend;
  uint8_t *ub_data;

  if (ubp == 0)
    return 0 ;

  // get a bucket (without data table)
  kread (kd, ubp, ub, sizeof(struct uma_bucket));

  if (!upd)
    return ub->ub_cnt;

  // if no data, leave
  if (ub->ub_cnt == 0)
      return 0;

  // get data table
  ub_size = sizeof(ub->ub_entries*sizeof(void*));
  ub_bucket = malloc(ub_size);
  kread (kd, ubp + offsetof(struct uma_bucket, ub_bucket), ub_bucket, ub_size);

  // allocate data for an item
  isize = si->usi_uz->uz_size;
  ub_data = malloc(isize);

  // read the data of each bucket
  for (int i = 0; i < ub->ub_entries - ub->ub_cnt; i++) {
//    kread(kd, ub_bucket[i], ub_data, isize);
/*

    iptr = (uintptr_t*)ub_data;
    iend = iptr + isize;

    while (iptr < iend) {
      si->usi_data = *iptr;
      (*upd)(si);
      iptr += sizeof(uintptr_t);
    }
*/
  }

  free (ub_data);
  free (ub_bucket);
  return ub->ub_cnt;
}

static int
scan_bucketlist(kvm_t *kd, struct uma_bucket *ubp, usc_info_t si, umascan_t upd)
{
  struct uma_bucket ub;

  if (upd == NULL)
    return 0;

  int ub_cnt = 0;
  while (ubp != NULL) {
    ub_cnt += scan_bucket(kd, ubp, &ub, si, upd);
    ubp = LIST_NEXT(&ub, ub_link);
  }

  return ub_cnt;
}

void
umascan(usc_hdl_t hdl, umascan_t upd, void *arg) {
  struct usc_info si;
  cpuset_t all_cpus;
  int mp_maxcpus, mp_maxid;
  long cpusetsize;
  char uk_name [MEMTYPE_MAXNAME], uz_name [MEMTYPE_MAXNAME];
  kvm_t* kd;
  LIST_HEAD(, uma_keg) uma_kegs;

  kd = hdl->usc_kd;
  si.usi_uk = NULL;
  si.usi_arg = arg;

  // Read symbols
  if (!KSYM_INITIALISED)
    init_ksym(kd);
  kread_symbol(kd, KSYM_MP_MAXCPUS, &mp_maxcpus, sizeof(mp_maxcpus));
  kread_symbol(kd, KSYM_MP_MAXID, &mp_maxid, sizeof(mp_maxid));
  kread_symbol(kd, KSYM_UMA_KEGS, &uma_kegs, sizeof(uma_kegs));
  
  cpusetsize = sysconf(_SC_CPUSET_SIZE);
  if (cpusetsize == -1 || (u_long)cpusetsize > sizeof(cpuset_t))
    err(MEMSTAT_ERROR_KVM_NOSYMBOL, "bad cpusetsize");

  CPU_ZERO(&all_cpus);  
  kread_symbol(kd, KSYM_ALLCPUS, &all_cpus, cpusetsize);

  /**
   * uma_zone ends in an array of mp_maxid cache entries.
   * but it is declared as an array of size 1
   * aditional space is hence needed.  
   **/
  size_t uz_len = sizeof(struct uma_zone) + mp_maxid * sizeof(struct uma_cache);
  struct uma_zone * uz = malloc(uz_len);

  struct uma_keg *ukp, uk;
  for (ukp = LIST_FIRST(&uma_kegs); ukp != 0; ukp =
      LIST_NEXT(&uk, uk_link)) {
    int mt_free = 0;
    
    kread(kd, ukp, &uk, sizeof(uk));
    si.usi_uk = &uk;

    kread_string(kd, uk.uk_name, uk_name, MEMTYPE_MAXNAME);
    si.usi_name = uk_name;
    si.usi_size = uk.uk_size;
    
    // full/part/free slabs
    uint32_t uk_freecount = 0;
    uk_freecount += scan_slab (kd, LIST_FIRST(&uk.uk_full_slab), &si, upd, FULL_SLABS);
    uk_freecount += scan_slab (kd, LIST_FIRST(&uk.uk_free_slab), &si, upd, FREE_SLABS);
    uk_freecount += scan_slab (kd, LIST_FIRST(&uk.uk_part_slab), &si, upd, PART_SLABS);

    assert (uk_freecount == uk.uk_free);
  
    // zones
    struct uma_zone *uzp;
    for (uzp = LIST_FIRST(&uk.uk_zones); uzp != 0;
         uzp = LIST_NEXT(uz, uz_link)) {

      // get zone (without or with caches)
      kread (kd, uzp, uz, uz_len);
      si.usi_uz = uz;
      
      // the zone's keg needs to point to our keg
      assert (ukp == uz->uz_klink.kl_keg);

      kread_string(kd, uz->uz_name, uz_name, MEMTYPE_MAXNAME);
      si.usi_name = uz_name;

      // if zone is not secondary or it is the head of the list 
      // then the keg and zone names are the same
      if (uzp == LIST_FIRST(&uk.uk_zones)) {
        assert (uk.uk_name == uz->uz_name);
      }

      // UMA secondary zones share a keg with the primary zone.
      // To avoid double-reporting of free items, report only in the primary zone.
      if (!(uk.uk_flags & UMA_ZONE_SECONDARY) || uzp == LIST_FIRST(&uk.uk_zones)) {
        mt_free += uk.uk_free;
      }

      mt_free += scan_bucketlist(kd, LIST_FIRST(&uz->uz_buckets), &si, upd);
      
      // if zone has caches per cpu
      if (!(uk.uk_flags & UMA_ZFLAG_INTERNAL)) {
        struct uma_bucket *ub = malloc(sizeof(struct uma_bucket));
        for (int cpu = 0; cpu <= mp_maxid; cpu++) {
          if (!CPU_ISSET(cpu, &all_cpus))
            continue;
          
          struct uma_cache *uc = &uz->uz_cpu[cpu];
          uc;
          mt_free += scan_bucket(kd, uc->uc_allocbucket, ub, &si, upd);
          mt_free += scan_bucket(kd, uc->uc_freebucket, ub, &si, upd);
        }
        free(ub);
      }

    } // zones
  } // kegs
  free(uz);
}
