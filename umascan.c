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

struct nlist ksymbols[] = {
  { .n_name = "_uma_kegs" },
  { .n_name = "_mp_maxcpus" },
  { .n_name = "_mp_maxid" },
  { .n_name = "_all_cpus" },
  { .n_name = "_allproc" },
  { .n_name = "_dumppcb" },
  { .n_name = "_dumptid" },
  { .n_name = "_stopped_cpus" },
  { .n_name = "_zombproc" },
  { .n_name = "" },
};

static char k_name[MEMTYPE_MAXNAME];

int
kread(kvm_t *kd, void *addr, void *buf, size_t size)
{
  ssize_t ret;
  ret = kvm_read(kd, (uintptr_t)addr, buf, size);
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

void
scan_slab(kvm_t *kd, struct uma_slab *usp, size_t slabsize,
          scan_update update, void *args)
{
  struct uma_slab us;
/*  
  if (verbose)
    printf("\tFull slabs:\n");
*/
  if (update == NULL)
    return;

  while (usp != NULL) {
    /*
    if (verbose)
      printf("\t\tslab: 0x%lx\n", (uintptr_t) usp);
    */

    kread(kd, usp, &us, sizeof(struct uma_slab));

    uint us_len = slabsize/sizeof(uintptr_t);
    uintptr_t us_data [us_len];

    kread(kd, us.us_data, &us_data, slabsize);

    for (uint i = 0; i < us_len; i++)
    {
      (*update)(us_data[i], args);
    }

    usp = LIST_NEXT(&us, us_link);
  }
}

void
scan_bucket(kvm_t *kd, struct uma_bucket *ubp, struct uma_bucket *ub1,
            size_t bucketsize, scan_update update, void *args)
{
  struct uma_bucket * ub2;

  if (ubp == NULL || update == NULL)
    return;

  // get a bucket (without data table)
  kread (kd, ubp, ub1, sizeof(struct uma_bucket));

  // if no data, leave
  if (ub1->ub_cnt == 0)
      return;

  // get new bucket (with data table)
  size_t ub_len = sizeof(struct uma_bucket) + ub1->ub_cnt*sizeof(uintptr_t);
  ub2 = malloc(ub_len);
  kread (kd, ubp, ub2, ub_len);

  // read the data of each bucket
  uint16_t i;
  for (i = 0; i < ub2->ub_cnt; i++) {
    uint32_t ub_num = bucketsize/sizeof(uintptr_t);
    uintptr_t ub_data[ub_num];
    kread(kd, ub2->ub_bucket[i], &ub_data, bucketsize);

    uint32_t j;
    for (j = 0; j < ub_num; j++) {
      (*update)(ub_data[j], args);
    }
  }
  
  free(ub2);
}

void
scan_bucketlist(kvm_t *kd, struct uma_bucket *ubp, size_t bucketsize,
                scan_update update, void *args)
{
  struct uma_bucket ub;
  if (update == NULL)
    return;

  while (ubp != NULL) {
    scan_bucket(kd, ubp, &ub, bucketsize, update, args);
    ubp = LIST_NEXT(&ub, ub_link);
  }
}

void
scan_uma(kvm_t *kd, struct scan *update, void *args) {
  int all_cpus, mp_maxcpus, mp_maxid;
  LIST_HEAD(, uma_keg) uma_kegs;

  // Read symbols
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

  struct uma_keg *kzp, kz;
  for (kzp = LIST_FIRST(&uma_kegs); kzp != NULL; kzp =
      LIST_NEXT(&kz, uk_link)) {

    kread(kd, kzp, &kz, sizeof(kz));
    /*
    if (verbose) {
      printf("keg: 0x%lx\n", (uintptr_t)kzp);
      printf("\tslab size: %hu\n", kz.uk_slabsize);
      printf("\tobject size: %d\n", kz.uk_size);
    }
    */

    //char k_name [MEMTYPE_MAXNAME];
    kread_string(kd, kz.uk_name, k_name, MEMTYPE_MAXNAME);

    // full/part/free slabs
    scan_slab(kd, LIST_FIRST(&kz.uk_full_slab),
              kz.uk_slabsize, update->fullslabs, args);
    scan_slab(kd, LIST_FIRST(&kz.uk_part_slab),
              kz.uk_slabsize, update->partslabs, args);
    scan_slab(kd, LIST_FIRST(&kz.uk_free_slab),
              kz.uk_slabsize, update->freeslabs, args);

    // zones
    struct uma_zone * uzp;
    for (uzp = LIST_FIRST(&kz.uk_zones); uzp != NULL;
         uzp = LIST_NEXT(uz, uz_link)) {

      // get zone (without or with caches)
      kread (kd, uzp, uz, 
        (kz.uk_flags & UMA_ZFLAG_INTERNAL) ?
          sizeof(struct uma_zone) : uz_len);
    
      char z_name[MEMTYPE_MAXNAME];
      kread_string(kd, uz->uz_name, z_name, MEMTYPE_MAXNAME);

      scan_bucketlist(kd, LIST_FIRST(&uz->uz_buckets),
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
          scan_bucket(kd, uc->uc_allocbucket, &ub,
                      uz->uz_size, update->allocbuckets, args);
          scan_bucket(kd, uc->uc_freebucket, &ub,
                      uz->uz_size, update->freebuckets, args);
          
        }
      }

    } // zones
  } // kegs
}
