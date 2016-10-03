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
#include <sys/user.h>
#include <sys/cpuset.h>
#include <vm/uma.h>
#include <vm/uma_int.h>

#include <err.h>
#include <kvm.h>
#include <sysexits.h>
#include <memstat.h>

#include <assert.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fcntl.h>
#include <gelf.h>

#include "umascan.h"

/* machine dependent */
void scan_kstacks(usc_hdl_t hdl, usc_info_t si, umascan_t upd);

typedef enum usc_slabinkeg {
  FULL_SLABS,
  PART_SLABS,
  FREE_SLABS
} usc_slabinkeg_t;

struct usc_hdl {
  kvm_t *usc_kd;
  Elf *usc_e;
  int usc_symfd;
  struct nlist usc_ksym[KSYM_SIZE];
  int usc_flags;
  uma_keg_t usc_uk;
  uma_zone_t usc_uz;
};

usc_hdl_t
usc_create (const char *kernel, const char *core, int flags)
{
  int fd;
  kvm_t* kd;
  Elf* e = NULL;
  usc_hdl_t hdl = NULL;
  
  if (elf_version(EV_CURRENT) == EV_NONE) {
    warnx("ELF library initialization failed: %s", elf_errmsg(-1));
    return NULL;
  }

  if ((kd = kvm_openfiles(kernel, core, NULL, 0, "kvm")) == NULL) {
    warnx("kvm_open: %s", kvm_geterr(kd));
    return NULL;
  }
  if ((fd = open(kernel, O_RDONLY, 0)) < 0) {
    warn("open \"%s\" failed", kernel);
    goto error;
  }

  if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
    warnx("elf begin() failed: %s", elf_errmsg(-1));
    goto error;
  }

  if (elf_kind(e) != ELF_K_ELF) {
    warnx("\"%s\" is not an ELF object", kernel);
    goto error;
  }

  hdl = malloc(sizeof(struct usc_hdl));
  hdl->usc_kd = kd;
  hdl->usc_e = e;
  hdl->usc_symfd = fd;
  hdl->usc_uk = NULL;
  hdl->usc_uz = NULL;
  hdl->usc_flags = flags ? flags : USCAN_DEFAULT;

  hdl->usc_ksym[KSYM_UMA_KEGS].n_value = 0;
  hdl->usc_ksym[KSYM_UMA_KEGS].n_name = "_uma_kegs";
  hdl->usc_ksym[KSYM_MP_MAXCPUS].n_name = "_mp_maxcpus";
  hdl->usc_ksym[KSYM_MP_MAXID].n_name = "_mp_maxid";
  hdl->usc_ksym[KSYM_ALLCPUS].n_name = "_all_cpus";
  hdl->usc_ksym[KSYM_ALLPROC].n_name = "_allproc";
  hdl->usc_ksym[KSYM_SIZE-1].n_name = "";

  if (kvm_nlist(kd, hdl->usc_ksym) != 0) {
    warnx("kvm_nlist: %s", kvm_geterr(kd));
    goto error;
  }

  if (hdl->usc_ksym[KSYM_UMA_KEGS].n_type == 0 || hdl->usc_ksym[KSYM_UMA_KEGS].n_value == 0) {
    warnx("kvm_nlist return");
    goto error;
  }

  return hdl;

error:
  if (e)
    elf_end(e);
  close(fd); 
  kvm_close(kd);
  if (hdl)
    free(hdl);
  return NULL;
}

void
usc_delete (usc_hdl_t hdl)
{
  elf_end(hdl->usc_e);
  close(hdl->usc_symfd);  
  kvm_close(hdl->usc_kd);
  free(hdl);
}

void
kread(usc_hdl_t hdl, const void* addr, void *buf, size_t size)
{
  ssize_t ret;
  if (!INKERNEL((uintptr_t)addr))
    warnx("address %p is not located in kernel area", addr);
  ret = kvm_read(hdl->usc_kd, (uintptr_t)addr, buf, size);
  if (ret < 0)
    errx(MEMSTAT_ERROR_KVM, "kread (%p): %s", addr, kvm_geterr(hdl->usc_kd));
  if ((size_t)ret != size)
    errx(MEMSTAT_ERROR_KVM_SHORTREAD, "kread (%p): %s", addr, kvm_geterr(hdl->usc_kd));
}

void
kread_symbol(usc_hdl_t hdl, int index, void *buf, size_t size)
{
  uintptr_t addr = hdl->usc_ksym[index].n_value;
  if (addr == 0)
    err(-1, "%s: symbol address null", hdl->usc_ksym[index].n_name);
  kread(hdl, (void*)addr, buf, size);
}

void
kread_string(usc_hdl_t hdl, const void *addr, char *buf, int buflen)
{
  int i;
  for (i = 0; i < buflen; i++) {
    kread(hdl, (void*)((uint8_t*)addr + i), &(buf[i]), sizeof(char));
    if (buf[i] == '\0')
      return;
  }
  /* Truncate. */
  buf[i-1] = '\0';
}

static void
scan_globals (usc_hdl_t hdl, usc_info_t si, umascan_t upd)
{
  char *name;
  Elf_Scn *scn;
  GElf_Shdr shdr;
  size_t i, shstrndx;
  uint8_t* data;

  if (elf_getshdrstrndx(hdl->usc_e, &shstrndx) != 0)
    errx(EX_DATAERR, "elf_getshdrstrndx() failed: %s", elf_errmsg(-1));

  scn = NULL;

  while ((scn = elf_nextscn(hdl->usc_e, scn)) != NULL) {
    if (gelf_getshdr(scn, &shdr) != &shdr)
      errx(EX_SOFTWARE, "getshdr() failed: %s", elf_errmsg(-1));

    if (shdr.sh_flags & ~(SHF_ALLOC | SHF_WRITE) || shdr.sh_flags == 0)
      continue;

    if ((name = elf_strptr(hdl->usc_e, shstrndx, shdr.sh_name)) == NULL)
      errx(EX_SOFTWARE, "elf_strptr() failed: %s", elf_errmsg(-1));

    if (!INKERNEL(shdr.sh_addr)) {
      warnx("section header \"%s\" not in kernel space", name);
      continue;
    }

    si->usi_name = name;
    si->usi_flag = USCAN_GLOBAL;
    si->usi_iaddr = shdr.sh_addr;
    si->usi_size = shdr.sh_size;
    
    data = malloc(shdr.sh_size);
    kread(hdl, (void*)shdr.sh_addr, data, shdr.sh_size);
    
    for(i = 0; i < shdr.sh_size; i+= sizeof(uintptr_t)) {
      si->usi_data = *(uintptr_t*)(data + i);
      (*upd)(si);
    }

    free(data);
  }
}

static int
scan_slab(usc_hdl_t hdl, struct uma_slab *usp, usc_info_t si, umascan_t upd, usc_slabinkeg_t usk)
{
  struct uma_slab us;
  int i, ipers, uk_freecount = 0, us_freecount = 0;
  size_t j, isize, irsize, ussize;
  uintptr_t *iptr, *iend;
  uint8_t *us_data, *us_item;
  
  ipers = hdl->usc_uk->uk_ipers;
  isize = hdl->usc_uk->uk_size;
  irsize = hdl->usc_uk->uk_rsize;

  /* array of items in the slabs */
  ussize = ipers * isize;
  us_data = malloc(ussize);

  while (usp != NULL) {
    us_freecount = 0;
    
    kread(hdl, usp, &us, sizeof(struct uma_slab));
    kread(hdl, us.us_data, us_data, ussize);

    for (i = 0; i < ipers; i++) {
      // is it a free item?
      if (BIT_ISSET(SLAB_SETSIZE, i, &us.us_free)) {
        us_freecount++;
        continue;
      }

      si->usi_iaddr = (uintptr_t) us.us_data + i*isize;
      us_item = us_data + i*isize;

      /* let's be sure to not go beyound the size of the array */
      assert (us_item < us_data + ussize);
      
      if (!upd)
        continue;
 
      for (j = 0; j < irsize; j += sizeof(uintptr_t)) {
        si->usi_data = *(uintptr_t*)(us_item + j);
        (*upd)(si);
      }
    }

    /* free slabs do not seem to be using us_freecount field */
    if (usk != FREE_SLABS)
      assert (us_freecount == us.us_freecount);

    uk_freecount += us_freecount;
    usp = LIST_NEXT(&us, us_link);
  }
  
  free (us_data);
  return uk_freecount;
}

static int
scan_bucket(usc_hdl_t hdl, struct uma_bucket *ubp, struct uma_bucket *ub,
            usc_info_t si, umascan_t upd)
{
  int i;
  size_t j, ub_size, isize;
  void ** ub_bucket;
  uint8_t *ub_data;

  if (ubp == 0)
    return 0 ;

  // get a bucket (without data table)
  kread(hdl, ubp, ub, sizeof(struct uma_bucket));

  if (!upd)
    return ub->ub_cnt;

  // if no data, leave
  if (ub->ub_cnt == 0)
      return 0;

  // get data table
  ub_size = ub->ub_entries*sizeof(void*);
  ub_bucket = malloc(ub_size);
  kread(hdl, ubp + offsetof(struct uma_bucket, ub_bucket), ub_bucket, ub_size);

  // allocate data for an item
  isize = hdl->usc_uz->uz_size;
  ub_data = malloc(isize);

  // read the data of each bucket
  for (i = 0; i < ub->ub_entries - ub->ub_cnt; i++) {
    kread(hdl, ub_bucket[i], ub_data, isize);
    for (j = 0; j < isize; j += sizeof(uintptr_t)) {
      si->usi_data = *(uintptr_t*)(ub_data + j);
      (*upd)(si);
    }
  }

  free (ub_data);
  free (ub_bucket);
  return ub->ub_cnt;
}

static int
scan_bucketlist(usc_hdl_t hdl, struct uma_bucket *ubp, usc_info_t si, umascan_t upd)
{
  struct uma_bucket ub;

  if (upd == NULL)
    return 0;

  int ub_cnt = 0;
  while (ubp != NULL) {
    ub_cnt += scan_bucket(hdl, ubp, &ub, si, upd);
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
  LIST_HEAD(, uma_keg) uma_kegs;

  hdl->usc_uk = NULL;
  si.usi_arg = arg;

  /* read symbols */
  kread_symbol(hdl, KSYM_MP_MAXCPUS, &mp_maxcpus, sizeof(mp_maxcpus));
  kread_symbol(hdl, KSYM_MP_MAXID, &mp_maxid, sizeof(mp_maxid));
  kread_symbol(hdl, KSYM_UMA_KEGS, &uma_kegs, sizeof(uma_kegs));
  
  cpusetsize = sysconf(_SC_CPUSET_SIZE);
  if (cpusetsize == -1 || (u_long)cpusetsize > sizeof(cpuset_t))
    err(MEMSTAT_ERROR_KVM_NOSYMBOL, "bad cpusetsize");

  CPU_ZERO(&all_cpus);  
  kread_symbol(hdl, KSYM_ALLCPUS, &all_cpus, cpusetsize);

  /* scan globals */
  if (hdl->usc_flags & USCAN_GLOBAL)
    scan_globals(hdl, &si, upd);

  /* scan kernel stacks */
  if (hdl->usc_flags & USCAN_KSTACK)  
    scan_kstacks(hdl, &si, upd);

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
    
    kread(hdl, ukp, &uk, sizeof(uk));
    hdl->usc_uk = &uk;

    kread_string(hdl, uk.uk_name, uk_name, MEMTYPE_MAXNAME);
    si.usi_name = uk_name;
    si.usi_flag = USCAN_SLAB;
    si.usi_size = uk.uk_size;
    
    // full/part/free slabs
    uint32_t uk_freecount = 0;
    if (hdl->usc_flags & USCAN_SLAB) {
      uk_freecount += scan_slab (hdl, LIST_FIRST(&uk.uk_full_slab), &si, upd, FULL_SLABS);
      uk_freecount += scan_slab (hdl, LIST_FIRST(&uk.uk_free_slab), &si, upd, FREE_SLABS);
      uk_freecount += scan_slab (hdl, LIST_FIRST(&uk.uk_part_slab), &si, upd, PART_SLABS);

      assert (uk_freecount == uk.uk_free);
    }

    // no point to continue if we are not scanning buckets
    if (!(hdl->usc_flags & USCAN_BUCKET))
      continue;
    si.usi_flag = USCAN_BUCKET;

    // zones
    struct uma_zone *uzp;
    for (uzp = LIST_FIRST(&uk.uk_zones); uzp != 0;
         uzp = LIST_NEXT(uz, uz_link)) {

      // get zone (without or with caches)
      kread (hdl, uzp, uz, uz_len);
      hdl->usc_uz = uz;
      
      // the zone's keg needs to point to our keg
      assert (ukp == uz->uz_klink.kl_keg);

      kread_string(hdl, uz->uz_name, uz_name, MEMTYPE_MAXNAME);

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

      mt_free += scan_bucketlist(hdl, LIST_FIRST(&uz->uz_buckets), &si, upd);
      
      // if zone has caches per cpu
      if (!(uk.uk_flags & UMA_ZFLAG_INTERNAL)) {
        struct uma_bucket *ub = malloc(sizeof(struct uma_bucket));
        for (int cpu = 0; cpu <= mp_maxid; cpu++) {
          if (!CPU_ISSET(cpu, &all_cpus))
            continue;
          
          struct uma_cache *uc = &uz->uz_cpu[cpu];
          mt_free += scan_bucket(hdl, uc->uc_allocbucket, ub, &si, upd);
          mt_free += scan_bucket(hdl, uc->uc_freebucket, ub, &si, upd);
        }
        free(ub);
      }

    } // zones
  } // kegs
  free(uz);
}
