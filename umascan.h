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

#ifndef _UMASCAN_H_
#define _UMASCAN_H_

#include <sys/types.h>
#include <sys/cpuset.h>
#include <sys/queue.h>

#define LIBMEMSTAT  /* Cause vm_page.h not to include opt_vmpage.h */
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <vm/uma_int.h>

#include <kvm.h>
#include <limits.h>
#include <stdio.h>

#define CRASHDIR "/var/crash"

struct kthr {
  uintptr_t paddr;
  uintptr_t kaddr;
  uintptr_t kstack;
  int kstack_pages;
  uintptr_t pcb;
  int tid;
  int pid;
  u_char cpu;
  SLIST_ENTRY(kthr) k_link;
};

struct coreinfo {
  kvm_t *kd;
  struct uma_keg *masterkeg;
  int maxcpus;
  int mp_maxid;
  uintptr_t allproc;
  uintptr_t zombproc; // unused
  uintptr_t dumppcb;
  int dumptid;
  cpuset_t stopped_cpus;
  SLIST_HEAD(, kthr) kthrs;
};

enum us_type {
  FULL_SLABS,
  PART_SLABS,
  FREE_SLABS
};

struct scaninfo {
  struct uma_keg* uk; 
  struct uma_zone* uz;
  struct uma_slab* us;
  char * uk_name;
  // value of the current data being scanned
  uint64_t data;
  // bounds of current item being scanned
  uintptr_t itemp; // pointer to the beginning of the item 
  uintptr_t size;  // size of item
  // private args to be passed when scanning
  void * priv;
};

typedef void (*umascan_t)(struct scaninfo*);

int init_masterkeg(kvm_t *kd, struct uma_keg* uk);
int init_coreinfo (kvm_t *kd, struct coreinfo* cinfo);

int kread (kvm_t *kd, uintptr_t addr, void *buf, size_t size);
int kread_symbol (kvm_t *kd, int index, void *buf, size_t size);
int kread_string(kvm_t *kd, const void *addr, char *buf, int buflen);

void kread_kthr (kvm_t *kd, struct coreinfo *cinfo);

void scan_slab (kvm_t *kd, uintptr_t usp, struct scaninfo* si, umascan_t upd, enum us_type ust);
/*
void scan_bucket (kvm_t *kd, uintptr_t, struct uma_bucket *ub1, 
                  size_t bucketsize, umascan_update update, void *args);
void scan_bucketlist (kvm_t *kd, uintptr_t ubp, size_t bucketsize, 
                  umascan_update update, void *args);
*/
void scan_uma(kvm_t *kd, umascan_t upd, void *args);


int scan_pointers (kvm_t *kd, FILE *fd);

void print_kthr(struct coreinfo *cinfo);
void print_mhdr(struct coreinfo *cinfo);

#endif // _UMA_SCAN_H_
