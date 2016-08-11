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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/cpuset.h>

#define LIBMEMSTAT
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <vm/uma_int.h>

#include <stdio.h>
#include <stdlib.h>

#include "umascan.h"

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
    p->partcount = 0;
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

#define fn_update(field) \
  void update_##field (uintptr_t data, void *args) \
  { \
    struct pointerlist *ps = (struct pointerlist *)args; \
    pointer_t * p; \
    SLIST_FOREACH(p, ps, p_link) { \
      if (data == p->addr) { \
        p->field++; \
      } \
    } \
  }

static fn_update(fullcount)
static fn_update(freecount)
static fn_update(partcount)
static fn_update(zonefull)
static fn_update(fullcache)
static fn_update(freecache)

int
scan_pointers(kvm_t *kd, FILE *fd)
{
  struct pointerlist ps;

  // fill pointer list
  create_pointerlist(fd, &ps);

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

  return 0;
}

