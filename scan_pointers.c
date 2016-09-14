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
#include <string.h>

#include "umascan.h"

struct uz_info {
  const char *uz_name;
  int uz_count;
  SLIST_ENTRY(uz_info) uz_link;
};

struct p_info {
  uintptr_t p_addr;
  int64_t p_refc;
  int p_count;
  const char *p_zone;
  SLIST_HEAD(,uz_info) uz_link;
  SLIST_ENTRY(p_info) p_link;
};

SLIST_HEAD(plist, p_info);

static void
create_plist(FILE * addrfd, struct plist * head)
{
  uintptr_t addr;
  SLIST_INIT(head);
  while (fscanf(addrfd, "%lx", &addr) != EOF) {
    struct p_info * p = malloc(sizeof(struct p_info));
    p->p_addr = addr;
    p->p_zone = NULL;
    p->p_count = 0;
    p->p_refc = -1;
    SLIST_INIT(&p->uz_link);
    SLIST_INSERT_HEAD(head, p, p_link);
  }
}

static void
free_plist(struct plist * head)
{
  struct p_info * p;
  SLIST_FOREACH(p, head, p_link) {
    free(p);  
  }
}

static void
print_plist(struct plist *head)
{
  struct p_info * p;
  SLIST_FOREACH(p, head, p_link) {
    printf("0x%lx:\n", p->p_addr);
    printf("\tzone name: %s\n", p->p_zone ? p->p_zone : "<unknown>");
    
    printf("\tref count: %ld\n", p->p_refc);
    printf("\ttotal count: %d\n", p->p_count);

    struct uz_info *uz;
    SLIST_FOREACH(uz, &p->uz_link, uz_link) {
      printf("\t\t%s: %d\n", uz->uz_name, uz->uz_count);
    }
  }
}

static void update (usc_info_t si)
{
  struct plist *ps = (struct plist *)si->usi_arg;
  struct p_info * p;
  
  SLIST_FOREACH(p, ps, p_link) {
    if (si->usi_iaddr <= p->p_addr && p->p_addr < si->usi_iaddr + si->usi_size) {
      p->p_zone = strdup(si->usi_name);
    }

   if (si->usi_data == p->p_addr) {
      struct uz_info* uz = NULL;
      int found = 0;

      p->p_count++;

      if (!(SLIST_EMPTY(&p->uz_link))) {
        SLIST_FOREACH (uz, (&p->uz_link), uz_link) {
          if(strcmp(si->usi_name, uz->uz_name) == 0) {
            uz->uz_count++;
            found = 1;
            break;
          }
        }
      }

      if (!found) {
        uz = malloc(sizeof(struct uz_info));
        uz->uz_count = 1;
        uz->uz_name = strdup(si->usi_name);
        SLIST_INSERT_HEAD(&p->uz_link, uz, uz_link);
      }       
    }
  }
}

void
scan_ptrs(usc_hdl_t hdl, FILE *fd)
{
  struct plist ps;
  //enum mode_t mode = hdl->usc_mode;

  // fill pointer list
  create_plist(fd, &ps);
  umascan(hdl, &update, &ps);

  struct p_info * p;
  SLIST_FOREACH(p, &ps, p_link) {
    memread(hdl, (void*)p->p_addr, &p->p_refc, sizeof(int64_t));
  }

  print_plist(&ps);
  free_plist(&ps);
}

