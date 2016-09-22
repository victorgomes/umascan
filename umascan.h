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

#include <sys/cpuset.h>
#include <vm/uma.h>
#include <vm/uma_int.h>

struct usc_hdl;
typedef struct usc_hdl* usc_hdl_t;

enum usc_type {
  USCAN_SLAB,
  USCAN_BUCKET
};

struct usc_info {
  struct uma_keg* usi_uk; 
  struct uma_zone* usi_uz;
  struct uma_slab* usi_us;
  char * usi_name;
  enum usc_type usi_type; 
  uint64_t usi_data;    // value of the current data being scanned
  uintptr_t usi_iaddr;  // address of the beginning of the item 
  uintptr_t usi_size;   // size of item
  void * usi_arg;       // private args to be passed when scanning
};
typedef struct usc_info* usc_info_t;

typedef void (*umascan_t)(usc_info_t);

/* libumascan */
usc_hdl_t create_usc_hdl (const char *kernel, const char *core);
void delete_usc_hdl (usc_hdl_t hdl);
void memread (usc_hdl_t, const void *addr, void *buf, size_t size);
void umascan(usc_hdl_t hdl, umascan_t usc, void *args);

/* pointer list */
struct plist;
struct plist* create_plist(void);
void destroy_plist(struct plist *lst);
int in_plist(uintptr_t addr, struct plist *lst);
void insert_plist(uintptr_t addr, struct plist *lst);
void print_plist(struct plist *lst);

struct plist* from_file(FILE *fd);
struct plist* from_dtrace(FILE *fd);

/* consumers */
void ptrscan (usc_hdl_t hdl, struct plist* lst);
void kread_kthr (usc_hdl_t hdl);
void print_kthr (usc_hdl_t hdl);
void print_mhdr (usc_hdl_t hdl);

#endif // _UMA_SCAN_H_
