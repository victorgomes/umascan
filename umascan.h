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

/* symbols in kernel */
#define KSYM_UMA_KEGS     0
#define KSYM_MP_MAXCPUS   1
#define KSYM_MP_MAXID     2 
#define KSYM_ALLCPUS      3
#define KSYM_ALLPROC      4
#define KSYM_SIZE         6

/* umascan flags */
#define USCAN_SLAB      0x1
#define USCAN_BUCKET    0x2
#define USCAN_KSTACK    0x4
#define USCAN_GLOBAL    0x8
#define USCAN_REGISTER  0x10

#define USCAN_DEFAULT   0x1D
#define USCAN_ALL       0x1F

#ifdef DEBUG
int debug;
#define DEBUGSTR(...) if (debug > 0) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUGSTR(...)
#endif


struct usc_hdl;
typedef struct usc_hdl* usc_hdl_t;

struct usc_info {
  const char *usi_name;  /* zone name, register name, ... */
  int         usi_flag;  /* what is being scanned */
  uintptr_t   usi_data;  /* value of the current data being scanned */
  vm_offset_t usi_iaddr; /* address of the beginning of the item  */
  uintptr_t   usi_size;  /* size of item */
  void       *usi_arg;   /* private args to be passed when scanning */
};
typedef struct usc_info* usc_info_t;

typedef void (*umascan_t)(usc_info_t);

/* libumascan */
usc_hdl_t usc_create(const char *kernel, const char *core, int flags);
void usc_delete (usc_hdl_t hdl);
void umascan(usc_hdl_t hdl, umascan_t usc, void *args);

void kread(usc_hdl_t, const void *addr, void *buf, size_t size);
void kread_symbol(usc_hdl_t hdl, int sym_idx, void *buf, size_t size);
void kread_string(usc_hdl_t hdl, const void *addr, char *buf, int buflen);

/* pointer list */
struct plist;
struct plist* plist_create(void);
void plist_delete(struct plist *lst);
int plist_in(uintptr_t addr, struct plist *lst);
void plist_insert (struct plist *lst, uintptr_t addr,
                   const char *name, int rc_offset, const char *rc_type);
void plist_print(struct plist *lst);
struct plist* plist_from_file(FILE *fd);
struct plist* plist_from_dtrace(FILE *fd);

/* consumers */
void ptrscan (usc_hdl_t hdl, struct plist* lst);

#endif // _UMA_SCAN_H_
