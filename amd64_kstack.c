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

#include <err.h>
#include <string.h>

#include "umascan.h"

extern int debug;

struct amd64_frame {
  struct amd64_frame *f_frame;
  long f_retaddr;
  long f_arg0;
};

void scan_kstacks(usc_hdl_t, usc_info_t, umascan_t);

void
scan_kstacks(usc_hdl_t hdl, usc_info_t si, umascan_t upd)
{
  struct proc *p_addr, p;
  struct thread *td_addr, td;
  struct pcb pcb;
  struct amd64_frame *f_addr, frame;
  uintptr_t f_args_addr, *f_args, *f_arg;
  size_t f_args_size;
  char reg_name[15];

  kread_symbol(hdl, KSYM_ALLPROC, &p_addr, sizeof(p_addr));
  if (debug > 0)
    printf("allproc addr: %p\n", p_addr);

  while (p_addr != 0) {
    kread(hdl, p_addr, &p, sizeof(p));
    td_addr = TAILQ_FIRST(&p.p_threads);

    while (td_addr != 0) {
      kread(hdl, td_addr, &td, sizeof(td));
      kread(hdl, td.td_pcb, &pcb, sizeof(struct pcb));

      /* scan registers */
#define scan_reg(r) \
  strcpy(reg_name, "Register "); \
  si->usi_name = strcat(reg_name, #r); \
  si->usi_data = pcb.pcb_##r; \
  (*upd)(si);
        scan_reg(r15);
        scan_reg(r14);
        scan_reg(r13);
        scan_reg(r12);
        scan_reg(rbx);
        scan_reg(rip);
        scan_reg(cr0);
        scan_reg(cr2);
        scan_reg(cr3);
        scan_reg(cr4);
        scan_reg(dr0);
        scan_reg(dr1);
        scan_reg(dr2);
        scan_reg(dr3);
        scan_reg(dr6);
        scan_reg(dr7);

      // scan frames
      si->usi_name = "Stack frame arguments";
      f_addr = (struct amd64_frame*) pcb.pcb_rbp;
      while(1) {
        if (!f_addr)
          break;

        if (!INKERNEL((unsigned long)f_addr)) {
          warnx ("frame (%p) not in kernel.", f_addr);
          break;
        }

        kread(hdl, f_addr, &frame, sizeof(struct amd64_frame));
        if (!INKERNEL((uintptr_t)frame.f_retaddr)) {
          warnx( "return address of frame is not in kernel.");
          break;
        }

        // loop exit condition
        if (frame.f_frame <= f_addr ||
            (vm_offset_t)frame.f_frame >= td.td_kstack + td.td_kstack_pages * PAGE_SIZE) {
          break;
        }

        f_args_addr = (uintptr_t) f_addr + 16;
        f_args_size = ((uintptr_t)frame.f_frame) - f_args_addr;
        f_args = malloc(f_args_size);
        kread(hdl, (void*)f_args_addr, f_args, f_args_size);

        // scan arguments inside frames
        f_arg = (uintptr_t *)f_args;
        while (f_args_addr < (uintptr_t)frame.f_frame) {
          si->usi_data = *f_arg;
          (*upd)(si);
          f_arg++;
          f_args_addr+=8;
        }
        free(f_args);

        f_addr = frame.f_frame;
      } 
      td_addr = TAILQ_NEXT(&td, td_plist);
    }
    p_addr = LIST_NEXT(&p, p_list);
  }
}
