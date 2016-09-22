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

#include <err.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include <dtrace.h>

#include "umascan.h"

static int sigintr;

static int 
chewrec (const dtrace_probedata_t *data, const dtrace_recdesc_t *rec, void *arg)
{
  uint64_t *base;
  struct plist *lst;
  uintptr_t addr;

  // second pass
  if (rec == NULL)
    return DTRACE_CONSUME_NEXT;

  base = (uint64_t*)data->dtpda_data;
  lst = (struct plist *) arg;

  /* First rec points to printf action and the second to the
   * first argument of printf */
  rec++;
  addr = *(base + rec->dtrd_offset);

  /* If we are already know the pointer, just skip */
  if (in_plist(addr, lst))
    return DTRACE_CONSUME_NEXT;

  insert_plist(addr, lst);

  switch (data->dtpda_flow) {
  case DTRACEFLOW_ENTRY:
    printf("\tENTRY:");
    break;
  case DTRACEFLOW_RETURN:
    printf("\tRETURN:n");
    break;
  case DTRACEFLOW_NONE:
    break;
  }

  dtrace_probedesc_t *epd = data->dtpda_pdesc;
  printf("%s:%s:%s:%s", epd->dtpd_name, epd->dtpd_provider,
    epd->dtpd_mod, epd->dtpd_func);
  printf("\t%lx\n", addr);
  
  return DTRACE_CONSUME_NEXT;
}

static void
intr (int signo)
{
  sigintr = 1;
}

struct plist*
from_dtrace (FILE *fd)
{
  struct plist *lst;
  struct sigaction act;
  int errno, done;

  dtrace_hdl_t* dtp;

  dtp = dtrace_open(DTRACE_VERSION, 0, &errno);
  if (dtp == NULL)
    err(-1, "failed to initilalize dtrace: %s\n", dtrace_errmsg(NULL, errno));

  dtrace_setopt(dtp, "bufsize", "4m");
  dtrace_setopt(dtp, "aggsize", "4m");

  if (fd == NULL)
    err(-1, "failed to open dtrace script..\n");
  dtrace_prog_t* prog = dtrace_program_fcompile(dtp, fd, 0, 0, NULL);
  if (prog == NULL)
    err(-1, "failed to compile dtrace program\n");
  fclose(fd);
  
  dtrace_proginfo_t info;
  if (dtrace_program_exec(dtp, prog, &info) == -1)
    err(-1, "failed to enable dtrace probes\n");

  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;
  act.sa_handler = intr;
  sigaction (SIGINT, &act, NULL);
  sigaction (SIGTERM, &act, NULL);

  if (dtrace_go(dtp) != 0)
    err(-1, "could not start instrumentation\n");
  printf("dtrace started... Press CTRL-C to stop.\n");

  lst = create_plist();

  done = 0;
  do {
    if (!sigintr && !done) {
      dtrace_sleep(dtp);
    }

    if (done || sigintr) {
      done = 1;
      if (dtrace_stop(dtp) == -1)
        err(-1, "could not stop tracing\n");
    }

    switch (dtrace_work(dtp, stdout, NULL, chewrec, lst)) {
      case DTRACE_WORKSTATUS_DONE:
        done = 1;
        break;
      case DTRACE_WORKSTATUS_OKAY:
        break;
      default:
        err(-1, "process aborted");
    }
  } while (!done);

  dtrace_close(dtp);

  return lst;
}    