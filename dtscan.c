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
#include <string.h>

#include <dtrace.h>
#include <yaml.h>

#include "umascan.h"

static int sigintr;

static const char *struct_name = NULL, *rc_name = NULL, *rc_type = NULL;
static int rc_offset = -1;

static int 
chewrec (const dtrace_probedata_t *data, const dtrace_recdesc_t *rec, void *arg)
{
  struct plist *lst;
  uintptr_t addr;

  // second pass
  if (rec == NULL)
    return DTRACE_CONSUME_NEXT;

  addr = *(uintptr_t*)data->dtpda_data;
  lst = (struct plist *) arg;

  /* If we are already know the pointer, just skip */
  if (plist_in(addr, lst) || addr == 0)
    return DTRACE_CONSUME_NEXT;

  plist_insert(lst, addr, struct_name, rc_offset, rc_type);

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

static char *
concat (const char *s1, const char *s2)
{
  size_t len1, len2;
  char *r;

  len1 = strlen(s1);
  len2 = strlen(s2);
  r = malloc(len1+len2+1);
  
  memcpy(r, s1, len1);
  memcpy(r+len1, s2, len2+1);
  return r;
}
static const char *
create_probe_str (const char *prov, const char *mod, const char *fun, const char *dir, int arg)
{
  char *str;
  asprintf(&str, "%s:%s:%s:%s { printf(\"%%p\\n\", args[%d]); }\n",
    prov ? prov : "", mod ? mod : "", fun ? fun : "", dir ? dir : "", arg);
  return str;
}

static char*
parse_dtscript (FILE *fd)
{
  yaml_parser_t parser;
  yaml_event_t e;
  const char *tok;
  char * dtscript = "";
  const char *prov = NULL, *mod = NULL, *fun = NULL, *dir = NULL;
  int arg;

  enum {
    PARSE_TOP,
    PARSE_NAME,
    PARSE_RC,
    PARSE_RC_NAME,
    PARSE_RC_OFFSET,
    PARSE_RC_TYPE,
    PARSE_PROBES,
    PARSE_PROVIDER,
    PARSE_MODULE,
    PARSE_FUNCTION,
    PARSE_DIRECTION,
    PARSE_ARG
  } flag = PARSE_TOP;

  if (!yaml_parser_initialize(&parser))
    errx(-1, "failed to initialize yaml parser\n");

  yaml_parser_set_input_file(&parser, fd);

  do {
    if (!yaml_parser_parse(&parser, &e))
      errx(-1, "parse error: %d\n", parser.error);

    switch (e.type) {
    case YAML_SEQUENCE_END_EVENT:
      switch (flag) {
      case PARSE_TOP:
        break;
      case PARSE_PROBES:
        flag = PARSE_TOP;
        break;
      default:
        errx(-1, "wrong end of sequence");
        break;
      }
      break;
    case YAML_MAPPING_END_EVENT:
      switch (flag) {
      case PARSE_TOP:
        break;
      case PARSE_RC:
        flag = PARSE_TOP;
        break;
      case PARSE_PROBES:
        dtscript = concat (dtscript, create_probe_str(prov, mod, fun, dir, arg));
        prov = mod = fun = dir = NULL;
        break;
      default:
        errx(-1, "wrong end of mapping");
        break;
      }
      break;
    case YAML_SCALAR_EVENT:
      tok = (char*) e.data.scalar.value;
      switch (flag) {
      case PARSE_TOP:
        if (strcmp(tok, "name") == 0)
          flag = PARSE_NAME;
        else if (strcmp(tok, "ref_field") == 0)
          flag = PARSE_RC;
        else if (strcmp(tok, "probes") == 0)
          flag = PARSE_PROBES;
        else
          errx(-1, "parsing: wrong token in top");
        break;
      case PARSE_NAME:
        struct_name = strdup(tok);
        flag = PARSE_TOP;
        break;
      case PARSE_RC:
        if (strcmp(tok, "name") == 0)
          flag = PARSE_RC_NAME;
        else if (strcmp(tok, "offset") == 0)
          flag = PARSE_RC_OFFSET;
        else if (strcmp(tok, "type") == 0)
          flag = PARSE_RC_TYPE;
        else
          errx(-1, "parsing: wrong token in ref field");
        break;
      case PARSE_RC_NAME:
        rc_name = strdup(tok);
        flag = PARSE_RC;
        break;
      case PARSE_RC_OFFSET:
        rc_offset = atoi(tok);
        flag = PARSE_RC;
        break;
      case PARSE_RC_TYPE:
        rc_type = strdup(tok);
        flag = PARSE_RC;
        break;
      case PARSE_PROBES:
        if (strcmp(tok, "provider") == 0)
          flag = PARSE_PROVIDER;
        else if (strcmp(tok, "module") == 0)
          flag = PARSE_MODULE;
        else if (strcmp(tok, "function") == 0)
          flag = PARSE_FUNCTION;
        else if (strcmp(tok, "direction") == 0)
          flag = PARSE_DIRECTION;
        else if (strcmp(tok, "arg") == 0)
          flag = PARSE_ARG;
        else
          errx(-1, "parsing: wrong token in probes");
        break;
      case PARSE_PROVIDER:
        prov = strdup(tok);
        flag = PARSE_PROBES;
        break;
      case PARSE_MODULE:
        mod = strdup(tok);
        flag = PARSE_PROBES;
        break;
      case PARSE_FUNCTION:
        fun = strdup(tok);
        flag = PARSE_PROBES;
        break;
      case PARSE_DIRECTION:
        dir = strdup(tok);
        flag = PARSE_PROBES;
        break;
      case PARSE_ARG:
        arg = atoi(tok);
        flag = PARSE_PROBES;
        break;
      default:
        errx(-1, "parsing: unexpected token: %s", tok);
        break;
      }
    default:
      break;
    }

    if (e.type != YAML_STREAM_END_EVENT)
      yaml_event_delete(&e);

  } while (e.type != YAML_STREAM_END_EVENT);
  yaml_event_delete(&e);
  yaml_parser_delete(&parser);
  fclose(fd);
  
  DEBUGSTR("dtrace script:\n\n%s", dtscript);

  return dtscript;
}

struct plist*
plist_from_dtrace (FILE *fd)
{
  struct plist *lst;
  struct sigaction act;
  int errno, done;
  char* dtscript;

  dtrace_hdl_t* dtp;

  dtp = dtrace_open(DTRACE_VERSION, 0, &errno);
  if (dtp == NULL)
    err(-1, "failed to initilalize dtrace: %s\n", dtrace_errmsg(NULL, errno));

  dtrace_setopt(dtp, "bufsize", "4m");
  dtrace_setopt(dtp, "aggsize", "4m");

  if (fd == NULL)
    err(-1, "failed to open dtrace script..\n");

  dtscript = parse_dtscript(fd);
  dtrace_prog_t* prog = dtrace_program_strcompile(dtp, dtscript, DTRACE_PROBESPEC_NAME, 0, 0, NULL);
  if (prog == NULL)
    err(-1, "failed to compile dtrace program\n");
  free(dtscript);
  
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
  printf("dtrace started... press CTRL-C to stop.\n");

  lst = plist_create();

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