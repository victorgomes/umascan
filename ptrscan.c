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
#include <sys/queue.h>
#include <err.h>
#include <yaml.h>

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
  const char *p_struct_name;
  int p_rc_offset;
  const char *p_rc_type;
  SLIST_HEAD(,uz_info) uz_link;
  SLIST_ENTRY(p_info) p_link;
};

SLIST_HEAD(plist, p_info);

struct plist*
plist_create()
{
  struct plist* lst = malloc(sizeof(struct plist));
  if (lst)
    SLIST_INIT(lst);
  return lst;
}

void
plist_delete(struct plist* head)
{
  struct p_info * p;
  SLIST_FOREACH(p, head, p_link) {
    free(p);  
  }
  free(head);
}

int
plist_in (uintptr_t addr, struct plist *head)
{
  struct p_info *p;
  SLIST_FOREACH(p, head, p_link) {
    if (p->p_addr == addr)
      return 1;
  }
  return 0;
}

void
plist_insert (uintptr_t addr, struct plist *head)
{
  struct p_info *p = malloc(sizeof(struct p_info));
  p->p_addr = addr;
  SLIST_INSERT_HEAD(head, p, p_link);
}

void
plist_print (struct plist *head)
{
  struct p_info * p;
  struct uz_info *uz;

  SLIST_FOREACH(p, head, p_link) {
    printf("0x%lx:\n", p->p_addr);
    printf("\tzone name: %s\n", p->p_zone ? p->p_zone : "<unknown>");
    
    if (p->p_rc_offset != -1)
      printf("\tref count: %ld\n", p->p_refc);
    printf("\ttotal count: %d\n", p->p_count);

    SLIST_FOREACH(uz, &p->uz_link, uz_link) {
      printf("\t\t%s: %d\n", uz->uz_name, uz->uz_count);
    }
  }
}

static void
parse (yaml_parser_t *p, yaml_event_t *e, const char *errmsg)
{
  if (!yaml_parser_parse(p, e)) {
    if (!errmsg)
      errx(-1, "parse error: %s\n", errmsg);
    else
      errx(-1, "parse error: %d\n", p->error);
  }
}

static void
add_ptr_to_plist (struct plist *head, uintptr_t addr, int rc_offset, const char *rc_type)
{
  struct p_info *p = malloc(sizeof(struct p_info));
  p->p_addr = addr;
  p->p_zone = NULL;
  p->p_count = 0;
  p->p_refc = -1;
  p->p_rc_offset = rc_offset;
  p->p_rc_type = rc_type;
  SLIST_INIT(&p->uz_link);
  SLIST_INSERT_HEAD(head, p, p_link);
}

struct plist*
plist_from_file(FILE * fd)
{
  yaml_parser_t parser;
  yaml_event_t e;
  struct plist * plist;
  const char* tok, *struct_name = "", *rc_type = "";
  int rc_offset = -1;

  enum {
    PARSE_TOP,
    PARSE_POINTERS,
    PARSE_NAME,
    PARSE_RC,
    PARSE_RC_OFFSET,
    PARSE_RC_TYPE,
    PARSE_VALUES
  } flag = PARSE_TOP;

  yaml_parser_initialize(&parser);

  if (!yaml_parser_initialize(&parser))
    errx(-1, "failed to initialize yaml parser\n");
  
  yaml_parser_set_input_file(&parser, fd);

  plist = plist_create();
  do {
    parse(&parser, &e, NULL);

    switch (e.type) {
    case YAML_SEQUENCE_END_EVENT:
      switch(flag) {
      case PARSE_TOP:
        break;
      case PARSE_VALUES:
        flag = PARSE_POINTERS;
        break;
      default:
        errx(-1, "wrong format -- sequence");
        break;
      }
      break;
    case YAML_MAPPING_END_EVENT:
      switch(flag) {
      case PARSE_TOP:
        break;
      case PARSE_POINTERS:
        struct_name = NULL;
        rc_offset = -1;
        rc_type = "";
        flag = PARSE_TOP;
        break;
      case PARSE_RC:
        flag = PARSE_POINTERS;
        break;
      default:
        errx(-1, "wrong format - mapping");
      }
      break;
    case YAML_SCALAR_EVENT: 
      tok = (char*) e.data.scalar.value;
      switch(flag) {
      case PARSE_TOP:
        if (strcmp(tok, "pointers") == 0)
          flag = PARSE_POINTERS;
        else
          add_ptr_to_plist (plist, strtoull(tok, NULL, 0), rc_offset, rc_type);
        break;
      case PARSE_POINTERS:
        if (strcmp(tok, "name") == 0)
          flag = PARSE_NAME;
        else if (strcmp(tok, "ref_field") == 0)
          flag = PARSE_RC;
        else if (strcmp(tok, "values") == 0)
          flag = PARSE_VALUES;
        else
          errx(-1, "wrong format, expecting `name`, `ref_field` and `values`");
        break;
      case PARSE_NAME:
        struct_name = strdup(tok);
        flag = PARSE_POINTERS;
        break;
      case PARSE_RC:
        if (strcmp(tok, "offset") == 0)
          flag = PARSE_RC_OFFSET;
        else if (strcmp(tok, "type") == 0)
          flag = PARSE_RC_TYPE;
        break;
      case PARSE_RC_OFFSET:
        rc_offset = atoi(tok);
        flag = PARSE_RC;
        break;
      case PARSE_RC_TYPE:
        rc_type = strdup(tok);
        flag = PARSE_RC;
        break;
      case PARSE_VALUES:
        add_ptr_to_plist (plist, strtoull(tok, NULL, 0), rc_offset, rc_type);
        break;
      }
      break;
     default:
        break;
    }

    if (e.type != YAML_STREAM_END_EVENT)
      yaml_event_delete(&e);

  } while (e.type != YAML_STREAM_END_EVENT);
  yaml_event_delete(&e);

  yaml_parser_delete(&parser);

  fclose(fd);
  return plist;
}

static void
update (usc_info_t si)
{
  struct plist *ps = (struct plist *)si->usi_arg;
  struct p_info * p;
  struct uz_info* uz = NULL;
  int found = 0;
  
  SLIST_FOREACH(p, ps, p_link) {
    if (si->usi_iaddr <= p->p_addr && p->p_addr < si->usi_iaddr + si->usi_size) {
      p->p_zone = strdup(si->usi_name);
    }

   if (si->usi_data == p->p_addr) {
      uz = NULL;
      found = 0;
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
ptrscan(usc_hdl_t hdl, struct plist *lst)
{
  umascan(hdl, &update, lst);
  struct p_info * p;
  SLIST_FOREACH(p, lst, p_link) {
    /* only update refc if offset exists and the pointer was found by umascan,
     * otherwise we risk of deferencing a non existing pointer */
    if (p->p_rc_offset != -1 && p->p_zone)
      kread(hdl, (void*)(p->p_addr + p->p_rc_offset), &p->p_refc, sizeof(int64_t));
  }
  plist_print(lst);
}
