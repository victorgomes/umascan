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
#include <sys/stat.h>

#include <err.h>
#include <sysexits.h>
#include <paths.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "umascan.h"

#define CRASHDIR "/var/crash"

int debug; // Debug level (usually 0)

typedef enum {
  M_NONE,
  M_SCAN_SLABS,
  M_SCAN_BUCKETS,
  M_DTRACE
} scn_mode_t ;

static void
usage()
{
  fprintf(stderr,
          "usage: %s [-v] [-n dumpnr | -c core] [-k kernel] (-s addr | -z prbs)\n",
          getprogname());
  exit(EX_USAGE);
}

static const char *
vmcore_from_dumpnr (int dumpnr)
{
  char path[PATH_MAX];
  struct stat st;
  if (dumpnr > 0)
    snprintf(path, sizeof(path), "%s/vmcore.%d", CRASHDIR, dumpnr);
  else
    snprintf(path, sizeof(path), "%s/vmcore.last", CRASHDIR);
  if (stat(path, &st) == -1)
    err(EX_NOINPUT, "%s", path);    
  if (!S_ISREG(st.st_mode))
    errx(EX_NOINPUT, "%s: not a regular file", path);
  return strdup(path);
}

static const char *
kernel_from_vmcore(const char * vmcore)
{
  char path[PATH_MAX];
  char *crashdir = strdup(vmcore);
  FILE *info;
  char *s;
  struct stat st;
  int ret, nr, l;

  s = strrchr(crashdir, '/');
  
  if (s) {
    /* truncate crash path */
    *s = '\0';
    vmcore = s+1;
  } else {
    free(crashdir);
    crashdir = "";
  }

  s = strrchr(vmcore, '.');
  // No dump number, impossible to get kernel image
  if (!s)
    return NULL;

  ret = sscanf(strrchr(vmcore, '.')+1, "%d", &nr);
  if (ret < 1)
    return NULL;

  /*
   * Copied from kgdb/main.c
   **/
  
  /*
   * If there's a kernel image right here in the crash directory, then
   * use it.  The kernel image is either called kernel.<nr> or is in a
   * subdirectory kernel.<nr> and called kernel.  The latter allows us
   * to collect the modules in the same place.
   */
  snprintf(path, sizeof(path), "%s/kernel.%d", crashdir, nr);
  if (stat(path, &st) == 0) {
    if (S_ISREG(st.st_mode)) {
      return strdup(path);
    }
    if (S_ISDIR(st.st_mode)) {
      snprintf(path, sizeof(path), "%s/kernel.%d/kernel",
          crashdir, nr);
      if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
        return strdup(path);
      }
    }
  }

  /*
   * No kernel image here.  Parse the dump header.  The kernel object
   * directory can be found there and we probably have the kernel
   * image still in it.  The object directory may also have a kernel
   * with debugging info (called kernel.debug).  If we have a debug
   * kernel, use it.
   */
  snprintf(path, sizeof(path), "%s/info.%d", crashdir, nr);
  info = fopen(path, "r");
  if (info == NULL) {
    warn("%s", path);
    return NULL;
  }
  while (fgets(path, sizeof(path), info) != NULL) {
    l = strlen(path);
    if (l > 0 && path[l - 1] == '\n')
      path[--l] = '\0';
    if (strncmp(path, "    ", 4) == 0) {
      s = strchr(path, ':');
      s = (s == NULL) ? path + 4 : s + 1;
      l = snprintf(path, sizeof(path), "%s/kernel.debug", s);
      if (stat(path, &st) == -1 || !S_ISREG(st.st_mode)) {
        path[l - 6] = '\0';
        if (stat(path, &st) == -1 ||
            !S_ISREG(st.st_mode))
          break;
      }
      break;
    }
  }
  fclose(info);
  
  if (!strcmp(crashdir, ""))
    free(crashdir);

  return strdup(path);
}

int
main(int argc, char *argv[])
{
  FILE *fd = NULL;
  scn_mode_t mode;
  const char *vmcore = NULL, *kernel = NULL;
  char *s;
  int ch, verbose = 0, dumpnr = -1;
  struct plist* lst;

  debug = 0;

  while ((ch = getopt(argc, argv, "hvn:c:d:k:szb")) != -1) {
    switch (ch) {
    case 'v':
      verbose = 1;
      break;
    case 'n': 
      dumpnr = strtol(optarg, &s, 0);
      if (dumpnr < 0 || *s == '\0') {
        warnx("option %c: invalid kernel dump number", optopt);
        usage();
      }
      break;
    case 'k':
      kernel = strdup(optarg);
      break;
    case 'c':
      vmcore = strdup(optarg);
      break;
    case 'b':
      mode = M_SCAN_BUCKETS;
      break;
    case 's':
      mode = M_SCAN_SLABS;
      break;
    case 'z':
      mode = M_DTRACE;
      break;
    case 'd':
      debug = strtol(optarg, &s, 0);
      break;
    case 'h':
    case '?':
    default:
      usage();
    }
  }

  // incompatible  argumetns
  if (dumpnr >= 0 && vmcore != NULL) {
    warnx("option -n and -c are mutually exclusive");
    usage();      
  }

  // try to get core from dump number
  if (vmcore == NULL && dumpnr >= 0)
    vmcore = vmcore_from_dumpnr(dumpnr);
  
  // if still no core, use live memory
  if (vmcore == NULL)
    vmcore = _PATH_MEM;

  // try to get kernel image from core
  if (kernel == NULL)
    kernel = kernel_from_vmcore(vmcore);

  // if no kernel image, use the one from boot
  if (kernel == NULL)
    kernel = getbootfile();

  // open argument file
  if (argc > optind) {
    char * path = strdup(argv[optind++]); 
    fd = fopen(path, "r");
    if (fd && verbose)
      warnx("input file: %s", path);
  }

  // if no argument file, use stdin
  if (fd == NULL)
    fd = stdin;

  usc_hdl_t hdl = create_usc_hdl (kernel, vmcore);

  if (verbose) {
    warnx("core file: %s", vmcore);
    warnx("kernel image: %s", kernel);
  }
 
  lst = NULL;
  switch(mode) {
  case (M_SCAN_SLABS):
  case (M_SCAN_BUCKETS):
    lst = from_file(fd);
    break;
  case (M_DTRACE):
    lst = from_dtrace(fd);
    print_plist(lst);
    break;
  case (M_NONE):
  default:
    usage();
  }

  if (lst) {
    ptrscan (hdl, lst);
    destroy_plist(lst);
  }  

  delete_usc_hdl(hdl);

  return (0);
}
