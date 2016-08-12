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
#include <sys/cpuset.h>

#define LIBMEMSTAT
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <vm/uma_int.h>

#include <err.h>
#include <kvm.h>
#include <limits.h>
#include <sysexits.h>
#include <memstat.h>
#include <paths.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "umascan.h"

int debug; // Debug level (usually 0)

enum mode_t {
  M_NONE,
  M_QUERY_KTHR,
  M_QUERY_MHDR,
  M_SCAN
};

struct umascan_args {
  const char *vmcore; // Core dump file name
  const char *kernel; // Kernel image (symbol)
  FILE *fd;           // Extra input file argument (depends on mode)
  mode_t mode;        // Application mode
  kvm_t *kd;          // kvm description
  int verbose;        // Verbose mode
};

static void
usage()
{
  fprintf(stderr,
          "usage: %s [-v] [-n dumpnr | -c core]  (-q string | -s) [-k kernel] [addrs]\n",
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
  kvm_t *kd;
  char *s;;;
  int ch, dumpnr = -1;

  debug = 0;
  
  struct umascan_args args = { 
    .vmcore = NULL,
    .kernel = NULL,
    .verbose = 0,
  };

  while ((ch = getopt(argc, argv, "hvn:c:d:k:q:s")) != -1) {
    switch (ch) {
    case 'v':
      args.verbose = 1;
      break;
    case 'n': 
      dumpnr = strtol(optarg, &s, 0);
      if (dumpnr < 0 || *s == '\0') {
        warnx("option %c: invalid kernel dump number", optopt);
        usage();
      }
      break;
    case 'k':
      args.kernel = strdup(optarg);
      break;
    case 'c':
      args.vmcore = strdup(optarg);
      break;
    case 'q':
      if (strcmp(optarg, "kthr") == 0)
        args.mode = M_QUERY_KTHR;
      else if (strcmp(optarg, "mhdr") == 0)
        args.mode = M_QUERY_MHDR;
      else
        usage();
      break;
    case 's':
      args.mode = M_SCAN;
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
  if (dumpnr >= 0 && args.vmcore != NULL) {
    warnx("option -n and -c are mutually exclusive");
    usage();      
  }

  // try to get core from dump number
  if (args.vmcore == NULL && dumpnr >= 0)
    args.vmcore = vmcore_from_dumpnr(dumpnr);
  
  if (args.vmcore == NULL && args.mode == M_QUERY_MHDR) {
    warnx("specify minidump core with flag -c");
    usage();
  }

  // if still no core, use live memory
  if (args.vmcore == NULL)
    args.vmcore = _PATH_MEM;

  // try to get kernel image from core
  if (args.kernel == NULL)
    args.kernel = kernel_from_vmcore(args.vmcore);

  // if no kernel image, use the one from boot
  if (args.kernel == NULL)
    args.kernel = getbootfile();

  // open argument file
  if (argc > optind) {
    char * path = strdup(argv[optind++]); 
    args.fd = fopen(path, "r");
    if (args.fd && args.verbose)
      warnx("input file: %s", path);
  }

  // if no argument file, use stdin
  if (args.fd == NULL)
    args.fd = stdin;

  kd = kvm_open(args.kernel, args.vmcore, NULL, 0, "kvm");
  if (kd == NULL)
    errx(EX_NOINPUT, "kvm_open: %s", kvm_geterr(kd));

  if (args.verbose) {
    warnx("core file: %s", args.vmcore);
    warnx("kernel image: %s", args.kernel);
  }
 
  switch(args.mode) {
  case M_QUERY_KTHR:
  {
    struct coreinfo cinfo;
    init_coreinfo(kd, &cinfo);
    kread_kthr(kd, &cinfo);
    print_kthr(&cinfo);
    break;
  }
  case M_QUERY_MHDR:
  {
    struct coreinfo cinfo;
    cinfo.kd = kd;
    print_mhdr(&cinfo);
    break;
  }
  case (M_SCAN):
    scan_pointers(kd, args.fd);
    break;
  case (M_NONE):
  default:
    usage();
  }

  return (0);
}
