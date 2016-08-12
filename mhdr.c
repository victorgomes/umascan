#include <sys/param.h>
#include <machine/minidump.h>

#include "umascan.h"
#include "kvm_private.h"

// FreeBSD 10
struct vmstate {
  int minidump;
  struct minidumphdr hdr;
  // Other stuff here
};

void
print_mhdr(struct coreinfo *cinfo) {
  struct minidumphdr hdr = cinfo->kd->vmst->hdr;
  printf("Minidump headear:\n"
    "\tmagic: %s\n"
    "\tversion: %d\n"
    "\tmsgbufsize: %d\n"
    "\tbitmapsize: %d\n"
    "\tpmapsize: %d\n"
    "\tkernbase: 0x%lx\n"
    "\tdmapend: 0x%lx\n"
    "\tdmapbase: 0x%lx\n",
    hdr.magic, hdr.version, hdr.msgbufsize, hdr.bitmapsize, hdr.pmapsize,
    hdr.kernbase, hdr.dmapend, hdr.dmapbase);
}


