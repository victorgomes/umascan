#umascan
Intrumentation tool for FreeBSD's Unified Memory Allocation (UMA).

## Usage

```bash
umascan [-v] [-n dumpnr | -c core] [-k kernel] (-s addr | -z probs)
```

## Description

The umascan utility is a instrumentation tool based on kvm, which scans a list
of pointers (from a file or from a list of dtrace probes) in the UMA's allocated
memory. It can be used with the live kernel or with a core file.  It displays
the zone name where the pointer is located, the total count of references (by
zone name), and the value of its reference count field if the structure has this
field.

The options are as follows:

`-c core`
: Explicitly select the core dump file to be used.

`-n dumpnr`
: Use the kernel core dump file numbered `dumpnr`.

`-k kernel`
: Select the kernel symbol file to be used. If no kernel symbol file is given, the symbol file of the currently running kernel will be used.

`-s addr`
: Scan pointers in file file `addrs`.

`-z probs`
: Run dtrace with the probes selected and scan the pointers retrieved by dtrace.

`-v`
: Increase verbosity.

The `-c` and `-n` (`-s` and `-z`) options are mutually exclusive.  If no core dump file
is specified through any options, `/dev/mem` will be opened to allow scanning the
currently running kernel.

## Example

```bash
# ./umascan -c /var/crash/vmcore.0 -s ucred.list

umascan: input file: ucred.list
umascan: core file: /var/crash/vmcore.0
umascan: kernel image: /usr/obj/usr/src/sys/GENERIC/kernel.debug
0xfffff80002db4a00:
	zone name: 256
	ref count: 45
	total count: 15
		Files: 12
		PROC: 3
```
