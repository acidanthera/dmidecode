/*
 * Common "util" functions
 * This file is part of the dmidecode project.
 *
 *   Copyright (C) 2002-2010 Jean Delvare <khali@linux-fr>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 *   For the avoidance of doubt the "preferred form" of this code is one which
 *   is in an open unpatent encumbered format. Where cryptographic key signing
 *   forms part of the process of creating an executable the information
 *   including keys needed to generate an equivalently functional executable
 *   are deemed to be part of the source code.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include "config.h"

#ifdef USE_MMAP
#include <sys/mman.h>
#ifndef MAP_FAILED
#define MAP_FAILED ((void *) -1)
#endif /* !MAP_FAILED */
#endif /* USE MMAP */

#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "types.h"
#include "util.h"

static int myread(int fd, u8 *buf, size_t count, const char *prefix)
{
	ssize_t r = 1;
	size_t r2 = 0;

	while (r2 != count && r != 0)
	{
		r = read(fd, buf + r2, count - r2);
		if (r == -1)
		{
			if (errno != EINTR)
			{
				close(fd);
				perror(prefix);
				return -1;
			}
		}
		else
			r2 += r;
	}

	if (r2 != count)
	{
		close(fd);
		fprintf(stderr, "%s: Unexpected end of file\n", prefix);
		return -1;
	}

	return 0;
}

int checksum(const u8 *buf, size_t len)
{
	u8 sum = 0;
	size_t a;

	for (a = 0; a < len; a++)
		sum += buf[a];
	return (sum == 0);
}

static void *mem_chunk_ioreg(size_t base, size_t len)
{
#ifdef __APPLE__
	CFDataRef data;
	CFStringRef field;
	io_registry_entry_t entry;
	void *blob;
	size_t org_len;

	if (base == 0xF0000)
	{
		field = CFSTR("SMBIOS-EPS");
	}
	else
	{
		field = CFSTR("SMBIOS");
	}

	data = NULL;
	entry = IORegistryEntryFromPath(kIOMasterPortDefault,
		"IOService:/AppleACPIPlatformExpert/bios/AppleSMBIOS");
	if (entry != MACH_PORT_NULL)
	{
		data = IORegistryEntryCreateCFProperty(entry, field, kCFAllocatorDefault, 0);
		if (data != NULL)
		{
			if (CFGetTypeID(data) != CFDataGetTypeID())
			{
				CFRelease(data);
				data = NULL;
			}
		}
		IOObjectRelease(entry);
	}

	if (data != NULL)
	{
		if ((blob = calloc(1, len)) != NULL)
		{
			org_len = (size_t)CFDataGetLength(data);
			if (org_len < len)
				len = org_len;
			memcpy(blob, CFDataGetBytePtr(data), len);
			CFRelease(data);
			return blob;
		} else {
			CFRelease(data);
			perror("malloc");
			return NULL;
		}
	}

#endif

	fprintf(stderr, "Unable to access I/O Registry at %lx for %lu bytes\n",
		(unsigned long)base, (unsigned long)len);
	return NULL;
}

/*
 * Copy a physical memory chunk into a memory buffer.
 * This function allocates memory.
 */
void *mem_chunk(size_t base, size_t len, const char *devmem)
{
	void *p;
	int fd;
#ifdef USE_MMAP
	size_t mmoffset;
	void *mmp;
#endif

	if (strcmp(devmem, "I/O Registry") == 0) {
		return mem_chunk_ioreg(base, len);
	}

	if ((fd = open(devmem, O_RDONLY)) == -1)
	{
		perror(devmem);
		return NULL;
	}

	if ((p = malloc(len)) == NULL)
	{
		perror("malloc");
		return NULL;
	}

#ifdef USE_MMAP
#ifdef _SC_PAGESIZE
	mmoffset = base % sysconf(_SC_PAGESIZE);
#else
	mmoffset = base % getpagesize();
#endif /* _SC_PAGESIZE */
	/*
	 * Please note that we don't use mmap() for performance reasons here,
	 * but to workaround problems many people encountered when trying
	 * to read from /dev/mem using regular read() calls.
	 */
	mmp = mmap(0, mmoffset + len, PROT_READ, MAP_SHARED, fd, base - mmoffset);
	if (mmp == MAP_FAILED)
		goto try_read;

	memcpy(p, (u8 *)mmp + mmoffset, len);

	if (munmap(mmp, mmoffset + len) == -1)
	{
		fprintf(stderr, "%s: ", devmem);
		perror("munmap");
	}

	goto out;

#endif /* USE_MMAP */

try_read:
	if (lseek(fd, base, SEEK_SET) == -1)
	{
		fprintf(stderr, "%s: ", devmem);
		perror("lseek");
		free(p);
		return NULL;
	}

	if (myread(fd, p, len, devmem) == -1)
	{
		free(p);
		return NULL;
	}

out:
	if (close(fd) == -1)
		perror(devmem);

	return p;
}

int write_dump(size_t base, size_t len, const void *data, const char *dumpfile, int add)
{
	FILE *f;

	f = fopen(dumpfile, add ? "r+b" : "wb");
	if (!f)
	{
		fprintf(stderr, "%s: ", dumpfile);
		perror("fopen");
		return -1;
	}

	if (fseek(f, base, SEEK_SET) != 0)
	{
		fprintf(stderr, "%s: ", dumpfile);
		perror("fseek");
		goto err_close;
	}

	if (fwrite(data, len, 1, f) != 1)
	{
		fprintf(stderr, "%s: ", dumpfile);
		perror("fwrite");
		goto err_close;
	}

	if (fclose(f))
	{
		fprintf(stderr, "%s: ", dumpfile);
		perror("fclose");
		return -1;
	}

	return 0;

err_close:
	fclose(f);
	return -1;
}

/* Returns end - start + 1, assuming start < end */
u64 u64_range(u64 start, u64 end)
{
	u64 res;

	res.h = end.h - start.h;
	res.l = end.l - start.l;

	if (end.l < start.l)
		res.h--;
	if (++res.l == 0)
		res.h++;

	return res;
}
