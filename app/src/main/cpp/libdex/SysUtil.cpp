/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * System utilities.
 */
#include "DexFile.h"
#include "SysUtil.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#if !defined(__MINGW32__)
# include <sys/mman.h>
#endif
#include <limits.h>
#include <errno.h>
#include <android/log.h>
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "LOG_TAG", __VA_ARGS__)

/*
 * TEMP_FAILURE_RETRY is defined by some, but not all, versions of
 * <unistd.h>. (Alas, it is not as standard as we'd hoped!) So, if it's
 * not already defined, then define it here.
 */
#ifndef TEMP_FAILURE_RETRY
/* Used to retry syscalls that can return EINTR. */
#define TEMP_FAILURE_RETRY(exp) ({         \
    typeof (exp) _rc;                      \
    do {                                   \
        _rc = (exp);                       \
    } while (_rc == -1 && errno == EINTR); \
    _rc; })
#endif

/*
 * Create an anonymous shared memory segment large enough to hold "length"
 * bytes.  The actual segment may be larger because mmap() operates on
 * page boundaries (usually 4K).
 */
static void* sysCreateAnonShmem(size_t length)
{
#if !defined(__MINGW32__)
    void* ptr;

    ptr = mmap(NULL, length, PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANON, -1, 0);
    if (ptr == MAP_FAILED) {
        LOGD("mmap(%d, RW, SHARED|ANON) failed: %s", (int) length,
            strerror(errno));
        return NULL;
    }

    return ptr;
#else
    ALOGE("sysCreateAnonShmem not implemented.");
    return NULL;
#endif
}

/*
 * Create a private anonymous storage area.
 */
int sysCreatePrivateMap(size_t length, MemMapping* pMap)
{
    void* memPtr;

    memPtr = sysCreateAnonShmem(length);
    if (memPtr == NULL)
        return -1;

    pMap->addr = pMap->baseAddr = memPtr;
    pMap->length = pMap->baseLength = length;
    return 0;
}

/*
 * Determine the current offset and remaining length of the open file.
 */
static int getFileStartAndLength(int fd, off_t *start_, size_t *length_)
{
    off_t start, end;
    size_t length;

    assert(start_ != NULL);
    assert(length_ != NULL);

    start = lseek(fd, 0L, SEEK_CUR);
    end = lseek(fd, 0L, SEEK_END);
    (void) lseek(fd, start, SEEK_SET);

    if (start == (off_t) -1 || end == (off_t) -1) {
        LOGD("could not determine length of file");
        return -1;
    }

    length = end - start;
    if (length == 0) {
        LOGD("file is empty");
        return -1;
    }

    *start_ = start;
    *length_ = length;

    return 0;
}

#if defined(__MINGW32__)
int sysFakeMapFile(int fd, MemMapping* pMap)
{
    /* No MMAP, just fake it by copying the bits.
       For Win32 we could use MapViewOfFile if really necessary
       (see libs/utils/FileMap.cpp).
    */
    off_t start;
    size_t length;
    void* memPtr;

    assert(pMap != NULL);

    if (getFileStartAndLength(fd, &start, &length) < 0)
        return -1;

    memPtr = malloc(length);
    if (read(fd, memPtr, length) < 0) {
        ALOGW("read(fd=%d, start=%d, length=%d) failed: %s", (int) length,
            fd, (int) start, strerror(errno));
        free(memPtr);
        return -1;
    }

    pMap->baseAddr = pMap->addr = memPtr;
    pMap->baseLength = pMap->length = length;

    return 0;
}
#endif

/*
 * Map a file (from fd's current offset) into a private, read-write memory
 * segment that will be marked read-only (a/k/a "writable read-only").  The
 * file offset must be a multiple of the system page size.
 *
 * In some cases the mapping will be fully writable (e.g. for files on
 * FAT filesystems).
 *
 * On success, returns 0 and fills out "pMap".  On failure, returns a nonzero
 * value and does not disturb "pMap".
 */
int sysMapFileInShmemWritableReadOnly(int fd, MemMapping* pMap)
{
#if !defined(__MINGW32__)
    off_t start;
    size_t length;
    void* memPtr;

    assert(pMap != NULL);

    if (getFileStartAndLength(fd, &start, &length) < 0)
        return -1;

    memPtr = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_FILE | MAP_PRIVATE,
            fd, start);
    if (memPtr == MAP_FAILED) {
        LOGD("mmap(%d, R/W, FILE|PRIVATE, %d, %d) failed: %s", (int) length,
            fd, (int) start, strerror(errno));
        return -1;
    }
    if (mprotect(memPtr, length, PROT_READ) < 0) {
        /* this fails with EACCESS on FAT filesystems, e.g. /sdcard */
        int err = errno;
        LOGD("mprotect(%p, %zd, PROT_READ) failed: %s",
            memPtr, length, strerror(err));
        LOGD("mprotect(RO) failed (%d), file will remain read-write", err);
    }

    pMap->baseAddr = pMap->addr = memPtr;
    pMap->baseLength = pMap->length = length;

    return 0;
#else
    return sysFakeMapFile(fd, pMap);
#endif
}

/*
 * Map part of a file into a shared, read-only memory segment.  The "start"
 * offset is absolute, not relative.
 *
 * On success, returns 0 and fills out "pMap".  On failure, returns a nonzero
 * value and does not disturb "pMap".
 */
int sysMapFileSegmentInShmem(int fd, off_t start, size_t length,
    MemMapping* pMap)
{
#if !defined(__MINGW32__)
    size_t actualLength;
    off_t actualStart;
    int adjust;
    void* memPtr;

    assert(pMap != NULL);

    /* adjust to be page-aligned */
    adjust = start % SYSTEM_PAGE_SIZE;
    actualStart = start - adjust;
    actualLength = length + adjust;

    memPtr = mmap(NULL, actualLength, PROT_READ, MAP_FILE | MAP_SHARED,
                fd, actualStart);
    if (memPtr == MAP_FAILED) {
        LOGD("mmap(%d, R, FILE|SHARED, %d, %d) failed: %s",
            (int) actualLength, fd, (int) actualStart, strerror(errno));
        return -1;
    }

    pMap->baseAddr = memPtr;
    pMap->baseLength = actualLength;
    pMap->addr = (char*)memPtr + adjust;
    pMap->length = length;

    LOGVV("mmap seg (st=%d ln=%d): bp=%p bl=%d ad=%p ln=%d",
        (int) start, (int) length,
        pMap->baseAddr, (int) pMap->baseLength,
        pMap->addr, (int) pMap->length);

    return 0;
#else
    ALOGE("sysMapFileSegmentInShmem not implemented.");
    return -1;
#endif
}

/*
 * Change the access rights on one or more pages to read-only or read-write.
 *
 * Returns 0 on success.
 */
int sysChangeMapAccess(void* addr, size_t length, int wantReadWrite,
    MemMapping* pMap)
{
#if !defined(__MINGW32__)
    /*
     * Verify that "addr" is part of this mapping file.
     */
    if (addr < pMap->baseAddr ||
        (u1*)addr >= (u1*)pMap->baseAddr + pMap->baseLength)
    {
        LOGD("Attempted to change %p; map is %p - %p",
            addr, pMap->baseAddr, (u1*)pMap->baseAddr + pMap->baseLength);
        return -1;
    }

    /*
     * Align "addr" to a page boundary and adjust "length" appropriately.
     * (The address must be page-aligned, the length doesn't need to be,
     * but we do need to ensure we cover the same range.)
     */
    u1* alignAddr = (u1*) ((uintptr_t) addr & ~(SYSTEM_PAGE_SIZE-1));
    size_t alignLength = length + ((u1*) addr - alignAddr);

    //ALOGI("%p/%zd --> %p/%zd", addr, length, alignAddr, alignLength);
    int prot = wantReadWrite ? (PROT_READ|PROT_WRITE) : (PROT_READ);
    if (mprotect(alignAddr, alignLength, prot) != 0) {
        LOGD("mprotect (%p,%zd,%d) failed: %s",
            alignAddr, alignLength, prot, strerror(errno));
        return (errno != 0) ? errno : -1;
    }
#endif

    /* for "fake" mapping, no need to do anything */
    return 0;
}

/*
 * Release a memory mapping.
 */
void sysReleaseShmem(MemMapping* pMap)
{
#if !defined(__MINGW32__)
    if (pMap->baseAddr == NULL && pMap->baseLength == 0)
        return;

    if (munmap(pMap->baseAddr, pMap->baseLength) < 0) {
        LOGD("munmap(%p, %zd) failed: %s",
            pMap->baseAddr, pMap->baseLength, strerror(errno));
    } else {
        LOGD("munmap(%p, %zd) succeeded", pMap->baseAddr, pMap->baseLength);
        pMap->baseAddr = NULL;
        pMap->baseLength = 0;
    }
#else
    /* Free the bits allocated by sysMapFileInShmem. */
    if (pMap->baseAddr != NULL) {
      free(pMap->baseAddr);
      pMap->baseAddr = NULL;
    }
    pMap->baseLength = 0;
#endif
}

/*
 * Make a copy of a MemMapping.
 */
void sysCopyMap(MemMapping* dst, const MemMapping* src)
{
    memcpy(dst, src, sizeof(MemMapping));
}

/*
 * Write until all bytes have been written.
 *
 * Returns 0 on success, or an errno value on failure.
 */
int sysWriteFully(int fd, const void* buf, size_t count, const char* logMsg)
{
    while (count != 0) {
        ssize_t actual = TEMP_FAILURE_RETRY(write(fd, buf, count));
        if (actual < 0) {
            int err = errno;
            LOGD("%s: write failed: %s", logMsg, strerror(err));
            return err;
        } else if (actual != (ssize_t) count) {
            LOGD("%s: partial write (will retry): (%d of %zd)",
                logMsg, (int) actual, count);
            buf = (const void*) (((const u1*) buf) + actual);
        }
        count -= actual;
    }

    return 0;
}

/* See documentation comment in header file. */
int sysCopyFileToFile(int outFd, int inFd, size_t count)
{
    const size_t kBufSize = 32768;
    unsigned char buf[kBufSize];

    while (count != 0) {
        size_t getSize = (count > kBufSize) ? kBufSize : count;

        ssize_t actual = TEMP_FAILURE_RETRY(read(inFd, buf, getSize));
        if (actual != (ssize_t) getSize) {
            LOGD("sysCopyFileToFile: copy read failed (%d vs %zd)",
                (int) actual, getSize);
            return -1;
        }

        if (sysWriteFully(outFd, buf, getSize, "sysCopyFileToFile") != 0)
            return -1;

        count -= getSize;
    }

    return 0;
}
