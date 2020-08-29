#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)


import unittest
import os
import sys
sys.path.append("..")

from qiling import *
from qiling.os.posix.syscall.unistd import ql_syscall_pread64

# syscalls that need to be implemented for android
def syscall_getrandom(ql, buf, buflen, flags, null0, null1, null2):
    data = None
    regreturn = None
    try:
        data = os.urandom(buflen)
        ql.uc.mem_write(buf, data)
        regreturn = len(data)
    except:
        regreturn = -1

    ql.nprint("getrandom(0x%x, 0x%x, 0x%x) = %d" %
              (buf, buflen, flags, regreturn))

    if data:
        ql.dprint(0, "[+] getrandom() CONTENT:")
        ql.dprint(0, str(data))
    ql.os.definesyscall_return(regreturn)


"""
Android linker calls fstatfs to determine if the file is on tmpfs as part of checking if libraries are allowed
https://cs.android.com/android/platform/superproject/+/master:bionic/linker/linker.cpp;l=1215
"""
def syscall_fstatfs(ql, fd, buf, null0, null1, null2, null3):
    data = b"0" * (12*8)  # for now, just return 0s
    regreturn = None
    try:
        ql.uc.mem_write(buf, data)
        regreturn = 0
    except:
        regreturn = -1

    ql.nprint("fstatfs(0x%x, 0x%x) = %d" % (fd, buf, regreturn))

    if data:
        ql.dprint(0, "[+] fstatfs() CONTENT:")
        ql.dprint(0, str(data))
    ql.os.definesyscall_return(regreturn)

# as above, but called from 32-bit instead of 64
def syscall_fstatfs64(ql, fd, size, buf, null0, null1, null2):
    data = b"0" * size # for now, just return 0s
    regreturn = None
    try:
        ql.uc.mem_write(buf, data)
        regreturn = 0
    except:
        regreturn = -1

    ql.nprint("fstatfs64(0x%x, 0x%x, 0x%x) = %d" % (fd, size, buf, regreturn))

    if data:
        ql.dprint(0,"[+] fstatfs64() CONTENT:")
        ql.dprint(0,str(data))
    ql.os.definesyscall_return(regreturn)


def syscall_personality(ql, personality, null0, null1, null2, null3, null4 ):
    regreturn = 0 # for now, just return 0 for the personality

    ql.nprint("personality(%d) = %d" % (personality, regreturn))

    ql.os.definesyscall_return(regreturn)

""" ARMEABI syscalls use two registers to pass 64bit values - but they must start on an even register.
    If there's an odd register first, it's ignored. pread64 is affected by this - r3 is a dummy,
    r4 and r5 are where the 64-bit offset is actually passed """
def syscall_pread64_armeabi(ql, read_fd, read_buf, read_len, dummy, offset_lo, offset_hi, *args, **kw):
    read_offt = offset_lo + (offset_hi << 32)
    ql_syscall_pread64(ql, read_fd, read_buf, read_len, read_offt)


class TestAndroid(unittest.TestCase):
    """def test_android_arm64(self):
        test_binary = "../examples/rootfs/arm64_android/bin/arm64_android_hello"
        rootfs = "../examples/rootfs/arm64_android"

        # FUTURE FIX: at this stage, need a file called /proc/self/exe in the rootfs - Android linker calls stat against /proc/self/exe and bails if it can't find it
        # qiling handles readlink against /proc/self/exe, but doesn't handle it in stat
        # https://cs.android.com/android/platform/superproject/+/master:bionic/linker/linker_main.cpp;l=221
        self.assertTrue(os.path.isfile(os.path.join(rootfs, "proc", "self", "exe")), rootfs +
                        "/proc/self/exe not found, Android linker will bail. Need a file at that location (empty is fine)")

        ql = Qiling([test_binary], rootfs, output="debug")
        #ql.hook_block(block_cb)

        # slide in the syscalls we need for android on arm64
        # FUTURE FIX: implement fstatfs
        ql.set_syscall(0x2C, syscall_fstatfs)
        # FUTURE FIX: pread64 implemented in qiling, just not hooked up for arm64
        ql.set_syscall(0x43, ql_syscall_pread64)
        # FUTURE FIX: implement getrandom
        ql.set_syscall(0x116, syscall_getrandom)

        ql.run()
    
    def test_android_arm(self):
        test_binary = "../examples/rootfs/arm_android/bin/arm_android_hello"  
        rootfs = "../examples/rootfs/arm_android"

        ql = Qiling([test_binary], rootfs, output="debug")
        ql.multithread = True # avoid exception on exit

        # slide in the syscalls we need for android on arm 32
        # https://cs.android.com/android/platform/superproject/+/master:bionic/libc/bionic/libc_init_common.cpp;drc=97271920bf831610819ddfa44e4e2cc0815afd6e;l=290
        ql.set_syscall(0x88, syscall_personality)
        ql.set_syscall(0xB4, syscall_pread64_armeabi)
        ql.set_syscall(0x10B, syscall_fstatfs64) 
        ql.set_syscall(0x180, syscall_getrandom)

        # stat - https://cs.android.com/android/platform/superproject/+/master:bionic/libc/include/sys/stat.h;l=81;bpv=1;bpt=1
        ql.run()"""

    def test_arm(self):
        ql = Qiling(["../examples/rootfs/arm_linux/bin/arm_posix_syscall"], "../examples/rootfs/arm_linux", output="debug")
        ql.set_syscall(0xB4, syscall_pread64_armeabi) #ql_syscall_pread64)
        ql.run()

    """def test_arm64(self):
        ql = Qiling(["../examples/rootfs/arm64_linux/bin/arm64_posix_syscall"], "../examples/rootfs/arm64_linux", output="debug")
        ql.run()"""


if __name__ == "__main__":
    unittest.main()
