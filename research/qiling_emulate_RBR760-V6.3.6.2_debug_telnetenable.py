#!/usr/bin/env python3
# Netgear telnetenable emulator via Qiling
# (c) B.Kerler 2021, licenced under MIT

import sys, os, random

sys.path.append("..")
from qiling import *
from unicorn import *
from unicorn.arm_const import *
import logging
from struct import pack, unpack
import time
from binascii import hexlify

password=b"test"

# ?? cf mem map in crashes
OFF=0x0056555000-0x10000

def replace_function(ql, addr, callback):
    def runcode(ql):
        ret = callback(ql)
        ql.arch.regs.r0 = ret
        ql.arch.regs.pc = ql.arch.regs.lr

    ql.hook_address(runcode, addr)


def hook_mem_read(uc, access, address, size, value, user_data):
    if address > OFF+0xF000000:
        pc = uc.reg_read(UC_ARM_REG_PC)
        print("READ of 0x%x (0x%x) at 0x%X (0x%x), data size = %u" % (address, address-OFF, pc, pc-OFF, size))


def hook_code(uc, access, address, size):
    pc = uc.reg_read(UC_ARM_REG_PC)
#    if OFF+0x10684< pc < OFF+0x12000:
#        print("PC at 0x%x (0x%x)" % (pc, pc-OFF))
    if pc==OFF+0x11378:
         uc.reg_write(UC_ARM_REG_PC, pc+4)
    if pc==OFF+0x1182c: # skip prep_exec
        uc.reg_write(UC_ARM_REG_R0,1)
        uc.reg_write(UC_ARM_REG_PC, pc+4)
    if pc==OFF+0x11a44:
         uc.reg_write(UC_ARM_REG_PC, pc+4)
    if pc==OFF+0x11aa4:
         uc.reg_write(UC_ARM_REG_PC, pc+8)

def hook_mem_invalid(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)
    if access == UC_MEM_WRITE:
        info = ("invalid WRITE of 0x%x at 0x%X, data size = %u, data value = 0x%x" % (address, pc, size, value))
    if access == UC_MEM_READ:
        info = ("invalid READ of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_FETCH:
        info = ("UC_MEM_FETCH of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_READ_UNMAPPED:
        info = ("UC_MEM_READ_UNMAPPED of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_WRITE_UNMAPPED:
        info = ("UC_MEM_WRITE_UNMAPPED of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_FETCH_UNMAPPED:
        info = ("UC_MEM_FETCH_UNMAPPED of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_WRITE_PROT:
        info = ("UC_MEM_WRITE_PROT of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_FETCH_PROT:
        info = ("UC_MEM_FETCH_PROT of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_FETCH_PROT:
        info = ("UC_MEM_FETCH_PROT of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_READ_AFTER:
        info = ("UC_MEM_READ_AFTER of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    print(info)
    return False


def main():
    filename = "debug_telnetenable_sh_RBR760-V6.3.6.2"
    data = open(filename, "rb").read()

    ql = Qiling([filename], rootfs=".")
    ql.gdb = "0.0.0.0:9999"
    ql.arch.enable_vfp()

    def aeabi_idivmod(ql):
        num = ql.arch.regs.R0
        denom = ql.arch.regs.R1
        ql.arch.regs.R0 = num // denom
        ql.arch.regs.R1 = num % denom
        return ql.arch.regs.R0

    def memcmp(ql):
        s0 = ql.arch.regs.R0
        s1 = ql.arch.regs.R1
        n = ql.arch.regs.R2
        ss0 = ql.mem.read(s0, n)
        print("memcmp s0:", ss0)
        ss1 = ql.mem.read(s1, n)
        print("memcmp s1:", ss1)
#        print("DEBUG:", ql.mem.read(s0-0x1000, 0x2000))
        if ss0 < ss1:
            ql.arch.regs.R0 = -1
        elif ss0 > ss1:
            ql.arch.regs.R0 = 1
        else:
            ql.arch.regs.R0 = 0
        return ql.arch.regs.R0

    def getpid(ql):
        return 1

    def sprintf(ql):
        dst=ql.arch.regs.R0
        fmt = bytearray()
        tmp = -1
        pos = 0
        while tmp != 0:
            v = ql.mem.read(ql.arch.regs.R1 + pos,1)[0]
            if v == 0:
                break
            pos += 1
            fmt.append(v)
        if fmt.decode('utf-8') == 'x%lx':
            value=ql.arch.regs.R2

            data=fmt.decode('utf-8') % value
        elif fmt.decode('utf-8') == 'exec \'%s\' "$@"':
            print("@ 0x%x" % ql.arch.regs.R2)
            value=bytearray()
            tmp = -1
            pos = 0
            while tmp != 0:
                v = ql.mem.read(ql.arch.regs.R2 + pos,1)[0]
                if v == 0:
                    break
                pos += 1
                value.append(v)

            data=fmt.decode('utf-8') % value.decode('utf-8')
        else:
            print("SPRINTF ERROR:", fmt)
            data = ""
        print("sprintf:",data)
        ql.mem.write(dst, bytes(data,'utf-8'))
        return len(data)

    def getenv(ql):
        name = bytearray()
        tmp = -1
        pos = 0
        while tmp != 0:
            v = ql.mem.read(ql.arch.regs.R0 + pos,1)[0]
            if v == 0:
                break
            pos += 1
            name.append(v)
        print("getenv: ", name.decode('utf-8'))
        return 0

    def calloc(ql):
        s1 = ql.arch.regs.R0
        s2 = ql.arch.regs.R1
        count = s1+s2
        dst = 0xc000000 + (random.randint(0,0x100000) & 0xfffffff0)
        ql.mem.write(dst, b'\x00'*count)
        ql.arch.regs.R0 = dst
        return ql.arch.regs.R0

    def malloc(ql):
        size = ql.arch.regs.R0
        dst = 0xc000000 + (random.randint(0,0x100000) & 0xfffffff0)
        ql.arch.regs.R0 = dst
        return ql.arch.regs.R0

    def memset(ql):
        dst = ql.arch.regs.R0
        val = ql.arch.regs.R1
        count = ql.arch.regs.R2
        data = bytearray()
        for i in range(count):
            data.append(val)
        ql.mem.write(dst, bytes(data))
        return 0

    def memcpy(ql):
        dst = ql.arch.regs.R0
        src = ql.arch.regs.R1
        count = ql.arch.regs.R2
        data = ql.mem.read(src, count)
        print("memcpy:", data)
        with open('debug_telnetenable_sh_RBR760-V6.3.6.2.sh', 'wb') as f:
            f.write(data)
        ql.mem.write(dst, bytes(data))
        return 0

    def execvp(ql):
        data = bytearray()
        tmp = -1
        pos = 0
        while tmp != 0:
            v = ql.mem.read(ql.arch.regs.R0 + pos,1)[0]
            if v == 0:
                break
            pos += 1
            data.append(v)
        print("execvp:", bytes(data))
        argv = ql.arch.regs.R1
        arg = ql.mem.read(argv, 4)
        print(arg)
        return 0

    ql.uc.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
    ql.uc.hook_add(UC_HOOK_MEM_READ, hook_mem_read)
    ql.uc.hook_add(UC_HOOK_CODE, hook_code)
    replace_function(ql, OFF+0x10aa4, aeabi_idivmod)
    replace_function(ql, OFF+0x10aec, memcmp)
    replace_function(ql, OFF+0x10a5c, getpid)
    replace_function(ql, OFF+0x10b4c, sprintf)
    replace_function(ql, OFF+0x10a50, getenv)
    replace_function(ql, OFF+0x10abc, calloc)
    replace_function(ql, OFF+0x10a8c, malloc)
    replace_function(ql, OFF+0x10b1c, memset)
    replace_function(ql, OFF+0x10a68, memcpy)
    replace_function(ql, OFF+0x10bac, execvp)

# xref of main -> hover __libc_start_main -> thunk
    ql.arch.regs.sp = 0x10b78 + 0x12000  # SP from main

    ql.mem.map(0x20000, 0x4000)
    ql.mem.map(0xc000000, 0x100000)
    ql.run(begin=OFF+0x11684, end=OFF+0x11c3c)


if __name__ == "__main__":
    main()
