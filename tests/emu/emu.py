#!/usr/bin/env python3
# Unicorn harness: runs bootloader.bin and models UART0, SysCtl, GPIO, and the
# FMA/FMC/FMD flash controller so the update+boot path executes against a flash array.

import struct, sys, os
from unicorn import *
from unicorn.arm_const import *

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BIN = REPO + "/bootloader/bin/bootloader.bin"

FLASH_BASE, FLASH_SIZE = 0x00000000, 0x00040000   # 256 KB
SRAM_BASE,  SRAM_SIZE  = 0x20000000, 0x00008000   # 32 KB
PERIPH_BASE, PERIPH_SIZE = 0x40000000, 0x00060000 # UART0 + GPIO apertures
FLASHCTL_BASE, FLASHCTL_SIZE = 0x400FD000, 0x00001000
SYSCTL_BASE, SYSCTL_SIZE = 0x400FE000, 0x00001000
PPB_BASE, PPB_SIZE = 0xE0000000, 0x00100000

UART0 = 0x4000C000
UART_DR, UART_FR, UART_FBRD, UART_LCRH, UART_CTL = 0x00, 0x18, 0x28, 0x2C, 0x30
FR_RXFE = 1 << 4
FR_TXFF = 1 << 5
FR_BUSY = 1 << 3

FMA, FMD, FMC = 0x400FD000, 0x400FD004, 0x400FD008
FMC_WRKEY = 0xA4420000
FMC_ERASE, FMC_WRITE, FMC_COMT = 0x02, 0x01, 0x08

flash = bytearray(b"\xff" * FLASH_SIZE)

class Bench:
    def __init__(self, uart_in=b""):
        self.uart_in = bytearray(uart_in)
        self.uart_out = bytearray()
        self.fma = 0
        self.fmd = 0
        self.steps = 0
        self.did_reset = False

    def uart_read_hook(self, offset):
        if offset == UART_FR:
            fr = 0
            if not self.uart_in:
                fr |= FR_RXFE
            return fr
        if offset == UART_DR:
            if self.uart_in:
                return self.uart_in.pop(0)
            return 0
        return 0

    def uart_write_hook(self, offset, value):
        if offset == UART_DR:
            self.uart_out.append(value & 0xFF)

def run(uart_in=b"", max_count=600_000_000, preload_flash=None):
    global flash
    flash = bytearray(b"\xff" * FLASH_SIZE)
    code = open(BIN, "rb").read()
    flash[:len(code)] = code
    if preload_flash:
        for addr, data in preload_flash:
            flash[addr:addr+len(data)] = data

    bench = Bench(uart_in)

    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)

    uc.mem_map(FLASH_BASE, FLASH_SIZE)
    uc.mem_map(SRAM_BASE, SRAM_SIZE)
    uc.mem_map(PERIPH_BASE, PERIPH_SIZE)
    uc.mem_map(FLASHCTL_BASE, FLASHCTL_SIZE)
    uc.mem_map(SYSCTL_BASE, SYSCTL_SIZE)
    uc.mem_map(PPB_BASE, PPB_SIZE)
    uc.mem_map(0x42000000, 0x02000000)  # bit-band alias

    uc.mem_write(FLASH_BASE, bytes(flash))

    # all peripherals present+ready
    for off in range(0, 0x1000, 4):
        uc.mem_write(SYSCTL_BASE + off, b"\xff\xff\xff\xff")

    unmapped = []

    def hook_mem_read(uc, access, address, size, value, user):
        if UART0 <= address < UART0 + 0x1000:
            v = bench.uart_read_hook(address - UART0)
            uc.mem_write(address, struct.pack("<I", v)[:size])
        return True

    def hook_mem_write(uc, access, address, size, value, user):
        if UART0 <= address < UART0 + 0x1000:
            bench.uart_write_hook(address - UART0, value)
            if bench.uart_out.endswith(b"Loaded new firmware.\n"): # stop at completion banner
                uc.emu_stop()
            return True
        return True

    uc.hook_add(UC_HOOK_MEM_READ, hook_mem_read, begin=PERIPH_BASE, end=PERIPH_BASE+PERIPH_SIZE)
    uc.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write, begin=PERIPH_BASE, end=PERIPH_BASE+PERIPH_SIZE)
    uc.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write, begin=FLASHCTL_BASE, end=FLASHCTL_BASE+FLASHCTL_SIZE)

    # enable FPU (CPACR CP10/11)
    CPACR = 0xE000ED88
    uc.mem_write(CPACR, struct.pack("<I", 0xF << 20))
    try:
        uc.reg_write(UC_ARM_REG_C1_C0_2, 0xF << 20)
    except Exception:
        pass

    sp = struct.unpack("<I", bytes(uc.mem_read(0x0, 4)))[0]
    reset = struct.unpack("<I", bytes(uc.mem_read(0x4, 4)))[0]
    uc.reg_write(UC_ARM_REG_SP, sp)

    err = None
    try:
        uc.emu_start(reset | 1, 0, count=max_count)
    except UcError as e:
        err = (str(e), uc.reg_read(UC_ARM_REG_PC))
    return {
        "uart_out": bytes(bench.uart_out),
        "flash": bytes(flash),
        "err": err,
        "unmapped": [(a, hex(x)) for a, x in unmapped[:8]],
        "sp": sp, "reset": reset,
    }
