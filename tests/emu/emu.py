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
        self.min_sp = 0xffffffff
        self.flash_error = None
        self.ops = []

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

def run(uart_in=b"", max_count=600_000_000, preload_flash=None, code_hooks=None,
        stop_on_flash=None):
    global flash
    flash = bytearray(b"\xff" * FLASH_SIZE)
    with open(BIN, "rb") as f:
        code = f.read()
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

    # flash write-buffer model (driverlib FlashProgram)
    FMC2, FWBVAL, FWBN = 0x400FD020, 0x400FD030, 0x400FD100
    FMC2_WRBUF = 0x01
    bench.wbuf = [0] * 32
    bench.fwbval = 0

    def flash_ok(address, size, operation):
        if address < FLASH_BASE or address + size > FLASH_BASE + FLASH_SIZE:
            bench.flash_error = (operation, address, size)
            uc.emu_stop()
            return False
        return True

    # stop_on_flash: ("erase", page) or an int = cut after that many flash operations
    def note_op(kind, addr):
        bench.ops.append((kind, addr))
        if stop_on_flash == (kind, addr):
            uc.emu_stop()
        elif isinstance(stop_on_flash, int) and len(bench.ops) >= stop_on_flash:
            uc.emu_stop()

    def hook_mem_write(uc, access, address, size, value, user):
        if UART0 <= address < UART0 + 0x1000:
            bench.uart_write_hook(address - UART0, value)
            if bench.uart_out.endswith(b"Loaded new firmware.\n"): # stop at completion banner
                uc.emu_stop()
            return True
        if address == FMA:
            bench.fma = value
        elif address == FMD:
            bench.fmd = value
        elif FWBN <= address < FWBN + 128:
            i = (address - FWBN) >> 2
            bench.wbuf[i] = value
            bench.fwbval |= (1 << i)
        elif address == FWBVAL:
            bench.fwbval = value
        elif address == FMC:
            if (value & 0xFFFF0000) == FMC_WRKEY:
                if value & FMC_ERASE:
                    page = bench.fma & ~0x3FF
                    if not flash_ok(page, 1024, "erase"):
                        return True
                    flash[page:page + 1024] = b"\xff" * 1024
                    uc.mem_write(FLASH_BASE + page, bytes(flash[page:page + 1024]))
                    note_op("erase", page)
                elif value & FMC_WRITE:
                    a = bench.fma
                    if not flash_ok(a, 4, "write"):
                        return True
                    old = struct.unpack("<I", flash[a:a+4])[0]
                    if bench.fmd & ~old:
                        bench.flash_error = ("0 to 1", a, 4)
                        uc.emu_stop()
                        return True
                    flash[a:a+4] = struct.pack("<I", old & bench.fmd)
                    uc.mem_write(FLASH_BASE + a, bytes(flash[a:a+4]))
                    note_op("write", a)
        elif address == FMC2:
            if (value & 0xFFFF0000) == FMC_WRKEY and (value & FMC2_WRBUF):
                base = bench.fma & ~0x7F
                if not flash_ok(base, 128, "write buffer"):
                    return True
                for i in range(32):
                    if bench.fwbval & (1 << i):
                        a = base + i * 4
                        old = struct.unpack("<I", flash[a:a+4])[0]
                        if bench.wbuf[i] & ~old:
                            bench.flash_error = ("0 to 1", a, 4)
                            uc.emu_stop()
                            return True
                for i in range(32):
                    if bench.fwbval & (1 << i):
                        a = base + i * 4
                        old = struct.unpack("<I", flash[a:a+4])[0]
                        flash[a:a+4] = struct.pack("<I", old & bench.wbuf[i])
                uc.mem_write(FLASH_BASE + base, bytes(flash[base:base+128]))
                bench.fwbval = 0
                note_op("wrbuf", base)
        return True

    def hook_unmapped(uc, access, address, size, value, user):
        unmapped.append((access, address))
        return False

    def hook_flashctl_read(uc, access, address, size, value, user):
        if address == FMC or address == FMC2: # busy bits read 0 = done
            uc.mem_write(address, b"\x00\x00\x00\x00")
        elif address == FWBVAL:
            uc.mem_write(FWBVAL, struct.pack("<I", bench.fwbval))
        return True

    uc.hook_add(UC_HOOK_MEM_READ, hook_mem_read, begin=PERIPH_BASE, end=PERIPH_BASE+PERIPH_SIZE)
    uc.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write, begin=PERIPH_BASE, end=PERIPH_BASE+PERIPH_SIZE)
    uc.hook_add(UC_HOOK_MEM_READ, hook_flashctl_read, begin=FLASHCTL_BASE, end=FLASHCTL_BASE+FLASHCTL_SIZE)
    uc.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write, begin=FLASHCTL_BASE, end=FLASHCTL_BASE+FLASHCTL_SIZE)
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_unmapped)

    def hook_sram_write(uc, access, address, size, value, user):
        bench.min_sp = min(bench.min_sp, uc.reg_read(UC_ARM_REG_SP))
        return True
    uc.hook_add(UC_HOOK_MEM_WRITE, hook_sram_write,
                begin=SRAM_BASE, end=SRAM_BASE + SRAM_SIZE - 1)

    # SysCtlReset writes NVIC_APINT then spins; stop there
    def hook_reset(uc, access, address, size, value, user):
        if address == 0xE000ED0C and ((value >> 16) == 0x05FA):
            bench.did_reset = True
            uc.emu_stop()
        return True
    uc.hook_add(UC_HOOK_MEM_WRITE, hook_reset, begin=0xE000ED00, end=0xE000ED10)

    # enable FPU (CPACR CP10/11)
    CPACR = 0xE000ED88
    uc.mem_write(CPACR, struct.pack("<I", 0xF << 20))
    try:
        uc.reg_write(UC_ARM_REG_C1_C0_2, 0xF << 20)
    except Exception:
        pass

    # optional fault-injection hooks: (address, fn(uc)) fired when PC hits address
    if code_hooks:
        for addr, fn in code_hooks:
            def mk(fn):
                def h(uc, address, size, user):
                    fn(uc)
                return h
            uc.hook_add(UC_HOOK_CODE, mk(fn), begin=addr, end=addr)

    sp = struct.unpack("<I", bytes(uc.mem_read(0x0, 4)))[0]
    reset = struct.unpack("<I", bytes(uc.mem_read(0x4, 4)))[0]
    uc.reg_write(UC_ARM_REG_SP, sp)
    bench.min_sp = sp

    err = None
    try:
        uc.emu_start(reset | 1, 0, count=max_count)
    except UcError as e:
        err = (str(e), uc.reg_read(UC_ARM_REG_PC))
    return {
        "uart_out": bytes(bench.uart_out),
        "flash": bytes(flash),
        "flash_error": bench.flash_error,
        "ops": bench.ops,
        "err": err,
        "unmapped": [(a, hex(x)) for a, x in unmapped[:8]],
        "sp": sp, "min_sp": bench.min_sp, "reset": reset,
    }

def main():
    r = run()
    print("SP=0x%08x reset=0x%08x" % (r["sp"], r["reset"]))
    if r["err"]:
        print("STOP UcError:", r["err"][0], "PC=0x%08x" % r["err"][1])
    print("uart_out (%d bytes):" % len(r["uart_out"]), r["uart_out"][:80])
    if r["unmapped"]:
        print("first unmapped accesses:", r["unmapped"])

if __name__ == "__main__":
    main()
