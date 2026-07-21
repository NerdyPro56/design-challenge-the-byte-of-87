# Cryptographic Automotive Software Handler and Bootloader (CrASHBoot)

## The Byte of 87 secure redesign

This repository hardens CrASHBoot for the 2026 BWSI eCTF. The update path uses ChaCha20-Poly1305 with an Ed25519 signature over the header and ciphertext, a monotone `min_ver` ratchet blocks rollback, and the boot record commits through a derived magic rather than a branch. The debug port locks at first boot so a flash dump returns nothing.

Below is the installation and development guide for the most secure (TM) automotive bootloader on the planet! We guarentee that cars running our software will be unhackable (provided hacking is not attempted). Of all the automotive bootloaders, this is certainly one of the ones of all time. Read on.. and shiver your timbers at our mad embedded security skillz.

### Internal Notes

Letter
```
I find myself trapped in the labyrinthine depths of my company, shackled by an unending torrent of menial tasks. My desk has become my prison, my workload, my jailer. I am buried under a mountain of code, my skills squandered on trivialities while critical applications do not get the attention they deserve. In a desperate attempt to keep up with the workload, I've had to rapidly create a functional, yet insecure, product. It's a risky move, one that fills me with dread. I haven't had the time to implement the necessary security goals of confidentiality, integrity, and authentication. If you are reading this: I implore you, proceed with caution. **Do not release this software.** It is potentially riddled with vulnerabilities and exposed to the most basic types of attacks. 

Please, send help. I need to escape this relentless cycle. I need a team of talented interns to tackle this challenge. Otherwise, I fear the worst.
```

Do not worry, poor employee. Your call for help has reached thee! Fear not your bugs, nor dread the deploy, us interns come, to code your buoy!

# Project Structure
```
├── bootloader
│   ├── bin
│   ├── bootloader.ld
│   ├── inc
│   │   ├── bootloader.h
│   │   └── user_settings.h
│   ├── Makefile
│   └── src
│       ├── bootloader.c
│       └── startup_gcc.c
├── firmware
│   ├── bin
│   ├── firmware.ld
│   ├── Makefile
│   └── src
│       └── firmware.c
├── makedefs
├── README.md
├── tests
│   ├── emu
│   │   ├── drive_update.py
│   │   ├── emu.py
│   │   └── fault_rollback.py
│   ├── test_emu_budget.py
│   └── test_host_tools.py
└── tools
    ├── __init__.py
    ├── bl_build.py
    ├── fw_protect.py
    ├── fw_update.py
    └── util.py
```

(obtained via `tree --gitignore -I lib`)

# Prerequisites

- `arm-none-eabi-gcc` toolchain
- `lm4flash` to flash an unlocked board
- `openocd` to debug or erase an unlocked board
- TI LM Flash Programmer on Windows to unlock a latched board
- a venv at `tools/.venv`: `pip install pycryptodome pyserial unicorn`
- wolfSSL as a submodule: `git submodule update --init --recursive`

`bootloader/Makefile` builds wolfSSL. `bootloader/inc/user_settings.h` selects its primitives.

# Build and Flash

```
cd tools
python bl_build.py                       # production: debug lock enabled
lm4flash ../bootloader/bin/bootloader.bin
```

Each build generates new keys:

- `bootloader/inc/secrets.h`: device key and verification key
- `tools/secret_build_output.txt`: encryption key and signing seed

Git ignores both files. Preserve them with the build they belong to.

A development build leaves SWD open:

```
ECTF_LOCK=0 python bl_build.py
lm4flash ../bootloader/bin/bootloader.bin
```

## Debug Lock and Recovery

The production build clears `BOOTCFG.DBG1`. An unplug and replug latches the lock. RESET does not.

Before the latch:

```
# erase flash and committed user registers
openocd -f board/ti_ek-tm4c123gxl.cfg -c "init; halt; stellaris recover; exit"

# erase an unlocked target
openocd -f board/ti_ek-tm4c123gxl.cfg -c "init; halt; stellaris mass_erase 0; exit"
```

Power-cycle after `stellaris recover`.

After the latch, OpenOCD cannot open the ICDI debug channel. Use TI LM Flash Programmer on Windows. Installers live under `vendor/ti/`.

# Protect and Update Firmware

```
cd ../firmware && make
cd ../tools
python fw_protect.py --infile ../firmware/bin/firmware.bin --outfile fw.bin --version 2 --message "hello"
python fw_update.py --firmware fw.bin --port /dev/tty.usbmodemXXXX
```

Version 0 installs without changing `min_ver`. Other versions must meet or exceed `min_ver`. Rejection resets into the bootloader. After **B**oot, press RESET to return.

Ed25519 verification takes about eight seconds at 16 MHz. Success ends with the final ack.

# Interacting with the Bootloader

```
python -m serial.tools.miniterm /dev/tty.usbmodemXXXX 115200
```

`U` updates, `B` boots. `Ctrl-]` exits miniterm, `Ctrl-A X` exits picocom.

# Tests

```
python -m unittest discover -s tests
```

Wire tests use pycryptodome. Emulator tests run `bootloader.bin` under Unicorn. Build first. The fault test corrupts one `min_ver` read; the remaining reads reject rollback:

```
python tests/emu/drive_update.py
python tests/emu/fault_rollback.py
```

`.github/workflows/ci.yml` runs these checks on each push.

# Debugging

Debugging requires an unlocked board.

```bash
openocd -f board/ti_ek-tm4c123gxl.cfg
gdb-multiarch -ex "target extended-remote localhost:3333" bootloader/bin/bootloader.axf
```

```
layout src
list main
break bootloader.c:97
```

Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED <br>
Approved for public release. Distribution unlimited 23-02181-25.

Portions modified by The Byte of 87 Design Team, 2026
