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
- `lm4flash` to flash, `openocd` to debug and to recover a locked board
- a venv at `tools/.venv`: `pip install pycryptodome pyserial unicorn`
- wolfSSL as a submodule: `git submodule update --init --recursive`

The wolfssl target is already enabled in `bootloader/Makefile`. `user_settings.h` under `bootloader/inc` configures which primitives build in; leave it alone without a specific reason to change it.

# Build and Flash

```
cd tools
python bl_build.py
lm4flash ../bootloader/bin/bootloader.bin
```

Every run of `bl_build.py` generates a fresh key pair and writes `bootloader/inc/secrets.h` plus `tools/secret_build_output.txt`. Neither is tracked in git; both are needed by `fw_protect.py`, so keep them.

The default build locks the debug port. A dev build that keeps the port open:

```
ECTF_LOCK=0 python bl_build.py
```

# Protect and Update Firmware

```
cd ../firmware && make
cd ../tools
python fw_protect.py --infile ../firmware/bin/firmware.bin --outfile fw.bin --version 2 --message "hello"
python fw_update.py --firmware fw.bin --port /dev/tty.usbmodemXXXX
```

Version 0 always installs and leaves the minimum version unchanged. Every other version must be at or above the last one the board accepted. A rejected update resets the board back into the bootloader automatically. Only a successful **B**oot needs a physical RESET, since firmware has no path back to the bootloader.

Commit takes several seconds on the stock 16MHz clock, the Ed25519 verify running at that speed. Wait for the final ack before assuming failure.

Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED <br>
Approved for public release. Distribution unlimited 23-02181-25.

Portions modified by The Byte of 87 Design Team, 2026
