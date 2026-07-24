# Cryptographic Automotive Software Handler and Bootloader (CrASHBoot)

> [!warning]
> # Warning: This bootloader may soft-brick your Tiva if you mess up instructions (recoverable)

<img width="736" height="736" alt="image" src="https://github.com/user-attachments/assets/3ec145d9-b7bc-44f8-8cb2-86ae1ae6bf5b" />

## The Byte of 87 secure redesign

This repository hardens CrASHBoot for the 2026 BWSI eCTF. The update path uses ChaCha20-Poly1305 with an Ed25519 signature over the header and ciphertext, a monotone `min_ver` ratchet blocks rollback, and the boot record commits through a derived magic rather than a branch. The debug port locks at first boot so a flash dump returns nothing.

Below is the installation and development guide for the most secure (TM) automotive bootloader on the planet! We guarentee that cars running our software will be unhackable (provided hacking is not attempted). Of all the automotive bootloaders, this is certainly one of the ones of all time. Read on.. and shiver your timbers at our mad embedded security skillz.

### Internal Notes

Letter
```
I find myself trapped in the labyrinthine depths of my company, shackled by an unending torrent of menial tasks. My desk has become my prison, my workload, my jailer. I am buried under a mountain of code, my skills squandered on trivialities while critical applications do not get the attention they deserve. In a desperate attempt to keep up with the workload, I've had to rapidly create a functional, yet insecure, product. It's a risky move, one that fills me with dread. I haven't had the time to implement the necessary security goals of confidentiality, integrity, and authentication. If you are reading this: I implore you, proceed with caution. **Do not release this software.** It is potentially riddled with vulnerabilities and exposed to the most basic types of attacks. 

Please, send help. I need to escape this relentless cycle. I need a team of talented interns to tackle this challenge. Otherwise, I fear the worst.
```
![e](https://i.pinimg.com/originals/4c/d6/ea/4cd6eaa599851725aa5a195d162fb20d.gif)

Do not worry, poor employee. Your call for help has reached thee! Fear not your bugs, nor dread the deploy, us interns come, to code your buoy!

# Read This First
<img width="736" height="736" alt="image" src="https://github.com/user-attachments/assets/c9ca1dc7-8b6a-4e08-a10d-13ab942fba40" />

```
ECTF_LOCK=0 python bl_build.py    # dev: keeps lm4flash and openocd
python bl_build.py                # handoff: SWD dies at the next power cycle
```

Locked boards still update and boot. Only SWD closes; recovery is TI LM Flash Programmer on Windows.

`fw_update.py` hanging with no output means a stray byte left the bootloader mid-header. Press RESET.

# Project Structure
![e](https://i.pinimg.com/originals/da/91/0e/da910eb6a6fefe154615509504477a18.gif)

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
![e](https://i.pinimg.com/originals/8f/c2/54/8fc254c88aead8df332af9039d9658d2.gif)
- `arm-none-eabi-gcc` toolchain
- `lm4flash` to flash an unlocked board
- `openocd` to debug or erase an unlocked board
- TI LM Flash Programmer on Windows to unlock a latched board
- a venv at `tools/.venv`: `pip install pycryptodome pyserial unicorn`
- wolfSSL as a submodule: `git submodule update --init --recursive`

`bootloader/Makefile` builds wolfSSL. `bootloader/inc/user_settings.h` selects its primitives.

# Host Tool API
![e](https://i.pinimg.com/originals/21/3c/5a/213c5a93142eb37cd2a986b7d4cb123a.gif)

Three tools, three command lines, fixed by the rules. Run each from `tools/`. Exit zero means success.

```
python bl_build.py
python fw_protect.py --infile <in.bin> --outfile <out.bin> --version <n> --message <str>
python fw_update.py  --port <serial port> --firmware <out.bin>
```

Limits: firmware 30720 B, message 1024 B, version 0 to 65535. `ECTF_LOCK` is an environment variable, not a flag, so the mandated command line stays the mandated command line.

# The Factory Sequence

![e](https://images.steamusercontent.com/ugc/261594144871269127/2876A5D936B8790021A14AADC28F035E92418015/?imw=5000&imh=5000&ima=fit&impolicy=Letterbox&imcolor=%23000000&letterbox=false)


```
cd tools
python bl_build.py                                  # keys + bootloader.bin; lock ON
lm4flash ../bootloader/bin/bootloader.bin           # needs the port still open
python fw_protect.py --infile ../firmware/bin/firmware.bin \
    --outfile init_fw_prot.bin --version 2 --message "Firmware V2"
python fw_update.py --port /dev/tty.usbmodemXXXX --firmware init_fw_prot.bin
                                                    # unplug/replug: lock latches HERE
```

- Flash, boot, power cycle, in that order. The lock latches on the third.
- Flags go in the firmware binary and the release message.
- Keys are per build. Protect with the build that flashed the board.

# Build and Flash

<img width="250" height="379" alt="image" src="https://github.com/user-attachments/assets/dceb7010-5797-47df-bfcc-b75d19dcb96f" />
<img width="270" height="506.5" alt="image" src="https://github.com/user-attachments/assets/eb773898-d51d-470b-85ed-b42187c32daa" />

```
ECTF_LOCK=0 python bl_build.py && lm4flash ../bootloader/bin/bootloader.bin   # reflashable
python bl_build.py             && lm4flash ../bootloader/bin/bootloader.bin   # one-way
```

# Protect and Update Firmware


```
cd ../firmware && make
cd ../tools
python fw_protect.py --infile ../firmware/bin/firmware.bin \
    --outfile fw.bin --version 2 --message "hello"
python fw_update.py --firmware fw.bin --port /dev/tty.usbmodemXXXX
```

```
Wrote frame 11 (64 bytes)
Done writing firmware.        # exit 0. a rejection raises and exits 1
```

~8-12 s; the crypto takes a while. Rerun freely. If it acts up, RESET.

```
--version 0    # installs at any floor, never raises it
--version 1    # below min_ver: refused at the header, before anything is erased
```

A bad signature is refused after the erase, so the device reports no firmware until a good image lands.

# Interacting with the Bootloader

<img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/ec02c261-c105-45d3-b6e3-8605dd0935f8" />


```
python -m serial.tools.miniterm /dev/tty.usbmodemXXXX 115200
```

`U` updates, `B` boots. `Ctrl-]` quits miniterm. Close it before `fw_update.py`.

# When It Looks Bricked

<img width="550" height="550" alt="image" src="https://github.com/user-attachments/assets/a06b4139-85ac-4f3d-8a63-b75419f6c54d" />


| Symptom | Cause | Cure |
| --- | --- | --- |
| `no handshake from the bootloader after 10s` | stranded mid-header | press RESET, rerun |
| `Bootloader responded with b'W'` | image refused; `W` opens the reset banner, it is not a reply | check the version, and that the keys match the flashed build |
| `No firmware loaded. Please RESET device.` | no committed boot record | rerun `fw_update.py` with a valid image |
| `B` does nothing | firmware already running | press RESET |
| `lm4flash` hangs forever | debug port latched | TI unlock, below |
| `openocd`: `query supported failed: 0x7` | debug port latched | TI unlock, below |

`reject()` resets before the `ERROR` byte leaves the FIFO, so you see the banner instead. Any non-`OK` reply exits 1.

# Debug Lock and Recovery

<img width="302" height="222" alt="image" src="https://github.com/user-attachments/assets/d884ec45-acb5-4217-82fe-f972afb14c26" />


The production build clears `BOOTCFG.DBG1` on the first boot. An unplug and replug latches it. RESET does not.

Before the latch:

```
# erase flash and committed user registers
openocd -f board/ti_ek-tm4c123gxl.cfg -c "init; halt; stellaris recover; exit"

# erase an unlocked target
openocd -f board/ti_ek-tm4c123gxl.cfg -c "init; halt; stellaris mass_erase 0; exit"
```

Power-cycle after `stellaris recover`.

After the latch, only the TI unlock works. `openocd` and `lm4flash` both fail. The serial port still enumerates; that is the UART bridge, not the debug channel.

Run PowerShell as Administrator from the repository root:

```powershell
Expand-Archive .\vendor\ti\LMFlashProgrammer_1613.zip .\vendor\ti\lmflash
msiexec.exe /i ".\vendor\ti\lmflash\LMFlashProgrammer.msi"
Expand-Archive .\vendor\ti\stellaris_icdi_drivers_spmc016a.zip .\vendor\ti\icdi
pnputil.exe /add-driver ".\vendor\ti\icdi\stellaris_icdi_drivers\stellaris_icdi_debug.inf" /install
```

Catalog trust error? Trust the archived signer, then repeat `pnputil`:

```powershell
$cat = Get-AuthenticodeSignature ".\vendor\ti\icdi\stellaris_icdi_drivers\stellaris_icdi_debug.cat"
$store = [System.Security.Cryptography.X509Certificates.X509Store]::new("TrustedPublisher", "LocalMachine")
$store.Open("ReadWrite")
$store.Add($cat.SignerCertificate)
$store.Close()
pnputil.exe /add-driver ".\vendor\ti\icdi\stellaris_icdi_drivers\stellaris_icdi_debug.inf" /install
```

Unplug and replug. Confirm the ICDI interface:

```powershell
Get-PnpDevice -PresentOnly | Where-Object InstanceId -Like 'USB\VID_1CBE&PID_00FD*'
```

```powershell
& 'C:\Program Files (x86)\Texas Instruments\Stellaris\LM Flash Programmer\LMFlash.exe'
```

In **Other Utilities**, select **Debug Port Unlock** and **TM4C123**:

1. Disconnect power.
2. Hold RESET.
3. Reconnect power.
4. Run Unlock.
5. Release RESET when prompted.
6. Unplug and replug.

Unlock erases flash and restores `BOOTCFG`. The erase runs before the port reopens, so the keys are gone before JTAG is usable again. There is no partial unlock.

Verify and reflash from macOS or Linux:

```bash
# SWD must enumerate again; BOOTCFG should read 0xfffffffe
openocd -f board/ti_ek-tm4c123gxl.cfg \
  -c "init; halt; mdw 0x400FE1D0 1; exit"
cd tools
ECTF_LOCK=0 python bl_build.py
lm4flash ../bootloader/bin/bootloader.bin
```

`BOOTCFG` reads the value latched at power-on, not the value just committed. A freshly locked board still reads `0xfffffffe` until it is power-cycled. Do not read that as a failed commit.

# Tests

```
python -m unittest discover -s tests
```

Wire tests use pycryptodome. Emulator tests run `bootloader.bin` under Unicorn. Build first. The fault test corrupts one `min_ver` read; the remaining reads reject rollback:

```
python tests/emu/drive_update.py
python tests/emu/fault_rollback.py
```

`.github/workflows/ci.yml` runs these on each push, plus the image size ceiling and a symbol check.

The symbol check earns its keep. `bootloader/Makefile` force-lists every driverlib object on the link line, so only `--gc-sections` keeps uDMA, USB, CAN and the rest out of flash. uDMA is a flash-to-UART copy engine, a gadget worth denying anyone who gets execution. Nothing calls them, so a hit means the strip broke.

```
arm-none-eabi-nm --defined-only bootloader/bin/bootloader.axf \
  | grep -E ' [TtWw] (uDMA|USB|CAN|EMAC|EPI|LCD|QEI|PWM|SHAMD5|Hibernate|OneWire)'
```

Silence is a pass.

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

Read the boot state over SWD while unlocked:

```bash
openocd -f board/ti_ek-tm4c123gxl.cfg -c \
  'init; halt; echo "magic  =[format 0x%08x [read_memory 0xFC08 32 1]]";
   echo "floor  =[format 0x%08x [read_memory 0xF800 32 1]]";
   echo "bootcfg=[format 0x%08x [read_memory 0x400FE1D0 32 1]]"; resume; exit'
```

`magic` reads `0x544f4f42` on a committed image. Anything else is the verdict word XORed in: bit 0 version, bit 1 signature, low byte tag. `0xffffffff` means erased. `floor` is the first ratchet word; `0xffffffff` means never raised, which reads as version 1.

Always `resume` after a `halt`. A halted core does not answer the UART, and the next `fw_update.py` will hang against it.

Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED <br>
Approved for public release. Distribution unlimited 23-02181-25.

Portions modified by The Byte of 87 Design Team, 2026
