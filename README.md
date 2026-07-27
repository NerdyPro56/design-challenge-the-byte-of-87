<img width="525" height="268" alt="image" src="https://github.com/user-attachments/assets/d9cda4fc-abd3-4706-a788-f6ace7e0635a" />

# Cryptographic Automotive Software Handler and Bootloader (CrASHBoot)
## "Informative diagrams" and Warning by Taurox
> [!warning]
> # Warning: This bootloader may soft-brick your Tiva if you mess up instructions (recoverable)

<img width="736" height="736" alt="image" src="https://github.com/user-attachments/assets/3ec145d9-b7bc-44f8-8cb2-86ae1ae6bf5b" />

## The Byte of 87 secure redesign

<img width="1188" height="301" alt="image" src="https://github.com/user-attachments/assets/12433aa3-654a-40fb-86f4-5dc58206de2e" />

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
│   │   ├── fault_commit.py
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

# Design

This section uses ASD-STE100 Simplified Technical English.

All device code is in `bootloader/src/bootloader.c`. The file `bootloader/inc/user_settings.h` selects the wolfSSL primitives for the build. The three host tools in `tools/` make the keys, make the protected image, and send the image to the device. The line numbers below refer to the current source.

## Protected Image Format

The tool `fw_protect.py` writes a header of 98 bytes. The ciphertext follows the header (`fw_protect.py:44`). The constants `HDR_LEN` and `SIG_OFF` at `bootloader.c:43-44` give the same layout on the device.

| Offset | Size | Field | Produced by | Consumed by |
| --- | --- | --- | --- | --- |
| 0 | 6 | version, firmware size, message length, little-endian | `fw_protect.py:34` | `bootloader.c:231-233` |
| 6 | 12 | ChaCha20 nonce | `fw_protect.py:36` | `bootloader.c:293` |
| 18 | 16 | Poly1305 tag | `fw_protect.py:39` | `bootloader.c:312` |
| 34 | 64 | Ed25519 signature | `fw_protect.py:41` | `bootloader.c:247` |
| 98 | size + msg_len | ciphertext of the firmware, then the release message | `fw_protect.py:39` | streamed at `bootloader.c:259-262` |

The first 6 bytes are the associated data for the AEAD (`fw_protect.py:38`). The bootloader gives the same 6 bytes to the AEAD at `bootloader.c:296`. If an attacker changes the version in the header from 1 to 3, the tag does not agree.

The signature at `fw_protect.py:41` covers the associated data, the nonce, the tag, and the ciphertext. The signature does not cover itself. An attacker who has `fw_key` can calculate a correct tag for any ciphertext. That attacker cannot sign the ciphertext again, because the private key stays in the factory.

The tool adds a null byte to the release message (`fw_protect.py:21`). Therefore `MAX_MSG_LEN` is 1025 and not 1024 (`bootloader.h:11`). A message of 1024 bytes gives a `msg_len` of 1025. An empty message gives a `msg_len` of 1. The bootloader rejects a `msg_len` of 0 at `bootloader.c:237`.

## Memory Map

| Address range | Contents | Constant |
| --- | --- | --- |
| `0x00000` to `0x0F7FF` | bootloader code, `fw_key_obf`, `ed_pub` | `FLASH` LENGTH, `bootloader.ld:27` |
| `0x0F800` to `0x0FBFF` | version floor ratchet | `MIN_VER_BASE`, `bootloader.c:36` |
| `0x0FC00` to `0x0FFFF` | boot record | `METADATA_BASE`, `bootloader.c:35` |
| `0x10000` to `0x177FF` | installed firmware, then the release message | `FW_BASE`, `bootloader.c:37` |
| `0x18000` to `0x1FFFF` | staging area for an incoming update | `SCRATCH_BASE`, `bootloader.c:39` |
| `0x20000` to `0x27FFF` | backup of the firmware that an update replaces | `BACKUP_FW_BASE`, `bootloader.c:40` |
| `0x28000` to `0x283FF` | backup boot record | `BACKUP_METADATA_BASE`, `bootloader.c:41` |

The linker script stops the image at `0x0F800`. A bootloader that becomes too large gives a link error. It does not write into the ratchet page. The `#error` block at `bootloader.c:54-59` does the same calculation for the four firmware regions at build time. It uses `MAX_IMAGE_SIZE` as the largest case. If you move one base constant and do not move the next one, the build fails.

The release message starts at `FW_BASE` plus the firmware size. Its start address changes with the size of the image. The limits of 30720 bytes and 1025 bytes keep the two items in the firmware region.

The boot record has 12 bytes. The field sequence puts `size` at the address that `fw_size_address` (`bootloader.c:62`) uses:

| Offset | Size | Field |
| --- | --- | --- |
| `0xFC00` | 2 | version |
| `0xFC02` | 2 | firmware size |
| `0xFC04` | 2 | message length |
| `0xFC06` | 2 | padding |
| `0xFC08` | 4 | magic |

Flash memory programs words in an increasing address sequence. The magic is in the last word. Therefore the bootloader writes the magic last. If power stops during the write, the magic stays `0xFFFFFFFF`. No code reads the padding. The padding puts the magic on a word boundary.

The function `record_ok` (`bootloader.c:126`) is the only test of a record. It examines the magic, the firmware size, and the message length together. The functions `recover_firmware` and `sync_floor` call `record_ok`. They do not repeat the test.

## Keys

The tool `bl_build.py` makes two secrets for each build. `fw_key` is 32 random bytes (`bl_build.py:26`). The Ed25519 key pair comes from `ECC.generate` (`bl_build.py:27`). The build writes the public key and `fw_key_obf` to `bootloader/inc/secrets.h`. `fw_key_obf` is `fw_key` XOR the first 32 bytes of `SHA512(ed_pub)` (`bl_build.py:31-32`).

The private seed goes only to `tools/secret_build_output.txt` (`bl_build.py:37-38`). The tool `fw_protect.py` reads that file (`fw_protect.py:29-32`). The chip never holds the private seed.

The two arrays are at `bootloader.c:65-66`. The bootloader calculates `fw_key` in a stack buffer immediately before it uses the key (`bootloader.c:287-292`). The function `wc_ChaCha20Poly1305_Init` copies the key schedule. The bootloader then erases the buffer with a `volatile` helper (`bootloader.c:294-295`). Therefore the key stays in SRAM for one function call and not for the full update.

The XOR operation is an obstacle and not a boundary. A person who has the source code can calculate `fw_key` from `ed_pub`. The debug lock gives the confidentiality.

## Boot Path

The function `main` (`bootloader.c:183`) does four steps before it accepts a command:

1. `lock_debug`, if `LOCK` is 1
2. `lock_sram_xn`
3. `recover_firmware`
4. `sync_floor`

The function `lock_debug` (`bootloader.c:94`) sets `DBG1` in `BOOTCFG` to 0. If the bit is already 0, the function returns immediately. The function `lock_sram_xn` (`bootloader.c:84`) makes the 32 kB of SRAM no-execute with MPU region 0. Therefore the processor cannot execute data in a buffer.

The function `boot_firmware` (`bootloader.c:409`) does no cryptography. The magic shows that the image passed the tag test, the version test, and the signature test at installation. The test `test_boot_is_crypto_free` (`tests/test_emu_budget.py:76`) limits the boot path to 500000 instructions. A new cryptographic operation in this path makes the test fail.

## Two-Pass Update

The function `load_firmware` (`bootloader.c:220`) does the checks in two passes. The two passes keep `fw_key` away from data that an attacker selects.

In pass one the bootloader reads the header of 98 bytes (`bootloader.c:227-229`). It examines the two lengths and compares the version with the floor (`bootloader.c:237-242`). It then starts an Ed25519 verification on the header (`bootloader.c:245-248`). Each frame goes into the one-page buffer `data[]`. The bootloader gives each frame to `wc_ed25519_verify_msg_update` (`bootloader.c:262`) and programs the frame into the staging area as ciphertext (`bootloader.c:267`). In this pass the bootloader does not change the installed firmware or its record. The function `wc_ed25519_verify_msg_final` (`bootloader.c:276`) gives the result.

Pass two starts only if `diff` is 0 (`bootloader.c:286`). The bootloader calculates `fw_key` again. It decrypts the staging area one page at a time (`bootloader.c:299-309`). It then compares the 16 tag bytes (`bootloader.c:311-313`).

A bootloader that decrypts before it verifies the signature gives an attacker a good target for power analysis. The key is constant. The attacker selects the nonce at `hdr+6` and the ciphertext. The bootloader always accepts a version 0 header. Therefore the attacker can do the operation many times. A bootloader that verifies the signature first uses `fw_key` only on data from the factory.

The bootloader processes both passes as a stream. Therefore an image of 30 kB operates in 32 kB of SRAM. The options `ED25519_SMALL` and `WOLFSSL_ED25519_STREAMING_VERIFY` (`user_settings.h:321-324`) make the stream verification available. They also keep the stack frame in the 1024 words at `startup_gcc.c:51`.

## Install Transaction

The active record stays correct during both passes. If the transfer stops, or if the bootloader rejects the image, the previous firmware still starts. The test `test_reset_during_frames_keeps_old_firmware` (`tests/test_emu_budget.py:81`) stops a transfer in a frame. It then shows the old release message.

If `diff` is 0, the bootloader does these steps in this sequence (`bootloader.c:318-352`):

1. Copy the installed firmware to `BACKUP_FW_BASE`. Write the backup record last (`bootloader.c:321-329`).
2. Erase the active record. Copy the decrypted image from the staging area over the old image (`bootloader.c:331-338`).
3. Write the new record. The magic is in the last word (`bootloader.c:343`).
4. Raise the floor with `sync_floor`. Erase the backup record. Erase the backup firmware pages (`bootloader.c:346-352`).

If power stops in step 2 or step 3, flash memory holds an incomplete active record and a correct backup record. At the next start, `recover_firmware` (`bootloader.c:148`) corrects this condition before `main` accepts a command. It copies the backup pages to the firmware region and writes the active record again. It erases the backup record only after both operations are successful. If power stops during this recovery, the next start does the same operations again. Each interruption point gives the old image or the new image.

Step 4 erases the backup firmware. If the backup stays, a flash dump shows the replaced firmware in plain text. The test `test_max_image_and_backup_fit_tm4c` (`tests/test_emu_budget.py:63`) shows that the full backup region reads `0xFF` after an installation. The test installs the largest image two times. Therefore the 256 kB of flash memory holds an active copy, a staged copy, and a backup copy at the same time.

## Version Ratchet

The floor has its own page at `MIN_VER_BASE`. No code erases this page. A program operation changes flash bits from 1 to 0. Only an erase operation changes them back to 1. The function `min_ver_slot` (`bootloader.c:106`) finds the first word that reads `0xFFFFFFFF`. The function `sync_floor` (`bootloader.c:168`) programs one more word of 4 bytes at that address with `FlashProgram`.

No code sends the floor to `program_flash`, because `program_flash` erases the page first (`bootloader.c:374`). A floor in the boot record page is not safe for the same reason. Each write of the record erases that page. The floor then reads as erased for approximately 20 ms. If a person pushes RESET in this interval, an old version installs. The separate page removes this interval.

The function `cur_floor` (`bootloader.c:116`) reads the floor. The floor is the last word that does not read `0xFFFFFFFF`. A fully erased page gives version 1. The function is `noinline` and reads through a `volatile` pointer. This is necessary. In an earlier build the compiler kept one floor value in a register, and the early rejection and both fold operations used that register. One fault on the register then let a version 1 image install.

The bootloader now reads the floor again at `bootloader.c:240`, `279`, `282`, and `173`. One incorrect read does not defeat the other tests. The test `tests/emu/fault_rollback.py` finds each `bl cur_floor` instruction in the binary and sets `r0` to 1 at each of these points.

A version 0 image installs at each floor value and does not raise the floor. The condition `ver != 0` at the four points gives this behavior. The bootloader writes the record before it raises the floor. The function `main` calls `sync_floor` at each start. Therefore a reset between the two write operations raises the floor before the new image starts.

The page holds 256 words. The bootloader uses a word only when `ver` is more than the floor. Therefore 256 versions in an increasing sequence fill the page. The function `sync_floor` stops at the last word (`bootloader.c:175`) and does not write into the record page. The floor is a 32-bit word. Therefore version `0xFFFF` is `0x0000FFFF` and stays different from the erased word `0xFFFFFFFF`. A 16-bit floor makes these two values the same.

## Fault Resistance

The commit has no branch instruction that a fault can skip. The bootloader puts the version result, the signature result, and the 16 tag byte differences into one word, `diff`. The magic for the record is `BOOT_MAGIC ^ diff` (`bootloader.c:316`). If one test fails, this calculation gives a magic that the boot path rejects.

The 16 byte differences resist one fault. The version result and the signature result are single conditions. Therefore the bootloader calculates them two times at different points (`bootloader.c:279-283`). Each result now needs two faults, as the tag does. This is important against an attacker who has `fw_key`. That attacker makes a correct tag and a correct version. Only `diff |= 2` then stays. The test `tests/emu/fault_commit.py` finds the XOR instruction in the binary and skips it. The test shows that `diff == 0` still controls the record write.

The function `boot_firmware` uses the same method (`bootloader.c:415-430`). It reads the magic two times through `volatile` pointers. It puts both limit tests into the word `bad`. It tests `bad` again for each character of the message. It tests `bad` one more time before it starts the firmware.

The `volatile` keywords are necessary in both places. Without `volatile` on the two magic reads, the compiler removes the second read. Without `volatile` on `bad`, the compiler removes the test in the loop and the test before the jump. One branch then controls both operations. The message loop reads `msg_len` bytes from `FW_BASE + size`, and a failed update puts attacker values in these two fields. That one branch therefore gives the attacker a flash read function. Examine the disassembly after each change to this function.

The first test returns to the command loop and does not stop the processor (`bootloader.c:422`). A stopped bootloader does not answer `U`. A person must then remove the power to update the device. The test before the jump does stop the processor, because the next instruction starts the image.

## Host Protocol

The tool `fw_update.py` divides the file at byte 98 (`fw_update.py:94-95`) and sends the header without a change. Before the handshake it removes the bytes in the input buffer (`fw_update.py:44-47`). This is necessary because the device resets after a rejection. The banner after the reset contains three `U` characters, and the tool can read these characters as the echo.

The handshake has a limit of 10 seconds (`fw_update.py:54-59`). A bootloader that stops in the header does not answer. The tool then gives an error and does not wait.

Each frame has a length of 2 bytes in big-endian sequence and then the data (`fw_update.py:103`). The bootloader acknowledges each frame (`bootloader.c:273`). `FRAME_SIZE` is 256 (`fw_update.py:34`), and this value must divide `FLASH_PAGESIZE`. The bootloader fills a page buffer of 1024 bytes and rejects a frame that is too large for the buffer (`bootloader.c:256`). A different frame size makes a correct update cross the page limit, and the bootloader then rejects that update.

The last read is the commit acknowledgement (`fw_update.py:111-113`). It gives the result of the tag test and the signature test. Without this read, the last acknowledgement is the acknowledgement of the last frame. The bootloader sends that byte before it calculates the tag. The tool then gives exit code 0 for a rejected image. `RESP_TIMEOUT` is 30 seconds (`fw_update.py:35`), because the commit acknowledgement occurs after the signature verification, the decryption, the backup copy, and the installation.

The function `reject` (`bootloader.c:72`) waits for `UARTBusy` before the reset. Therefore the `ERROR` byte goes out of the transmitter before the reset.

One condition stays open. The bootloader sends the first OK after the version test and before the verification (`bootloader.c:250`). The OK therefore shows if the version is more than the floor. An attacker finds the floor in approximately 16 attempts. The published version numbers give the same data. A later OK breaks the frame sequence of the host tool.

## Build Configuration

`LOCK` is 1 by default (`bootloader/Makefile:23`). The tool `bl_build.py` sends the value of the environment variable `ECTF_LOCK` to make (`bl_build.py:42`). Therefore the command `python bl_build.py` makes an image that locks the debug port.

Make does not see a change to a `-D` option. The stamp file test at `bootloader/Makefile:27` removes `bootloader.o` when the value changes.

The file `user_settings.h` puts ChaCha20, Poly1305, Ed25519, Curve25519, and SHA512 in the build (lines 300 to 325 and line 357). It removes AES, DES3, RSA, and TLS.

The link command at `bootloader/Makefile:62` lists all driverlib objects. Only `--gc-sections` from `makedefs:85` keeps uDMA, USB, CAN, and the other drivers out of flash memory. The uDMA controller can copy flash memory to the UART, and an attacker who executes code can use it. No code calls these drivers. Therefore the symbol test in CI fails only if the removal fails.

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

<img width="547" height="250" alt="image" src="https://github.com/user-attachments/assets/d09ff2bf-12a1-4610-8958-25ca28d9b1c2" />

<img width="378" height="379" alt="image" src="https://github.com/user-attachments/assets/30115e29-d746-4239-be26-62979ab64e26" />


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

~8-12 s; the crypto takes a while. RESET during an update keeps the last committed firmware bootable.

```
--version 0    # installs at any floor, never raises it
--version 1    # below min_ver: refused at the header, before anything is erased
```

A bad signature is refused without replacing the last committed firmware.

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
| `Bootloader responded with b'\x01'` | image refused | check the version, and that the keys match the flashed build |
| `No firmware loaded. Please RESET device.` | no firmware has committed | run `fw_update.py` with a valid image |
| `B` does nothing | firmware already running | press RESET |
| `lm4flash` hangs forever | debug port latched | TI unlock, below |
| `openocd`: `query supported failed: 0x7` | debug port latched | TI unlock, below |

`reject()` drains the transmitter before it resets, so the `ERROR` byte arrives ahead of the banner. Any non-`OK` reply exits 1.

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
