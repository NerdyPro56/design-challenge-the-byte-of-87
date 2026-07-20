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

Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED <br>
Approved for public release. Distribution unlimited 23-02181-25.

Portions modified by The Byte of 87 Design Team, 2026
