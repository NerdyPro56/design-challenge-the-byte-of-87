// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#include "bootloader.h"

// Hardware Imports
#include "inc/hw_memmap.h"    // Peripheral Base Addresses
#include "inc/hw_types.h"     // Boolean type
#include "inc/hw_flash.h"     // debug lock regs, hwreg form
#include "inc/tm4c123gh6pm.h" // Peripheral Bit Masks and Registers
// #include "inc/hw_ints.h" // Interrupt numbers

// Driver API Imports
#include "driverlib/flash.h"     // FLASH API
#include "driverlib/interrupt.h" // Interrupt API
#include "driverlib/sysctl.h"    // System control API (clock/reset)

// Application Imports
#include "driverlib/gpio.h"
#include "driverlib/mpu.h"
#include "uart/uart.h"

// Crypto Imports
#include "secrets.h"
#include "wolfssl/wolfcrypt/chacha20_poly1305.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/sha512.h"

// Forward Declarations
void load_firmware(void);
void boot_firmware(void);

// Firmware Constants
#define METADATA_BASE 0xFC00 // boot record
#define MIN_VER_BASE  0xF800 // ratchet page never erased
#define FW_BASE       0x10000 // firmware base
#define SRAM_BASE     0x20000000 // 32 kB, execute-never under the MPU
#define SCRATCH_BASE  0x18000 // ciphertext staging; fw_key runs only after the signature verifies
#define BOOT_MAGIC    0x544F4F42 // verified install writes it
#define HDR_LEN       98 // aad6 nonce12 tag16 sig64
#define SIG_OFF       34 // sig offset
#define REC_LEN       12
#define MAX_FW_SIZE   30720

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Device metadata
uint16_t * fw_size_address = (uint16_t *)(METADATA_BASE + 2); // record+2; boot reads size here

// keys from bl_build
static const uint8_t fw_key_obf[] = FW_KEY_OBF; // fw_key ^ sha512(ed_pub)[:32]; no plain key at rest
static const uint8_t ed_pub[] = ED25519_PUB; // verify half; private seed never leaves factory

// Firmware Buffer
unsigned char data[FLASH_PAGESIZE] __attribute__((aligned(4))); // one-page staging; word-aligned for FlashProgram


static void reject(void) {
    uart_write(UART0, ERROR);
    SysCtlReset();
}

// volatile so the store survives; no dead-store elimination
static void wipe(volatile uint8_t *p, uint32_t n) {
    while (n--) { *p++ = 0; }
}

// SRAM execute-never; injected data cannot run as code. bench-verify before a locked build
static void lock_sram_xn(void) {
    MPURegionSet(0, SRAM_BASE,
                 MPU_RGN_SIZE_32K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RW_USR_RW | MPU_RGN_ENABLE);
    MPUEnable(MPU_CONFIG_PRIV_DEFAULT);
    __asm(" dsb\n isb\n");
}

// kill jtag/swd so a dump reads nothing
// locked is dbg1==0 never set dbg1 that reopens debug
#if LOCK
static void lock_debug(void) {
    if ((HWREG(FLASH_BOOTCFG) & 0x00000002) == 0) { // already locked
        return;
    }
    HWREG(FLASH_FMD) = HWREG(FLASH_BOOTCFG) & ~0x00000002; // clear dbg1 only
    HWREG(FLASH_FMA) = 0x75100000;                         // bootcfg commit addr
    HWREG(FLASH_FMC) = FLASH_FMC_WRKEY | FLASH_FMC_COMT;
    while (HWREG(FLASH_FMC) & FLASH_FMC_COMT) { }
}
#endif

// bits fall 1->0 bump one word never erase
static uint32_t *min_ver_slot(void) {
    uint32_t *p = (uint32_t *)MIN_VER_BASE;
    while (p < (uint32_t *)METADATA_BASE && *p != 0xFFFFFFFF) {
        p++;
    }
    return p; // first free word
}

// re-read the floor from flash on every call; noinline + volatile so no single held
// register feeds all the version gates, else one value-fault on it rolls back
__attribute__((noinline)) static uint16_t cur_floor(void) {
    volatile uint32_t *p = (volatile uint32_t *)MIN_VER_BASE;
    uint16_t v = 1;
    while (p < (volatile uint32_t *)METADATA_BASE && *p != 0xFFFFFFFF) {
        v = (uint16_t)*p;
        p++;
    }
    return v;
}


int main(void) {

#if LOCK
    lock_debug(); // lock before any uart
#endif

    lock_sram_xn(); // SRAM execute-never before any input is parsed

    initialize_uarts(UART0);

    uart_write_str(UART0, "Welcome to the BWSI Vehicle Update Service!\n");
    uart_write_str(UART0, "Send \"U\" to update, and \"B\" to run the firmware.\n");

    int resp;
    while (1) {
        uint32_t instruction = uart_read(UART0, BLOCKING, &resp);

        if (instruction == UPDATE) {
            uart_write_str(UART0, "U");
            load_firmware();
            uart_write_str(UART0, "Loaded new firmware.\n");
            nl(UART0);
        } else if (instruction == BOOT) {
            uart_write_str(UART0, "B");
            uart_write_str(UART0, "Booting firmware...\n");
            boot_firmware();
        }
    }
}


 /*
 * Load the firmware into flash.
 */
void load_firmware(void) {
    int read, sigok = 0; // sigok 0 = fail closed
    uint8_t hdr[HDR_LEN], tag[16], rec[REC_LEN] __attribute__((aligned(4))); // word aligned
    ChaChaPoly_Aead aead;
    ed25519_key ekey;
    uint32_t page = FW_BASE, spage = SCRATCH_BASE, idx = 0, got = 0, diff = 0; // fw ptr, scratch ptr, buf idx, bytes got, verdict

    for (uint32_t i = 0; i < HDR_LEN; i++) { // header is a fixed 98 bytes
        hdr[i] = uart_read(UART0, BLOCKING, &read);
    }

    uint16_t ver = hdr[0] | (hdr[1] << 8); // little endian, attacker-supplied until the tag
    uint16_t size = hdr[2] | (hdr[3] << 8);
    uint16_t msg_len = hdr[4] | (hdr[5] << 8);
    uint32_t total = size + msg_len; // bytes to stream: firmware then message

    uint32_t *slot = min_ver_slot(); // free slot for the ratchet bump

    // unauth here bounds; signature then tag are the gate
    if (size == 0 || size > MAX_FW_SIZE || msg_len == 0 || msg_len > MAX_MSG_LEN) {
        reject();
    }
    if (ver != 0 && ver < cur_floor()) { // 0 = debug
        reject();
    }

    // pass one: sign over the ciphertext and stage it; fw_key is never run on this data
    wc_ed25519_init(&ekey);
    wc_ed25519_import_public(ed_pub, ED25519_PUB_KEY_SIZE, &ekey); // gates the fw_key decrypt below
    wc_ed25519_verify_msg_init(hdr + SIG_OFF, ED25519_SIG_SIZE, &ekey, (byte)Ed25519, NULL, 0);
    wc_ed25519_verify_msg_update(hdr, SIG_OFF, &ekey); // signed prefix: aad+nonce+tag

    FlashErase(METADATA_BASE); // no bootable image until commit
    uart_write(UART0, OK);

    while (got < total) {
        uint32_t n = (uint32_t)uart_read(UART0, BLOCKING, &read) << 8; // frame len, big endian
        n |= uart_read(UART0, BLOCKING, &read);

        if (n == 0 || got + n > total || idx + n > FLASH_PAGESIZE) { // page buffer bound
            reject();
        }
        for (uint32_t i = 0; i < n; i++) { // fill the page buffer
            data[idx + i] = uart_read(UART0, BLOCKING, &read);
        }
        wc_ed25519_verify_msg_update(data + idx, n, &ekey); // signature over the ciphertext
        idx += n;
        got += n;

        if (idx == FLASH_PAGESIZE || got == total) { // frame size divides page
            if (program_flash((uint8_t *)spage, data, idx)) { // stage ciphertext, not decrypted
                reject();
            }
            spage += FLASH_PAGESIZE;
            idx = 0;
        }
        uart_write(UART0, OK);
    }

    wc_ed25519_verify_msg_final(hdr + SIG_OFF, ED25519_SIG_SIZE, &sigok, &ekey); // sigok 1 = valid

    // version and signature verdicts fold first, each twice so a skip costs two faults; fw_key still idle
    if (ver != 0 && ver < cur_floor()) { diff |= 1; } // version verdict, floor re-read
    if (sigok != 1)                    { diff |= 2; } // signature verdict
    // second fold separated so each verdict costs two skips
    if (ver != 0 && ver < cur_floor()) { diff |= 1; }
    if (sigok != 1)                    { diff |= 2; }

    // pass two: only a validly signed image reaches fw_key; decrypt scratch in place into the fw region
    if (diff == 0) {
        uint8_t fwk[32], h[WC_SHA512_DIGEST_SIZE]; // reconstruct fw_key from the obfuscated form at use
        wc_Sha512 sh;
        wc_InitSha512(&sh);
        wc_Sha512Update(&sh, ed_pub, ED25519_PUB_KEY_SIZE);
        wc_Sha512Final(&sh, h);
        for (uint32_t i = 0; i < 32; i++) { fwk[i] = fw_key_obf[i] ^ h[i]; }
        wc_ChaCha20Poly1305_Init(&aead, fwk, hdr + 6, CHACHA20_POLY1305_AEAD_DECRYPT); // nonce = hdr+6
        wipe((volatile uint8_t *)fwk, 32); // Init copied the key schedule; raw key out of SRAM
        wipe((volatile uint8_t *)h, sizeof h);
        wc_ChaCha20Poly1305_UpdateAad(&aead, hdr, 6); // aad relabel breaks tag
        spage = SCRATCH_BASE;
        got = 0;
        while (got < total) {
            uint32_t n = total - got; // one page at a time out of scratch
            if (n > FLASH_PAGESIZE) { n = FLASH_PAGESIZE; }
            memcpy(data, (const void *)spage, n); // read the staged ciphertext
            wc_ChaCha20Poly1305_UpdateData(&aead, data, data, n); // decrypt in place
            if (program_flash((uint8_t *)page, data, n)) {
                reject();
            }
            page += FLASH_PAGESIZE;
            spage += FLASH_PAGESIZE;
            got += n;
        }
        wc_ChaCha20Poly1305_Final(&aead, tag); // tag over the staged stream
        for (uint32_t i = 0; i < 16; i++) {
            diff |= tag[i] ^ hdr[18 + i]; // no early out 16 bytes resist one fault
        }
    }

    uint32_t magic = BOOT_MAGIC ^ diff; // diff!=0 makes a magic boot refuses even if the write is forced

    // ratchet before record a cut raises floor with nothing installed
    if (diff == 0 && ver > cur_floor() && slot < (uint32_t *)METADATA_BASE) {
        uint32_t w = ver;
        FlashProgram(&w, (uint32_t)slot, 4); // not program_flash it erases
    }

    memcpy(rec, hdr, 6); // record = ver, size, msg_len
    memcpy(rec + 8, &magic, 4); // pad aligns magic to last word
    if (diff == 0) { // gate on diff; a lone XOR skip no longer commits, two skips now
        program_flash((uint8_t *)METADATA_BASE, rec, REC_LEN); // magic last torn write stays 0xffffffff
    } else {
        reject(); // record stays erased, boot bounds fold rejects the 0xffff size
    }
    wipe((volatile uint8_t *)&aead, sizeof aead); // keyed ChaCha state off the stack
    wipe((volatile uint8_t *)data, FLASH_PAGESIZE); // last plaintext page
    uart_write(UART0, OK);
}

/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of byets to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 */
long program_flash(void* page_addr, unsigned char * data, unsigned int data_len) { //flashes the program
    uint32_t word = 0;
    int ret;
    int i;

    // Erase next FLASH page
    FlashErase((uint32_t) page_addr);

    // Clear potentially unused bytes in last word
    // If data not a multiple of 4 (word size), program up to the last word
    // Then create temporary variable to create a full last word
    if (data_len % FLASH_WRITESIZE) {
        // Get number of unused bytes
        int rem = data_len % FLASH_WRITESIZE;
        int num_full_bytes = data_len - rem;

        // Program up to the last word
        ret = FlashProgram((unsigned long *)data, (uint32_t) page_addr, num_full_bytes);
        if (ret != 0) {
            return ret;
        }

        // Create last word variable -- fill unused with 0xFF
        for (i = 0; i < rem; i++) {
            word = (word >> 8) | (data[num_full_bytes + i] << 24); // Essentially a shift register from MSB->LSB
        }
        for (i = i; i < 4; i++) {
            word = (word >> 8) | 0xFF000000;
        }

        // Program word
        return FlashProgram(&word, (uint32_t) page_addr + num_full_bytes, 4);
    } else {
        // Write full buffer of 4-byte words
        return FlashProgram((unsigned long *)data, (uint32_t) page_addr, data_len);
    }
}

void boot_firmware(void) {
    uint16_t size = *fw_size_address; // from the committed record
    uint16_t msg_len = *(uint16_t *)(METADATA_BASE + 4);

    // fold magic+bounds twice erased page fails
    // gate print and jump a skipped branch cannot leak flash
    volatile uint32_t bad = *(volatile uint32_t *)(METADATA_BASE + 8) ^ BOOT_MAGIC;
    if (size > MAX_FW_SIZE)    { bad |= 0x10000; }
    if (msg_len > MAX_MSG_LEN) { bad |= 0x20000; }
    bad |= *(volatile uint32_t *)(METADATA_BASE + 8) ^ BOOT_MAGIC; // volatile: keep both reads

    if (bad) {
        uart_write_str(UART0, "No firmware loaded. Please RESET device.\n");
        return; // back to the command loop; reaches neither the print nor the jump
    }

    uint8_t *msg = (uint8_t *)(FW_BASE + size);
    for (uint16_t i = 0; i < msg_len && msg[i] && !bad; i++) { // !bad skipped gate cannot leak
        uart_write(UART0, msg[i]);
    }

    if (bad) { while (1) { } } // recheck before jump
    __asm("LDR R0,=0x10001\n\t"  // 0x10001 = FW_BASE + thumb bit
          "BX R0\n\t");
}
