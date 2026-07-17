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
#include "uart/uart.h"

// Crypto Imports
#include "secrets.h"
#include "wolfssl/wolfcrypt/chacha20_poly1305.h"
#include "wolfssl/wolfcrypt/ed25519.h"

// Forward Declarations
void load_firmware(void);

// Firmware Constants
#define METADATA_BASE 0xFC00 // boot record
#define MIN_VER_BASE  0xF800 // ratchet page never erased
#define FW_BASE       0x10000 // firmware base
#define BOOT_MAGIC    0x544F4F42 // verified install writes it
#define HDR_LEN       98 // aad6 nonce12 tag16 sig64
#define SIG_OFF       34 // sig offset
#define REC_LEN       12
#define MAX_FW_SIZE   30720

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Device metadata
uint16_t * fw_size_address = (uint16_t *)(METADATA_BASE + 2);

// public keys from bl_build
static const uint8_t fw_key[] = FW_KEY;
static const uint8_t ed_pub[] = ED25519_PUB;

// Firmware Buffer
unsigned char data[FLASH_PAGESIZE];


static void reject(void) {
    uart_write(UART0, ERROR);
    SysCtlReset();
}

// bits fall 1->0 bump one word never erase
static uint32_t *min_ver_slot(void) {
    uint32_t *p = (uint32_t *)MIN_VER_BASE;
    while (p < (uint32_t *)METADATA_BASE && *p != 0xFFFFFFFF) {
        p++;
    }
    return p; // first free word
}


int main(void) {

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
        }
    }
}


 /*
 * Load the firmware into flash.
 */
void load_firmware(void) {
    int read, sigok = 0;
    uint8_t hdr[HDR_LEN], tag[16], rec[REC_LEN] __attribute__((aligned(4))); // word aligned
    ChaChaPoly_Aead aead;
    ed25519_key ekey;
    uint32_t page = FW_BASE, idx = 0, got = 0, diff = 0;

    for (uint32_t i = 0; i < HDR_LEN; i++) {
        hdr[i] = uart_read(UART0, BLOCKING, &read);
    }

    uint16_t ver = hdr[0] | (hdr[1] << 8);
    uint16_t size = hdr[2] | (hdr[3] << 8);
    uint16_t msg_len = hdr[4] | (hdr[5] << 8);
    uint32_t total = size + msg_len;

    uint32_t *slot = min_ver_slot();
    uint16_t min_ver = 1; // fresh device floors at 1
    if (slot != (uint32_t *)MIN_VER_BASE) {
        min_ver = (uint16_t)slot[-1];
    }

    // unauth here bounds only tag is the gate
    if (size == 0 || size > MAX_FW_SIZE || msg_len == 0 || msg_len > MAX_MSG_LEN) {
        reject();
    }
    if (ver != 0 && ver < min_ver) { // 0 = debug
        reject();
    }

    wc_ChaCha20Poly1305_Init(&aead, fw_key, hdr + 6, CHACHA20_POLY1305_AEAD_DECRYPT);
    wc_ChaCha20Poly1305_UpdateAad(&aead, hdr, 6); // aad relabel breaks tag

    wc_ed25519_init(&ekey);
    wc_ed25519_import_public(ed_pub, ED25519_PUB_KEY_SIZE, &ekey);
    wc_ed25519_verify_msg_init(hdr + SIG_OFF, ED25519_SIG_SIZE, &ekey, (byte)Ed25519, NULL, 0);
    wc_ed25519_verify_msg_update(hdr, SIG_OFF, &ekey); // signed prefix

    FlashErase(METADATA_BASE); // no bootable image until commit
    uart_write(UART0, OK);

    while (got < total) {
        uint32_t n = (uint32_t)uart_read(UART0, BLOCKING, &read) << 8;
        n |= uart_read(UART0, BLOCKING, &read);

        if (n == 0 || got + n > total || idx + n > FLASH_PAGESIZE) { // page buffer bound
            reject();
        }
        for (uint32_t i = 0; i < n; i++) {
            data[idx + i] = uart_read(UART0, BLOCKING, &read);
        }
        wc_ed25519_verify_msg_update(data + idx, n, &ekey); // sig over ct before decrypt
        wc_ChaCha20Poly1305_UpdateData(&aead, data + idx, data + idx, n); // in place
        idx += n;
        got += n;

        if (idx == FLASH_PAGESIZE || got == total) { // frame size divides page
            if (program_flash((uint8_t *)page, data, idx)) {
                reject();
            }
            page += FLASH_PAGESIZE;
            idx = 0;
        }
        uart_write(UART0, OK);
    }

    wc_ChaCha20Poly1305_Final(&aead, tag);
    wc_ed25519_verify_msg_final(hdr + SIG_OFF, ED25519_SIG_SIZE, &sigok, &ekey);
    for (uint32_t i = 0; i < 16; i++) {
        diff |= tag[i] ^ hdr[18 + i]; // no early out 16 bytes resist one fault
    }
    if (ver != 0 && ver < min_ver) { diff |= 1; } // version verdict
    if (sigok != 1)                { diff |= 2; } // signature verdict
    // second fold separated so each verdict costs two skips
    if (ver != 0 && ver < min_ver) { diff |= 1; }
    if (sigok != 1)                { diff |= 2; }
    uint32_t magic = BOOT_MAGIC ^ diff; // bad verdict makes a magic boot refuses

    // ratchet before record a cut raises floor with nothing installed
    if (diff == 0 && ver > min_ver && slot < (uint32_t *)METADATA_BASE) {
        uint32_t w = ver;
        FlashProgram(&w, (uint32_t)slot, 4); // not program_flash it erases
    }

    memcpy(rec, hdr, 6);
    memcpy(rec + 8, &magic, 4); // pad aligns magic to last word
    program_flash((uint8_t *)METADATA_BASE, rec, REC_LEN); // magic last torn write stays 0xffffffff

    if (diff != 0) { // host only record already decided
        reject();
    }
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
long program_flash(void* page_addr, unsigned char * data, unsigned int data_len) {
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
