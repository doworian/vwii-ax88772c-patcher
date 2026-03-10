/*
 * AX88772B/C USB Ethernet Patcher for vWii
 * by doworian - March 2026
 *
 * The vWii ethernet driver in IOS80 only supports the AX88772 (PID 0x7720).
 * The newer AX88772B/C chips report PID 0x772B and have two register changes:
 * - RX Control [11:9]: MFB (burst) bits became RH3M/RH2M/RH1M (header mode)
 * - Software Reset [7]: reserved bit became IPOSC (oscillator keep-alive)
 *
 * IOS80 has its own ETH module (0000000b.app, ARM32) with 9 patches.
 * IOS58 has a separate ETH module (0000003c.app, Thumb) that needs its own
 * set of patches, plus the USB stack VID:PID table shared between both.
 *
 * Based on FIX94/dmm's Patched IOS80 Installer for vWii.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ogcsys.h>
#include <gccore.h>
#include <wiiuse/wpad.h>
#include <network.h>

#include "IOSPatcher.h"
#include "identify.h"
#include "sha1.h"
#include "tools.h"
#include "memory/mem2.hpp"

extern s32 get_IOS(IOS** ios, u32 iosnr, u32 revision);
extern void encrypt_IOS(IOS* ios);
extern void forge_tmd(signed_blob* s_tmd);
extern s32 install_IOS(IOS* ios, bool skipticket);

#define IOS80_NR 80
#define IOS80_REV 7200
#define IOS58_NR 58
#define IOS58_REV 6432

/* -- IOS80 patch patterns (ARM32, 0000000b.app) --------------------------- */

/*
 * Patches 1-2: USB device path strings containing the PID.
 * "/dev/usb/ehc/0b95/772" and "/dev/usb/oh0/0b95/772"
 * Byte 21 (the char after "772") is '0' on stock - we change it to 'b'.
 */
static const u8 pat_ehc[] = {
    0x2F,0x64,0x65,0x76,0x2F,0x75,0x73,0x62,
    0x2F,0x65,0x68,0x63,0x2F,0x30,0x62,0x39,
    0x35,0x2F,0x37,0x37,0x32
};
static const u8 pat_oh0[] = {
    0x2F,0x64,0x65,0x76,0x2F,0x75,0x73,0x62,
    0x2F,0x6F,0x68,0x30,0x2F,0x30,0x62,0x39,
    0x35,0x2F,0x37,0x37,0x32
};

/*
 * Patch 3: PID constructed in a register via MOV R3,#0x7700
 * then ADD R3,R3,#0x20. We find the MOV and change the ADD's
 * immediate 16 bytes later from 0x20 to 0x2B.
 */
static const u8 pat_mov_pid[] = { 0xE3, 0xA0, 0x3C, 0x77 };

/*
 * Patches 4-6: RX control register values for each buffer size.
 * 772B repurposed bits [10:9] as RH2M/RH1M (header mode select).
 * Stock values 0x018/0x218/0x318 all become 0x118 (RH1M=1, RH2M=0)
 * so the RX parser gets type-1 headers with no IP alignment padding.
 */
static const u8 pat_rxctrl_a[] = { 0xE3,0x53,0x09,0x01, 0xE3,0xA0,0x10,0x18 };
static const u8 pat_rxctrl_a_new[] = { 0xE3,0x53,0x09,0x01, 0xE3,0xA0,0x1F,0x46 };

static const u8 pat_rxctrl_b[] = { 0xE3,0xA0,0x1F,0x86, 0xEA,0xFF,0xFF,0x8C };
static const u8 pat_rxctrl_b_new[] = { 0xE3,0xA0,0x1F,0x46, 0xEA,0xFF,0xFF,0x8C };

static const u8 pat_rxctrl_c[] = { 0xE3,0xA0,0x1F,0xC6 };
static const u8 pat_rxctrl_c_new[] = { 0xE3,0xA0,0x1F,0x46 };

/*
 * Patches 7-8: Software reset register - set IPOSC=1 (bit 7).
 * Keeps the 25MHz crystal alive during PHY power-down so we don't hit
 * the 772B's 600ms cold-start penalty (772A was only 160ms).
 */
static const u8 pat_swrst_init[] = { 0xE5,0x9A,0x00,0x00, 0xE3,0xA0,0x10,0x44 };
static const u8 pat_swrst_init_new[] = { 0xE5,0x9A,0x00,0x00, 0xE3,0xA0,0x10,0xC4 };

static const u8 pat_swrst_down[] = { 0xE5,0x94,0x00,0x00, 0xE3,0xA0,0x10,0x4C };
static const u8 pat_swrst_down_new[] = { 0xE5,0x94,0x00,0x00, 0xE3,0xA0,0x10,0xCC };

/*
 * Patch 9: VID:PID device scanner in IOS80.
 * Stock code builds 0x0B957720 via MOV R12,#0x0B900000 + ADD +0x57000 + ADD +0x720.
 * 0x0B95772B can't be split into 3 ARM rotated immediates, so we replace
 * the whole 12-byte sequence with LDR R12,[PC,#0] / B skip / .word 0x0B95772B.
 */
static const u8 pat_vidpid[] = { 0xE3,0xA0,0xC6,0xB9, 0xE2,0x8C,0xCA,0x57, 0xE2,0x8C,0xCE,0x72 };
static const u8 pat_vidpid_new[] = { 0xE5,0x9F,0xC0,0x00, 0xEA,0x00,0x00,0x00, 0x0B,0x95,0x77,0x2B };

/* -- IOS58 patch patterns ------------------------------------------------- */

/*
 * Patch 10: VID:PID bytes shared between the USB stack device table and
 * the ETH driver's literal pool constant.
 *
 * The 8-byte sequence 0B957720 00FFFFFF appears in TWO separate IOS58
 * content modules:
 *   - The USB stack: this is a device table entry (VID:PID + mask)
 *   - The ETH driver (0000003c.app): the 0x0B957720 LDR constant at
 *     0x13AA1AB8 followed by the 0x00FFFFFF AND mask at 0x13AA1ABC
 *
 * Both must be patched or the device-to-driver handoff breaks. The old
 * code used find_content_with() which only returned the first hit.
 */
static const u8 pat_ios58_vidpid[] = { 0x0B,0x95,0x77,0x20, 0x00,0xFF,0xFF,0xFF };

/*
 * Patches 11-12: RX control register values in IOS58 ETH driver (Thumb).
 *
 * IOS58's ETH module is Thumb, not ARM32. The immediate loads use
 * MOVS Rd,#imm8 + LSLS Rd,Rd,#2 to construct values > 255:
 *   0xC6 << 2 = 0x318  (16K EHC path)
 *   0x86 << 2 = 0x218  (8K path)
 *   0x46 << 2 = 0x118  (4K path - already correct)
 *
 * Same deal as IOS80: bits [10:9] changed meaning on 772B. The 0x318
 * EHC path sets RH2M=1 which inserts 2 bytes of alignment padding the
 * parser doesn't expect. Force everything to 0x118.
 *
 * Big-endian Thumb halfwords: MOVS R1,#0xC6 = 21 C6, LSLS R1,R1,#2 = 00 89
 */
static const u8 pat_ios58_rxc_318[] = { 0x21,0xC6, 0x00,0x89 };
static const u8 pat_ios58_rxc_218[] = { 0x21,0x86, 0x00,0x89 };
static const u8 pat_ios58_rxc_118[] = { 0x21,0x46, 0x00,0x89 };

/*
 * Patch 13: Software Reset IPOSC in IOS58 axDown.
 *
 * sub_13AA18CC writes SW Reset register with 0x4C (IPRL+PRI+PRL).
 * Same issue as IOS80: without IPOSC the 772B oscillator dies during
 * PHY power-down and needs 600ms to cold-start on resume.
 *
 * Thumb: MOVS R1,#0x4C = bytes 21 4C  ->  MOVS R1,#0xCC = bytes 21 CC
 *
 * We need context to avoid false hits. In the IOS58 axDown function,
 * the 0x4C write is immediately preceded by the BL return from the
 * RX control register write (sub_13AA0E9C). The sequence is:
 *   BL sub_13AA0F1C   (sw_reset write, 4 bytes)
 * We use the fact that right before MOVS R1,#0x4C there is always
 * the axDown-specific BIC+STRH+LDRH+LDR sequence. But the safest
 * unique anchor is actually "21 4C" preceded by the write-RX-ctrl
 * return check pattern. For robustness we'll search for 21 4C within
 * the content that also has the RX ctrl patterns (i.e. the ETH module)
 * and verify only one match exists.
 */
static const u8 pat_ios58_swrst[] = { 0x21,0x4C };
static const u8 pat_ios58_swrst_new[] = { 0x21,0xCC };

/* -- Pattern search helpers ----------------------------------------------- */

static s32 find_pattern(const u8* buf, u32 size, const u8* pat, u32 len)
{
    if (size < len) return -1;
    for (u32 i = 0; i <= size - len; i++)
        if (memcmp(buf + i, pat, len) == 0)
            return (s32)i;
    return -1;
}

static s32 find_content_with(IOS* ios, const u8* pat, u32 len)
{
    tmd* t = (tmd*)SIGNATURE_PAYLOAD(ios->tmd);
    tmd_content* cr = TMD_CONTENTS(t);
    for (int i = 0; i < ios->content_count; i++) {
        if (!ios->decrypted_buffer[i]) continue;
        if (find_pattern(ios->decrypted_buffer[i], (u32)cr[i].size, pat, len) >= 0)
            return i;
    }
    return -1;
}

static s32 find_eth_module(IOS* ios)
{
    s32 idx = find_content_with(ios, pat_ehc, sizeof(pat_ehc));
    return (idx >= 0) ? idx : find_content_with(ios, pat_oh0, sizeof(pat_oh0));
}

static s32 patch_byte(u8* buf, u32 size, const u8* base, u32 baselen,
    u32 offset, u8 expect, u8 value, const char* name)
{
    s32 off = find_pattern(buf, size, base, baselen);
    if (off < 0 || (u32)(off + offset + 1) > size) {
        printf("  %s: NOT FOUND\n", name);
        return -1;
    }
    u8 c = buf[off + offset];
    if (c == value) {
        printf("  %s: already 0x%02X\n", name, value);
        return 1;
    }
    if (c != expect) {
        printf("  %s: unexpected 0x%02X\n", name, c);
        return -1;
    }
    printf("  %s @ 0x%04X: 0x%02X -> 0x%02X\n", name, off + offset, c, value);
    buf[off + offset] = value;
    return 0;
}

static s32 patch_block(u8* buf, u32 size, const u8* old, const u8* repl,
    u32 len, const char* name)
{
    s32 off = find_pattern(buf, size, old, len);
    if (off >= 0) {
        printf("  %s @ 0x%04X\n", name, off);
        memcpy(buf + off, repl, len);
        return 0;
    }
    if (find_pattern(buf, size, repl, len) >= 0) {
        printf("  %s: already done\n", name);
        return 1;
    }
    printf("  %s: NOT FOUND\n", name);
    return -1;
}

/*
 * Count occurrences of a pattern in a buffer. Used to make sure
 * we're not blindly patching something that shows up in the wrong spot.
 */
static int count_pattern(const u8* buf, u32 size, const u8* pat, u32 len)
{
    int n = 0;
    if (size < len) return 0;
    for (u32 i = 0; i <= size - len; i++)
        if (memcmp(buf + i, pat, len) == 0)
            n++;
    return n;
}

/* -- IOS80: apply all 9 ethernet patches --------------------------------- */

static s32 patch_ios80_ethernet(IOS* ios)
{
    tmd* t = (tmd*)SIGNATURE_PAYLOAD(ios->tmd);
    tmd_content* cr = TMD_CONTENTS(t);
    u8 hash[20];
    int applied = 0, existing = 0;
    s32 r;

    s32 index = find_eth_module(ios);
    if (index < 0) {
        printf("Can't find ethernet module in IOS80\n");
        return -1;
    }
    printf("Ethernet module is content #%d\n", index);

    u8* buf = ios->decrypted_buffer[index];
    u32 size = (u32)cr[index].size;

    /* 1: ehc path PID char '0' -> 'b' */
    r = patch_byte(buf, size, pat_ehc, sizeof(pat_ehc), 21, 0x30, 0x62, "ehc path");
    if (r < 0) return -1;
    if (r == 0) applied++; else existing++;

    /* 2: oh0 path PID char '0' -> 'b' */
    r = patch_byte(buf, size, pat_oh0, sizeof(pat_oh0), 21, 0x30, 0x62, "oh0 path");
    if (r < 0) return -1;
    if (r == 0) applied++; else existing++;

    /* 3: ADD R3,R3,#0x20 -> #0x2B (PID low byte in register) */
    {
        s32 off = find_pattern(buf, size, pat_mov_pid, sizeof(pat_mov_pid));
        if (off < 0 || (u32)(off + 20) > size) {
            printf("  PID imm: pattern not found\n");
            return -1;
        }
        u8* add = buf + off + 16;
        if (add[0] != 0xE2 || add[1] != 0x83 || add[2] != 0x30) {
            printf("  PID imm: unexpected ADD at +16\n");
            return -1;
        }
        if (add[3] == 0x2B) {
            printf("  PID imm: already 0x2B\n");
            existing++;
        }
        else if (add[3] == 0x20) {
            printf("  PID imm @ 0x%04X: 0x20 -> 0x2B\n", (s32)(add - buf) + 3);
            add[3] = 0x2B;
            applied++;
        }
        else {
            printf("  PID imm: unexpected 0x%02X\n", add[3]);
            return -1;
        }
    }

    /* 4: RX ctrl A - MOV R1,#0x018 -> #0x118 */
    r = patch_block(buf, size, pat_rxctrl_a, pat_rxctrl_a_new,
        sizeof(pat_rxctrl_a), "RX ctrl A");
    if (r < 0) return -1;
    if (r == 0) applied++; else existing++;

    /* 5: RX ctrl B - MOV R1,#0x218 -> #0x118 */
    r = patch_block(buf, size, pat_rxctrl_b, pat_rxctrl_b_new,
        sizeof(pat_rxctrl_b), "RX ctrl B");
    if (r < 0) return -1;
    if (r == 0) applied++; else existing++;

    /* 6: RX ctrl C - MOV R1,#0x318 -> #0x118 (EHC/USB2 path) */
    r = patch_block(buf, size, pat_rxctrl_c, pat_rxctrl_c_new,
        sizeof(pat_rxctrl_c), "RX ctrl C");
    if (r < 0) return -1;
    if (r == 0) applied++; else existing++;

    /* 7: sw_reset in axInit - 0x44 -> 0xC4 (IPOSC=1) */
    r = patch_block(buf, size, pat_swrst_init, pat_swrst_init_new,
        sizeof(pat_swrst_init), "sw_reset init");
    if (r < 0) return -1;
    if (r == 0) applied++; else existing++;

    /* 8: sw_reset in axDown - 0x4C -> 0xCC (IPOSC=1) */
    r = patch_block(buf, size, pat_swrst_down, pat_swrst_down_new,
        sizeof(pat_swrst_down), "sw_reset down");
    if (r < 0) return -1;
    if (r == 0) applied++; else existing++;

    /* 9: VID:PID scanner - MOV+ADD+ADD -> LDR from inline literal pool */
    r = patch_block(buf, size, pat_vidpid, pat_vidpid_new,
        sizeof(pat_vidpid), "VID:PID scanner");
    if (r < 0) return -1;
    if (r == 0) applied++; else existing++;

    if (applied == 0) {
        printf("IOS80: all 9 patches already applied\n");
        return 1;
    }

    t->contents[index].type = 1;
    SHA1(buf, size, hash);
    memcpy(cr[index].hash, hash, 20);
    printf("IOS80: %d new + %d existing = 9 on content #%d\n", applied, existing, index);
    return 0;
}

/* -- IOS58: patch everything ---------------------------------------------- */

/*
 * IOS58's ethernet support spans two content modules:
 *
 *   1) USB stack - has a VID:PID device recognition table so the USB
 *      subsystem knows to route our adapter to the ETH driver at all.
 *
 *   2) ETH driver (0000003c.app, Thumb code) - the actual AX88772 driver.
 *      Has its OWN hardcoded VID:PID constant in the device scanner
 *      (sub_13AA19B0), plus the same RX control and SW reset register
 *      issues as IOS80's ARM32 driver.
 *
 * The 8-byte pattern 0B957720 00FFFFFF appears in BOTH contents because
 * in the ETH driver, the 0x0B957720 literal pool entry at 0x13AA1AB8 is
 * immediately followed by the 0x00FFFFFF AND mask at 0x13AA1ABC. The old
 * patcher only hit whichever content came first in the TMD content list
 * and left the other one with the stock 0x7720.
 *
 * We also need the register-level patches on the ETH driver content:
 * RX control header mode (same root cause as IOS80 patches 4-6) and
 * SW reset IPOSC (same root cause as IOS80 patches 7-8).
 *
 * IOS58 uses /dev/usb/ven (vendor interface) instead of device-specific
 * paths, so there are no path string patches. And the VID:PID is a single
 * data pool constant, not a MOV+ADD+ADD sequence, so patch 9's equivalent
 * is just the byte change covered by the VID:PID sweep.
 */
static s32 patch_ios58_ethernet(IOS* ios)
{
    tmd* t = (tmd*)SIGNATURE_PAYLOAD(ios->tmd);
    tmd_content* cr = TMD_CONTENTS(t);
    u8 hash[20];
    int vidpid_hits = 0;
    s32 r;

    /*
     * Pass 1: sweep ALL contents for VID:PID.
     *
     * Every content that has 0B957720 00FFFFFF gets byte [3] changed
     * from 0x20 to 0x2B. We track which contents we touched so we can
     * update their hashes and mark them non-shared.
     */
    printf("Scanning IOS58 contents for VID:PID...\n");

    for (int i = 0; i < ios->content_count; i++) {
        if (!ios->decrypted_buffer[i]) continue;
        u8* buf = ios->decrypted_buffer[i];
        u32 sz = (u32)cr[i].size;

        s32 off = find_pattern(buf, sz, pat_ios58_vidpid, sizeof(pat_ios58_vidpid));
        if (off >= 0) {
            printf("  content #%d: VID:PID @ 0x%04X -> 0x772B\n", i, off + 2);
            buf[off + 3] = 0x2B;
            t->contents[i].type = 1;
            SHA1(buf, sz, hash);
            memcpy(cr[i].hash, hash, 20);
            vidpid_hits++;
            continue;
        }

        /* already patched? */
        u8 done[] = { 0x0B,0x95,0x77,0x2B, 0x00,0xFF,0xFF,0xFF };
        if (find_pattern(buf, sz, done, sizeof(done)) >= 0) {
            printf("  content #%d: VID:PID already 0x772B\n", i);
            vidpid_hits++;
        }
    }

    if (vidpid_hits == 0) {
        printf("IOS58: no VID:PID found in any content\n");
        return -1;
    }
    printf("IOS58: VID:PID patched/verified in %d content(s)\n", vidpid_hits);

    /*
     * Pass 2: find the ETH driver content and apply register patches.
     *
     * The ETH driver is the content that contains the RX ctrl Thumb
     * patterns. The USB stack module doesn't have MOVS+LSLS sequences
     * for AX88772 register values, so the RX ctrl pattern is a safe
     * way to identify the right content.
     */
    s32 eth = find_content_with(ios, pat_ios58_rxc_318, sizeof(pat_ios58_rxc_318));

    if (eth < 0) {
        /* maybe already patched - look for the replacement value */
        if (find_content_with(ios, pat_ios58_rxc_118, sizeof(pat_ios58_rxc_118)) >= 0) {
            printf("IOS58: ETH register patches already applied\n");
            return (vidpid_hits > 0) ? 0 : -1;
        }
        printf("IOS58: can't find ETH driver content\n");
        return -1;
    }

    printf("ETH driver is content #%d\n", eth);

    u8* buf = ios->decrypted_buffer[eth];
    u32 size = (u32)cr[eth].size;
    int applied = 0, existing = 0;

    /* 11: RX ctrl 0x4000 (EHC): 0x318 -> 0x118 */
    r = patch_block(buf, size, pat_ios58_rxc_318, pat_ios58_rxc_118,
        sizeof(pat_ios58_rxc_318), "RX ctrl 4000");
    if (r < 0) return -1;
    if (r == 0) applied++; else existing++;

    /* 12: RX ctrl 0x2000: 0x218 -> 0x118 */
    r = patch_block(buf, size, pat_ios58_rxc_218, pat_ios58_rxc_118,
        sizeof(pat_ios58_rxc_218), "RX ctrl 2000");
    if (r < 0) return -1;
    if (r == 0) applied++; else existing++;

    /*
     * 13: SW reset IPOSC in axDown: 0x4C -> 0xCC
     *
     * The 2-byte pattern 21 4C (MOVS R1,#0x4C) is short enough that
     * we need to be careful about false hits. Count how many times it
     * appears in this content - in the stock 0000003c.app it should
     * appear exactly once, in sub_13AA18CC (axDown).
     */
    {
        int n = count_pattern(buf, size, pat_ios58_swrst, sizeof(pat_ios58_swrst));
        int n_done = count_pattern(buf, size, pat_ios58_swrst_new, sizeof(pat_ios58_swrst_new));

        if (n == 1 && n_done == 0) {
            r = patch_block(buf, size, pat_ios58_swrst, pat_ios58_swrst_new,
                sizeof(pat_ios58_swrst), "sw_reset down");
            if (r < 0) return -1;
            if (r == 0) applied++; else existing++;
        }
        else if (n == 0 && n_done == 1) {
            printf("  sw_reset down: already done\n");
            existing++;
        }
        else if (n > 1) {
            /*
             * Multiple hits for 21 4C - can't blindly patch.
             * Fall back to patching nothing and warn. This shouldn't
             * happen on stock IOS58 v6432 but guard against it anyway.
             */
            printf("  sw_reset down: %d matches for 0x4C, skipping (ambiguous)\n", n);
        }
        else {
            printf("  sw_reset down: NOT FOUND\n");
            return -1;
        }
    }

    if (applied > 0) {
        t->contents[eth].type = 1;
        SHA1(buf, size, hash);
        memcpy(cr[eth].hash, hash, 20);
    }

    printf("IOS58 ETH: %d new + %d existing patches on content #%d\n",
        applied, existing, eth);
    return (applied > 0 || vidpid_hits > 0) ? 0 : 1;
}

/* -- Generic: read, patch, fakesign, encrypt, install --------------------- */

static s32 do_patch_and_install(u32 iosnr, u32 rev, s32(*patcher)(IOS*))
{
    s32 ret;
    IOS* ios = NULL;

    printf("\nReading IOS%u v%u...\n", iosnr, rev);
    ret = get_IOS(&ios, iosnr, rev);
    if (ret < 0) {
        printf("Failed to read IOS%u (ret %d)\n", iosnr, ret);
        return ret;
    }

    ret = patcher(ios);
    if (ret == 1) {
        printf("Nothing to do.\n");
        free_IOS(&ios);
        return 0;
    }
    if (ret < 0) {
        free_IOS(&ios);
        return ret;
    }

    printf("Fakesigning TMD...\n");
    forge_tmd(ios->tmd);

    printf("Encrypting...\n");
    encrypt_IOS(ios);

    printf("Installing IOS%u", iosnr);
    ret = install_IOS(ios, false);
    free_IOS(&ios);

    if (ret < 0) {
        printf("\nInstall failed (ret %d)\n", ret);
        if (ret == -1017 || ret == -2011)
            printf("Hash check still active - launch from HBC.\n");
        return ret;
    }
    printf("Done.\n");
    return 0;
}

/* -- Video ---------------------------------------------------------------- */

static void InitVideo(void)
{
    VIDEO_Init();
    GXRModeObj* rmode = VIDEO_GetPreferredMode(NULL);
    void* xfb = MEM_K0_TO_K1(SYS_AllocateFramebuffer(rmode));
    VIDEO_Configure(rmode);
    VIDEO_SetNextFramebuffer(xfb);
    VIDEO_SetBlack(FALSE);
    VIDEO_Flush();
    VIDEO_WaitVSync();
    if (rmode->viTVMode & VI_NON_INTERLACE) VIDEO_WaitVSync();
    CON_InitEx(rmode, 24, 32, rmode->fbWidth - 32, rmode->xfbHeight - 48);
    VIDEO_ClearFrameBuffer(rmode, xfb, COLOR_BLACK);
}

static void bail(const char* msg)
{
    printf("\n%s\n", msg);
    printf("Press any button to exit...\n");
    waitforbuttonpress(NULL, NULL);
    ISFS_Deinitialize();
    Reboot();
}

extern void __exception_setreload(int t);
extern s32 IOS_ReloadIOS(int version);

/* -- Entry point ---------------------------------------------------------- */

int main(int argc, char* argv[])
{
    __exception_setreload(10);
    s32 ret;

    InitVideo();
    MEM_init();
    printheadline();

    printf("\n\n");
    printf("=== AX88772B/C USB Ethernet Patcher for vWii ===\n\n");
    printf("Adapter PID 0x772B -> stock driver expects 0x7720.\n");
    printf("IOS80: 9 patches (ARM32 ETH driver)\n");
    printf("IOS58: VID:PID + ETH register patches (Thumb driver)\n\n");
    printf("Requires stock IOS80 v7200 and IOS58 v6432.\n");
    printf("Make sure you have Priiloader + Aroma as safety net.\n\n");

    Patch_AHB();
    ret = (__IOS_LoadStartupIOS() == 0 && *(vu32*)0xCD800064 == 0xFFFFFFFF);

    printf("Patching running IOS...\n");
    PatchIOS(true);
    usleep(1000);

    printf("Init NAND...\n");
    ISFS_Initialize();

    PAD_Init();
    WPAD_Init();
    WPAD_SetDataFormat(WPAD_CHAN_0, WPAD_FMT_BTNS_ACC_IR);

    if (!ret)
        bail("AHBPROT not available. Launch from HBC with <ahb_access/>.");

    s32 v80 = checkIOS(IOS80_NR);
    s32 v58 = checkIOS(IOS58_NR);
    printf("IOS80: v%d %s\n", v80, (v80 == IOS80_REV) ? "[ok]" : "[wrong]");
    printf("IOS58: v%d %s\n", v58, (v58 == IOS58_REV) ? "[ok]" : "[wrong]");

    if (v80 != IOS80_REV) bail("IOS80 is not v7200.");
    if (v58 != IOS58_REV) bail("IOS58 is not v6432.");

    printf("\nPress A to patch, anything else to exit.\n");
    u32 pressed = 0, pressedGC = 0;
    waitforbuttonpress(&pressed, &pressedGC);
    if (pressed != WPAD_BUTTON_A && pressedGC != PAD_BUTTON_A) {
        printf("Cancelled.\n");
        ISFS_Deinitialize();
        Reboot();
    }

    printf("\n--- Step 1/2: IOS80 (9 patches) ---\n");
    ret = do_patch_and_install(IOS80_NR, IOS80_REV, patch_ios80_ethernet);
    if (ret < 0)
        bail("IOS80 failed. Use Aroma to recover.");

    printf("\n--- Step 2/2: IOS58 (VID:PID + ETH patches) ---\n");
    ret = do_patch_and_install(IOS58_NR, IOS58_REV, patch_ios58_ethernet);
    if (ret < 0)
        bail("IOS58 failed. IOS80 already patched. Re-run to retry.");

    ISFS_Deinitialize();

    printf("\n\nAll done.\n");
    printf("Press B to test network, any other button to exit.\n");

    pressed = pressedGC = 0;
    waitforbuttonpress(&pressed, &pressedGC);
    if (pressed != WPAD_BUTTON_B && pressedGC != PAD_BUTTON_B) {
        Reboot();
        return 0;
    }

    printf("\nReloading IOS58 to activate patches...\n");
    WPAD_Shutdown();
    IOS_ReloadIOS(IOS58_NR);

    PAD_Init();
    WPAD_Init();
    WPAD_SetDataFormat(WPAD_CHAN_0, WPAD_FMT_BTNS_ACC_IR);

    printf("Waiting for controller...");
    int wait;
    for (wait = 0; wait < 40; wait++) {
        WPAD_ScanPads();
        u32 type = 0;
        if (WPAD_Probe(0, &type) == WPAD_ERR_NONE)
            break;
        PAD_ScanPads();
        if (PAD_ButtonsHeld(0))
            break;
        usleep(100000);
        if (wait % 5 == 0) printf(".");
    }
    printf("\n");

    for (;;) {
        printf("\nInitializing network");
        s32 net = -1;
        int tries = 0;
        while (tries < 50) {
            net = net_init();
            if (net == 0 || (net != -11))
                break;
            if (tries % 5 == 0) printf(".");
            usleep(100000);
            tries++;
        }

        if (net < 0) {
            printf("\nnet_init failed: %d\n", net);
            printf("Make sure the adapter is plugged in.\n");
        }
        else {
            u32 ip = net_gethostip();
            if (ip == 0) {
                printf("\nNo IP address assigned (DHCP timeout?)\n");
            }
            else {
                printf("\nLocal: %u.%u.%u.%u\n",
                    (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                    (ip >> 8) & 0xFF, ip & 0xFF);

                /* grab WAN IP from icanhazip.com - plain text, no parsing */
                printf("WAN:   ");
                s32 sock = net_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
                if (sock >= 0) {
                    struct hostent* he = net_gethostbyname("api.ipify.org");
                    if (he && he->h_length > 0) {
                        struct sockaddr_in sa;
                        memset(&sa, 0, sizeof(sa));
                        sa.sin_family = AF_INET;
                        sa.sin_port = htons(80);
                        memcpy(&sa.sin_addr, he->h_addr_list[0], he->h_length);

                        if (net_connect(sock, (struct sockaddr*)&sa, sizeof(sa)) >= 0) {
                            const char* req =
                                "GET / HTTP/1.0\r\n"
                                "Host: api.ipify.org\r\n"
                                "Connection: close\r\n\r\n";
                            net_send(sock, req, strlen(req), 0);

                            char resp[512];
                            int total = 0, n, idle = 0;
                            while (total < (int)sizeof(resp) - 1 && idle < 250) {
                                n = net_recv(sock, resp + total, sizeof(resp) - 1 - total, 0);
                                if (n > 0) {
                                    total += n;
                                    idle = 0;
                                }
                                else if (n == 0) {
                                    break;
                                }
                                else {
                                    usleep(20000);
                                    idle++;
                                }
                            }
                            resp[total] = '\0';

                            /* find body after header/body separator */
                            char* body = strstr(resp, "\r\n\r\n");
                            if (body) {
                                body += 4;
                            }
                            else {
                                body = strstr(resp, "\n\n");
                                if (body) body += 2;
                            }
                            if (body) {
                                /* trim trailing junk */
                                char* end = body;
                                while (*end && *end != '\r' && *end != '\n' && *end != ' ') end++;
                                *end = '\0';
                                if (*body)
                                    printf("%s\n", body);
                                else
                                    printf("(empty body)\n");
                            }
                            else {
                                printf("(bad response)\n");
                            }
                        }
                        else {
                            printf("(connect failed)\n");
                        }
                    }
                    else {
                        printf("(DNS failed)\n");
                    }
                    net_close(sock);
                }
                else {
                    printf("(socket failed)\n");
                }
            }
            net_deinit();
        }

        printf("\nPress B to retry, any other button to exit.\n");
        pressed = pressedGC = 0;
        waitforbuttonpress(&pressed, &pressedGC);
        if (pressed != WPAD_BUTTON_B && pressedGC != PAD_BUTTON_B)
            break;
    }

    Reboot();
    return 0;
}