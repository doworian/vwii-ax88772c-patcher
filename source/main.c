/*
 * AX88772B/C USB Ethernet Patcher for vWii
 * by doworian — March 2026
 *
 * The vWii ethernet driver in IOS80 only supports the AX88772 (PID 0x7720).
 * The newer AX88772B/C chips report PID 0x772B and have two register changes:
 *   - RX Control [11:9]: MFB (burst) bits became RH3M/RH2M/RH1M (header mode)
 *   - Software Reset [7]: reserved bit became IPOSC (oscillator keep-alive)
 *
 * 9 patches to IOS80's ethernet module, 1 patch to IOS58's VID:PID table.
 * Based on FIX94/dmm's Patched IOS80 Installer for vWii.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gccore.h>
#include <wiiuse/wpad.h>

#include "IOSPatcher.h"
#include "identify.h"
#include "sha1.h"
#include "tools.h"
#include "memory/mem2.hpp"

extern s32 get_IOS(IOS** ios, u32 iosnr, u32 revision);
extern void encrypt_IOS(IOS* ios);
extern void forge_tmd(signed_blob* s_tmd);
extern s32 install_IOS(IOS* ios, bool skipticket);

#define IOS80_NR   80
#define IOS80_REV  7200
#define IOS58_NR   58
#define IOS58_REV  6432

/* ── IOS80 patch patterns ────────────────────────────────────────────── */

// Patches 1-2: USB device path strings containing the PID
// "/dev/usb/ehc/0b95/772" and "/dev/usb/oh0/0b95/772"
// Byte 21 (the char after "772") is '0' on stock — we change it to 'b'.
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

// Patch 3: PID constructed in a register via MOV R3,#0x7700 then ADD R3,R3,#0x20.
// We find the MOV and change the ADD's immediate 16 bytes later from 0x20 to 0x2B.
static const u8 pat_mov_pid[] = { 0xE3, 0xA0, 0x3C, 0x77 };

// Patches 4-6: RX control register values for each buffer size.
// 772B repurposed bits [10:9] as RH2M/RH1M (header mode select).
// Stock values 0x018/0x218/0x318 all need to become 0x118 (RH1M=1, RH2M=0)
// so the RX parser gets type-1 headers with no IP alignment padding.
static const u8 pat_rxctrl_a[] = { 0xE3,0x53,0x09,0x01, 0xE3,0xA0,0x10,0x18 };
static const u8 pat_rxctrl_a_new[] = { 0xE3,0x53,0x09,0x01, 0xE3,0xA0,0x1F,0x46 };

static const u8 pat_rxctrl_b[] = { 0xE3,0xA0,0x1F,0x86, 0xEA,0xFF,0xFF,0x8C };
static const u8 pat_rxctrl_b_new[] = { 0xE3,0xA0,0x1F,0x46, 0xEA,0xFF,0xFF,0x8C };

static const u8 pat_rxctrl_c[] = { 0xE3,0xA0,0x1F,0xC6 };
static const u8 pat_rxctrl_c_new[] = { 0xE3,0xA0,0x1F,0x46 };

// Patches 7-8: Software reset register — set IPOSC=1 (bit 7).
// Keeps the 25MHz crystal alive during PHY power-down so we don't hit
// the 772B's 600ms cold-start penalty (772A was only 160ms).
static const u8 pat_swrst_init[] = { 0xE5,0x9A,0x00,0x00, 0xE3,0xA0,0x10,0x44 };
static const u8 pat_swrst_init_new[] = { 0xE5,0x9A,0x00,0x00, 0xE3,0xA0,0x10,0xC4 };

static const u8 pat_swrst_down[] = { 0xE5,0x94,0x00,0x00, 0xE3,0xA0,0x10,0x4C };
static const u8 pat_swrst_down_new[] = { 0xE5,0x94,0x00,0x00, 0xE3,0xA0,0x10,0xCC };

// Patch 9: VID:PID device scanner.
// Stock code builds 0x0B957720 via MOV R12,#0x0B900000 + ADD +0x57000 + ADD +0x720.
// 0x0B95772B can't be split into 3 ARM rotated immediates, so we replace
// the whole 12-byte sequence with LDR R12,[PC,#0] / B skip / .word 0x0B95772B.
static const u8 pat_vidpid[] = { 0xE3,0xA0,0xC6,0xB9, 0xE2,0x8C,0xCA,0x57, 0xE2,0x8C,0xCE,0x72 };
static const u8 pat_vidpid_new[] = { 0xE5,0x9F,0xC0,0x00, 0xEA,0x00,0x00,0x00, 0x0B,0x95,0x77,0x2B };

/* ── IOS58 patch pattern ─────────────────────────────────────────────── */

// Patch 10: VID:PID recognition table entry. Change 0x7720 -> 0x772B.
static const u8 pat_ios58_vidpid[] = { 0x0B,0x95,0x77,0x20, 0x00,0xFF,0xFF,0xFF };

/* ── Pattern search helpers ──────────────────────────────────────────── */

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

// Patch a single byte at (pattern_match + offset)
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

// Replace a whole block in-place
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

/* ── IOS80: apply all 9 ethernet patches ─────────────────────────────── */

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

    // 1: ehc path PID char '0' -> 'b'
    r = patch_byte(buf, size, pat_ehc, sizeof(pat_ehc), 21, 0x30, 0x62, "ehc path");
    if (r < 0) return -1;
    if (r == 0) applied++; else existing++;

    // 2: oh0 path PID char '0' -> 'b'
    r = patch_byte(buf, size, pat_oh0, sizeof(pat_oh0), 21, 0x30, 0x62, "oh0 path");
    if (r < 0) return -1;
    if (r == 0) applied++; else existing++;

    // 3: ADD R3,R3,#0x20 -> #0x2B (PID low byte in register)
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

    // 4: RX ctrl A — MOV R1,#0x018 -> #0x118
    r = patch_block(buf, size, pat_rxctrl_a, pat_rxctrl_a_new,
        sizeof(pat_rxctrl_a), "RX ctrl A");
    if (r < 0) return -1;
    if (r == 0) applied++; else existing++;

    // 5: RX ctrl B — MOV R1,#0x218 -> #0x118
    r = patch_block(buf, size, pat_rxctrl_b, pat_rxctrl_b_new,
        sizeof(pat_rxctrl_b), "RX ctrl B");
    if (r < 0) return -1;
    if (r == 0) applied++; else existing++;

    // 6: RX ctrl C — MOV R1,#0x318 -> #0x118 (the EHC/USB2 path)
    r = patch_block(buf, size, pat_rxctrl_c, pat_rxctrl_c_new,
        sizeof(pat_rxctrl_c), "RX ctrl C");
    if (r < 0) return -1;
    if (r == 0) applied++; else existing++;

    // 7: sw_reset in axInit — 0x44 -> 0xC4 (IPOSC=1)
    r = patch_block(buf, size, pat_swrst_init, pat_swrst_init_new,
        sizeof(pat_swrst_init), "sw_reset init");
    if (r < 0) return -1;
    if (r == 0) applied++; else existing++;

    // 8: sw_reset in axDown — 0x4C -> 0xCC (IPOSC=1)
    r = patch_block(buf, size, pat_swrst_down, pat_swrst_down_new,
        sizeof(pat_swrst_down), "sw_reset down");
    if (r < 0) return -1;
    if (r == 0) applied++; else existing++;

    // 9: VID:PID scanner — MOV+ADD+ADD -> LDR from inline literal pool
    r = patch_block(buf, size, pat_vidpid, pat_vidpid_new,
        sizeof(pat_vidpid), "VID:PID scanner");
    if (r < 0) return -1;
    if (r == 0) applied++; else existing++;

    if (applied == 0) {
        printf("IOS80: all 9 patches already applied\n");
        return 1;
    }

    // Mark content as non-shared and update hash
    t->contents[index].type = 1;
    SHA1(buf, size, hash);
    memcpy(cr[index].hash, hash, 20);
    printf("IOS80: %d new + %d existing = 9 on content #%d\n", applied, existing, index);
    return 0;
}

/* ── IOS58: patch VID:PID table ──────────────────────────────────────── */

static s32 patch_ios58_vidpid_table(IOS* ios)
{
    tmd* t = (tmd*)SIGNATURE_PAYLOAD(ios->tmd);
    tmd_content* cr = TMD_CONTENTS(t);
    u8 hash[20];

    s32 index = find_content_with(ios, pat_ios58_vidpid, sizeof(pat_ios58_vidpid));
    if (index < 0) {
        u8 done[] = { 0x0B, 0x95, 0x77, 0x2B, 0x00, 0xFF, 0xFF, 0xFF };
        if (find_content_with(ios, done, sizeof(done)) >= 0) {
            printf("IOS58: VID:PID already 0x772B\n");
            return 1;
        }
        printf("Can't find VID:PID table in IOS58\n");
        return -1;
    }

    printf("VID:PID table is content #%d\n", index);
    u8* buf = ios->decrypted_buffer[index];
    u32 size = (u32)cr[index].size;

    s32 off = find_pattern(buf, size, pat_ios58_vidpid, sizeof(pat_ios58_vidpid));
    if (off < 0) {
        printf("  VID:PID pattern lost\n");
        return -1;
    }

    printf("  VID:PID @ 0x%04X: 0x7720 -> 0x772B\n", off + 2);
    buf[off + 3] = 0x2B;

    t->contents[index].type = 1;
    SHA1(buf, size, hash);
    memcpy(cr[index].hash, hash, 20);
    printf("IOS58: patched content #%d\n", index);
    return 0;
}

/* ── Generic: read, patch, fakesign, encrypt, install ────────────────── */

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
            printf("Hash check still active — launch from HBC.\n");
        return ret;
    }
    printf("Done.\n");
    return 0;
}

/* ── Video ───────────────────────────────────────────────────────────── */

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

/* ── Entry point ─────────────────────────────────────────────────────── */

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
    printf("IOS80: 9 patches | IOS58: 1 patch\n\n");
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

    printf("\n--- Step 2/2: IOS58 (1 patch) ---\n");
    ret = do_patch_and_install(IOS58_NR, IOS58_REV, patch_ios58_vidpid_table);
    if (ret < 0)
        bail("IOS58 failed. IOS80 already patched. Re-run to retry.");

    ISFS_Deinitialize();

    printf("\n\nAll done. Plug in adapter and test from System Settings.\n");
    printf("Press any button to exit.\n");
    waitforbuttonpress(NULL, NULL);

    Reboot();
    return 0;
}