/*
 * AX88772C USB Ethernet Patcher for vWii
 *
 * Patches IOS80 + IOS58 to recognize AX88772C (PID 0x772C)
 * and fixes RX Control Register init for AX88772B/C compatibility.
 *
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

#define IOS80_NR 80
#define IOS80_REV 7200
#define IOS58_NR 58
#define IOS58_REV 6432

/* ---- PID path patterns ---- */

static const u8 pat_ehc[] = {
    0x2F,0x64,0x65,0x76,0x2F,0x75,0x73,0x62,
    0x2F,0x65,0x68,0x63,0x2F,0x30,0x62,0x39,
    0x35,0x2F,0x37,0x37,0x32,0x30
};

static const u8 pat_oh0[] = {
    0x2F,0x64,0x65,0x76,0x2F,0x75,0x73,0x62,
    0x2F,0x6F,0x68,0x30,0x2F,0x30,0x62,0x39,
    0x35,0x2F,0x37,0x37,0x32,0x30
};

static const u8 pat_ehc_done[] = {
    0x2F,0x64,0x65,0x76,0x2F,0x75,0x73,0x62,
    0x2F,0x65,0x68,0x63,0x2F,0x30,0x62,0x39,
    0x35,0x2F,0x37,0x37,0x32,0x63
};

static const u8 pat_oh0_done[] = {
    0x2F,0x64,0x65,0x76,0x2F,0x75,0x73,0x62,
    0x2F,0x6F,0x68,0x30,0x2F,0x30,0x62,0x39,
    0x35,0x2F,0x37,0x37,0x32,0x63
};

/* ---- ARM PID immediate patterns ---- */

static const u8 pat_mov_pid[] = { 0xE3, 0xA0, 0x3C, 0x77 };
static const u8 pat_add_orig[] = { 0xE2, 0x83, 0x30, 0x20 };
static const u8 pat_add_new[] = { 0xE2, 0x83, 0x30, 0x2C };

/* ---- RX Control Register patterns ---- */

// axInit MFB=0x800 path: CMP R3,#0x4000 followed by MOV R1,#0x18
static const u8 pat_rxctrl_mfb800[] = {
    0xE3, 0x53, 0x09, 0x01,
    0xE3, 0xA0, 0x10, 0x18
};
static const u8 pat_rxctrl_mfb800_new[] = {
    0xE3, 0x53, 0x09, 0x01,
    0xE3, 0xA0, 0x1F, 0x46
};
static const u8 pat_rxctrl_mfb800_done[] = {
    0xE3, 0x53, 0x09, 0x01,
    0xE3, 0xA0, 0x1F, 0x46
};

// axInit MFB=0x2000 path: MOV R1,#0x218 followed by B (backward)
static const u8 pat_rxctrl_mfb2k[] = {
    0xE3, 0xA0, 0x1F, 0x86,
    0xEA, 0xFF, 0xFF, 0x8C
};
static const u8 pat_rxctrl_mfb2k_new[] = {
    0xE3, 0xA0, 0x1F, 0xC6,
    0xEA, 0xFF, 0xFF, 0x8C
};
static const u8 pat_rxctrl_mfb2k_done[] = {
    0xE3, 0xA0, 0x1F, 0xC6,
    0xEA, 0xFF, 0xFF, 0x8C
};

/* ---- IOS58 VID:PID table ---- */

static const u8 pat_vidpid[] = {
    0x0B,0x95,0x77,0x20,0x00,0xFF,0xFF,0xFF
};
static const u8 pat_vidpid_done[] = {
    0x0B,0x95,0x77,0x2C,0x00,0xFF,0xFF,0xFF
};

/* ---- helpers ---- */

static s32 find_pattern(const u8* buf, u32 size, const u8* pat, u32 len)
{
    if (size < len) return -1;
    u32 i;
    for (i = 0; i <= size - len; i++)
        if (memcmp(buf + i, pat, len) == 0)
            return (s32)i;
    return -1;
}

static s32 find_content_with(IOS* ios, const u8* pat, u32 len)
{
    tmd* t = (tmd*)SIGNATURE_PAYLOAD(ios->tmd);
    tmd_content* cr = TMD_CONTENTS(t);
    int i;
    for (i = 0; i < ios->content_count; i++)
    {
        if (!ios->decrypted_buffer[i]) continue;
        if (find_pattern(ios->decrypted_buffer[i], (u32)cr[i].size, pat, len) >= 0)
            return i;
    }
    return -1;
}

static s32 find_eth_module(IOS* ios)
{
    s32 idx;
    const u8* search_pats[] = { pat_ehc, pat_ehc_done, pat_oh0, pat_oh0_done };
    u32 search_lens[] = { sizeof(pat_ehc), sizeof(pat_ehc_done), sizeof(pat_oh0), sizeof(pat_oh0_done) };
    int i;
    for (i = 0; i < 4; i++)
    {
        idx = find_content_with(ios, search_pats[i], search_lens[i]);
        if (idx >= 0) return idx;
    }
    return -1;
}

/*
 * Patch IOS80 ethernet module — 5 sites:
 *   1) ehc device path  '7720' -> '772c'
 *   2) oh0 device path  '7720' -> '772c'
 *   3) ARM PID immediate  ADD #0x20 -> ADD #0x2C
 *   4) RX ctrl MFB=0x800  MOV R1,#0x18 -> MOV R1,#0x118  (set RH1M)
 *   5) RX ctrl MFB=0x2000 MOV R1,#0x218 -> MOV R1,#0x318  (set RH1M)
 */
static s32 patch_ios80_ethernet(IOS* ios)
{
    tmd* t = (tmd*)SIGNATURE_PAYLOAD(ios->tmd);
    tmd_content* cr = TMD_CONTENTS(t);
    s32 index, off;
    u8 hash[20];
    int applied = 0, existing = 0, total = 5;

    index = find_eth_module(ios);
    if (index < 0)
    {
        printf("Can't find ethernet module in IOS80\n");
        return -1;
    }

    printf("Ethernet module is content #%d\n", index);
    u8* buf = ios->decrypted_buffer[index];
    u32 size = (u32)cr[index].size;

    /* --- site 1: ehc path --- */
    off = find_pattern(buf, size, pat_ehc, sizeof(pat_ehc));
    if (off >= 0)
    {
        printf("  ehc path @ 0x%04X: '0' -> 'c'\n", off + 21);
        buf[off + 21] = 0x63;
        applied++;
    }
    else if (find_pattern(buf, size, pat_ehc_done, sizeof(pat_ehc_done)) >= 0)
    {
        printf("  ehc path: already done\n");
        existing++;
    }
    else
    {
        printf("  ehc path: NOT FOUND\n");
        return -1;
    }

    /* --- site 2: oh0 path --- */
    off = find_pattern(buf, size, pat_oh0, sizeof(pat_oh0));
    if (off >= 0)
    {
        printf("  oh0 path @ 0x%04X: '0' -> 'c'\n", off + 21);
        buf[off + 21] = 0x63;
        applied++;
    }
    else if (find_pattern(buf, size, pat_oh0_done, sizeof(pat_oh0_done)) >= 0)
    {
        printf("  oh0 path: already done\n");
        existing++;
    }
    else
    {
        printf("  oh0 path: NOT FOUND\n");
        return -1;
    }

    /* --- site 3: ARM PID immediate --- */
    off = find_pattern(buf, size, pat_mov_pid, sizeof(pat_mov_pid));
    if (off >= 0 && (u32)(off + 16 + 4) <= size)
    {
        u8* add = buf + off + 16;
        if (memcmp(add, pat_add_orig, 4) == 0)
        {
            printf("  PID imm @ 0x%04X: #0x20 -> #0x2C\n", off + 16 + 3);
            add[3] = 0x2C;
            applied++;
        }
        else if (memcmp(add, pat_add_new, 4) == 0)
        {
            printf("  PID imm: already done\n");
            existing++;
        }
        else
        {
            printf("  PID imm: unexpected bytes %02X %02X %02X %02X\n",
                add[0], add[1], add[2], add[3]);
            return -1;
        }
    }
    else
    {
        printf("  MOV R3, #0x7700 not found\n");
        return -1;
    }

    /* --- site 4: RX control MFB=0x800 (0x18 -> 0x118, sets RH1M) --- */
    off = find_pattern(buf, size, pat_rxctrl_mfb800, sizeof(pat_rxctrl_mfb800));
    if (off >= 0)
    {
        printf("  RX ctrl MFB800 @ 0x%04X: #0x18 -> #0x118\n", off + 4);
        memcpy(buf + off, pat_rxctrl_mfb800_new, sizeof(pat_rxctrl_mfb800_new));
        applied++;
    }
    else if (find_pattern(buf, size, pat_rxctrl_mfb800_done, sizeof(pat_rxctrl_mfb800_done)) >= 0)
    {
        printf("  RX ctrl MFB800: already done\n");
        existing++;
    }
    else
    {
        printf("  RX ctrl MFB800: NOT FOUND\n");
        return -1;
    }

    /* --- site 5: RX control MFB=0x2000 (0x218 -> 0x318, sets RH1M) --- */
    off = find_pattern(buf, size, pat_rxctrl_mfb2k, sizeof(pat_rxctrl_mfb2k));
    if (off >= 0)
    {
        printf("  RX ctrl MFB2K @ 0x%04X: #0x218 -> #0x318\n", off);
        memcpy(buf + off, pat_rxctrl_mfb2k_new, sizeof(pat_rxctrl_mfb2k_new));
        applied++;
    }
    else if (find_pattern(buf, size, pat_rxctrl_mfb2k_done, sizeof(pat_rxctrl_mfb2k_done)) >= 0)
    {
        printf("  RX ctrl MFB2K: already done\n");
        existing++;
    }
    else
    {
        printf("  RX ctrl MFB2K: NOT FOUND\n");
        return -1;
    }

    if (applied == 0)
    {
        printf("IOS80: all %d patches already applied\n", total);
        return 1;
    }

    t->contents[index].type = 1;
    SHA1(buf, size, hash);
    memcpy(cr[index].hash, hash, 20);

    printf("IOS80: %d new + %d existing = %d total on content #%d\n",
        applied, existing, total, index);
    return 0;
}

static s32 patch_ios58_vidpid(IOS* ios)
{
    tmd* t = (tmd*)SIGNATURE_PAYLOAD(ios->tmd);
    tmd_content* cr = TMD_CONTENTS(t);
    s32 index, off;
    u8 hash[20];

    index = find_content_with(ios, pat_vidpid, sizeof(pat_vidpid));
    if (index < 0)
    {
        index = find_content_with(ios, pat_vidpid_done, sizeof(pat_vidpid_done));
        if (index >= 0)
        {
            printf("IOS58: VID:PID already patched\n");
            return 1;
        }
        printf("Can't find VID:PID stub in IOS58\n");
        return -1;
    }

    printf("VID:PID stub is content #%d\n", index);
    u8* buf = ios->decrypted_buffer[index];
    u32 size = (u32)cr[index].size;

    off = find_pattern(buf, size, pat_vidpid, sizeof(pat_vidpid));
    if (off < 0)
    {
        printf("VID:PID pattern lost?\n");
        return -1;
    }

    printf("  VID:PID @ 0x%04X: 0x20 -> 0x2C\n", off + 3);
    buf[off + 3] = 0x2C;

    t->contents[index].type = 1;
    SHA1(buf, size, hash);
    memcpy(cr[index].hash, hash, 20);

    printf("IOS58: patched content #%d\n", index);
    return 0;
}

static s32 do_patch_and_install(u32 iosnr, u32 rev, s32(*patcher)(IOS*))
{
    s32 ret;
    IOS* ios = NULL;

    printf("\nReading IOS%u v%u...\n", iosnr, rev);
    ret = get_IOS(&ios, iosnr, rev);
    if (ret < 0)
    {
        printf("Failed to read IOS%u (ret %d)\n", iosnr, ret);
        return ret;
    }

    ret = patcher(ios);
    if (ret == 1)
    {
        printf("Nothing to do.\n");
        free_IOS(&ios);
        return 0;
    }
    if (ret < 0)
    {
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

    if (ret < 0)
    {
        printf("\nInstall failed (ret %d)\n", ret);
        if (ret == -1017 || ret == -2011)
            printf("Hash check still active on running IOS.\n");
        return ret;
    }

    printf("Done.\n");
    return 0;
}

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

int main(int argc, char* argv[])
{
    __exception_setreload(10);
    s32 ret;

    InitVideo();
    MEM_init();
    printheadline();

    printf("\n\n");
    printf("=== AX88772C USB Ethernet Patcher for vWii ===\n\n");
    printf("Patches IOS80 + IOS58 to recognize AX88772C (PID 772C)\n");
    printf("and fixes RX header format for AX88772B/C chips.\n\n");
    printf(" IOS80: ehc/oh0 paths, ARM PID, RX ctrl init (5 patches)\n");
    printf(" IOS58: VID:PID table entry (1 patch)\n\n");
    printf("Requires IOS80 v7200 and IOS58 v6432 (stock vWii).\n");
    printf("Make sure you have Priiloader + Aroma as brick protection.\n\n");

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
        bail("AHBPROT not available. Launch from HBC.");

    s32 v80 = checkIOS(IOS80_NR);
    s32 v58 = checkIOS(IOS58_NR);
    printf("IOS80: v%d %s\n", v80, (v80 == IOS80_REV) ? "[ok]" : "[wrong]");
    printf("IOS58: v%d %s\n", v58, (v58 == IOS58_REV) ? "[ok]" : "[wrong]");

    if (v80 != IOS80_REV) bail("IOS80 is not v7200.");
    if (v58 != IOS58_REV) bail("IOS58 is not v6432.");

    printf("\nPress A to patch, anything else to exit.\n");
    u32 pressed = 0, pressedGC = 0;
    waitforbuttonpress(&pressed, &pressedGC);
    if (pressed != WPAD_BUTTON_A && pressedGC != PAD_BUTTON_A)
    {
        printf("Cancelled.\n");
        ISFS_Deinitialize();
        Reboot();
    }

    printf("\n--- Step 1/2: IOS80 (ethernet driver + RX ctrl fix) ---\n");
    ret = do_patch_and_install(IOS80_NR, IOS80_REV, patch_ios80_ethernet);
    if (ret < 0)
        bail("IOS80 failed. IOS58 untouched. Use Aroma to recover.");

    printf("\n--- Step 2/2: IOS58 (VID:PID stub) ---\n");
    ret = do_patch_and_install(IOS58_NR, IOS58_REV, patch_ios58_vidpid);
    if (ret < 0)
        bail("IOS58 failed. IOS80 already patched. Re-run to retry.");

    ISFS_Deinitialize();

    printf("\n\nAll done. Plug in the adapter and test from System Settings.\n");
    printf("Press any button to exit.\n");
    waitforbuttonpress(NULL, NULL);

    Reboot();
    return 0;
}