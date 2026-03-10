/*
 * AX88772B/C USB Ethernet Patcher for vWii
 *
 * The AX88772C reports USB PID 0x772B (same as 772B).
 * Two register meanings changed between 772A and 772B:
 *   - RX Control bits [9:8]: MFB on 772A, RH2M/RH1M on 772B
 *   - Software Reset bit 7: reserved on 772A, IPOSC on 772B
 *
 * Based on FIX94/dmm's Patched IOS80 Installer for vWii.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gccore.h>
#include <unistd.h>

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

// "/dev/usb/ehc/0b95/772" (21 bytes, char at [21] is the PID suffix)
static const u8 pat_ehc[] = {
	0x2F,0x64,0x65,0x76,0x2F,0x75,0x73,0x62,
	0x2F,0x65,0x68,0x63,0x2F,0x30,0x62,0x39,
	0x35,0x2F,0x37,0x37,0x32
};

// "/dev/usb/oh0/0b95/772"
static const u8 pat_oh0[] = {
	0x2F,0x64,0x65,0x76,0x2F,0x75,0x73,0x62,
	0x2F,0x6F,0x68,0x30,0x2F,0x30,0x62,0x39,
	0x35,0x2F,0x37,0x37,0x32
};

// MOV R3, #0x7700 — the ADD R3, R3, #imm is 16 bytes later
static const u8 pat_mov_pid[] = { 0xE3, 0xA0, 0x3C, 0x77 };

// RX control: CMP R3, #val; MOV R1, #0x18
static const u8 pat_rxctrl_a[] = {
	0xE3, 0x53, 0x09, 0x01,
	0xE3, 0xA0, 0x10, 0x18
};
// patched: MOV R1, #0x118 (set RH1M=1, RH2M stays 0)
static const u8 pat_rxctrl_a_new[] = {
	0xE3, 0x53, 0x09, 0x01,
	0xE3, 0xA0, 0x1F, 0x46
};

// RX control: MOV R1, #0x218; B back
static const u8 pat_rxctrl_b[] = {
	0xE3, 0xA0, 0x1F, 0x86,
	0xEA, 0xFF, 0xFF, 0x8C
};
// patched: MOV R1, #0x118 (set RH1M=1, CLEAR RH2M)
static const u8 pat_rxctrl_b_new[] = {
	0xE3, 0xA0, 0x1F, 0x46,
	0xEA, 0xFF, 0xFF, 0x8C
};

// sw_reset in axInit: LDR R0,[R10]; MOV R1, #0x44
static const u8 pat_swrst_init[] = {
	0xE5, 0x9A, 0x00, 0x00,
	0xE3, 0xA0, 0x10, 0x44
};
// patched: MOV R1, #0xC4 (IPOSC=1 so crystal stays alive during power-down)
static const u8 pat_swrst_init_new[] = {
	0xE5, 0x9A, 0x00, 0x00,
	0xE3, 0xA0, 0x10, 0xC4
};

// sw_reset in axDown: LDR R0,[R4]; MOV R1, #0x4C
static const u8 pat_swrst_down[] = {
	0xE5, 0x94, 0x00, 0x00,
	0xE3, 0xA0, 0x10, 0x4C
};
// patched: MOV R1, #0xCC (IPOSC=1)
static const u8 pat_swrst_down_new[] = {
	0xE5, 0x94, 0x00, 0x00,
	0xE3, 0xA0, 0x10, 0xCC
};

// IOS58 VID:PID table entry for AX88772 (stock)
static const u8 pat_vidpid[] = { 0x0B, 0x95, 0x77, 0x20, 0x00, 0xFF, 0xFF, 0xFF };

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
	s32 idx = find_content_with(ios, pat_ehc, sizeof(pat_ehc));
	if (idx >= 0) return idx;
	return find_content_with(ios, pat_oh0, sizeof(pat_oh0));
}

static s32 patch_byte(u8* buf, u32 size, const u8* base, u32 baselen,
	u32 offset, u8 expect, u8 value, const char* name)
{
	s32 off = find_pattern(buf, size, base, baselen);
	if (off < 0 || (u32)(off + offset + 1) > size)
	{
		printf("  %s: NOT FOUND\n", name);
		return -1;
	}
	u8 c = buf[off + offset];
	if (c == value)
	{
		printf("  %s: already 0x%02X\n", name, value);
		return 1;
	}
	if (c != expect)
	{
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
	if (off >= 0)
	{
		printf("  %s @ 0x%04X\n", name, off);
		memcpy(buf + off, repl, len);
		return 0;
	}
	if (find_pattern(buf, size, repl, len) >= 0)
	{
		printf("  %s: already done\n", name);
		return 1;
	}
	printf("  %s: NOT FOUND\n", name);
	return -1;
}

static s32 patch_ios80_ethernet(IOS* ios)
{
	tmd* t = (tmd*)SIGNATURE_PAYLOAD(ios->tmd);
	tmd_content* cr = TMD_CONTENTS(t);
	u8 hash[20];
	int applied = 0, existing = 0;
	s32 r;

	s32 index = find_eth_module(ios);
	if (index < 0)
	{
		printf("Can't find ethernet module in IOS80\n");
		return -1;
	}
	printf("Ethernet module is content #%d\n", index);

	u8* buf = ios->decrypted_buffer[index];
	u32 size = (u32)cr[index].size;

	// 1: ehc path byte 21 — '0' to 'b'
	r = patch_byte(buf, size, pat_ehc, sizeof(pat_ehc), 21, 0x30, 0x62, "ehc path");
	if (r < 0) return -1;
	if (r == 0) applied++; else existing++;

	// 2: oh0 path byte 21 — '0' to 'b'
	r = patch_byte(buf, size, pat_oh0, sizeof(pat_oh0), 21, 0x30, 0x62, "oh0 path");
	if (r < 0) return -1;
	if (r == 0) applied++; else existing++;

	// 3: ARM PID immediate — ADD R3, R3, #0x20 to #0x2B
	s32 off = find_pattern(buf, size, pat_mov_pid, sizeof(pat_mov_pid));
	if (off < 0 || (u32)(off + 20) > size)
	{
		printf("  PID: MOV R3, #0x7700 not found\n");
		return -1;
	}
	u8* add = buf + off + 16;
	if (add[0] != 0xE2 || add[1] != 0x83 || add[2] != 0x30)
	{
		printf("  PID: unexpected instruction at +16\n");
		return -1;
	}
	if (add[3] == 0x2B)
	{
		printf("  PID imm: already 0x2B\n");
		existing++;
	}
	else if (add[3] == 0x20)
	{
		printf("  PID imm @ 0x%04X: 0x20 -> 0x2B\n", (s32)(add - buf) + 3);
		add[3] = 0x2B;
		applied++;
	}
	else
	{
		printf("  PID imm: unexpected 0x%02X\n", add[3]);
		return -1;
	}

	// 4: RX control path A — MOV R1, #0x18 to #0x118
	r = patch_block(buf, size, pat_rxctrl_a, pat_rxctrl_a_new,
		sizeof(pat_rxctrl_a), "RX ctrl A (#0x18 -> #0x118)");
	if (r < 0) return -1;
	if (r == 0) applied++; else existing++;

	// 5: RX control path B — MOV R1, #0x218 to #0x118
	r = patch_block(buf, size, pat_rxctrl_b, pat_rxctrl_b_new,
		sizeof(pat_rxctrl_b), "RX ctrl B (#0x218 -> #0x118)");
	if (r < 0) return -1;
	if (r == 0) applied++; else existing++;

	// 6: sw_reset axInit — #0x44 to #0xC4
	r = patch_block(buf, size, pat_swrst_init, pat_swrst_init_new,
		sizeof(pat_swrst_init), "sw_reset init (#0x44 -> #0xC4)");
	if (r < 0) return -1;
	if (r == 0) applied++; else existing++;

	// 7: sw_reset axDown — #0x4C to #0xCC
	r = patch_block(buf, size, pat_swrst_down, pat_swrst_down_new,
		sizeof(pat_swrst_down), "sw_reset down (#0x4C -> #0xCC)");
	if (r < 0) return -1;
	if (r == 0) applied++; else existing++;

	if (applied == 0)
	{
		printf("IOS80: all 7 patches already applied\n");
		return 1;
	}

	t->contents[index].type = 1;
	SHA1(buf, size, hash);
	memcpy(cr[index].hash, hash, 20);
	printf("IOS80: %d new + %d existing = 7 on content #%d\n",
		applied, existing, index);
	return 0;
}

static s32 patch_ios58_vidpid(IOS* ios)
{
	tmd* t = (tmd*)SIGNATURE_PAYLOAD(ios->tmd);
	tmd_content* cr = TMD_CONTENTS(t);
	u8 hash[20];

	s32 index = find_content_with(ios, pat_vidpid, sizeof(pat_vidpid));
	if (index < 0)
	{
		// check if already patched
		u8 done[] = { 0x0B, 0x95, 0x77, 0x2B, 0x00, 0xFF, 0xFF, 0xFF };
		index = find_content_with(ios, done, sizeof(done));
		if (index >= 0)
		{
			printf("IOS58: VID:PID already 772B\n");
			return 1;
		}
		printf("Can't find VID:PID in IOS58\n");
		return -1;
	}

	printf("VID:PID stub is content #%d\n", index);
	u8* buf = ios->decrypted_buffer[index];
	u32 size = (u32)cr[index].size;

	s32 off = find_pattern(buf, size, pat_vidpid, sizeof(pat_vidpid));
	if (off < 0)
	{
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
	printf("=== AX88772B/C USB Ethernet Patcher for vWii ===\n\n");
	printf("The AX88772C chip uses PID 0x772B (same as 772B).\n\n");
	printf(" IOS80: PID + RX header mode + IPOSC  (7 patches)\n");
	printf(" IOS58: VID:PID table                  (1 patch)\n\n");
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

	printf("\n--- Step 1/2: IOS80 ---\n");
	ret = do_patch_and_install(IOS80_NR, IOS80_REV, patch_ios80_ethernet);
	if (ret < 0)
		bail("IOS80 failed. Use Aroma to recover.");

	printf("\n--- Step 2/2: IOS58 ---\n");
	ret = do_patch_and_install(IOS58_NR, IOS58_REV, patch_ios58_vidpid);
	if (ret < 0)
		bail("IOS58 failed. IOS80 already patched. Re-run to retry.");

	ISFS_Deinitialize();

	printf("\n\nAll done. Plug in adapter and test from System Settings.\n");
	printf("Press any button to exit.\n");
	waitforbuttonpress(NULL, NULL);

	Reboot();
	return 0;
}