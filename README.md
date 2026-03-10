# vwii-ax88772b-patcher

Patches vWii IOS80 and IOS58 to support ASIX AX88772B/C USB ethernet adapters. The stock driver only handles the original AX88772 (PID `0x7720`) - the 772B/C reports `0x772B`.

The AX88772C chip reports PID `0x772B` on the USB bus (same as the 772B), not `0x772C`. Confirmed via Windows Device Manager hardware IDs. (Verify on your own PC to be sure)

## What it patches

**IOS80 - ARM32 ETH driver, 0000000b.app (9 patches):**

| # | Patch | Description |
|---|-------|-------------|
| 1 | ehc device path `7720` → `772b` | EHCI USB insertion registration string |
| 2 | oh0 device path `7720` → `772b` | OHCI USB insertion registration string |
| 3 | `ADD R3, R3, #0x20` → `#0x2B` | PID immediate in register construction |
| 4 | RX ctrl A: `MOV R1, #0x018` → `#0x118` | Header mode for 2048-byte buffer path |
| 5 | RX ctrl B: `MOV R1, #0x218` → `#0x118` | Header mode for 8192-byte buffer path |
| 6 | RX ctrl C: `MOV R1, #0x318` → `#0x118` | Header mode for 16384-byte buffer path (EHC) |
| 7 | sw_reset axInit: `#0x44` → `#0xC4` | Set IPOSC - keep crystal alive during PHY power-down |
| 8 | sw_reset axDown: `#0x4C` → `#0xCC` | Set IPOSC |
| 9 | VID:PID scanner: `MOV+ADD+ADD` → `LDR` literal | Device list matching - see below |

**IOS58 - Thumb ETH driver, 0000003c.app + USB stack (4 patches):**

| # | Patch | Description |
|---|-------|-------------|
| 10 | VID:PID `0B95:7720` → `0B95:772B` | All content modules containing the VID:PID pattern |
| 11 | RX ctrl 0x4000: `MOVS R1, #0xC6` → `#0x46` | Header mode for EHCI buffer path (`0x318` → `0x118`) |
| 12 | RX ctrl 0x2000: `MOVS R1, #0x86` → `#0x46` | Header mode for OHCI buffer path (`0x218` → `0x118`) |
| 13 | sw_reset axDown: `MOVS R1, #0x4C` → `#0xCC` | Set IPOSC |

### Why these patches exist

**Patches 1–3, 9–10:** PID recognition. The PID value `0x7720` is encoded multiple ways across both IOS modules - ASCII in path strings, an ARM `ADD` immediate, a 3-instruction `MOV+ADD+ADD` sequence using rotated 8-bit immediates, Thumb literal pool constants, and USB stack device table entries. Each needed a different fix.

**Patch 9** deserves special mention. The device scanner builds `0x0B957720` across three ARM instructions (`MOV R12, #0x0B900000` / `ADD #0x57000` / `ADD #0x720`). The value `0x0B95772B` can't be decomposed into 3 rotated 8-bit immediates because `0x72B` spans 10 bits. We replace the 12-byte sequence with an inline literal pool load (`LDR R12, [PC, #0]` / `B skip` / `.word 0x0B95772B`) - same size, same register, same flow. IDA hides this behind a pseudo-instruction, so the real encoding is only visible in hex view.

**Patches 4–6, 11–12:** RX control register bits `[10:9]` changed from MFB (max frame burst) on 772A to RH2M/RH1M (header format select) on 772B. The EHC path writes `0x318`, which sets `RH2M=1` and inserts 2 bytes of IP alignment padding after the RX header. The parser reads at `header+4` but the frame starts at `header+6`. Every packet is misaligned. We force `0x118` - type 1 headers, no padding. IOS58's Thumb driver has the same issue with different instruction encoding (`MOVS` + `LSLS` instead of ARM `MOV`).

**Patches 7–8, 13:** Bit 7 of the software reset register changed from reserved (772A) to IPOSC (772B). Without `IPOSC=1`, the oscillator dies during PHY power-down and needs 600ms to cold-start (vs 160ms on 772A). The driver has no delay in `axUp` to wait for this.

## Network test

After patching, press B to test the connection. The patcher reloads IOS58 to activate the patches, initializes the ethernet stack, and displays your local IPv4 address and WAN IP.

## Requirements

- Wii U running vWii with **IOS80 v7200** and **IOS58 v6432** (stock)
- Homebrew Channel with `<ahb_access/>`
- Priiloader + Aroma installed (brick protection)
- ASIX AX88772B or AX88772C USB ethernet adapter

## Usage

1. Copy `ax88772b_patcher.zip` files to `sd:/apps/ax88772b_patcher/`
2. Launch from Homebrew Channel
3. Press A to patch
4. Press B to test network (optional)

Safe to re-run - detects already-applied patches.

## Building

Requires [devkitPPC](https://devkitpro.org/) with libogc and libfat.

## Credits

Based on [Patched IOS80 Installer for vWii](https://gbatemp.net/threads/patched-ios80-installer-for-vwii-allows-sd-menu-custom-channels.344882/) by FIX94, damysteryman, Dr Clipper, Davebaol, ZRicky11.

772B register analysis informed by SDIO's [wafel_ax88772b](https://github.com/StroopwafelCFW/wafel_ax88772b) plugin for native Wii U and the ASIX AX88772B/AX88772A datasheets.
