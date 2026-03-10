# vwii-ax88772b-patcher

Patches vWii IOS80 and IOS58 to support ASIX AX88772B/C USB ethernet adapters on the Wii U's vWii mode. The stock vWii driver only supports the original AX88772 (PID `0x7720`).

The AX88772C chip reports PID `0x772B` on the USB bus (same as the 772B), not `0x772C`. This was confirmed via Windows Device Manager hardware IDs.

## What it patches

**IOS80** (ethernet driver, 7 patches):
- `/dev/usb/ehc/0b95/7720` → `772b` (EHCI device path)
- `/dev/usb/oh0/0b95/7720` → `772b` (OHCI device path)
- `ADD R3, R3, #0x20` → `#0x2B` (PID immediate for USB device matching)
- RX control path A: `MOV R1, #0x18` → `#0x118` (set RH1M for type 1 RX headers)
- RX control path B: `MOV R1, #0x218` → `#0x118` (clear RH2M, set RH1M)
- sw_reset in axInit: `MOV R1, #0x44` → `#0xC4` (set IPOSC to keep crystal alive)
- sw_reset in axDown: `MOV R1, #0x4C` → `#0xCC` (set IPOSC)

**IOS58** (VID:PID stub, 1 patch):
- Binary table entry `0B95:7720` → `0B95:772B`

The RX header and IPOSC patches account for register definition changes between the AX88772A and AX88772B silicon. Bits [9:8] of the RX control register changed from MFB (max frame burst) to RH2M/RH1M (header format select), and bit 7 of the software reset register changed from reserved to IPOSC (oscillator keep-alive during power-down).

## Requirements

- Wii U running vWii with **IOS80 v7200** and **IOS58 v6432** (stock)
- Homebrew Channel with AHBPROT
- Priiloader + Aroma installed (brick protection)
- ASIX AX88772B or AX88772C adapter

## Usage

1. Copy `boot.dol` to `sd:/apps/ax88772b_patcher/boot.dol`
2. Add a `meta.xml` with `<ahb_access/>` in the same folder
3. Launch from Homebrew Channel
4. Press A to patch

The patcher detects already-applied patches and is safe to re-run.

## Building

Requires [devkitPPC](https://devkitpro.org/) with libogc and libfat.

## Credits

Based on [Patched IOS80 Installer for vWii](https://gbatemp.net/threads/patched-ios80-installer-for-vwii-allows-sd-menu-custom-channels.344882/) by FIX94, damysteryman, Dr Clipper, Davebaol, ZRicky11.

AX88772B register analysis informed by SDIO's [wafel_ax88772b](https://github.com/StroopwafelCFW/wafel_ax88772b) plugin for native Wii U and the ASIX AX88772B/AX88772A datasheets.
```

## References

- [devkitPPC](https://devkitpro.org/)
- [Patched IOS80 Installer for vWii](https://gbatemp.net/threads/patched-ios80-installer-for-vwii-allows-sd-menu-custom-channels.344882/)
- [wafel_ax88772b](https://github.com/StroopwafelCFW/wafel_ax88772b)