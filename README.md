# vwii-ax88772c-patcher

Patches vWii IOS80 and IOS58 to recognize ASIX AX88772C USB ethernet adapters (PID `0x772C`). The stock vWii driver only supports the original AX88772 (PID `0x7720`).

**Status: Work in progress.** PID whitelisting is done but the adapter still isn't connecting — likely needs an rx control register init change for the 772C silicon. See [this GBAtemp thread](https://gbatemp.net/threads/we-can-now-use-the-ax88772b-on-the-wii-u.670646/) for context.

## What it patches

**IOS80** (ethernet driver, content #12):
- `/dev/usb/ehc/0b95/7720` → `772c` (EHCI device path)
- `/dev/usb/oh0/0b95/7720` → `772c` (OHCI device path)
- `ADD R3, R3, #0x20` → `ADD R3, R3, #0x2C` (PID immediate used for USB device registration)

**IOS58** (VID:PID stub, content #17):
- Binary table entry `0B95:7720` → `0B95:772C`

All patches are single-byte changes. The patcher handles partial patch state (safe to re-run).

## Requirements

- Wii U running vWii with **IOS80 v7200** and **IOS58 v6432** (stock)
- Homebrew Channel with AHBPROT
- Priiloader + Aroma installed (brick protection)
- ASIX AX88772C adapter

## Usage

1. Copy `boot.dol` to `sd:/apps/ax88772c_patcher/boot.dol`
2. Add a `meta.xml` with `<ahb_access/>` in the same folder
3. Launch from Homebrew Channel
4. Press A to patch

## Building

Requires [devkitPPC](https://devkitpro.org/) with libogc and libfat.

## Credits

Based on [Patched IOS80 Installer for vWii](https://gbatemp.net/threads/patched-ios80-installer-for-vwii-allows-sd-menu-custom-channels.344882/) by FIX94, damysteryman, Dr Clipper, Davebaol, ZRicky11.