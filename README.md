# WPC Loader — Ghidra ROM Loader for Williams Pinball Controller

A [Ghidra](https://ghidra-sre.org/) extension that loads Williams Pinball Controller (WPC)
game ROMs and builds a complete, navigable memory map — including banked ROM overlays,
ASIC I/O registers, interrupt vectors, and OS-level RAM symbols.

---

## Overview

WPC pinball machines (1990–1999) use a **Motorola 68B09E** CPU running at 2 MHz with a
64 KB address space. Game ROMs come in four sizes: 128 KiB, 256 KiB, 512 KiB, or 1 MiB,
divided into 16 KiB pages that are bank-switched into the CPU window at `0x4000–0x7FFF`
via the `WPC_ROM_BANK` hardware register (`0x3FFC`).

The loader covers all six WPC hardware generations:

| Generation | Years | Key hardware |
|---|---|---|
| WPC Alphanumeric | 1990–1991 | 14-segment displays, separate sound board |
| WPC DMD | 1991–1993 | 128×32 dot-matrix display |
| WPC Fliptronic | 1993–1994 | Dedicated flipper board |
| WPC DCS | 1993–1995 | High-fidelity DCS audio board |
| WPC Security | 1994–1996 | Security PIC chip in switch matrix path |
| WPC-95 | 1995–1999 | FPGA-consolidated boards, extra RAM bank-switching |

---

## Memory Map

The loader creates the following Ghidra memory blocks:

| Block | Address range | Size | Permissions | Volatile | Description |
|---|---|---|---|---|---|
| `RAM` | `0x0000–0x1FFF` | 8 KiB | R/W | No | Battery-backed SRAM |
| `RAM_EXT` | `0x2000–0x2FFF` | 4 KiB | R/W | No | Extra RAM — DCS / WPC-95 *(optional)* |
| `DMD` | `0x3000–0x3BFF` | 3 KiB | R/W | **No** | DMD display SRAM windows — see note |
| `IO` | `0x3C00–0x3FFF` | 1 KiB | R/W | **Yes** | WPC ASIC hardware registers |
| `ROM_PAGE_XX` | `0x4000–0x7FFF` | 16 KiB | R/W/X | No | Banked ROM overlay — see note |
| `ROM_SYSTEM` | `0x8000–0xFFFF` | 32 KiB | R/W/X | No | Fixed system ROM — see note |

### Block notes

**`DMD` — R/W, non-volatile**

The DMD controller board has 8 KiB of SRAM holding up to 16 bit-planes (512 bytes each).
The CPU maps up to two pages at a time into the `0x3000–0x3BFF` window and has full R/W
access to them. Critically, the DMD controller **cannot autonomously write** to these RAM
pages — it only reads from them to refresh the display. This means the block is *not*
volatile from Ghidra's perspective: the CPU is the sole writer, and a value written will
read back unchanged until the CPU changes it again.

**`ROM_PAGE_XX` — R/W/X, non-volatile overlays**

The WPC ASIC does not physically write-protect the ROM window. The CPU can and does write
to `0x4000–0x7FFF`, typically to patch self-modifying trampolines or update code vectors
in-place. However, these writes affect only the currently mapped page in the ASIC's bus
logic — they are **not persisted to the ROM chip**. When a different page is banked in and
the original page is later restored, all writes are gone. Each Ghidra overlay block models
a single bank-in snapshot; cross-bank write effects are not represented.

**`ROM_SYSTEM` — R/W/X**

The system ROM at `0x8000–0xFFFF` mirrors the behaviour of the hardware: the WPC ASIC
does not enforce read-only protection on the fixed ROM window, so the CPU can issue write
cycles to this region. In practice the writes have no lasting effect (the ROM chip ignores
them), but marking the block writable prevents Ghidra from flagging legitimate write
instructions as analysis errors.

### Banked ROM page numbering

WPC hardware page numbers are counted from the **top** of the address space downward.
The last two pages (`0x3E`, `0x3F`) are permanently visible in the system ROM window
(`0x8000–0xFFFF`) and are not overlaid. For a ROM of *N* total 16 KiB pages, banked
page index *b* gets hardware page number `0x3F − (N − 1 − b)`:

| ROM size | Total pages | Banked overlay range |
|---|---|---|
| 128 KiB | 8 | `ROM_PAGE_38` – `ROM_PAGE_3D` (6 pages) |
| 256 KiB | 16 | `ROM_PAGE_30` – `ROM_PAGE_3D` (14 pages) |
| 512 KiB | 32 | `ROM_PAGE_20` – `ROM_PAGE_3D` (30 pages) |
| 1 MiB | 64 | `ROM_PAGE_00` – `ROM_PAGE_3D` (62 pages) |

---

## Labels Applied

### I/O registers (`0x3FB8–0x3FFF`)

All documented WPC ASIC and peripheral registers are labelled, including:

- `WPC_ROM_BANK` — bank-switch register
- `WPC_ZEROCROSS_IRQ_CLEAR` — IRQ source / watchdog kick
- `WPC_LEDS` — diagnostic LED
- `WPC_SOL_*` — solenoid driver outputs
- `WPC_LAMP_*` — lamp matrix row/column
- `WPC_SW_*` / `WPCS_PIC_*` — switch matrix inputs (pre-Security / WPC-S)
- `WPC_DMD_*` — DMD page select and scanline registers
- `WPC_SHIFTADDR` / `WPC_SHIFTBIT` — hardware bit-shifter
- `WPC_RAM_LOCK` / `WPC_RAM_LOCKSIZE` — RAM write-protect
- `WPC_CLK_*` — real-time clock
- `WPCS_DATA` / `WPCS_CONTROL_STATUS` — sound board
- `WPC_FLIPTRONIC_PORT_A` — flipper coil/switch I/O
- `WPC95_FLIPPER_*` — WPC-95 flipper registers
- `WPC_ROM_CHECKSUM` / `WPC_ROM_CHECKSUM_DELTA` — checksum fields

### Interrupt vectors (`0xFFF0–0xFFFE`)

Each 6809 vector slot is typed as a `Pointer16`, labelled (`VEC_RESET`, `VEC_NMI`,
`VEC_SWI`, `VEC_IRQ`, `VEC_FIRQ`, `VEC_SWI2`, `VEC_SWI3`, `VEC_RESERVED`), and a
Ghidra function (`<name>_ISR`) is created at its target address.

The reset vector target is also registered as the program **entry point**.

### RAM symbols (`0x0000–0x03FF`)

Around 50 OS-level symbols from WPC reverse-engineering work, including threading
variables, lamp matrix buffers, solenoid enable shadows, IRQ counters, and DMD ISR state.

---

## Loader Options

Two options appear in Ghidra's import dialog:

| Option | Default | Description |
|---|---|---|
| **Create banked ROM overlays** | ✅ On | Creates one `ROM_PAGE_XX` overlay block per banked page |
| **Create extended RAM block (DCS/WPC-95)** | ✅ On | Creates the 4 KiB `RAM_EXT` block at `0x2000` |

Disable the overlays for a quick analysis pass on the fixed ROM only.

---

## ROM Validity

The loader accepts files whose size is exactly one of the four valid WPC ROM sizes
(128 KiB, 256 KiB, 512 KiB, 1 MiB). After loading, the message log reports the ROM
version number (decoded from the low byte of the checksum word at `0xFFEE`) and
whether the checksum is disabled (`delta = 0x00FF`, development mode).

---

## Requirements

| Requirement | Version |
|---|---|
| [Ghidra](https://ghidra-sre.org/) | **12.0.4** |
| Java | 21 (bundled with Ghidra) |

---

## Building

Use gradle that is bundled with Ghidra

**1. Set your Ghidra installation path**
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.4_PUBLIC
```

**2. Compile:**

```bash
/path/to/ghidra_12.0.4_PUBLIC/support/gradle/gradlew
# → dist/ghidra_12.0.4_PUBLIC_<date>_WPCLoader.zip
```

**3. Install in Ghidra:**

In Ghidra's project manager: *File → Install Extensions* → select the zip from `dist/`.
Restart Ghidra when prompted.

---

## Usage

1. Open Ghidra and create or open a project.
2. Drag a WPC ROM file (`.bin`, `.rom`, or any extension) onto the project window,
   or use *File → Import File*.
3. Ghidra will auto-detect the WPC format via the file size check and propose
   **WPC ROM Loader** with `6809:BE:16:default` (Motorola 6809, big-endian).
4. Adjust the import options (overlays, extended RAM) as needed, then click **OK**.
5. Open the imported program in the CodeBrowser and run **Auto Analyze** to disassemble
   the system ROM. Each banked overlay can be analysed separately.

---
