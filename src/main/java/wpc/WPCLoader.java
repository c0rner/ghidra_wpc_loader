/* ###
 * IP: GHIDRA
 * Copyright 2026 Martin Akesson
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package wpcloader;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.data.Pointer16DataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.Memory;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for Williams Pinball Controller (WPC) game ROMs.
 *
 * <p>WPC machines use a Motorola 68B09E CPU at 2 MHz with a 64 KB address space.
 * ROMs come in four sizes: 128 KiB, 256 KiB, 512 KiB, or 1 MiB, divided into
 * 16 KiB pages. The last 32 KiB of the ROM is always mapped at 0x8000–0xFFFF
 * (the "fixed" system ROM). Up to 62 additional 16 KiB pages are bank-switched
 * into the window at 0x4000–0x7FFF via the WPC_ROM_BANK register (0x3FFC).
 *
 * <p>Each banked page is created as a Ghidra overlay block at 0x4000–0x7FFF,
 * named ROM_PAGE_XX where XX is the WPC page number in hex (00–3D).
 */
public class WPCLoader extends AbstractLibrarySupportLoader {

	// ── Valid ROM sizes ───────────────────────────────────────────────────────

	private static final long ROM_SIZE_128K = 0x0002_0000L;
	private static final long ROM_SIZE_256K = 0x0004_0000L;
	private static final long ROM_SIZE_512K = 0x0008_0000L;
	private static final long ROM_SIZE_1M   = 0x0010_0000L;

	private static final long[] VALID_SIZES = {
		ROM_SIZE_128K, ROM_SIZE_256K, ROM_SIZE_512K, ROM_SIZE_1M
	};

	// ── ROM layout constants ──────────────────────────────────────────────────

	private static final int BANK_SIZE        = 0x4000; // 16 KiB per banked page

	// ── CPU address map ───────────────────────────────────────────────────────

	private static final long RAM_START          = 0x0000L;
	private static final long RAM_SIZE           = 0x2000L; // 8 KiB base RAM
	private static final long RAM_EXT_START      = 0x2000L;
	private static final long RAM_EXT_SIZE       = 0x1000L; // 4 KiB (DCS and later)
	private static final long DMD_START          = 0x3000L;
	private static final long DMD_SIZE           = 0x0C00L; // 3 KiB DMD window
	private static final long IO_START           = 0x3C00L;
	private static final long IO_SIZE            = 0x0400L; // 1 KiB I/O window
	private static final long BANKED_ROM_START   = 0x4000L;
	private static final long BANKED_ROM_SIZE    = 0x4000L; // 16 KiB bank window
	private static final long SYSTEM_ROM_START   = 0x8000L;
	private static final long SYSTEM_ROM_SIZE    = 0x8000L; // 32 KiB fixed system ROM

	// ── Checksum / version fields in the system ROM ────────────────────────────

	private static final long ADDR_CHECKSUM_DELTA = 0xFFECL;
	private static final long ADDR_CHECKSUM       = 0xFFEEL;

	// ── 6809 interrupt vector table (0xFFF0–0xFFFE) ───────────────────────────

	/** Each entry: { cpu_address, label_name } */
	private static final Object[][] VECTORS = {
		{ 0xFFF0L, "VEC_RESERVED"  },
		{ 0xFFF2L, "VEC_SWI3"      },
		{ 0xFFF4L, "VEC_SWI2"      },
		{ 0xFFF6L, "VEC_FIRQ"      },
		{ 0xFFF8L, "VEC_IRQ"       },
		{ 0xFFFAL, "VEC_SWI"       },
		{ 0xFFFCL, "VEC_NMI"       },
		{ 0xFFFEL, "VEC_RESET"     },
	};

	// ── I/O register definitions ──────────────────────────────────────────────

	/**
	 * WPC ASIC and peripheral I/O registers.
	 * Each entry: { cpu_address, register_name }
	 * Addresses cover the range 0x3000–0x3FFF (the IO block).
	 */
	private static final Object[][] IO_REGISTERS = {
		// WPC-95 DMD extra page registers (0x3FB8–0x3FBB)
		{ 0x3FB8L, "WPC_DMD_3200_PAGE"              },
		{ 0x3FB9L, "WPC_DMD_3000_PAGE"              },
		{ 0x3FBAL, "WPC_DMD_3600_PAGE"              },
		{ 0x3FBBL, "WPC_DMD_3400_PAGE"              },
		// DMD display control registers (0x3FBC–0x3FBF)
		{ 0x3FBCL, "WPC_DMD_HIGH_PAGE"              },
		{ 0x3FBDL, "WPC_DMD_SCANLINE"               },
		{ 0x3FBEL, "WPC_DMD_LOW_PAGE"               },
		{ 0x3FBFL, "WPC_DMD_ACTIVE_PAGE"            },
		// External I/O: parallel & serial (0x3FC0–0x3FC6)
		{ 0x3FC0L, "WPC_PARALLEL_STATUS_PORT"       },
		{ 0x3FC1L, "WPC_PARALLEL_DATA_PORT"         },
		{ 0x3FC2L, "WPC_PARALLEL_STROBE_PORT"       },
		{ 0x3FC3L, "WPC_SERIAL_DATA_OUTPUT"         },
		{ 0x3FC4L, "WPC_SERIAL_CONTROL_OUTPUT"      },
		{ 0x3FC5L, "WPC_SERIAL_BAUD_SELECT"         },
		{ 0x3FC6L, "WPC_TICKET_DISPENSE"            },
		// Fliptronic board (0x3FD4–0x3FD5) – not present on WPC-95
		{ 0x3FD4L, "WPC_FLIPTRONIC_PORT_A"          },
		{ 0x3FD5L, "WPC_FLIPTRONIC_PORT_B"          },
		// DCS / WPC sound board (0x3FDC–0x3FDD)
		{ 0x3FDCL, "WPCS_DATA"                      },
		{ 0x3FDDL, "WPCS_CONTROL_STATUS"            },
		// WPC ASIC I/O control: solenoids (0x3FE0–0x3FE3)
		{ 0x3FE0L, "WPC_SOL_GEN_OUTPUT"             },
		{ 0x3FE1L, "WPC_SOL_HIGHPOWER_OUTPUT"       },
		{ 0x3FE2L, "WPC_SOL_FLASH1_OUTPUT"          },
		{ 0x3FE3L, "WPC_SOL_LOWPOWER_OUTPUT"        },
		// Lamp matrix (0x3FE4–0x3FE5)
		{ 0x3FE4L, "WPC_LAMP_ROW_OUTPUT"            },
		{ 0x3FE5L, "WPC_LAMP_COL_STROBE"            },
		// General illumination & relays (0x3FE6)
		{ 0x3FE6L, "WPC_GI_TRIAC"                   },
		// Switch matrix inputs (0x3FE7–0x3FEA)
		{ 0x3FE7L, "WPC_SW_JUMPER_INPUT"            },
		{ 0x3FE8L, "WPC_SW_CABINET_INPUT"           },
		{ 0x3FE9L, "WPC_SW_ROW_INPUT"               }, // also WPCS_PIC_READ on WPC-S
		{ 0x3FEAL, "WPC_SW_COL_STROBE"              }, // also WPCS_PIC_WRITE on WPC-S
		// Extended board I/O / alphanumeric (0x3FEB–0x3FEF)
		{ 0x3FEBL, "WPC_EXTBOARD1"                  }, // WPC_ALPHA_POS on alphanumeric
		{ 0x3FECL, "WPC_EXTBOARD2"                  }, // WPC_ALPHA_ROW1 on alphanumeric
		{ 0x3FEDL, "WPC_EXTBOARD3"                  },
		{ 0x3FEEL, "WPC_ALPHA_ROW2"                 }, // WPC95_FLIPPER_COIL_OUTPUT on WPC-95
		{ 0x3FEFL, "WPC95_FLIPPER_SWITCH_INPUT"     }, // WPC-95 only
		// Diagnostics LED (0x3FF2)
		{ 0x3FF2L, "WPC_LEDS"                       },
		// RAM bank register – WPC-95 only (0x3FF3)
		{ 0x3FF3L, "WPC_RAM_BANK_WPC95"             },
		// Hardware bit-shifter (0x3FF4–0x3FF7)
		{ 0x3FF4L, "WPC_SHIFTADDR"                  },
		{ 0x3FF6L, "WPC_SHIFTBIT"                   },
		{ 0x3FF7L, "WPC_SHIFTBIT2"                  },
		// Miscellaneous ASIC control (0x3FF8–0x3FFF)
		{ 0x3FF8L, "WPC_PERIPHERAL_TIMER_FIRQ_CLEAR"},
		{ 0x3FF9L, "WPC_ROM_LOCK"                   },
		{ 0x3FFAL, "WPC_CLK_HOURS_DAYS"             },
		{ 0x3FFBL, "WPC_CLK_MINS"                   },
		{ 0x3FFCL, "WPC_ROM_BANK"                   },
		{ 0x3FFDL, "WPC_RAM_LOCK"                   },
		{ 0x3FFEL, "WPC_RAM_LOCKSIZE"               },
		{ 0x3FFFL, "WPC_ZEROCROSS_IRQ_CLEAR"        },
	};

	// ── Known RAM locations ───────────────────────────────────────────────────

	/** Selected OS-level RAM symbols from wpc_games reverse-engineering work. */
	private static final Object[][] RAM_LABELS = {
		{ 0x0008L, Pointer16DataType.dataType, "FIRQ_SPRINGBOARD_1"},
		{ 0x000AL, Pointer16DataType.dataType, "FIRQ_SPRINGBOARD_2"},
		{ 0x0011L, ByteDataType.dataType,      "BANK_SHADOW"       }, // Early ROMs offse +2
		{ 0x0012L, Pointer16DataType.dataType, "BANK_SPRINGBOARD"  }, // 
		// Real Time Clock
		{ 0x1800L, WordDataType.dataType, "RTC_YEAR"   },
		{ 0x1802L, ByteDataType.dataType, "RTC_MONTH"  },
		{ 0x1803L, ByteDataType.dataType, "RTC_DAY"    },
		{ 0x1803L, ByteDataType.dataType, "RTC_WEEKDAY"},
		{ 0x1804L, ByteDataType.dataType, "RTC_HOUR"   },
		{ 0x1805L, ByteDataType.dataType, "RTC_MINUTE" },
		// Checksum fields in system ROM
		{ ADDR_CHECKSUM_DELTA, WordDataType.dataType, "WPC_ROM_CHECKSUM_DELTA"},
		{ ADDR_CHECKSUM,       WordDataType.dataType, "WPC_ROM_CHECKSUM"      },
	};

	// ── Loader options ────────────────────────────────────────────────────────

	private static final String OPT_CREATE_OVERLAYS  = "Create banked ROM overlays";
	private static final String OPT_DISABLE_CHECKSUM = "Disable ROM checksum verification";
	private static final String OPT_EXT_RAM          = "Create extended RAM block (DCS/WPC-95)";

	// ─────────────────────────────────────────────────────────────────────────
	// AbstractLoader overrides
	// ─────────────────────────────────────────────────────────────────────────

	@Override
	public String getName() {
		return "WPC ROM Loader";
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 100;
	}

	/**
	 * Accept only files whose size matches one of the four valid WPC ROM sizes.
	 * Returns a single load spec targeting the Motorola 6809 big-endian 16-bit
	 * language/compiler pair used by all WPC hardware generations.
	 */
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		long fileLen = provider.length();
		for (long size : VALID_SIZES) {
			if (fileLen == size) {
				loadSpecs.add(new LoadSpec(this, 0,
					new LanguageCompilerSpecPair("6809:BE:16:default", "default"), true));
				break;
			}
		}
		return loadSpecs;
	}

	/**
	 * Build the complete WPC memory map and populate labels.
	 *
	 * <p>Memory layout created:
	 * <ul>
	 *   <li>RAM (0x0000–0x1FFF) — 8 KiB battery-backed SRAM, R/W</li>
	 *   <li>RAM_EXT (0x2000–0x2FFF) — 4 KiB extra RAM (DCS/WPC-95), R/W, optional</li>
	 *   <li>DMD (0x3000–0x3BFF) — DMD windows, R/W</li>
	 *   <li>IO (0x3C00–0x3FFF) — ASIC registers, volatile R/W</li>
	 *   <li>ROM_PAGE_XX overlays at 0x4000–0x7FFF — one per banked page, R/X</li>
	 *   <li>ROM_SYSTEM (0x8000–0xFFFF) — last 32 KiB of the ROM file, R/X</li>
	 * </ul>
	 */
	@Override
	protected void load(Program program, Loader.ImporterSettings settings)
			throws CancelledException, IOException {

		ByteProvider provider = settings.provider();
		List<Option> options  = settings.options();
		MessageLog log        = settings.log();
		TaskMonitor monitor   = settings.monitor();

		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		long romSize = provider.length();
		int pageCount = (int) (romSize / BANK_SIZE);

		try {
			monitor.setMessage("Loading WPC ROM system region…");
			createSystemRomBlock(api, provider, romSize, log);

			monitor.setMessage("Creating RAM blocks…");
			createRamBlocks(api, options, log);

			monitor.setMessage("Creating DMD block…");
			createDmdBlock(api, log);

			monitor.setMessage("Creating I/O block…");
			createIoBlock(api, log);

			boolean createOverlays = getBoolOption(options, OPT_CREATE_OVERLAYS, true);
			if (createOverlays) {
				monitor.setMessage("Creating banked ROM overlays…");
				createBankedOverlays(api, provider, pageCount, monitor, log);
			}

			monitor.setMessage("Applying I/O register labels…");
			applyIoLabels(api, log);

			monitor.setMessage("Applying RAM labels…");
			applyRamLabels(api, log);

			monitor.setMessage("Applying interrupt vector labels…");
			applyVectorLabels(api, log);

			monitor.setMessage("Setting entry point…");
			setEntryPoint(api, log);

			boolean disableChecksum = getBoolOption(options, OPT_DISABLE_CHECKSUM, true);
			if (disableChecksum) {
				log.appendMsg("WPCLoader", "ROM checksum verification disabled by option.");
				disableRomChecksum(api, log);
			}

			logRomInfo(api, romSize, pageCount, log);
			monitor.setMessage("WPC ROM loaded successfully.");

		} catch (CancelledException e) {
			throw e;
		} catch (Exception e) {
			log.appendException(e);
			throw new IOException("Failed to load WPC ROM: " + e.getMessage(), e);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = new ArrayList<>();
		list.add(new Option(OPT_CREATE_OVERLAYS,  Boolean.TRUE));
		list.add(new Option(OPT_DISABLE_CHECKSUM, Boolean.TRUE));
		list.add(new Option(OPT_EXT_RAM,          Boolean.FALSE));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec,
			List<Option> options, Program program) {
		return null;
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Private helpers – block creation
	// ─────────────────────────────────────────────────────────────────────────

	/** Load the last 32 KiB of the ROM file into 0x8000–0xFFFF. */
	private void createSystemRomBlock(FlatProgramAPI api, ByteProvider provider,
			long romSize, MessageLog log) throws Exception {
		byte[] sysBytes = provider.readBytes(romSize - SYSTEM_ROM_SIZE, SYSTEM_ROM_SIZE);
		MemoryBlock block = api.createMemoryBlock(
			"ROM_SYSTEM", api.toAddr(SYSTEM_ROM_START), sysBytes, false);
		block.setPermissions(true, true, true); // R/W/X
	}

	/** Create the 8 KiB base RAM block and optionally the 4 KiB extended RAM block. */
	private void createRamBlocks(FlatProgramAPI api, List<Option> options,
			MessageLog log) throws Exception {
		// 8 KiB battery-backed SRAM
		MemoryBlock ram = api.createMemoryBlock(
			"RAM", api.toAddr(RAM_START), (InputStream) null, RAM_SIZE, false);
		ram.setPermissions(true, true, false);

		if (getBoolOption(options, OPT_EXT_RAM, true)) {
			MemoryBlock ramExt = api.createMemoryBlock(
				"RAM_EXT", api.toAddr(RAM_EXT_START), (InputStream) null, RAM_EXT_SIZE, false);
			ramExt.setPermissions(true, true, false);
		}
	}

	/** Create a single volatile 3 KiB block covering the entire 0x3000–0x3BFF DMD window. */
	private void createDmdBlock(FlatProgramAPI api, MessageLog log) throws Exception {
		MemoryBlock dmd = api.createMemoryBlock(
			"DMD", api.toAddr(DMD_START), (InputStream) null, DMD_SIZE, false);
		dmd.setPermissions(true, true, false);
		dmd.setVolatile(true);
	}

	/** Create a single volatile 1 KiB block covering the entire 0x3C00–0x3FFF I/O window. */
	private void createIoBlock(FlatProgramAPI api, MessageLog log) throws Exception {
		MemoryBlock io = api.createMemoryBlock(
			"IO", api.toAddr(IO_START), (InputStream) null, IO_SIZE, false);
		io.setPermissions(true, true, false);
		io.setVolatile(true);
	}

	/**
	 * Create one Ghidra overlay block per banked ROM page.
	 *
	 * <p>WPC page numbering: for a ROM with {@code pageCount} total 16 KiB pages,
	 * the banked pages are indices 0 … pageCount-3, and the last two pages are the
	 * fixed system ROM (always at 0x8000–0xFFFF). The WPC ASIC page number for
	 * bank index {@code b} is {@code 0x3F - (pageCount - 1 - b)}, so a 128 KiB ROM
	 * (8 pages) has banked pages 0x38–0x3D, and a 1 MiB ROM (64 pages) has 0x00–0x3D.
	 */
	private void createBankedOverlays(FlatProgramAPI api, ByteProvider provider,
			int pageCount, TaskMonitor monitor, MessageLog log) throws Exception {
		int bankedPages = pageCount - 2; // last 2 pages = fixed system ROM
		for (int bank = 0; bank < bankedPages; bank++) {
			monitor.checkCancelled();
			int pageNum = 0x3F - (pageCount - 1 - bank);
			String name = String.format("ROM_PAGE_%02X", pageNum);
			long fileOffset = (long) bank * BANK_SIZE;
			byte[] bankBytes = provider.readBytes(fileOffset, BANK_SIZE);
			MemoryBlock block = api.createMemoryBlock(
				name, api.toAddr(BANKED_ROM_START), bankBytes, true);
			block.setPermissions(true, true, true); // R/W/X
		}
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Private helpers – symbol application
	// ─────────────────────────────────────────────────────────────────────────

	/** Apply labels for every known WPC ASIC and peripheral I/O register. */
	private void applyIoLabels(FlatProgramAPI api, MessageLog log) {
		for (Object[] reg : IO_REGISTERS) {
			long addr = (Long) reg[0];
			String name = (String) reg[1];
			try {
				api.createLabel(api.toAddr(addr), name, true);
				api.createData(api.toAddr(addr), ByteDataType.dataType);
			} catch (Exception e) {
				log.appendMsg("WPCLoader", "Could not create label " + name + ": " + e.getMessage());
			}
		}
	}

	/** Apply labels for the known OS-level RAM symbols. */
	private void applyRamLabels(FlatProgramAPI api, MessageLog log) {
		for (Object[] entry : RAM_LABELS) {
			long addr = (Long) entry[0];
			DataType type = (DataType) entry[1];
			String name = (String) entry[2];
			try {
				api.createLabel(api.toAddr(addr), name, true);
				api.createData(api.toAddr(addr), type);
			} catch (Exception e) {
				log.appendMsg("WPCLoader", "Could not create RAM label " + name + ": " + e.getMessage());
			}
		}
	}

	/**
	 * Label each 6809 interrupt vector as a 16-bit pointer and create a function
	 * at the target address named after the vector.
	 */
	private void applyVectorLabels(FlatProgramAPI api, MessageLog log) {
		for (Object[] vec : VECTORS) {
			long vecAddr = (Long) vec[0];
			String vecName = (String) vec[1];
			try {
				Address addr = api.toAddr(vecAddr);
				api.createLabel(addr, vecName, true);
				api.createData(addr, Pointer16DataType.dataType);

				// Read the 2-byte big-endian target address
				byte[] bytes = api.getBytes(addr, 2);
				int target = ((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF);
				Address targetAddr = api.toAddr(target);
				if (api.getMemoryBlock(targetAddr) != null &&
						api.getFunctionAt(targetAddr) == null) {
					api.createFunction(targetAddr, vecName + "_ISR");
				}
			} catch (Exception e) {
				log.appendMsg("WPCLoader", "Could not create vector " + vecName + ": " + e.getMessage());
			}
		}
	}

	/**
	 * Read the RESET vector (0xFFFE) from the fixed ROM and register that address
	 * as the program entry point.
	 */
	private void setEntryPoint(FlatProgramAPI api, MessageLog log) {
		try {
			byte[] bytes = api.getBytes(api.toAddr(0xFFFEL), 2);
			int resetTarget = ((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF);
			Address entry = api.toAddr(resetTarget);
			api.addEntryPoint(entry);
			if (api.getFunctionAt(entry) == null) {
				api.createFunction(entry, "entry");
			}
		} catch (Exception e) {
			log.appendMsg("WPCLoader", "Could not set entry point: " + e.getMessage());
		}
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Private helpers – diagnostics
	// ─────────────────────────────────────────────────────────────────────────

	/** Log ROM metadata (size, version, checksum status) to the message log. */
	private void logRomInfo(FlatProgramAPI api, long romSize, int pageCount, MessageLog log) {
		try {
			byte[] cksumBytes = api.getBytes(api.toAddr(ADDR_CHECKSUM), 2);
			int storedChecksum = ((cksumBytes[0] & 0xFF) << 8) | (cksumBytes[1] & 0xFF);
			int versionByte = storedChecksum & 0xFF;
			int vMajor = (versionByte >> 4) & 0x0F;
			int vMinor = versionByte & 0x0F;

			byte[] deltaBytes = api.getBytes(api.toAddr(ADDR_CHECKSUM_DELTA), 2);
			int delta = ((deltaBytes[0] & 0xFF) << 8) | (deltaBytes[1] & 0xFF);
			boolean checksumDisabled = (delta == 0x00FF);

			log.appendMsg("WPCLoader",
				String.format("ROM size: %d KiB  |  %d pages (%d banked + 2 fixed)",
					romSize / 1024, pageCount, pageCount - 2));
			log.appendMsg("WPCLoader",
				String.format("ROM version: %d.%d  |  checksum: 0x%04X  |  delta: 0x%04X%s",
					vMajor, vMinor, storedChecksum, delta,
					checksumDisabled ? "  [checksum checking DISABLED]" : ""));
		} catch (Exception e) {
			log.appendMsg("WPCLoader", "Could not read ROM metadata: " + e.getMessage());
		}
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Utility
	// ─────────────────────────────────────────────────────────────────────────

	private static boolean getBoolOption(List<Option> options, String name, boolean defaultVal) {
		if (options == null) return defaultVal;
		for (Option opt : options) {
			if (name.equals(opt.getName())) {
				Object val = opt.getValue();
				if (val instanceof Boolean) return (Boolean) val;
			}
		}
		return defaultVal;
	}

	/** Set the ROM checksum delta to disable checksum verification in the WPC OS. */
	private void disableRomChecksum(FlatProgramAPI api, MessageLog log) {
		try {
			api.setShort(api.toAddr(ADDR_CHECKSUM_DELTA), (short) 0x00FF);
		} catch (Exception e) {
			log.appendMsg("WPCLoader", "Could not disable ROM checksum: " + e.getMessage());
		}
	}
}
