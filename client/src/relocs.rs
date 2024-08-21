use object::macho::{self, LinkeditDataCommand};
use object::read::macho::{MachHeader, MachOFile64};
use object::{Object, ObjectSegment, ReadRef};

use object::LittleEndian as LE;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct DyldChainedFixupsHeader {
    /// 0
    fixups_version: u32,
    /// Offset of dyld\_chained\_starts\_in\_image in chain\_data..
    starts_offset: u32,
    /// Offset of imports table in chain_data.
    imports_offset: u32,
    /// Offset of symbol strings in chain_data.
    symbols_offset: u32,
    /// Number of imported symbol names.
    imports_count: u32,
    /// DYLD_CHAINED_IMPORT*.
    imports_format: u32,
    /// 0 => uncompressed, 1 => zlib compressed.
    symbols_format: u32,
}

/// This struct is embedded in LC_DYLD_CHAINED_FIXUPS payload.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct DyldChainedStartsInImage {
    seg_count: u32,
    // Each entry is offset into this struct for that segment.
    // followed by pool of dyld\_chain\_starts\_in\_segment data.
    seg_info_offset: [u32; 1],
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct DyldChainedStartsInSegment {
    /// size of this (amount kernel needs to copy).
    size: u32,
    /// 0x1000 or 0x4000
    page_size: u16,
    /// DYLD_CHAINED_PTR_*.
    pointer_format: u16,
    /// Offset in memory to start of segment.
    segment_offset: u64,
    /// For 32-bit OS, any value beyond this is not a pointer.
    max_valid_pointer: u32,
    /// How many pages are in the array.
    page_count: u16,
    // Each entry is offset in each page of first element in chain
    // or DYLD_CHAINED_PTR_START_NONE if no fixups on page.
    page_start: [u16; 1],
}

unsafe impl object::Pod for DyldChainedFixupsHeader {}
unsafe impl object::Pod for DyldChainedStartsInImage {}
unsafe impl object::Pod for DyldChainedStartsInSegment {}

const DYLD_CHAINED_IMPORT: u32 = 1;
const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;

/// stride 8, unauth target is vmaddr.
const DYLD_CHAINED_PTR_ARM64E: u16 = 1;
/// Target is vmaddr.
const DYLD_CHAINED_PTR_64: u16 = 2;
const DYLD_CHAINED_PTR_32: u16 = 3;
const DYLD_CHAINED_PTR_32_CACHE: u16 = 4;
const DYLD_CHAINED_PTR_32_FIRMWARE: u16 = 5;
/// Target is vm offset.
const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;
/// Stride 4, unauth target is vm offset.
const DYLD_CHAINED_PTR_ARM64E_KERNEL: u16 = 7;
const DYLD_CHAINED_PTR_64_KERNEL_CACHE: u16 = 8;
/// Stride 8, unauth target is vm offset.
const DYLD_CHAINED_PTR_ARM64E_USERLAND: u16 = 9;
/// Stride 1, x86_64 kernel caches.
const DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE: u16 = 11;
/// Stride 8, unauth target is vm offset, 24-bit bind
const DYLD_CHAINED_PTR_ARM64E_USERLAND24: u16 = 12;

/// used in page_start[] to denote a page with no fixups.
const DYLD_CHAINED_PTR_START_NONE: u16 = 0xFFFF;
/// used in page_start[] to denote a page which has multiple starts.
const DYLD_CHAINED_PTR_START_MULTI: u16 = 0x8000;
/// used in chain_starts[] to denote last start in list for page.
const DYLD_CHAINED_PTR_START_LAST: u16 = 0x8000;

#[derive(Debug)]
pub enum RelocationKind<'data> {
    Bind {
        value: u64,
    },
    RebaseLocal {
        sym_name: &'data str,
        weak: bool,
    },
    RebaseExtern {
        library: &'data str,
        sym_name: &'data str,
        weak: bool,
    },
}

#[derive(Debug)]
pub struct Relocation<'data> {
    pub target: usize,
    pub kind: RelocationKind<'data>,
}

#[derive(Debug, Clone, Copy)]
enum ChainedFixupPointerGeneric {
    Generic32,
    Generic64,
    GenericArm64e,
    Firmware32,
}

impl ChainedFixupPointerGeneric {
    fn bind_and_stride(&self, ptr: u64) -> (bool, u64) {
        match self {
            Self::Generic32 => ((ptr >> 31) != 0, (ptr >> 21) & 0x3FF),
            Self::Generic64 => ((ptr >> 63) != 0, (ptr >> 51) & 0xFFF),
            Self::GenericArm64e => ((ptr >> 63) != 0, (ptr >> 52) & 0x7FF),
            Self::Firmware32 => (false, (ptr >> 26) & 0x3F),
        }
    }
}

fn find_required_lcmds<'data>(
    obj: &MachOFile64<'data, LE>,
) -> Result<(Option<&'data LinkeditDataCommand<LE>>, Vec<&'data str>), object::Error> {
    let header = obj.macho_header();
    let endian = obj.endian();

    let mut dylibs = Vec::new();
    let mut chained_fixups = None;

    let twolevel = header.flags(endian) & macho::MH_TWOLEVEL != 0;
    if twolevel {
        dylibs.push("");
    }

    let mut load_cmds_iter = header.load_commands(endian, obj.data(), 0)?;
    while let Some(lcmd) = load_cmds_iter.next()? {
        if let Some(dylib) = lcmd.dylib()? {
            let dylib = lcmd.string(endian, dylib.dylib.name)?;
            let dylib = std::str::from_utf8(dylib).unwrap_or("");
            dylibs.push(dylib);
        }
        if lcmd.cmd() == macho::LC_DYLD_CHAINED_FIXUPS {
            chained_fixups = Some(lcmd.data()?);
        }
    }

    Ok((chained_fixups, dylibs))
}

fn parse_base_addr(obj: &MachOFile64<LE>) -> Result<u64, object::Error> {
    // Macho addresses are relative to the __TEXT segment.
    for segment in obj.segments() {
        if let Some(b"__TEXT") = segment.name_bytes()? {
            return Ok(segment.address());
        }
    }

    Ok(0)
}

struct ImportEntry<'data> {
    lib_ordinal: u64,
    addend: u64,
    weak: bool,
    name: &'data str,
}

fn parse_chained_import<'data>(
    imports_addr: u64,
    symbols_addr: u64,
    idx: u64,
    data: &'data [u8],
    imports: &mut Vec<ImportEntry<'data>>,
) {
    let entry_off = imports_addr + idx * size_of::<u32>() as u64;
    let Ok(raw): Result<&u32, _> = data.read_at(entry_off) else {
        println!("[macho::parse_chained_import] Invalid import at ordinal {idx}.");
        return;
    };

    let sym_name_addr = symbols_addr + (raw >> 9) as u64;
    let sym_name_range = sym_name_addr..data.len() as u64;
    let sym_name = data.read_bytes_at_until(sym_name_range, 0).unwrap_or(&[]);
    let Ok(name) = std::str::from_utf8(sym_name) else {
        println!("[macho::parse_chained_import] Invalid import at ordinal {idx}.");
        return;
    };

    imports.push(ImportEntry {
        lib_ordinal: (raw & 0xff) as u64,
        addend: 0,
        weak: (raw >> 8) != 0,
        name,
    });
}

fn parse_chained_import_addend<'data>(
    imports_addr: u64,
    symbols_addr: u64,
    idx: u64,
    data: &'data [u8],
    imports: &mut Vec<ImportEntry<'data>>,
) {
    let entry_off = imports_addr + idx * size_of::<[u32; 2]>() as u64;
    let Ok(raw): Result<&u64, _> = data.read_at(entry_off) else {
        println!("[macho::parse_chained_import_addend] Invalid import at ordinal {idx}.");
        return;
    };

    let addend: u32 = *data.read_at(entry_off).unwrap_or(&0);
    let sym_name_addr = symbols_addr + (raw >> 9) as u64;
    let sym_name_range = sym_name_addr..data.len() as u64;
    let sym_name = data.read_bytes_at_until(sym_name_range, 0).unwrap_or(&[]);
    let Ok(name) = std::str::from_utf8(sym_name) else {
        println!("[macho::parse_chained_import_addend] Invalid import at ordinal {idx}.");
        return;
    };

    imports.push(ImportEntry {
        lib_ordinal: (raw & 0xff) as u64,
        addend: addend as u64,
        weak: (raw >> 8) != 0,
        name,
    });
}

fn parse_chained_import_addend64<'data>(
    imports_addr: u64,
    symbols_addr: u64,
    idx: u64,
    data: &'data [u8],
    imports: &mut Vec<ImportEntry<'data>>,
) {
    let entry_off = imports_addr + idx * size_of::<[u64; 2]>() as u64;
    let Ok(raw): Result<&u64, _> = data.read_at(entry_off) else {
        println!("[macho::parse_chained_import_addend64] Invalid import at ordinal {idx}.");
        return;
    };

    let addend: u64 = *data.read_at(entry_off).unwrap_or(&0);
    let sym_name_addr = symbols_addr + (raw >> 17) as u64;
    let sym_name_range = sym_name_addr..data.len() as u64;
    let sym_name = data.read_bytes_at_until(sym_name_range, 0).unwrap_or(&[]);
    let Ok(name) = std::str::from_utf8(sym_name) else {
        println!("[macho::parse_chained_import_addend64] Invalid import at ordinal {idx}.");
        return;
    };

    imports.push(ImportEntry {
        lib_ordinal: raw & 0xffff,
        addend,
        weak: (raw >> 16) != 0,
        name,
    });
}

fn parse_page_starts_table_starts(page_starts: u64, page_count: u64, data: &[u8]) -> Vec<Vec<u16>> {
    let mut page_start_offs = Vec::new();
    for idx in 0..page_count {
        let entry_off = page_starts + size_of::<u16>() as u64 * idx;
        let Ok(&start): Result<&u16, _> = data.read_at(entry_off) else {
            println!("[macho::parse_page_table] Failed to read page offset at offset {idx}.");
            continue;
        };

        if start & DYLD_CHAINED_PTR_START_MULTI != 0 && start != DYLD_CHAINED_PTR_START_NONE {
            let overflow_idx = (start & !DYLD_CHAINED_PTR_START_MULTI) as u64;
            let mut sub_page_addr = page_starts + size_of::<u16>() as u64 * overflow_idx;
            let mut page_start_sub_starts = Vec::new();
            loop {
                let Ok(&sub_page_start): Result<&u16, _> = data.read_at(sub_page_addr) else {
                    continue;
                };
                if sub_page_start & DYLD_CHAINED_PTR_START_LAST == 0 {
                    page_start_sub_starts.push(sub_page_start);
                    page_start_offs.push(page_start_sub_starts.clone());
                    sub_page_addr += size_of::<u16>() as u64;
                } else {
                    page_start_sub_starts.push(sub_page_start & !DYLD_CHAINED_PTR_START_LAST);
                    page_start_offs.push(page_start_sub_starts);
                    break;
                }
            }
        } else {
            page_start_offs.push(vec![start]);
        }
    }

    page_start_offs
}

pub fn parse_chained_fixups<'data>(
    obj: &MachOFile64<'data, LE>,
) -> Result<Vec<Relocation<'data>>, object::Error> {
    let mut relocs = Vec::new();

    let (Some(chained_fixups), dylibs) = find_required_lcmds(obj)? else {
        return Ok(relocs);
    };

    let base_addr = 0; // parse_base_addr(obj)?;
    let real_base_addr = parse_base_addr(obj)?;
    let data = obj.data();
    let endian = obj.endian();

    let data_off = chained_fixups.dataoff.get(endian) as u64;
    let Ok(fixups_header): Result<&DyldChainedFixupsHeader, _> = data.read_at(data_off) else {
        println!(
            "[macho::parse_chained_fixups] Failed to read lazy bind \
                  when parsing import at offset {data_off:#x}."
        );
        return Ok(relocs);
    };

    let imports_addr = data_off + fixups_header.imports_offset as u64;
    let imports_count = fixups_header.imports_count as u64;
    let imports_format = fixups_header.imports_format;
    let chained_fixups_size = chained_fixups.datasize.get(endian) as u64;

    if imports_count > chained_fixups_size {
        println!("[macho::parse_chained_fixups] Binary is malformed.");
        return Ok(relocs);
    }

    let symbols_off = fixups_header.symbols_offset as u64;
    let symbols_addr = data_off + symbols_off;

    let parse_import_fn = match imports_format {
        DYLD_CHAINED_IMPORT => parse_chained_import,
        DYLD_CHAINED_IMPORT_ADDEND => parse_chained_import_addend,
        DYLD_CHAINED_IMPORT_ADDEND64 => parse_chained_import_addend64,
        _ => {
            println!(
                "[macho::parse_chained_fixups] Unknown import format \
                      (might not be supported)."
            );
            return Ok(relocs);
        }
    };

    let mut imports = Vec::new();
    for idx in 0..imports_count {
        parse_import_fn(imports_addr, symbols_addr, idx, data, &mut imports)
    }

    let fixups_start_addr = data_off + fixups_header.starts_offset as u64;
    let Ok(segs): Result<&DyldChainedStartsInImage, _> = data.read_at(fixups_start_addr) else {
        println!("[macho::parse_chained_fixups] Failed to read image starts.");
        return Ok(relocs);
    };

    // Skip to seg_info_offset list.
    let seg_info_addr = fixups_start_addr + size_of::<u32>() as u64;

    for idx in 0..segs.seg_count as u64 {
        let off = match data.read_at::<u32>(seg_info_addr + idx * size_of::<u32>() as u64) {
            Ok(&seg_info_off) if seg_info_off != 0 => seg_info_off,
            _ => continue,
        };

        let mut chain_addr = fixups_start_addr + off as u64;
        let Ok(starts): Result<&DyldChainedStartsInSegment, _> = data.read_at(chain_addr) else {
            println!("[macho::parse_chained_fixups] Failed to read segments starts.");
            continue;
        };

        let (stride_size, format) = match starts.pointer_format {
            DYLD_CHAINED_PTR_ARM64E
            | DYLD_CHAINED_PTR_ARM64E_USERLAND
            | DYLD_CHAINED_PTR_ARM64E_USERLAND24 => (8, ChainedFixupPointerGeneric::GenericArm64e),
            DYLD_CHAINED_PTR_ARM64E_KERNEL => (4, ChainedFixupPointerGeneric::GenericArm64e),
            // DYLD_CHAINED_PTR_ARM64E_FIRMWARE not supported anywhere by the looks of it.
            DYLD_CHAINED_PTR_64 | DYLD_CHAINED_PTR_64_OFFSET | DYLD_CHAINED_PTR_64_KERNEL_CACHE => {
                (4, ChainedFixupPointerGeneric::Generic64)
            }
            DYLD_CHAINED_PTR_32 | DYLD_CHAINED_PTR_32_CACHE => {
                (4, ChainedFixupPointerGeneric::Generic32)
            }
            DYLD_CHAINED_PTR_32_FIRMWARE => (4, ChainedFixupPointerGeneric::Firmware32),
            DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE => (1, ChainedFixupPointerGeneric::Generic64),
            _ => {
                println!(
                    "[macho::parse_chained_fixups] Unknown or unsupported \
                          pointer format {}.",
                    starts.pointer_format
                );
                continue;
            }
        };

        // Skip to page_start list.
        chain_addr += size_of::<DyldChainedStartsInSegment>() as u64 - size_of::<u16>() as u64;

        let page_count = starts.page_count as u64;
        let page_start_offs = parse_page_starts_table_starts(chain_addr, page_count, data);

        for (jdx, page_starts) in page_start_offs.into_iter().enumerate() {
            let page_addr = starts.segment_offset + jdx as u64 * starts.page_size as u64;
            for start in page_starts {
                if start == DYLD_CHAINED_PTR_START_NONE {
                    continue;
                }

                let mut chain_entry_addr = page_addr + start as u64;
                let mut fixups_done = false;
                while !fixups_done {
                    let ptr = match format {
                        ChainedFixupPointerGeneric::Generic32
                        | ChainedFixupPointerGeneric::Firmware32 => {
                            data.read_at::<u32>(chain_entry_addr).map(|ptr| *ptr as u64)
                        }
                        ChainedFixupPointerGeneric::Generic64
                        | ChainedFixupPointerGeneric::GenericArm64e => {
                            data.read_at::<u64>(chain_entry_addr).copied()
                        }
                    };
                    let Ok(ptr) = ptr else {
                        println!(
                            "[macho::parse_chained_fixups] Couldn't read fixup pointer at \
                                  offset {chain_entry_addr:#x}."
                        );
                        continue;
                    };

                    let (bind, next_entry_stride_count) = format.bind_and_stride(ptr);

                    if bind {
                        let ordinal = match starts.pointer_format {
                            DYLD_CHAINED_PTR_64 | DYLD_CHAINED_PTR_64_OFFSET => ptr & 0xFFFFF,
                            DYLD_CHAINED_PTR_ARM64E
                            | DYLD_CHAINED_PTR_ARM64E_KERNEL
                            | DYLD_CHAINED_PTR_ARM64E_USERLAND24 => {
                                if starts.pointer_format == DYLD_CHAINED_PTR_ARM64E_USERLAND24 {
                                    ptr & 0xFFFFFF
                                } else {
                                    ptr & 0xFFFF
                                }
                            }
                            DYLD_CHAINED_PTR_32 => ptr & 0xFFFFF,
                            _ => {
                                println!(
                                    "[macho::parse_chained_fixups] Unknown bind format at \
                                          {chain_entry_addr:#x}."
                                );
                                chain_entry_addr += next_entry_stride_count * stride_size;
                                if next_entry_stride_count == 0 {
                                    fixups_done = true;
                                }
                                continue;
                            }
                        };

                        let Some(entry) = imports.get(ordinal as usize) else {
                            println!(
                                "[macho::parse_chained_fixups] Ordinal {ordinal} has no \
                                       matching import."
                            );
                            continue;
                        };

                        let target_addr = base_addr + chain_entry_addr;

                        if entry.name.is_empty() {
                            println!(
                                "[macho::parse_chained_fixups] Import table entry at \
                                      {target_addr:#x} has no entries."
                            );
                            continue;
                        }

                        let Some(library) = dylibs.get(entry.lib_ordinal as usize) else {
                            println!(
                                "[macho::parse_chained_fixups] Import table entry at \
                                     {target_addr:#x} is corrupt."
                            );
                            continue;
                        };

                        relocs.push(Relocation {
                            target: (target_addr + entry.addend) as usize,
                            kind: if entry.lib_ordinal == 253 || entry.lib_ordinal == 0 {
                                RelocationKind::RebaseLocal {
                                    sym_name: entry.name,
                                    weak: entry.weak,
                                }
                            } else {
                                RelocationKind::RebaseExtern {
                                    library,
                                    sym_name: entry.name,
                                    weak: entry.weak,
                                }
                            },
                        });
                    } else {
                        let entry_addr = match starts.pointer_format {
                            DYLD_CHAINED_PTR_ARM64E
                            | DYLD_CHAINED_PTR_ARM64E_KERNEL
                            | DYLD_CHAINED_PTR_ARM64E_USERLAND
                            | DYLD_CHAINED_PTR_ARM64E_USERLAND24 => {
                                let auth = ptr & 1 != 0;
                                let mut entry_addr = if auth { ptr & 0xFFFF } else { ptr & 0xFFFA };
                                if starts.pointer_format != DYLD_CHAINED_PTR_ARM64E || auth {
                                    entry_addr += base_addr;
                                }
                                entry_addr
                            }
                            DYLD_CHAINED_PTR_64 => ptr & 0x7FFFFFFFFFF,
                            DYLD_CHAINED_PTR_64_OFFSET => (ptr & 0x7FFFFFFFFFF) + base_addr,
                            DYLD_CHAINED_PTR_64_KERNEL_CACHE
                            | DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE => ptr & 0x3FFFFFFF,
                            DYLD_CHAINED_PTR_32
                            | DYLD_CHAINED_PTR_32_CACHE
                            | DYLD_CHAINED_PTR_32_FIRMWARE => ptr & 0x3FFFFFF,
                            _ => {
                                println!(
                                    "[macho::parse_chained_fixups] Unknown bind format at \
                                          {chain_entry_addr:#x}."
                                );
                                chain_entry_addr += next_entry_stride_count * stride_size;
                                if next_entry_stride_count == 0 {
                                    fixups_done = true;
                                }
                                continue;
                            }
                        };

                        // FIXME: doesn't handle obj-c
                        // if objc {
                        //      add_relocated_pointer(chain_entry_addr, entry_offset);
                        // }

                        relocs.push(Relocation {
                            kind: RelocationKind::Bind {
                                value: entry_addr - real_base_addr,
                            },
                            target: (chain_entry_addr + base_addr) as usize,
                        });
                    }

                    chain_entry_addr += next_entry_stride_count * stride_size;

                    if chain_entry_addr > page_addr + starts.page_size as u64 {
                        println!(
                            "[macho::parse_chained_fixups] Pointer at {chain_entry_addr:#x} \
                                  left page."
                        );
                        fixups_done = true;
                    }

                    if next_entry_stride_count == 0 {
                        fixups_done = true;
                    }
                }
            }
        }
    }

    Ok(relocs)
}
