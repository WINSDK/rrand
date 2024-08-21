#![allow(dead_code)]

use std::ffi::c_void;
use std::ffi::CString;
use std::mem;
use std::ptr;
use std::sync::LazyLock;

use object::macho;
use object::Object;
use object::ObjectSection;
use object::ObjectSegment;
use object::{pod, Pod};
use object::read::macho::MachOFile64;
use object::LittleEndian as LE;

use crate::relocs::{parse_chained_fixups, RelocationKind};

pub type ExitCode = i32;

static PAGE_SIZE: LazyLock<usize> =
    LazyLock::new(|| unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize });

#[derive(Debug, PartialEq)]
pub enum Error {
    Allocate,
    OutOfMemory,
    OutOfBoundWrite,
    OutOfBoundRead,
    ReadAlignment,
    LoadLibrary,
    LoadSymbol,
    InitTLV,
    ParseRelocations,
}

extern "C" {
    fn tlv_get_addr(desc: *mut TLVDescriptor) -> *mut c_void;
    fn sys_icache_invalidate(start: *mut c_void, size: usize);
}

#[used]
#[link_section = "__DATA_CONST,__pth_jit_func"]
static PTHREAD_JIT_WRITE_CALLBACK_ALLOWLIST: &[libc::pthread_jit_write_callback_t] =
    &[Some(writing_callback), None];

enum WriteKind<'a> {
    Copy(&'a [u8]),
    Set { val: u8, size: usize },
}

struct WriteOp<'a> {
    vm: &'a mut VM,
    offset: usize,
    kind: WriteKind<'a>,
}

extern "C" fn writing_callback(ctx: *mut c_void) -> i32 {
    let WriteOp { vm, offset, kind: ty } = unsafe { &mut *(ctx as *mut WriteOp) };

    match ty {
        WriteKind::Copy(bytes) => {
            vm.region[*offset..][..bytes.len()].copy_from_slice(bytes);
        }
        WriteKind::Set { val, size } => {
            vm.region[*offset..][..*size].fill(*val);
        }
    }
    0
}

impl WriteOp<'_> {
    fn commit(mut self) {
        unsafe {
            let write_op = std::mem::transmute(&mut self);
            libc::pthread_jit_write_with_callback_np(Some(writing_callback), write_op);
        }
    }
}

pub struct Allocation<'a> {
    vm: &'a mut VM,
    offset: usize,
    size: usize,
}

impl Allocation<'_> {
    pub fn write_slice(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > self.size {
            return Err(Error::OutOfBoundWrite);
        }

        let write_op = WriteOp {
            vm: self.vm,
            offset: self.offset,
            kind: WriteKind::Copy(bytes),
        };
        write_op.commit();
        Ok(())
    }

    pub fn write<T: Pod + Copy>(&mut self, val: &T) -> Result<(), Error> {
        if mem::size_of::<T>() > self.size {
            return Err(Error::OutOfBoundWrite);
        }

        let bytes = pod::bytes_of(val);
        let write_op = WriteOp {
            vm: self.vm,
            offset: self.offset,
            kind: WriteKind::Copy(bytes),
        };
        write_op.commit();
        Ok(())
    }

    pub fn set_value(&mut self, val: u8) {
        let write_op = WriteOp {
            vm: self.vm,
            offset: self.offset,
            kind: WriteKind::Set {
                val,
                size: self.size,
            },
        };
        write_op.commit();
    }

    pub fn address(&self) -> u64 {
        self.vm.region.as_ptr() as u64 + self.offset as u64
    }
}

pub struct VM {
    region: &'static mut [u8],
    offset: usize,
}

impl VM {
    pub fn new(size: usize) -> Result<Self, Error> {
        unsafe {
            let region = libc::mmap(
                ptr::null_mut(),
                size + *PAGE_SIZE - size % *PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT,
                -1,
                0,
            );

            if region.is_null() {
                return Err(Error::Allocate);
            }

            let region = std::slice::from_raw_parts_mut(region, size);
            let region: &'static mut [u8] = std::mem::transmute(region);

            Ok(Self { region, offset: 0 })
        }
    }

    pub fn address(&self) -> u64 {
        self.region.as_ptr() as u64
    }

    #[inline]
    fn checked_get(&self, addr: usize, size: usize) -> Option<&[u8]> {
        self.region.get(addr..)?.get(..size)
    }

    pub fn alloc(&mut self, size: usize) -> Result<Allocation, Error> {
        self.checked_get(self.offset, size)
            .ok_or(Error::OutOfMemory)?;
        let offset = self.offset;
        self.offset += size;
        Ok(Allocation {
            vm: self,
            offset,
            size,
        })
    }

    pub fn read<T: Pod + Copy>(&self, addr: usize) -> Result<T, Error> {
        let size = mem::size_of::<T>();
        let bytes = self.checked_get(addr, size).ok_or(Error::OutOfBoundRead)?;
        let read = pod::from_bytes(bytes).map_err(|_| Error::ReadAlignment)?;
        Ok(*read.0)
    }

    pub fn read_slice(&self, addr: usize, size: usize) -> Result<&[u8], Error> {
        self.checked_get(addr, size).ok_or(Error::OutOfBoundRead)
    }

    pub fn write<T: Pod + Copy>(&mut self, addr: usize, val: &T) -> Result<(), Error> {
        let size = mem::size_of::<T>();
        self.checked_get(addr, size).ok_or(Error::OutOfBoundWrite)?;
        let bytes = pod::bytes_of(val);
        let write_op = WriteOp {
            vm: self,
            offset: addr,
            kind: WriteKind::Copy(bytes),
        };
        write_op.commit();
        Ok(())
    }

    pub fn write_slice(&mut self, addr: usize, bytes: &[u8]) -> Result<(), Error> {
        self.checked_get(addr, bytes.len())
            .ok_or(Error::OutOfBoundWrite)?;
        let write_op = WriteOp {
            vm: self,
            offset: addr,
            kind: WriteKind::Copy(bytes),
        };
        write_op.commit();
        Ok(())
    }

    pub fn relocate(&mut self, obj: &MachOFile64<LE>) -> Result<(), Error> {
        for reloc in parse_chained_fixups(&obj).map_err(|_| Error::ParseRelocations)? {
            match reloc.kind {
                RelocationKind::Bind { mut value } => {
                    value += self.address();
                    self.write(reloc.target, &value)?;
                }
                RelocationKind::RebaseLocal { .. } => todo!("rebase local"),
                RelocationKind::RebaseExtern { library, sym_name, weak } => {
                    match load_lib_and_func(library, sym_name) {
                        Err(err) if weak => {
                            println!("{err:?}");
                            continue;
                        }
                        Err(err) => panic!("{err:?}"),
                        Ok(func) => {
                            self.write(reloc.target, &func)?;
                        }
                    }

                }
            }
        }

        Ok(())
    }

    pub fn exec_init_funcs(&mut self, obj: &MachOFile64<LE>) -> Result<(), Error> {
        let base_addr = parse_base_addr(obj);

        let mut key = 0;
        for section in obj.sections() {
            let flags = section.macho_section().flags.get(LE);

            if flags & macho::SECTION_TYPE != macho::S_THREAD_LOCAL_VARIABLES {
                continue;
            }

            if section.size() == 0 {
                continue;
            }

            if key == 0 {
                if unsafe { libc::pthread_key_create(&mut key, Some(libc::free)) } != 0 {
                    return Err(Error::InitTLV);
                }
            }

            let addr = self.address() + (section.address() - base_addr);

            for offset in (0..section.size() as usize).step_by(mem::size_of::<TLVDescriptor>()) {
                let tlv_desc = unsafe { &*((addr + offset as u64) as *mut TLVDescriptor) };
                let tlv_desc = TLVDescriptor {
                    thunk: tlv_get_addr,
                    key,
                    offset: tlv_desc.offset,
                };
                WriteOp {
                    vm: self,
                    offset: (section.address() - base_addr) as usize + offset,
                    kind: WriteKind::Copy(pod::bytes_of(&tlv_desc)),
                }.commit();
            }
        }

        for section in  obj.sections() {
            match section.macho_section().flags.get(LE) & macho::SECTION_TYPE {
                macho::S_MOD_INIT_FUNC_POINTERS => println!("S_MOD_INIT_FUNC_POINTERS"),
                macho::S_INIT_FUNC_OFFSETS => {
                    println!("S_INIT_FUNC_OFFSETS");
                },
                macho::S_MOD_TERM_FUNC_POINTERS => println!("S_MOD_TERM_FUNC_POINTERS"),
                _ => continue,
            }
        }

        Ok(())
    }

    pub unsafe fn exec(mut self, entrypoint: u64) -> Result<ExitCode, Error> {
        let envp: Vec<CString> = std::env::vars()
            .flat_map(|(key, val)| CString::new(format!("{key}={val}")))
            .collect();
        let envp: Vec<*const i8> = envp
            .iter()
            .map(|env| env.as_ptr())
            .chain(std::iter::once(ptr::null()))
            .collect();

        // We empty out the program name, might produce weird results on some binaries.
        let argv = [c"".as_ptr(), ptr::null()];

        let stack_size = 1024 * 1024 * 4;
        let stack = vec![0u8; stack_size];

        // Align stack.
        let stack_addr = (stack.as_ptr() as usize + 15) & !15;

        let base_addr = self.address();

        // // Required for arm chips as to invalid the instruction cache.
        sys_icache_invalidate(base_addr as *mut c_void, self.region.len());

        let entrypoint = base_addr + entrypoint;

        println!("Binary loaded at {base_addr:#X}");
        println!("Entering entrypoint at {entrypoint:#X}");

        let mut exit_code: i32;

        std::arch::asm!("
            // Save stack pointer.
            mov x3, sp
            adrp x4, saved_sp@PAGE
            str x3, [x4, saved_sp@PAGEOFF]

            mov sp, {stack}
            mov x29, {entry}
            blr {entry}

            // Restore stack pointer.
            adrp x4, saved_sp@PAGE
            ldr x3, [x4, saved_sp@PAGEOFF]
            mov sp, x3
            ",
            stack = in(reg) stack_addr,
            entry = in(reg) entrypoint,
            in("w0") argv.len() - 1,
            in("x1") argv.as_ptr(),
            in("x2") envp.as_ptr(),
            lateout("w0") exit_code,
            clobber_abi("system"),
        );

        Ok(exit_code)
    }
}

std::arch::global_asm!("
.data
.p2align 3
saved_sp:
    .8byte 0
");

impl Drop for VM {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.region.as_mut_ptr() as *mut c_void, self.region.len()) };
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TLVDescriptor {
    thunk: unsafe extern "C" fn(*mut TLVDescriptor) -> *mut c_void,
    key: u64,
    offset: u64,
}

unsafe impl Pod for TLVDescriptor {}

fn parse_base_addr(obj: &MachOFile64<LE>) -> u64 {
    for segment in obj.segments() {
        if let Ok(Some(b"__TEXT")) = segment.name_bytes() {
            return segment.address();
        }
    }

    0
}

fn load_lib_and_func(library: &str, sym_name: &str) -> Result<u64, Error> {
    let c_lib = CString::new(library).map_err(|_| Error::LoadLibrary)?;
    let lib = unsafe { libc::dlopen(c_lib.as_ptr(), libc::RTLD_NOW) };
    if lib.is_null() {
        return Err(Error::LoadLibrary);
    }

    let sym_name = sym_name.strip_prefix("_").unwrap_or(sym_name); // this is scuffed
    let c_sym_name = CString::new(sym_name).map_err(|_| Error::LoadSymbol)?;
    let func = unsafe { libc::dlsym(lib, c_sym_name.as_ptr()) };
    if lib.is_null() {
        return Err(Error::LoadSymbol);
    }

    Ok(func as u64)
}
