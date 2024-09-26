#![allow(dead_code)]

use std::ffi::c_void;
use std::ffi::CString;
use std::mem;
use std::ptr;
use std::sync::LazyLock;

use object::read::macho::{Section, Segment};
use object::{macho, pod, Pod, Object, ObjectSegment};
use object::LittleEndian as LE;

use crate::{MachO, parse_base_addr};
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
    SetMemoryProtection,
    ParseRelocations(object::Error),
    ParseObjcSELS,
}

const VM_FLAGS_ANYWHERE: i32 = 0x0001;

extern "C" {
    fn sys_icache_invalidate(start: *mut c_void, size: usize);

    pub fn vm_protect(
        target_task: libc::vm_map_t,
        address: libc::vm_address_t,
        size: libc::vm_size_t,
        set_max: i32,
        new_prot: libc::vm_prot_t,
    ) -> libc::kern_return_t;
}

pub struct Allocation<'a> {
    vm: &'a mut VM,
    offset: usize,
    size: usize,
}

impl Allocation<'_> {
    pub fn write<T: Pod + Copy>(&mut self, val: &T) -> Result<(), Error> {
        self.write_slice(pod::bytes_of(val))
    }

    pub fn write_slice(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.vm.write_slice(self.offset, bytes)
    }

    pub fn set_value(&mut self, val: u8) {
        let _ = self.vm.set_value(self.offset, self.size, val);
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
            let mut region = 0;
            let size = (size + *PAGE_SIZE) & !*PAGE_SIZE; // align size
            let res = libc::vm_allocate(
                libc::mach_task_self(),
                &mut region,
                size,
                libc::VM_FLAGS_ANYWHERE,
            );

            if res != 0 {
                return Err(Error::Allocate);
            }

            let region = std::slice::from_raw_parts_mut(region as *mut u8, size);
            let region: &'static mut [u8] = std::mem::transmute(region);

            if cfg!(debug_assertions) {
                region.fill(0x00);
            }

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

    #[inline]
    fn checked_get_mut(&mut self, addr: usize, size: usize) -> Option<&mut [u8]> {
        self.region.get_mut(addr..)?.get_mut(..size)
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

    pub fn read<T: Pod + Copy>(&self, offset: usize) -> Result<T, Error> {
        let size = mem::size_of::<T>();
        let bytes = self
            .checked_get(offset, size)
            .ok_or(Error::OutOfBoundRead)?;
        let read = pod::from_bytes(bytes).map_err(|_| Error::ReadAlignment)?;
        Ok(*read.0)
    }

    pub fn read_slice(&self, offset: usize, size: usize) -> Result<&[u8], Error> {
        self.checked_get(offset, size).ok_or(Error::OutOfBoundRead)
    }

    pub fn write<T: Pod + Copy>(&mut self, offset: usize, val: &T) -> Result<(), Error> {
        self.write_slice(offset, pod::bytes_of(val))
    }

    pub fn write_slice(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        self
            .checked_get_mut(offset, bytes.len())
            .ok_or(Error::OutOfBoundWrite)?
            .copy_from_slice(bytes);
        Ok(())
    }

    pub fn set_value(&mut self, offset: usize, size: usize, val: u8) -> Result<(), Error> {
        self
            .checked_get_mut(offset, size)
            .ok_or(Error::OutOfBoundWrite)?
            .fill(val);
        Ok(())
    }

    pub fn relocate(&mut self, obj: &MachO) -> Result<(), Error> {
        for reloc in parse_chained_fixups(&obj).map_err(Error::ParseRelocations)? {
            match reloc.kind {
                RelocationKind::Bind { mut value } => {
                    value += self.address();
                    self.write(reloc.target, &value)?;
                }
                RelocationKind::RebaseLocal { .. } => todo!("rebase local"),
                RelocationKind::RebaseExtern {
                    library,
                    sym_name,
                    weak,
                } => match load_lib_and_func(library, sym_name) {
                    Err(err) if weak => {
                        println!("{err:?}");
                        continue;
                    }
                    Err(err) => panic!("{err:?}"),
                    Ok(func) => {
                        self.write(reloc.target, &func)?;
                    }
                },
            }
        }

        Ok(())
    }

    pub fn set_protection(&mut self, obj: &MachO) -> Result<(), Error> {
        let base_addr = parse_base_addr(obj);

        for segment in obj.segments() {
            if let Ok(Some(b"__PAGEZERO")) = segment.name_bytes() {
                continue;
            }

            let addr = self.address() + (segment.address() - base_addr);
            let init_prot = segment.macho_segment().initprot(LE) as i32;

            let rflag = if init_prot & libc::VM_PROT_READ != 0 {
                'r'
            } else {
                '-'
            };
            let wflag = if init_prot & libc::VM_PROT_WRITE != 0 {
                'w'
            } else {
                '-'
            };
            let eflag = if init_prot & libc::VM_PROT_EXECUTE != 0 {
                'x'
            } else {
                '-'
            };
            println!("Segment at {addr:#X} set to {rflag}{wflag}{eflag}.");

            unsafe {
                let res = vm_protect(
                    libc::mach_task_self(),
                    addr as libc::vm_address_t,
                    segment.size() as libc::vm_size_t,
                    0,
                    init_prot,
                );

                if res != 0 {
                    return Err(Error::SetMemoryProtection);
                }
            }
        }

        Ok(())
    }

    // typedef void (*Initializer)(int argc, const char* const argv[], const char* const envp[], const char* const apple[], const ProgramVars* vars);
    pub fn run_initializers(&mut self, obj: &MachO) -> Result<(), Error> {
        let pm = crate::tls::ParsedMacho::from_obj(obj);
        crate::tls::tlv_initialize_descriptors(&pm, self.address())?;

        for section in &pm.sections {
            let flags = section.flags(LE);

            if flags & macho::SECTION_TYPE == macho::S_INIT_FUNC_OFFSETS {
                panic!();
            }
        }

        Ok(())
    }

    pub fn init_objc_runtime(&mut self, obj: &MachO) -> Result<(), Error> {
        let pm = crate::tls::ParsedMacho::from_obj(obj);
        unsafe { crate::objc::map_images(&pm, self.address())? };
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
        let stack_addr = ((stack.as_ptr() as usize + stack_size) + 15) & !15;

        let base_addr = self.address();

        // Required for arm chips as to invalid the instruction cache.
        sys_icache_invalidate(base_addr as *mut c_void, self.region.len());

        let entrypoint = base_addr + entrypoint;
        println!("Entering entrypoint at {entrypoint:#x}");

        let mut exit_code: i32;

        std::arch::asm!("
            mov x3, sp

            // Set allocated stack.
            mov sp, {stack}

            // Save stack and frame pointer.
            sub sp, sp, 16
            stp x3, x29, [sp]

            // Set frame pointer to hide backtrace.
            mov x29, {entry}

            // Call entrypoint.
            blr {entry}

            // Restore stack and frame pointer.
            ldp x3, x29, [sp]
            add sp, sp, 16

            // Set old stack pointer (old stack must also stay aligned).
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

impl Drop for VM {
    fn drop(&mut self) {
        unsafe {
            let res = libc::vm_deallocate(
                libc::mach_task_self(),
                self.region.as_ptr() as libc::vm_address_t,
                self.region.len() as libc::vm_size_t,
            );

            if res != 0 {
                println!("Failed to deallocate VM memory.");
            }
        }
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

fn load_lib_and_func(library: &str, sym_name: &str) -> Result<u64, Error> {
    println!("Loading {library} -- {sym_name}.");
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
