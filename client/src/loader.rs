#![allow(dead_code)]

use std::ffi::c_void;
use std::ffi::CString;
use std::mem;
use std::ptr;
use std::sync::LazyLock;

use object::{pod, Pod};

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
}

extern "C" {
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
    addr: usize,
    ty: WriteKind<'a>,
}

extern "C" fn writing_callback(ctx: *mut c_void) -> i32 {
    let WriteOp { vm, addr, ty } = unsafe { &mut *(ctx as *mut WriteOp) };

    match ty {
        WriteKind::Copy(bytes) => {
            vm.region[*addr..][..bytes.len()].copy_from_slice(bytes);
        }
        WriteKind::Set { val, size } => {
            vm.region[*addr..][..*size].fill(*val);
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
            addr: self.offset,
            ty: WriteKind::Copy(bytes),
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
            addr: self.offset,
            ty: WriteKind::Copy(bytes),
        };
        write_op.commit();
        Ok(())
    }

    pub fn set_value(&mut self, val: u8) {
        let write_op = WriteOp {
            vm: self.vm,
            addr: self.offset,
            ty: WriteKind::Set {
                val,
                size: self.size,
            },
        };
        write_op.commit();
    }

    fn address(&self) -> u64 {
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
            addr,
            ty: WriteKind::Copy(bytes),
        };
        write_op.commit();
        Ok(())
    }

    pub fn write_slice(&mut self, addr: usize, bytes: &[u8]) -> Result<(), Error> {
        self.checked_get(addr, bytes.len())
            .ok_or(Error::OutOfBoundWrite)?;
        let write_op = WriteOp {
            vm: self,
            addr,
            ty: WriteKind::Copy(bytes),
        };
        write_op.commit();
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

        // let stack_size = 1024 * 1024 * 4;
        // let stack_addr = self.alloc(stack_size)?.address(); // + stack_size as u64;

        // // // Align stack.
        // let stack_addr = (stack_addr - 15) & !15;

        // // Required for arm chips as to invalid the instruction cache.
        let base_addr = self.address();
        sys_icache_invalidate(base_addr as *mut c_void, self.region.len());

        let entrypoint = base_addr + entrypoint;
        println!("Entering entrypoint at {entrypoint:#X}");

        let mut exit_code: i32;
        std::arch::asm!("
            blr {entry}
            ",
            entry = in(reg) entrypoint,
            in("w0") argv.len() - 1,
            in("x1") argv.as_ptr(),
            in("x2") envp.as_ptr(),
            lateout("w0") exit_code,
            clobber_abi("system"),
        );

        //
        // std::arch::asm!("
        //     blr x4

        //     // Handle the return value of main, call exit(),
        //     mov x8, #93
        //     svc #0",
        //     in("w0") 1i32,
        //     in("x1") argv_entry_addr,
        //     in("x2") envp_entry_addr,
        //     in("x3") stack_addr,
        //     in("x4") entrypoint,
        //     options(noreturn),
        // );

        Ok(exit_code)
    }
}

impl Drop for VM {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.region.as_mut_ptr() as *mut c_void, self.region.len()) };
    }
}
