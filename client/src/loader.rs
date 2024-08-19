#![allow(dead_code)]

use std::sync::LazyLock;
use std::ffi::c_void;
use std::ptr;
use std::mem;

use object::{pod, Pod};

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

#[used]
#[link_section = "__DATA_CONST,__pth_jit_func"]
static PTHREAD_JIT_WRITE_CALLBACK_ALLOWLIST: &[libc::pthread_jit_write_callback_t] =
    &[Some(writing_callback), None];

enum WriteOpTy<'a> {
    Copy(&'a [u8]),
    Set { val: u8, size: usize },
}

struct WriteOp<'a> {
    vm: &'a mut VM,
    addr: usize,
    ty: WriteOpTy<'a>,
}

extern "C" fn writing_callback(ctx: *mut c_void) -> i32 {
    let WriteOp { vm, addr, ty } = unsafe { &mut *(ctx as *mut WriteOp) };

    match ty {
        WriteOpTy::Copy(bytes) => {
            vm.region[*addr..][..bytes.len()].copy_from_slice(bytes);
        }
        WriteOpTy::Set { val, size } => {
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
            ty: WriteOpTy::Copy(bytes),
        };
        write_op.commit();
        Ok(())
    }

    pub fn set_value(&mut self, val: u8) {
        let write_op = WriteOp {
            vm: self.vm,
            addr: self.offset,
            ty: WriteOpTy::Set {
                val,
                size: self.size,
            },
        };
        write_op.commit();
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

    #[inline]
    fn checked_get(&self, addr: usize, size: usize) -> Option<&[u8]> {
        self.region.get(addr..)?.get(..size)
    }

    pub fn alloc(&mut self, size: usize) -> Result<Allocation, Error> {
        self.checked_get(self.offset, size).ok_or(Error::OutOfMemory)?;
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
            ty: WriteOpTy::Copy(bytes),
        };
        write_op.commit();
        Ok(())
    }

    pub fn write_slice(&mut self, addr: usize, bytes: &[u8]) -> Result<(), Error> {
        self.checked_get(addr, bytes.len()).ok_or(Error::OutOfBoundWrite)?;
        let write_op = WriteOp {
            vm: self,
            addr,
            ty: WriteOpTy::Copy(bytes),
        };
        write_op.commit();
        Ok(())
    }

    pub unsafe fn exec(mut self, entrypoint: usize) -> Result<(), Error> {
        let stack_size = 1024 * 1024 * 4;
        let stack = self.alloc(stack_size)?;

        // Compute the stack address
        //
        // Stack upon _start should be:
        // [END OF STACK]
        // [NULL pointer (end of argv)]
        // [argv...]
        // [argc: u32]

        let argc = 1i32;
        let argv = 0;

        let entrypoint = self.region.as_ptr().add(entrypoint);
        println!("entrypoint loaded at {entrypoint:p}");

        // ret.regs[2] = stack + STACK_SIZE - 0x8 - (argv.len() * 4) as u32;
        // The program must be the first thing allocated, therefore
        // the entrypoint must be an offset into the beginning of memory.
        // std::arch::asm!(
        //     "blr {entry}",
        //     entry = in(reg) self.region.as_ptr().add(entrypoint),
        //     in("w0") argc,
        //     in("x1") arg2,
        //     in("x2") arg3,
        //     clobber_abi("system")
        // );

        Ok(())
    }
}

impl Drop for VM {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.region.as_mut_ptr() as *mut c_void, self.region.len()) };
    }
}
