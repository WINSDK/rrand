use std::ffi::c_void;
use std::mem;
use std::sync::OnceLock;

use object::macho::{self, Section64};
use object::read::macho::Section;
use object::{LittleEndian as LE, Object};

use crate::loader::Error;
use crate::MachO;

#[derive(Clone)]
struct Context {
    pm: ParsedMacho,
    real_base_addr: u64,
}

#[derive(Clone)]
pub struct ParsedMacho {
    pub base_addr: u64,
    pub sections: Vec<Section64<LE>>,
}

impl ParsedMacho {
    pub fn from_obj(obj: &MachO) -> Self {
        let sections = obj.sections().map(|sec| *sec.macho_section()).collect();
        let base_addr = crate::parse_base_addr(obj);
        Self {
            base_addr,
            sections,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TLVDescriptor {
    thunk: unsafe extern "C" fn(&mut TLVDescriptor) -> *mut c_void,
    key: libc::pthread_key_t,
    offset: u64,
}

static CTX: OnceLock<Context> = OnceLock::new();

extern "C" {
    fn tlv_get_addr(desc: &mut TLVDescriptor) -> *mut c_void;
}

std::arch::global_asm!("
	// Parameters: X0 = descriptor
	// Result:  X0 = address of TLV
	// Note: all registers except X0, x16, and x17 are preserved
	.align 2
	.globl _tlv_get_addr
	.private_extern _tlv_get_addr
_tlv_get_addr:
	ldr		x16, [x0, #8]			// get key from descriptor
	mrs		x17, TPIDRRO_EL0
	and		x17, x17, #-8			// clear low 3 bits???
	ldr		x17, [x17, x16, lsl #3]	// get thread allocation address for this key
	cbz		x17, LlazyAllocate		// if NULL, lazily allocate
	ldr		x16, [x0, #16]			// get offset from descriptor
	add		x0, x17, x16			// return allocation+offset
	ret		lr

LlazyAllocate:
	stp		fp, lr, [sp, #-16]!
	mov		fp, sp
	sub		sp, sp, #288
	stp		x1, x2, [sp, #-16]!		// save all registers that C function might trash
	stp		x3, x4, [sp, #-16]!
	stp		x5, x6, [sp, #-16]!
	stp		x7, x8, [sp, #-16]!
	stp		x9, x10,  [sp, #-16]!
	stp		x11, x12, [sp, #-16]!
	stp		x13, x14, [sp, #-16]!
	stp		x15, x16, [sp, #-16]!
	stp		q0,  q1,  [sp, #-32]!
	stp		q2,  q3,  [sp, #-32]!
	stp		q4,  q5,  [sp, #-32]!
	stp		q6,  q7,  [sp, #-32]!
	stp		x0, x17,  [sp, #-16]!	// save descriptor

	mov		x0, x16					// use key from descriptor as parameter
	bl		_tlv_allocate_and_initialize_for_key
	ldp		x16, x17, [sp], #16		// pop descriptor
	ldr		x16, [x16, #16]			// get offset from descriptor
	add		x0, x0, x16				// return allocation+offset

	ldp		q6,  q7,  [sp], #32
	ldp		q4,  q5,  [sp], #32
	ldp		q2,  q3,  [sp], #32
	ldp		q0,  q1,  [sp], #32
	ldp		x15, x16, [sp], #16
	ldp		x13, x14, [sp], #16
	ldp		x11, x12, [sp], #16
	ldp		x9, x10,  [sp], #16
	ldp		x7, x8, [sp], #16
	ldp		x5, x6, [sp], #16
	ldp		x3, x4, [sp], #16
	ldp		x1, x2, [sp], #16

	mov		sp, fp
	ldp		fp, lr, [sp], #16
	ret		lr
");

#[no_mangle]
extern "C" fn tlv_allocate_and_initialize_for_key(key: libc::pthread_key_t) -> *mut c_void {
    let Context { real_base_addr, pm } = CTX.get().expect("tlv_initialize_descriptors not called");

    let mut has_initializers = false;
    let mut start = 0;
    let mut size = 0;
    for section in &pm.sections {
        let flags = section.flags.get(LE);

        match flags & macho::SECTION_TYPE {
            macho::S_THREAD_LOCAL_INIT_FUNCTION_POINTERS => {
                has_initializers = true;
            }
            macho::S_THREAD_LOCAL_ZEROFILL | macho::S_THREAD_LOCAL_REGULAR => {
                if start == 0 {
                    start = real_base_addr + (section.addr(LE) - pm.base_addr);
                }
                size += section.size(LE);
                break;
            }
            _ => continue,
        }
    }

    if start == 0 || size == 0 {
        unreachable!();
    }

    let buffer = unsafe {
        let layout = std::alloc::Layout::array::<u8>(size as usize)
            .expect("TLV of too large of invalid size");
        let alloc = std::alloc::alloc(layout);
        std::ptr::copy_nonoverlapping(start as *mut u8, alloc, size as usize);
        alloc as *mut c_void
    };

    if unsafe { libc::pthread_setspecific(key, buffer) } != 0 {
        panic!("TLV init from unknown thread");
    }

    if !has_initializers {
        return buffer;
    }

    for section in &pm.sections {
        let flags = section.flags(LE);

        if flags & macho::SECTION_TYPE == macho::S_THREAD_LOCAL_INIT_FUNCTION_POINTERS {
            let start = real_base_addr + (section.addr(LE) - pm.base_addr);
            if section.size(LE) == 0 {
                continue;
            }
            let len = section.size(LE) as usize / mem::size_of::<extern "C" fn()>();
            let funcs = unsafe { std::slice::from_raw_parts(start as *const extern "C" fn(), len) };
            for func in funcs {
                func();
            }
        }
    }

    buffer
}

// Called by main thread.
pub fn tlv_initialize_descriptors(pm: &ParsedMacho, real_base_addr: u64) -> Result<(), Error> {
    println!("Initializing TLV.");

    let mut has_tls = false;
    for section in &pm.sections {
        let sec_type = section.flags(LE) & macho::SECTION_TYPE;

        if sec_type == macho::S_THREAD_LOCAL_VARIABLES && section.size(LE) != 0 {
            has_tls = true;
            break;
        }
    }

    if !has_tls {
        return Ok(());
    }

    let mut key = 0;
    for section in &pm.sections {
        let flags = section.flags(LE);

        if flags & macho::SECTION_TYPE != macho::S_THREAD_LOCAL_VARIABLES {
            continue;
        }

        if section.size(LE) == 0 {
            continue;
        }

        if key == 0 {
            if unsafe { libc::pthread_key_create(&mut key, Some(libc::free)) } != 0 {
                return Err(Error::InitTLV);
            }
        }

        let addr = real_base_addr + (section.addr(LE) - pm.base_addr);

        for offset in (0..section.size(LE)).step_by(mem::size_of::<TLVDescriptor>()) {
            let tlv_desc = unsafe { &mut *((addr + offset) as *mut TLVDescriptor) };
            tlv_desc.thunk = tlv_get_addr;
            tlv_desc.key = key;
        }
    }

    let _ = CTX.set(Context {
        pm: pm.clone(),
        real_base_addr,
    });

    Ok(())
}
