use std::ffi::c_void;
use std::mem;
use std::sync::OnceLock;
use crate::loader::Error;

use object::macho::{self, Section64};
use object::read::macho::{MachOFile64, Section};
use object::{LittleEndian as LE, Object};

#[derive(Clone)]
struct Context {
    pm: ParsedMacho,
    real_base_addr: u64,
}

#[derive(Clone)]
pub struct ParsedMacho {
    base_addr: u64,
    sections: Vec<Section64<LE>>,
}

impl ParsedMacho {
    pub fn from_obj(obj: &MachOFile64<LE>) -> Self {
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
    thunk: extern "C" fn(&mut TLVDescriptor) -> *mut c_void,
    key: libc::pthread_key_t,
    offset: u64,
}

static CTX: OnceLock<Context> = OnceLock::new();

extern "C" fn tlv_get_addr(desc: &mut TLVDescriptor) -> *mut c_void {
    let mut buffer = unsafe { libc::pthread_getspecific(desc.key) };

    if buffer.is_null() {
        buffer = tlv_allocate_and_initialize_for_key(desc.key);
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

#[no_mangle]
pub extern "C" fn tlv_allocate_and_initialize_for_key(key: libc::pthread_key_t) -> *mut c_void {
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
        let layout = std::alloc::Layout::array::<u8>(size as usize).unwrap();
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
            let len = section.size(LE) as usize / mem::size_of::<extern "C" fn()>();
            let funcs = unsafe { std::slice::from_raw_parts(start as *const extern "C" fn(), len) };
            for func in funcs {
                func();
            }
        }
    }

    buffer
}
