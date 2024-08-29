use crate::loader::Error;
use crate::tls::ParsedMacho;
use object::read::macho::Section;
use object::LittleEndian as LE;
use std::mem;
use std::ffi::CStr;

type SEL = *const *const i8;

#[link(name = "objc")]
extern "C" {
    fn sel_registerName(str: *const i8) -> SEL;
}

fn obj_sels<'data>(pm: &ParsedMacho, real_base_addr: u64) -> Result<&'data mut [SEL], Error> {
    let section = pm
        .sections
        .iter()
        .filter(|sec| matches!(sec.name(), b"__objc_selrefs"))
        .next()
        .ok_or(Error::NotObjc)?;

    let start = real_base_addr + (section.addr(LE) - pm.base_addr);
    if section.size(LE) == 0 {
        return Ok(&mut []);
    }
    let len = section.size(LE) as usize / mem::size_of::<SEL>();
    Ok(unsafe { std::slice::from_raw_parts_mut(start as *mut SEL, len) })
}

pub fn map_images(pm: &ParsedMacho, real_base_addr: u64) -> Result<(), Error> {
    for sel in obj_sels(pm, real_base_addr)? {
        unsafe {
            let sel_name = CStr::from_ptr(*sel as *const i8);
            println!("Registering {sel_name:?} to the objc runtime.");
            let new_sel = sel_registerName(sel_name.as_ptr());
            *sel = new_sel;
        }
    }

    Ok(())
}
