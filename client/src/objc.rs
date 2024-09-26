use crate::loader::Error;
use crate::objc_ffi::*;
use crate::tls::ParsedMacho;
use object::read::macho::Section;
use object::LittleEndian as LE;
use std::collections::HashSet;
use std::ffi::CStr;
use std::mem::offset_of;
use std::os::raw::c_void;
use std::{mem, ptr};

fn parse_objc_section_list<T>(
    pm: &ParsedMacho,
    real_base_addr: u64,
    name: &[u8],
) -> &'static mut [*mut T] {
    let Some(section) = pm.sections.iter().find(|sec| sec.name() == name) else {
        return &mut [];
    };

    let start = real_base_addr + (section.addr(LE) - pm.base_addr);
    if section.size(LE) == 0 {
        return &mut [];
    }

    let len = section.size(LE) as usize / mem::size_of::<*mut T>();
    unsafe { std::slice::from_raw_parts_mut(start as *mut *mut T, len) }
}

pub unsafe fn map_images(pm: &ParsedMacho, real_base_addr: u64) -> Result<(), Error> {
    // Keep track of registered protocols to avoid duplicates
    let mut registered = HashSet::new();

    for proto in parse_objc_section_list::<protocol_t>(pm, real_base_addr, b"__objc_protolist") {
        register_protocol(&mut registered, *proto);
    }

    for class in parse_objc_section_list::<class_t>(pm, real_base_addr, b"__objc_classlist") {
        register_class(&mut registered, *class);
    }

    // for &cat in parse_objc_section_list::<class_t>(pm, real_base_addr, b"__objc_catlist") {
    //     register_category(cat)?;
    // }

    sel_registerName(c".cxx_construct".as_ptr());
    sel_registerName(c".cxx_destruct".as_ptr());

    for sel_ref in parse_objc_section_list::<i8>(pm, real_base_addr, b"__objc_selrefs") {
        let sel_name = CStr::from_ptr(*sel_ref);
        println!("Registering {sel_name:?}.");
        *sel_ref = sel_registerName(sel_name.as_ptr()) as *mut i8;
    }

    Ok(())
}

unsafe fn register_class(registered: &mut HashSet<&CStr>, class_ptr: *mut class_t) {
    let class = &*class_ptr;

    // Parse class data.
    let data_ptr = class.data & !0x7; // Clear flags.
    let ro = data_ptr as *const class_ro_t;

    let superclass = if !class.superclass.is_null() {
        let superclass_data_ptr = (*class.superclass).data & !0x7;
        let superclass_ro = superclass_data_ptr as *const class_ro_t;
        let superclass_name = (*superclass_ro).name;
        objc_getClass(superclass_name)
    } else {
        ptr::null_mut()
    };

    // dbg!(CStr::from_ptr((*ro).name));

    let new_class = objc_allocateClassPair(superclass, (*ro).name, 0);

    // Add protocols to the class.
    let protocol_list_ptr = (*ro).base_protocols;
    if !protocol_list_ptr.is_null() {
        let protocol_list = &*protocol_list_ptr;

        let count = protocol_list.count;
        let start = protocol_list_ptr.add(1) as *mut protocol_t;

        for idx in 0..count {
            let proto_ptr = start.add(idx as usize);
            class_addProtocol(new_class, proto_ptr);
        }
    }

    // Add methods to the class.
    let method_list_ptr = (*ro).base_methods;
    if !method_list_ptr.is_null() {
        for_each_method(method_list_ptr, |name_ptr, types_ptr, imp_ptr| {
            let sel = sel_registerName(*name_ptr);
            class_addMethod(new_class, sel, imp_ptr, types_ptr);
        });
    }

    // Add ivars, properties, etc., as needed
    // TODO: Parse ivars and add them using class_addIvar
    objc_registerClassPair(new_class);
}

unsafe fn register_protocol(registered: &mut HashSet<&CStr>, proto_ptr: *mut protocol_t) {
    let proto = &*proto_ptr;

    if !proto.name.is_null() {
        println!("BUG");
        return;
    }

    let proto_name_cstr = CStr::from_ptr(proto.name);

    if registered.contains(&proto_name_cstr) {
        return;
    }

    let new_protocol = objc_allocateProtocol(proto.name);

    // Protocol with the same name as name already exists.
    if new_protocol.is_null() {
        return;
    }

    // Register adopted protocols.
    if !proto.protocols.is_null() {
        let adopted_protocols_ptr = proto.protocols;
        let adopted_protocols = &*adopted_protocols_ptr;

        let count = adopted_protocols.count as usize;
        let start = adopted_protocols_ptr.add(1) as *mut protocol_t;

        for idx in 0..count {
            let adopted_proto_ptr = start.add(idx);

            // Recursively register adopted protocols,
            register_protocol(registered, adopted_proto_ptr);

            let adopted_proto_name_ptr = (*adopted_proto_ptr).name;
            let adopted_protocol = objc_getProtocol(adopted_proto_name_ptr);
            if !adopted_protocol.is_null() {
                protocol_addProtocol(new_protocol, adopted_protocol);
            }
        }
    }

    if !proto.instance_methods.is_null() {
        register_protocol_methods(new_protocol, proto.instance_methods, false, true);
    }

    if !proto.class_methods.is_null() {
        register_protocol_methods(new_protocol, proto.class_methods, false, false);
    }

    if !proto.optional_instance_methods.is_null() {
        register_protocol_methods(new_protocol, proto.optional_instance_methods, true, true);
    }

    if !proto.optional_class_methods.is_null() {
        register_protocol_methods(new_protocol, proto.optional_class_methods, true, false);
    }

    if !proto.instance_properties.is_null() {
        register_protocol_properties(new_protocol, proto.instance_properties, false, true);
    }

    objc_registerProtocol(new_protocol);
    registered.insert(proto_name_cstr);
}

unsafe fn register_protocol_methods(
    protocol: *mut protocol_t,
    method_list_ptr: *const method_list_t,
    is_optional: bool,
    is_instance_method: bool,
) {
    for_each_method(method_list_ptr, |name_ptr, types_ptr, _| {
        protocol_addMethodDescription(
            protocol,
            name_ptr,
            types_ptr,
            !is_optional as i32,
            is_instance_method as i32,
        );
    });
}

unsafe fn register_protocol_properties(
    protocol: *mut protocol_t,
    property_list_ptr: *const property_list_t,
    is_optional: bool,
    is_instance_property: bool,
) {
    let property_list = &*property_list_ptr;

    let count = property_list.count as usize;
    let size = (property_list.entsize_and_flags & !3) as usize;
    let start = property_list_ptr.add(1);

    for idx in 0..count {
        let property_ptr = start.byte_add(idx * size) as *const property_t;
        let property = &*property_ptr;

        let mut attrs_count = 0;
        dbg!(CStr::from_ptr(property.name));
        let attrs_ptr = property_copyAttributeList(property_ptr, &mut attrs_count);

        protocol_addProperty(
            protocol,
            property.name,
            attrs_ptr,
            attrs_count,
            is_optional as i32,
            is_instance_property as i32,
        );
    }
}

unsafe fn for_each_method<F>(method_list_ptr: *const method_list_t, f: F)
where
    F: Fn(*mut *const i8, *const i8, *const c_void),
{
    let method_list = &*method_list_ptr;

    let count = method_list.count as usize;
    let size = (method_list.entsize_and_flags & 0xFFFF) as usize;
    let start = method_list_ptr.add(1);

    assert!(
        method_list.entsize_and_flags & 0x40000000 == 0,
        "direct offsets not supported"
    );

    if size == mem::size_of::<method_t_ptr>() {
        for idx in 0..count {
            let method_ptr = (start as *const method_t_ptr).add(idx);
            let method = &*method_ptr;

            // dbg!(method);
            // dbg!(CStr::from_ptr(method.types));
            // dbg!(CStr::from_ptr(*method.name));
            f(method.name, method.types, method.imp);
        }

        return;
    }

    if size == mem::size_of::<method_t_rel>() {
        for idx in 0..count {
            let method_ptr = (start as *const method_t_rel).add(idx);
            let method = &*method_ptr;

            // Adjust relative pointers.
            let name_ptr = method.name.resolve(method_ptr, offset_of!(method_t_rel, name));
            let types_ptr = method.types.resolve(method_ptr, offset_of!(method_t_rel, types));
            let imp_ptr = method.imp.resolve(method_ptr, offset_of!(method_t_rel, imp));

            f(name_ptr, types_ptr, imp_ptr);
        }

        return;
    }

    panic!("Invalid method_t of size: {size}");
}
