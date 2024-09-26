#![allow(non_camel_case_types)]

use std::ffi::c_void;
use std::marker::PhantomData;

#[link(name = "objc")]
extern "C" {
    pub fn sel_registerName(str: *const i8) -> *const i8;

    pub fn objc_getClass(name: *const i8) -> *mut class_t;
    pub fn objc_getProtocol(name: *const i8) -> *mut protocol_t;

    pub fn objc_registerProtocol(proto: *mut protocol_t);
    pub fn objc_allocateProtocol(name: *const i8) -> *mut protocol_t;

    pub fn objc_registerClassPair(class: *mut class_t);
    pub fn objc_allocateClassPair(
        superclass: *const class_t, 
        name: *const i8, 
        extraBytes: usize
    ) -> *mut class_t;

    pub fn class_getName(class: *mut class_t) -> *const i8;

    pub fn class_addProtocol(
        cls: *mut class_t, 
        proto: *const protocol_t
    ) -> i32;
    pub fn class_addMethod(
        cls: *mut class_t, 
        name: *const i8, 
        imp: *const c_void, 
        types: *const i8
    ) -> i32;

    pub fn protocol_addProtocol(proto: *mut protocol_t, addition: *mut protocol_t);
    pub fn protocol_addProperty(
        proto: *mut protocol_t,
        name: *const i8,
        attributes: *const c_void,
        attributeCount: u32,
        isRequiredProperty: i32,
        isInstanceProperty: i32,
    );
    pub fn protocol_addMethodDescription(
        proto: *mut protocol_t,
        name: *mut *const i8,
        types: *const i8,
        isRequiredMethod: i32,
        isInstanceMethod: i32,
    );

    pub fn property_copyAttributeList(
        property: *const property_t, 
        outCount: *mut u32
    ) -> *mut c_void;
}

#[repr(C)]
pub struct class_t {
    pub isa: *mut class_t,
    pub superclass: *mut class_t,
    pub cache: usize,
    pub vtable: usize,
    pub data: usize, // class_rw_t *
}

#[repr(C)]
pub struct class_ro_t {
    pub flags: u32,
    pub instance_start: u32,
    pub instance_size: u32,
    pub reserved: u32,
    pub ivar_layout: *const u8,
    pub name: *const i8,
    pub base_methods: *const method_list_t,
    pub base_protocols: *const protocol_list_t,
    pub ivars: *const c_void,
    pub weak_ivar_layout: *const u8,
    pub base_properties: *const property_list_t,
}

#[repr(C)]
pub struct method_list_t {
    pub entsize_and_flags: u32,
    pub count: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct method_t_rel {
    pub name: RVA<*const i8>,
    pub types: RVA<i8>,
    pub imp: RVA<c_void>,
}

#[repr(C)]
#[derive(Debug)]
pub struct method_t_ptr {
    pub name: *mut *const i8,
    pub types: *mut i8,
    pub imp: *mut c_void,
}

#[repr(C)]
pub struct protocol_list_t {
    pub count: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct protocol_t {
    pub isa: *mut class_t,
    pub name: *const i8,
    pub protocols: *mut protocol_list_t,
    pub instance_methods: *mut method_list_t,
    pub class_methods: *mut method_list_t,
    pub optional_instance_methods: *mut method_list_t,
    pub optional_class_methods: *mut method_list_t,
    pub instance_properties: *mut property_list_t,
    pub size: u32,
    pub flags: u32,
    // Fields below this point are not always present on disk.
    pub extended_method_types: *mut c_void,
    pub demangled_name: *const i8,
    pub class_properties: *mut property_list_t,
}

#[repr(C)]
pub struct property_list_t {
    pub entsize_and_flags: u32,
    pub count: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct property_t {
    pub name: *const i8,
    pub attrs: *mut c_void,
}

#[derive(Debug)]
#[repr(transparent)]
pub struct RVA<T>(pub u32, pub PhantomData<T>);

impl<T> RVA<T> {
    #[inline]
    pub fn resolve<U>(&self, base_ptr: *const U, field_offset: usize) -> *mut T {
        unsafe { (base_ptr as *mut T).byte_add(self.0 as usize).byte_add(field_offset) }
    }
}
