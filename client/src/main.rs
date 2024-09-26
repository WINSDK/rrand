use std::net::TcpStream;
use std::time::Duration;

use loader::VM;
use object::{macho, Object, ObjectSegment};
use object::read::macho::MachOFile64;
use object::LittleEndian as LE;
use shared::Error;

mod tls;
mod objc;
mod objc_ffi;
mod relocs;
mod loader;

pub type MachO<'data> = MachOFile64<'data, LE>;

pub fn parse_base_addr(obj: &MachO) -> u64 {
    for segment in obj.segments() {
        if let Ok(Some(b"__TEXT")) = segment.name_bytes() {
            return segment.address();
        }
    }

    0
}

fn write_flattened_binary(obj: &MachO) -> Result<VM, loader::Error> {
    let mut segments = Vec::new();
    for segment in obj.segments() {
        if let Ok(Some("__PAGEZERO")) = segment.name() {
            continue;
        }
        segments.push((segment.address(), segment.size(), segment.data().unwrap()));
    }

    if segments.is_empty() {
        panic!("empty binary");
    }

    segments.sort_unstable_by_key(|&(addr, ..)| addr);

    // let size_estimate = (segments[segments.len() - 1].0 - segments[0].0) as usize;
    let mut vm = VM::new(1024 * 1024 * 64)?;

    let mut end_of_prev_segment = segments[0].0;
    for (addr, _, bytes) in segments {
        let pad_size = addr - end_of_prev_segment;
        if pad_size > 0 {
            vm.alloc(pad_size as usize)?.set_value(0);
        }
        let mut alloc = vm.alloc(bytes.len())?;
        alloc.write_slice(bytes)?;
        end_of_prev_segment = addr + bytes.len() as u64;
    }

    Ok(vm)
}

fn connect() -> Result<TcpStream, Error> {
    let addr = "0.0.0.0:3771".parse().unwrap();
    let timeout = Duration::from_secs(3);
    let stream = TcpStream::connect_timeout(&addr, timeout).map_err(|_| Error::Connect)?;
    println!("Connected to the server!");

    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    Ok(stream)
}

fn main() -> Result<(), Error> {
    let mut stream = connect()?;

    let (public_key, secret_key) = shared::gen_keypair();
    let sym_key = shared::exchange_keys(&mut stream, &secret_key, &public_key)?;

    let binary = shared::net::recv(&mut stream, &sym_key)?;
    println!("Received binary of size {:#X}.", binary.len());

    let obj = MachO::parse(&*binary).unwrap();

    for lcmd in obj.macho_load_commands().unwrap() {
        if let Ok(macho::LC_DYLD_INFO | macho::LC_DYLD_INFO_ONLY) = lcmd.map(|cmd| cmd.cmd()) {
            panic!("Traditional dynamic relocations aren't supported, \
                    only codegen by xcode >= 12.0.")
        }
    }

    let mut vm = write_flattened_binary(&obj).unwrap();

    vm.relocate(&obj).unwrap();
    vm.set_protection(&obj).unwrap();
    vm.init_objc_runtime(&obj).unwrap();
    vm.run_initializers(&obj).unwrap();

    // 0x0000000000002344
    let exit_code = unsafe { vm.exec(0x0000000000002344).unwrap() };
    println!("Program exited with code: {exit_code}");

    Ok(())
}
