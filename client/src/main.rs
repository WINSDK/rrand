use std::net::TcpStream;
use std::time::Duration;

use loader::VM;
use object::{macho, Object, ObjectSegment};
use object::read::macho::MachOFile64;
use object::LittleEndian as LE;
use shared::Error;

mod relocs;
mod loader;

fn write_flattened_binary(obj: &MachOFile64<LE>) -> Result<VM, loader::Error> {
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
        println!("segment allocated at {:#X}", alloc.address());
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

    let obj = MachOFile64::parse(&*binary).unwrap();

    for lcmd in obj.macho_load_commands().unwrap() {
        if let Ok(macho::LC_DYLD_INFO | macho::LC_DYLD_INFO_ONLY) = lcmd.map(|cmd| cmd.cmd()) {
            panic!("Traditional dynamic relocations aren't supported, \
                    only codegen by xcode >= 12.0.")
        }
    }

    let mut vm = write_flattened_binary(&obj).unwrap();

    vm.relocate(&obj).unwrap();
    vm.exec_init_funcs(&obj).unwrap();

    let exit_code = unsafe { vm.exec(obj.entry()).unwrap() };
    println!("Program exited with code: {exit_code}");

    Ok(())
}
