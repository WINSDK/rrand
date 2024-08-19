use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};

#[derive(Debug)]
pub enum Error {
    Bind,
    StreamRead,
    StreamWrite,
    StreamClosed,
    PubkeyCorrupt,
    Encryption,
}

struct Payload {
    macho: Vec<u8>,
}

// required order for packets:
//
// <- pubkey       (plain)
// -> payload size (encrypted)
//
fn handle_client(mut stream: TcpStream, payload: Arc<Payload>) -> Result<(), Error> {
    let mut rng = rand::thread_rng();

    let mut pubkey = [0; 451];
    stream
        .read_exact(&mut pubkey)
        .map_err(|_| Error::StreamRead)?;

    let pubkey = std::str::from_utf8(&pubkey).map_err(|_| Error::PubkeyCorrupt)?;
    let pubkey = RsaPublicKey::from_public_key_pem(&pubkey).map_err(|_| Error::PubkeyCorrupt)?;
    println!("Received pubkey.");

    let payload_len = (payload.macho.len() as u64).to_be_bytes();
    let payload_len = pubkey
        .encrypt(&mut rng, Pkcs1v15Encrypt, &payload_len)
        .map_err(|_| Error::Encryption)?;
    stream
        .write_all(&payload_len)
        .map_err(|_| Error::StreamWrite)?;
    println!("Send payload size.");

    Ok(())
}

fn main() -> Result<(), Error> {
    let payload = Arc::new(Payload {
        macho: vec![0, 1, 2, 3],
    });

    let listener = TcpListener::bind("0.0.0.0:3771").map_err(|_| Error::Bind)?;
    println!("Listening on port 3771...");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let payload = Arc::clone(&payload);
                std::thread::spawn(|| {
                    if let Err(err) = handle_client(stream, payload) {
                        eprintln!("Client failed with: '{err:?}'.");
                    }
                });
            }
            Err(e) => eprintln!("Failed to accept a connection: {}", e),
        }
    }

    Ok(())
}
