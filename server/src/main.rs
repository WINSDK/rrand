use shared::{Error, PublicKey, SecretKey};
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

fn read_bin() -> Vec<u8> {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../bundle");

    let mut file = std::fs::File::open(path).unwrap();
    let mut macho = Vec::new();
    file.read_to_end(&mut macho).unwrap();
    macho
}

fn handle_client(
    mut stream: TcpStream,
    secret_key: &SecretKey,
    public_key: &PublicKey,
) -> Result<(), Error> {
    let sym_key = shared::exchange_keys(&mut stream, secret_key, public_key)?;

    let binary = read_bin();
    shared::net::send(&mut stream, &sym_key, &binary)?;
    println!("Send binary of size {:#X}.", binary.len());

    Ok(())
}

fn main() -> Result<(), Error> {
    let listener = TcpListener::bind("0.0.0.0:3771").map_err(|_| Error::Bind)?;
    println!("Listening on port 3771...");

    let (public_key, secret_key) = shared::gen_keypair();
    let (public_key, secret_key) = (Arc::new(public_key), Arc::new(secret_key));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let secret_key = Arc::clone(&secret_key);
                let public_key = Arc::clone(&public_key);
                std::thread::spawn(move || {
                    if let Err(err) = handle_client(stream, &secret_key, &public_key) {
                        eprintln!("Client failed with: '{err:?}'.");
                    }
                });
            }
            Err(e) => eprintln!("Failed to accept a connection: {}", e),
        }
    }

    Ok(())
}
