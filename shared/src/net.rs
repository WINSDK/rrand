use std::io::{Write, Read};
use std::net::TcpStream;
use chacha20poly1305::{Key, Nonce};
use p256::{EncodedPoint, PublicKey};

use crate::Error;

pub fn send(stream: &mut TcpStream, key: &Key, plaintext: &[u8]) -> Result<(), Error> {
    let (nonce, ciphertext) = super::encrypt_data(plaintext, key)?;

    stream
        .write_all(&nonce)
        .map_err(|_| Error::StreamWrite)?;
    stream
        .write_all(&(ciphertext.len() as u64).to_le_bytes())
        .map_err(|_| Error::StreamWrite)?;
    stream
        .write_all(&ciphertext)
        .map_err(|_| Error::StreamWrite)?;

    Ok(())
}

pub fn recv(stream: &mut TcpStream, key: &Key) -> Result<Vec<u8>, Error> {
    let mut nonce = Nonce::default();
    stream
        .read_exact(nonce.as_mut_slice())
        .map_err(|_| Error::StreamRead)?;

    let mut cipher_len = [0; 8];
    stream
        .read_exact(&mut cipher_len)
        .map_err(|_| Error::StreamRead)?;
    let cipher_len = u64::from_le_bytes(cipher_len) as usize;

    let mut ciphertext = vec![0; cipher_len];
    stream
        .read_exact(&mut ciphertext)
        .map_err(|_| Error::StreamRead)?;

    super::decrypt_data(&ciphertext, key, &nonce)
}

pub (crate) fn send_pubkey(stream: &mut TcpStream, public_key: &PublicKey) -> Result<(), Error> {
    let encoded_pubkey = EncodedPoint::from(public_key);
    stream
        .write_all(&(encoded_pubkey.len() as u64).to_le_bytes())
        .map_err(|_| Error::StreamWrite)?;
    stream
        .write_all(encoded_pubkey.as_bytes())
        .map_err(|_| Error::StreamWrite)?;
    println!("Send public key.");

    Ok(())
}

pub (crate) fn recv_pubkey(stream: &mut TcpStream) -> Result<PublicKey, Error> {
    let mut pubkey_len = [0; 8];
    stream
        .read_exact(&mut pubkey_len)
        .map_err(|_| Error::StreamRead)?;
    let pubkey_len = u64::from_le_bytes(pubkey_len) as usize;

    let mut pubkey = vec![0; pubkey_len];
    stream
        .read_exact(&mut pubkey)
        .map_err(|_| Error::StreamRead)?;
    println!("Received public key.");

    PublicKey::from_sec1_bytes(&pubkey)
        .map_err(|_| Error::PubkeyCorrupt)
}
