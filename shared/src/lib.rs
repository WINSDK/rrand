use std::net::TcpStream;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use chacha20poly1305::aead::Aead;
use hkdf::Hkdf;
use rand_core::RngCore;

pub use p256::ecdh::SharedSecret;
pub use p256::{PublicKey, SecretKey};

pub mod net;

#[derive(Debug)]
pub enum Error {
    Bind,
    Connect,
    StreamRead,
    StreamWrite,
    StreamClosed,
    PubkeyCorrupt,
    Encryption,
    Decription,
}

pub fn gen_keypair() -> (PublicKey, SecretKey) {
    let secret_key = SecretKey::random(&mut rand_core::OsRng);
    (secret_key.public_key(), secret_key)
}

fn derive_symmetric_key(shared_secret: SharedSecret) -> Key {
    let hkdf = Hkdf::<sha2::Sha256>::new(None, shared_secret.raw_secret_bytes());
    let mut okm = [0; 32];
    hkdf.expand(b"chacha20-key", &mut okm).unwrap();
    Key::from(okm)
}

pub fn exchange_keys(stream: &mut TcpStream, secret_key: &SecretKey, public_key: &PublicKey) -> Result<Key, Error> {
    net::send_pubkey(stream, public_key)?;
    let client_public_key = net::recv_pubkey(stream)?;
    let shared_secret = p256::ecdh::diffie_hellman(
        secret_key.to_nonzero_scalar(),
        client_public_key.as_affine()
    );
    Ok(derive_symmetric_key(shared_secret))
}

pub fn encrypt_data(plaintext: &[u8], key: &Key) -> Result<(Nonce, Vec<u8>), Error> {
    let mut nonce = [0; 12];
    rand_core::OsRng.fill_bytes(&mut nonce);
    let nonce = Nonce::from(nonce);

    let cipher = ChaCha20Poly1305::new(key);
    let ciphertext = cipher.encrypt(&nonce, plaintext)
        .map_err(|_| Error::Encryption)?;

    Ok((nonce, ciphertext))
}

pub fn decrypt_data(ciphertext: &[u8], key: &Key, nonce: &Nonce) -> Result<Vec<u8>, Error> {
    let cipher = ChaCha20Poly1305::new(key);
    cipher.decrypt(nonce, ciphertext).map_err(|_| Error::Decription)
}
