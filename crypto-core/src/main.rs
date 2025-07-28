use oqs::kem::{Algorithm, Kem};
use std::fs::{self, File};
use std::io::Read;
use std::env;
use serde::{Serialize, Deserialize};
use anyhow::{Result, Context};
use aes_gcm::aead::{Aead, KeyInit, OsRng, generic_array::GenericArray};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;

#[derive(Serialize, Deserialize)]
struct KeyStore {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

fn generate_keys() -> Result<KeyStore> {
    let kem = Kem::new(Algorithm::Kyber512)
        .context("Failed to create KEM instance")?;
    let (public_key, secret_key) = kem.keypair()
        .context("Failed to generate keypair")?;
    Ok(KeyStore {
        public_key: public_key.into_vec(),
        secret_key: secret_key.into_vec(),
    })
}

fn encrypt_file(input_path: &str, output_path: &str, public_key: &[u8]) -> Result<()> {
    let kem = Kem::new(Algorithm::Kyber512)
        .context("Failed to create KEM instance")?;

    let mut file = File::open(input_path)
        .with_context(|| format!("Failed to open input file: {}", input_path))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .with_context(|| format!("Failed to read input file: {}", input_path))?;

    let pk = kem.public_key_from_bytes(public_key)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse public key"))?;

    let (ciphertext, shared_secret) = kem.encapsulate(&pk)
        .context("Failed to encapsulate")?;

    let key = GenericArray::from_slice(shared_secret.as_ref());
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    
    let encrypted_data = cipher.encrypt(nonce, data.as_ref())
        .map_err(|e| anyhow::anyhow!("AES encryption failed: {}", e))?;

    let mut output = Vec::new();
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(ciphertext.as_ref());
    output.extend_from_slice(&encrypted_data);

    fs::write(output_path, &output)
        .with_context(|| format!("Failed to write output file: {}", output_path))?;

    Ok(())
}

fn decrypt_file(input_path: &str, output_path: &str, secret_key: &[u8]) -> Result<()> {
    let kem = Kem::new(Algorithm::Kyber512)
        .context("Failed to create KEM instance")?;

    let mut file = File::open(input_path)
        .with_context(|| format!("Failed to open input file: {}", input_path))?;
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data)
        .with_context(|| format!("Failed to read input file: {}", input_path))?;

    let nonce = &encrypted_data[..12];
    let ciphertext_len = 768;
    let ciphertext = &encrypted_data[12..12 + ciphertext_len];
    let aes_data = &encrypted_data[12 + ciphertext_len..];

    let sk = kem.secret_key_from_bytes(secret_key)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse secret key"))?;

    let ct = kem.ciphertext_from_bytes(ciphertext)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse ciphertext"))?;

    let shared_secret = kem.decapsulate(&sk, &ct)
        .context("Failed to decapsulate")?;

    let key = GenericArray::from_slice(shared_secret.as_ref());
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(nonce);
    
    let decrypted_data = cipher.decrypt(nonce, aes_data.as_ref())
        .map_err(|e| anyhow::anyhow!("AES decryption failed: {}", e))?;

    fs::write(output_path, decrypted_data)
        .with_context(|| format!("Failed to write output file: {}", output_path))?;

    Ok(())
}

fn save_keystore(keystore: &KeyStore, path: &str) -> Result<()> {
    let json = serde_json::to_string(keystore)
        .context("Failed to serialize keystore")?;
    fs::write(path, json)
        .with_context(|| format!("Failed to write keystore file: {}", path))?;
    Ok(())
}

fn load_keystore(path: &str) -> Result<KeyStore> {
    let json = fs::read_to_string(path)
        .with_context(|| format!("Failed to read keystore file: {}", path))?;
    let keystore = serde_json::from_str(&json)
        .context("Failed to deserialize keystore")?;
    Ok(keystore)
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        println!("Usage: {} <encrypt/decrypt> <input_file> <output_file>", args[0]);
        return Ok(());
    }

    let action = &args[1];
    let input_path = &args[2];
    let output_path = &args[3];

    let keystore = load_keystore("keystore.json").unwrap_or_else(|_| {
        let keystore = generate_keys().expect("Key generation failed");
        save_keystore(&keystore, "keystore.json").expect("Failed to save keystore");
        keystore
    });

    match action.as_str() {
        "encrypt" => encrypt_file(input_path, output_path, &keystore.public_key)?,
        "decrypt" => decrypt_file(input_path, output_path, &keystore.secret_key)?,
        _ => println!("Invalid action! Use 'encrypt' or 'decrypt'"),
    }

    Ok(())
}
