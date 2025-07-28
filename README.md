#  QuantumVault

**QuantumVault** is a hybrid file encryption tool written in Rust that combines **post-quantum security** (via Kyber512) with modern **symmetric encryption** (via AES-256-GCM). It’s designed to ensure the confidentiality and integrity of your data — even in a future where quantum computers pose a threat to traditional cryptography.

---

##  Features

-  **Post-Quantum Cryptography**: Uses [Kyber512](https://pq-crystals.org/kyber/) for quantum-resistant key encapsulation.
-  **Authenticated Encryption**: Leverages AES-256-GCM for fast, secure encryption with built-in integrity checking.
-  Secure key generation and persistent storage (`keystore.json`)
-  Self-contained encrypted files — no need for separate key files
-  Command-line interface for quick and easy usage

---

##  Dependencies

- [`oqs`](https://crates.io/crates/oqs) – Post-quantum KEM (Kyber)
- [`aes-gcm`](https://crates.io/crates/aes-gcm) – Symmetric authenticated encryption
- [`rand`](https://crates.io/crates/rand) – Random number generator
- [`serde`](https://crates.io/crates/serde), [`serde_json`](https://crates.io/crates/serde_json) – Serialization

---

##  Building from Source

```bash
git clone https://github.com/dc-r00tk1t/QuantumVault
cd QuantumVault
cd crypto-core
cargo build --release

python cli.py encrypt input.txt encrypted.bin --totp < TOTP >
python cli.py decrypt encrypted.bin decrypted.txt --totp < TOTP >