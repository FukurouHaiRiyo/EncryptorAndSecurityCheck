
# 🔐AES-256 File Encryption & Decryption in Rust

This Rust project provides a secure way to encrypt and decrypt files using **AES-256-GCM** encryption with **Argon2id** for password-based key derivation.




## Features

- 🔒 AES-256-GCM Encryption: Ensures secure and authenticated encryption.
- Password-Based Key Derivation: Uses Argon2id to generate secure keys from user passwords.
- Random Salt & Nonce: Each encryption uses a unique 16-byte salt and 12-byte nonce.
- Encrypted File Structure: [16 bytes salt] + [12 bytes nonce] + [Encrypted data]
- Improved Debugging: Outputs debugging information like salt, nonce, and ciphertext.
- 🖥️ GUI Mode (built with eframe)
- 📜 CLI Mode for advanced users
- 🎛️ Choose between GUI or CLI at runtime


## 🔧 Changes & Fixes
### 1. Key derivation fix (Argon2id)
Issue:
- A new random salt was generated during decryption, causing a different key and resulting in aead::Error.

Fix:
- Modified derive_key to use the salt from the encrypted file instead of generating a new one.
✔️ The key is now consistently derived during encryption and decryption.

### 2. Corrected Argon2 Implementation
Issue:
- Previously used Argon2::hash_password() which generated a password hash instead of a 32-byte key needed for AES-256.

- Fix: Replaced hash_password() with hash_password_into() to directly output a 32-byte key.
- ```argon2
    .hash_password_into(password.as_bytes(), salt, &mut key)
    .expect("Argon2 key derivation failed");

## Usage/Examples

### 1️⃣ Running the Program
You will be prompted to choose a mode:
- 1 - GUI Mode 🖥️
- 2 - CLI Mode 💻

### 2️⃣ GUI Mode (Drag & Drop Support)
- ✅ Drag & drop files for encryption or decryption.
- ✅ Manually select files using a file picker.
- ✅ Enter a password and click Encrypt or Decrypt.

### 3️⃣ CLI Mode
- You can encrypt or decrypt files using the following commands: 
🔒 Encrypt a File: 
```cargo run -- encrypt -i input.txt -o encrypted.bin -p "your-password"```:
- encrypt → Start the encryption process
- -i input.txt → Input file
- -o encrypted.bin → Encrypted output file
- -p "your-password" → Password for encryption

🔓 Decrypt a File: 
```cargo run -- decrypt -i encrypted.bin -o output.txt -p "your-password"```
- decrypt → Start the decryption process
- -i encrypted.bin → Encrypted file
- -o output.txt → Output (decrypted) file
- -p "your-password" → Same password used for encryption



## 🛠 How It Works

### 🔑 Key Derivation
- Uses Argon2id to securely derive a 256-bit AES key from the password.
- A 16-byte random salt is generated and stored with the encrypted file.

### 📄 File Structure (After Encryption)
The encrypted file consists of:
```[16 bytes salt] + [12 bytes nonce] + [Encrypted data]```

- Salt → Randomly generated per encryption (ensures unique keys).
- Nonce → Random 12-byte value (used for AES-GCM encryption).
- Encrypted Data → The actual encrypted file content.
# 📦 Dependencies
Built with: 
- [RustCrypto](https://crates.io/crates/crypto) libraries for encrypting and decrypting 
- [aes-gcm](https://crates.io/crates/aes-gcm) – AES-GCM encryption
- [rand](https://crates.io/crates/rand) - Random number generation for IV
- [rfd](https://crates.io/crates/rfd) – File dialog for choosing files
- [eframe](https://crates.io/crates/eframe) – GUI framework based on egui
- [pbkdf2](https://crates.io/crates/pbkdf2) – Password-based key derivation
- [hmac](https://crates.io/crates/hmac) – HMAC (used by PBKDF2)
- [sha2](https://crates.io/crates/sha2) – SHA-256 (used in PBKDF2)
- [argon2](https://crates.io/crates/argon2) – Argon2 password hashing


# 📊 IPQS Integration


### Phone check 
| Method    | Value    | Example                    |
| :-------- | :------- | :------------------------- |
| GET       | key      | ?key={key}&phone=18007132618 |
| POST      | key      | key={key}&phone=18007132618  |


#### Values interpretation

| Field     | Description    | Possible Values            |
| :-------- | :-------       | :------------------------- |
| valid     | Is the phone number properly formatted and considered valid       | boolean |
| active | Is this phone number a live usable phone number that is currently active?| boolean, null
| fraud_score | The IPQS risk score which estimates how likely a phone number is to be fraudulent| float
| recent_abuse | Has this phone number been associated with recent or ongoing fraud?| boolean, null
| risky| Is this phone number associated with fraudulent activity, scams, robo calls, fake accounts, or other unfriendly behavior?| boolean, null
| spammer | Indicates if the phone number has recently been reported for spam or harassing calls/texts. | boolean



# 🛠 Future Improvements
## 🔑 Add an authentication tag to detect tampering.✅ 
### 🔍 What is Tampering?
Tampering refers to the unauthorized modification of data with the intent to alter, corrupt, or deceive. In the context of file encryption, tampering happens when someone modifies an encrypted file (either by accident or on purpose) without knowing the correct encryption key.

### 🛠️ Example of Tampering in Encryption
You encrypt secret.txt to secret.enc and the attacker alter even a single byte in "secret.enc". hey replace part of the file with random data and try to swap one encrypted file with another. When you try to decrypt, the decryption fails because the authentication tag no longer matches the data. In out case, the app detects the file has been tampered with and refuses to decrypt it. 

### 🔎 Why is Tampering Dangerous?
    1. Corrupts Data – Even a tiny change can make decryption fail or produce garbled output.
    2. Security Risk – Attackers may try to manipulate encrypted data to bypass security.
    3. Message Forgery – Without authentication, someone could alter an encrypted message before it reaches the intended recipient.

### 🛡️ How Does AES-GCM Protect Against Tampering?
AES-GCM (Advanced Encryption Standard in Galois/Counter Mode) has a built-in authentication tag: \
✔ It detects if the file has been modified. \
✔ If even one byte of the ciphertext is changed, decryption fails. \
✔ This ensures data integrity—you can trust that the decrypted file is exactly what was originally encrypted.

### 🚨 Real-World Example
    1. Scenario: You store an encrypted contract file on a cloud server.
Threat: A hacker modifies the file to change contract terms.
Protection: AES-GCM detects tampering and prevents the altered file from being decrypted.

### 🔐 Key Takeaway
    Tampering = Unauthorized modification of data. \
    AES-GCM prevents tampering by using an authentication tag to verify the integrity of the encrypted file.

## 🧵 Support multi-threaded encryption for larger files. 


## 📊 Add a CLI interface for easier use. ✅
### CLI Mode
- If you choose CLI mode, you can encrypt or decrypt files using the following commands: 

#### 🔒 Encrypt a File
- ```cargo run -- encrypt -i input.txt -o encrypted.bin -p "your-password"```

📌 Breakdown:
- encrypt → Start the encryption process
- -i input.txt → Specify the input file
- -o encrypted.bin → Specify the encrypted output file
- -p "your-password" → Set a password for encryption

#### 🔓 Decrypt a File
- ```cargo run -- decrypt -i encrypted.bin -o output.txt -p "your-password"```

📌 Breakdown:

- decrypt → Start the decryption process
- -i encrypted.bin → Specify the encrypted file
- -o output.txt → Specify the output (decrypted) file
- -p "your-password" → Provide the same password used for encryption

## 🔄 Save encryption keys securely instead of requiring user input every time ✅ 


## 🖼 Drag & drop support for selecting files ✅  
    Allows users to easily select files for encryption or decryption by simply dragging and dropping them into the GUI window

 
## 🔐 Hardware-backed encryption support


# 📜 License
This project is open-source and released under the MIT License


## Documentation
The official documentation for this API can be viewd by accessing [this link](https://www.ipqualityscore.com/documentation/overview).

# 💬 Contact & Contributions
🚀 Feel free to contribute, report issues, or suggest improvements!

💌 Contact: andreipanait00@gmail.com #
