![Python](https://img.shields.io/badge/Python-3.9%2B-blue) ![License](https://img.shields.io/badge/License-Apache%202.0-green)

# Secure-Storage-App
A secure file storage system built with Python, featuring AES-256-GCM encryption, PBKDF2 password-based key derivation, optional secure wipe, and a modern Tkinter GUI. Provides safe encryption, decryption, password strength checks, file logs, and multi-threaded execution.

## Features

### Strong Encryption
- AES-256-GCM (authenticated encryption)
- PBKDF2-HMAC-SHA256 key derivation (200,000 iterations)
- Per-file random salt + nonce
- Protects confidentiality and detects tampering

### Password Security
- Password strength indicator
- Password show/hide toggle
- One-click strong password generator

### Modern Tkinter GUI
- File browser
- Log window (real-time updates)
- File lists for encrypted & decrypted files
- Progress bar for long operations
- Responsive (threaded encryption/decryption)

### Secure Data Handling
- Optional: Remove original after encrypt/decrypt
- Optional: Secure wipe (3-pass overwrite)
- Automatic folder creation
- Timestamped logging (ISO-8601)

### Distribution-Ready
- Fully compatible with PyInstaller
- Works standalone as a Windows EXE
- Safe folder structure for storing encrypted/decrypted files

## Installation
1. Clone the repository
- `git clone https://github.com/rajeevmore112/Secure-Storage-App.git`
- `cd Secure-Storage-App`

2. Create virtual environment (recommended)
- `python -m venv venv`
- `venv\Scripts\activate`     # Windows

4. Install dependencies
- `pip install -r requirements.txt`

## Running the Application
GUI Version
- `python secure_storage_gui_v2.py`

CLI Version
- `python secure_storage_pw.py`

## Security Notes
- AES-256-GCM provides authenticated encryption (confidentiality + integrity).
- PBKDF2 key stretching increases resistance against password cracking.
- Secure wipe uses 3-pass overwriting but may not fully erase data on SSDs due to TRIM.
- Users are advised to use strong passwords (12+ characters recommended).
- Encryption is symmetric — losing your password means losing access permanently.

## Limitations
- Secure wipe effectiveness is not guaranteed on SSDs.
- Application currently encrypts/decrypts one file at a time (no bulk folder mode).
- Only supports local file encryption (not cloud/stream encryption).

## Download (Windows EXE)
A pre-built Windows executable is available under **Releases**:

👉 https://github.com/rajeevmore112/Secure-Storage-App/releases

Download the `.zip`, extract it, and run `SecureStorage.exe`.

## Project Structure
Secure-Storage-App/
│
│── assets/
│   │── App_GUI.jpg
│   │── Deletion_Confirmation.jpg
│   │── Details_Inserted.jpg
│   │── File_Encrypted.jpg
│   │── File_Encrypted_and_Wiped.jpg
│   │── File_Normal.jpg
│   └── File_Wiped_and_Decrypted.jpg
│
├── LICENSE                       # Apache 2.0 License
├── README.md                     # Documentation
├── requirements.txt              # Dependencies
├── secure_storage_gui_v2.py      # GUI application (AES-256-GCM)
└── secure_storage_pw.py          # CLI encryption tool

## License
This project is licensed under the Apache 2.0 License — see the LICENSE file for details.
