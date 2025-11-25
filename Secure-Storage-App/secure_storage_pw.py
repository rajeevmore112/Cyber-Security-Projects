"""
Secure File Storage with Password-based AES-256-GCM
- PBKDF2-HMAC-SHA256 derives a 256-bit key from a user password + random salt
- AES-GCM provides authenticated encryption (integrity + confidentiality)
- File format: [16B salt][12B nonce][ciphertext+tag]
Author: Rajeev More
Date: 2025
"""

import os
import sys
import hashlib
from datetime import datetime, timezone
from getpass import getpass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Config
ENC_DIR = "encrypted_files"
DEC_DIR = "decrypted_files"
LOG_FILE = "file_metadata.log"
SALT_SIZE = 16           # bytes
NONCE_SIZE = 12          # bytes (recommended for GCM)
KDF_ITERATIONS = 200_000 # adjust upward for more CPU-hardness

os.makedirs(ENC_DIR, exist_ok=True)
os.makedirs(DEC_DIR, exist_ok=True)


def derive_key(password: bytes, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """
    Derive a 32-byte (256-bit) key from password and salt using PBKDF2-HMAC-SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password)


def encrypt_file_with_password(filepath: str, password: str):
    """
    Encrypt a file with a password. Writes file to ENC_DIR with .enc suffix.
    File format: [salt(16)] [nonce(12)] [ciphertext+tag]
    """
    if not os.path.exists(filepath):
        print("[!] File not found:", filepath)
        return

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password.encode("utf-8"), salt)
    aesgcm = AESGCM(key)

    with open(filepath, "rb") as f:
        plaintext = f.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    filename = os.path.basename(filepath)
    out_path = os.path.join(ENC_DIR, filename + ".enc")

    with open(out_path, "wb") as out:
        out.write(salt)
        out.write(nonce)
        out.write(ciphertext)

    # Log metadata (do not log plaintext or password)
    phash = hashlib.sha256(plaintext).hexdigest()
    with open(LOG_FILE, "a") as log:
        log.write(f"{datetime.now(timezone.utc).isoformat()}Z | ENCRYPT | {filename} | sha256:{phash} | out:{out_path}\n")

    print(f"[+] Encrypted -> {out_path}")


def decrypt_file_with_password(enc_path: str, password: str):
    """
    Decrypt a file produced by encrypt_file_with_password.
    Expects format [salt][nonce][ciphertext].
    """
    if not os.path.exists(enc_path):
        print("[!] Encrypted file not found:", enc_path)
        return

    with open(enc_path, "rb") as f:
        salt = f.read(SALT_SIZE)
        if len(salt) != SALT_SIZE:
            print("[!] Invalid file format or truncated (salt).")
            return
        nonce = f.read(NONCE_SIZE)
        if len(nonce) != NONCE_SIZE:
            print("[!] Invalid file format or truncated (nonce).")
            return
        ciphertext = f.read()
        if not ciphertext:
            print("[!] Invalid file: no ciphertext.")
            return

    try:
        key = derive_key(password.encode("utf-8"), salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except Exception as e:
        print("[!] Decryption failed: authentication error or wrong password.")
        # don't print exception details in production; show for debug
        # print("DEBUG:", e)
        return

    # write decrypted file
    original_name = os.path.basename(enc_path)
    if original_name.endswith(".enc"):
        original_name = original_name[:-4]
    out_path = os.path.join(DEC_DIR, original_name)
    with open(out_path, "wb") as out:
        out.write(plaintext)

    phash = hashlib.sha256(plaintext).hexdigest()
    with open(LOG_FILE, "a") as log:
        log.write(f"{datetime.now(timezone.utc).isoformat()}Z | DECRYPT | {original_name} | sha256:{phash} | from:{enc_path}\n")

    print(f"[+] Decrypted -> {out_path}")


def menu():
    print("\n==== Secure File Storage (Password + AES-256-GCM) ====")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    print("3. Exit")
    choice = input("Choice: ").strip()
    if choice == "1":
        fp = input("Enter file path to encrypt: ").strip('"')
        pwd = getpass("Enter password (will not be shown): ")
        pwd2 = getpass("Confirm password: ")
        if pwd != pwd2:
            print("[!] Passwords do not match.")
            return
        if len(pwd) < 6:
            print("[!] Use a stronger password (>=6 chars recommended).")
            # still allow, but warn
        encrypt_file_with_password(fp, pwd)
    elif choice == "2":
        fp = input("Enter path of .enc file to decrypt: ").strip('"')
        pwd = getpass("Enter password used to encrypt: ")
        decrypt_file_with_password(fp, pwd)
    elif choice == "3":
        print("Exiting.")
        sys.exit(0)
    else:
        print("[!] Invalid choice.")


if __name__ == "__main__":
    while True:
        try:
            menu()
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user. Exiting.")
            sys.exit(0)
