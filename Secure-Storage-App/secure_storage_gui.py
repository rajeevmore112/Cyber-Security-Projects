"""
secure_storage_gui_v2.py
Upgraded GUI for Secure File Storage (AES-256-GCM + PBKDF2)
Features:
 - ttk layout, progress bar, threaded ops
 - password show/hide, strength indicator, generate password
 - file lists for encrypted/decrypted directories, refresh & open-folder
 - live log panel
 - optional removal / secure wipe of original after encryption
Author: Rajeev More (upgraded)
"""

import os
import sys
import hashlib
import threading
import queue
import secrets
import string
import webbrowser
from datetime import datetime, timezone
from tkinter import *
from tkinter import ttk, filedialog, messagebox

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ====== Config ======
ENC_DIR = "encrypted_files"
DEC_DIR = "decrypted_files"
LOG_FILE = "file_metadata.log"
os.makedirs(ENC_DIR, exist_ok=True)
os.makedirs(DEC_DIR, exist_ok=True)

SALT_SIZE = 16
NONCE_SIZE = 12
KDF_ITERATIONS = 200_000

# Thread UI queue
ui_q = queue.Queue()

# ====== Crypto utils (same as before) ======
def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password)

# ====== File-delete utilities ======
def delete_original(path: str) -> bool:
    """Quick delete original file."""
    try:
        os.remove(path)
        return True
    except Exception as e:
        append_log(f"[!] Could not delete original {path}: {e}")
        return False

def shred_and_delete(path: str, passes: int = 3) -> bool:
    """
    Overwrite file with random bytes 'passes' times, then delete.
    Note: not guaranteed on SSDs due to wear-leveling/TRIM.
    """
    try:
        length = os.path.getsize(path)
        # Open in r+b mode for in-place overwrite
        with open(path, "r+b") as f:
            for i in range(passes):
                f.seek(0)
                # generate in-chunks to avoid huge memory for very large files
                remaining = length
                chunk_size = 64 * 1024
                while remaining > 0:
                    write_bytes = secrets.token_bytes(min(chunk_size, remaining))
                    f.write(write_bytes)
                    remaining -= len(write_bytes)
                f.flush()
                os.fsync(f.fileno())
        os.remove(path)
        return True
    except Exception as e:
        append_log(f"[!] Shred failed for {path}: {e}")
        return False

# ====== Worker functions (encrypt/decrypt) ======
def encrypt_file_worker(filepath, password, remove_original=False, secure_wipe=False):
    try:
        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        key = derive_key(password.encode(), salt)
        aesgcm = AESGCM(key)

        with open(filepath, "rb") as f:
            plaintext = f.read()

        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        filename = os.path.basename(filepath)
        out_path = os.path.join(ENC_DIR, filename + ".enc")
        with open(out_path, "wb") as out:
            out.write(salt)
            out.write(nonce)
            out.write(ciphertext)

        phash = hashlib.sha256(plaintext).hexdigest()
        timestamp = datetime.now(timezone.utc).isoformat()
        with open(LOG_FILE, "a") as log:
            log.write(f"{timestamp} | ENCRYPT | {filename} | sha256:{phash}\n")

        # deletion step (attempt after successful encryption)
        deletion_msg = ""
        if remove_original:
            if secure_wipe:
                ok = shred_and_delete(filepath, passes=3)
                deletion_msg = " Original securely wiped." if ok else " Failed to securely wipe original."
            else:
                ok = delete_original(filepath)
                deletion_msg = " Original deleted." if ok else " Failed to delete original."

            # log deletion outcome
            with open(LOG_FILE, "a") as log:
                log.write(f"{timestamp} | DELETE_ORIGINAL | {os.path.basename(filepath)} | removed:{ok}\n")

        return True, f"Encrypted -> {out_path}{deletion_msg}"
    except Exception as e:
        return False, f"Encrypt failed: {e}"

def decrypt_file_worker(enc_path, password, remove_enc_after=False, secure_wipe=False):
    try:
        with open(enc_path, "rb") as f:
            salt = f.read(SALT_SIZE)
            nonce = f.read(NONCE_SIZE)
            ciphertext = f.read()

        key = derive_key(password.encode(), salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        original_name = os.path.basename(enc_path)
        if original_name.endswith(".enc"):
            original_name = original_name[:-4]
        out_path = os.path.join(DEC_DIR, original_name)
        with open(out_path, "wb") as out:
            out.write(plaintext)

        phash = hashlib.sha256(plaintext).hexdigest()
        timestamp = datetime.now(timezone.utc).isoformat()
        with open(LOG_FILE, "a") as log:
            log.write(f"{timestamp} | DECRYPT | {original_name} | sha256:{phash}\n")

        # optional: remove encrypted after decrypt
        deletion_msg = ""
        if remove_enc_after:
            if secure_wipe:
                ok = shred_and_delete(enc_path, passes=3)
                deletion_msg = " Encrypted file securely wiped." if ok else " Failed to securely wipe encrypted file."
            else:
                ok = delete_original(enc_path)
                deletion_msg = " Encrypted file deleted." if ok else " Failed to delete encrypted file."
            with open(LOG_FILE, "a") as log:
                log.write(f"{timestamp} | DELETE_ENC | {os.path.basename(enc_path)} | removed:{ok}\n")

        return True, f"Decrypted -> {out_path}{deletion_msg}"
    except Exception as e:
        return False, "Decrypt failed (wrong password or corrupted file)"

# ====== Helper UI functions ======
def human_path(p): return os.path.abspath(p)

def open_folder(path):
    if os.path.exists(path):
        if sys.platform == "win32":
            os.startfile(os.path.abspath(path))
        else:
            webbrowser.open(os.path.abspath(path))

def get_files(dirname):
    try:
        return sorted([f for f in os.listdir(dirname) if os.path.isfile(os.path.join(dirname, f))])
    except FileNotFoundError:
        return []

def append_log(message):
    timestamp = datetime.now(timezone.utc).isoformat()
    msg = f"{timestamp} - {message}"
    # write to GUI log & file
    try:
        txt_log.configure(state=NORMAL)
        txt_log.insert(END, msg + "\n")
        txt_log.see(END)
        txt_log.configure(state=DISABLED)
    except Exception:
        # UI may not be initialized if called early; ignore safely
        pass
    with open(LOG_FILE, "a") as lf:
        lf.write(msg + "\n")

def refresh_file_lists():
    enc_list.delete(0, END)
    dec_list.delete(0, END)
    for f in get_files(ENC_DIR):
        enc_list.insert(END, f)
    for f in get_files(DEC_DIR):
        dec_list.insert(END, f)

def choose_file():
    path = filedialog.askopenfilename(title="Select file")
    if path:
        entry_path.delete(0, END)
        entry_path.insert(0, path)

# Simple password strength indicator
def password_strength(pw: str) -> int:
    score = 0
    if len(pw) >= 8: score += 25
    if any(c.islower() for c in pw): score += 15
    if any(c.isupper() for c in pw): score += 15
    if any(c.isdigit() for c in pw): score += 20
    if any(c in string.punctuation for c in pw): score += 25
    return min(score, 100)

def update_strength_indicator(event=None):
    pw = entry_password.get()
    score = password_strength(pw)
    progress_pwd['value'] = score
    if score < 40:
        lbl_strength.config(text="Weak", foreground="red")
    elif score < 70:
        lbl_strength.config(text="Medium", foreground="orange")
    else:
        lbl_strength.config(text="Strong", foreground="green")

def gen_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
    entry_password.delete(0, END)
    entry_password.insert(0, pwd)
    update_strength_indicator()

# Thread wrapper to run crypto tasks without freezing UI
def run_in_thread(target, args=()):
    def task():
        ui_q.put(("start", None))
        success, msg = target(*args)
        ui_q.put(("done", (success, msg)))
    t = threading.Thread(target=task, daemon=True)
    t.start()

# Handlers for button actions (start encryption/decryption)
def handle_encrypt():
    path = entry_path.get().strip()
    pwd = entry_password.get()
    remove_original_opt = chk_remove_var.get()
    secure_wipe_opt = chk_shred_var.get()
    if not path or not os.path.exists(path):
        messagebox.showerror("Error", "Please select a valid file to encrypt.")
        return
    if not pwd:
        messagebox.showerror("Error", "Enter password.")
        return

    # confirm deletion if requested
    if remove_original_opt:
        confirm = messagebox.askyesno("Confirm Deletion",
                                      "You requested to remove the original after encryption.\n"
                                      "This action is irreversible. Continue?")
        if not confirm:
            # user cancelled; do not proceed
            append_log("Encryption canceled by user (deletion not confirmed).")
            return

    append_log(f"Starting encryption: {path}")
    # pass deletion flags into worker
    run_in_thread(encrypt_file_worker, (path, pwd, remove_original_opt, secure_wipe_opt))

def handle_decrypt():
    selection = None
    path = entry_path.get().strip()
    if path and path.endswith(".enc"):
        selection = path
    else:
        sel = enc_list.curselection()
        if sel:
            selection = os.path.join(ENC_DIR, enc_list.get(sel[0]))
    if not selection or not os.path.exists(selection):
        messagebox.showerror("Error", "Please select an encrypted file (.enc) to decrypt.")
        return
    pwd = entry_password.get()
    if not pwd:
        messagebox.showerror("Error", "Enter password.")
        return

    # Optional: prompt to remove encrypted file after decrypt (UI exposes same checkboxes)
    remove_after_decrypt = chk_remove_var.get()
    secure_wipe_opt = chk_shred_var.get()
    if remove_after_decrypt:
        confirm = messagebox.askyesno("Confirm Deletion",
                                      "You requested to remove the encrypted file after decryption.\n"
                                      "This action is irreversible. Continue?")
        if not confirm:
            append_log("Decryption canceled by user (deletion not confirmed).")
            return

    append_log(f"Starting decryption: {selection}")
    run_in_thread(decrypt_file_worker, (selection, pwd, remove_after_decrypt, secure_wipe_opt))

# UI poll loop for thread results
def ui_poll():
    try:
        while True:
            action, payload = ui_q.get_nowait()
            if action == "start":
                progress_bar.start(10)
            elif action == "done":
                progress_bar.stop()
                success, msg = payload
                append_log(msg)
                refresh_file_lists()
                # show result in a small popup
                if success:
                    messagebox.showinfo("Result", msg)
                else:
                    messagebox.showerror("Error", msg)
    except queue.Empty:
        pass
    root.after(200, ui_poll)

# ====== Build GUI ======
root = Tk()
root.title("Secure File Storage")
root.geometry("960x720")

# Top frame for file selection
frm_top = ttk.Frame(root, padding=10)
frm_top.pack(fill=X)

ttk.Label(frm_top, text="File:", font=("Segoe UI", 10)).grid(row=0, column=0, sticky=W)
entry_path = ttk.Entry(frm_top, width=60)
entry_path.grid(row=0, column=1, padx=6)
ttk.Button(frm_top, text="Browse", command=choose_file).grid(row=0, column=2, padx=6)
ttk.Button(frm_top, text="Refresh Lists", command=refresh_file_lists).grid(row=0, column=3, padx=6)
ttk.Button(frm_top, text="Open Encrypted Folder", command=lambda: open_folder(ENC_DIR)).grid(row=0, column=4, padx=6)
ttk.Button(frm_top, text="Open Decrypted Folder", command=lambda: open_folder(DEC_DIR)).grid(row=0, column=5, padx=6)

# password frame
frm_pwd = ttk.Frame(root, padding=(10,5))
frm_pwd.pack(fill=X)
ttk.Label(frm_pwd, text="Password:", font=("Segoe UI", 10)).grid(row=0, column=0, sticky=W)
entry_password = ttk.Entry(frm_pwd, width=40, show="*")
entry_password.grid(row=0, column=1, padx=6)
entry_password.bind("<KeyRelease>", update_strength_indicator)
chk_show_var = BooleanVar(value=False)
def toggle_pwd():
    entry_password.config(show="" if chk_show_var.get() else "*")
ttk.Checkbutton(frm_pwd, text="Show", variable=chk_show_var, command=toggle_pwd).grid(row=0, column=2, padx=6)
ttk.Button(frm_pwd, text="Generate", command=gen_password).grid(row=0, column=3, padx=6)

# password strength
frm_strength = ttk.Frame(root, padding=(10,0))
frm_strength.pack(fill=X)
progress_pwd = ttk.Progressbar(frm_strength, length=300, maximum=100, mode="determinate")
progress_pwd.grid(row=0, column=1, padx=6, sticky=W)
lbl_strength = ttk.Label(frm_strength, text="Strength")
lbl_strength.grid(row=0, column=2, padx=6, sticky=W)

# delete options (new)
frm_delete = ttk.Frame(root, padding=(10,5))
frm_delete.pack(fill=X)
chk_remove_var = BooleanVar(value=False)
chk_shred_var = BooleanVar(value=False)
ttk.Checkbutton(frm_delete, text="Remove original after encrypt/decrypt", variable=chk_remove_var).grid(row=0, column=0, sticky=W, padx=6)
ttk.Checkbutton(frm_delete, text="Secure wipe (3 passes)", variable=chk_shred_var).grid(row=0, column=1, sticky=W, padx=6)
ttk.Label(frm_delete, text="(Warning: secure wipe may be ineffective on SSDs)").grid(row=0, column=2, sticky=W, padx=6)

# action buttons
frm_actions = ttk.Frame(root, padding=10)
frm_actions.pack(fill=X)
ttk.Button(frm_actions, text="Encrypt File", command=handle_encrypt).grid(row=0, column=0, padx=6)
ttk.Button(frm_actions, text="Decrypt File", command=handle_decrypt).grid(row=0, column=1, padx=6)

# center frame: file lists and progress
frm_center = ttk.Frame(root, padding=10)
frm_center.pack(fill=BOTH, expand=True)

# Encrypted files list
frm_enc = ttk.LabelFrame(frm_center, text="Encrypted Files")
frm_enc.pack(side=LEFT, fill=BOTH, expand=True, padx=5, pady=5)
enc_list = Listbox(frm_enc, height=12)
enc_list.pack(side=LEFT, fill=BOTH, expand=True, padx=(5,0), pady=5)
scroll_enc = ttk.Scrollbar(frm_enc, orient=VERTICAL, command=enc_list.yview)
scroll_enc.pack(side=LEFT, fill=Y, padx=(0,5))
enc_list.config(yscrollcommand=scroll_enc.set)

# Decrypted files list
frm_dec = ttk.LabelFrame(frm_center, text="Decrypted Files")
frm_dec.pack(side=LEFT, fill=BOTH, expand=True, padx=5, pady=5)
dec_list = Listbox(frm_dec, height=12)
dec_list.pack(side=LEFT, fill=BOTH, expand=True, padx=(5,0), pady=5)
scroll_dec = ttk.Scrollbar(frm_dec, orient=VERTICAL, command=dec_list.yview)
scroll_dec.pack(side=LEFT, fill=Y, padx=(0,5))
dec_list.config(yscrollcommand=scroll_dec.set)

# Progress bar
frm_prog = ttk.Frame(root, padding=(10,2))
frm_prog.pack(fill=X)
progress_bar = ttk.Progressbar(frm_prog, mode="indeterminate")
progress_bar.pack(fill=X, padx=10, pady=5)

# Log panel
frm_log = ttk.LabelFrame(root, text="Log")
frm_log.pack(fill=BOTH, expand=True, padx=10, pady=(0,10))
txt_log = Text(frm_log, height=8, state=DISABLED)
txt_log.pack(fill=BOTH, expand=True, padx=6, pady=6)

# initial refresh
refresh_file_lists()
update_strength_indicator()

# start UI poll
root.after(200, ui_poll)
root.mainloop()
