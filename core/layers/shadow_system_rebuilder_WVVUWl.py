#!/usr/bin/env python3
# SHENRON: Shadow System Rebuilder ‚Äî Restores original file states post-compromise

import os
import hashlib
import shutil
import time

ORIGINALS_BACKUP = os.path.expanduser("~/SHENRON/data/original_system_files")
TARGET_SYSTEM_DIR = os.path.expanduser("~/storage/shared")

def compute_hash(filepath):
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def restore_original(filepath, backup_path):
    shutil.copy2(backup_path, filepath)
    print(f"[+] Restored original file: {filepath}")

def rebuild_integrity():
    print("[*] Scanning and restoring original file integrity...")
    for root, dirs, files in os.walk(ORIGINALS_BACKUP):
        for file in files:
            rel_path = os.path.relpath(os.path.join(root, file), ORIGINALS_BACKUP)
            target_file = os.path.join(TARGET_SYSTEM_DIR, rel_path)
            backup_file = os.path.join(root, file)

            if os.path.exists(target_file):
                orig_hash = compute_hash(backup_file)
                target_hash = compute_hash(target_file)
                if orig_hash != target_hash:
                    restore_original(target_file, backup_file)
                    os.utime(target_file, (time.time() - 86400, time.time() - 86400))  # Adjust timestamps
    print("[‚úì] Shadow system rebuild complete. System integrity restored.")

if __name__ == "__main__":
    rebuild_integrity()

ìŒ¬Åõkøû¶Ôì,`#MORPHED
