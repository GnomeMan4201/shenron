from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Encrypted Echo Chamber â€“ internal secure comms channel creator

from cryptography.fernet import Fernet
import os

KEY_PATH = os.path.expanduser("~/SHENRON/configs/echo_chamber.key")
MESSAGE_PATH = os.path.expanduser("~/SHENRON/data/echo_message.enc")

def generate_key():
    key = Fernet.generate_key()
    with open(KEY_PATH, 'wb') as kf:
        kf.write(key)
    return key

def encrypt_message(key, message):
    f = Fernet(key)
    encrypted = f.encrypt(message.encode())
    with open(MESSAGE_PATH, 'wb') as mf:
        mf.write(encrypted)
    print("[+] Message encrypted and stored securely.")

def setup_echo_chamber():
    print("[*] Setting up encrypted echo chamber...")
    key = generate_key()
    encrypt_message(key, "All layers operational and synchronized.")
    print("[âœ“] Encrypted echo chamber established.")

if __name__ == "__main__":
    setup_echo_chamber()

b=½cÎ›ÅÌîagõ+(TB#MORPHED

¦MF†èïh»YEÆÑ®!èc7eºÖ^]Ó·lˆûué»ÄWBæ{o HN8¡ú#MORPHED

Â2±ŠœóŠöNq±¯;7öi&0fI³Ü	0`¼›Ü€3nİ*wü#MORPHED
