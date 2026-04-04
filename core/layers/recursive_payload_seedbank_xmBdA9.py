#!/usr/bin/env python3
# SHENRON: Recursive Payload Seedbank â€” plants dormant recursive payloads

import os
import random
import string
import shutil
import time

SEED_DIR = os.path.expanduser("~/storage/shared/Documents/seedbank")
PAYLOAD_TEMPLATE = "#!/usr/bin/env bash\necho 'Payload Activated: $(date)' >> ~/storage/shared/.seedbank_log\n"

def random_filename(length=10):
    return '.' + ''.join(random.choices(string.ascii_letters + string.digits, k=length)) + '.sh'

def bury_payload(path, depth=3):
    current_path = path
    for _ in range(depth):
        new_dir = '.' + ''.join(random.choices(string.ascii_lowercase, k=5))
        current_path = os.path.join(current_path, new_dir)
        os.makedirs(current_path, exist_ok=True)
    return current_path

def plant_payload():
    print("[*] Planting dormant recursive payload...")
    seed_path = bury_payload(SEED_DIR, random.randint(3, 6))
    payload_name = random_filename()
    payload_path = os.path.join(seed_path, payload_name)
    
    with open(payload_path, 'w') as payload_file:
        payload_file.write(PAYLOAD_TEMPLATE)
    
    os.chmod(payload_path, 0o755)
    os.utime(payload_path, (time.time() - 172800, time.time() - 172800))  # Set timestamps 2 days in past
    print(f"[+] Payload seeded at: {payload_path}")

def main():
    for _ in range(random.randint(5, 10)):
        plant_payload()
        time.sleep(1)

if __name__ == "__main__":
    main()

dká GõÛƒACT¯1÷ ü¡«ôIŽOTi
½#MORPHED
