#!/usr/bin/env python3
# SHENRON Layer: Transient Exfiltration Shell
# Launches stealthy, temporary outbound tunnel that dissolves after exfil

import socket
import threading
import time
import os
import random

LOG = os.path.expanduser("~/SHENRON/logs/exfil_transients.log")
FAKE_DATA = b"sample_exfil_block_" + os.urandom(8)

def handle_client(conn, addr):
    try:
        conn.sendall(FAKE_DATA)
        time.sleep(random.uniform(1.0, 2.5))
        conn.close()
        with open(LOG, "a") as f:
            f.write(f"[‚úì] Exfil complete from transient shell to {addr}\n")
    except Exception as e:
        with open(LOG, "a") as f:
            f.write(f"[!] Exfil failure to {addr}: {e}\n")

def launch_shell():
    port = random.randint(49152, 65535)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(1)

    with open(LOG, "a") as f:
        f.write(f"[*] Transient shell spawned on port {port}\n")

    # One-shot connection then dissolve
    conn, addr = server.accept()
    threading.Thread(target=handle_client, args=(conn, addr)).start()
    time.sleep(3)
    server.close()

def main():
    print("[*] Launching Transient Exfiltration Shell...")
    launch_shell()
    print("[‚úì] Transient channel complete. Shell dissolved.")

if __name__ == "__main__":
    main()

åı»i7«,ìãs1ﬂ ‹”~÷øb¿i.uMŸ3”4u—k"Ri6ò{å`O#MORPHED
