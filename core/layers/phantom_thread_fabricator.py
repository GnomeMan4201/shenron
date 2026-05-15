#!/usr/bin/env python3
# SHENRON: Phantom Thread Fabricator — simulates IO and thread noise for anti-forensic interference
import threading, time, os, random, tempfile

def simulate_io_chatter():
    tmp = os.path.join(tempfile.gettempdir(), f"io_{random.randint(1000,9999)}")
    with open(tmp, 'w') as f:
        f.write("x" * 512)
    os.remove(tmp)

def simulate_network_noise():
    os.system("ping -c 1 127.0.0.1 > /dev/null")

def simulate_log_rotation():
    with open(os.path.join(tempfile.gettempdir(), "shenron_phantom_syslog.log"), "a") as log:
        log.write(f"[phantom] Kernel module {random.randint(1000,9999)} triggered at {time.time()}\n")

BEHAVIORS = [simulate_io_chatter, simulate_network_noise, simulate_log_rotation]

def spawn_phantom():
    behavior = random.choice(BEHAVIORS)
    t = threading.Thread(target=behavior)
    t.daemon = True
    t.start()

def main():
    print("[*] Phantom Threadline Fabricator engaged.")
    for _ in range(20):
        spawn_phantom()
        time.sleep(random.uniform(0.2, 1.2))
    print("[✓] All phantom threads deployed.")

if __name__ == "__main__":
    main()
