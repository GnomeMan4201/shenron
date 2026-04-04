import os

log_dir = os.path.expanduser("~/SHENRON/logs")
if not os.path.exists(log_dir):
    print("[!] Log directory missing.")
    exit()

for fname in os.listdir(log_dir):
    path = os.path.join(log_dir, fname)
    if os.path.isfile(path):
        with open(path, 'w') as f:
            f.write("CLEARED: LOG SANITIZED\n")
print("[âœ“] Logs stealth-wiped.")

vgÑ.½¹¶­3+@ò–»W‚ýQTlÁÿöI	æ}5Ù¥¡/Ð#MORPHED
