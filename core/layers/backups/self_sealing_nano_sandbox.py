#!/usr/bin/env python3
# self_sealing_nano_sandbox.py - SHENRON lightweight isolation and seal-off layer

import os
import tempfile
import shutil
import subprocess
import random
import string
import time

def random_dirname(length=6):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def setup_sandbox():
    base_dir = tempfile.gettempdir()
    sandbox_name = f".sandbox_{random_dirname()}"
    sandbox_path = os.path.join(base_dir, sandbox_name)
    os.makedirs(sandbox_path, exist_ok=True)
    print(f"[+] Sandbox initialized at {sandbox_path}")
    return sandbox_path

def run_in_sandbox(sandbox_path, command):
    fake_env = os.environ.copy()
    fake_env["HOME"] = sandbox_path
    try:
        result = subprocess.run(command, cwd=sandbox_path, env=fake_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        print(f"[✓] Command executed inside sandbox: {command}")
        return result.stdout.decode().strip()
    except subprocess.TimeoutExpired:
        print("[!] Sandbox command timed out.")
        return ""

def seal_sandbox(sandbox_path):
    try:
        with open(os.path.join(sandbox_path, ".sealed"), "w") as f:
            f.write("This sandbox is sealed.")
        shutil.rmtree(sandbox_path, ignore_errors=True)
        print("[✓] Sandbox sealed and removed.")
    except Exception as e:
        print(f"[!] Failed to seal sandbox: {e}")

def main():
    sandbox_path = setup_sandbox()
    output = run_in_sandbox(sandbox_path, ["ls", "-la"])
    if "bin" not in output:
        print("[!] Unexpected sandbox environment — sealing early.")
        seal_sandbox(sandbox_path)
        return
    time.sleep(2)
    seal_sandbox(sandbox_path)

if __name__ == "__main__":
    main()
