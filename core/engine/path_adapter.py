#!/usr/bin/env python3
import os, re
HOME = os.path.expanduser("~")
SHENRON_HOME = os.path.join(HOME, ".shenron")
LOG_DIR = os.path.join(SHENRON_HOME, "logs")
PAYLOAD_DIR = os.path.join(SHENRON_HOME, "payloads")
TRIGGER_DIR = os.path.join(SHENRON_HOME, "triggers")
for d in [LOG_DIR, PAYLOAD_DIR, TRIGGER_DIR]:
    os.makedirs(d, exist_ok=True)
PATH_MAP = [
    (r"/data/data/com\.termux/files/home", HOME),
    (r"/data/data/com\.termux/files/usr/var/log", LOG_DIR),
    (r"/data/data/com\.termux/files", HOME),
    (r"/sdcard/DCIM", TRIGGER_DIR),
    (r"/sdcard", HOME),
    (r"~/SHENRON/logs", LOG_DIR),
    (r"~/SHENRON/payloads", PAYLOAD_DIR),
    (r"~/SHENRON", SHENRON_HOME),
]
def adapt(path):
    for pattern, replacement in PATH_MAP:
        path = re.sub(pattern, replacement, path)
    return path
def patch_source(source):
    for pattern, replacement in PATH_MAP:
        source = re.sub(pattern, replacement, source)
    return source
def log_path(name):
    return os.path.join(LOG_DIR, f"{name}.log")
