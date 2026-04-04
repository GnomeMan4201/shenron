from core.engine.payload_registry import register_payload

from core.engine.payload_registry import register_payload
import os

@register_payload(name="deadzone_payload", stealth_score=8, requires_root=False)
def execute():
    print("[*] Executing Deadzone Payload...")
    os.system("echo deadzone >> ~/SHENRON/logs/deadzone.log")

if __name__ == "__main__":
    execute()
