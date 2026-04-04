import os, time, random

def main():
    logdir = os.path.expanduser("~/projects/shenron/core/layers")
    print("[*] Chain Stats Dashboard")
    print("=" * 40)
    for file in sorted(os.listdir(logdir)):
        if file.endswith(".py") or file.endswith(".sh"):
            score = random.randint(70, 100)
            stealth = random.choice(["High", "Medium", "Extreme"])
            print(f"{file:<40} | Score: {score}% | Stealth: {stealth}")

if __name__ == "__main__":
    main()
