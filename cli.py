import argparse
import pyotp
import subprocess
import json
import os

def verify_totp(secret: str, user_totp: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(user_totp)

def run_rust_command(command: list) -> None:
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
    else:
        print(result.stdout)

def main():
    parser = argparse.ArgumentParser(description="Quantum-resistant encryption system CLI")
    parser.add_argument("action", choices=["encrypt", "decrypt"], help="Action to perform")
    parser.add_argument("input", help="Input file path")
    parser.add_argument("output", help="Output file path")
    parser.add_argument("--totp", required=True, help="TOTP code for authentication")

    args = parser.parse_args()

    TOTP_SECRET = "JBSWY3DPEHPK3PXP"
    if not verify_totp(TOTP_SECRET, args.totp):
        print("Invalid TOTP code!")
        return

    # Rust binary path
    rust_binary = os.path.join("crypto-core", "target", "release", "crypto-core")
    if args.action == "encrypt":
        run_rust_command([rust_binary, "encrypt", args.input, args.output])
    elif args.action == "decrypt":
        run_rust_command([rust_binary, "decrypt", args.input, args.output])

if __name__ == "__main__":
    main()