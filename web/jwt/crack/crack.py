import sys
import json
import argparse
import os
import hmac
import hashlib
from base64 import urlsafe_b64decode

ALG_HASHES = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

def usage():
    print(f"""
        usage: python3 {sys.argv[0]} --token=<JWT> --wordlist=<path>
        example: python3 {sys.argv[0]} --token=eyJ... --wordlist=rockyou.txt
    """)

def b64url_decode(data):
    # JWT is base64url with no padding; add it back before decoding
    padding = "=" * (-len(data) % 4)
    return urlsafe_b64decode(data + padding)

def decode_token(t):
    try:
        headerb64, payloadb64, signatureb64 = t.split(".")
    except ValueError:
        sys.exit("[!] Malformed token: expected 3 dot-separated parts")

    header = json.loads(b64url_decode(headerb64))
    signature = b64url_decode(signatureb64)
    signing_input = f"{headerb64}.{payloadb64}".encode()  # the exact bytes that were signed
    return header, signing_input, signature

def validate_alg(alg):
    return alg.upper() in ALG_HASHES

def validate_match(candidate, signing_input, signature, alg):
    expected = hmac.new(candidate.encode(), signing_input, ALG_HASHES[alg.upper()]).digest()
    return hmac.compare_digest(expected, signature)

def brute_force(t, w):
    header, signing_input, signature = decode_token(t)

    alg = header.get("alg", "")
    if not validate_alg(alg):
        sys.exit(f"[!] Unsupported or non-HMAC algorithm: {alg!r}")

    with open(w, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            candidate = line.rstrip("\r\n")
            if validate_match(candidate, signing_input, signature, alg):
                print(f"[+] Key found: {candidate}")
                return
    print("[-] Key not found in wordlist")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", required=True, help="JWT token")
    parser.add_argument("--wordlist", required=True, help="Path to wordlist")
    args = parser.parse_args()

    print(f"[+] Token:    {args.token}")
    print(f"[+] Wordlist: {args.wordlist}")

    if not os.path.isfile(args.wordlist):
        sys.exit(f"[!] Wordlist not found: {args.wordlist}")

    brute_force(args.token, args.wordlist)

if __name__ == "__main__":
    main()