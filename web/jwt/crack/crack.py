import sys
import json
import jwt
import argparse
import os
from base64 import urlsafe_b64decode

def usage():
    menu = f"""
        usage: python3 {sys.argv[0]} [ARGUMENTS]

        example: python3 {sys.argv[0]} --token=abc123 --wordlist=/path/to/wordlist.txt


        ARGUMENTS:
            --token                 YOUR JWT TOKEN
            --wordlist              WORDLIST
    """
    print(menu)

def verify_path(w):
    if os.path.isfile(w):
        return True
    return False

def validate_token_form(t):
    try:
        jwt.get_unverified_header(token)
        jwt.decode

def decode_token(t):
    headerb64, payloadb64, signatureb64 = t.split(".")

    header = json.loads(urlsafe_b64decode(header))
    payload = json.loads(urlsafe_b64decode(payload))
    signature = urlsafe_b64decode(signature)

    return ((header, payload, signature), (headerb64, payloadb64, signatureb64))

def validate_alg(alg):
    if alg.upper() in ["HS256", "HS384", "HS512"]:
        return True
    return False

def validate_match(candidate, token, payload, alg):
    candidate_token = jwt.encode(payload, candidate, algorithm=alg)
    if candidate_token == token:
        return True
    else:
        return False

def brute_force(t, w):
    decoded_parts, encoded_parts = decode_token(t)
    header, payload, signature = decoded_parts

    alg = header["alg"]
    if not validate_alg(alg):
        usage()
        sys.exit(f"[!] Algorithm not valid: {alg}")

    # atp: valid wordlist + valid alg
    with open(w, "r") as f:
        for line in f:
            candidate = line.rstrip("\n")
            if validate_match(candidate, t, payload, alg):
                print(f"[+] Key found: {candidate}")
                break
            

def main():
    if len(sys.argv) < 3:
        usage()
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("--token", required=True, help="Token value")
    parser.add_argument("--wordlist", required=True, help="Path to wordlist")
    args = parser.parse_args()
    print(f"[+] Token: {args.token}")
    print(f"[+] Path: {args.wordlist}")

    if not verify_path(args.wordlist):
        sys.exit(f"[!] Wordlist not found: {args.wordlist}")

    

    # now we must find the key that produces
    brute_force(args.token, args.wordlist)


if __name__ == "__main__":
    main()
