import sys
import argparse
import base64

def decode(part):
    
    padding = "=" * (-len(part) % 4)
    d = base64.urlsafe_b64decode(part + padding)
    return d

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--token")
    arg = parser.parse_args()

    parts = arg.token.split(".")

    if len(parts) != 3:
        parser.error("Token must have 3 dot-separated parts (header, payload, signature)")

    header, payload, signature = parts

    print(f"Header: {decode(header)}")
    print(f"Payload: {decode(payload)}")
    print(f"Signature: {decode(signature).hex()}")

    

if __name__ == "__main__":
    main()