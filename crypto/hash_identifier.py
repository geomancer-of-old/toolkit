#!/usr/bin/env python3
"""
hash_identifier.py — Identify likely hash types from a string.

Heuristic identifier based on length and character set. Like any such tool
(hashid, hash-identifier), it guesses *candidates* — many algorithms share the
same length and alphabet, so results are ranked possibilities, not certainties.

Usage:
    python3 hash_identifier.py <hash>
    python3 hash_identifier.py -f hashes.txt
    echo "<hash>" | python3 hash_identifier.py
"""

import argparse
import re
import sys

# (name, compiled regex, note). Order roughly by how common / specific it is.
# Prefixed formats (with $sigil$) are checked first since they're unambiguous.
HASH_DB = [
    # --- Unambiguous prefixed / structured formats ---
    ("bcrypt",                 r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$", "Blowfish-based, used for passwords"),
    ("MD5 crypt",              r"^\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$", "Unix crypt (md5crypt)"),
    ("SHA-256 crypt",          r"^\$5\$[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{43}$", "Unix crypt"),
    ("SHA-512 crypt",          r"^\$6\$[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{86}$", "Unix crypt (/etc/shadow)"),
    ("Argon2",                 r"^\$argon2(id|i|d)\$.+$", "Modern password hashing (PHC)"),
    ("PHPass / Wordpress",     r"^\$(P|H)\$[./A-Za-z0-9]{31}$", "phpBB3, WordPress, Drupal7"),
    ("Django PBKDF2-SHA256",   r"^pbkdf2_sha256\$\d+\$.+$", "Django default"),
    ("NTLM (prefixed)",        r"^\$NT\$[a-fA-F0-9]{32}$", ""),

    # --- Raw hex digests (by length) ---
    ("CRC-32",                 r"^[a-fA-F0-9]{8}$", "Checksum, not cryptographic"),
    ("MySQL < 4.1",            r"^[a-fA-F0-9]{16}$", "Old MySQL password hash"),
    ("MD5 / MD4 / NTLM",       r"^[a-fA-F0-9]{32}$", "32 hex is very ambiguous (MD5, NTLM, MD4, LM, RIPEMD-128)"),
    ("SHA-1",                  r"^[a-fA-F0-9]{40}$", "Also MySQL5, RIPEMD-160, Tiger-160, HAVAL-160"),
    ("SHA-224",                r"^[a-fA-F0-9]{56}$", "Also SHA3-224, HAVAL-224"),
    ("SHA-256",                r"^[a-fA-F0-9]{64}$", "Also SHA3-256, RIPEMD-256, Keccak-256, BLAKE2s"),
    ("SHA-384",                r"^[a-fA-F0-9]{96}$", "Also SHA3-384"),
    ("SHA-512",                r"^[a-fA-F0-9]{128}$", "Also SHA3-512, Whirlpool, BLAKE2b, Keccak-512"),

    # --- MySQL 4.1+ ---
    ("MySQL 4.1+ (SHA1(SHA1))", r"^\*[A-F0-9]{40}$", "Leading asterisk, uppercase hex"),

    # --- Base64-ish digests ---
    ("LDAP {SSHA}",            r"^\{SSHA\}[A-Za-z0-9+/]+={0,2}$", "Salted SHA-1, base64"),
    ("LDAP {SHA}",             r"^\{SHA\}[A-Za-z0-9+/]{27}=$", "Unsalted SHA-1, base64"),
]


def identify(h: str):
    """Return a list of (name, note) candidates for the given hash string."""
    h = h.strip()
    matches = [(name, note) for name, pattern, note in HASH_DB if re.match(pattern, h)]
    return matches


def report(h: str):
    h = h.strip()
    if not h:
        return
    print(f"\n[*] Analyzing: {h}")
    print(f"    Length: {len(h)} chars")
    matches = identify(h)
    if not matches:
        print("    No match found. May be an uncommon or truncated hash, or not a hash at all.")
        return
    print("    Possible types (most specific first):")
    for name, note in matches:
        suffix = f"  — {note}" if note else ""
        print(f"      - {name}{suffix}")


def main():
    parser = argparse.ArgumentParser(description="Identify likely hash types from a string.")
    parser.add_argument("hash", nargs="?", help="The hash string to identify")
    parser.add_argument("-f", "--file", help="Read hashes from a file, one per line")
    args = parser.parse_args()

    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    report(line)
        except OSError as e:
            print(f"Error reading {args.file}: {e}", file=sys.stderr)
            sys.exit(1)
    elif args.hash:
        report(args.hash)
    elif not sys.stdin.isatty():
        for line in sys.stdin:
            report(line)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
