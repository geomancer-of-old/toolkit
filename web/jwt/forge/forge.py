import sys
import jwt
import json

def usage():
    print(f"Usage: python3 {sys.argv[0]} [algorithm] [claims] [secret-key]")
    more_text = """
        Available Algorithms:
            None                    No signing algorithm used
            Symmetric Algorithms (HMAC)
                HS256                   uses SHA-256
                HS384                   uses SHA-384
                HS512                   uses SHA-512
            Asymmetric Algorithms (RSA & ECDSA)
                RS256                   RSASSA-PKCS1-v1_5 using SHA-256
                RS384/RS512             RSASSA-PKCS1-v1_5 using SHA-384 or SHA-512
                PS256/PS384/PS512       RSASSA-PS usinh SHA-256, SHA-384 or SHA-512
    """
    print(more_text)


def deserialise(str_data):
    data = json.loads(str_data)
    return data

def find_claims(s):
    start = s.rfind("{")
    end = s.rfind("}")
    if start == -1 or end == -1 or end < start:
        return (None, None, "This program defaults to an empty claim if incorrectly formatted")
    else:
        return (s[start:end+1],end, "Claims successfully parsed")


def parse_claims_and_key(s):
    claims, end, msg = find_claims(s)
    print(f"[+] {msg}: {claims}")
    if claims is None:
        sys.exit("[!} Refusing to sign: provide claims as JSON")

    secret = s[end+1:].strip()
    print(f"[+] Secret: {secret}")
    return (deserialise(claims), secret)

def validate_alg(alg):
    if alg.upper() in ["NONE", "HS256","HS384","HS512","RS256","RS384","RS512","PS256","PS384","PS512"]:
        return True
    return False

def main():
    if (len(sys.argv) < 3):
        usage()
        sys.exit(1)
    alg = sys.argv[1]
    if not validate_alg(alg):
        print(f"[!] {alg} is not a supported JWT signing algorithm")
        usage()
        sys.exit(1)

    claims, key = parse_claims_and_key(" ".join(sys.argv[2:]))

    key = None if alg.upper() == "NONE" else key
    if alg.upper() == "NONE":
        key = None
        alg = "none"

    forged_jwt = jwt.encode(claims, key, algorithm=alg)
    print(f"[!] Forged JWT: {forged_jwt}")


if __name__ == "__main__":
    main()
