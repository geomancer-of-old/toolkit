import sys
import string


def rot13(cipher, shift=13):
    plaintext = ""
    cipher = cipher.upper()
    for letter in cipher:
        if letter.isalpha():
            pos = mappings.index(letter)
            pos += shift
            if (pos >= 26):
                pos = pos % 26
            plaintext += mappings[pos]
        else:
           plaintext += letter

    return plaintext

def main():
    cipher = input("[+] Enter the cipher: ")
    opt = input(f"[+] Are you certain the shift={shift}? [y/N] ")

    if opt == "y" or opt == "Y":
        plaintext = rot13(cipher, shift)
        print(f"[+] Plaintext: {plaintext}")
    elif opt == "n" or opt == "N":
        width = convert_to_int(input("[+] How wide would you like to go?: "))

        start = shift - width
        end = shift + width

        for i in range(start, end + 1):
            print(f"[+] Plaintext: {rot13(cipher, i)}")
    

    

def convert_to_int(num):
    try:
        num = int(num)
    except ValueError:
        print(f"[!] Exception occurred: {num}")
        sys.exit(1)

    return num

if __name__ == "__main__":
    print(f"Usage: python3 {sys.argv[0]} [shift]")
    
    shift = convert_to_int(sys.argv[1]) if len(sys.argv) >= 2 else 13

    mappings = [letter for letter in string.ascii_uppercase ]
    main()