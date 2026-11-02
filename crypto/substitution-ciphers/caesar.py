import sys
import string


def calculate_plaintext(cipher, shift):
    plaintext = ""
    cipher = cipher.upper()

    for c in cipher:
        if c.isalpha():
            pos = mappings.index(c)
            pos = (pos - shift) % 26
            letter = mappings[pos]
        else:
            letter = c

        plaintext += letter

    return plaintext

def convert_to_int(num):
    try:
        iNum = int(num)
    except ValueError as e:
        print(f"[!] Exception occurred: {e}")
        sys.exit(1)
    return iNum

def main():    
    guess_shift = input("[+] Enter shift estimate: ")
    opt = input("[+] Are you certain of the shift [y/N]: ")
    
    if opt == "y" or opt == "Y":
        cipher = input("[+] Enter the cipher: ")
        shift = convert_to_int(guess_shift)
        plaintext = calculate_plaintext(cipher, shift)
        print(f"[+] Your plaintext value is {plaintext}")
    elif opt == "n" or "N":
        width = input("[+] How wide would you like to go?: ")
        cipher = input("[+] Enter the cipher: ")
        width = convert_to_int(width)

        start = convert_to_int(guess_shift) - width
        end = convert_to_int(guess_shift) + width
        candidate_shifts = [i for i in range(start, end+1)]

        print("="*20 + "\n")
        for candidate in candidate_shifts:
            plaintext = calculate_plaintext(cipher, candidate)
            print(f"[+] Your plaintext value is {plaintext}")

if __name__ == "__main__":
    mappings = [letter for letter in string.ascii_uppercase]
    main()