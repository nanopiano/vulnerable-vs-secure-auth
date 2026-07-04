"""
safe_client.py — Alice (Client)
Mitigated Authentication Protocol - Figure 2

How it works:
  1. Alice enters her username and password locally — password never leaves her machine
  2. Alice sends "I'm Alice" + alice_nonce to Bob
  3. Bob sends back bob_nonce + E("Bob", alice_nonce_hash, shared_key)
     Alice decrypts this to verify Bob actually has the shared key
  4. Alice sends E("Alice", hash_pass_bob_nonce, shared_key) to Bob
     hash_pass_bob_nonce = SHA-256(password + bob_nonce)
     Bob decrypts and verifies Alice knows the password and has the shared key
  5. both sides verified — mutual authentication done

Why the password is never sent over the network:
  Alice hashes her password with bob_nonce locally and sends only the hash
  inside the encrypted message, so the password never leaves her machine

Functions in this file:
  add_padding(data)
      AES needs data in 16 byte chunks — adds padding to make that happen

  remove_padding(data)
      removes the padding after decryption

  encrypt_message(message, key)
      encrypts with AES-CBC using a random session_iv, returns base64 encoded result

  decrypt_message(encrypted, key)
      decrypts the base64 encoded message and returns the original text

  main()
      runs the full client side protocol flow

Libraries we use:
  socket             — so Alice and Bob can talk over the network
  os.urandom()       — generates random bytes for the nonce
  hashlib            — SHA-256 to hash the nonces and password
  Crypto.Cipher.AES  — AES encryption from pycryptodome
  base64             — turns encrypted bytes into text so we can send over socket
"""

import socket
import os
import hashlib
import base64
from Crypto.Cipher import AES

# terminal colors
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"

# shared key — must match exactly what Bob has, exactly 32 bytes for AES-256
shared_key = b"wxacadpqc3vkerbv5group5$&aes7940"

BOB_IP   = "172.20.10.2"  # Bob's IP address
BOB_PORT = 9998


def add_padding(data: bytes) -> bytes:
    # AES needs input in 16 byte blocks so we pad whatever is missing
    missing_bytes = 16 - (len(data) % 16)
    return data + bytes([missing_bytes] * missing_bytes)


def remove_padding(data: bytes) -> bytes:
    # strip the padding off after decryption
    num_padding_bytes = data[-1]
    return data[:-num_padding_bytes]


def encrypt_message(message: str, key: bytes) -> str:
    # fresh random IV every time so the same message never looks the same
    session_iv      = os.urandom(16)
    aes_cipher      = AES.new(key, AES.MODE_CBC, session_iv)
    encrypted_bytes = aes_cipher.encrypt(add_padding(message.encode()))
    return base64.b64encode(session_iv + encrypted_bytes).decode()


def decrypt_message(encrypted: str, key: bytes) -> str:
    # decode from base64 then grab the IV from the first 16 bytes
    raw_bytes  = base64.b64decode(encrypted)
    session_iv = raw_bytes[:16]
    aes_cipher = AES.new(key, AES.MODE_CBC, session_iv)
    return remove_padding(aes_cipher.decrypt(raw_bytes[16:])).decode()


def main():
    print(GREEN + r"""
    _    _ _
   / \  | (_) ___ ___
  / _ \ | | |/ __/ _ \
 / ___ \| | | (_|  __/
/_/   \_\_|_|\___\___|
""" + RESET)
    print(f"{CYAN}  Mitigated Authentication Protocol — Client (Alice)")
    print(f"  Connecting to Bob at {BOB_IP}:{BOB_PORT}{RESET}\n")

    # Alice enters credentials locally — password never leaves this machine
    username = input(f"{YELLOW}[ALICE] Username: {RESET}")
    password = input(f"{YELLOW}[ALICE] Password: {RESET}")
    print()

    # connect to Bob
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((BOB_IP, BOB_PORT))
    print(f"{CYAN}[ALICE] Connected to Bob successfully{RESET}")
    print()

    # ----- Message 1 -----
    # generate alice_nonce and send "I'm Alice" + alice_nonce to Bob
    alice_nonce      = str(int.from_bytes(os.urandom(64), byteorder='big'))
    alice_nonce_hash = hashlib.sha256(alice_nonce.encode()).hexdigest()

    print(f"{YELLOW}[ALICE] Generated alice_nonce: {alice_nonce}{RESET}")
    print(f"{YELLOW}[ALICE] Computed alice_nonce_hash — SHA-256 of alice_nonce: {alice_nonce_hash}{RESET}")
    client.send(f"I'm {username}|{alice_nonce}".encode())
    print(f"{CYAN}[ALICE] Sent to Bob: 'I'm {username}' + alice_nonce{RESET}")
    print()

    # ----- Message 2 -----
    # receive bob_nonce + E("Bob", alice_nonce_hash, shared_key) from Bob
    received_msg  = client.recv(4096).decode()
    msg_parts     = received_msg.split("|", 1)
    bob_nonce     = msg_parts[0]
    bob_encrypted = msg_parts[1]

    print(f"{CYAN}[ALICE] Received from Bob: bob_nonce + encrypted message{RESET}")
    print(f"{CYAN}[ALICE] bob_nonce: {bob_nonce}{RESET}")
    print(f"{CYAN}[ALICE] Encrypted message: {bob_encrypted}{RESET}")

    # decrypt and verify Bob's message
    try:
        decrypted_bob_msg = decrypt_message(bob_encrypted, shared_key)
        msg_contents      = decrypted_bob_msg.split("|")
        sender_name       = msg_contents[0]
        received_hash     = msg_contents[1]

        print(f"{YELLOW}[ALICE] Decrypted Bob's message: '{decrypted_bob_msg}'{RESET}")
        print(f"{YELLOW}[ALICE] Checking — does the decrypted message contain 'Bob' and the correct alice_nonce_hash?{RESET}")

        if sender_name != "Bob" or received_hash != alice_nonce_hash:
            print(f"{RED}[ALICE] ❌ Bob verification FAILED — possible impersonation!{RESET}")
            client.close()
            return

        print(f"{GREEN}[ALICE] ✅ Match confirmed — Bob has shared_key and sent back correct alice_nonce_hash, Bob is verified!{RESET}")
        print()

    except Exception as error:
        print(f"{RED}[ALICE] Decryption failed — {error}{RESET}")
        client.close()
        return

    # ----- Message 3 -----
    # compute hash_pass_bob_nonce = SHA-256(password + bob_nonce)
    # this proves Alice knows the password without ever sending it
    hash_pass_bob_nonce = hashlib.sha256((password + bob_nonce).encode()).hexdigest()
    alice_encrypted     = encrypt_message(f"Alice|{hash_pass_bob_nonce}", shared_key)

    print(f"{YELLOW}[ALICE] Computed hash_pass_bob_nonce — SHA-256 of (password + bob_nonce): {hash_pass_bob_nonce}{RESET}")
    print(f"{YELLOW}[ALICE] Encrypted 'Alice' + hash_pass_bob_nonce with shared_key{RESET}")
    print(f"{YELLOW}[ALICE] Encrypted message: {alice_encrypted}{RESET}")
    client.send(alice_encrypted.encode())
    print(f"{CYAN}[ALICE] Sent to Bob: encrypted message containing 'Alice' + hash_pass_bob_nonce{RESET}")
    print()

    # get final result
    final_result = client.recv(1024).decode()

    if final_result == "AUTH_SUCCESS":
        print(f"{GREEN}[ALICE] ✅ Mutual Authentication SUCCESS — both Alice and Bob verified!{RESET}\n")
    else:
        print(f"{RED}[ALICE] ❌ Authentication FAILED.{RESET}\n")

    client.close()

if __name__ == "__main__":
    main()
