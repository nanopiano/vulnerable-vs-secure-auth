"""
safe_server.py — Bob (Server)
Mitigated Authentication Protocol - Figure 2

How it works:
  1. Bob receives "I'm Alice" + alice_nonce from Alice
  2. Bob sends back bob_nonce + E("Bob", alice_nonce_hash, shared_key)
     to prove he has the shared key
  3. Bob receives E("Alice", hash_pass_bob_nonce, shared_key) from Alice
     hash_pass_bob_nonce = SHA-256(password + bob_nonce)
     Bob computes the same hash locally and compares — verifies Alice
     knows the password and has the shared key
  4. both sides verified — mutual authentication done

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

  handle_client(conn, addr)
      runs the full protocol with one connected client

  main()
      starts the server and keeps it running waiting for connections

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

# shared key — must be exactly 32 bytes for AES-256
shared_key = b"wxacadpqc3vkerbv5group5$&aes7940"

SERVER_HOST = "0.0.0.0"  # accept connections from any machine
SERVER_PORT = 9998

user_database = {
    "Alice": "password123",
    "Bob":   "helloworld89/jo"
}


def add_padding(data: bytes) -> bytes:
    missing_bytes = 16 - (len(data) % 16)
    return data + bytes([missing_bytes] * missing_bytes)


def remove_padding(data: bytes) -> bytes:
    num_padding_bytes = data[-1]
    return data[:-num_padding_bytes]


def encrypt_message(message: str, key: bytes) -> str:
    session_iv      = os.urandom(16)
    aes_cipher      = AES.new(key, AES.MODE_CBC, session_iv)
    encrypted_bytes = aes_cipher.encrypt(add_padding(message.encode()))
    return base64.b64encode(session_iv + encrypted_bytes).decode()


def decrypt_message(encrypted: str, key: bytes) -> str:
    raw_bytes  = base64.b64decode(encrypted)
    session_iv = raw_bytes[:16]
    aes_cipher = AES.new(key, AES.MODE_CBC, session_iv)
    return remove_padding(aes_cipher.decrypt(raw_bytes[16:])).decode()


def handle_client(conn, addr):
    print(f"\n{CYAN}[BOB] Incoming connection from {addr}{RESET}")

    # ----- Message 1 -----
    # receive "I'm Alice" + alice_nonce from Alice
    message1         = conn.recv(4096).decode()
    msg1_parts       = message1.split("|")
    identity         = msg1_parts[0]
    alice_nonce      = msg1_parts[1]
    alice_nonce_hash = hashlib.sha256(alice_nonce.encode()).hexdigest()
    username         = identity[4:]  # grab name after "I'm "

    print(f"{CYAN}[BOB] Received identity: '{identity}'{RESET}")
    print(f"{CYAN}[BOB] Received alice_nonce: {alice_nonce}{RESET}")
    print(f"{YELLOW}[BOB] alice_nonce_hash (SHA-256 of alice_nonce): {alice_nonce_hash}{RESET}")

    # check if we know this user
    if username not in user_database:
        print(f"{RED}[BOB] Unknown user '{username}'. Rejecting.{RESET}")
        conn.send("AUTH_FAILED".encode())
        conn.close()
        return
    print()

    # ----- Message 2 -----
    # generate bob_nonce, encrypt "Bob" + alice_nonce_hash and send to Alice
    bob_nonce     = str(int.from_bytes(os.urandom(64), byteorder='big'))
    bob_encrypted = encrypt_message(f"Bob|{alice_nonce_hash}", shared_key)

    print(f"{YELLOW}[BOB] Generated bob_nonce: {bob_nonce}{RESET}")
    print(f"{YELLOW}[BOB] Encrypted 'Bob' + alice_nonce_hash with shared_key{RESET}")
    print(f"{YELLOW}[BOB] Encrypted message: {bob_encrypted}{RESET}")
    conn.send(f"{bob_nonce}|{bob_encrypted}".encode())
    print(f"{CYAN}[BOB] Sent bob_nonce and encrypted message to Alice{RESET}")
    print()

    # ----- Message 3 -----
    # receive E("Alice", hash_pass_bob_nonce, shared_key) from Alice and verify
    alice_encrypted = conn.recv(4096).decode()
    print(f"{CYAN}[BOB] Received encrypted message from Alice{RESET}")
    print(f"{CYAN}[BOB] Encrypted message: {alice_encrypted}{RESET}")

    try:
        decrypted_alice_msg = decrypt_message(alice_encrypted, shared_key)
        msg_contents        = decrypted_alice_msg.split("|")
        sender_name         = msg_contents[0]
        received_hash       = msg_contents[1]

        # Bob computes the same hash locally using stored password and bob_nonce
        stored_password     = user_database[username]
        hash_pass_bob_nonce = hashlib.sha256((stored_password + bob_nonce).encode()).hexdigest()

        print(f"{YELLOW}[BOB] Decrypted message: '{decrypted_alice_msg}'{RESET}")
        print(f"{YELLOW}[BOB] Computed hash_pass_bob_nonce — SHA-256 of (stored password + bob_nonce): {hash_pass_bob_nonce}{RESET}")

        # verify Alice sent the correct name and hash_pass_bob_nonce
        if sender_name == "Alice" and received_hash == hash_pass_bob_nonce:
            print(f"{GREEN}[BOB] ✅ Match confirmed — the hash Alice sent equals the hash Bob computed, Alice is authenticated!{RESET}")
            conn.send("AUTH_SUCCESS".encode())
        else:
            print(f"{RED}[BOB] ❌ Verification failed — wrong credentials or key!{RESET}")
            conn.send("AUTH_FAILED".encode())

    except Exception as error:
        print(f"{RED}[BOB] Decryption failed — {error}{RESET}")
        conn.send("AUTH_FAILED".encode())

    print()
    conn.close()


def main():
    print(GREEN + r"""
  ____        _     
 | __ )  ___ | |__  
 |  _ \ / _ \| '_ \ 
 | |_) | (_) | |_) |
 |____/ \___/|_.__/ 
""" + RESET)
    print(f"{CYAN}  Mitigated Authentication Protocol — Server (Bob)")
    print(f"  Listening on {SERVER_HOST}:{SERVER_PORT}")
    print(f"  Waiting for connections...{RESET}\n")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((SERVER_HOST, SERVER_PORT))
    server.listen(5)

    while True:
        conn, addr = server.accept()
        handle_client(conn, addr)


if __name__ == "__main__":
    main()
