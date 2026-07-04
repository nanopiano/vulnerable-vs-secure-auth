"""
server.py — Bob (Server)
Vulnerable Authentication Protocol - Figure 1

How it works:
  1. Bob waits for Alice to say "I'm Alice"
  2. Bob sends back a random number (nonce)
  3. Alice hashes her password with the nonce and sends it
  4. Bob does the same hash and checks if they match

Functions in this file:
  compute_hash(password, nonce)
      takes a password and nonce, sticks them together, and runs
      SHA-256 on it. both Alice and Bob use this same function —
      if they get the same result, the password was correct.

  handle_client(conn, addr)
      runs the full authentication conversation with one client.
      called every time someone connects.

  main()
      starts the server and keeps it running, waiting for clients.

Built-in stuff we use:
  socket         — lets computers talk to each other over a network
  os.urandom()   — generates truly random bytes for the nonce
  hashlib        — gives us SHA-256 for hashing
  .encode()      — turns a string into bytes so we can send it over the network
  .decode()      — turns received bytes back into a readable string
"""

import socket
import hashlib
import os

# terminal colors — makes the output easier to read
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"

# this is Bob's "database" — stores usernames and their passwords
# in real life you'd never store passwords in plaintext like this!
USER_DATABASE = {
    "Alice": "password123",
    "Bob":   "securepass"
}

HOST = "0.0.0.0"       # accept connections from any machine on the network
PORT = 9999


def compute_hash(password: str, nonce: str) -> str:
    # stick the password and nonce together then hash them with SHA-256
    data = (password + nonce).encode()
    return hashlib.sha256(data).hexdigest()


def handle_client(conn, addr):
    print(f"\n{CYAN}[BOB] Incoming connection from {addr}{RESET}")

    # step 1 — find out who is connecting
    identity_msg = conn.recv(1024).decode()
    print(f"{CYAN}[BOB] Identity claim received: '{identity_msg}'{RESET}")

    if not identity_msg.startswith("I'm "):
        print(f"{RED}[BOB] Unrecognised message format. Dropping connection.{RESET}")
        conn.close()
        return

    username = identity_msg[4:]  # grab just the name after "I'm "

    # check if we actually know this user
    if username not in USER_DATABASE:
        print(f"{RED}[BOB] Unknown user '{username}'. Rejecting.{RESET}")
        conn.send("UNKNOWN_USER".encode())
        conn.close()
        return

    # step 2 — generate a fresh random nonce and send it to Alice
    # 64 random bytes = 512-bit number, basically impossible to predict or repeat
    nonce = str(int.from_bytes(os.urandom(64), byteorder='big'))
    print(f"{YELLOW}[BOB] Nonce generated and sent to {username}{RESET}")
    print(f"{YELLOW}[BOB] Nonce: {nonce}{RESET}")
    conn.send(nonce.encode())

    # step 3 — receive the hash Alice computed
    received_hash = conn.recv(4096).decode()  # 4096 buffer to handle the large nonce
    print(f"{CYAN}[BOB] Hash received from {username}: {received_hash}{RESET}")

    # step 4 — compute the same hash ourselves and compare
    stored_password = USER_DATABASE[username]
    print(f"{YELLOW}[BOB] Stored password for {username}: {stored_password}{RESET}")
    print(f"{YELLOW}[BOB] Hashing: SHA-256('{stored_password}' + nonce){RESET}")
    expected_hash   = compute_hash(stored_password, nonce)
    print(f"{YELLOW}[BOB] Expected hash : {expected_hash}{RESET}")
    print(f"{YELLOW}[BOB] Received hash : {received_hash}{RESET}")

    if received_hash == expected_hash:
        print(f"{GREEN}[BOB] Hash match confirmed — {username} is authenticated!{RESET}")
        conn.send("AUTH_SUCCESS".encode())
    else:
        print(f"{RED}[BOB] Hash mismatch — authentication denied for {username}.{RESET}")
        conn.send("AUTH_FAILED".encode())

    conn.close()


def main():
    print(GREEN + r"""
  ____        _     
 | __ )  ___ | |__  
 |  _ \ / _ \| '_ \ 
 | |_) | (_) | |_) |
 |____/ \___/|_.__/ 
""" + RESET)
    print(f"{CYAN}  Vulnerable Authentication Protocol — Server (Bob)")
    print(f"  Listening on {HOST}:{PORT}")
    print(f"  Waiting for connections...{RESET}\n")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # avoid "port in use" errors on restart
    server.bind((HOST, PORT))
    server.listen(5)  # allow up to 5 queued connections

    while True:
        conn, addr = server.accept()  # wait for someone to connect
        handle_client(conn, addr)


if __name__ == "__main__":
    main()
