"""
client.py — Alice (Client)
Vulnerable Authentication Protocol - Figure 1

How it works:
  1. Alice tells Bob who she is by sending "I'm Alice"
  2. Bob sends back a random number (nonce)
  3. Alice hashes her password with the nonce and sends it to Bob
  4. Bob checks the hash and tells Alice if she's authenticated

Functions in this file:
  compute_hash(password, nonce)
      takes a password and nonce, sticks them together, and runs
      SHA-256 on it. must be identical to the one in server.py —
      both sides need to produce the same hash for the same inputs.

  main()
      runs the full client-side flow — gets credentials from the
      user, connects to Bob, and follows the protocol.

Built-in stuff we use:
  socket           — lets computers talk to each other over a network
  hashlib          — gives us SHA-256 for hashing
  .encode()        — turns a string into bytes so we can send it over the network
  .decode()        — turns received bytes back into a readable string
"""

import socket
import hashlib

# terminal colors — makes the output easier to read
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"

HOST = "172.20.10.9"   # Bob's IP address (server on PC1)
PORT = 9999


def compute_hash(password: str, nonce: str) -> str:
    # stick the password and nonce together then hash them with SHA-256
    data = (password + nonce).encode()
    return hashlib.sha256(data).hexdigest()


def main():
    print(GREEN + r"""
    _    _ _
   / \  | (_) ___ ___
  / _ \ | | |/ __/ _ \
 / ___ \| | | (_|  __/
/_/   \_\_|_|\___\___|
""" + RESET)
    print(f"{CYAN}  Vulnerable Authentication Protocol — Client (Alice)")
    print(f"  Connecting to Bob at {HOST}:{PORT}{RESET}\n")

    # get Alice's credentials from the keyboard
    username = input(f"{YELLOW}[ALICE] Username: {RESET}")
    password = input(f"{YELLOW}[ALICE] Password: {RESET}")  # shown for demo purposes

    # connect to Bob's server
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    print(f"{CYAN}[ALICE] Connected to Bob successfully{RESET}")

    # step 1 — tell Bob who we are
    identity_msg = f"I'm {username}"
    client.send(identity_msg.encode())
    print(f"{CYAN}[ALICE] Sent identity claim: '{identity_msg}'{RESET}")

    # step 2 — receive the nonce Bob generated for us
    nonce = client.recv(4096).decode()  # 4096 buffer to handle the large 512-bit nonce

    if nonce == "UNKNOWN_USER":
        print(f"{RED}[ALICE] Server does not recognise user '{username}'. Exiting.{RESET}")
        client.close()
        return

    print(f"{CYAN}[ALICE] Nonce received from Bob: {nonce}{RESET}")

    # step 3 — hash our password with the nonce and send it to Bob
    hashed = compute_hash(password, nonce)
    print(f"{YELLOW}[ALICE] Hash computed: {hashed}{RESET}")
    client.send(hashed.encode())
    print(f"{YELLOW}[ALICE] Hash sent to Bob{RESET}")

    # step 4 — find out if Bob accepted us
    result = client.recv(1024).decode()

    if result == "AUTH_SUCCESS":
        print(f"\n{GREEN}[ALICE] ✅ Authentication SUCCESS — identity verified by Bob!{RESET}\n")
    else:
        print(f"\n{RED}[ALICE] ❌ Authentication FAILED — incorrect credentials.{RESET}\n")

    client.close()  # done, close the connection cleanly


if __name__ == "__main__":
    main()
