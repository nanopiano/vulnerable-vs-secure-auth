
# CSEC 472 Authentication Protocol Attack and Mitigation

This project shows how a simple challenge response authentication protocol fails against network eavesdropping. It also shows how AES encryption and mutual authentication fix that failure.

## What this project does

A client (Alice) and server (Bob) authenticate over a socket connection using SHA 256 hashing and a nonce. The first version sends the hash in plain text. An attacker on the same network captures it with Wireshark and cracks the password offline using a wordlist.

The second version encrypts every message with AES 256 and adds mutual authentication. Bob proves he holds the shared key. Alice proves she knows the password. Neither sends the password over the network. The same attack fails against this version because there is nothing readable to capture.

## Files

Vulnerable protocol

1. server.py runs Bob, the server. He generates the nonce and checks the hash.
2. client.py runs Alice, the client. She sends her username and password.
3. attacker.py runs the offline dictionary attack using a captured nonce and hash.

Mitigated protocol

1. safe_server.py runs Bob using AES 256 encryption and mutual authentication.
2. safe_client.py runs Alice using AES 256 encryption and mutual authentication.

## Requirements

You need Python 3. You also need the pycryptodome library for the mitigated protocol.

```
pip install pycryptodome
```

## How to run the vulnerable protocol

Start the server first.

```
python server.py
```

Run the client in a separate terminal.

```
python client.py
```

Enter a username and password when prompted. Alice uses the password password123 by default, so you can test authentication right away.

## How to run the attack

You need Wireshark and a wordlist like rockyou.txt to capture real traffic. If you just want to see the attack logic work, copy the nonce and hash values printed in the client and server terminals. Paste them into attacker.py when it asks.

```
python attacker.py
```

The script tries every password in the wordlist against the captured nonce and hash until it finds a match.

## How to run the mitigated protocol

Update the shared_key value in both safe_server.py and safe_client.py so they match. Start the server.

```
python safe_server.py
```

Run the client in a separate terminal.

```
python safe_client.py
```

Try the same attack setup against this version. You will only see the nonces in plain text. The password hash stays locked inside the encrypted message, so the dictionary attack has nothing to work with.

## Why the vulnerable protocol fails

The password never gets sent directly, but the hash and nonce travel in plain text. Once an attacker captures both, they guess passwords offline and check each guess against the same hash. Nothing in the protocol limits how many guesses an attacker can make. Nothing alerts Bob that something is wrong.

## Why the mitigated protocol holds up

Every message gets encrypted with a shared AES 256 key before it goes over the network. An attacker who captures the traffic sees random ciphertext instead of a usable hash. Both sides also prove they know the shared key, so no one can impersonate Alice or Bob without it.

## Context

Built this as part of my course work. It demonstrates protocol design flaws. It does not serve as a template for a production authentication system. Do not use the hardcoded shared key or plaintext password database in anything real.
