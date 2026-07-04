
# Authentication Protocol Attack and Mitigation

This project shows how a challenge response authentication protocol fails against network eavesdropping. It also shows how AES encryption and mutual authentication fix that failure.

## Overview

Alice acts as the client. Bob acts as the server. They authenticate over a socket connection using SHA 256 hashing and a nonce. The first version sends the hash in plain text. An attacker on the same network captures it with Wireshark and cracks the password offline using a wordlist.

The second version encrypts every message with AES 256 and adds mutual authentication. Bob proves he holds the shared key. Alice proves she knows the password. Neither one sends the password over the network. The attack fails against this version because there is nothing readable to capture.

## Environment

You need three machines on the same network for the full attack demo.

1. A client machine running client.py or safe_client.py. This machine acts as Alice.
2. A server machine running server.py or safe_server.py. This machine acts as Bob.
3. An attacker machine running Kali Linux with Wireshark and arpspoof installed. This machine runs attacker.py.

The original setup used a shared hotspot network with all three machines connected. You can also run everything on one machine using localhost if you just want to test the protocol logic without the network attack.

You need Python 3 and the pycryptodome library for the mitigated protocol.

```
pip install pycryptodome
```

## Threat model

The attacker sits on the same local network as Alice and Bob. The attacker sees all traffic on that network but starts with no access to either machine, no knowledge of the password, and no knowledge of any shared key.

The attacker uses ARP spoofing to redirect traffic between Alice and Bob through their own machine. This lets them capture packets with Wireshark even on a switched network. Once they capture the nonce and hash, they work completely offline. They do not need to interact with Alice or Bob again.

The attacker wants to recover Alice's password using an offline dictionary attack. They win against the vulnerable protocol because the hash and nonce travel as plain text. They fail against the mitigated protocol because both values sit inside an AES encrypted message they cannot read without the shared key.

This threat model does not cover an attacker who already has the shared key or physical access to either machine. Key distribution and key compromise sit outside the scope of this project.

## File structure

```
vulnerable/
    server.py
    client.py
    attacker.py
mitigated/
    safe_server.py
    safe_client.py
```

Vulnerable folder

1. server.py runs Bob. He generates the nonce and checks the hash.
2. client.py runs Alice. She sends her username and password.
3. attacker.py runs the offline dictionary attack using a captured nonce and hash.

Mitigated folder

1. safe_server.py runs Bob using AES 256 encryption and mutual authentication.
2. safe_client.py runs Alice using AES 256 encryption and mutual authentication.

## How to run the vulnerable protocol

Start the server first.

```
cd vulnerable
python server.py
```

Run the client in a separate terminal.

```
cd vulnerable
python client.py
```

Enter a username and password when prompted. Alice uses the password password123 by default, so you can test authentication right away.

## How to run the attack

You need Wireshark and a wordlist like rockyou.txt to capture real traffic. If you just want to see the attack logic work, copy the nonce and hash values printed in the client and server terminals. Paste them into attacker.py when it asks.

```
cd vulnerable
python attacker.py
```

The script tries every password in the wordlist against the captured nonce and hash until it finds a match.

## How to run the mitigated protocol

Update the shared_key value in both safe_server.py and safe_client.py so they match each other. Start the server.

```
cd mitigated
python safe_server.py
```

Run the client in a separate terminal.

```
cd mitigated
python safe_client.py
```

Try the same attack setup against this version. You only see the nonces in plain text. The password hash stays locked inside the encrypted message, so the dictionary attack has nothing to work with.

## Why the vulnerable protocol fails

The password never gets sent directly, but the hash and nonce travel in plain text. Once an attacker captures both, they guess passwords offline and check each guess against the same hash. Nothing in the protocol limits how many guesses an attacker can make. Nothing alerts Bob that something is wrong.

## Why the mitigated protocol holds up

Every message gets encrypted with a shared AES 256 key before it goes over the network. An attacker who captures the traffic sees random ciphertext instead of a usable hash. Both sides also prove they know the shared key, so no one can impersonate Alice or Bob without it.

AES 256 also holds up well against quantum computers. Quantum computing breaks algorithms like RSA, but it does not break AES the same way. The only real quantum threat here comes from Grover's algorithm, and that only cuts the effective key strength in half. AES 256 under that attack still gives you roughly 128 bit security, which stays strong by today's standards. Large quantum computers capable of running that attack do not exist yet, so this stays a future concern rather than something you need to fix right now.

## Context

built this to demo authentication and security models. It demonstrates protocol design flaws. It does not serve as a template for a production authentication system. Do not use the hardcoded shared key or plaintext password database in anything real.
