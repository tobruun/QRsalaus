# Secure QR

Serverless option for encrypted QR-codes. This project includes a proof of concept with a working python implementation. This is a project work for the course Cybersecurity Project in University of Oulu.

The basic idea is to generate safe, encrypted and available offline QR-codes. QR-codes are secured with a password which are hashed using Argon2id. This project includes a spesification for implementation to other projects.

## Spesifications

### Nonce

12 bits generated using a secure random number generator. It is used as an IV for ciphers.

### Argon2id

Argon2id uses following settings:

| Setting | Value |
| ---- | ----- |
| salt | 12 bytes |
| length | 32 bytes |
| iterations | 4 |
| lanes | 2 |
| memory cost | 12288 kB |

The salt that is included with Argon2id is the **nonce which value is incremented by 1** to avoid nonce reuse issues.

### Included ciphers

256 bit AES-GCM (AEAD) with 12 byte IV (nonce).

256 bit Chacha20-Poly1305 (AEAD) with 12 byte IV (nonce).

256 bit AES-CTR with 16 byte IV (nonce expanded with zeros).

### Byte32 encoding

This project uses byte32 encoding to take advantage of QR-code's possibility to use alphanumeric encoding. The padding character is changed from `=` to `$` due to compatability.