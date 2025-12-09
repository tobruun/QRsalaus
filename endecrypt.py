import secrets
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.padding import PKCS7

from enum import Enum
# General structure for password encryption: Passphrase and cleartext in -> generate nonce -> Argon2id Passphrase -> Pad cleartext -> encrypt cleartext -> output ciphertext
# General structure for password decryption: Passphrase and ciphertext in -> Argon2id Passphrase -> Try decrypt -> depad -> output cleartext

class MODES(Enum):
    AESGCM = 1
    CHACHA20POLY = 2

def _argon_the_password(password: bytes, salt: bytes) -> bytes:
    # OWASP recommendation with 12288 kb of memory is 3 iterations with 1 lane, using a bit longer process
    argon = Argon2id(
        salt=salt,
        length=32,
        iterations=4,
        lanes=2,
        memory_cost=12288
    )
    # To avoid nonce reuse, increase the value by 1. Only done internally
    _ = int.from_bytes(salt)
    _ += 1
    salt = _.to_bytes(length=12)
    return argon.derive(password)

def _aes_gcm_encrypt(cleartext: bytes, key: bytes, nonce: bytes):
    padder = PKCS7(128).padder()
    padded_cleartext = padder.update(cleartext)
    padded_cleartext += padder.finalize()
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, padded_cleartext, None)
    return ciphertext

def _aes_gcm_decrypt(ciphertext: bytes, key: bytes, nonce: bytes):    
    unpadder = PKCS7(128).unpadder()
    aes = AESGCM(key)
    cleartext_padded = aes.decrypt(nonce, ciphertext, None)
    cleartext = unpadder.update(cleartext_padded)
    cleartext += unpadder.finalize()
    return cleartext


def encrypt(cleartext: str, password: bytes, mode):
    # Prep for encryption. Used nonce by argon and AES
    nonce = secrets.randbits(96).to_bytes(length=12)
    secret = _argon_the_password(password, nonce)
    text = cleartext.encode()
    ciphertext: bytes = b""
    
    match mode:
        case MODES.AESGCM:
            ciphertext = _aes_gcm_encrypt(text, secret, nonce)
    
    return (ciphertext, nonce)
    

def decrypt(ciphertext: bytes, password: bytes, nonce: bytes, mode):
    secret = _argon_the_password(password, nonce)
    cleartext: bytes = b""

    match mode:
        case MODES.AESGCM:
            cleartext = _aes_gcm_decrypt(ciphertext, secret, nonce)
    
    return cleartext.decode("utf-8")


if __name__ == "__main__":
    text = "This is a test text"
    encrypted = encrypt(text, b"test123", MODES.AESGCM)
    print(encrypted[0], encrypted[1])
    print(decrypt(encrypted[0], b"test123", encrypted[1], MODES.AESGCM))