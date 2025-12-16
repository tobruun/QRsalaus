import secrets
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import modes, algorithms, Cipher
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.padding import PKCS7

from enum import Enum
# General structure for password encryption: Passphrase and cleartext in -> generate nonce -> Argon2id Passphrase -> Pad cleartext -> encrypt cleartext -> output ciphertext
# General structure for password decryption: Passphrase and ciphertext in -> Argon2id Passphrase -> Try decrypt -> depad -> output cleartext

class MODES(Enum):
    NONE = 0
    AESGCM = 1
    AESCTR = 2
    CHACHA20POLY = 3

def b32_encode(input: bytes) -> str:
    input = base64.b32encode(input)
    s : str = input.decode("ascii")
    s = s.replace("=", "$")
    return s

def b32_decode(input: str) -> bytes:
    input = input.replace("$", "=")
    b : bytes = input.encode("ascii")
    b = base64.b32decode(b)
    return b    

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

def _aes_gcm_encrypt(cleartext: bytes, key: bytes, nonce: bytes) -> bytes:
    padder = PKCS7(128).padder()
    padded_cleartext = padder.update(cleartext)
    padded_cleartext += padder.finalize()
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, padded_cleartext, None)
    return ciphertext

def _aes_gcm_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:    
    unpadder = PKCS7(128).unpadder()
    aes = AESGCM(key)
    cleartext_padded = aes.decrypt(nonce, ciphertext, None)
    cleartext = unpadder.update(cleartext_padded)
    cleartext += unpadder.finalize()
    return cleartext

def _chachapoly_encryption(cleartext: bytes, key: bytes, nonce: bytes) -> bytes:
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, cleartext, None)
    return ciphertext

def _chachapoly_decryption(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    chacha = ChaCha20Poly1305(key)
    cleartext = chacha.decrypt(nonce, ciphertext, None)
    return cleartext

def _aes_ctr_encrypt(cleartext: bytes, key: bytes, nonce: bytes) -> bytes:
    # This is abit sus, only 12 bytes of random and can fit 16 TODO: Do better
    _ = int.from_bytes(nonce)
    nonce = _.to_bytes(length=16)
    aes = Cipher(algorithms.AES256(key), modes.CTR(nonce))
    aesenc = aes.encryptor()
    ciphertext = aesenc.update(cleartext) + aesenc.finalize()
    return ciphertext

def _aes_ctr_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    # This is abit sus, only 12 bytes of random and can fit 16 TODO: Do better
    _ = int.from_bytes(nonce)
    nonce = _.to_bytes(length=16)
    aes = Cipher(algorithms.AES256(key), modes.CTR(nonce))
    aesdec = aes.decryptor()
    cleartext = aesdec.update(ciphertext) + aesdec.finalize()
    return cleartext
    

def encrypt(cleartext: str, password: bytes, mode) -> tuple[bytes, bytes]:
    # Prep for encryption. Used nonce by argon and AES
    if mode == MODES.NONE:
        return (cleartext.encode(), b"")
    nonce = secrets.randbits(96).to_bytes(length=12)
    secret = _argon_the_password(password, nonce)
    text = cleartext.encode()
    ciphertext: bytes = b""
    
    match mode:
        case MODES.AESGCM:
            ciphertext = _aes_gcm_encrypt(text, secret, nonce)
        case MODES.AESCTR:
            ciphertext = _aes_ctr_encrypt(text, secret, nonce)
        case MODES.CHACHA20POLY:
            ciphertext = _chachapoly_encryption(text, secret, nonce)
        case _:
            raise NotImplementedError("Encryption mode not found. Try using the MODES enum.")
    
    return (ciphertext, nonce)
    
def decrypt(ciphertext: bytes, password: bytes, nonce: bytes, mode) -> bytes:

    if mode == MODES.NONE:
        return ciphertext
    
    secret = _argon_the_password(password, nonce)
    cleartext: bytes = b""

    match mode:
        case MODES.AESGCM:
            cleartext = _aes_gcm_decrypt(ciphertext, secret, nonce)
        case MODES.AESCTR:
            cleartext = _aes_ctr_decrypt(ciphertext, secret, nonce)
        case MODES.CHACHA20POLY:
            cleartext = _chachapoly_decryption(ciphertext, secret, nonce)
        case _:
            raise NotImplementedError("Decryption mode not found. Try using the MODES enum.")
    
    return cleartext


if __name__ == "__main__":
    text = "This is a test text"
    encrypted = encrypt(text, b"test123", MODES.AESGCM)
    print(encrypted[0], encrypted[1])
    print(decrypt(encrypted[0], b"test123", encrypted[1], MODES.AESGCM).decode("utf-8"))

    text = "This is a test text with a counter"
    encrypted = encrypt(text, b"test345", MODES.AESCTR)
    print(encrypted[0], encrypted[1])
    print(decrypt(encrypted[0], b"test345", encrypted[1], MODES.AESCTR).decode("utf-8"))

    text = "Cha cha is a dance"
    encrypted = encrypt(text, b"chacha12", MODES.CHACHA20POLY)
    print(encrypted[0], encrypted[1])
    print(decrypt(encrypted[0], b"chacha12", encrypted[1], MODES.CHACHA20POLY).decode("utf-8"))