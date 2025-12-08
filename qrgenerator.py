import qrcode

import base64
import os

from pyzbar.pyzbar import decode
from PIL import Image

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


## hashing and running through PBKDFH2MAC
def password_to_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_200_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

## encrypt the text
def encrypt(data: str, password: str) -> str:
    salt = os.urandom(16)
    key = password_to_key(password, salt)
    f = Fernet(key)

    token = f.encrypt(data.encode())
    blob = salt + token

    return base64.urlsafe_b64encode(blob).decode()

# decrypt the your hash with the password
def decrypt(blob64: str, password: str) -> str:
    
    blob = base64.urlsafe_b64decode(blob64.encode())

    salt = blob[:16]
    token = blob[16:]

    key = password_to_key(password, salt)

    f = Fernet(key)

    return f.decrypt(token).decode()


## generates the qr code
def make_qr(input: str, password: str):
    ## make the encrypt stuff for your qr
    cipher = encrypt(input, password)
    ## makes the qr from what you used
    img = qrcode.make(cipher)

    print(type(img))

    save_path = "generated.png"
    img.save(save_path)

    print("Saved at:", os.path.abspath(save_path))

## read the qr
def read_qr(qr, password):
    ## makes a list of the image and it's format
    decoded = decode(Image.open(qr))

    ## put the hash into data
    data = decoded[0].data.decode()

    ## runs the decrypt function and returns the plain text
    decrypted = decrypt(data, password)
    return decrypted


def main():

    example = "http://google.com"
    password = "password123"

    make_qr(example, password)

    print(read_qr("generated.png", password))


if __name__ == "__main__":
    main()
