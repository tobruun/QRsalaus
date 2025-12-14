import qrcode

import base64
import os

from pyzbar.pyzbar import decode
from PIL import Image

import endecrypt

## generates the qr code
def make_qr(input: str, password: str, mode: endecrypt.MODES):
    ## make the encrypt stuff for your qr
    encrypted_data = endecrypt.encrypt(input, password.encode(), mode)

    #header variable that contains the nonce and encryption scheme
    header: bytes = encrypted_data[1] + mode.value.to_bytes(1)

    #concatenate the encrypted message and header variables to create the final blob
    blob = encrypted_data[0] + header

    ## makes the qr from what you used
    img = qrcode.make(blob)

    print(type(img))

    save_path = "generated.png"
    img.save(save_path) # pyright: ignore[reportArgumentType]

    print("Saved at:", os.path.abspath(save_path))

## read the qr
def read_qr(qr, password):
    ## makes a list of the image and it's format
    decoded = decode(Image.open(qr))

    ## put the hash into data
    data = decoded[0].data.decode()

    header_length = 13  # Assuming the header is at most 32 bytes long
    header = data[:header_length]
    counter = header[12]
    nonce = header[:12]
    encrypted_data = data[header_length:]

    # Extract encryption scheme and password from the header
    header_contents = header.decode()
    if "ENCRYPTION_SCHEME:" in header_contents:
        _, encryption_scheme = header_contents.split(":")
        print(f"Encrypted QR contents with scheme: {encryption_scheme}")

    try:
        decrypted_text = decrypt(encrypted_data, password)
        print(f"\nDecrypted result:")
        print(decrypted_text)
    except Exception as e:
        print(f"\nDecryption failed: {e}")


def main():

    example = "http://google.com"
    password = "password123"

    make_qr(example, password, endecrypt.MODES.AESGCM)

    print(read_qr("generated.png", password))


if __name__ == "__main__":
    main()
