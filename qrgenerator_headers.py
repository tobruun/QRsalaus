import qrcode
import os

from pyzbar.pyzbar import decode, ZBarSymbol
from PIL import Image

import endecrypt

## generates the qr code
def make_qr(input: str, password: str, mode: endecrypt.MODES, filename: str):
    ## make the encrypt stuff for your qr
    encrypted_data = endecrypt.encrypt(input, password.encode(), mode)

    #header variable that contains the nonce and encryption scheme
    header: bytes = encrypted_data[1] + mode.value.to_bytes(1)
    print(header)

    #concatenate the encrypted message and header variables to create the final blob
    blob = encrypted_data[0] + header

    blob_t = endecrypt.b32_encode(blob)

    ## makes the qr from what you used
    img = qrcode.make(blob_t)

    print(type(img))

    img.save(filename) # pyright: ignore[reportArgumentType]

    print("Saved at:", os.path.abspath(filename))

## read the qr
def read_qr(qr, password: str):
    ## makes a list of the image and it's format
    decoded = decode(Image.open(qr), [ZBarSymbol.QRCODE])
    ## put the hash into data
    data = decoded[0].data.decode()
    data = endecrypt.b32_decode(data)

    header_length = 13
    header = data[-header_length:]
    mode_byte = header[12]
    nonce = header[:12]
    encrypted_data = data[:-header_length]
    mode = endecrypt.MODES.NONE

    print(header)

    if mode_byte == 1:
        mode = endecrypt.MODES.AESGCM
    elif mode_byte == 2:
        mode = endecrypt.MODES.AESCTR
    elif mode_byte == 3:
        mode = endecrypt.MODES.CHACHA20POLY
    else:
        print("Invalid choice. Defaulting to NONE.")

    try:
        decrypted_text = endecrypt.decrypt(encrypted_data, password.encode(), nonce, mode)
        print(f"\nDecrypted result:")
        print(decrypted_text.decode())
    except Exception as e:
        print(f"\nDecryption failed: {e}")


def main():

    example = "http://google.com"
    password = "password123"
    filename = "example.png"

    make_qr(example, password, endecrypt.MODES.AESGCM, filename)

    print(read_qr(filename, password))


if __name__ == "__main__":
    main()
