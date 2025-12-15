import qrcode
import base64
import os
# from pyzbar.pyzbar import decode
# from PIL import Image
import cv2
import endecrypt

def main():
    input_data = input("Enter your input data: ")
    password = input("Enter your password: ")
    print("Choose an encryption method:")
    print("1. AES-GCM")
    print("2. AES-CTR")
    print("3. ChaCha20-Poly1305")
    choice = int(input("Enter the number of your chosen encryption method: "))
    
    if choice == 1:
        mode = endecrypt.MODES.AESGCM
    elif choice == 2:
        mode = endecrypt.MODES.AESCTR
    elif choice == 3:
        mode = endecrypt.MODES.CHACHA20POLY
    else:
        print("Invalid choice. Defaulting to AES-GCM.")
        mode = endecrypt.MODES.AESGCM

    encrypted_data = endecrypt.encrypt(input_data, password.encode(), mode)
    header: bytes = encrypted_data[1] + mode.value.to_bytes(1)
    blob = encrypted_data[0] + header
    encoded_blob = base64.urlsafe_b64encode(blob).decode()
    img = qrcode.make(encoded_blob)
    print(type(img))
    save_path = "test__generated.png"
    img.save(save_path)  # pyright: ignore[reportArgumentType]
    print("Saved at:", os.path.abspath(save_path))

    # password = input("Enter your password to read the QR code: ")
    
    img_cv = cv2.imread(save_path)
    detector = cv2.QRCodeDetector()
    data, bbox, straight_qrcode = detector.detectAndDecode(img_cv)
    
    if data:
        data_bytes = base64.urlsafe_b64decode(data.encode())
        header_length = 13
        header = data_bytes[-header_length:]
        mode_byte = header[12]
        nonce = header[:12]
        encrypted_data = data_bytes[:-header_length]
        mode = endecrypt.MODES(mode_byte)

        try:
            decrypted_text = endecrypt.decrypt(encrypted_data, password.encode(), nonce, mode)
            print(f"\nDecrypted result:")
            print(decrypted_text.decode())
        except Exception as e:
            print(f"\nDecryption failed: {e}")
    else:
        print("No QR code found")

if __name__ == "__main__":
    main()