import cv2
import base64
from endecrypt import decrypt, MODES, b32_decode

def scan_camera():
    ## webcam
    cap = cv2.VideoCapture(0)

    if not cap.isOpened():
        print("Error: Could not access camera")
        return

    print("Camera started — press 'q' to quit.")
    print("Scanning for QR code...")

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        cv2.imshow("QR Scanner", frame)

        ## decode QR using opencv
        detector = cv2.QRCodeDetector()
        data, bbox, straight_qrcode = detector.detectAndDecode(frame)

        if data:
            print("\nEncrypted QR contents detected.")
            # Assume data is base64 string
            try:
                data_bytes = b32_decode(data)
                header_length = 13
                header = data_bytes[-header_length:]
                mode_byte = header[12]
                nonce = header[:12]
                encrypted_data = data_bytes[:-header_length]

                # Detect mode
                if mode_byte == 1:
                    mode_name = "AES-GCM"
                elif mode_byte == 2:
                    mode_name = "AES-CTR"
                elif mode_byte == 3:
                    mode_name = "ChaCha20-Poly1305"
                else:
                    print("Unknown encryption method.")
                    continue

                print(f"Detected encryption method: {mode_name}")
                password = input("Enter password to decrypt: ")

                mode = MODES(mode_byte)

                decrypted_text = decrypt(encrypted_data, password.encode(), nonce, mode)
                print("\nDecrypted result:")
                print(decrypted_text.decode())

            except Exception as e:
                print(f"\nDecryption failed: {e}")

            cap.release()
            cv2.destroyAllWindows()
            return

        ## exit with key press
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()


if __name__ == "__main__":
    scan_camera()