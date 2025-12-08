import cv2
from pyzbar.pyzbar import decode
from PIL import Image
from qrgenerator import decrypt

def scan_camera(password: str):
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

        ## decode QR using pyzbar directly on the numpy frame
        decoded = decode(frame)

        if decoded:
            data = decoded[0].data.decode()
            print("\nEncrypted QR contents:")
            print(data)

            try:
                text = decrypt(data, password)
                print("\n Decrypted result:")
                print(text)
            except Exception as e:
                print("\n Decryption failed:", e)

            cap.release()
            cv2.destroyAllWindows()
            return

        ## exit with key press
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()


if __name__ == "__main__":
    pw = input("Enter password: ")
    scan_camera(pw)
