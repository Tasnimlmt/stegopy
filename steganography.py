from PIL import Image 
from cryptography.fernet import Fernet
import hashlib
import base64
import os
from tkinter import Tk
from tkinter.filedialog import askopenfilename, asksaveasfilename


class Steganography:
    @staticmethod
    def generate_key(password: str) -> bytes:
        hash_obj = hashlib.sha256(password.encode())
        key = base64.urlsafe_b64encode(hash_obj.digest())
        return key

    @staticmethod
    def encrypt_message(message: str, password: str) -> str:
        key = Steganography.generate_key(password)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(message.encode())
        return encrypted.decode()

    @staticmethod
    def decrypt_message(encrypted_message: str, password: str) -> str:
        try:
            key = Steganography.generate_key(password)
            fernet = Fernet(key)
            decrypted = fernet.decrypt(encrypted_message.encode())
            return decrypted.decode()
        except Exception:
            return None

    @staticmethod
    def string_to_binary(message: str) -> str:
        return ''.join(format(ord(char), '08b') for char in message)

    @staticmethod
    def binary_to_string(binary: str) -> str:
        chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
        message = ''
        for char in chars:
            if len(char) == 8:
                try:
                    message += chr(int(char, 2))
                except ValueError:
                    continue
        return message

    @staticmethod
    def hide_message(image_path: str, message: str, password: str, output_path: str = None):
        try:
            img = Image.open(image_path)
            img = img.convert('RGB')
        except Exception as e:
            print(f"Error loading image: {e}")
            return False

        encrypted_msg = Steganography.encrypt_message(message, password)
        binary_msg = Steganography.string_to_binary(encrypted_msg)

        delimiter = '1111111111111110'
        msg_length = len(binary_msg)
        length_binary = format(msg_length, '032b')
        full_binary = length_binary + binary_msg + delimiter

        pixels = list(img.getdata())
        max_bits = len(pixels) * 3

        if len(full_binary) > max_bits:
            print(f"Error: Message too large ({len(full_binary)} bits needed, {max_bits} available)")
            return False

        new_pixels = []
        binary_index = 0
        for pixel in pixels:
            r, g, b = pixel
            new_pixel = [r, g, b]
            for channel in range(3):
                if binary_index < len(full_binary):
                    new_pixel[channel] = (new_pixel[channel] & 0xFE) | int(full_binary[binary_index])
                    binary_index += 1
            new_pixels.append(tuple(new_pixel))

        stego_img = Image.new(img.mode, img.size)
        stego_img.putdata(new_pixels)

  
        if output_path is None:
            root = Tk()
            root.withdraw()
            root.update()
            output_path = asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG Image", "*.png")],
                title="Save encoded image as"
            )
            root.destroy()

            if not output_path:
                print("✖ Save canceled.")
                return False

        stego_img.save(output_path, 'PNG')

        print(f" Message hidden successfully in: {output_path}")
        print(f"  Original message: {len(message)} characters")
        print(f"  Encrypted size: {len(encrypted_msg)} characters")
        print(f"  Bits used: {len(full_binary)} / {max_bits} ({len(full_binary)/max_bits*100:.2f}%)")
        return True

    @staticmethod
    def extract_message(image_path: str, password: str) -> str:
        try:
            img = Image.open(image_path)
            img = img.convert('RGB')
        except Exception as e:
            print(f"Error loading image: {e}")
            return None

        pixels = list(img.getdata())
        binary_data = ''

        for pixel in pixels:
            for channel in pixel:
                binary_data += str(channel & 1)

        try:
            length_binary = binary_data[:32]
            msg_length = int(length_binary, 2)
        except ValueError:
            print("Error: Could not read message length")
            return None

        if msg_length <= 0 or msg_length > len(binary_data) - 32:
            print("Error: No hidden message found or invalid length")
            return None

        message_binary = binary_data[32:32 + msg_length]

        encrypted_msg = Steganography.binary_to_string(message_binary)
        if not encrypted_msg:
            print("Error: Could not extract encrypted message")
            return None

        decrypted = Steganography.decrypt_message(encrypted_msg, password)

        if decrypted:
            print(f" Message extracted successfully!")
            return decrypted
        else:
            print(" Decryption failed. Wrong password or corrupted data.")
            return None


def choose_image_file():
    root = Tk()
    root.withdraw()
    root.update()
    file_path = askopenfilename(
        title="Choose an image",
        filetypes=[("Image Files", "*.png *.jpg *.jpeg *.bmp")]
    )
    root.destroy()
    return file_path


def main():
  
    print("  STEGANOGRAPHY - Hide Messages in Images")
    

    while True:
        print("\nChoose an option:")
        print("1. Hide message in image")
        print("2. Extract message from image")
        print("3. Exit")

        choice = input("\nEnter choice (1/2/3): ").strip()

        if choice == '1':
            print("\n--- HIDE MESSAGE ---")
            print("Please select an image…")
            image_path = choose_image_file()

            if not image_path:
                print(" No image selected!")
                continue

            message = input("Enter secret message: ").strip()
            if not message:
                print(" Error: Message cannot be empty!")
                continue

            password = input("Enter password: ").strip()
            if not password:
                print("Error: Password cannot be empty!")
                continue

            print("\n Processing...")
            Steganography.hide_message(image_path, message, password, output_path=None)

        elif choice == '2':
            print("\n--- EXTRACT MESSAGE ---")
            print("Please select a stego image…")
            image_path = choose_image_file()

            if not image_path:
                print(" No image selected!")
                continue

            password = input("Enter password: ").strip()
            if not password:
                print(" Error: Password cannot be empty!")
                continue

            print("\n⏳ Processing...")
            message = Steganography.extract_message(image_path, password)

            if message:
                print(f"\n{'='*60}")
                print(f" Hidden Message:\n{message}")
                print(f"{'='*60}")

        elif choice == '3':
            print("\n Goodbye!")
            break

        else:
            print(" Invalid choice. Please try again.")


if __name__ == "__main__":
    main()

