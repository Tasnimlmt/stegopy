
from PIL import Image

def encode_message(input_image_path, message, output_image_path):
    img = Image.open(input_image_path)
    encoded = img.copy()
    width, height = img.size
    index = 0

    # Convert message to binary and add a delimiter
    binary_message = ''.join(format(ord(c), '08b') for c in message) + '1111111111111110'  # end marker

    for row in range(height):
        for col in range(width):
            if index < len(binary_message):
                pixel = list(img.getpixel((col, row)))
                # Change LSB of red channel
                pixel[0] = pixel[0] & ~1 | int(binary_message[index])
                encoded.putpixel((col, row), tuple(pixel))
                index += 1
            else:
                encoded.save(output_image_path)
                print("[+] Message successfully hidden in", output_image_path)
                return

    encoded.save(output_image_path)
    print("[+] Message successfully hidden in", output_image_path)


def decode_message(encoded_image_path):
    img = Image.open(encoded_image_path)
    binary_data = ""
    width, height = img.size

    for row in range(height):
        for col in range(width):
            pixel = img.getpixel((col, row))
            binary_data += str(pixel[0] & 1)

    # Split bits into bytes
    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]

    # Decode until the stop marker
    decoded_data = ""
    for byte in all_bytes:
        char = chr(int(byte, 2))
        decoded_data += char
        if decoded_data.endswith('þ'):  # corresponds to '1111111111111110'
            break

    message = decoded_data[:-1]  # remove the end marker
    print("[+] Hidden message extracted successfully!")
    return message