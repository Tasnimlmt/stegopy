# from PIL import Image

# # ===============================
# # Steganography Tool - LSB Method
# # ===============================

# def _to_binary(data):
#     """
#     Convert data (string or bytes) to a binary string.
#     Example: 'A' -> '01000001'
#     """
#     if isinstance(data, str):
#         return ''.join(format(ord(char), '08b') for char in data)
#     elif isinstance(data, bytes) or isinstance(data, bytearray):
#         return ''.join(format(byte, '08b') for byte in data)
#     else:
#         raise TypeError("Data must be string or bytes")


# def _from_binary(binary_str):
#     """
#     Convert binary string back to normal text.
#     Example: '01000001' -> 'A'
#     """
#     chars = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
#     message = ''.join(chr(int(b, 2)) for b in chars)
#     return message


# def encode_message(image_path, message, output_path):
#     """
#     Hide a secret message inside an image using LSB.
#     The result is a new image that looks identical to the original.
#     """
#     # Open image
#     img = Image.open(image_path)
#     encoded = img.copy()
#     width, height = img.size
#     pixels = encoded.load()

#     # Convert message to binary + add a special terminator
#     #binary_message = _to_binary(message) + '1111111111111110'  # Terminator sequence
#     binary_message = _to_binary(message) + _to_binary("###END###")

#     data_index = 0
#     total_pixels = width * height

#     for y in range(height):
#         for x in range(width):
#             if data_index >= len(binary_message):
#                 break

#             r, g, b = pixels[x, y]

#             # Modify the least significant bit of each color component
#             r_bin = format(r, '08b')
#             g_bin = format(g, '08b')
#             b_bin = format(b, '08b')

#             if data_index < len(binary_message):
#                 r_bin = r_bin[:-1] + binary_message[data_index]
#                 data_index += 1
#             if data_index < len(binary_message):
#                 g_bin = g_bin[:-1] + binary_message[data_index]
#                 data_index += 1
#             if data_index < len(binary_message):
#                 b_bin = b_bin[:-1] + binary_message[data_index]
#                 data_index += 1

#             # Write modified pixel
#             pixels[x, y] = (int(r_bin, 2), int(g_bin, 2), int(b_bin, 2))

#         if data_index >= len(binary_message):
#             break

#     # Save new image
#     encoded.save(output_path)
#     print(f"[+] Message successfully hidden in {output_path}")


# def decode_message(image_path):
#     """
#     Extract the hidden message from an image.
#     """
#     img = Image.open(image_path)
#     binary_data = ""
#     pixels = img.load()
#     width, height = img.size

#     for y in range(height):
#         for x in range(width):
#             r, g, b = pixels[x, y]
#             binary_data += format(r, '08b')[-1]
#             binary_data += format(g, '08b')[-1]
#             binary_data += format(b, '08b')[-1]






#     # # Find the terminator sequence
#     # end_index = binary_data.find('1111111111111110')
#     # if end_index != -1:
#     #     binary_data = binary_data[:end_index]







#     end_marker = _to_binary("###END###")
#     end_index = binary_data.find(end_marker)
#     if end_index != -1:
#        binary_data = binary_data[:end_index]







#     # Convert binary to text
#     decoded_message = _from_binary(binary_data)
#     print(f"[+] Hidden message extracted successfully!")
#     return decoded_message














# from PIL import Image

# # ===============================
# # Steganography Tool - LSB Method (Fixed)
# # ===============================

# def _to_binary(data):
#     """Convert data (string or bytes) to a binary string."""
#     if isinstance(data, str):
#         return ''.join(format(ord(char), '08b') for char in data)
#     elif isinstance(data, bytes) or isinstance(data, bytearray):
#         return ''.join(format(byte, '08b') for byte in data)
#     else:
#         raise TypeError("Data must be string or bytes")


# def _from_binary(binary_str):
#     """Convert binary string back to normal text."""
#     chars = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
#     message = ''.join(chr(int(b, 2)) for b in chars)
#     return message


# def encode_message(image_path, message, output_path):
#     """Hide a secret message inside an image using LSB."""
#     img = Image.open(image_path)
#     encoded = img.copy()
#     width, height = img.size
#     pixels = encoded.load()

#     # Convert message to binary + terminator
#     binary_message = _to_binary(message) + '1111111111111110'  # Terminator

#     data_index = 0
#     total_bits = len(binary_message)

#     for y in range(height):
#         for x in range(width):
#             if data_index >= total_bits:
#                 break

#             r, g, b = pixels[x, y]

#             rgb = [r, g, b]
#             for i in range(3):
#                 if data_index < total_bits:
#                     rgb[i] = (rgb[i] & ~1) | int(binary_message[data_index])
#                     data_index += 1

#             pixels[x, y] = tuple(rgb)

#         if data_index >= total_bits:
#             break

#     encoded.save(output_path)
#     print(f"[+] Message successfully hidden in {output_path}")


# def decode_message(image_path):
#     """Extract the hidden message from an image."""
#     img = Image.open(image_path)
#     binary_data = ""
#     pixels = img.load()
#     width, height = img.size

#     for y in range(height):
#         for x in range(width):
#             r, g, b = pixels[x, y]
#             binary_data += str(r & 1)
#             binary_data += str(g & 1)
#             binary_data += str(b & 1)

#             # Check terminator every few bits to stop early
#             if binary_data.endswith('1111111111111110'):
#                 binary_data = binary_data[:-16]
#                 decoded_message = _from_binary(binary_data)
#                 print("[+] Hidden message extracted successfully!")
#                 return decoded_message

#     print("[!] No terminator found, message might be corrupted.")
#     return _from_binary(binary_data)











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