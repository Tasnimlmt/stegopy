
from stego import encode_message, decode_message

# File paths
original_image = "input.jpeg"
encoded_image = "encoded.jpeg"
secret_message = "Hello Tasneem! This is a secret message."

print("Encoding message...")
encode_message(original_image, secret_message, encoded_image)
print("Message encoded successfully!")

print("Decoding message...")
decoded = decode_message(encoded_image)
print("Decoded message:", decoded)
