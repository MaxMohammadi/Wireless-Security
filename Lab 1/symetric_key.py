from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from base64 import b64encode

print("---CBC Mode---")

plaintext = b"We love phoenix. She is our favorite professor!"

key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC)
cipher_bytes = cipher.encrypt(pad(plaintext, AES.block_size))

initialization_vector = b64encode(cipher.iv).decode("utf-8")

cipher_text = b64encode(cipher_bytes).decode("utf-8")

print(f"Plaintext: {plaintext}\nInitialization vector: {initialization_vector}\nCipher text: {cipher_text}")