import pip

def install(package):
    pip.main(['install', package])

try:
    import Crypto
    print("module 'pycryptodom' is installed")
except ModuleNotFoundError:
    print("module 'pycryptodom' is not installed")
    install("pycryptodom")
    
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
from base64 import b64encode
from base64 import b64decode

plaintext = b"We love phoenix. She is our favorite professor!"
key = get_random_bytes(16)

print("---CTR Mode Encryption---")

cipher = AES.new(key, AES.MODE_CTR)
cipher_bytes = cipher.encrypt(plaintext)
nonce = b64encode(cipher.nonce).decode('utf-8')
cipher_text = b64encode(cipher_bytes).decode('utf-8')

print(f"Plaintext: {plaintext}\nCiphertext: {cipher_text}\n")
print("---CTR Mode Decryption---")

nonce = b64decode(nonce)
cipher_text = b64decode(cipher_text)
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
plaintext = cipher.decrypt(cipher_text)

print(f"Decrypted plaintext: {plaintext}")
print("\n-----------------------------" + "\n")
print("---ECB Mode Encryption---")

cipher = AES.new(key, AES.MODE_ECB)
cipher_text = cipher.encrypt(pad(plaintext, 32))

print(f"Plaintext: {plaintext}\nCiphertext: {cipher_text}\n")
print("---ECB Mode Decryption---")

decipher = AES.new(key, AES.MODE_ECB)
decipher_text = unpad(decipher.decrypt(cipher_text), 32)

print(f"Decrypted plaintext: {decipher_text}")
print("\n-----------------------------" + "\n")
print("---CBC Mode Encryption---")

cipher = AES.new(key, AES.MODE_CBC)
ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
iv = b64encode(cipher.iv).decode('utf-8')
cipher_text = b64encode(ct_bytes).decode('utf-8')

print(f"Plaintext: {plaintext}\nCiphertext: {cipher_text}\n")
print("---CBC Mode Decryption---")

iv = b64decode(iv)
cipher = AES.new(key, AES.MODE_CBC, iv)
cipher_text = b64decode(cipher_text)
pt = unpad(cipher.decrypt(cipher_text), AES.block_size)

print(f"Decrypted plaintext: {pt}")

print("\n-----------------------------" + "\n")

print("---CFB Mode Encryption---")


cipher = AES.new(key, AES.MODE_CFB)
ct_bytes = cipher.encrypt(plaintext)
iv = b64encode(cipher.iv).decode('utf-8')
cipher_text = b64encode(ct_bytes).decode('utf-8')
print(f"Plaintext: {plaintext}\nCiphertext: {cipher_text}\n")

print("---CFB Mode Decryption---")

iv = b64decode(iv)
cipher_text = b64decode(cipher_text)
cipher = AES.new(key, AES.MODE_CFB, iv=iv)
pt = cipher.decrypt(cipher_text)

print(f"Decrypted plaintext: {pt}")

print("\n-----------------------------" + "\n")

print("---OFB Mode Encryption---")

cipher = AES.new(key, AES.MODE_OFB)
cipher_bytes = cipher.encrypt(plaintext)
iv = b64encode(cipher.iv).decode('utf-8')
cipher_text = b64encode(cipher_bytes).decode('utf-8')

print(f"Plaintext: {plaintext}\nCiphertext: {cipher_text}\n")

print("---OFB Mode Decryption---")

iv = b64decode(iv)
ct = b64decode(cipher_text)
cipher = AES.new(key, AES.MODE_OFB, iv=iv)
decipher_text = cipher.decrypt(ct)

print(f"Decrypted plaintext: {decipher_text}")

print("\n-----------------------------" + "\n")

