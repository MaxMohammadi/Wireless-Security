from Crypto.Cipher import AES
import base64
import math
from Crypto.Util import Counter

#32 bytes
encryption_key = 'this is the wireless security la'
#16 bytes
initial_vector = 'initial_vector11'

def encrypt(message):
    cipher = AES.new(encryption_key, AES.MODE_CBC, initial_vector)
    length = len(message)
    next_multiple_of_16 = 16 * math.ceil(length/16)
    padded_message = message.rjust(next_multiple_of_16)
    raw_ciphertext = cipher.encrypt(padded_message)
    return base64.b64encode(raw_ciphertext).decode('utf-8')

def decrypt(message):
    cipher = AES.new(encryption_key, AES.MODE_CBC, initial_vector)
    raw_ciphertext = base64.b64decode(ciphertext)
    decrypted_message_with_padding = cipher.decrypt(raw_ciphertext)
    return decrypted_message_with_padding.decode('utf-8').strip()

message = 'this is the wireless security lab'
 
ciphertext = encrypt(message)
print('Cipher text: %s' % ciphertext)
 
decrypted_message = decrypt(ciphertext)
print('Decrypted message: %s' % decrypted_message)
