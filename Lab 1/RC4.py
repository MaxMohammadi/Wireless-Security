

from Crypto.Cipher import ARC4


key=b'\xff' * 5


print("#------------Encrypt----------#")
cipher = ARC4.new(key)
encrypt = cipher.encrypt("this is the wireless security lab") 
print('Cipher text: ', encrypt)

print("\n#------------Decrypt----------#")
cipher = ARC4.new(key)
decrypted_message = cipher.decrypt(encrypt)
print('Decrypted message: ', (decrypted_message).decode('utf-8'))

