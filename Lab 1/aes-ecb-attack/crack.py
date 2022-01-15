from Crypto.Cipher import AES
 
def oracle(target):
  key = '1111111111111111'
  secret = 'this is the wire'
  message = target + secret
  cipher = AES.new(key, AES.MODE_ECB)
  encrypted = cipher.encrypt(pad(message))
  return encrypted 

def pad(secret):
    pl = len(secret)
    mod = pl % 16
    if mod != 0:
        padding = 16 - mod
        secret += 'X' * padding
    return secret

def byte_at_a_time(secret, index):
  reference = oracle(secret[:-(index+1)]).hex()
  for i in range(0, 255):
    ct = oracle(secret[:-1] + chr(i) ).hex()
    if reference[:32] == ct[:32] :
      print("Found %s" % chr(i))
      return chr(i)
  return '#'

def crack():
  secret = 'AAAAAAAAAAAAAAAA'
  next_byte = ''
  for i in range(0, 15):
    next_byte = byte_at_a_time(secret, i)
    print(secret)
    secret = secret[1:-1] + next_byte + 'A'
  next_byte = byte_at_a_time(secret, i+1)
  secret = secret[:-1] + next_byte
  print('secret: ' + secret)

crack()