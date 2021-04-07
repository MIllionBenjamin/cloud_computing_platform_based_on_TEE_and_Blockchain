from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_EAX)
data = bytes("-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDX2N0wicj4Knhqkkuyk+Di/zbJ\nXCD6RlI5eR0IqGC1lIO0fFRgvxVABRBa35f6Ktc8mN0PZAY/TOedcq+yMOLcLsIs\nd//yW1EZN843T6oDof2SPIre1wJuEx1t7kIgJyAqqJi1YfFNc3N8jjZp5959LP0K\nVdxDlyUKCdALxbXw1wIDAQAB\n-----END PUBLIC KEY-----", encoding="utf8")
ciphertext, tag = cipher.encrypt_and_digest(data)


print(cipher.nonce, tag, ciphertext)
all_encypted = cipher.nonce + tag + ciphertext
nonce = all_encypted[0: 16]
tag = all_encypted[16: 32]
ciphertext = all_encypted[32: ]
print(nonce, tag, ciphertext)
cipher = AES.new(key, AES.MODE_EAX, nonce)
print(cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8"))






