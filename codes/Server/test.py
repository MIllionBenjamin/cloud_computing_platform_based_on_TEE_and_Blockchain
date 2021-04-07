from KeyManager import KeyManager
from Client import Client

client_1 = Client()
key_manager = KeyManager()

key_manager.generate_key_for_client_key(client_1.rsa_public_key)

encrypted_keys_and_sign = key_manager.return_encrypted_keys_and_sign(client_1.rsa_public_key)
print(encrypted_keys_and_sign)
client_1.decrypt_AES_key(encrypted_keys_and_sign["enc_aes_key"])
client_1.decrypt_server_public_key(encrypted_keys_and_sign["enc_rsa_public_key"])
client_1.validate_information(encrypted_keys_and_sign["enc_aes_key"], 
                              encrypted_keys_and_sign["enc_rsa_public_key"], 
                              encrypted_keys_and_sign["enc_aes_key_signature"], 
                              encrypted_keys_and_sign["enc_rsa_public_key_signature"])

from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
# Validate Signature
imported_server_public_key = RSA.importKey(client_1.server_public_key)
enc_rsa_public_key_signature_hash = SHA256.new(encrypted_keys_and_sign["enc_rsa_public_key"])
enc_aes_key_signature_hash = SHA256.new(encrypted_keys_and_sign["enc_aes_key"])
#try:
pkcs1_15.new(imported_server_public_key).verify(enc_rsa_public_key_signature_hash, encrypted_keys_and_sign["enc_rsa_public_key_signature"])
pkcs1_15.new(imported_server_public_key).verify(enc_aes_key_signature_hash, encrypted_keys_and_sign["enc_aes_key_signature"])
print("Verify Success.")
#except (ValueError, TypeError):
#    print("Fail")




'''
# Decrypt AES Key
imported_rsa_private_key = RSA.importKey(rsa_private_key)
cipher_rsa = PKCS1_OAEP.new(imported_rsa_private_key)
decrypted_aes_key = cipher_rsa.decrypt(encrypted_keys_and_sign["enc_aes_key"])
print("AES Key Decryption:", decrypted_aes_key == key_manager.client_key_map_server_key[rsa_public_key]["aes_key"])
# Decrypt Sever RSA Private Key
nonce = encrypted_keys_and_sign["enc_rsa_public_key"][0: AES_KEY_BYTE]
tag = encrypted_keys_and_sign["enc_rsa_public_key"][AES_KEY_BYTE: 2 * AES_KEY_BYTE]
ciphertext = encrypted_keys_and_sign["enc_rsa_public_key"][2 * AES_KEY_BYTE: ]
cipher_aes = AES.new(decrypted_aes_key, AES.MODE_EAX, nonce)
try:
    decrypted_sever_rsa_public_key = cipher_aes.decrypt_and_verify(ciphertext, tag)
except (ValueError, TypeError):
    print("Decrypt Server RSA Public Key Failed.")    
print("Decrypt Server RSA Public Key:", decrypted_sever_rsa_public_key == key_manager.client_key_map_server_key[rsa_public_key]["rsa_public_key"])
'''

