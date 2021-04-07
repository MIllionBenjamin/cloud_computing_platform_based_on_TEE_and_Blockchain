from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

from Constant import RSA_KEY_LENGTH, AES_KEY_BIT, AES_KEY_BYTE 
from Constant import encrypt_rsa_public_key, encrypt_aes_key, sign_encrypted_text, decrypt_AES_key, decrypt_rsa_public_key

class KeyManager:
    def __init__(self):
        self.client_key_map_server_key = {}
        return
    
    
    '''
    1.1 : 客户端A生成一对密钥KRA,，将其中公钥KRA pub发送给密钥管理器；
	1.2：密钥管理器收到客户端A发来的包含公钥KRA pub的请求后，
            生成一对新密钥KRS和一个新密钥KA，
            将新生成的密钥KA用KRA pub加密，用KA对KRS pub加密并对加密后的密文用KRS pri进行加签，返回给客户端A。
            并且，密钥管理器保存KRA pub与KRS及KA的对应关系。
            客户端A先用KRA pri对密文解密得到KA，再用KA解密得到KRS pub，KRS pub对密文进行验签，验签成功说明得到的KRS pub和KA可信。
    '''
    def generate_key_for_client_key(self, client_key):
        if client_key in self.client_key_map_server_key:
            print("Keys Pair Already Exists")
        random_generator = Random.new().read
        rsa_key_pair = RSA.generate(RSA_KEY_LENGTH, random_generator)
        rsa_private_key = rsa_key_pair.export_key()
        rsa_public_key = rsa_key_pair.publickey().export_key()
        aes_key = Random.get_random_bytes(AES_KEY_BYTE)
        self.client_key_map_server_key[client_key] = {"rsa_private_key": rsa_private_key, 
                                                      "rsa_public_key": rsa_public_key, 
                                                      "aes_key": aes_key}
        print("Successfully Create Keys Pair")

    def return_encrypted_keys_and_sign(self, client_key):
        if client_key not in self.client_key_map_server_key:
            self.generate_key_for_client_key(client_key)
        
        aes_key = self.client_key_map_server_key[client_key]["aes_key"]
        rsa_public_key = self.client_key_map_server_key[client_key]["rsa_public_key"]
        rsa_private_key = self.client_key_map_server_key[client_key]["rsa_private_key"]
        
        enc_rsa_public_key = encrypt_rsa_public_key(aes_key, rsa_public_key)
        enc_aes_key = encrypt_aes_key(client_key, aes_key)
        enc_rsa_public_key_signature = sign_encrypted_text(rsa_private_key, enc_rsa_public_key)
        enc_aes_key_signature = sign_encrypted_text(rsa_private_key, enc_aes_key)
        
        return {"enc_rsa_public_key": enc_rsa_public_key, 
                "enc_aes_key": enc_aes_key, 
                "enc_rsa_public_key_signature": enc_rsa_public_key_signature, 
                "enc_aes_key_signature": enc_aes_key_signature}
        
        
'''
random_generator = Random.new().read
rsa_key_pair = RSA.generate(RSA_KEY_LENGTH, random_generator)
rsa_private_key = rsa_key_pair.export_key()
rsa_public_key = rsa_key_pair.publickey().export_key()




key_manager = KeyManager()
key_manager.generate_key_for_client_key(rsa_public_key)
print(key_manager.client_key_map_server_key)
print(rsa_public_key in key_manager.client_key_map_server_key)


encrypted_keys_and_sign = key_manager.return_encrypted_keys_and_sign(rsa_public_key)
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
# Validate Signature
imported_server_public_key = RSA.importKey(decrypted_sever_rsa_public_key)
enc_rsa_public_key_signature_hash = SHA256.new(encrypted_keys_and_sign["enc_rsa_public_key"])
enc_aes_key_signature_hash = SHA256.new(encrypted_keys_and_sign["enc_aes_key"])
#try:
pkcs1_15.new(imported_server_public_key).verify(enc_rsa_public_key_signature_hash, encrypted_keys_and_sign["enc_rsa_public_key_signature"])
pkcs1_15.new(imported_server_public_key).verify(enc_aes_key_signature_hash, encrypted_keys_and_sign["enc_aes_key_signature"])
print("Verify Success.")
#except (ValueError, TypeError):
#    print("Fail")
'''






