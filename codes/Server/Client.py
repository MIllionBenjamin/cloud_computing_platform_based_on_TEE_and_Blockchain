from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

from Constant import RSA_KEY_LENGTH, AES_KEY_BIT, AES_KEY_BYTE 
from Constant import encrypt_rsa_public_key, encrypt_aes_key, sign_encrypted_text, decrypt_AES_key, decrypt_rsa_public_key, validate_signature

import os

class Client:
    def __init__(self, key_files_path: str = None):
        random_generator = Random.new().read
        rsa_key_pair = RSA.generate(RSA_KEY_LENGTH, random_generator)
        self.rsa_private_key = rsa_key_pair.export_key()
        self.rsa_public_key = rsa_key_pair.publickey().export_key()
        self.aes_key = None
        self.aes_key_valid = False
        self.server_public_key = None
        self.server_public_key_valid = False
        #self.AES_KEY_BYTE = 16
        return
    
    def has_aes_key(self):
        '''
        If has aes_key from the server.
        '''
        return True if self.aes_key is not None else False
    
    def decrypt_AES_key(self, enc_aes_key):
        '''
        Decrypt the AES key from the server.
        '''
        self.aes_key = decrypt_AES_key(self.rsa_private_key, enc_aes_key)
        print("AES Key:", self.aes_key)
        
    def decrypt_server_public_key(self, enc_public_key):
        '''
        Decrypt the RSA Public Key by AES Key.
        '''
        self.server_public_key = decrypt_rsa_public_key(self.aes_key, enc_public_key)
        print("Server Public Key:", self.server_public_key)
        
    def validate_information(self, enc_aes_key, enc_server_public_key, aes_signature, public_key_signature):
        '''
        Use Signature to Validate Keys.
        '''
        if validate_signature(self.server_public_key, enc_aes_key, aes_signature):
            self.aes_key_valid = True
            print("AES Key Valid:", self.aes_key_valid)
        if validate_signature(self.server_public_key, enc_server_public_key, public_key_signature):
            self.server_public_key_valid = True
            print("Server Public Key Valid:", self.server_public_key_valid)
    
    
            
    
            

        
    
    
    
    
        
    
        