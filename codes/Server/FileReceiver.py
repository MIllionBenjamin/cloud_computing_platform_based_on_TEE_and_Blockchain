from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import time

from KeyManager import KeyManager
from Constant import RSA_KEY_LENGTH, AES_KEY_BIT, AES_KEY_BYTE 
from Constant import encrypt_bytes_by_AES, encrypt_aes_key, sign_encrypted_text, decrypt_AES_key, decrypt_bytes_by_AES, validate_signature

class FileReceiver:
    def __init__(self):
        return
    
    def return_AES_key_Hash1_File_bytes(self, key_manager: KeyManager, client_public_key, enc_aes_key, enc_file):
        
        if client_public_key not in key_manager.client_key_map_server_key:
            return "Error: Client Public Key Invalid."
        
        server_public_key = key_manager.client_key_map_server_key[client_public_key]["rsa_public_key"]
        server_private_key = key_manager.client_key_map_server_key[client_public_key]["rsa_private_key"]
        aes_key = key_manager.client_key_map_server_key[client_public_key]["aes_key"]
        
        # Validate AES Key
        decrypted_aes_key = decrypt_AES_key(server_private_key, enc_aes_key)
        if decrypted_aes_key != aes_key:
            return "Error: enc_aes_key Invalid."
        
        # Generate Hash, Encrypt it and Sign it
        time_now_bytes = bytes(str(time.time()), encoding = "utf-8")
        time_client_key_hash = SHA256.new(time_now_bytes + client_public_key).digest()
        enc_time_client_key_hash = encrypt_aes_key(client_public_key, time_client_key_hash)
        enc_time_client_key_hash_hash = SHA256.new(enc_time_client_key_hash)
        enc_time_client_key_hash_hash_signature = sign_encrypted_text(server_private_key, enc_time_client_key_hash_hash)
        
        # Decrypt enc_file
        decrypted_file_bytes = decrypt_bytes_by_AES(aes_key, enc_file)
        
        return {"to Client": (enc_time_client_key_hash, 
                              enc_time_client_key_hash_hash_signature), 
                "to CodeRunner": (aes_key, 
                                  time_client_key_hash, 
                                  decrypted_file_bytes)}
        
        
        
        
        
        
    
    
    
