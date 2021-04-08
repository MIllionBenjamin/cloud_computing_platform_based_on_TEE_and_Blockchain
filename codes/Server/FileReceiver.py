from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import time

from KeyManager import KeyManager
from Constant import RSA_KEY_LENGTH, AES_KEY_BIT, AES_KEY_BYTE 
from Constant import encrypt_bytes_by_AES, encrypt_bytes_by_RSA, sign_encrypted_text, decrypt_bytes_by_RSA, decrypt_bytes_by_AES, validate_signature

class FileReceiver:
    def __init__(self):
        return
    
    def return_to_client_to_CodeRunner(self, 
                                        key_manager: KeyManager, 
                                        client_public_key, 
                                        enc_aes_key, 
                                        enc_aes_key_signature, 
                                        enc_task_hash,
                                        enc_task_hash_signature, 
                                        enc_file_content, 
                                        enc_file_content_signature):
        '''
        Receive Info From Client and Process it.
        Return: [0] is to Client.
                [1] is to CodeRunner. Will be None if Error occurs.
        '''
        
        # Validate client_public_key
        if client_public_key not in key_manager.client_key_map_server_key:
            return "Error: Client Public Key Invalid.", None
        
        # Get Keys
        server_public_key = key_manager.client_key_map_server_key[client_public_key]["rsa_public_key"]
        server_private_key = key_manager.client_key_map_server_key[client_public_key]["rsa_private_key"]
        aes_key = key_manager.client_key_map_server_key[client_public_key]["aes_key"]
        
        # Validate Signatures
        if not validate_signature(client_public_key, enc_aes_key, enc_aes_key_signature):
            return "Error: AES Key Signature Invalid.", None
        if not validate_signature(client_public_key, enc_task_hash, enc_task_hash_signature):
            return "Error: Task Hash Signature Invalid.", None
        if not validate_signature(client_public_key, enc_file_content, enc_file_content_signature):
            return "Error: File Content Signature Invalid.", None
        
        # Decrypt AES key
        decrypted_aes_key = decrypt_bytes_by_RSA(server_private_key, enc_aes_key)
        # Validate AES Key
        if decrypted_aes_key != aes_key:
            return "Error: enc_aes_key Invalid.", None
        
        # Decrypt Task Hash
        task_hash = decrypt_bytes_by_RSA(server_private_key, enc_task_hash)
        
        # Decrypt enc_file
        decrypted_file_bytes = decrypt_bytes_by_AES(aes_key, enc_file_content)
        
        return "Task Arranged Success", {"aes_key": aes_key, 
                                         "task_hash": task_hash, 
                                         "file_content": decrypted_file_bytes}
        
        
        
        
        
        
    
    
    
