from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

from Constant import RSA_KEY_LENGTH, AES_KEY_BIT, AES_KEY_BYTE 
from Constant import encrypt_bytes_by_AES, encrypt_bytes_by_RSA, sign_encrypted_text, decrypt_bytes_by_RSA, decrypt_bytes_by_AES, validate_signature

import os
import time

class Task:
    '''
    To Represent a Task.
    '''
    def __init__(self, task_name, create_time, task_file_path, task_hash):
        self.task_name = task_name
        self.create_time = create_time
        self.task_file_path = task_file_path
        self.task_hash = task_hash
        self.has_result = False
        self.result = None

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
        
        self.server_rsa_encrypt_aes_key = None
        '''
        See Class Task
        '''
        self.task_info = []
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
        self.aes_key = decrypt_bytes_by_RSA(self.rsa_private_key, enc_aes_key)
        print("AES Key:", self.aes_key)
        
    def decrypt_server_public_key(self, enc_public_key):
        '''
        Decrypt the RSA Public Key by AES Key.
        '''
        self.server_public_key = decrypt_bytes_by_AES(self.aes_key, enc_public_key)
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
            
    def rsa_encrypt_aes_key(self):
        '''
        Use Server Public Key to Encrypt AES Key. Return it.
        '''
        if self.server_rsa_encrypt_aes_key is not None:
            return self.server_rsa_encrypt_aes_key
        self.server_rsa_encrypt_aes_key = encrypt_bytes_by_RSA(self.server_public_key, self.aes_key)
        return self.server_rsa_encrypt_aes_key
    
    def aes_encrypt_file_bytes(self, file_path):
        '''
        Use AES Key to Encrypt File Bytes. Return the Encrypted Content.
        '''
        read_file = open(file_path, "rb")
        enc_file_bytes = encrypt_bytes_by_AES(self.aes_key, read_file.read())
        read_file.close()
        return enc_file_bytes
    
    def sign_by_private_key(self, enc_text):
        '''
        Use Self Private Key to Sign enc_text
        '''
        return sign_encrypted_text(self.rsa_private_key, enc_text)
    
    def generate_task(self, task_name, task_file_path):
        '''
        Generate a Task. Return the Info that will be sent to FileReceiver on Server.
        '''
        # Current Time. E.g. '2021-04-08 16:30:02'
        time_str_now = time.strftime("%Y-%m-%d %X", time.localtime())
        
        # RSA Encrypt aes_key
        enc_aes_key =  self.rsa_encrypt_aes_key()
        # Sign enc_aes_key
        enc_aes_key_signature = self.sign_by_private_key(enc_aes_key)
        
        # Generate Task Hash
        task_hash = SHA256.new(bytes(task_name + time_str_now + task_file_path, encoding = "utf-8")).digest()
        # RSA Encrypt Task Hash by Server Public Key
        enc_task_hash = encrypt_bytes_by_RSA(self.server_public_key, task_hash)
        # Sign enc_task_hash
        enc_task_hash_signature = self.sign_by_private_key(enc_task_hash)
        
        # AES Encrypt File by aes_key
        enc_file_content = self.aes_encrypt_file_bytes(task_file_path)
        # Sign enc_file_content
        enc_file_content_signature = self.sign_by_private_key(enc_file_content)
        
        # Create New Task
        new_task = Task(task_name, 
                        time_str_now, 
                        task_file_path, 
                        task_hash)
        self.task_info.append(new_task)
        
        # Return the Info that will be sent to FileReceiver on Server.
        return {
                "client_public_key": self.rsa_public_key,
                "enc_aes_key": enc_aes_key, 
                "enc_aes_key_signature": enc_aes_key_signature,
                "enc_task_hash": enc_task_hash, 
                "enc_task_hash_signature": enc_task_hash_signature, 
                "enc_file_content": enc_file_content, 
                "enc_file_content_signature": enc_file_content_signature
                }
    
    
    def validate_block(self, block, signature):
        block_bytes = bytes(str(block["index"]) + str(block["timestamp"]), encoding = "utf-8") + block["previous_hash"]
        if block["transactions"]:
            block_bytes += block["transactions"][0]["task_hash"] + block["transactions"][0]["enc_result"] + block["transactions"][0]["enc_run_info"]
        return validate_signature(self.server_public_key, block_bytes, signature)
    
    def decrypt_results(self, enc_result, enc_run_info):
        return {
            "enc_result": str(decrypt_bytes_by_AES(self.aes_key, enc_result), encoding = "utf-8"), 
            "enc_run_info": str(decrypt_bytes_by_AES(self.aes_key, enc_run_info), encoding = "utf-8")
        }
        
    

