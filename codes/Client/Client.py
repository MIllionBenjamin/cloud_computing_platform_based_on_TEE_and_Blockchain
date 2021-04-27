from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

from Constant import RSA_KEY_LENGTH, AES_KEY_BIT, AES_KEY_BYTE 
from Constant import encrypt_bytes_by_AES, encrypt_bytes_by_RSA, sign_encrypted_text, decrypt_bytes_by_RSA, decrypt_bytes_by_AES, validate_signature

import os
import time
import numpy as np

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
        self.run_info = None

class Client:
    def __init__(self, config_dict: dict = None):
        '''
        config_dict has rsa_private_key, rsa_public_key and task_info
        '''
        self.rsa_private_key = None
        self.rsa_public_key = None
        #See Class Task
        self.task_info = []
        if config_dict is None:
            random_generator = Random.new().read
            rsa_key_pair = RSA.generate(RSA_KEY_LENGTH, random_generator)
            self.rsa_private_key = rsa_key_pair.export_key()    
            self.rsa_public_key = rsa_key_pair.publickey().export_key()
        else:
            self.rsa_private_key = config_dict["rsa_private_key"]
            self.rsa_public_key = config_dict["rsa_public_key"]
            self.task_info = config_dict["task_info"]
            
        self.aes_key = None
        self.aes_key_valid = False
        self.server_public_key = None
        self.server_public_key_valid = False
        
        self.server_rsa_encrypt_aes_key = None
        
        #self.AES_KEY_BYTE = 16
        return
    
    def has_aes_key(self):
        '''
        If has aes_key from the server.
        '''
        return True if self.aes_key is not None else False
    
    
    def decrypt_AES_key(self, enc_aes_key: bytes) -> None:
        '''
        Decrypt the AES key from the server.
        '''
        self.aes_key = decrypt_bytes_by_RSA(self.rsa_private_key, enc_aes_key)
        print("AES Key:", self.aes_key)
        
    def decrypt_server_public_key(self, enc_public_key: bytes) -> None:
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
            
    def rsa_encrypt_aes_key(self) -> bytes:
        '''
        Use Server Public Key to Encrypt AES Key. Return it.
        '''
        if self.server_rsa_encrypt_aes_key is not None:
            return self.server_rsa_encrypt_aes_key
        self.server_rsa_encrypt_aes_key = encrypt_bytes_by_RSA(self.server_public_key, self.aes_key)
        return self.server_rsa_encrypt_aes_key
    
    def aes_encrypt_file_bytes(self, file_path: str) -> bytes:
        '''
        Use AES Key to Encrypt File Bytes. Return the Encrypted Content.
        '''
        read_file = open(file_path, "rb")
        enc_file_bytes = encrypt_bytes_by_AES(self.aes_key, read_file.read())
        read_file.close()
        return enc_file_bytes
    
    def sign_by_private_key(self, enc_text: bytes) -> bytes:
        '''
        Use Self Private Key to Sign enc_text
        '''
        return sign_encrypted_text(self.rsa_private_key, enc_text)
    
    def generate_task(self, task_name: str, task_file_path: str) -> dict:
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
                "client_key": self.rsa_public_key,
                "enc_aes_key": enc_aes_key, 
                "enc_aes_key_signature": enc_aes_key_signature,
                "enc_task_hash": enc_task_hash, 
                "enc_task_hash_signature": enc_task_hash_signature, 
                "enc_file_content": enc_file_content, 
                "enc_file_content_signature": enc_file_content_signature
                }
    
    
    def validate_block(self, block: dict, signature: bytes) -> bool:
        block_bytes = bytes(str(block["index"]) + str(block["timestamp"]), encoding = "utf-8") + block["previous_hash"]
        if block["transactions"]:
            block_bytes += block["transactions"][0]["task_hash"] + block["transactions"][0]["enc_result"] + block["transactions"][0]["enc_run_info"]
        return validate_signature(self.server_public_key, block_bytes, signature)
    
    def decrypt_and_save_results(self, block: dict) -> dict:
        '''
        Decrypt results and update self.task_info
        '''
        task_hash = block["transactions"][0]["task_hash"]
        result = str(decrypt_bytes_by_AES(self.aes_key, block["transactions"][0]["enc_result"]), encoding = "utf-8")
        run_info = str(decrypt_bytes_by_AES(self.aes_key, block["transactions"][0]["enc_run_info"]), encoding = "utf-8")
        for task in self.task_info:
            if task.task_hash == task_hash:
                task.has_result = True
                task.result = result
                task.run_info = run_info
        return {
            "result": result, 
            "run_info": run_info
        }
        
    

