from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

from Constant import RSA_KEY_LENGTH, AES_KEY_BIT, AES_KEY_BYTE 
from Constant import encrypt_bytes_by_AES, encrypt_bytes_by_RSA, sign_encrypted_text, decrypt_bytes_by_RSA, decrypt_bytes_by_AES, validate_signature

import os
import time
import subprocess

class CodeRunner:
    def __init__(self):
        return
    
    def run_code_file(self, client_public_key: bytes, 
                            aes_key: bytes, 
                            task_hash: bytes, 
                            file_content: bytes) -> dict:
        '''
        Run Codes in the File. 
        Return task_hash, encrypted result and encrypted run_info (Now the Elapsed Time).
        '''
        
        CURRENT_PATH = "./"
        CODE_FILE_NAME = "code_file.py"
        CODE_FILE_PATH = CURRENT_PATH + CODE_FILE_NAME
        
        # Write file_content to a File
        code_file = open(CODE_FILE_PATH, "w+")
        code_file.write(file_content.decode("utf-8"))
        code_file.close()
        
        # Give X Permission to code_file
        give_permission_process = subprocess.run(["chmod", "777", CODE_FILE_PATH], cwd = CURRENT_PATH)  # doesn't capture output
        if give_permission_process.returncode == 0:
            print("Give Code File Permission Success.")
        else:
            print("Give Code File Permission Fail.")
        
        # Run Code File and Record Elapsed Time.
        run_begin_time = time.time()
        run_code_file_process = subprocess.run(["python", CODE_FILE_PATH], cwd = CURRENT_PATH, capture_output = True)
        result_text = ""
        if run_code_file_process.returncode == 0:
            result_text = run_code_file_process.stdout
            if result_text is None:
                result_text = "Run Code Success but No Output.\n"
        else:
            result_text = run_code_file_process.stderr
            if result_text is None:
                result_text = "Run Code Fail but No Output.\n"
        
        result_bytes = bytes(str(result_text), encoding = "utf-8") if type(result_text) is not bytes else result_text
        run_elapsed_time_text = str(round(time.time() - run_begin_time, 4)) + 's'
        run_elapsed_time_bytes = bytes(run_elapsed_time_text, encoding = "utf-8")
        
        # Delete Code File
        os.remove(CODE_FILE_PATH)
        
        # Encrypt Bytes
        enc_result = encrypt_bytes_by_AES(aes_key, result_bytes)
        enc_run_info = encrypt_bytes_by_AES(aes_key, run_elapsed_time_bytes)
        
        return {"client_public_key": client_public_key, 
                "task_hash": task_hash, 
                "enc_result": enc_result, 
                "enc_run_info": enc_run_info}
    