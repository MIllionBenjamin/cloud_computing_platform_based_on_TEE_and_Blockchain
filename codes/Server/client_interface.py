from Client import Client
from Constant import bytes_to_base64_str, base64_str_to_bytes, dic_base64_to_bytes

import os
import numpy as np

PUBLIC_KEY_FILENAME = "client_public_key"
PRIVATE_KEY_FILENAME = "client_private_key"
TASK_INFO_FILENAME = "task_info.npy"

class ClientInterface:
    def __init__(self, server_url: str = '0.0.0.0:8383', saving_path: str = '.'):
        self.server_url = server_url
        self.saving_path = saving_path
        self.client = None
        
        public_key_path = os.path.join(saving_path, PUBLIC_KEY_FILENAME)
        private_key_path = os.path.join(saving_path, PRIVATE_KEY_FILENAME)
        task_info_path = os.path.join(saving_path, TASK_INFO_FILENAME)
        if os.path.exists(public_key_path) and os.path.exists(private_key_path) and os.path.exists(task_info_path):
            public_key_file = open(public_key_file, "rb")
            client_public_key = public_key_file.read()
            public_key_file.close()
            private_key_file = open(private_key_path, "rb")
            client_private_key = private_key_file.read()
            public_key_file.close()
            task_info = np.load(task_info_path)
            print("task_info type", type(task_info))
            self.client = Client(config_dict)
            
         

while True:
    if input() == '1':
        print(client_1.rsa_public_key)
        print(bytes_to_base64_str(client_1.rsa_public_key))
    if input() == '2':
        print(bytes_to_base64_str(client_1.rsa_public_key))
    if input() == '3':
        aes_key_bytes = base64_str_to_bytes(input())
        client_1.decrypt_AES_key(aes_key_bytes)
        print(client_1.aes_key)
        


