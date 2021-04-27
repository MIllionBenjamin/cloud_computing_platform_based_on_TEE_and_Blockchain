from Client import Client
from Constant import bytes_to_base64_str, base64_str_to_bytes, dic_base64_to_bytes, dic_bytes_content_to_base64

import os
import numpy as np
import pandas as pd
import requests
import json


PUBLIC_KEY_FILENAME = "client_public_key"
PRIVATE_KEY_FILENAME = "client_private_key"
TASK_INFO_FILENAME = "task_info.npy"
TASK_CSV_FILENAME = "task_info.csv"
FULL_CHAIN_NAME = "full_chain"

def print_task(task):
    print("Task Name:", task.task_name)
    print("Task Hash:", task.task_hash)
    print("Task File Path:", task.task_file_path)
    print("Create Time:", task.create_time)
    print("Result:", task.result)
    print("Run Info:", task.run_info)
    

def base64_block_to_bytes(block: dict):
    bytes_block = block.copy()
    bytes_block["previous_hash"] = base64_str_to_bytes(bytes_block["previous_hash"])
    for key in bytes_block["transactions"][0]:
        block["transactions"][0][key] = base64_str_to_bytes(block["transactions"][0][key])
    return bytes_block

class ClientInterface:
    def __init__(self, server_url: str = 'http://0.0.0.0:8383', saving_path: str = '.'):
        '''
        Create Client from Files in saving_path if Config Files Found.
        Else Create a New Client and Save Client Config Files to saving_path.
        '''
        print("------Begin Loading Client------")
        self.server_url = server_url
        self.saving_path = saving_path
        self.client = None
        
        public_key_path = os.path.join(saving_path, PUBLIC_KEY_FILENAME)
        private_key_path = os.path.join(saving_path, PRIVATE_KEY_FILENAME)
        task_info_path = os.path.join(saving_path, TASK_INFO_FILENAME)
        if os.path.exists(public_key_path) and os.path.exists(private_key_path) and os.path.exists(task_info_path):
            print("Client Files Found. Load them.")
            public_key_file = open(public_key_path, "rb")
            client_public_key = public_key_file.read()
            public_key_file.close()
            private_key_file = open(private_key_path, "rb")
            client_private_key = private_key_file.read()
            public_key_file.close()
            task_info = np.load(task_info_path, allow_pickle = True)
            self.client = Client({"rsa_public_key": client_public_key, 
                                  "rsa_private_key": client_private_key, 
                                  "task_info": list(task_info)})
        else:
            print("Client Files not Found. Create New Client.")
            self.client = Client()
            print("Client Files Saving at:", saving_path)
            public_key_file = open(public_key_path, "wb+")
            public_key_file.write(self.client.rsa_public_key)
            public_key_file.close()
            private_key_file = open(private_key_path, "wb+")
            private_key_file.write(self.client.rsa_private_key)
            public_key_file.close()
            np.save(task_info_path, self.client.task_info)
        print("RSA Public Key Save in:", public_key_path)
        print("RSA Private Key Save in:", private_key_path)
        print("Task Info Save in: (Using Numpy File Format)", task_info_path)
        print("------Load Client Success------\n")
    
    
    def request_keys(self):
        '''
        Request Keys from Server.
        '''
        print("------Begin Requesting Keys from Server------")
        request_json = json.dumps({"client_key": bytes_to_base64_str(self.client.rsa_public_key)})
        keys_request = requests.post(self.server_url + "/key", data = request_json)
        keys_bytes_json = dic_base64_to_bytes(keys_request.json())
        self.client.decrypt_AES_key(keys_bytes_json["enc_aes_key"])
        print("Decrypt AES Key Success.")
        self.client.decrypt_server_public_key(keys_bytes_json["enc_rsa_public_key"])
        print("Decrypt Server RSA Public Key Success.")
        self.client.validate_information(keys_bytes_json["enc_aes_key"], 
                                         keys_bytes_json["enc_rsa_public_key"], 
                                         keys_bytes_json["enc_aes_key_signature"], 
                                         keys_bytes_json["enc_rsa_public_key_signature"])
        print("Signature Validation Success.")
        print("------Request Keys Success------\n")
    
    
    def post_task(self, task_name: str, task_file_path: str):
        print("------Begin Posting Task------")
        request_json = json.dumps(dic_bytes_content_to_base64(self.client.generate_task(task_name, task_file_path)))
        print("Task Create Success. Task Info:")
        print_task(self.client.task_info[-1])
        task_post_request = requests.post(self.server_url + "/task", data = request_json)
        print("Response from Server:", task_post_request.json())
        np.save(os.path.join(self.saving_path, TASK_INFO_FILENAME), self.client.task_info)
        print("Local Task Info Update Success.")
        print("------Post Task Success------\n")
        
    
    
    def get_all_results(self):
        print("------Begin Getting Task's Results------")
        no_result_exist = False
        for task in self.client.task_info:
            if not task.has_result:
                no_result_exist = True
                print("Getting Result of:", task.task_name)
                print("Task Hash:", task.task_hash)
                print("Task File Path:", task.task_file_path)
                request_para = {"task_hash": bytes_to_base64_str(task.task_hash)}
                result_request = requests.get(self.server_url + "/block", params = request_para)
                result_json = result_request.json()
                if result_json["block"] is None:
                    print("Server Has No Result of this Task Now.\n")
                    continue
                print("Result Block Received.")
                result_block = base64_block_to_bytes(result_json["block"])
                signature = base64_str_to_bytes(result_json["signature"])
                print("Result Block Validation:", self.client.validate_block(result_block, signature))
                print("Result and Run Info:")
                print(self.client.decrypt_and_save_results(result_block))
                print("Result of", task.task_name, "Accepted.\n")
        if not no_result_exist:
            print("All Tasks Have Result.")
        else:
            np.save(os.path.join(self.saving_path, TASK_INFO_FILENAME), self.client.task_info)
            print("Local Task Info Update Success.")
        print("------Get Task's Results Success------\n")
    
    
    def export_task_info_as_csv(self):
        print("------Begin Exporting Task Info to CSV------")
        task_info_dict = {
            "task_name": [], 
            "create_time": [], 
            "task_file_path": [], 
            "task_hash": [], 
            "has_result": [], 
            "result": [], 
            "run_info": []
        }
        for task in self.client.task_info:
            task_info_dict["task_name"].append(task.task_name)
            task_info_dict["create_time"].append(task.create_time)
            task_info_dict["task_file_path"].append(task.task_file_path)
            task_info_dict["task_hash"].append(task.task_hash)
            task_info_dict["has_result"].append(task.has_result)
            task_info_dict["result"].append(task.result)
            task_info_dict["run_info"].append(task.run_info)
        task_dataframe = pd.DataFrame(data = task_info_dict)
        task_dataframe.to_csv(os.path.join(self.saving_path, TASK_CSV_FILENAME), index = False)
        print("------Export Task Info to CSV Success------\n")
            
                
                
    def get_full_chain(self):
        print("------Begin Getting Full Chain------")
        full_chain_request = requests.get(self.server_url + "/block")
        full_chain_json = full_chain_request.json()
        print("Finish Getting Full Chain base64 Json.")
        full_chain_json[0]["previous_hash"] = base64_str_to_bytes(full_chain_json[0]["previous_hash"])
        for i in range(1, len(full_chain_json)):
            full_chain_json[i] = base64_block_to_bytes(full_chain_json[i])
        print("Base64 Content Converted to Bytes Success.")
        full_chain_path = os.path.join(self.saving_path, FULL_CHAIN_NAME)
        with open(full_chain_path, "w+") as full_chain_file:
            for block in full_chain_json:
                full_chain_file.write(str(block) + '\n')
        print("Full Chain Save in:", full_chain_path)
        print("------Get Full Chain Success------\n")
        
        
print("Welcome to the Client Interface of the Demo of A Privacy-Preserving Computing Platform based on TEE and Blockchain.")
server_url = input("Please Enter Server URL: ")
saving_path = input("Please Enter Client Files Saving Path (For Current Path, Enter '.'): ")
client_interface = ClientInterface(server_url, saving_path)
client_interface.request_keys()

while True:
    try:
        print("Press Num and Enter to Perform the Operation:")
        print("1. Post Task")
        print("2. Get Task Results")
        print("3. Export Task Info to CSV")
        print("4. Get Full Chain")
        print("5. Exit")
        command = input()
        if command == '1':
            task_name = input("Enter Task Name: ")
            task_file_path = input("Enter Task Path: ")
            client_interface.post_task(task_name, task_file_path)
        if command == '2':
            client_interface.get_all_results()
        elif command == '3':
            client_interface.export_task_info_as_csv()
        elif command == '4':
            client_interface.get_full_chain()
        elif command == '5':
            print("Exit. Bye.")
            break
        else:
            print("Invalid Command.")
        input("Press Enter to Continue")
    except Exception as e:
        print(e)
        print("Error Occurs. Press Enter to Continue.")
        input()
        continue
        
        
    
                
            
            
