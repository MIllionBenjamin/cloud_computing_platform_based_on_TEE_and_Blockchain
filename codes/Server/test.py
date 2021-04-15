from KeyManager import KeyManager
from Client import Client

client_1 = Client()
key_manager = KeyManager()

key_manager.generate_key_for_client_key(client_1.rsa_public_key)

print(client_1.rsa_public_key in key_manager.client_key_map_server_key)

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
from Constant import encrypt_bytes_by_AES, decrypt_bytes_by_AES

aes_key = Random.get_random_bytes(16)

non_encrypt_file = open("../encrypt_file.py", "rb")
#encrypted_file = open("../encrypted_file_py", "wb+")
#encrypted_file.write(encrypt_bytes_by_AES(aes_key, non_encrypt_file.read()))
#encrypted_file = open("../encrypted_file_py", "rb")
decrypted_file = open("../decrypted_file.py", "w+")
decrypted_file.write(decrypt_bytes_by_AES(aes_key, encrypt_bytes_by_AES(aes_key, non_encrypt_file.read())).decode("utf-8"))

non_encrypt_file.close()
#encrypted_file.close()
decrypted_file.close()
'''


def a(n):
    if n == 1:
        return 1, 2, 3, 4
    else:
        return "Error"
    
print(a(1))
print(type(a(1)))
print(a(2))
print(type(a(2)))

import time

#print(bytes(time.time()))
time_bytes = bytes(str(time.time()), encoding = "utf-8")
print(time_bytes + client_1.rsa_public_key)

print(type((1, "1")))


import pprint

pp = pprint.PrettyPrinter(indent=4)

from FileReceiver import FileReceiver

file_receiver = FileReceiver()

task_info = client_1.generate_task("task_1", "../encrypt_file.py")
result_to_client, result_to_CodeRunner = file_receiver.validate_and_decrypt_task_info(key_manager, 
                                             task_info["client_public_key"], 
                                             task_info["enc_aes_key"], 
                                             task_info["enc_aes_key_signature"], 
                                             task_info["enc_task_hash"], 
                                             task_info["enc_task_hash_signature"], 
                                             task_info["enc_file_content"], 
                                             task_info["enc_file_content_signature"])

print(result_to_client)
print(result_to_CodeRunner)

from CodeRunner import CodeRunner

code_runner = CodeRunner()
run_return = code_runner.run_code_file(result_to_CodeRunner["client_public_key"], 
                                       result_to_CodeRunner["aes_key"], 
                                       result_to_CodeRunner["task_hash"], 
                                       result_to_CodeRunner["file_content"])

print(run_return)
from Constant import encrypt_bytes_by_AES, decrypt_bytes_by_AES
print(decrypt_bytes_by_AES(client_1.aes_key, run_return["enc_result"]))
print(decrypt_bytes_by_AES(client_1.aes_key, run_return["enc_run_info"]))


from BlockchainRecorder import BlockchainRecorder

from Constant import bytes_to_base64_str
blockchain_recorder = BlockchainRecorder()

blockchain_recorder.new_record(run_return["client_public_key"], 
                               run_return["task_hash"], 
                               run_return["enc_result"], 
                               run_return["enc_run_info"])
print(blockchain_recorder.all_blocks)
print(blockchain_recorder.client_public_key_maps_task_hash)

block_result = blockchain_recorder.return_block_and_signature(run_return["task_hash"], key_manager)
print(block_result)

print(client_1.validate_block(block_result["block"], block_result["signature"]))
print(client_1.decrypt_and_save_results(block_result["block"]))


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

