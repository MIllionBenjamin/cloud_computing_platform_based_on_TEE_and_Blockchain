from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15



RSA_KEY_LENGTH = 1024
AES_KEY_BIT = 128
AES_KEY_BYTE = 16


def encrypt_bytes_by_AES(aes_key, rsa_public_key):
    '''
    Encrypt RSA Public Key by AES Key.
    '''
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(rsa_public_key)
    nonce = cipher_aes.nonce
    enc_rsa_public_key = nonce + tag + ciphertext
    print("Encrypt Bytes by AES Success.")
    return enc_rsa_public_key


def encrypt_bytes_by_RSA(rsa_public_key, aes_key):
    '''
    Encrypt AES KEY by RSA Public Key.
    '''
    client_public_key = RSA.importKey(rsa_public_key)
    cipher_rsa = PKCS1_OAEP.new(client_public_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)
    print("Encrypt Bytes by RSA Public Key Success.")
    return enc_aes_key


def sign_encrypted_text(rsa_private_key, unsigned_enc_text):
    '''
    Sign Encrypted Text by RSA Private Key.
    '''
    rsa_private_key = RSA.importKey(rsa_private_key)
    enc_text_hash = SHA256.new(unsigned_enc_text)
    enc_text_signature = pkcs1_15.new(rsa_private_key).sign(enc_text_hash)
    print("Sign Text Success.")
    return enc_text_signature


def decrypt_bytes_by_RSA(rsa_private_key, enc_aes_key):
    '''
    Decrypt the AES key by RSA Private Key.
    '''
    imported_rsa_private_key = RSA.importKey(rsa_private_key)
    cipher_rsa = PKCS1_OAEP.new(imported_rsa_private_key)
    decrypted_aes_key = cipher_rsa.decrypt(enc_aes_key)
    return decrypted_aes_key


def decrypt_bytes_by_AES(aes_key, enc_public_key):
    '''
    Decrypt the RSA Public Key by AES Key.
    '''
    nonce = enc_public_key[0: AES_KEY_BYTE]
    tag = enc_public_key[AES_KEY_BYTE: 2 * AES_KEY_BYTE]
    ciphertext = enc_public_key[2 * AES_KEY_BYTE: ]
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
    try:
        server_public_key = cipher_aes.decrypt_and_verify(ciphertext, tag)
        #print("Decrypt Bytes by AES Success.")
        return server_public_key
    except (ValueError, TypeError):
        #print("Decrypt Bytes by AES Fail.")    
        return None


def validate_signature(rsa_public_key, enc_content, signature):
    '''
    Validate Signature.
    '''
    imported_public_key = RSA.importKey(rsa_public_key)
    enc_content_hash = SHA256.new(enc_content)
    
    try:
        pkcs1_15.new(imported_public_key).verify(enc_content_hash, signature)
        return True
    except (ValueError, TypeError):
        return False
    
    
import base64

def bytes_to_base64_str(message_bytes):
    return base64.b64encode(message_bytes).decode("utf-8")

def base64_str_to_bytes(base64_str: str):
    return base64.b64decode(base64_str.encode("utf-8"))

def dic_bytes_content_to_base64(dic_with_bytes: dict) -> dict:
    '''
    If dic_with_bytes[key]'s type is bytes, convert dic_with_bytes[key] to base64 str;
    Else keep original content unchanged.
    Especially, if dic_with_bytes[key] is a list, consider it as a block(see BlockchainRecorder)
    '''
    dic_with_base64 = {}
    for key in dic_with_bytes:
        if type(dic_with_bytes[key]) is bytes:
            dic_with_base64[key] = bytes_to_base64_str(dic_with_bytes[key])
        elif type(dic_with_bytes[key]) is list:
            list_with_base64 = []
            for item in dic_with_bytes[key]:
                list_with_base64.append(dic_bytes_content_to_base64(item))
            dic_with_base64[key] = list_with_base64
        elif type(dic_with_bytes[key]) is dict:
            dic_with_base64[key] = dic_bytes_content_to_base64(dic_with_bytes[key])
        else:
            dic_with_base64[key] = dic_with_bytes[key]
    return dic_with_base64


def dic_base64_to_bytes(dic_all_base64: dict) -> dict:
    '''
    Convert all base64 strings in dict to bytes
    '''
    dic_all_bytes = {}
    for key in dic_all_base64:
        dic_all_bytes[key] = base64_str_to_bytes(dic_all_base64[key])
    return dic_all_bytes
    


'''
print(bytes("asd", encoding="utf-8"))
print(type(bytes_to_base64_str(bytes("asd", encoding="utf-8"))))
print(bytes_to_base64_str(bytes("asd", encoding="utf-8")))
print(base64_str_to_bytes(bytes_to_base64_str(bytes("asd", encoding="utf-8"))))
'''