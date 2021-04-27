import time
import json
from Crypto.Hash import SHA256

from KeyManager import KeyManager
from Constant import sign_encrypted_text



class BlockchainRecorder(object):
    def __init__(self):
        self.client_public_key_maps_task_hash = {}
        
        self.chain = []
        self.current_transactions = []
        
        # Create Genesis Block
        self.new_block(previous_hash=bytes('1', encoding="utf-8"))

    def new_block(self, previous_hash: bytes = None):
        """
        Create a new Block in the Blockchain
        
        :param previous_hash: (Optional) <str> Hash of previous Block
        :return: <dict> New Block
        """

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'transactions': self.current_transactions,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        return block


    def new_transaction(self, task_hash: bytes, enc_result: bytes, enc_run_info: bytes) -> int:
        '''
        Adds a new transaction to the list of transactions.
        The transaction is exactly the recorder of code running.
        The transaction contains task_hash, enc_result, enc_run_info.
        Return: <int> The index of the Block that will hold this transaction
        '''
        self.current_transactions.append({
            'task_hash': task_hash,
            'enc_result': enc_result,
            'enc_run_info': enc_run_info,
        })

        return self.last_block['index'] + 1

    def new_record(self, client_public_key: bytes, task_hash: bytes, enc_result: bytes, enc_run_info: bytes) -> bool:
        '''
        Create New Record and add client_public_key maps task_hash.
        One Block, one record(transaction).
        '''
        if client_public_key in self.client_public_key_maps_task_hash:
            self.client_public_key_maps_task_hash[client_public_key].add(task_hash)
        else:
            self.client_public_key_maps_task_hash[client_public_key] = set()
            self.client_public_key_maps_task_hash[client_public_key].add(task_hash)
        self.new_transaction(task_hash, enc_result, enc_run_info)
        self.new_block()
        return True
    
    
    def generate_block_bytes(self, block: bytes):
        '''
        Generate Block Bytes in Specific Method.
        '''
        block_bytes = bytes(str(block["index"]) + str(block["timestamp"]), encoding = "utf-8") + block["previous_hash"]
        if block["transactions"]:
            block_bytes += block["transactions"][0]["task_hash"] + block["transactions"][0]["enc_result"] + block["transactions"][0]["enc_run_info"]
        return block_bytes
    
    
    def hash(self, block):
        """
        Creates a SHA-256 hash of a Block
        :param block: <dict> Block
        :return: <str>
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        
        return SHA256.new(self.generate_block_bytes(block)).digest()

    
    def find_client_key_by_task_hash(self, task_hash: bytes) -> bytes:
        '''
        Return the client key which has the given tsak_hash.
        '''
        for client_key in self.client_public_key_maps_task_hash:
            if task_hash in self.client_public_key_maps_task_hash[client_key]:
                return client_key
        return None
    
    def find_block_by_task_hash(self, task_hash: bytes):
        '''
        Return the block whose task_hash is the same as given task_hash.
        '''
        for block in self.chain:
            if block['transactions'] and block['transactions'][0]["task_hash"] == task_hash:
                return block
        return None
    
    def return_block_and_signature(self, task_hash: bytes, key_manager: KeyManager) -> dict:
        '''
        Use task_hash and self.client_public_key_maps_task_hash to find the client pub key.
        Use client pub key to find corresponding server pri key in key_manager.
        Find the block whose task_hash is the same as given task_hash.
        Sign the block by server pri key.
        Return the block and the signature
        '''
        client_key = self.find_client_key_by_task_hash(task_hash)
        if client_key is None:
            return {"block": None, 
                    "Info": "Result Not Found"}
        server_pri_key = key_manager.client_key_map_server_key[client_key]["rsa_private_key"]
        block = self.find_block_by_task_hash(task_hash)
        block_bytes = self.generate_block_bytes(block)
        signature = sign_encrypted_text(server_pri_key, block_bytes)
        return {
            "block": block, 
            "signature": signature
        }
        
        
    
    @property
    def last_block(self):
        # Returns the last Block in the chain
        return self.chain[-1]
    
    @property
    def all_blocks(self):
        # Returns the last Block in the chain
        return self.chain
    
