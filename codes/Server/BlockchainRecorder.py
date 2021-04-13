import time
import json
import hashlib

class BlockchainRecorder(object):
    def __init__(self):
        self.client_public_key_maps_task_hash = {}
        
        self.chain = []
        self.current_transactions = []
        
        # Create Genesis Block
        self.new_block(previous_hash=1)

    def new_block(self, previous_hash=None):
        """
        Create a new Block in the Blockchain
        :param proof: <int> The proof given by the Proof of Work algorithm
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


    def new_transaction(self, task_hash, enc_result, enc_run_info):
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

    def new_record(self, client_public_key, task_hash, enc_result, enc_run_info):
        '''
        Create New Record and add client_public_key maps task_hash.
        One Block, one record(transaction).
        '''
        if client_public_key in self.client_public_key_maps_task_hash:
            self.client_public_key_maps_task_hash[client_public_key].append(task_hash)
        else:
            self.client_public_key_maps_task_hash[client_public_key] = []
            self.client_public_key_maps_task_hash[client_public_key].append(task_hash)
        self.new_transaction(task_hash, enc_result, enc_run_info)
        self.new_block()
        return True
    
    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block
        :param block: <dict> Block
        :return: <str>
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def find_block_by_task_hash(self, task_hash):
        '''
        Return the block whose task_hash is the same as given task_hash.
        '''
        for block in self.chain:
            if block['transactions'] and block['transactions'][0]["task_hash"] == task_hash:
                return block
    
    @property
    def last_block(self):
        # Returns the last Block in the chain
        return self.chain[-1]
    
    @property
    def all_blocks(self):
        # Returns the last Block in the chain
        return self.chain
    
