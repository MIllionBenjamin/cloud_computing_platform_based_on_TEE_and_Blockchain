from flask import Flask, abort, request, jsonify
from flask.views import MethodView
from concurrent.futures import ThreadPoolExecutor
from time import sleep


from Constant import base64_str_to_bytes, bytes_to_base64_str, dic_bytes_content_to_base64, dic_base64_to_bytes

from KeyManager import KeyManager
from FileReceiver import FileReceiver
from CodeRunner_only_task_run_TEE import CodeRunner
from BlockchainRecorder import BlockchainRecorder

key_manager = KeyManager()
file_receiver = FileReceiver()
code_runner = CodeRunner()
blockchain_recorder = BlockchainRecorder()

executor = ThreadPoolExecutor(2)

app = Flask(__name__)

class Key(MethodView):
    def post(self):
        json_data = request.get_json(force=True)
        client_key = dic_base64_to_bytes(json_data)["client_key"]
        base64_return_value = dic_bytes_content_to_base64(key_manager.return_encrypted_keys_and_sign(client_key))
        #print(key_manager.client_key_map_server_key)
        #print(key_manager.return_encrypted_keys_and_sign(client_key))
        #print(len(key_manager.client_key_map_server_key))
        return jsonify(base64_return_value)
app.add_url_rule('/key', view_func = Key.as_view(name='key'))


class Task(MethodView):
    def run_and_record(self, to_code_runner: dict):
        code_run_return = code_runner.run_code_file(to_code_runner["client_public_key"], 
                                                    to_code_runner["aes_key"], 
                                                    to_code_runner["task_hash"], 
                                                    to_code_runner["file_content"])
        blockchain_recorder.new_record(code_run_return["client_public_key"], 
                                       code_run_return["task_hash"], 
                                       code_run_return["enc_result"], 
                                       code_run_return["enc_run_info"])

        print("Task Done!")
        
    def post(self):
        json_data = request.get_json(force=True)
        json_dic = dic_base64_to_bytes(json_data)
        to_client, to_code_runner = file_receiver.validate_and_decrypt_task_info(key_manager, 
                                                                   json_dic["client_key"], 
                                                                   json_dic["enc_aes_key"], 
                                                                   json_dic["enc_aes_key_signature"], 
                                                                   json_dic["enc_task_hash"], 
                                                                   json_dic["enc_task_hash_signature"], 
                                                                   json_dic["enc_file_content"], 
                                                                   json_dic["enc_file_content_signature"])
        executor.submit(self.run_and_record, to_code_runner)
        return jsonify({"task_arranged_status": to_client})
app.add_url_rule('/task', view_func = Task.as_view(name='task'))


class Block(MethodView):
    def get(self):
        task_hash_base64 = str(request.args.get("task_hash", "-1"))
        if task_hash_base64 != "-1":
            task_hash = base64_str_to_bytes(task_hash_base64)
            block_and_signature = blockchain_recorder.return_block_and_signature(task_hash, key_manager)
            block_and_signature_base64 = dic_bytes_content_to_base64(block_and_signature)
            return jsonify(block_and_signature_base64)
        else:
            all_blocks = blockchain_recorder.all_blocks
            all_blocks_base64 = []
            for block in all_blocks:
                all_blocks_base64.append(dic_bytes_content_to_base64(block))
            return jsonify(all_blocks_base64)
app.add_url_rule('/block', view_func = Block.as_view(name='block'))


if __name__ == '__main__':
    app.run(host = "0.0.0.0", port = 8383)