import socket
import threading
from base64 import b64decode, b64encode
from bloomFilter import *
from helper import *
import re

address = ("localhost", 55000)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(address)
NUM_PARTS = 4
# message deffinition:
# header - data size - data
# header is static size HEADER_SIZE
# data size is 4 bytes

cbf_list = []

def client_handler(socket):
    while True:
        received_parts = []
        
        for _ in range(NUM_PARTS):
            part = receive_message(socket)
            if part:
                received_parts.append(part)
                                
        if len(received_parts) == NUM_PARTS:
            entire_message = ''.join(received_parts)
            bf_type, bloom_filter = reconstruct_bf(entire_message)
            print("Reconstructed bloom filter!", bf_type)
            
            
            if bf_type == 'CBF':
                print("Uploading close contacts CBF to server.")
                cbf_list.append(bloom_filter)
                return_match_message('Uploaded', socket)
                   
            elif bf_type == 'QBF':
                if len(cbf_list) == 0:
                    return_match_message('Negative', socket)
                    break
                print("Received QBF.")
                # checking all cbfs in the list for a matching bf
                for cbfs in cbf_list:
                    print(type(cbfs))
                    for cbf in cbfs: 
                        print(type(cbf))
                        if cbf.match(bloom_filter):
                            print("Match found")
                            return_match_message('Positive', socket)
                            break
                print("Match not found")
                return_match_message('Negative', socket)          
            
        else:
            print("Error: Did not receive all parts.")
            break
    exit()

def start():
    server.listen()
    while True:
        socket, client_addr = server.accept()
        thread = threading.Thread(target=client_handler, args=(socket,))
        thread.start()
        print(f"[NEW CONNECTION] - {client_addr}\n![CURRENT CONNECTIONS] - {threading.active_count()-1}")

def main():
    print(f"[SERVER STARTUP] - binding to {address}")
    start()

if __name__ == "__main__":
    main()