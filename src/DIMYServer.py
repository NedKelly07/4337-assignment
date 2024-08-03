import socket
import threading
from base64 import b64decode, b64encode
from bloomFilter import *
from helper import *

address = ("localhost", 55000)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(address)

cbf_list = []

def client_handler(socket):
    try:
        while True:
            message = receive_message(socket)
            if message:
                bf_type, bloom_filter = reconstruct_bf(message)
                bloom_filter = BloomFilter(bloom_filter)
                print(f"Received Bloom filter type: {bf_type}")
                
                if bf_type == 'CBF':
                    print("Uploading close contacts CBF to server.")
                    cbf_list.append(bloom_filter)
                    return_match_message('Uploaded', socket)
                    break
                elif bf_type == 'QBF':
                    if len(cbf_list) == 0:
                        return_match_message('Negative', socket)
                        continue
                    # checking all cbfs in the list for a matching bf
                    match_found = False
                    for cbf in cbf_list:
                        if cbf.match(bloom_filter):
                            return_match_message('Positive', socket)
                            match_found = True
                            break
                    if not match_found:
                        print("Match not found")
                        return_match_message('Negative', socket)
            else:
                print("Error: Did not receive all parts.")
                break
    finally:
        socket.close()
        print("Connection closed.")
    print("Exiting handler thread.")
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