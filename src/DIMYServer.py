import socket
import threading
from base64 import b64decode, b64encode
from bloomFilter import *
from helper import *

address = ("localhost", 55000)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(address)

# message deffinition:
# header - data size - data
# header is static size HEADER_SIZE
# data size is 4 bytes

cbf_list = []

def client_handler(socket, client_addr):
    while True:
        header, data_bits = receive_msg(socket)
        bf = BloomFilter()
        if (data_bits != 0) and (header == HEAD_QBF or header == HEAD_QBF):
            bf = BloomFilter(bit_array=data_bits)
            pdebug(f'got client BF: [{bf}]')
        pdebug(f'got message from [{client_addr}] with header: [{header}]')
        if header == HEAD_CBF:
            print(f'[Task 9] client [{client_addr}] uploading CBF...')
            try:
                cbf_list.append(bf)
            except Exception as e:
                edebug(f'[client_handler] exception {e}')
                send_msg(socket, HEAD_FAIL)
            else:
                send_msg(socket, HEAD_SUCCESS)
                print(f'...done\nCBF content: [{bf}]')
        
        if header == HEAD_QBF:
            print(f'[Task 10] client [{client_addr}] uploading QBF...')
            match = None
            found = False
            for cbf in cbf_list:
                if cbf.match(bf):
                    found = True
                    match = cbf
                    break
            print('...done')
            if found:
                # match with covid positive interaction
                print(f'client [{client_addr}] positive match with existing CBF')
                pdebug(f'client BF: \n[{bf}]\nmatched with CBF:\n[{cbf}]')
                send_msg(socket, HEAD_SUCCESS)
            else:
                print(f'client [{client_addr}] no match with existing CBF\'s')
                send_msg(socket, HEAD_FAIL)
        
        if header == HEAD_DISCONNECT:
            print(f'client [{client_addr}] dissconnect.')
            send_msg(socket, HEAD_SUCCESS)
            break

        if header == HEAD_INFO:
            print(f'client [{client_addr}] request info.')
            info = f"""
            server address: [{address}]\n
            connected with client: [{client_addr}]\n
            server debug mode: [{debug}]
            """
            print(info)

        if header == HEAD_INFO_VERBOSE:
            print(f'client [{client_addr}] request verbose info.')
            info = f"""
            server address: [{address}]\n
            connected with client: [{client_addr}]\n
            server debug mode: [{debug}]\n
            cbf list:\n
            """
            for cbf in cbf_list:
                info = info + '[' + cbf + ']' + f'\n'
            
            print(info)

        else:
            send_msg(socket, HEAD_FAIL) # bad data
            edebug(f'malformed packet (??)\ngot unrecognised header: [{header}]')
    
    exit()

def start():
    server.listen()
    while True:
        socket, client_addr = server.accept()
        thread = threading.Thread(target=client_handler, args=(socket, client_addr))
        thread.start()
        print(f"[NEW CONNECTION] - {client_addr}\n![CURRENT CONNECTIONS] - {threading.activeCount()-1}")

def main():
    print(f"[SERVER STARTUP] - binding to {address}")
    start()

if __name__ == "__main__":
    main()