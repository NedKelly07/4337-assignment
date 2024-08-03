import bloomFilter
import struct
import base64
from base64 import b64decode, b64encode
from bitarray import bitarray
from copy import deepcopy
from time import sleep
import select

HEADER_SIZE = 20

def combine_DBFS(bloom_list):
    if len(bloom_list) == 0:
        return None
    lst_cpy = deepcopy(bloom_list)
    combined_DBFS = lst_cpy.pop(0)
    for bloom_filter in lst_cpy:
        combined_DBFS.combine(bloom_filter)
    return combined_DBFS

def add_header(message):
    return f"{len(message):<{HEADER_SIZE}}" + message

def send_bf(sock, bf, bf_type):
    bf_bytes = bf.tobytes()
    bf_string = b64encode(bf_bytes).decode()  # Encode bytes to base64 string
    entire_message = bf_type + bf_string
    
    # add header and send message to server
    message_with_header = add_header(entire_message)
    sock.sendall(message_with_header.encode())
        
def receive_message(sock):
    try:
        # Receive the header first
        header = sock.recv(HEADER_SIZE)
        if not header: 
            return False
        
        message_length = int(header.decode().strip())
        
        # Now receive the rest of the message
        data = b""
        while len(data) < message_length:
            packet = sock.recv(message_length - len(data))
            if not packet:
                return False
            data += packet
        
        return data.decode()
    except Exception as e:
        print(f"Error receiving message: {e}")
        return False

def reconstruct_bf(entire_message):
    try:
        # Split the message into the type and encoded bitarray
        bf_type, bf_encoded = entire_message.split('|', 1)
    except ValueError:
        print("Error: Message format is incorrect. Could not split into type and data.")
        return None

    # Decode the base64 string back to bytes
    try:
        bf_bytes = b64decode(bf_encoded)
    except base64.binascii.Error as e:
        print(f"Error decoding base64: {e}")
        return None
    bf = bitarray()
    bf.frombytes(bf_bytes)
    #print(bf_type)
    return bf_type, bf  

def return_match_message(result, socket):
    message = add_header(result)
    message_encoded = message.encode('utf-8')
    socket.send(message_encoded)

def check_covid_positive():
    while True:
        user_notify = input("\nWould you like to notify your close contacts? Enter 'Y' or 'N': \n").strip().upper()
        if user_notify in ['Y', 'N']:
            return user_notify == 'Y'
        print("Invalid input. Please enter 'Y' or 'N'.")