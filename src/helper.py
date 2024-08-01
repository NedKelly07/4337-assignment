import bloomFilter
import struct
import base64
from base64 import b64decode, b64encode
from bitarray import bitarray
from copy import deepcopy
from time import sleep
import select


debug = True # toggle for verbose data output

HEADER_SIZE = 20
NUM_PARTS = 4

def combine_DBFS(bloom_list):
    # Initialize combined_DBFS with the first Bloom filter
    if len(bloom_list) == 0:
        return None
    lst_cpy = deepcopy(bloom_list)
    combined_DBFS = lst_cpy.pop(0)
    for bloom_filter in lst_cpy:
        combined_DBFS.combine(bloom_filter)
    return combined_DBFS

def add_header(message):
    return f"{len(message):<{HEADER_SIZE}}" + message

def send_bf(socket, bf, bf_type):
    bf_bytes = bf.tobytes()
    # encode bytes into base64 encoded bytes objkect, transform into string rep
    bf_string = b64encode(bf_bytes).decode()    
    entire_message = bf_type + bf_string
    part_size = len(entire_message) // NUM_PARTS
    split_message = [entire_message[i * part_size:(i + 1) * part_size] for i in range(NUM_PARTS)]
    for part in split_message:
        message_to_send = add_header(part)
        print(type(message_to_send))
        socket.send(message_to_send)
        sleep(0.5) 
        
def receive_message(socket):
    header = socket.recv(HEADER_SIZE).decode('utf-8').strip()
    if header == '':
        return False
    message_length = int(header)
    print(f"Message length: {message_length}")
    message = socket.recv(message_length).decode('utf-8')
    return message

def reconstruct_bf(entire_message):
    try:
        # Split the message into the type and encoded bitarray
        bf_type, bf_encoded = entire_message.split('|', 1)  # Split only once
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
    print(bf_type)
    return bf_type, bf  

def return_match_message(result, socket):
    message = add_header(result)
    message_encoded = message.encode('utf-8')
    socket.send(message_encoded)

def check_covid_positive():
    while True:
        user_notify = input("Would you like to notify your close contacts? Enter 'Y' or 'N': \n").strip().upper()
        if user_notify in ['Y', 'N']:
            return user_notify == 'Y'
        print("Invalid input. Please enter 'Y' or 'N'.")