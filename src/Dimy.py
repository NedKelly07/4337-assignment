import random
import hashlib
import socket
import threading
import time
from bloomFilter import BloomFilter
from collections import defaultdict, deque
from copy import deepcopy
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes 
from subrosa import split_secret, recover_secret, Share
from helper import *


k = 3
n = 5

address = ('<broadcast>', 8500)
server_address = ('localhost', 55000)

# TCP connection
tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_socket.connect(server_address)
print(f"""connecting to server on {server_address}""")
tcp_lock = threading.Lock()

stop_event = threading.Event()

last_ephid_time = time.time()
shares = []
received_shares = defaultdict(list)
ephid = None
ephid_hash = None
share_index = 0
own_ephid_hashes = deque(maxlen=5)

salt = b'wegwegwe'

BROADCAST_TIMER = 3
EPHID_TIMER = 15
DBF_TIMER = 90
QBF_TIMER = 540

dbf = BloomFilter() # initial dbf
dbf_list = []

# TASK 1 
def generate_ephid():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    ephid = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return private_key, ephid

# TASK 2
def shamir_secret_split(secret):
    shares = split_secret(secret, k, n)
    return shares

# TASK 3: broadcast share with a probability of 0.5
def broadcast_share(share, ephid_hash, sock):
    if random.random() < 0.5:
        print(f"[TASK 3a]: Dropping share: {share.hex()}")
        return
    message = f"{share.hex()}|{ephid_hash}"
    print(f"[TASK 3a]: Broadcasting share: {share.hex()}")
    sock.sendto(message.encode('utf-8'), address)

# TASK 3: BROADCASTING SHARES AND GENERATING NEW EPHID EVERY 15 SECONDS 
def udp_broadcaster():
    global last_ephid_time, shares, ephid, ephid_hash, share_index, own_ephid_hashes, private_key
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) # UDP socket
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) #enable broadcasting
    while not stop_event.is_set():
        current_time = time.time()
        if current_time - last_ephid_time >= EPHID_TIMER or not shares:
            private_key, ephid = generate_ephid()
            ephid_hash = hashlib.sha256(ephid).hexdigest()
            own_ephid_hashes.append(ephid_hash)  
            shares = shamir_secret_split(ephid)
            last_ephid_time = current_time
            share_index = 0
            print(f"[TASK 1]: Generated new EphID with hash: {ephid_hash}\n")
        
            for index, share in enumerate(shares, 1):
                print(f"[TASK 2]: Generated share {index} of {len(shares)}: {bytes(share).hex()}")
            
        if shares and share_index < len(shares):
            share = bytes(shares[share_index])
            broadcast_share(share, ephid_hash, sock)
            share_index += 1
            time.sleep(BROADCAST_TIMER)

# TASK 4: RECEIVE SHARES AND RECONSTRUCT EPHID
def udp_receiver():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    server.bind(('', 8500))
    while not stop_event.is_set():
        data, _ = server.recvfrom(2048)
        try:
            message = data.decode('utf-8')
            share_hex, recv_ephid_hash_hex = message.split('|', 1)
            if recv_ephid_hash_hex in own_ephid_hashes:
                continue
            print(f"[TASK 3b]: Received share: {share_hex} with EphID hash: {recv_ephid_hash_hex}")
            ephid_key = recv_ephid_hash_hex
            received_shares[ephid_key].append(bytes.fromhex(share_hex))
            
            # TODO: print received shares + num of received shares for each EphID

            if len(received_shares[ephid_key]) >= k:
                verify_and_reconstruct_shares(received_shares[ephid_key], recv_ephid_hash_hex)                
                
        except ValueError:
            print("Error: Could not split data")
            
# TASK 4/5/6: RECONSTRUCT EPHID, DERIVE ENCOUNTER ID AND ADD ENCOUNTER ID TO DBF
def verify_and_reconstruct_shares(shares, original_ephid_hash):
    try:
        shares_list = [Share.from_bytes(share) for share in shares]
        recv_ephid = recover_secret(shares_list[:k])
        reconstructed_hash = hashlib.sha256(recv_ephid).hexdigest()
        if reconstructed_hash == original_ephid_hash:
            print("[TASK 4]: \nSuccessfully reconstructed EphID:", reconstructed_hash, "original", original_ephid_hash)
            
            recv_public_key = x25519.X25519PublicKey.from_public_bytes(recv_ephid)
            shared_secret = private_key.exchange(recv_public_key)
            EncID = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=b'EncID'
            ).derive(shared_secret)
            print("[TASK 5]: Derived Encounter ID (EncID):", EncID.hex())
            del received_shares[original_ephid_hash]
            print("\n[TASK 6] Adding EncID to DBF")
            dbf.add(EncID) 
            print(f"DBF # of '1' bits: {dbf.get_num_true()}")
            
        else:
            print("Failed to verify the reconstructed EphID.")
    except Exception as e:
        print(f"Error reconstructing EphID: {e}")

# TASK 7: This thread funciton will swap out DBF every 90 seconds
def dbf_cycle():
    global dbf, dbf_list
    # start timer for next timer cycle immediately in order for
    # cycle time to remain as 90 seconds and not affected by function overhead
    next_timer = threading.Timer(DBF_TIMER, dbf_cycle)
    next_timer.daemon = True # set to true to ensurte timers end when program ends
    next_timer.start()

    print("\n[Task 7B] Rotating old DBF to new DBF")
    if len(dbf_list) == 6:
        dbf_list.pop(0) # pop oldest dbf from list
    print("Appending old DBF to dbf_list\n")
    dbf_list.append(deepcopy(dbf)) # need to make independant copy of old dbf
    print("Creating new DBF")
    dbf.reset() # setting all bits to 0 essentially makes a new dbf

    if stop_event.is_set():
        next_timer.cancel()
        exit()

# Task 7/8: This thread function combines DBFs into one QBF every 9 minutes and sends to server
def qbf_cycle(socket, tcp_lock):
    global dbf_list
    # start timer for next timer cycle immediately in order for
    # cycle time to remain as 540 seconds and not affected by function overhead
    next_timer = threading.Timer(QBF_TIMER, qbf_cycle)
    next_timer.daemon = True # set to true to ensurte timers end when program ends
    next_timer.start()

    qbf = combine_DBFS(dbf_list)
    print(f"[Task 8] Combining all DBFs into one QBF (# of '1' bits: {qbf.get_num_true()})")
    print("[Task 10-a] Uploading QBF to server")
    with tcp_lock:
        response = send_qbf(socket, qbf)
    if response == True:
        print("\033[33;1m"+ f'Our system HAS found that you have been in close contact with someone who has been diagnosed positive with COVID-19\nPLEASE SEAK THE APPROPIATE ATTENTION AND CARE' + "\033[0m")
    if response == False:
        print('Our system has NOT found that you have been in close contact with someone who has been diagnosed positive with COVID-19')
    else:
        edebug(f'[qbf_cycle] failed to send QBF to server')

    if stop_event.is_set():
        next_timer.cancel()
        exit()

    

# Task 9: Wait for a user nput to indictate node has COVID-19, once indicated,
# combine all DBFs into a CBF and upload to server, once uploaded stop sending QBFs
# thread for general user input, inclues indictating node has COVID-19, as per task 9
def wait_for_input(socket, tcp_lock):
    global dbf_list
    # create qbf cycle timer in here so that once positive can cancel timer and stop sending QBFs
    qbf_cycle_timer = threading.Timer(QBF_TIMER, qbf_cycle, args=(socket, tcp_lock))
    qbf_cycle_timer.daemon = True
    qbf_cycle_timer.start()

    while True:
        user_input = input(f"""
                        >Enter 'p' to test positive to COVID-19\n
                        >Enter 'info' to request the server to display info\n
                        >Enter 'verbose' to request the server to display info including all CBF's\n
                        >Enter 'dc' to dissconnect from the server
                        """)
        if user_input.lower() == 'p':
            user_input = input("[Task 9] Tested positive for COVID-19, do you want to send your CBF?\nEnter Y or 'y' for yes or any other letter otherwise:")
            if user_input.lower == 'Y':
                qbf_cycle_timer.cancel()
                cbf = combine_DBFS(dbf_list)
                print(f"Combining all DBFs into one CBF (# of '1' bits: {cbf.get_num_true()})")
                print("Uploading CBF to server and no more sending QBFs...")
                with tcp_lock:
                    send_cbf(socket, cbf)
                break

        if user_input.lower() == 'info':
            print('requesting the server to display info on its terminal...')
            with tcp_lock:
                send_msg(socket, HEAD_INFO)
            print('...done')
        
        if user_input.lower() == 'verbose':
            print("requesting the server to display info including all CBF's on its terminal...")
            with tcp_lock:
                send_msg(socket, HEAD_INFO)
            print('...done')

        if user_input.lower() == 'dc':
            print("requesting server close connection...")
            with tcp_lock:
                send_msg(socket, HEAD_INFO)
                header, data = receive_msg(socket)
            if header == HEAD_SUCCESS:
                print('...done, exiting')
                qbf_cycle_timer.cancel()
                stop_event.set()
                socket.close()
                exit()
            else:
                edebug('server could not close connection')

# thread function to receive all server messages, interpret and display 
# def server_receiver():
#     print()

# ^^^if this needs to be done later, use socket.setblocking(False) at the end of the while loop in wait_for_input
# temporaraly to catch anything in the socket buffer, and do something with that...
        
def start():
    threading.Thread(name="UDPBroadcaster", target=udp_broadcaster).start()
    threading.Thread(name="UDPReceiver", target=udp_receiver).start()
    dbf_cycle_timer = threading.Timer(DBF_TIMER, dbf_cycle)
    input_thread  = threading.Thread(name="waitForInput", target=wait_for_input, args=(socket, tcp_lock))

    dbf_cycle_timer.daemon = True
    input_thread.daemon = True
    dbf_cycle_timer.start()
    time.sleep(0.05) # just want to ensure dbf_cycle_timer starts before qbf_cycle_timer (which is in input_thread)
    input_thread.start()

if __name__ == "__main__":
    start()
