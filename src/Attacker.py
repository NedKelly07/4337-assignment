### Code Implemented by:
# Ben Crabtree - z5257714
# Justina Nguyen-  z5419348
# Nick Talbot - z5316975
###
import random
import hashlib
import socket
import threading
import time
import sys
import select
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

num_threads = 50
flood_interval = 0.1

# TCP connection
tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_socket.connect(server_address)
print(f"""connecting to server on {server_address}""")

last_ephid_time = time.time()
shares = []
received_shares = defaultdict(lambda: {'shares': [], 'start_time': None})
ephid = None
ephid_hash = None
share_index = 0
own_ephid_hashes = deque(maxlen=5)

salt = b'abcdefhijklmnop'
exit_program = False

BROADCAST_TIMER = 3
EPHID_TIMER = 15
# DBF_TIMER = 90
# QBF_TIMER = 540
DBF_TIMER = 40
QBF_TIMER = 60

dbf = BloomFilter()
dbf_list = []

# TASK 1: generate EphID using x25519
def generate_ephid():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    ephid = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return private_key, ephid

# TASK 2: split EphID into n shares
def shamir_secret_split(secret):
    shares = split_secret(secret, k, n)
    return shares

# TASK 3: broadcast share with a probability of 0.5
def broadcast_share(share, ephid_hash, sock):
    if random.random() < 0.5:
        print(f"[TASK 3a]: Dropping share: {share.hex()}\n")
        return
    message = f"{share.hex()}|{ephid_hash}"
    print(f"[TASK 3a]: Broadcasting share: {share.hex()}\n")
    sock.sendto(message.encode('utf-8'), address)

# TASK 3: BROADCASTING SHARES AND GENERATING NEW EPHID EVERY 15 SECONDS 
def udp_broadcaster():
    global last_ephid_time, shares, ephid, ephid_hash, share_index, own_ephid_hashes, private_key
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    print("Press 'p' to notify server of COVID-19 positive status\n")
    while True:
        current_time = time.time()
        if current_time - last_ephid_time >= EPHID_TIMER or not shares:
            private_key, ephid = generate_ephid()
            ephid_hash = hashlib.sha256(ephid).hexdigest()
            own_ephid_hashes.append(ephid_hash)  
            shares = shamir_secret_split(ephid)
            last_ephid_time = current_time
            share_index = 0
            print(f"[TASK 1]: Generated new EphID with hash: {ephid_hash}\n")
        
            print('[TASK 2]')
            for index, share in enumerate(shares, 1):
                print(f"Generated share {index} of {len(shares)}: {bytes(share).hex()}")
            print('\n')
            
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
    while True:
        data, _ = server.recvfrom(2048)
        try:
            message = data.decode('utf-8')
            share_hex, recv_ephid_hash_hex = message.split('|', 1)
            if recv_ephid_hash_hex in own_ephid_hashes:
                continue
            print(f"[TASK 3b]: Received share: {share_hex} \nwith EphID hash: {recv_ephid_hash_hex}\n")
            ephid_key = recv_ephid_hash_hex
            
            if received_shares[ephid_key]['start_time'] is None:
                received_shares[ephid_key]['start_time'] = time.time()
            
            received_shares[ephid_key]['shares'].append(bytes.fromhex(share_hex))
            
            for ephid_key, data in list(received_shares.items()):
                shares = data['shares']
                start_time = data['start_time']
                time_elapsed = time.time() - start_time

                if time_elapsed >= 15:  # Check if 15 seconds have passed
                    print(f"Removing EphID {ephid_key}. Less than {k} shares received.")
                    del received_shares[ephid_key]
                else:
                    if len(shares) >= k:
                        print(f"EphID {ephid_key} has {len(shares)} shares. Reconstructing EphID.")
                        verify_and_reconstruct_shares(shares, ephid_key)
                    else: 
                        print(f"EphID {ephid_key} has {len(shares)} shares.")                          
        except ValueError:
            print("Error: Could not split data")
                
# TASK 4/5/6: RECONSTRUCT EPHID, DERIVE ENCOUNTER ID AND ADD ENCOUNTER ID TO DBF
def verify_and_reconstruct_shares(shares, original_ephid_hash):
    try:
        shares_list = [Share.from_bytes(share) for share in shares]
        recv_ephid = recover_secret(shares_list[:k])
        reconstructed_hash = hashlib.sha256(recv_ephid).hexdigest()
        if reconstructed_hash == original_ephid_hash:
            print("[TASK 4]: Successfully reconstructed EphID:\n", reconstructed_hash, "\nOriginal hash:\n", original_ephid_hash, "\n")
            
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
            print("[TASK 6] Adding EncID to DBF")
            dbf.add(EncID)
            print(f"DBF # of '1' bits: {dbf.get_num_true()}")
        else:
            print("Failed to verify the reconstructed EphID.")
    except Exception as e:
        print(f"Error reconstructing EphID: {e}")

def update_dbf():
    global dbf, dbf_list
    
    dbf_timer = DBF_TIMER
    start_time = time.time()
    
    while True:
        curr_time = time.time() - start_time
        # every 90 seconds, create a new DBF
        if curr_time > dbf_timer:
            print("\n[Task 7B] Rotating old DBF to new DBF")
            if len(dbf_list) == 6:
                dbf_list.pop(0) # pop oldest dbf from list
            print("Appending old DBF to dbf_list")
            dbf_list.append(deepcopy(dbf)) # need to make independant copy of old dbf
            print("Creating new DBF\n")
            dbf.reset() # setting all bits to 0 essentially makes a new dbf
            dbf_timer += DBF_TIMER 
        time.sleep(1)
        

def send_qbf():
    global dbf_list
    
    qbf_timer = QBF_TIMER
    start_time = time.time()
    
    while not exit_program:
        curr_time = time.time() - start_time
        # every 9 minutes, combine all DBFs into one QBF and send to server
        if curr_time > qbf_timer:
            print(f"\nNumber of DBFs in DBF list: {len(dbf_list)}")
            qbf = combine_DBFS(dbf_list)
            if qbf is None:
                continue
            print(f"[Task 8] Combining all DBFs into one QBF (# of '1' bits in QBF: {qbf.get_num_true()})")
            print("[Task 10-a] Uploading QBF to server")
            send_bf(tcp_socket, qbf.get_bitarray(), 'QBF|')
            qbf.reset()
            qbf_timer += QBF_TIMER
        time.sleep(1) 
            
def tcp_receiver():
    global tcp_socket
    while not exit_program:
        server_msg = receive_message(tcp_socket)
        if server_msg == False:
            break
        result = server_msg
        if result == "Uploaded":
            print(f"\n[TASK 10-B]: Server upload response: {result} successfully\n")
        else:
            print(f"\n[TASK 10-B]: Results from server: {result} match")
            if result == "Positive":
                print("Stay at home for recommended period. Get well soon!\n")
                
def listen_for_keypress():
    while True:
        if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
            line = sys.stdin.readline().strip()
            if line.lower() == 'p':
                on_p_pressed()
                
def on_p_pressed():
    global exit_program
    if check_covid_positive():
        print(f"Number of DBFs in DBF list: {len(dbf_list)}")
        close_contacts_cbf = combine_DBFS(dbf_list)
        if close_contacts_cbf is None:
            print("[TASK 10] No DBFs available to combine.")
            return  # Exit the function without proceeding
        print(f"\n[TASK 10] Combining all DBFs into one CBF (# of '1' bits in CBF: {close_contacts_cbf.get_num_true()}), sending CBF to server and stopping QBF generation\n")
        send_bf(tcp_socket, close_contacts_cbf.get_bitarray(), 'CBF|')
        exit_program = True
        
def start_flooding():
    threads = []
    for i in range(num_threads):
        t = threading.Thread(name=f"ClientUDPBroadcaster-{i}", target=udp_broadcaster, daemon=True)
        threads.append(t)

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()
    
def start():
    threading.Thread(name="UDPBroadcaster", target=udp_broadcaster).start()
    threading.Thread(name="UDPReceiver", target=udp_receiver).start()
    threading.Thread(name="UpdateDBF", target=update_dbf).start()
    threading.Thread(name="SendQBF", target=send_qbf).start()
    threading.Thread(name="TCPReceiver", target=tcp_receiver).start()
    keypress_thread = threading.Thread(target=listen_for_keypress, daemon=True)
    keypress_thread.start()

if __name__ == "__main__":
    start()
    start_flooding()


