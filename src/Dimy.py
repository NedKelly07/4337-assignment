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
import sys


k = 3
n = 5

address = ('<broadcast>', 8500)
server_address = ('localhost', 55000)

# TCP connection
tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_socket.connect(server_address)
print(f"""connecting to server on {server_address}""")
tcp_lock = threading.Lock()


last_ephid_time = time.time()
shares = []
received_shares = defaultdict(list)
ephid = None
ephid_hash = None
share_index = 0
own_ephid_hashes = deque(maxlen=5)

salt = b'wegwegwe'
exit_program = False

BROADCAST_TIMER = 3
EPHID_TIMER = 15
# DBF_TIMER = 90
# QBF_TIMER = 540
DBF_TIMER = 30
QBF_TIMER = 60

dbf = BloomFilter() # initial dbf
dbf_list = []
dfs_list_lock = threading.Lock()

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
        # print(f"[TASK 3a]: Dropping share: {share.hex()}")
        return
    message = f"{share.hex()}|{ephid_hash}"
    # print(f"[TASK 3a]: Broadcasting share: {share.hex()}")
    sock.sendto(message.encode('utf-8'), address)

# TASK 3: BROADCASTING SHARES AND GENERATING NEW EPHID EVERY 15 SECONDS 
def udp_broadcaster():
    global last_ephid_time, shares, ephid, ephid_hash, share_index, own_ephid_hashes, private_key
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) # UDP socket
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # enable broadcasting
    print("Press 'p' to notify server of COVID-19 positive status\n")
    while not exit_program:
        current_time = time.time()
        if current_time - last_ephid_time >= EPHID_TIMER or not shares:
            private_key, ephid = generate_ephid()
            ephid_hash = hashlib.sha256(ephid).hexdigest()
            own_ephid_hashes.append(ephid_hash)  
            shares = shamir_secret_split(ephid)
            last_ephid_time = current_time
            share_index = 0
            # print(f"[TASK 1]: Generated new EphID with hash: {ephid_hash}\n")
        
            # for index, share in enumerate(shares, 1):
            #     print(f"[TASK 2]: Generated share {index} of {len(shares)}: {bytes(share).hex()}")
            
        if shares and share_index < len(shares):
            share = bytes(shares[share_index])
            broadcast_share(share, ephid_hash, sock)
            share_index += 1
            time.sleep(BROADCAST_TIMER)
    exit(1)

# TASK 4: RECEIVE SHARES AND RECONSTRUCT EPHID
def udp_receiver():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    server.bind(('', 8500))
    while not exit_program:
        data, _ = server.recvfrom(2048)
        try:
            message = data.decode('utf-8')
            share_hex, recv_ephid_hash_hex = message.split('|', 1)
            if recv_ephid_hash_hex in own_ephid_hashes:
                continue
            # print(f"[TASK 3b]: Received share: {share_hex} with EphID hash: {recv_ephid_hash_hex}")
            ephid_key = recv_ephid_hash_hex
            received_shares[ephid_key].append(bytes.fromhex(share_hex))
            
            if len(received_shares[ephid_key]) >= k:
                verify_and_reconstruct_shares(received_shares[ephid_key], recv_ephid_hash_hex)                
                
        except ValueError:
            print("Error: Could not split data")
    
    exit(1)
            
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
            print("[TASK 6] Adding EncID to DBF")
            dbf.add(EncID)
            print(f"DBF # of '1' bits: {dbf.get_num_true()}")
        else:
            print("Failed to verify the reconstructed EphID.")
    except Exception as e:
        print(f"Error reconstructing EphID: {e}")

def tcp_sender():
    global dbf, dbf_list, exit_program
    
    dbf_timer = DBF_TIMER
    qbf_timer = QBF_TIMER 
    start_time = time.time()
    # QBF stops generating when client notify they have covid
    
    while not exit_program:
        curr_time = time.time() - start_time
        # every 90 seconds, create a new DBF
        if curr_time > dbf_timer:
            print("\n[Task 7B] Rotating old DBF to new DBF")
            if len(dbf_list) == 6:
                dbf_list.pop(0) # pop oldest dbf from list
            print("Appending old DBF to dbf_list\n")
            dbf_list.append(deepcopy(dbf)) # need to make independant copy of old dbf
            print("Creating new DBF")
            dbf.reset() # setting all bits to 0 essentially makes a new dbf
            dbf_timer += DBF_TIMER 

        # every 9 minutes, combine all DBFs into one QBF and send to server
        if curr_time > qbf_timer:
            print(len(dbf_list), "forQBF")
            qbf = combine_DBFS(dbf_list)
            if qbf is None:
                continue
            # print(f"[Task 8] Combining all DBFs into one QBF (# of '1' bits: {qbf.get_num_true()})")
            print("[Task 10-a] Uploading QBF to server")
            print(len(qbf.get_bitarray()))
            send_bf(tcp_socket, qbf.get_bitarray(), 'QBF|')
            qbf.reset()
            qbf_timer += QBF_TIMER   
            
def tcp_receiver():
    global tcp_socket, exit_program
    while True:
        server_msg = receive_message(tcp_socket)
        if server_msg == False:
            break
        print(server_msg)
        result = server_msg
        if result == "Uploaded":
            print(f"\n[TASK 10-B]: Server upload response: {result} successfully")
            # exit_program = True
        else:
            print(f"\n[TASK 10-B]: Results from server: {result} match")
            if result == "Positive":
                print("Stay at home for recommended period. Get well soon!")
                # exit_program = True
                
def listen_for_keypress():
    while True:
        if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
            line = sys.stdin.readline().strip()
            if line.lower() == 'p':
                on_p_pressed()
                
def on_p_pressed():
    global exit_program
    if check_covid_positive():
        print(len(dbf_list), "forCBF")
        close_contacts_cbf = combine_DBFS(dbf_list)
        if close_contacts_cbf is None:
            print("[TASK 10] No DBFs available to combine.")
            return  # Exit the function without proceeding
        print(f"[TASK 10] Combining all DBFs into one CBF, sending CBF to server and stopping QBF generation")
        print(len(close_contacts_cbf.get_bitarray()))
        send_bf(tcp_socket, close_contacts_cbf.get_bitarray(), 'CBF|')
        # receive a confirmation that the upload is successful
        exit_program = True
    sys.exit(1)
    
def start():
    threading.Thread(name="UDPBroadcaster", target=udp_broadcaster).start()
    threading.Thread(name="UDPReceiver", target=udp_receiver).start()
    threading.Thread(name="TCPSender", target=tcp_sender).start()
    threading.Thread(name="TCPReceiver", target=tcp_receiver).start()
    keypress_thread = threading.Thread(target=listen_for_keypress, daemon=True)
    keypress_thread.start()

if __name__ == "__main__":
    start()
