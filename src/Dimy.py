import random
import hashlib
import socket
import threading
import time
from bloomFilter import BloomFilter
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes 
from collections import defaultdict, deque
from subrosa import split_secret, recover_secret, Share
from helper import combine_DBFS


k = 3
n = 5

address = ('<broadcast>', 8500)
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
    while True:
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
            dbf.add(EncID) # decoding to string is better than using str()
            
        else:
            print("Failed to verify the reconstructed EphID.")
    except Exception as e:
        print(f"Error reconstructing EphID: {e}")

# TASK 7: This thread funciton will swpa out DBF every 90 seconds
def dbf_cycle():
    print()

# Task 7: This thread function, combines DBFs into one QBF
def qbf_cycle():
    print
        
def start():
    threading.Thread(name="UDPBroadcaster", target=udp_broadcaster).start()
    threading.Thread(name="UDPReceiver", target=udp_receiver).start()

if __name__ == "__main__":
    start()
