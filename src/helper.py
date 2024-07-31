import bloomFilter
import struct
import base64
from bitarray import bitarray

debug = True # toggle for verbose data output

HEADER_SIZE = 10
CHUNK_SIZE = 4096
BF_SIZE_BYTES = 100000 # 100kb
HEAD_QBF = 'QBF'
HEAD_CBF = 'CBF'
HEAD_DISCONNECT = "DC"
HEAD_SUCCESS = "OK"
HEAD_FAIL = "FAIL"
HEAD_INFO = "INFO"
HEAD_INFO_VERBOSE = "VERB"

def combine_DBFS(bloom_list):
    # Initialize combined_DBFS with the first Bloom filter
    combined_DBFS = bloom_list.pop(0)
    for bloom_filter in bloom_list:
        combined_DBFS.combine(bloom_filter)
    return combined_DBFS

# error debug
def edebug(msg):
    print('\033[1;31m' + "!!!" + msg + "!!!" + '\033[0m')

# print debug
def pdebug(msg):
    global debug
    if debug == True:
        print('\033[1;90m' + msg + '\033[0m')


def send_bf(socket, header, bf, chunk_size=CHUNK_SIZE):
    data_bytes = bf.get_bitarray().tobytes()
    
    # ensure header is exactly HEADER_SIZE bytes
    header = header.ljust(HEADER_SIZE)

    data_size = len(data_bytes)

    pdebug(f'[send_bf] bf bytes: (#bytes:{data_size})[{data_bytes}]')

    if data_size != BF_SIZE_BYTES:
        edebug(f'[send_bf] data_size of bf not BF_SIZE_BYTES [{data_size} =/= {BF_SIZE_BYTES}]')
    
    # make data size 4 bytes
    data_size_bytes = struct.pack('!I', data_size)
    
    # combine header and data size
    message = header.encode('utf-8') + data_size_bytes
    
    # send header and data size
    pdebug(f'[send_bf] sending header + data size [{message}]')
    socket.sendall(message)
    
    # send data in chunks
    for i in range(0, data_size, chunk_size):
        chunk = data_bytes[i:i+chunk_size]
        encoded_chunk = base64.b64encode(chunk)
        pdebug(f'[send_bf] sending data chunk [{message}]')
        socket.sendall(encoded_chunk)
    
    #send_msg(socket, HEAD_DONE)

def send_msg(socket, header, data="", chunk_size=CHUNK_SIZE):
    data_bytes = data.encode('utf-8')
    
    # ensure header is exactly HEADER_SIZE bytes
    header = header.ljust(HEADER_SIZE)

    data_size = len(data_bytes)

    pdebug(f'[send_msg] msg bytes: (#bytes:{data_size})[{data_bytes}]')
    
    # make data size 4 bytes
    data_size_bytes = struct.pack('!I', data_size)
    
    # combine header and data size
    message = header.encode('utf-8') + data_size_bytes
    
    # send header and data size
    pdebug(f'[send_msg] sending header + data size [{message}]')
    socket.sendall(message)

    if data_size == 0:
        return
    # else
    # send data in chunks
    for i in range(0, data_size, chunk_size):
        chunk = data_bytes[i:i+chunk_size]
        encoded_chunk = base64.b64encode(chunk)
        pdebug(f'[send_msg] sending data chunk [{message}]')
        socket.sendall(encoded_chunk)

    #send_msg(socket, HEAD_DONE)

def receive_msg(socket, chunk_size=CHUNK_SIZE):
    # header and data size
    message = socket.recv(HEADER_SIZE + 4)

    header = message[:HEADER_SIZE].decode('utf-8').strip()
    data_size_bytes = message[HEADER_SIZE:HEADER_SIZE+4]
    data_size = struct.unpack('!I', data_size_bytes)[0]

    pdebug(f'[receive_bf] got header + data size [{header}, {data_size}]')
    
    if data_size == 0:
        return header, 0

    data_bytes = bytearray()
    
    # receive data in chunks
    remaining_size = data_size
    while remaining_size > 0:
        chunk = socket.recv(min(chunk_size, remaining_size))
        decoded_chunk = base64.b64decode(chunk)
        data_bytes.extend(decoded_chunk)
        remaining_size -= len(decoded_chunk)
        pdebug(f'[receive_msg] recieving data chunk [{decoded_chunk}]')
        pdebug(f'[receive_msg] progress: {data_size - remaining_size}/{data_size}')
    
    if len(data_bytes) != data_size:
        edebug(f"[receive_msg] size recieved [{data_bytes}] =/= size expected [{data_size}]")
    if data_size != BF_SIZE_BYTES:
        edebug(f'[receive_msg] data_size of bf not BF_SIZE_BYTES [{data_size} =/= {BF_SIZE_BYTES}]')
    
    # convert bytes back to bitarray
    data_bits = bitarray()
    data_bits.frombytes(data_bytes)
    # done
    return header, data_bits