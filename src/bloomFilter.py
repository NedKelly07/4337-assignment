
from bitarray import bitarray
import mmh3


# Class for most bloom filter related operations
# This code was influenced and referenced from the GeeksforGeeks simple implementation
# https://www.geeksforgeeks.org/bloom-filters-introduction-and-python-implementation/
# code was change and/or added into to suit assignment implementation
class BloomFilter(object):

    def __init__(self, bit_array=None):
        self.size = 819200 # 100kB = 100 x 1024 x 8 bits
        self.hash_num = 3 # number of hashes used in added each key

        # set up bitmap
        if bit_array is not None:
            self.bits = bit_array
        else:
            self.bits = bitarray(self.size)
            self.bits.setall(0)

    def add(self, key): # key is expected to be of type String
        hash_digests = []
        # Generate three different hash digests for key and add each to bitmap
        for seed in range(self.hash_num):
            hash_digest = mmh3.hash(key, seed) % self.size
            # print(f"Hash [{seed}]: {hash_digest}") debug message
            hash_digests.append(hash_digest)

            self.bits[hash_digest] = True

    def reset(self):
        self.bits.setall(0)

    def combine(self, other):
        self.bits |= other.bits

    # two bloom filters 'match' if the AND bitwise operation has a value with 3 or more bits set to 1
    def match(self, other): 
        and_result = self.bits & other.bits
        return and_result.count(1) >= 3
    
    def get_num_true(self):
        return self.bits.count(1)
    
    def get_pos_true(self):
        pos_list = []
        for i in range(self.size):
            if self.bits[i] == True:
                pos_list.append(i)
        return pos_list

    def __str__(self):
        return self.bits.to01()
    
    def get_bitarray(self):
        return self.bits