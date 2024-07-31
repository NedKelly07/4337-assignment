
from bitarray import bitarray
import mmh3

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
            hash_digest = mmh3.hash(key, seed)
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

    def __str__(self):
        return self.bits.to01()

    

