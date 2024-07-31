import bloomFilter

def combine_DBFS(bloom_list):
    # Initialize combined_DBFS with the first Bloom filter
    combined_DBFS = bloom_list.pop(0)
    for bloom_filter in bloom_list:
        combined_DBFS.combine(bloom_filter)
    return combined_DBFS