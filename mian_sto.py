#!/usr/bin/env python
# -*- coding:utf-8 -*-
import os
import pandas as pd
import pickle
import sys
import tool
import EDMS
import time
import numpy as np
from key_deal import SkDeal

def get_file_size(filepath):
    return os.path.getsize(filepath)  # 单位: 字节

def get_object_size(obj):
    return sys.getsizeof(pickle.dumps(obj))  # 将对象序列化后测大小

if __name__ == '__main__':
    path = "./doc/data/storage/kw-5000.csv"
    key = '1234567890123454'
    enc_file_path = 'doc/encdata/data_index.csv'

    # Encrypt EHR data and measure ciphertext size
    EDMS.enc_file(key, path, enc_file_path)
    encrypted_data_size = get_file_size(enc_file_path)

    # Read plain CSV for attribute processing
    df = pd.read_csv(path)
    V_len = tool.vect_len(df)
    V_split = 25

    # Generate secret keys (SkDeal)
    skdeal_obj = SkDeal(V_len, V_split)
    sk_matrix = skdeal_obj.SK
    sk_build = skdeal_obj.sk_tran(sk_matrix)
    sk_trap = skdeal_obj.sk_inv(sk_matrix)

    # Measure secret key size (AES + Sk matrix)
    aes_key_size = len(key.encode('utf-8'))  # 字节数
    sk_matrix_size = get_object_size(sk_matrix)
    secret_key_total_size = aes_key_size + sk_matrix_size

    # Build index
    V = tool.get_attrvect(df)
    Enindex = EDMS.BuildIndex(sk_build, V, V_split)
    index_size = get_object_size(Enindex)

    # Build trapdoor
    search_word = {'race': 'Caucasian', 'gender': 'Female', 'age': '60-100', 'diag_1': 401}
    Vq = tool.get_attrtrapvect(path, search_word)
    Vq = (Vq + 1) % 2
    trapdoor = EDMS.Trapdoor(Vq, sk_trap, V_split)
    trapdoor_size = get_object_size(trapdoor)

    # Save to CSV
    storage_data = {
        'EncryptedDataSize(Bytes)': [encrypted_data_size],
        'SecretKeySize(Bytes)': [secret_key_total_size],
        'IndexSize(Bytes)': [index_size],
        'TrapdoorSize(Bytes)': [trapdoor_size]
    }

    output_df = pd.DataFrame(storage_data)
    output_path = "./doc/data/storage/EDMS_sto_5000.csv"
    output_df.to_csv(output_path, index=False)
    print(f"Storage overhead saved to {output_path}")
