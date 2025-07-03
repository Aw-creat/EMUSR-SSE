#!/usr/bin/env python
# -*- coding:utf-8 -*-
import os
import pandas as pd
import pickle
import sys
import tool
import EDMS
import aesED
from key_deal import SkDeal
from roleKey import RoleKey
from proxyEnc import ProxyEncryptor
import random

def get_file_size(filepath):
    return os.path.getsize(filepath)

def get_object_size(obj):
    return sys.getsizeof(pickle.dumps(obj))

if __name__ == '__main__':
    # Input paths
    path = "./doc/data/storage/kw-3000.csv"
    enc_data_path = 'doc/encdata/data_index_per_row.csv'
    did_path = "./doc/did_users.pkl"

    # Encrypt per row
    aesED.encrypt_per_row(path, enc_data_path)
    encrypted_data_size = get_file_size(enc_data_path)

    # Load dataset and compute vector length
    df = pd.read_csv(path)
    V_len = tool.vect_len(df)
    V_split = 25

    # SkDeal Key generation
    skdeal_obj = SkDeal(V_len, V_split)
    sk_matrix = skdeal_obj.SK
    sk_build = skdeal_obj.sk_tran(sk_matrix)
    sk_trap = skdeal_obj.sk_inv(sk_matrix)

    # AES Key Size (每行一个 key)
    sample_row = df.iloc[0]
    seed = '_'.join(str(i) for i in sample_row.values)
    aes_key = aesED.generate_key(seed)
    aes_key_size_per_row = len(aes_key)
    aes_key_size = aes_key_size_per_row * len(df)  # 所有密钥总大小
    sk_matrix_size = get_object_size(sk_matrix)
    secret_key_total_size = aes_key_size + sk_matrix_size

    # Build Index
    V = tool.get_attrvect(df)
    Enindex = EDMS.BuildIndex(sk_build, V, V_split)
    index_size = get_object_size(Enindex)

    # Role-based key (DID-related)
    sk_did = RoleKey(sk_matrix, did_path)
    random_did = random.choice(sk_did.user_DIDs)
    sk_role_inv = sk_did.get_SK_role_inv_by_DID(random_did)

    # Build Trapdoor T
    search_word = {'race': 'Caucasian', 'gender': 'Female', 'age': '60-100', 'diag_1': 401}
    Vq = tool.get_attrtrapvect(path, search_word)
    Vq = (Vq + 1) % 2
    T = EDMS.Trapdoor(Vq, sk_role_inv, V_split)
    T_size = get_object_size(T)
    print(T_size)

    # Proxy Trapdoor pT
    proxy = ProxyEncryptor(sk_did)
    pT = proxy.proxyTrap(random_did, T)
    pT_size = get_object_size(pT)
    print(pT_size)

    # Total trapdoor size
    trapdoor_total_size = T_size + pT_size

    # Output to CSV
    storage_data = {
        'EncryptedDataSize(Bytes)': [encrypted_data_size],
        'SecretKeySize(Bytes)': [secret_key_total_size],
        'IndexSize(Bytes)': [index_size],
        'TrapdoorSize(Bytes)': [trapdoor_total_size]
    }

    df_out = pd.DataFrame(storage_data)
    output_path = "./doc/data/storage/EUMAR_sto_3000.csv"
    df_out.to_csv(output_path, index=False)
    print(f"[+] Storage overhead saved to {output_path}")
