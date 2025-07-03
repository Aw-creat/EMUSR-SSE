import pandas as pd
import numpy as np
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import os

def generate_key(seed: str) -> bytes:
    """从字符串种子生成固定16字节AES密钥"""
    return hashlib.sha256(seed.encode()).digest()[:16]

def aes_encrypt(key: bytes, data: str) -> str:
    data = pad(data.encode(), AES.block_size)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(data)
    return base64.b64encode(encrypted).decode()

def aes_decrypt(key: bytes, enc_data: str) -> str:
    encrypted = base64.b64decode(enc_data.encode())
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted)
    return unpad(decrypted, AES.block_size).decode()

def encrypt_per_row(csv_path: str, output_path: str):
    df = pd.read_csv(csv_path)
    encrypted_records = []

    for i, row in df.iterrows():
        row_str = ','.join(str(x) for x in row)
        seed = f"row_{i}_secret"
        key = generate_key(seed)

        enc = aes_encrypt(key, row_str)
        encrypted_records.append(enc)

        '''if i < 5:
            print(f"Row {i} Seed: {seed}")
            print(f"  Original : {row_str}")
            print(f"  Encrypted: {enc}\n") '''

    pd.DataFrame({"id": range(len(encrypted_records)), "enc_medical": encrypted_records}) \
        .to_csv(output_path, index=False, encoding='utf-8')
    print(f"Encrypted data saved to: {output_path}")

def decrypt_per_row(encrypted_csv_path: str, original_csv_path: str):
    enc_df = pd.read_csv(encrypted_csv_path)
    original_df = pd.read_csv(original_csv_path)
    decrypted_records = []

    for i, enc in enumerate(enc_df['enc_medical']):
        seed = f"row_{i}_secret"
        key = generate_key(seed)

        dec = aes_decrypt(key, enc)
        decrypted_records.append(dec)

        '''if i < 5:
            print(f"Row {i} Seed: {seed}")
            print(f"  Encrypted: {enc}")
            print(f"  Decrypted: {dec}\n")'''

    return decrypted_records


def decrypt_by_index(encrypted_csv_path: str, index_list: list) -> list:
    """
    根据提供的索引列表解密加密CSV文件中的对应数据。

    参数：
        encrypted_csv_path: str，加密数据的CSV路径。
        index_list: list，要解密的记录索引（行号）。

    返回：
        list，解密后的字符串数据列表。
    """
    enc_df = pd.read_csv(encrypted_csv_path)
    decrypted_data = []

    for i in index_list:
        if i >= len(enc_df):
            raise IndexError(f"Index {i} is out of bounds for encrypted data.")
        enc = enc_df.loc[i, 'enc_medical']
        seed = f"row_{i}_secret"
        key = generate_key(seed)
        dec = aes_decrypt(key, enc)
        decrypted_data.append(dec)

    return decrypted_data


if __name__ == '__main__':
    input_csv = "./doc/data/veh-100K/veh_10k.csv"
    output_csv = "./doc/encdata/data_index_per_row.csv"
    encrypt_per_row(input_csv, output_csv)
    # To decrypt and verify:
    decrypted = decrypt_per_row(output_csv, input_csv)