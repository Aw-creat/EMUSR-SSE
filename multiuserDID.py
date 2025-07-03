#!/usr/bin/env python
# -*- coding:utf-8 -*-
import hashlib
import pickle
import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class MultiUserDID:
    def __init__(self, id_list=None):
        self.id_list = id_list if id_list is not None else []  # 支持空初始化
        self.DIDs = []
        self.private_keys = []
        self.public_keys = []

        if self.id_list:
            self.generate_DIDs()

    def generate_DIDs(self):
        for id_num in self.id_list:
            # 生成DID
            did = "did:example:" + hashlib.sha256(id_num.encode()).hexdigest()
            self.DIDs.append(did)

            # 生成密钥对
            sk = ed25519.Ed25519PrivateKey.generate()
            pk = sk.public_key()

            # 保存私钥和公钥
            self.private_keys.append(sk)
            self.public_keys.append(pk)

    def save(self, path="./doc/did_users.pkl"):
        """保存所有DID信息到文件"""
        os.makedirs(os.path.dirname(path), exist_ok=True)  # 自动创建目录
        data = {
            'DIDs': self.DIDs,
            'private_keys': [sk.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ).hex() for sk in self.private_keys],
            'public_keys': [pk.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex() for pk in self.public_keys]
        }
        with open(path, "wb") as f:
            pickle.dump(data, f)

    def load(self, path="./doc/did_users.pkl"):
        """从文件中加载DID信息"""
        with open(path, "rb") as f:
            data = pickle.load(f)
        self.DIDs = data['DIDs']
        self.private_keys = [ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sk_hex)) for sk_hex in data['private_keys']]
        self.public_keys = [ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex)) for pk_hex in data['public_keys']]

if __name__ == "__main__":
    # 只有当直接运行multiuserDID.py才执行
    print("[*] Running test inside multiuserDID.py...")

    user_num = 1
    id_list = [f"ID_{i:18d}" for i in range(user_num)]  # 生成22个假身份证号

    users = MultiUserDID(id_list)
    users.save()
    print(f"Generated and saved {len(users.DIDs)} DIDs to ./doc/did_users.pkl")

    # 测试读取
    print("[*] Loading saved DIDs...")
    new_users = MultiUserDID()
    new_users.load("./doc/did_users.pkl")
    print(f"Loaded {len(new_users.DIDs)} DIDs successfully.")
