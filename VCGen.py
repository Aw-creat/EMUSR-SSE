#!/usr/bin/env python
# -*- coding:utf-8 -*-
import pickle
import hashlib
import json
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class VCGenerator:
    def __init__(self, role_key_obj, did_user_path):
        self.role_key = role_key_obj

        with open(did_user_path, "rb") as f:
            data = pickle.load(f)
            self.DIDs = data['DIDs']
            self.private_keys = [
                ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sk_hex))
                for sk_hex in data['private_keys']
            ]
            self.public_keys = [
                ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex))
                for pk_hex in data['public_keys']
            ]

        # 默认数据拥有者为第一个用户
        self.owner_did = self.DIDs[0]
        self.owner_sk = self.private_keys[0]
        self.owner_pk = self.public_keys[0]

    def hash_matrices(self, matrices):
        concat = ''.join([str(m.tolist()) for m in matrices])
        return hashlib.sha256(concat.encode()).hexdigest()

    def sign(self, message: str) -> str:
        signature = self.owner_sk.sign(message.encode())
        return signature.hex()

    def generate_vc(self, did: str, pubkey_hex: str, R_list, S_list, t_exp: str):
        hR = self.hash_matrices(R_list)
        hS = self.hash_matrices(S_list)

        payload = {
            "DID": did,
            "public_key": pubkey_hex,
            "hash_R": hR,
            "hash_S": hS,
            "expiration": t_exp,
            "issuer": self.owner_did
        }

        signature = self.sign(json.dumps(payload, sort_keys=True))
        return {
            "payload": payload,
            "signature": signature
        }

    def generate_all_vcs(self, vc_expirations: dict, save_path="./doc/vc_all.json"):
        vcs = []

        for idx, did in enumerate(self.DIDs):
            if did not in vc_expirations:
                print(f"[!] Skipping {did}: no expiration specified.")
                continue

            pubkey_bytes = self.public_keys[idx].public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            pubkey_hex = pubkey_bytes.hex()
            R_list, S_list = self.role_key.get_R_S_by_DID(did)

            t_exp = vc_expirations[did]
            vc = self.generate_vc(did, pubkey_hex, R_list, S_list, t_exp)
            vcs.append(vc)

        with open(save_path, "w") as f:
            json.dump(vcs, f, indent=2)

        print(f"[+] {len(vcs)} VCs saved to {save_path}")


# ========== 测试 ==========
if __name__ == "__main__":
    from key_deal import SkDeal
    from multiuserDID import MultiUserDID
    from roleKey import RoleKey
    from datetime import timedelta

    V_len = 570
    V_split = 25
    sk_root = SkDeal(V_len, V_split).SK

    users = MultiUserDID([f"ID_{i:018d}" for i in range(V_split)])
    users.save("./doc/did_users.pkl")

    rk = RoleKey(sk_root, "./doc/did_users.pkl")
    vcgen = VCGenerator(rk, "./doc/did_users.pkl")

    # 设置不同DID的有效期
    now = datetime.utcnow()
    expirations = {
        did: (now + timedelta(days=(30 + i))).isoformat() + "Z"
        for i, did in enumerate(vcgen.DIDs)
    }

    vcgen.generate_all_vcs(vc_expirations=expirations)
