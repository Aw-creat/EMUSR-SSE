#!/usr/bin/env python
# -*- coding:utf-8 -*-
import pickle
import numpy as np

class RoleKey:
    def __init__(self, SK_root, did_path):
        self.SK_root = SK_root
        with open(did_path, "rb") as f:
            did_data = pickle.load(f)

        self.user_DIDs = did_data['DIDs']
        self.did_to_index = {did: idx for idx, did in enumerate(self.user_DIDs)}
        self.SK_role_cache = {}
        self.R = {}
        self.S = {}

    def get_SK_role_by_DID(self, did):
        if did in self.SK_role_cache:
            return self.SK_role_cache[did]

        idx = self.did_to_index.get(did)
        if idx is None:
            raise ValueError(f"[!] DID {did} not found!")

        SK_role = []
        R_list = []
        S_list = []

        for sk in self.SK_root:
            m1, m2, s = sk
            l = m1.shape[0]

            while True:
                r = np.random.randint(0, 2, (l, l))
                if np.linalg.det(r) != 0:
                    break
            while True:
                s_ = np.random.randint(0, 2, (l, l))
                if np.linalg.det(s_) != 0:
                    break

            m1r = m1 @ r
            m2s = m2 @ s_
            SK_role.append([m1r, m2s, s])
            R_list.append(r)
            S_list.append(s_)

        self.SK_role_cache[did] = SK_role
        self.R[did] = R_list
        self.S[did] = S_list
        return SK_role

    def get_R_S_by_DID(self, did):
        """返回给定DID对应的R和S矩阵列表"""
        if did not in self.R or did not in self.S:
            _ = self.get_SK_role_by_DID(did)  # 触发生成
        return self.R[did], self.S[did]

    def get_SK_role_tran_by_DID(self, did):
        SK = self.get_SK_role_by_DID(did)
        SK_T = []
        for sk in SK:
            M_T1 = np.transpose(sk[0])
            M_T2 = np.transpose(sk[1])
            S = sk[2]
            SK_T.append([M_T1, M_T2, S])
        return SK_T

    def get_SK_role_inv_by_DID(self, did):
        SK = self.get_SK_role_by_DID(did)
        SK_I = []
        for sk in SK:
            M_I1 = np.linalg.inv(sk[0])
            M_I2 = np.linalg.inv(sk[1])
            S = sk[2]
            SK_I.append([M_I1, M_I2, S])
        return SK_I

if __name__ == "__main__":
    from key_deal import SkDeal
    from multiuserDID import MultiUserDID

    V_len = 570
    V_split = 25
    sk_root = SkDeal(V_len, V_split).SK

    users = MultiUserDID([f"ID_{i:018d}" for i in range(V_split)])
    users.save("./doc/did_users.pkl")

    rk = RoleKey(sk_root, "./doc/did_users.pkl")
    test_did = rk.user_DIDs[0]

    print("[*] Testing get_SK_role_by_DID...")
    sk = rk.get_SK_role_by_DID(test_did)
    print("\n[*] SK dimensions:")
    for i, item in enumerate(sk):
        print(f"  - SK[{i}] -> M1*r: {item[0].shape}, M2*s_: {item[1].shape}, S: {item[2].shape}")

    print("[*] Testing get_SK_role_tran_by_DID...")
    sk_t = rk.get_SK_role_tran_by_DID(test_did)
    print("\n[*] SK Transpose dimensions:")
    for i, item in enumerate(sk_t):
        print(f"  - SK_T[{i}] -> M1^T: {item[0].shape}, M2^T: {item[1].shape}, S: {item[2].shape}")

    print("[*] Testing get_SK_role_inv_by_DID...")
    sk_i = rk.get_SK_role_inv_by_DID(test_did)
    print("\n[*] SK Inverse dimensions:")
    for i, item in enumerate(sk_i):
        print(f"  - SK_I[{i}] -> M1^-1: {item[0].shape}, M2^-1: {item[1].shape}, S: {item[2].shape}")
