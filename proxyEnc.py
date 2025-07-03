#!/usr/bin/env python
# -*- coding:utf-8 -*-
import pickle
import numpy as np
from roleKey import RoleKey

class ProxyEncryptor:
    def __init__(self, role_key_obj):
        self.role_key = role_key_obj  # 传入已初始化的 RoleKey 对象

    def proxyTrap(self, did, T):
        """
        给定 DID 和 Trapdoor，输出 Proxy Trapdoor
        :param did: 用户DID
        :param T: 普通Trapdoor（list of [T_P, T_DP]）
        :return: preT = list of (R_i @ T_P, S_i @ T_DP)
        """
        R_list, S_list = self.role_key.get_R_S_by_DID(did)

        preT = []
        for i in range(len(T)):
            T_P, T_DP = T[i]
            R = R_list[i]
            S_ = S_list[i]

            pre_TP = R @ T_P
            pre_TDP = S_ @ T_DP
            t = np.array([pre_TP, pre_TDP])
            preT.append(t)

        return preT

# 测试入口（可选）
if __name__ == "__main__":
    from key_deal import SkDeal
    from multiuserDID import MultiUserDID
    import tool, EDMS

    V_len = 570
    V_split = 25
    sk_root = SkDeal(V_len, V_split).SK
    users = MultiUserDID([f"ID_{i:06d}" for i in range(V_split)])
    users.save("./doc/did_users.pkl")

    rk = RoleKey(sk_root, "./doc/did_users.pkl")
    proxy = ProxyEncryptor(rk)

    did = rk.user_DIDs[0]
    sk_inv = rk.get_SK_role_inv_by_DID(did)

    V = np.random.randint(0, 2, V_len)
    T = EDMS.Trapdoor(V, sk_inv, V_split)

    preT = proxy.proxyTrap(did, T)

    print(f"[*] Proxy Trapdoor for {did}:")
    for i, (p1, p2) in enumerate(preT[:2]):
        print(f"  - preT[{i}]: T_P: {p1.shape}, T_DP: {p2.shape}")
