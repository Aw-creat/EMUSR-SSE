#!/usr/bin/env python
# -*- coding:utf-8 -*-
import json
import hashlib
import pickle
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ed25519

def load_pubkey_by_did(did: str, did_user_path="./doc/did_users.pkl"):
    """根据DID加载签发者的公钥"""
    with open(did_user_path, "rb") as f:
        data = pickle.load(f)
        did_list = data["DIDs"]
        pubkey_hex_list = data["public_keys"]

    if did not in did_list:
        raise ValueError(f"[!] Issuer DID {did} not found in DID registry.")

    idx = did_list.index(did)
    pubkey_hex = pubkey_hex_list[idx]
    return ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))


def verify_vc(vc_obj: dict, issuer_did: str, did_user_path="./doc/did_users.pkl") -> bool:
    """
    验证某个 VC 是否由指定 issuer_did 正确签发，且未过期
    """
    try:
        payload = vc_obj["payload"]  # 从 VC 的 payload 中读取 issuer 字段
        signature_hex = vc_obj["signature"]

        # 1. 检查 VC 是否由该 issuer 签发
        if payload["issuer"] != issuer_did:
            print("[!] VC 不是由指定DID签发")
            return False

        # 2. 检查有效期
        t_exp = payload["expiration"]
        if datetime.utcnow() > datetime.fromisoformat(t_exp.replace("Z", "")):
            print("[!] VC 已过期")
            return False

        # 3. 加载签发者的公钥
        issuer_pubkey = load_pubkey_by_did(issuer_did, did_user_path)

        # 4. 验证签名
        message = json.dumps(payload, sort_keys=True)
        signature = bytes.fromhex(signature_hex)
        issuer_pubkey.verify(signature, message.encode())

        print("[+] VC 验证成功")
        return True

    except Exception as e:
        print(f"[!] VC 验证失败: {e}")
        return False
