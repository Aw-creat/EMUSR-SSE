#!/usr/bin/env python
# -*- coding:utf-8 -*-
import os
import json
import hashlib
import pickle
import random
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from roleKey import RoleKey
from VCGen import VCGenerator
from multiuserDID import MultiUserDID

class MerkleTree:
    def __init__(self, leaves: list):
        self.leaves = leaves
        self.levels = []
        self.build_tree()

    def hash_node(self, val):
        return hashlib.sha256(val.encode()).hexdigest()

    def build_tree(self):
        current = [self.hash_node(str(leaf)) for leaf in self.leaves]
        self.levels = [current]

        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else left
                next_level.append(self.hash_node(left + right))
            self.levels.append(next_level)
            current = next_level

    def get_root(self):
        return self.levels[-1][0] if self.levels else None

    def print_tree(self):
        for i, level in enumerate(self.levels):
            print(f"Level {i}: {level}")

class AccessManager:
    def __init__(self, role_key_obj: RoleKey, did_user_path: str, vc_path: str):
        self.role_key = role_key_obj
        self.did_user_path = did_user_path
        self.vc_path = vc_path
        self.DID_leaf_map = {}
        self.leaves = []
        self.tree = None
        self.build_tree()

    def hash_matrix_list(self, matrix_list):
        combined = ''.join([str(m.tolist()) for m in matrix_list])
        return hashlib.sha256(combined.encode()).hexdigest()

    def build_tree(self):
        self.leaves = []
        for did in self.role_key.user_DIDs:
            R_list, S_list = self.role_key.get_R_S_by_DID(did)
            hR = self.hash_matrix_list(R_list)
            hS = self.hash_matrix_list(S_list)
            leaf = f"{hashlib.sha256(did.encode()).hexdigest()}:{hR}:{hS}"
            self.DID_leaf_map[did] = leaf
            self.leaves.append(leaf)

        while not self._is_power_of_two(len(self.leaves)):
            self.leaves.append("EMPTY")

        self.tree = MerkleTree(self.leaves)

    def _is_power_of_two(self, n):
        return (n & (n - 1) == 0) and n != 0

    def add_user(self, new_did, expiration):
        with open(self.did_user_path, "rb") as f:
            data = pickle.load(f)

        sk = ed25519.Ed25519PrivateKey.generate()
        pk = sk.public_key()
        sk_hex = sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ).hex()
        pk_hex = pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()

        data['DIDs'].append(new_did)
        data['private_keys'].append(sk_hex)
        data['public_keys'].append(pk_hex)

        with open(self.did_user_path, "wb") as f:
            pickle.dump(data, f)

        self.role_key.user_DIDs.append(new_did)
        self.role_key.did_to_index[new_did] = len(self.role_key.SK_root) - 1
        self.role_key.get_SK_role_by_DID(new_did)

        R_list, S_list = self.role_key.get_R_S_by_DID(new_did)

        vcgen = VCGenerator(self.role_key, self.did_user_path)
        vc = vcgen.generate_vc(new_did, pk_hex, R_list, S_list, expiration)

        if os.path.exists(self.vc_path):
            with open(self.vc_path, "r") as f:
                vcs = json.load(f)
        else:
            vcs = []

        vcs.append(vc)

        with open(self.vc_path, "w") as f:
            json.dump(vcs, f, indent=2)

        hR = self.hash_matrix_list(R_list)
        hS = self.hash_matrix_list(S_list)
        leaf = f"{hashlib.sha256(new_did.encode()).hexdigest()}:{hR}:{hS}"
        self.DID_leaf_map[new_did] = leaf
        self.leaves.append(leaf)

        while not self._is_power_of_two(len(self.leaves)):
            self.leaves.append("EMPTY")

        self.tree = MerkleTree(self.leaves)
        print(f"[+] Added user {new_did}")

    def revoke_user(self, did):
        with open(self.did_user_path, "rb") as f:
            data = pickle.load(f)

        if did not in data['DIDs']:
            print(f"[!] DID {did} not found.")
            return

        idx = data['DIDs'].index(did)
        for key in ['DIDs', 'private_keys', 'public_keys']:
            data[key].pop(idx)

        with open(self.did_user_path, "wb") as f:
            pickle.dump(data, f)

        self.role_key.user_DIDs.remove(did)
        self.role_key.did_to_index.pop(did, None)
        self.role_key.SK_role_cache.pop(did, None)
        self.role_key.R.pop(did, None)
        self.role_key.S.pop(did, None)

        if os.path.exists(self.vc_path):
            with open(self.vc_path, "r") as f:
                vcs = json.load(f)
            vcs = [vc for vc in vcs if vc['payload']['DID'] != did]
            with open(self.vc_path, "w") as f:
                json.dump(vcs, f, indent=2)

        leaf_to_remove = self.DID_leaf_map.get(did)
        self.leaves = [leaf if leaf != leaf_to_remove else "EMPTY" for leaf in self.leaves]
        self.DID_leaf_map.pop(did, None)
        self.tree = MerkleTree(self.leaves)
        print(f"[-] Revoked user {did}")

    def get_merkle_root(self):
        return self.tree.get_root()

    def print_merkle_tree(self):
        self.tree.print_tree()
