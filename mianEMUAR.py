#!/usr/bin/env python
# -*- coding:utf-8 -*- bn
import Update
import proxyEnc
import random
import tool
import pandas as pd
import time
from key_deal import SkDeal  # 引用类，密钥处理
from roleKey import RoleKey
from proxyEnc import ProxyEncryptor
from accessMan import AccessManager
from VCGen import VCGenerator
import EDMS
from datetime import datetime
from datetime import timedelta
from VCVerify import verify_vc
import json
import random
import aesED

if __name__ == '__main__':
    path = "./doc/data/veh-100K/veh_10k.csv"  # Address of EHR data set
    enc_data_path = 'doc/encdata/data_index_per_row.csv'
    start_time = time.perf_counter()
    aesED.encrypt_per_row(path, enc_data_path)  # Encrypt vehicle data
    print("AES encryption: %s seconds " % (time.perf_counter() - start_time))

    df = pd.read_csv(path)
    V_len = tool.vect_len(df)  # Index vector length with attribute hierarchy
    # print("V_len:", V_len)  # 打印V中元素个数 570
    V_split = 25  # the parameter h
    DID_path = "./doc/did_users.pkl"
    VC_path = "./doc/vc_all.json"

    # Key generation : only need to generate once
    SkDeal = SkDeal(V_len, V_split)  # 生成索引加密密钥 可逆矩阵
    Sk_root = SkDeal.SK
    sk_build = SkDeal.sk_tran(SkDeal.SK)  # 矩阵转置
    sk_trap = SkDeal.sk_inv(SkDeal.SK)  # 矩阵的逆

    # DID_ k user Key generation
    Sk_DID = RoleKey(Sk_root, DID_path) # 实例化
    random_did = random.choice(Sk_DID.user_DIDs)
    print(f"[*] Randomly selected DID: {random_did}")
    sk_role = Sk_DID.get_SK_role_by_DID(random_did)
    sk_role_inv = Sk_DID.get_SK_role_inv_by_DID(random_did) # 获取该DID对应的SK_role矩阵逆

    # VC Generation
    Vc = VCGenerator(Sk_DID, DID_path)
    # 设置不同DID的有效期
    now = datetime.utcnow()
    expirations = {
        did: (now + timedelta(days=(30 + i))).isoformat() + "Z"
        for i, did in enumerate(Vc.DIDs)
    }  # 单个设置："did:example:xxx1": (datetime.utcnow() + timedelta(days=30)).isoformat() + "Z"
    start_time = time.perf_counter()
    Vc.generate_all_vcs(vc_expirations=expirations)
    print("VC generation: %s seconds " % (time.perf_counter() - start_time))

    # BuildindexTree: only need to generate and save once
    start_time = time.perf_counter()
    V = tool.get_attrvect(df)  # V储存关键字维度
    # print("V bulid tree:", len(V))  # 打印V中元素个数 10000
    Enindex = EDMS.BuildIndex(sk_build, V, V_split)
    print("Buildindex: %s seconds" % (time.perf_counter() - start_time))

    # SearchIndex User + SGX
    search_word = {'race': 'Caucasian', 'gender': 'Female', 'age': '60-100', 'diag_1': 401}  # Query requirements
    V = tool.get_attrtrapvect(path, search_word)  # V储存关键字转换成编码后的值
    start_time = time.perf_counter()
    V = (V + 1) % 2  # 异或
    T = EDMS.Trapdoor(V, sk_role_inv, V_split)
    print("User Trapdoor: %s seconds" % (time.perf_counter() - start_time))
    # proxy SGX
    start_time = time.perf_counter()
    proxy = ProxyEncryptor(Sk_DID)
    pT = proxy.proxyTrap(random_did, T)
    print("proxy Trapdoor: %s seconds" % (time.perf_counter() - start_time))

    # proof Auth
    with open("./doc/vc_all.json", "r") as f:
        vc_list = json.load(f)
    vc = random.choice(vc_list)
    Do_did = vc["payload"]["issuer"]  # VC中记录的签发者
    Du_did = vc["payload"]["DID"]  # 被签发者
    start_time = time.perf_counter()
    verify_vc(vc, Do_did)  # print(f"[*] 验证 VC - 被签发者: {Du_did}, 签发者: {Do_did}")
    print("VC verify: %s seconds " % (time.perf_counter() - start_time))

    # Search
    start_time = time.perf_counter()
    R = EDMS.Search(Enindex, pT)
    print("Search: %s seconds " % (time.perf_counter() - start_time))
    print(R)
    # Read decrypted file
    start_time = time.perf_counter()
    EDMS.get_file_1(R)
    print("AES decryption: %s seconds " % (time.perf_counter() - start_time))

    # Insert：insert_ Each feature of word must be supplemented completely
    insert_word = {'age': 92, 'diag_1': 401, 'diag_2': 401, 'diag_3': 272, 'rand1': 221,
                   'race': 'Caucasian', 'gender': 'Female', 'admission_type_id': 1, 'discharge_disposition_id': 3,
                   'admission_source_id': 17, 'time_in_hospital': 4, 'num_lab_procedures': 17, 'num_procedures': 0,
                   'num_medications': 6, 'number_outpatient': 2, 'number_emergency': 0, 'number_inpatient': 0,
                   'number_diagnoses': 7, 'max_glu_serum': 0, 'A1Cresult': -1, 'metformin': 'No',
                   'repaglinide': 'No', 'nateglinide': 'No', 'chlorpropamide': 'No', 'glimepiride': 'No',
                   'acetohexamide': 'No', 'glipizide': 'No', 'glyburide': 'No', 'tolbutamide': 'No',
                   'pioglitazone': 'No',
                   'rosiglitazone': 'No', 'acarbose': 'No', 'miglitol': 'No', 'troglitazone': 'No',
                   'tolazamide': 'No', 'examide': 'No', 'citoglipton': 'No', 'insulin': 'No',
                   'glyburide-metformin': 'No', 'glipizide-metformin': 'No', 'glimepiride-pioglitazone': 'No',
                   'metformin-rosiglitazone': 'No', 'metformin-pioglitazone': 'No', 'change': 'No',
                   'diabetesMed': 'No', 'readmitted': -1}  # The inserted data
    val = insert_word.values()
    to_str = ','.join(str(i) for i in val)
    seed = '_'.join(str(i) for i in val)
    key = aesED.generate_key(seed)
    encdata = aesED.aes_encrypt(key, to_str)
    V = tool.get_attrtrapvect(path, insert_word)
    index = Update.updateindex(V, sk_build, V_split)
    V = (V + 1) % 2  # 异或
    trap = EDMS.Trapdoor(V, sk_trap, V_split)
    start_time = time.perf_counter()
    t = EDMS.update_insert(enc_data_path, encdata, Enindex, index, trap, 100240)
    print("Insert: %s seconds " % (time.perf_counter() - start_time))
    R = EDMS.Search(t, trap)
    print(R)

    # Delete
    search_word = {'race': 'Caucasian', 'gender': 'Female', 'age': '60-100', 'diag_1': 401}  # Conditions for
    # deleting EHR
    V = tool.get_attrtrapvect(path, search_word)
    V = (V + 1) % 2  # 异或
    trap = EDMS.Trapdoor(V, sk_trap, V_split)
    start_time = time.perf_counter()
    t = EDMS.update_delete(Enindex, trap, enc_data_path)
    print("Delete: %s seconds " % (time.perf_counter() - start_time))
    R = EDMS.Search(t, trap)
    print(R)

    # RDMST build: management
    RTree = AccessManager(Sk_DID, DID_path, VC_path)
    # print("[*] Merkle Tree Root:", RTree.get_merkle_root())
    # RTree.print_merkle_tree()

    # 新用户DID
    new_did = "did:example:abc12346789"
    # new_did = "did:example:user_" + str(random.randint(10000, 99999))
    expiration = (datetime.utcnow() + timedelta(days=60)).isoformat() + "Z"
    start_time = time.perf_counter()
    RTree.add_user(new_did, expiration)
    print("Add new DID: %s seconds " % (time.perf_counter() - start_time))

    start_time = time.perf_counter()
    RTree.revoke_user(new_did)
    print("Revoke DID: %s seconds " % (time.perf_counter() - start_time))
