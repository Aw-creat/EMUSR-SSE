#!/usr/bin/env python
# -*- coding:utf-8 -*-
import Update
import tool
import pandas as pd
import time
from key_deal import SkDeal  # 引用类，密钥处理
from roleKey import RoleKey
import EDMS

if __name__ == '__main__':
    path = "./doc/data/veh-100K/veh_10k.csv"  # Address of EHR data set
    key = '1234567890123454'  # Encrypt the secret key of EHR
    enc_file_path = 'doc/encdata/data_index.csv'
    start_time = time.perf_counter()
    EDMS.enc_file(key, path, enc_file_path)  # Encrypt EHR
    print("AES encryption: %s seconds " % (time.perf_counter() - start_time))
    df = pd.read_csv(path)
    V_len = tool.vect_len(df)  # Index vector length with attribute hierarchy
    print("V_len:", V_len)  # 打印V中元素个数
    V_split = 25  # the parameter h

    # Key generation : only need to generate once
    SkDeal = SkDeal(V_len, V_split)  # 生成索引加密密钥 可逆矩阵
    sk_build = SkDeal.sk_tran(SkDeal.SK)  # 矩阵转置
    sk_trap = SkDeal.sk_inv(SkDeal.SK)  # 矩阵的逆

    # BuildindexTree: only need to generate and save once
    start_time = time.perf_counter()
    V = tool.get_attrvect(df)  # V储存关键字维度
    # print("V bulid tree:", len(V))  # 打印V中元素个数
    Enindex = EDMS.BuildIndex(sk_build, V, V_split)
    print("Buildindex: %s seconds" % (time.perf_counter() - start_time))

    # SearchIndex
    search_word = {'race': 'Caucasian', 'gender': 'Female', 'age': '60-100', 'diag_1': 401}  # Query requirements
    V = tool.get_attrtrapvect(path, search_word)  # V储存关键字转换成编码后的值
    print("V query:", len(V))  # 打印V中元素个数
    start_time = time.perf_counter()
    V = (V + 1) % 2  # 异或
    T = EDMS.Trapdoor(V, sk_trap, V_split)
    print("Trapdoor: %s seconds" % (time.perf_counter() - start_time))

    # Search
    start_time = time.perf_counter()
    R = EDMS.Search(Enindex, T)
    print("Search: %s seconds " % (time.perf_counter() - start_time))
    print(R)
    # Read decrypted file
    start_time = time.perf_counter()
    EDMS.get_file(R, key)
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
                   'diabetesMed': 'No', 'readmitted': -1}  # The inserted EHR
    val = insert_word.values()
    to_str = ','.join(str(i) for i in val)
    encdata = tool.aesEncrypt(key, to_str)
    V = tool.get_attrtrapvect(path, insert_word)
    index = Update.updateindex(V, sk_build, V_split)
    V = (V + 1) % 2  # 异或
    trap = EDMS.Trapdoor(V, sk_trap, V_split)
    start_time = time.perf_counter()
    t = EDMS.update_insert(enc_file_path, encdata, Enindex, index, trap, 100240)
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
    t = EDMS.update_delete(Enindex, trap, enc_file_path)
    print("Delete: %s seconds " % (time.perf_counter() - start_time))
    R = EDMS.Search(t, trap)
    print(R)
