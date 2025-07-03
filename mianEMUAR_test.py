# Template for mainEMUAR.py (timing integrated)
import Update
import proxyEnc
import random
import tool
import pandas as pd
import time
from key_deal import SkDeal
from roleKey import RoleKey
from proxyEnc import ProxyEncryptor
from accessMan import AccessManager
from VCGen import VCGenerator
import EDMS
from datetime import datetime, timedelta
from VCVerify import verify_vc
import json
import aesED
import csv
import numpy as np

# Timing tools
timing_info = {}
_temps = {}

def mark_time(label):
    _temps[label] = time.perf_counter()

def log_time(label, merged_to=None):
    elapsed = time.perf_counter() - _temps[label]
    if merged_to:
        timing_info[merged_to] = timing_info.get(merged_to, 0) + elapsed
    else:
        timing_info[label] = elapsed

def export_timings(filename="./doc/data/test/mainEMUAR.csv"):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Stage", "Time"])
        for stage, duration in timing_info.items():
            writer.writerow([stage, round(duration, 6)])

def get_list_shape(lst):
    if isinstance(lst, list):
        if len(lst) == 0:
            return (0,)
        return (len(lst),) + get_list_shape(lst[0])
    else:
        return ()

if __name__ == '__main__':
    path = "./doc/data/keyword(10k)/kw-2000.csv"
    enc_data_path = 'doc/encdata/data_index_per_row.csv'

    # Encrypt = AES + BuildIndex
    mark_time("Encrypt")
    aesED.encrypt_per_row(path, enc_data_path)
    df = pd.read_csv(path)
    V_len = tool.vect_len(df)
    V_split = 25
    SkDeal = SkDeal(V_len, V_split)
    Sk_root = SkDeal.SK
    sk_build = SkDeal.sk_tran(SkDeal.SK)
    sk_trap = SkDeal.sk_inv(SkDeal.SK)
    V = tool.get_attrvect(df)
    Enindex = EDMS.BuildIndex(sk_build, V, V_split)
    log_time("Encrypt")

    # Role-based keys
    DID_path = "./doc/did_users.pkl"
    VC_path = "./doc/vc_all.json"
    Sk_DID = RoleKey(Sk_root, DID_path)
    random_did = random.choice(Sk_DID.user_DIDs)
    sk_role = Sk_DID.get_SK_role_by_DID(random_did)
    sk_role_inv = Sk_DID.get_SK_role_inv_by_DID(random_did)

    # Trapdoor = user + proxy
    search_word = {'race': 'Caucasian', 'gender': 'Female', 'age': '60-100', 'diag_1': 401}
    mark_time("Trapdoor")
    V = tool.get_attrtrapvect(path, search_word)
    V = (V + 1) % 2
    T = EDMS.Trapdoor(V, sk_role_inv, V_split)
    proxy = ProxyEncryptor(Sk_DID)
    pT = proxy.proxyTrap(random_did, T)
    # print("Type of pT:", type(pT))
    # shape = get_list_shape(pT)
    # print("pT shape:", shape)
    log_time("Trapdoor")

    # VC verify (not timed)
    with open(VC_path, "r") as f:
        vc_list = json.load(f)
    vc = random.choice(vc_list)
    Do_did = vc["payload"]["issuer"]
    verify_vc(vc, Do_did)

    # Search
    mark_time("Search")
    R = EDMS.Search(Enindex, pT)
    log_time("Search")

    # Decrypt
    mark_time("Decrypt")
    EDMS.get_file_1(R)
    log_time("Decrypt")

    # Insert
    insert_word = {'age': 92, 'diag_1': 401, 'diag_2': 401, 'diag_3': 272, 'rand1': 221, 'race': 'Caucasian', 'gender': 'Female',
                   'admission_type_id': 1, 'discharge_disposition_id': 3, 'admission_source_id': 17,
                   'time_in_hospital': 4, 'num_lab_procedures': 17, 'num_procedures': 0, 'num_medications': 6,
                   'number_outpatient': 2, 'number_emergency': 0, 'number_inpatient': 0, 'number_diagnoses': 7,
                   'max_glu_serum': 0, 'A1Cresult': -1, 'metformin': 'No', 'repaglinide': 'No', 'nateglinide': 'No',
                   'chlorpropamide': 'No', 'glimepiride': 'No', 'acetohexamide': 'No', 'glipizide': 'No',
                   'glyburide': 'No', 'tolbutamide': 'No', 'pioglitazone': 'No', 'rosiglitazone': 'No',
                   'acarbose': 'No', 'miglitol': 'No', 'troglitazone': 'No', 'tolazamide': 'No', 'examide': 'No',
                   'citoglipton': 'No', 'insulin': 'No', 'glyburide-metformin': 'No', 'glipizide-metformin': 'No',
                   'glimepiride-pioglitazone': 'No', 'metformin-rosiglitazone': 'No',
                   'metformin-pioglitazone': 'No', 'change': 'No', 'diabetesMed': 'No', 'readmitted': -1}
    val = insert_word.values()
    to_str = ','.join(str(i) for i in val)
    seed = '_'.join(str(i) for i in val)
    key = aesED.generate_key(seed)
    encdata = aesED.aes_encrypt(key, to_str)
    V = tool.get_attrtrapvect(path, insert_word)
    index = Update.updateindex(V, sk_build, V_split)
    V = (V + 1) % 2
    trap = EDMS.Trapdoor(V, sk_trap, V_split)
    mark_time("Insert")
    t = EDMS.update_insert(enc_data_path, encdata, Enindex, index, trap, 100240)
    log_time("Insert")

    # Delete
    search_word = {'race': 'Caucasian', 'gender': 'Female', 'age': '60-100', 'diag_1': 401}
    V = tool.get_attrtrapvect(path, search_word)
    V = (V + 1) % 2
    trap = EDMS.Trapdoor(V, sk_trap, V_split)
    mark_time("Delete")
    t = EDMS.update_delete_1(Enindex, trap, enc_data_path)
    log_time("Delete")

    export_timings("./doc/data/test/EMUAR_kw_2000.csv")
