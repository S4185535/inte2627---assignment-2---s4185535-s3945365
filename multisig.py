import hashlib 
from keys import gen_keys
from rsa import hash_to_int, sign, verify


#PKG key generation
P_PKG = 1004162036461488639338597000466705179253226703
Q_PKG = 950133741151267522116252385927940618264103623
E_PKG = 973028207197278907211
PKG_E, PKG_N, PKG_D = gen_keys(P_PKG, Q_PKG, E_PKG)

#Procurement officer key generation
P_PO = 1080954735722463992988394149602856332100628417
Q_PO = 1158106283320086444890911863299879973542293243
E_PO = 106506253943651610547613
PO_E, PO_N, PO_D = gen_keys(P_PO, Q_PO, E_PO)

#Inventory ID dictionary
IDENTITIES = {
    "A": 126,
    "B": 127,
    "C": 128,
    "D": 129,
}

#Random number for inventory dictionary
RANDOM = {
    "A": 621,
    "B": 721,
    "C": 821,
    "D": 921,
}

#derive each inventory node's Harn secret key from its identity
SECRET_KEYS = {}
for node_id, identity in IDENTITIES.items():
    SECRET_KEYS[node_id] = pow(identity, PKG_D, PKG_N)

#each signer computes t
T_VALUES = {}
for node_id, r in RANDOM.items():
    T_VALUES[node_id] = pow(r, PKG_E, PKG_N)

#find the product of all t values
def aggregate_t():
    t = 1
    for value in T_VALUES.values():
        t = (t * value) % PKG_N
    return t

#generate hash of both t and message
def harn_hash(t, message):
    combined = f"{t}|{message}"
    return hash_to_int(combined)

#compute each nodes partial sig
def generate_partial_signatures(message):
    t = aggregate_t()
    h = harn_hash(t, message)
    partial_sigs = {}
    for node_id in IDENTITIES:
        g_i = SECRET_KEYS[node_id]
        r_i = RANDOM[node_id]
        s_i = (g_i * pow(r_i, h, PKG_N)) % PKG_N
        partial_sigs[node_id] = s_i
    return {"message": message, "t": t, "h": h, "partial_sigs": partial_sigs}

#product of all sigs
def aggregate_s(partial_sigs):
    s = 1
    for value in partial_sigs.values():
        s = (s * value) % PKG_N
    return s

#verify the multi-sig
def verify_multisig(message, t, s):
    h = harn_hash(t, message)
    left = pow(s, PKG_E, PKG_N)
    identity_product = 1
    for identity in IDENTITIES.values():
        identity_product = (identity_product * identity) % PKG_N
    right = (identity_product * pow(t, h, PKG_N)) % PKG_N
    return {"left": left, "right": right, "valid": left == right, "h": h}

#function to do whole harn process in full
def multisign_message(message):
    partial = generate_partial_signatures(message)
    s = aggregate_s(partial["partial_sigs"])
    verification = verify_multisig(message, partial["t"], s)
    return {"message": message, "t_values": T_VALUES, "t": partial["t"], "h": partial["h"], "partial_sigs": partial["partial_sigs"], "s": s, "verification": verification}

#consensus check to ensure that message is approved
def consensus_check(message, t, s):
    results = {}
    for node_id in IDENTITIES:
        verification = verify_multisig(message, t, s)
        results[node_id] = verification["valid"]
    all_consistent = all(results.values())
    return {"node_results": results, "all_consistent": all_consistent}