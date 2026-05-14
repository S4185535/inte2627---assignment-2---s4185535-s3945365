import hashlib 
from keys import gen_keys
from rsa import hash_to_int, sign, verify


#PKG key generation
P_PKG = 1004162036461488639338597000466705179253226703
Q_PKG = 950133741151267522116252385927940618264103623
E_PKG = 973028207197278907211

PRIV_KEY_PKG = gen_keys(P_PKG, Q_PKG, E_PKG)

#Procurement officer key generation
P_PO = 1080954735722463992988394149602856332100628417
Q_PO = 1158106283320086444890911863299879973542293243
E_PO = 106506253943651610547613

PRIV_KEY_PO = gen_keys(P_PO, Q_PO, E_PO)

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

