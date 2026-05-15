#All p, q, e values are hardcoded from the List of Keys document

def gen_keys(p, q, e):
    #Given p, q, e -> return public key (e, n) and private key d
    n = p * q
    phin = (p - 1) * (q - 1)
    d = pow(e, -1, phin)   #modular inverse of e mod phi(n)
    return e, n, d

#Inventory A
P_A = int(1210613765735147311106936311866593978079938707)
Q_A = int(1247842850282035753615951347964437248190231863)
E_A = int(815459040813953176289801)
e_a, n_a, d_a = gen_keys(P_A, Q_A, E_A)

#Inventory B
P_B = int(787435686772982288169641922308628444877260947)
Q_B = int(1325305233886096053310340418467385397239375379)
E_B = int(692450682143089563609787)
e_b, n_b, d_b = gen_keys(P_B, Q_B, E_B)

#Inventory C
P_C = int(1014247300991039444864201518275018240361205111)
Q_C = int(904030450302158058469475048755214591704639633)
E_C = int(1158749422015035388438057)
e_c, n_c, d_c = gen_keys(P_C, Q_C, E_C)

#Inventory D
P_D = int(1287737200891425621338551020762858710281638317)
Q_D = int(1330909125725073469794953234151525201084537607)
E_D = int(33981230465225879849295979)
e_d, n_d, d_d = gen_keys(P_D, Q_D, E_D)

#Dictionary so loop over all 4 nodes easily.
NODES = {"A": {"e": e_a, "n": n_a, "d": d_a}, "B": {"e": e_b, "n": n_b, "d": d_b}, "C": {"e": e_c, "n": n_c, "d": d_c}, "D": {"e": e_d, "n": n_d, "d": d_d},}