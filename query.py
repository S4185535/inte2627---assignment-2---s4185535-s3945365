#Multi-Signature Query Verification and Secure Delivery
#Handles the full query workflow when the procurement officer asks for an item quantity

from keys import NODES
#Use the same ledger files set up in consensus.py
from consensus import LEDGER_TXT_FILES
#Use the harn multi-sig functions from multisig.py
from multisig import multisign_message, verify_multisig, consensus_check
#Procurement officer RSA keys for encrypting the response
from multisig import PO_E, PO_N, PO_D


#Slook up the item in each warehouse's ledger file
def lookup_item(item_id):
    #Loops through every node and checks each line of their ledger
    results = {}
    for node_id in NODES:
        #Open the ledger file for this node
        with open(LEDGER_TXT_FILES[node_id], "r") as f:
            lines = [line.strip() for line in f if line.strip()]
        found = None
        for line in lines:
            parts = line.split("|")
            #If the first part matches the item_id wanted, save it
            if parts[0] == item_id:
                found = {"qty": parts[1], "price": parts[2], "origin": parts[3]}
        results[node_id] = found
    return results


#build the response message the nodes will sign
def build_response(item_id, lookups):
    #Grab the first node that actually found the item
    record = None
    for node_id in lookups:
        if lookups[node_id] is not None:
            record = lookups[node_id]
            break
    #If no node has the item, return a not found message
    if record is None:
        return f"QUERY_RESPONSE|item_id={item_id}|qty=NOT_FOUND"
    return f"QUERY_RESPONSE|item_id={item_id}|qty={record['qty']}"


#encrypt the response using procurement officer's public key
#Only the procurement officer can decrypt because only they know PO_D
def encrypt_for_po(message, t, s):
    #Turn the string message into a number so RSA can work on it
    #ref: https://docs.python.org/3/library/stdtypes.html#int.from_bytes
    msg_int = int.from_bytes(message.encode(), "big")
    #c = m^e mod n
    enc_msg = pow(msg_int, PO_E, PO_N)
    enc_t = pow(t, PO_E, PO_N)
    enc_s = pow(s, PO_E, PO_N)
    return {"enc_msg": enc_msg, "enc_t": enc_t, "enc_s": enc_s}


#procurement officer decrypts the response with their private key
def decrypt_at_po(encrypted):
    #m = c^d mod n
    msg_int = pow(encrypted["enc_msg"], PO_D, PO_N)
    t = pow(encrypted["enc_t"], PO_D, PO_N)
    s = pow(encrypted["enc_s"], PO_D, PO_N)
    #Turn the number back into a string
    byte_len = (msg_int.bit_length() + 7) // 8
    message = msg_int.to_bytes(byte_len, "big").decode()
    return {"message": message, "t": t, "s": s}

#query process - runs every step in order
def process_query(item_id):
    #Look up the item in each node's ledger
    lookups = lookup_item(item_id)
    #If no node has the item, stop here
    if not any(lookups.values()):
        return {"item_id": item_id, "lookups": lookups, "item_found": False}
    #Build the response string
    response = build_response(item_id, lookups)
    #All nodes jointly sign the response using harn multi-sig
    signed = multisign_message(response)
    #Each node verifies the aggregated signature (consensus check)
    consensus = consensus_check(response, signed["t"], signed["s"])
    #Encrypt the signed response for the procurement officer
    encrypted = encrypt_for_po(response, signed["t"], signed["s"])
    #Procurement officer decrypts the package
    decrypted = decrypt_at_po(encrypted)
    #Procurement officer re-verifies the multi-signature on the decrypted message
    final_check = verify_multisig(decrypted["message"], decrypted["t"], decrypted["s"])
    #Check that decrypted message matches the original (extra integrity check)
    recovery_ok = decrypted["message"] == response
    return {
        "item_id": item_id,
        "lookups": lookups,
        "response": response,
        "signed": signed,
        "consensus": consensus,
        "encrypted": encrypted,
        "decrypted": decrypted,
        "final_check": final_check,
        "recovery_ok": recovery_ok,
        "item_found": True,
    }