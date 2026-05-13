import math 
from keys import NODES
from rsa import verify, hash_to_int

LEDGER_TXT_FILES = {
    "A": "data/inventory_a.txt",
    "B": "data/inventory_b.txt",
    "C": "data/inventory_c.txt",
    "D": "data/inventory_d.txt",
}

#helper functions

def _load_ledger(node_id:str) -> list:
    with open(LEDGER_TXT_FILES[node_id], "r") as f:
        return [line.strip() for line in f if line.strip()]

def _append_record_(node_id:str, record:str) -> None:
    with open(LEDGER_TXT_FILES[node_id], "a") as f:
        f.write(record + "\n")

#BFT Consensus Algorithm Implementation
def bft_consesnsus(record: str ,proposer: str, signature: int ) -> dict:
    num_nodes = len(NODES)
    supermajority = math.ceil((num_nodes * 2) / 3)

    #step 1 - leader creates a record and signs it
    leader = {
        "step": "LEADER ELECTION",
        "leader": proposer,
        "record": record,
        "signature": signature,
        }

    #step 2 - proposal
    proposal = {
        "step": "PROPOSAL",
        "from": proposer,
        "to": list(NODES.keys()),
        "record": record,
    }

    #step 3 - voting
    votes = {}
    leader_pub_key = NODES[proposer]

    for node_id in NODES:
        h = hash_to_int(record)
        valid = verify(h, signature, leader_pub_key["n"], leader_pub_key["e"])
        vote = "ACCEPT" if valid else "REJECT"
        votes[node_id] = {h, vote}
        # { 
        #     "hash" = h,
        #     "vote" = vote,
        # }

    accept_count = sum(1 for v in votes.values() if v["vote"] == "ACCEPT")
    print(accept_count)

    #step 4 - Finaility 
        #I the supermajority 2/3 is met then the record can become final.
        #Every node appends the record to their local ledger.
    consensus_reached = accept_count >= supermajority
    committed_nodes = []

    if consensus_reached:
        for node_id in NODES:
            _append_record_(node_id, record)
            committed_nodes.append(node_id)
    
    return{
        "leader": leader,
        "proposal": proposal,
        "votes": votes,
        "accept_count": accept_count,
        "num_nodes": num_nodes,
        "supermajority": supermajority,
        "consensus_reached": consensus_reached,
        "commited_nodes": committed_nodes,
    }

def get_all_ledgers() -> dict:
    return {node_id: _load_ledger(node_id) for node_id in NODES}