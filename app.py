#Run this .py to launch the website
#Inbulit flask to run website
from flask import Flask, request
#keys.py generate public and private keys for each warehouse
from keys import NODES
#rsa.py takes input and computes all calculations
from rsa import sign, verify, hash_to_int
#consensus.py handles consensus process for new records
from consensus import bft_consensus, get_all_ledgers

#ref: https://code.visualstudio.com/docs/python/tutorial-flask
app = Flask(__name__)

@app.route('/')
def home():
    #ref:  https://www.w3schools.com/html/html_forms.asp 
    return """
    <h1>DLT Inventory System</h1>
    <h2>Submit a new inventory record</h2>
    <form action="/add_record" method="POST">
      Item ID: <input name="item_id" maxlength="3" required><br><br>
      Quantity: <input name="qty" type="number" required><br><br>
      Price: <input name="price" type="number" required><br><br>
      Warehouse Location:
      <select name="origin">
        <option>A</option><option>B</option><option>C</option><option>D</option>
      </select><br><br>
      <input type="checkbox" id="tamper" name="tamper" value="yes">
      <label for="tamper">Tamper with record after signing (demo)</label><br><br>
      <button type="submit">Submit</button>
    </form>
    """

@app.route('/add_record', methods=['POST'])
def add_record():

    #Task 1 - Digital signature 
    invalid = False
    #Takes inputs from website and adds them to variables
    item_id = request.form['item_id']
    qty = request.form['qty']
    price = request.form['price']
    origin = request.form['origin']
    #Only present in data if checkbox is ticked
    tamper = request.form.get('tamper') == 'yes'
    #Forms input into string
    record = f"{item_id}|{qty}|{price}|{origin}"
    #Uses function from rsa.py to hash the record
    h = hash_to_int(record)
    #Finds the warehouse's public and private key from NODES dictionary
    signer = NODES[origin]
    signature = sign(h, signer["n"], signer["d"])
    #If tampering demo is checked, the record will be tampered with showing...
    #that the other warehouses cannot confirm the integrity and authenticity of the data
    if tamper:
        record = record + 'X'
    #Build the verification list as HTML
    #ref: https://www.w3schools.com/php/php_forms.asp
    results_html = ""
    for node_id in NODES:
        h_check = hash_to_int(record)
        ok = verify(h_check, signature, signer["n"], signer["e"])
        results_html += f"<li>Node {node_id}: {'VALID' if ok else 'INVALID'}</li>"
        if not ok:
            invalid = True
    if invalid:
        validation_message = 'INTEGRITY AND AUTHENTICITY OF MESSAGE CANNOT BE CONFIRMED. NEW RECORD WILL NOT BE ADDED'
    else:
        validation_message = 'Record integrity and authenticity verified. Record can be added'

    #Task 2 - BFT Consensus
    consensus_result = bft_consensus(record, origin, signature)

    #step 1 html
    phase1_html = f"""
    <div class="phase">
      <b>Step 1 Leader Election</b><br>
      Node <b>{consensus_result['leader']['leader']}</b> is selected as the leader/proposer
      for this consensus round (the node that created and signed the record).
    </div>
    """

    #step 2 html
    phase2_html = f"""
    <div class="phase">
      <b>Step 2 Proposal</b><br>
      Leader Node <b>{origin}</b> broadcasts the signed record to all
      {consensus_result['n_nodes']} validator nodes: <b>{", ".join(f"Node {n}" for n in consensus_result['proposal']['to'])}</b>.
    </div>
    """

    #step 3 html
    vote_rows = ""
    for node_id, info in consensus_result['votes'].items():
        css   = "accept" if info['vote'] == "ACCEPT" else "reject"
        vote_rows += (
            f"<tr>"
            f"<td>Node {node_id}</td>"
            f"<td class='mono'>{info['hash']}</td>"
            f"<td class='{css}'>{info['vote']}</td>"
            f"</tr>"
        )
 
    phase3_html = f"""
    <div class="phase">
      <b>Step 3 Voting (Pre-vote)</b><br>
      Each node re-hashes the received record and verifies the RSA signature
      using Node {origin}'s public key. A supermajority of ≥ {consensus_result['threshold']}
      ACCEPT votes is required to prevent conflicting records being committed.
    </div>
    <table>
      <tr><th>Node</th><th>SHA-256 hash (int)</th><th>Pre-vote</th></tr>
      {vote_rows}
    </table>
    <p>ACCEPT votes: <b>{consensus_result['accept_count']}</b> / {consensus_result['n_nodes']} &nbsp;|&nbsp;
       Supermajority threshold (⌈2/3 × {consensus_result['n_nodes']}⌉): <b>{consensus_result['threshold']}</b></p>
    """
    if consensus_result['consensus_reached']:
        committed = ", ".join(f"Node {n}" for n in result['committed_nodes'])
        phase4_html = f"""
        <div class="phase">
          <b>Step 4 – Finality</b><br>
          Supermajority met ({consensus_result['accept_count']} ≥ {consensus_result['threshold']}).
          Record is final and appended to: <b>{committed}</b>.
        </div>
        <div class="commit">
            <b>CONSENSUS REACHED</b> — Record is now immutable and stored in all node ledgers.
        </div>
        """
    else:
        phase4_html = f"""
        <div class="phase">
          <b>Step 4 Finality</b><br>
          Supermajority NOT met ({consensus_result['accept_count']} &lt; {consensus_result['threshold']}).
          Record cannot be finalised.
        </div>
        <div class="nocommit">
            <b>CONSENSUS FAILED</b> — Record was NOT stored.
        </div>
        """


    #ref: https://developer.mozilla.org/en-US/docs/Web/HTML
    return f"""
        <h1>Record submission workflow</h1>
        <h3>Record</h3>
        <p>{record}</p>
        <h3>SHA-256 hash</h3>
        <p>{h}</p>
        <h3>Signed by Inventory {origin}</h3>
        <p>{signature}</p>
        <h3>Verification</h3>
        <ul>{results_html}</ul>
        <p>{validation_message}<p>
        <a href="/">Submit another</a>
        
        <h2>Task 2 BFT Consensus</h2>
        <p>
        Simplified BFT consensus with <b>{consensus_result['n_nodes']} nodes</b>.
        Supermajority commit threshold: ≥ {consensus_result['threshold']} ACCEPT votes.
        </p>
 
    {phase1_html}
    {phase2_html}
    {phase3_html}
    {phase4_html}
    """

if __name__ == '__main__':
    app.run()