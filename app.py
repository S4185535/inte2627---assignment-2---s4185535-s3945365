#Run this .py to launch the website
#Inbulit flask to run website
from flask import Flask, request
#keys.py generate public and private keys for each warehouse
from keys import NODES
#rsa.py takes input and computes all calculations
from rsa import sign, verify, hash_to_int
#consensus.py handles consensus process for new records
from consensus import bft_consensus, get_all_ledgers
#query.py handles secure query workflow
from query import process_query

#ref: https://code.visualstudio.com/docs/python/tutorial-flask
app = Flask(__name__)

@app.route('/')
def home():
    #ref:  https://www.w3schools.com/html/html_forms.asp 

    #ledger
    ledgers = get_all_ledgers()
    ledger_html = "<h2>Current Ledgers</h2>"
    for node_id, records in ledgers.items():
        rows = "".join(f"<tr><td>{r}</td></tr>" for r in records) or "<tr><td><i>No records</i></td></tr>"
        ledger_html += f"<h4> Node {node_id}</h4><table>{rows}</table>"

    return f"""
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
    <h2>Query inventory (Task 3)</h2>
    <form action="/query" method="POST">
      Item ID to query: <input name="item_id" maxlength="3" required><br><br>
      <button type="submit">Submit Query</button>
    </form>
    
    {ledger_html}   
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
      {consensus_result['num_nodes']} validator nodes: <b>{", ".join(f"Node {n}" for n in consensus_result['proposal']['to'])}</b>.
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
      using Node {origin}'s public key. A supermajority of ≥ {consensus_result['supermajority']}
      ACCEPT votes is required to prevent conflicting records being committed.
    </div>
    <table>
      <tr><th>Node</th><th>SHA-256 hash (int)</th><th>Pre-vote</th></tr>
      {vote_rows}
    </table>
    <p>ACCEPT votes: <b>{consensus_result['accept_count']}</b> / {consensus_result['num_nodes']} &nbsp;|&nbsp;
       Supermajority threshold (⌈2/3 {consensus_result['num_nodes']}⌉): <b>{consensus_result['supermajority']}</b></p>
    """
    if consensus_result['consensus_reached']:
        committed = ", ".join(f"Node {n}" for n in consensus_result['committed_nodes'])
        phase4_html = f"""
        <div class="phase">
          <b>Step 4 Finality</b><br>
          Supermajority met ({consensus_result['accept_count']} ≥ {consensus_result['supermajority']}).
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
          Supermajority NOT met ({consensus_result['accept_count']} &lt; {consensus_result['supermajority']}).
          Record cannot be finalised.
        </div>
        <div class="nocommit">
            <b>CONSENSUS FAILED</b> — Record was NOT stored.
        </div>
        """
    #ledger
    ledgers = get_all_ledgers()
    ledger_html = "<h2>Current Ledgers</h2>"
    for node_id, records in ledgers.items():
        rows = "".join(f"<tr><td>{r}</td></tr>" for r in records) or "<tr><td><i>No records</i></td></tr>"
        ledger_html += f"<h4> Node {node_id}</h4><table>{rows}</table>"


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
        Simplified BFT consensus with <b>{consensus_result['num_nodes']} nodes</b>.
        Supermajority commit threshold: ≥ {consensus_result['supermajority']} ACCEPT votes.
        </p>
 
    {phase1_html}
    {phase2_html}
    {phase3_html}
    {phase4_html}
    <hr>
    {ledger_html}
    """

@app.route('/query', methods=['POST'])
def query_route():
    #Task 3: Secure query workflow
    #Takes item_id from the website and runs the full query process
    item_id = request.form['item_id']
    #Uses function from query.py to do the whole process
    result = process_query(item_id)
    #If the item wasn't found in any ledger, stop here
    if not result['item_found']:
        return f"<h1>No inventory ID '{item_id}' found</h1><a href='/'>Back to home</a>"

    #step 1 html
    step1_html = f"""
    <div class="phase">
      <b>Step 1 Query Submission</b><br>
    </div>
    """

    #step 2
    #Build the lookup table by looping over each node's result
    lookup_rows = ""
    for node_id in result['lookups']:
        rec = result['lookups'][node_id]
        if rec is None:
            lookup_rows += f"<tr><td>Node {node_id}</td><td><i>not found</i></td></tr>"
        else:
            lookup_rows += f"<tr><td>Node {node_id}</td><td>qty={rec['qty']} price={rec['price']} origin={rec['origin']}</td></tr>"
    step2_html = f"""
    <div class="phase">
      <b>Step 2 Item Lookup</b><br>
    </div>
    <table>
      <tr><th>Node</th><th>Record found</th></tr>
      {lookup_rows}
    </table>
    """

    #step 3 html
    step3_html = f"""
    <div class="phase">
      <b>Step 3 Response Message</b><br>
      <b>{result['response']}</b>
    </div>
    """

    #step 4 html
    #Build the per-node t value table
    #ref: https://www.w3schools.com/html/html_tables.asp
    t_rows = ""
    for node_id in result['signed']['t_values']:
        t_val = result['signed']['t_values'][node_id]
        t_rows += f"<tr><td>Node {node_id}</td><td>{t_val}</td></tr>"
    #Build the partial signatures table
    partial_rows = ""
    for node_id in result['signed']['partial_sigs']:
        sig = result['signed']['partial_sigs'][node_id]
        partial_rows += f"<tr><td>Node {node_id}</td><td>{sig}</td></tr>"
    step4_html = f"""
    <div class="phase">
      <b>Step 4 Harn Multi-Signature Generation</b><br>
    </div>
    <h4>node t valuess (t_i = r_i^e mod n)</h4>
    <table><tr><th>Node</th><th>t_i</th></tr>{t_rows}</table>
    <h4>Aggregated t (product of all t_i mod n)</h4>
    <p>{result['signed']['t']}</p>
    <h4>Hash h = H(t || message)</h4>
    <p>{result['signed']['h']}</p>
    <h4>Partial signatures (s_i = g_i * r_i^h mod n)</h4>
    <table><tr><th>Node</th><th>s_i</th></tr>{partial_rows}</table>
    <h4>Aggregated signature s (product of all s_i mod n)</h4>
    <p>{result['signed']['s']}</p>
    """

    #step 5 html
    #Build the consensus check table
    consensus_rows = ""
    for node_id in result['consensus']['node_results']:
        ok = result['consensus']['node_results'][node_id]
        css = "accept" if ok else "reject"
        consensus_rows += f"<tr><td>Node {node_id}</td><td class='{css}'>{'VALID' if ok else 'INVALID'}</td></tr>"
    all_consistent = "YES" if result['consensus']['all_consistent'] else "NO"
    step5_html = f"""
    <div class="phase">
      <b>Step 5 Consensus Check</b><br>
    </div>
    <table>
      <tr><th>Node</th><th>Verification</th></tr>
      {consensus_rows}
    </table>
    <p>All nodes agree: <b>{all_consistent}</b></p>
    """

    #step 6 html
    step6_html = f"""
    <div class="phase">
      <b>Step 6 RSA Encryption for Procurement Officer</b><br>
    </div>
    <p>Encrypted message: {result['encrypted']['enc_msg']}</p>
    <p>Encrypted t: {result['encrypted']['enc_t']}</p>
    <p>Encrypted s: {result['encrypted']['enc_s']}</p>
    """

    #step 7 html
    #If the decrypted message matches the original then recovery worked
    if result['recovery_ok']:
        recovery_message = "Recovered message matches the original"
    else:
        recovery_message = "decryption failed or data was tampered with"
    step7_html = f"""
    <div class="phase">
      <b>Step 7 Procurement Officer Decryption</b><br>
    </div>
    <p>Recovered message: <b>{result['decrypted']['message']}</b></p>
    <p>Recovered t: {result['decrypted']['t']}</p>
    <p>Recovered s: {result['decrypted']['s']}</p>
    <p>{recovery_message}</p>
    """

    #step 8 html
    #Final check
    if result['final_check']['valid']:
        final_message = "SIGNATURE VALID: Procurement Officer trusts the response"
    else:
        final_message = "SIGNATURE INVALID: response cannot be trusted"
    step8_html = f"""
    <div class="phase">
      <b>Step 8 Final Multi-Signature Verification</b><br>
    </div>
    <p>left  = s^e mod n = {result['final_check']['left']}</p>
    <p>right = (product of identities) * t^h mod n = {result['final_check']['right']}</p>
    <p><b>{final_message}</b></p>
    """

    #ref: https://developer.mozilla.org/en-US/docs/Web/HTML
    return f"""
    <h1>Task 3 Secure Query Workflow</h1>
    <p>
    Multi-signature query verification using the Harn identity-based scheme,
    with RSA encryption to deliver the response securely to the Procurement Officer.
    </p>

    {step1_html}
    {step2_html}
    {step3_html}
    {step4_html}
    {step5_html}
    {step6_html}
    {step7_html}
    {step8_html}
    <hr>
    <a href="/">Back to home</a>
    """

if __name__ == '__main__':
    app.run()