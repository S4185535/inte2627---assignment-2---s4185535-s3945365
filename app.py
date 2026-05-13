#Run this .py to launch the website
#Inbulit flask to run website
from flask import Flask, request
#keys.py generate public and private keys for each warehouse
from keys import NODES
#rsa.py takes input and computes all calculations
from rsa import sign, verify, hash_to_int
#consensus.py handles consensus process for new records
from consensus import bft_consesnsus, get_all_ledgers

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
    """

if __name__ == '__main__':
    app.run()