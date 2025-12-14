from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from web3 import Web3
import json
from datetime import datetime
import traceback
import re

app = Flask(__name__)
app.secret_key = 'supersecret'
app.config["MONGO_URI"] = "YOUR MONGO DB LINK "
mongo = PyMongo(app)

ganache_url = "http://127.0.0.1:8545"
w3 = Web3(Web3.HTTPProvider(ganache_url))
with open("PharmaChain_abi.json") as f:
    abi = json.load(f)
with open("contract_address.txt") as f:
    contract_address = f.read().strip()
contract = w3.eth.contract(address=contract_address, abi=abi)

ROLES = {1: "Manufacturer", 2: "Distributor", 3: "Pharmacy", 4: "Patient"}

def get_free_eth_account():
    used = [u.get('eth_account') for u in mongo.db.users.find() if 'eth_account' in u]
    for acct in w3.eth.accounts:
        if acct not in used:
            return acct
    raise Exception("No free Ethereum accounts available on Ganache.")

def get_users_by_role(role_id):
    return [u['username'] for u in mongo.db.users.find({'role': role_id}, {'username': 1})]

def get_status_name(idx):
    statuses = ["Registered", "Manufactured", "InTransit", "Delivered", "Dispensed"]
    return statuses[idx] if 0 <= idx < len(statuses) else "Unknown"

def format_timestamp(ts):
    return datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') if ts else ""

# CHAINPAGE Utility: Compose full custody chain details including tx info
def get_chainpage_details(batchId):
    custody_addresses = contract.functions.getBatchCustody(batchId).call()
    timestamps = contract.functions.getBatchTimestamps(batchId).call()
    # Transaction hash logic: assume contract.functions.getBatchTxHashes(batchId) exists!
    # If not, you may need to store tx hashes in MongoDB at transfer time, or retrieve via event logs!
    try:
        tx_hashes = contract.functions.getBatchTxHashes(batchId).call()  # Must be implemented on contract
    except Exception:
        tx_hashes = [None] * len(custody_addresses)

    address_to_username = {u.get('eth_account',''): u.get('username','unknown') for u in mongo.db.users.find({}, {'username': 1, 'eth_account': 1})}
    address_to_role = {u.get('eth_account',''): ROLES.get(u.get('role')) for u in mongo.db.users.find({}, {'role': 1, 'eth_account': 1})}
    chain_details = []
    for idx, addr in enumerate(custody_addresses):
        detail = {
            "eth_id": addr,
            "username": address_to_username.get(addr, 'unknown'),
            "role": address_to_role.get(addr, 'unknown'),
            "timestamp": format_timestamp(timestamps[idx]) if idx < len(timestamps) else "",
            "tx_hash": tx_hashes[idx] if tx_hashes and idx < len(tx_hashes) else None,
            "tx_nonce": None,
            "blockNumber": None,
            "from": None,
            "to": None
        }
        if detail["tx_hash"]:
            try:
                tx = w3.eth.get_transaction(detail["tx_hash"])
                detail["tx_nonce"] = tx.nonce
                detail["blockNumber"] = tx.blockNumber
                detail["from"] = tx["from"]
                detail["to"] = tx["to"]
            except Exception:
                pass
        chain_details.append(detail)
    return chain_details

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']
        role_id = int(request.form['role'])
        aadhaar = request.form['aadhaar'].strip()

        # Validate role
        if ROLES.get(role_id) is None:
            flash("Invalid role.")
            return redirect('/signup')

        # Validate Aadhaar format: 12 digits, not all same digits
        if not re.fullmatch(r'\d{12}', aadhaar) or re.fullmatch(r'(\d)\1{11}', aadhaar):
            flash("Invalid Aadhaar number. Must be 12 digits and not all the same digit.")
            return redirect('/signup')

        # Check username uniqueness
        if mongo.db.users.find_one({'username': username}):
            flash('Username already registered.')
            return redirect('/signup')

        # Check Aadhaar uniqueness
        if mongo.db.users.find_one({'aadhaar': aadhaar}):
            flash('Aadhaar number already registered.')
            return redirect('/signup')

        # Assign Ethereum account
        eth_account = get_free_eth_account()

        # Insert user data including Aadhaar
        mongo.db.users.insert_one({
            'username': username,
            'password': generate_password_hash(password),
            'role': role_id,
            'aadhaar': aadhaar,
            'eth_account': eth_account
        })

        # Set role on blockchain contract
        contract.functions.setRole(eth_account, role_id).transact({'from': w3.eth.accounts[0]})

        # Save user session
        session['username'] = username
        session['role'] = role_id

        return redirect('/dashboard')

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']
        user = mongo.db.users.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            session['role'] = user['role']
            return redirect('/dashboard')
        flash('Invalid credentials.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    username = session.get('username')
    role_id = session.get('role')
    role = ROLES.get(role_id, "Unknown")
    batch_list = []
    if "batches" in mongo.db.list_collection_names():
        batch_list = list(mongo.db.batches.find())
    batches = []
    for batch in batch_list:
        batchId = batch.get("batchId")
        if not batchId:
            continue
        try:
            batch_info = contract.functions.getBatchMetadata(batchId).call()
            users_in_chain = batch.get("users_in_chain", [])
            if username in users_in_chain:
                batches.append({
                    "batchId": batchId,
                    "status": get_status_name(batch_info[3]),
                    "origin": batch_info[0],
                    "meta": batch_info[2],
                    "custody": users_in_chain,
                })
        except Exception as e:
            print("DASHBOARD BATCH FETCH ERROR:", e)
            traceback.print_exc()
            continue
    next_role_id = None
    next_role_users = []
    if role_id and role_id < max(ROLES.keys()):
        next_role_id = role_id + 1
        next_role_users = get_users_by_role(next_role_id)
    return render_template('dashboard.html', role=role, username=username, batches=batches, next_role_users=next_role_users)

@app.route('/register_batch', methods=['POST'])
def register_batch():
    username = session.get('username')
    role_id = session.get('role')
    if ROLES.get(role_id) != "Manufacturer":
        flash("Only Manufacturer can register batch.")
        return redirect('/dashboard')
    user = mongo.db.users.find_one({'username': username})
    if not user:
        flash('User error.')
        return redirect('/dashboard')
    batchId = request.form['batchId']
    origin = request.form['origin']
    processingData = request.form['processingData']
    meta = request.form.get('meta', '')
    try:
        contract.functions.registerBatch(batchId, origin, processingData, meta).transact({'from': user['eth_account']})
    except Exception as e:
        msg = str(e)
        if "Batch exists" in msg:
            flash("Batch already exists on blockchain. Use a unique Batch ID.")
        else:
            flash(f"Error during blockchain registration: {msg}")
        return redirect('/dashboard')
    try:
        doc_to_insert = {
            "batchId": batchId,
            "users_in_chain": [username],
            "origin": origin,
            "processingData": processingData,
            "meta": meta
        }
        result = mongo.db.batches.insert_one(doc_to_insert)
        doc = mongo.db.batches.find_one({"batchId": batchId})
        print("Batch read after insert:", doc)
        flash("Batch registered!")
    except Exception as e:
        flash(f"Error saving batch to database: {e}")
    return redirect('/dashboard')

@app.route('/transfer_batch', methods=['POST'])
def transfer_batch():
    username = session.get('username')
    to_username = request.form['to_username'].strip().lower()
    batchId = request.form['batchId']
    current_user = mongo.db.users.find_one({'username': username})
    next_user = mongo.db.users.find_one({'username': to_username})
    if not next_user:
        flash("Recipient username does not exist.")
        return redirect('/dashboard')
    try:
        contract.functions.transferBatch(batchId, next_user['eth_account']).transact({'from': current_user['eth_account']})
        mongo.db.batches.update_one(
            {"batchId": batchId},
            {"$addToSet": {"users_in_chain": to_username}}
        )
        flash("Transferred successfully!")
    except Exception as e:
        print("Batch transfer error:", e)
        traceback.print_exc()
        flash(f"Transfer failed: {e}")
    return redirect('/dashboard')

@app.route('/chainpage')
def chainpage():
    batchId = request.args.get('batchId')
    if not batchId:
        flash('Invalid Batch.')
        return redirect('/dashboard')
    batch_info = contract.functions.getBatchMetadata(batchId).call()
    batch = {
        "status": get_status_name(batch_info[3]),
        "origin": batch_info[0],
        "meta": batch_info[2]
    }
    chain_details = get_chainpage_details(batchId)
    return render_template('chainpage.html', batchId=batchId, batch=batch, chain_details=chain_details)

if __name__ == "__main__":
    app.run(debug=True)
