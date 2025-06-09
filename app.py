from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import pickle
import pandas as pd
import numpy as np
from flask import session
import uuid
import json
from datetime import datetime
from dbconnect import *
from flask import Flask, send_file
import os
import datetime
import hashlib

from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy

import os
import hashlib
import time
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json
import base64
import json
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'memfileuploadencryptd'
app.config['SECRET_KEY'] = 'super secret key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/blockchainlog'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Initialize SQLAlchemy
db = SQLAlchemy(app)
import os
import datetime
import hashlib

import pickle
# Directory to store AES keys
KEY_DIRECTORY = "keys"

# Ensure the key directory exists
os.makedirs(KEY_DIRECTORY, exist_ok=True)

class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f"{self.index}{self.timestamp}{self.data}{self.previous_hash}".encode()
        return hashlib.sha256(block_string).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, time.time(), "Genesis Block", "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, new_block):
        new_block.previous_hash = self.get_latest_block().hash
        new_block.hash = new_block.calculate_hash()
        self.chain.append(new_block)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Verify if hash is correct
            if current_block.hash != current_block.calculate_hash():
                return False
            
            # Verify if block points to previous block's hash
            if current_block.previous_hash != previous_block.hash:
                return False
        return True

    def add_log_entry(self, attributes, success, message, username):
        log_data = {
            "timestamp": time.time(),
            "attributes": attributes,
            "success": success,
            "message": message,
            "username": username
        }
        new_block = Block(len(self.chain), time.time(), log_data, self.get_latest_block().hash)
        self.add_block(new_block)
        print(f"Log entry added to blockchain: {json.dumps(log_data, indent=4)}")

    def verify_access(self, attributes):
        access_granted = False
        for block in self.chain:
            if block.index != 0:  # Skip genesis block
                log_data = block.data
                if log_data["attributes"] == attributes and log_data["success"]:
                    access_granted = True
                    print(f"Access granted for attributes {attributes} on {time.ctime(log_data['timestamp'])}")
                    break
        if not access_granted:
            print("Access denied for specified attributes.")
        return access_granted

    def print_chain(self):
        for block in self.chain:
            print(f"Index: {block.index}")
            print(f"Timestamp: {time.ctime(block.timestamp)}")
            print(f"Data: {block.data}")
            print(f"Hash: {block.hash}")
            print(f"Previous Hash: {block.previous_hash}")
            print("\n")
            
def save_blockchain(blockchain, file_path="blockchain.json"):
    """Save the blockchain to a JSON file."""
    chain_data = []
    for block in blockchain.chain:
        block_dict = {
            "index": block.index,
            "timestamp": block.timestamp,
            "data": block.data,
            "previous_hash": block.previous_hash,
            "hash": block.hash
        }
        chain_data.append(block_dict)
    
    with open(file_path, "w") as file:
        json.dump(chain_data, file, indent=4)
    print(f"Blockchain saved to {file_path}")
    
def load_blockchain(file_path="blockchain.json"):
    """Load the blockchain from a JSON file."""
    with open(file_path, "r") as file:
        chain_data = json.load(file)
    
    blockchain = Blockchain()
    blockchain.chain = []
    
    for block_dict in chain_data:
        block = Block(
            index=block_dict["index"],
            timestamp=block_dict["timestamp"],
            data=block_dict["data"],
            previous_hash=block_dict["previous_hash"]
        )
        block.hash = block_dict["hash"]  # Use the saved hash
        blockchain.chain.append(block)
    
    print(f"Blockchain loaded from {file_path}")
    return blockchain
def save_key(secret_key,id, file_path="_key.key"):
    """Save AES key to a file."""
    with open("keys/"+str(id)+file_path, 'wb') as key_file:
        # Encode the key to Base64 and save it
        key_file.write(base64.b64encode(secret_key))


def save_encrypted_file(ciphertext, metadata,id, file_path="encrypted_data.json"):
    """Save encrypted data and metadata to a file."""
    data_to_save = {
        "ciphertext": ciphertext,
        "metadata": metadata
    }
    with open("static/Encrypted/"+str(id)+file_path, 'w') as file:
        json.dump(data_to_save, file)
    return "static/Encrypted/"+str(id)+file_path

def load_encrypted_file(file_path="encrypted_data.json"):
    """Load encrypted data and metadata from a file."""
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data["ciphertext"], data["metadata"]

def load_key(id,file_path="_key.key"):
    """Load AES key from a file."""
    with open("keys/"+str(id)+file_path, 'rb') as key_file:
        # Decode the Base64 encoded key
        return base64.b64decode(key_file.read())
def encrypt_data(data, policy_attributes, secret_key):
    """Encrypt data with a policy."""
    cipher = AES.new(secret_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    
    # Store policy in metadata
    metadata = {
        'policy': policy_attributes,
        'nonce': cipher.nonce.hex(),
        'tag': tag.hex()
    }
    return ciphertext.hex(), metadata

def decrypt_data(ciphertext, metadata, user_attributes, secret_key):
    """Decrypt data if user satisfies the policy."""
    required_attributes = set(metadata['policy'])
    user_attributes_set = set(user_attributes)

    # Check if user satisfies policy
    if not required_attributes.issubset(user_attributes_set):
        raise PermissionError("User does not satisfy the policy!")
    
    cipher = AES.new(secret_key, AES.MODE_GCM, nonce=bytes.fromhex(metadata['nonce']))
    plaintext = cipher.decrypt_and_verify(bytes.fromhex(ciphertext), bytes.fromhex(metadata['tag']))
    return plaintext.decode()
@app.route('/')
def hello():
    message= ''
    return render_template("index.html")

@app.route('/index')
def index():
    message= ''
    return render_template("index.html")

@app.route('/signup')
def signup():
    message= ''
    return render_template("signup.html",message = message)

@app.route('/signin')
def signin():
    message= ''
    return render_template("signin.html",message = message)

@app.route('/fileuploadencrypt')
def fileuploadencrypt():
    message= ''
    return render_template("fileuploadencrypt.html",message = message,name=session['name'])

@app.route('/blockchaininfo')
def blockchaininfo():

   
    return render_template("blockchain.html",message = blockchain.chain,name=session['name'])

@app.route('/userhome')
def userhome():
    message= ''
    return render_template("patient.html",message = message,name=session['name'])

@app.route('/staffhome')
def staffhome():
    message= ''
    return render_template("staff.html",message = message,name=session['name'])



@app.route('/ehr')
def ehr():
    message= ''

    return render_template("ehr.html",message = message,name=session['name'])

@app.route('/viewrecord')
def viewrecord():
    dataQuery="SELECT * FROM ehr where userid='"+str(session['id'])+"'"
    dataInfo = recoredselect(dataQuery)
    print(dataInfo)
    
    return render_template("viewrecord.html",message = dataInfo,name=session['name'])
@app.route('/viewpatientrecord')
def viewpatientrecord():
    dataQuery="SELECT * FROM ehr"
    dataInfo = recoredselect(dataQuery)
    print(dataInfo)
    
    return render_template("viewpatientrecord.html",message = dataInfo,name="Staff")


@app.route('/viewlog')
def viewlog():
    message= ''
    return render_template("viewlog.html",message = log_blockchain.chain,name=session['name'])
    


@app.route('/notification')
def notification():
    dataQuery="SELECT * FROM notification where userid='"+str(session['id'])+"'"
    dataInfo = recoredselect(dataQuery)
    print(dataInfo)
    return render_template("notification.html",message = dataInfo,name=session['name'])


@app.route('/recordupload', methods=["POST","GET"])
def recordupload():
    if request.method == 'POST':
        problem = request.form["problem"]
        description= request.form["description"]
        attribute= request.form["attribute"]
        bp= request.form["bp"]
        hb= request.form["hb"]
        attributeacess=[]
        attributeinfo=attribute.split(",")
        for i in attributeinfo:
            attributeacess.append(i)
        dataQuery="SELECT id FROM ehr ORDER BY id DESC LIMIT 1"
        dataInfo = recoredselect(dataQuery)
        print(dataInfo)
        id=1
        if(len(dataInfo)>0):
            id=id+dataInfo[0][0]
        loaded_key = load_key(session['id'])
        ciphertext, metadata = encrypt_data(description, attributeacess, loaded_key)
        # Save the encrypted data and metadata to a file
        encrypted_filepath=save_encrypted_file(ciphertext, metadata,id)

        sql1='insert into ehr(userid,acessattribute,problem,description,bp,hb,timestamp) values("%s","%s","%s","%s","%s","%s","%s")' % \
                    (session['id'],attribute,problem,encrypted_filepath,bp,hb,time.ctime(time.time()))
        print(sql1)
        inserquery(sql1)
        
        message="EHR Record upload Sucessfully"
    return render_template("ehr.html",message = message,name=session['name'])
    
@app.route('/register', methods=["POST","GET"])
def register():
    print("Data")
    if request.method == 'POST':
        
        email = request.form["email"]
        password= request.form["password"]
        username= request.form["username"]
        sql1='insert into account(username,email,password) values("%s","%s","%s")' % \
                    (username,email,password)
        print(sql1)
        inserquery(sql1)
        dataQuery="SELECT id FROM account ORDER BY id DESC LIMIT 1"
        dataInfo = recoredselect(dataQuery)
        print(dataInfo)
        id=dataInfo[0][0]
        secret_key = get_random_bytes(16)  
        save_key(secret_key,id)
        
        message=email+" account Created Sucessfully"
    return render_template('index.html', message =message)

@app.route('/authorised',methods = ["GET","POST"])
def authorised():
    message= '' 
    email= request.form["email"]
    password= request.form["password"] 
    print("-----------------------------")
    print(email)
    dataQuery = "select * from account where email='"+email+"' && password='"+password+"'"
    print(dataQuery)
   
    if(email=="Staff@gmail.com" and password=="Staff"):
        return render_template('staff.html',  name="Staff")
    dataInfo = recoredselect(dataQuery)
    print(dataInfo)
    if(dataInfo):
        session['id'] = dataInfo[0][0]
        session['name'] = dataInfo[0][1]
         
        return render_template('patient.html', message =dataInfo , name=session['name'])
    else:
        return render_template('index.html', message =message)

     




@app.route('/delete',methods=['GET','POST'])
def delete():
    file_id=request.args.get('id')
    dataQuery = "Delete from filesinfo where id='"+file_id+"'"
    inserquery(dataQuery)
    dataQuery = "select * from filesinfo where userid='"+str(session['id'])+"'"
    print(dataQuery)
    dataInfo = recoredselect(dataQuery)

    return render_template('fileuploadencryptResponse.html', message =dataInfo , name=session['name'])




@app.route('/viewdetail',methods=['GET','POST'])
def viewdetail():
    file_id=request.args.get('id')
    file_name=request.args.get('fileid')
    
    userid=request.args.get('userid')
    session['userid']=userid
    session['filename']=file_id
    session['fileid']=file_name
    return render_template('viewdetail.html',  name="staff")
log_blockchain = load_blockchain()
@app.route('/viewrecordinfo', methods=["POST","GET"])
def viewrecordinfo():
    if request.method == 'POST':
        purpose = request.form["purpose"]
        attribute= request.form["attribute"]
        name= request.form["name"]
        
        attributeacess=[]
        attributeinfo=attribute.split(",")
        for i in attributeinfo:
            attributeacess.append(i)
        
        sql1='insert into notification(userid,username,purpose,timestamp) values("%s","%s","%s","%s")' % \
                    (session['userid'],name,purpose,time.ctime(time.time()))
        print(sql1)
        inserquery(sql1)
        loaded_key = load_key(session['userid'])
        loaded_ciphertext, loaded_metadata = load_encrypted_file(session['filename'])
        try:
            decrypted_file = decrypt_data(loaded_ciphertext, loaded_metadata, attributeacess, loaded_key)
            print("Decrypted Data:", decrypted_file)
            log_blockchain.add_log_entry(attributes=attributeacess, success=True, message="Decryption successful.", username=name)
            decryptfilename="static/Decrypt/"+str(session['fileid'])+"_file.txt"
            if isinstance(decrypted_file, str):
                decrypted_file = decrypted_file.encode()  # UTF-8 encoding by default
            with open(decryptfilename, "wb") as file:
                file.write(decrypted_file)
                print("file write Sucess")
            try:
                return send_file(decryptfilename, as_attachment=True)
            except Exception as e:
                return str(e)

        except PermissionError as e:
            print("Access Denied")
            print(str(e))
            log_blockchain.add_log_entry(attributes=attributeinfo, success=False, message="Decryption Failed.",username=name)

        save_blockchain(log_blockchain) 
    
    


@app.route('/download',methods=['GET','POST'])
def download():
    file_id=request.args.get('id')
    file_name=request.args.get('fileid')
    
    accessattribute=request.args.get('accessattribute')
    loaded_key = load_key(session['id'])
    attributeacess=[]
    attributeinfo=accessattribute.split(",")
    for i in attributeinfo:
            attributeacess.append(i)
    loaded_ciphertext, loaded_metadata = load_encrypted_file(file_id)
    decrypted_file = decrypt_data(loaded_ciphertext, loaded_metadata, attributeacess, loaded_key)
    
    decryptfilename="static/Decrypt/"+str(file_name)+"_file.txt"
    if isinstance(decrypted_file, str):
        decrypted_file = decrypted_file.encode()  # UTF-8 encoding by default

    with open(decryptfilename, "wb") as file:
        file.write(decrypted_file)
        print("file write Sucess")
    try:
        return send_file(decryptfilename, as_attachment=True)
    except Exception as e:
        return str(e)
    


@app.route('/download1',methods=['GET','POST'])
def download1():
    file_id=request.args.get('id')
    dataQuery = "select * from filesinfo where id='"+file_id+"'"
    dataInfo = recoredselect(dataQuery)
    client_private_key = load_private_key(os.path.join(ECC_KEY_DIRECTORY, str(session['id'])+"client_private_key.pem"))
    client_public_key = load_public_key(os.path.join(ECC_KEY_DIRECTORY, str(session['id'])+"client_public_key.pem"))
    loaded_encrypted_data = load_encrypted_file(dataInfo[0][2])
    with open(dataInfo[0][3], 'rb') as file:
                encrypted_block = pickle.load(file)
    block_id=encrypted_block['block_id']
    decrypted_file = decrypt_file_and_block(loaded_encrypted_data, block_id, encrypted_block['block_data'], client_private_key, server_public_key)
    decryptfilename="static/Decrypt/"+str(file_id)+"_"+dataInfo[0][4]+"file.txt"
    if isinstance(decrypted_file, str):
        decrypted_file = decrypted_file.encode()  # UTF-8 encoding by default

    with open(decryptfilename, "wb") as file:
        file.write(decrypted_file)
        print("file write Sucess")
    try:
        return send_file(decryptfilename, as_attachment=True)
    except Exception as e:
        return str(e)
    



@app.route('/home')
def home():
    return render_template("index.html")




if __name__ == '__main__':
    app.run(debug=True)