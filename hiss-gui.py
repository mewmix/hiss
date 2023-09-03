import tkinter as tk
from tkinter import ttk

from tkinter import filedialog, messagebox
from eth_keys import keys
from ecies import encrypt, decrypt
import web3
from eth_account._utils.signing import extract_chain_id, to_standard_v
from eth_account._utils.legacy_transactions import serializable_unsigned_transaction_from_dict
import os
import requests


class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Hissssss")

        # Create a Notebook for tabbed interface
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create tabs
        self.tab1 = tk.Frame(self.notebook)
        self.tab2 = tk.Frame(self.notebook)

        self.notebook.add(self.tab1, text="EVM/ECIES")  # Updated tab name
        self.notebook.add(self.tab2, text="Experimental")  # Updated tab name

        self.encrypt_file_button = tk.Button(self.tab1, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_file_button.pack()
        self.decrypt_file_button = tk.Button(self.tab1, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_file_button.pack()
        self.get_provider_label = tk.Label(self.tab1, text="Provider:")
        self.get_provider_label.pack()
        self.get_provider_label_entry = tk.Entry(self.tab1)
        self.get_provider_label_entry.pack()
        self.get_txn_hash_label = tk.Label(self.tab1, text="Transaction Hash:")
        self.get_txn_hash_label.pack()
        self.get_txn_hash_label_entry = tk.Entry(self.tab1)
        self.get_txn_hash_label_entry.pack()
        self.get_public_key_txn_button = tk.Button(self.tab1, text="Get Public Key from Transaction", command=self.get_public_key_txn)
        self.get_public_key_txn_button.pack()

        self.public_key_label = tk.Label(self.tab1, text="Recipient's Public Key:")
        self.public_key_label.pack()

        self.public_key_entry = tk.Entry(self.tab1)
        self.public_key_entry.pack()

        self.message_label = tk.Label(self.tab1, text="Secret Message:")
        self.message_label.pack()

        self.message_entry = tk.Entry(self.tab1)
        self.message_entry.pack()

        self.encrypt_button = tk.Button(self.tab1, text="Encrypt", command=self.encrypt_message)
        self.encrypt_button.pack()

        self.private_key_label = tk.Label(self.tab1, text="Your Private Key:")
        self.private_key_label.pack()

        self.private_key_entry = tk.Entry(self.tab1)
        self.private_key_entry.pack()

        self.encrypted_message_label = tk.Label(self.tab1, text="Encrypted Message:")
        self.encrypted_message_label.pack()

        self.encrypted_message_entry = tk.Entry(self.tab1)
        self.encrypted_message_entry.pack()

        self.decrypt_button = tk.Button(self.tab1, text="Decrypt", command=self.decrypt_message)
        self.decrypt_button.pack()

        self.result_label = tk.Label(self.tab1, text="Result:")
        self.result_label.pack()

        self.result_text = tk.Text(self.tab1, height=5, width=40)
        self.result_text.pack()

        self.copy_button = tk.Button(self.tab1, text="Copy Result", command=self.copy_result)
        self.copy_button.pack()

        self.transaction_hashes_button = tk.Button(self.tab2, text="Get Transaction Hashes", command=self.get_transaction_hashes)        
        self.transaction_hashes_button.pack()
        # Create an entry field for the Etherscan API key
        self.api_key_label = tk.Label(self.tab2, text="Etherscan API Key:")
        self.api_key_label.pack()
        self.api_key_entry = tk.Entry(self.tab2)
        self.api_key_entry.pack()

        # Create an entry field for the address
        self.address_label = tk.Label(self.tab2, text="Address:")
        self.address_label.pack()
        self.address_entry = tk.Entry(self.tab2)
        self.address_entry.pack()

        self.get_transaction_hashes_button = tk.Button(self.tab2, text="Get Transaction Hashes", command=self.get_transaction_hashes)        
        self.get_transaction_hashes_button.pack()

    def get_transaction_hashes(self):
        address = self.address_entry.get()  # Get the address from the entry field
        api_key = self.api_key_entry.get()  # Get the API key from the entry field
        txn_hashes = get_transaction_hashes(address, api_key)
        
        # Display the transaction hashes in the result_text widget
        self.show_result('\n'.join(txn_hashes))

    def get_public_key_txn(self):
        provider = self.get_provider_label_entry.get()
        tx_hash = self.get_txn_hash_label_entry.get()
        recovered_public_key, from_address = pubkey_txn(provider, tx_hash)
        self.public_key_entry.delete(0, tk.END)
        self.public_key_entry.insert(0, recovered_public_key.to_hex())
        self.show_result(recovered_public_key.to_hex())

    def show_result(self, result):
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, result)
        

    def copy_result(self):
        result = self.result_text.get(1.0, tk.END).strip()  # Remove trailing newline
        self.root.clipboard_clear()
        self.root.clipboard_append(result)
        messagebox.showinfo("Copied", "Result has been copied to the clipboard!")


    def encrypt_file(self):
        public_key_hex = self.public_key_entry.get()
        input_file_path = filedialog.askopenfilename()
        output_file_path = filedialog.asksaveasfilename()
        encrypt_file(public_key_hex, input_file_path, output_file_path)
        messagebox.showinfo("Success", "File has been encrypted!")

    def decrypt_file(self):
        private_key = self.private_key_entry.get()
        input_file_path = filedialog.askopenfilename()
        output_file_path = filedialog.asksaveasfilename()
        decrypt_file(private_key, input_file_path, output_file_path)
        messagebox.showinfo("Success", "File has been decrypted!")

    def encrypt_message(self):
        public_key_hex = self.public_key_entry.get()
        message = self.message_entry.get()
        encrypted_data = encrypt(public_key_hex, message.encode())
        self.encrypted_message_entry.delete(0, tk.END)
        self.encrypted_message_entry.insert(0, encrypted_data.hex())
        self.show_result(encrypted_data.hex())

    def decrypt_message(self):
        private_key = self.private_key_entry.get()
        encrypted_data = bytes.fromhex(self.encrypted_message_entry.get())
        decrypted_data = decrypt(private_key, encrypted_data)
        self.show_result(decrypted_data.decode())
    

def get_transaction_hashes(address, api_key):
    url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&page=1&offset=10&sort=asc&apikey={api_key}"
    
    try:
        response = requests.get(url)
        response.raise_for_status()  # Check for HTTP errors

        data = response.json()
        if data['status'] == "1":
            transactions = data['result']
            txn_hashes = [txn['hash'] for txn in transactions]
            return txn_hashes
        else:
            print("API request was not successful.")
            return []

    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")
        return []

def pubkey_txn(provider, tx_hash):
    w3 = web3.Web3(web3.HTTPProvider(provider))
    tx = w3.eth.get_transaction(tx_hash)
    tx = dict(tx)

    type_0_keys = ['chainId', 'gas', 'gasPrice', 'nonce', 'to', 'value']
    type_1_keys = ["to", "nonce", "value", "gas", 'gasPrice', "chainId", "type"]
    type_2_keys = ["to", "nonce", "value", "gas", "chainId", "maxFeePerGas", "maxPriorityFeePerGas", "type"]

    s = w3.eth.account._keys.Signature(vrs=(
        to_standard_v(extract_chain_id(tx["v"])[1]),
        w3.to_int(tx["r"]),
        w3.to_int(tx["s"])
    ))

    if tx["type"] == 0:
        keys_to_get = type_0_keys
    elif tx["type"] == 1:
        keys_to_get = type_1_keys
    elif tx["type"] == 2:
        keys_to_get = type_2_keys

    if "chainId" not in tx:
        # !! This is hardcoded for ETH
        tx["chainId"] = 1

    tt = {k: tx[k] for k in keys_to_get}
    tt["data"] = tx["input"]

    ut = serializable_unsigned_transaction_from_dict(tt)
    recovered_public_key = s.recover_public_key_from_msg_hash(ut.hash())
    from_address = recovered_public_key.to_checksum_address()
    return recovered_public_key, from_address

def recover_public_key_from_private(private_key):
    private_key_bytes = bytes.fromhex(private_key)
    private_key_object = keys.PrivateKey(private_key_bytes)
    public_key = private_key_object.public_key
    uncompressed_public_key = public_key.to_hex()
    return uncompressed_public_key

def encrypt_with_public_key(public_key, message):
    encrypted = encrypt(public_key, message.encode())
    return encrypted

def decrypt_with_private_key(private_key, encrypted):
    decrypted = decrypt(private_key, encrypted)
    return decrypted.decode()



def encrypt_file(public_key_hex, input_file_path, output_file_path):
    with open(input_file_path, 'rb') as f:
        file_data = f.read()

    encrypted_data = encrypt(public_key_hex, file_data)
    
    with open(output_file_path, 'wb') as f:
        f.write(encrypted_data)

def decrypt_file(private_key_hex, input_file_path, output_file_path):
    with open(input_file_path, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = decrypt(private_key_hex, encrypted_data)
    
    with open(output_file_path, 'wb') as f:
        f.write(decrypted_data)

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
