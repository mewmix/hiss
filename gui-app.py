import tkinter as tk
from tkinter import filedialog
from eth_keys import keys
from ecies import encrypt, decrypt
from stegano import lsb
import web3
from eth_account._utils.signing import extract_chain_id, to_standard_v
from eth_account._utils.legacy_transactions import serializable_unsigned_transaction_from_dict
import os
from ecies import encrypt, decrypt

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Crypto Toolbox")

        # Create buttons
        self.pubkey_txn_btn = tk.Button(self.root, text="Pubkey Txn", command=self.pubkey_txn)
        self.recover_pubkey_btn = tk.Button(self.root, text="Recover Public Key", command=self.recover_public_key)
        self.encrypt_msg_btn = tk.Button(self.root, text="Encrypt Message", command=self.encrypt_message)
        self.decrypt_msg_btn = tk.Button(self.root, text="Decrypt Message", command=self.decrypt_message)
        self.encrypt_file_btn = tk.Button(self.root, text="Encrypt File", command=self.encrypt_file)
        self.decrypt_file_btn = tk.Button(self.root, text="Decrypt File", command=self.decrypt_file)

        # Arrange buttons in a grid
        self.pubkey_txn_btn.grid(row=0, column=0, padx=10, pady=5)
        self.recover_pubkey_btn.grid(row=1, column=0, padx=10, pady=5)
        self.encrypt_msg_btn.grid(row=2, column=0, padx=10, pady=5)
        self.decrypt_msg_btn.grid(row=3, column=0, padx=10, pady=5)
        self.encrypt_file_btn.grid(row=4, column=0, padx=10, pady=5)
        self.decrypt_file_btn.grid(row=5, column=0, padx=10, pady=5)

    def pubkey_txn(self):
        provider = input("Enter provider URL: ")  # User input
        tx_hash = input("Enter transaction hash: ")  # User input
        public_key, from_address = pubkey_txn(provider, tx_hash)
        result = f"Recovered Public Key: {public_key}\nFrom Address: {from_address}"
        self.show_result(result)

    def recover_public_key(self):
        private_key = input("Enter private key: ")  # User input
        public_key = recover_public_key_from_private(private_key)
        result = f"Recovered Public Key: {public_key}"
        self.show_result(result)

    def encrypt_message(self):
        public_key = input("Enter recipient's public key: ")  # User input
        message = input("Enter your secret message: ")  # User input
        encrypted_message = encrypt_with_public_key(public_key, message)
        self.show_result(encrypted_message)

    def decrypt_message(self):
        private_key = input("Enter your private key: ")  # User input
        encrypted_message = input("Enter encrypted message bytes: ")  # User input
        decrypted_message = decrypt_with_private_key(private_key, encrypted_message)
        self.show_result(decrypted_message)

    def encrypt_file(self):
        public_key = input("Enter recipient's public key: ")  # User input
        input_file_path = filedialog.askopenfilename(title="Select a file to encrypt")
        if input_file_path:
            output_file_path = filedialog.asksaveasfilename(title="Save encrypted file as")
            if output_file_path:
                encrypt_file(public_key, input_file_path, output_file_path)
                self.show_result("File encrypted and saved.")

    def decrypt_file(self):
        private_key = input("Enter your private key: ")  # User input
        input_file_path = filedialog.askopenfilename(title="Select a file to decrypt")
        if input_file_path:
            output_file_path = filedialog.asksaveasfilename(title="Save decrypted file as")
            if output_file_path:
                decrypt_file(private_key, input_file_path, output_file_path)
                self.show_result("File decrypted and saved.")

    def show_result(self, result):
        result_window = tk.Toplevel(self.root)
        result_window.title("Result")
        result_label = tk.Label(result_window, text=result, padx=10, pady=10)
        result_label.pack()


  
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
