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
from tkinter import messagebox

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Hissssss")


        self.encrypt_file_button = tk.Button(self.root, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_file_button.pack()
        self.decrypt_file_button = tk.Button(self.root, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_file_button.pack()



        self.public_key_label = tk.Label(self.root, text="Recipient's Public Key:")
        self.public_key_label.pack()

        self.public_key_entry = tk.Entry(self.root)
        self.public_key_entry.pack()

        self.message_label = tk.Label(self.root, text="Secret Message:")
        self.message_label.pack()

        self.message_entry = tk.Entry(self.root)
        self.message_entry.pack()

        self.encrypt_button = tk.Button(self.root, text="Encrypt", command=self.encrypt_message)
        self.encrypt_button.pack()

        self.private_key_label = tk.Label(self.root, text="Your Private Key:")
        self.private_key_label.pack()

        self.private_key_entry = tk.Entry(self.root)
        self.private_key_entry.pack()

        self.encrypted_message_label = tk.Label(self.root, text="Encrypted Message:")
        self.encrypted_message_label.pack()

        self.encrypted_message_entry = tk.Entry(self.root)
        self.encrypted_message_entry.pack()

        self.decrypt_button = tk.Button(self.root, text="Decrypt", command=self.decrypt_message)
        self.decrypt_button.pack()

        self.result_label = tk.Label(self.root, text="Result:")
        self.result_label.pack()

        self.result_text = tk.Text(self.root, height=5, width=40)
        self.result_text.pack()

        self.copy_button = tk.Button(self.root, text="Copy Result", command=self.copy_result)
        self.copy_button.pack()
    

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
