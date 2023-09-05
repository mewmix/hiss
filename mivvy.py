import kivy
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.filechooser import FileChooserListView
from eth_keys import keys
from ecies import encrypt, decrypt
import web3
from eth_account._utils.signing import extract_chain_id, to_standard_v
from eth_account._utils.legacy_transactions import serializable_unsigned_transaction_from_dict

class Hiss(App):
    def build(self):
        self.root = BoxLayout(orientation='vertical')
        # we need to load a file path from the user


        self.get_provider_label = Label(text="Provider:")
        self.root.add_widget(self.get_provider_label)
        self.get_provider_label_entry = TextInput()
        self.root.add_widget(self.get_provider_label_entry)

        self.get_txn_hash_label = Label(text="Transaction Hash:")
        self.root.add_widget(self.get_txn_hash_label)
        self.get_txn_hash_label_entry = TextInput()
        self.root.add_widget(self.get_txn_hash_label_entry)

        self.get_public_key_txn_button = Button(text="Get Public Key from Transaction")
        self.get_public_key_txn_button.bind(on_press=self.get_public_key_txn)
        self.root.add_widget(self.get_public_key_txn_button)

        self.public_key_label = Label(text="Recipient's Public Key:")
        self.root.add_widget(self.public_key_label)

        self.public_key_entry = TextInput()
        self.root.add_widget(self.public_key_entry)

        self.message_label = Label(text="Secret Message:")
        self.root.add_widget(self.message_label)

        self.message_entry = TextInput()
        self.root.add_widget(self.message_entry)

        self.encrypt_button = Button(text="Encrypt")
        self.encrypt_button.bind(on_press=self.encrypt_message)
        self.root.add_widget(self.encrypt_button)

        self.private_key_label = Label(text="Your Private Key:")
        self.root.add_widget(self.private_key_label)

        self.private_key_entry = TextInput()
        self.root.add_widget(self.private_key_entry)

        self.encrypted_message_label = Label(text="Encrypted Message:")
        self.root.add_widget(self.encrypted_message_label)

        self.encrypted_message_entry = TextInput()
        self.root.add_widget(self.encrypted_message_entry)

        self.decrypt_button = Button(text="Decrypt")
        self.decrypt_button.bind(on_press=self.decrypt_message)
        self.root.add_widget(self.decrypt_button)

        self.result_label = Label(text="Result:")
        self.root.add_widget(self.result_label)

        self.result_text = TextInput()
        self.root.add_widget(self.result_text)

        self.copy_button = Button(text="Copy Result")
        self.copy_button.bind(on_press=self.copy_result)
        self.root.add_widget(self.copy_button)

        return self.root

    def get_public_key_txn(self, instance):
        provider = self.get_provider_label_entry.text
        tx_hash = self.get_txn_hash_label_entry.text
        recovered_public_key, from_address = pubkey_txn(provider, tx_hash)
        self.public_key_entry.text = recovered_public_key.to_hex()
        self.show_result(recovered_public_key.to_hex())

    def show_result(self, result):
        self.result_text.text = result

    def copy_result(self, instance):
        result = self.result_text.text
        kivy.clipboard.Clipboard.copy(result)
        self.show_result("Copied to clipboard!")

    def encrypt_file(self, instance):
        public_key_hex = self.public_key_entry.text
        input_file_path = self.message_entry.text
        output_file_path = self.encrypted_message_entry.text
        encrypt_file(public_key_hex, input_file_path, output_file_path)
        self.show_result("File encrypted!")


    def decrypt_file(self, instance):
        private_key_hex = self.private_key_entry.text
        input_file_path = self.encrypted_message_entry.text
        output_file_path = self.message_entry.text
        decrypt_file(private_key_hex, input_file_path, output_file_path)
        self.show_result("File decrypted!")


    def encrypt_message(self, instance):
        public_key_hex = self.public_key_entry.text
        message = self.message_entry.text
        encrypted_data = encrypt(public_key_hex, message.encode())
        self.encrypted_message_entry.text = encrypted_data.hex()
        self.show_result(encrypted_data.hex())

    def decrypt_message(self, instance):
        private_key = self.private_key_entry.text
        encrypted_data = bytes.fromhex(self.encrypted_message_entry.text)
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
    Hiss().run()
