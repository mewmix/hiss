from eth_keys import keys
from ecies import encrypt, decrypt

import web3
from eth_account._utils.signing import extract_chain_id, to_standard_v
from eth_account._utils.legacy_transactions import serializable_unsigned_transaction_from_dict
import requests

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



def latest_hash(provider, address):
    w3 = web3.Web3(web3.HTTPProvider(provider))
    latest_block_number = w3.eth.block_number

    for block_number in range(latest_block_number, -1, -1):
        block = w3.eth.get_block(block_number)
        for tx_hash in block.transactions:
            tx = w3.eth.get_transaction(tx_hash)
            if tx['from'].lower() == address.lower():
                print(f"Transaction found for {address}.")
                return tx_hash.hex()

    print(f"No transactions found for {address}.")
    return None


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


# Example Ethereum private key
private_key = ''

# Recover public key from private key
recovered_public_private_key = recover_public_key_from_private(private_key)
print("Recovered from Private Key - Public Key:", recovered_public_private_key)

# Example message
message = 'Hello, ECIES!'

# Encrypt and then decrypt the message
encrypted_data = encrypt_with_public_key(recovered_public_private_key, message)
decrypted_message = decrypt_with_private_key(private_key, encrypted_data)

print("Encrypted:", encrypted_data.hex())
print("Decrypted:", decrypted_message)

recovered_public_key, from_address = pubkey_txn(provider='', tx_hash="0x8e6e0ed7025ede7bd89e82893ebee53c1fc459cfe7cd862fe39fe8c2042a2984")
# Print the recovered public key and from address
print("Recovered Public Key:", recovered_public_key.to_hex())
print("From Address:", from_address)
