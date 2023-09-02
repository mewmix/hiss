

```markdown

#Windows

# Hiss README

This repository contains Python script kiddy funcs for various Ethereum-related ECIES tools, including recovering public keys from transactions, encrypting and decrypting messages, and more.

Credit to the original author of the public key from transaction hash dev in this linked issue -

## Prerequisites

Make sure you have the following dependencies installed:

- Python 3.x
- `eth-keys` library
- `ecies` library
- `web3` library

You can install these dependencies using the following command:

git clone https://github.com/mewmix/hiss

pip install -r requirements.txt


And then to run the GUI

python hiss-gui.py

```

#SCREENSHOTS

<img width="289" alt="1" 
src="https://github.com/mewmix/hiss/assets/42463809/c98d43b6-8f94-46d8-8502-c3b1cd7dafcb">
<img width="673" alt="2" 
src="https://github.com/mewmix/hiss/assets/42463809/9752b3c5-ccbb-4f99-a974-82ee25e7332b">
<img width="680" alt="3" 
src="https://github.com/mewmix/hiss/assets/42463809/794356d5-2dac-4882-a3f1-3b130ac4fbda">
<img width="341" alt="Screen Shot 2023-08-31 at 9 05 42 PM" src="https://github.com/mewmix/hiss/assets/42463809/1d01a6bf-f336-4c79-ad0d-9492cd73f862">
## Usage

### Recover Public Key from Private Key

You can recover the public key corresponding to a given private key using the provided function:

```python
private_key = 'YOUR_PRIVATE_KEY_HERE'
recovered_public_key = recover_public_key_from_private(private_key)
print("Recovered Public Key:", recovered_public_key)
```

### Encrypt and Decrypt Messages

Encrypting and decrypting messages using ECIES is demonstrated in the following example:

```python
private_key = 'YOUR_PRIVATE_KEY_HERE'
message = 'Hello, ECIES!'

# Recover public key from private key
recovered_public_key = recover_public_key_from_private(private_key)

# Encrypt the message
encrypted_data = encrypt_with_public_key(recovered_public_key, message)

# Decrypt the message
decrypted_message = decrypt_with_private_key(private_key, encrypted_data)

print("Encrypted:", encrypted_data.hex())
print("Decrypted:", decrypted_message)
```

### Recover Public Key and From Address from Transaction

To recover the public key and "from" address of a transaction, use the `pubkey_txn` function:

```python
provider = 'YOUR_ETHEREUM_PROVIDER_URL'
tx_hash = 'YOUR_TRANSACTION_HASH_HERE'

recovered_public_key, from_address = pubkey_txn(provider, tx_hash)
print("Recovered Public Key:", recovered_public_key.to_hex())
print("From Address:", from_address)
```

### Encrypt and Decrypt Files

Encrypting and decrypting files using ECIES is demonstrated in the provided functions:

```python
public_key_hex = 'RECIPIENT_PUBLIC_KEY_HEX'
input_file_path = 'path/to/input/file'
output_file_path = 'path/to/output/file'

# Encrypt a file
encrypt_file(public_key_hex, input_file_path, output_file_path)

private_key_hex = 'YOUR_PRIVATE_KEY_HEX'

# Decrypt a file
decrypt_file(private_key_hex, input_file_path, output_file_path)
```

### Finding Latest Transaction Hash for Address

To find the latest transaction hash for a specific Ethereum address, use the `latest_hash` function:

```python
provider = 'YOUR_ETHEREUM_PROVIDER_URL'
address = 'TARGET_ETHEREUM_ADDRESS'

latest_tx_hash = latest_hash(provider, address)
if latest_tx_hash:
    print(f"Latest Transaction Hash for {address}: {latest_tx_hash}")
else:
    print(f"No transactions found for {address}.")
```

## Note

- Make sure to replace placeholders like `'YOUR_PRIVATE_KEY_HERE'`, `'RECIPIENT_PUBLIC_KEY_HEX'`, `'YOUR_TRANSACTION_HASH_HERE'`, `'YOUR_ETHEREUM_PROVIDER_URL'`, and `'TARGET_ETHEREUM_ADDRESS'` with actual values.
- This code is intended for educational and informational purposes. 

```

Feel free to customize the instructions and explanations as needed. Remember to replace the placeholders with actual values and adapt the document to your repository's structure and context.
