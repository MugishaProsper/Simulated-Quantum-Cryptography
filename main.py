import hashlib
import os
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def generate_quantum_key(length: int = 16):
    return os.urandom(length)

# Quantum-inspired hash function using SHA-256
def quantum_inspired_hash(input_text: str, quantum_key: bytes) -> str:
    """Simulate quantum hashing by combining input with quantum key."""
    combined_input = input_text.encode() + quantum_key
    return hashlib.sha256(combined_input).hexdigest()

def encrypt_message(message: str, secret_key: bytes) -> str:
    cipher = AES.new(secret_key, AES.MODE_CBC)  # Using CBC mode
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct  # Return both IV and ciphertext

def decrypt_message(encrypted_message: str, secret_key: bytes) -> str:
    iv = base64.b64decode(encrypted_message[:24])
    ct = base64.b64decode(encrypted_message[24:])
    cipher = AES.new(secret_key, AES.MODE_CBC, iv=iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size)
    return decrypted.decode('utf-8')

# Alice sends the message to Bob
def alice_send_message(message: str, secret_key: bytes):
    """Simulate Alice sending a message with encrypted hash."""
    quantum_key = generate_quantum_key()
    quantum_hash = quantum_inspired_hash(message, quantum_key)

    # Encrypt the hash with the secret key
    encrypted_hash = encrypt_message(quantum_hash, secret_key)

    # Return message, encrypted hash, and the quantum key (only for simulation)
    return message, encrypted_hash, quantum_key

# Bob receives and verifies the message
def bob_receive_message(encrypted_message: str, encrypted_hash: str, quantum_key: bytes, secret_key: bytes):
    """Simulate Bob receiving and verifying the message."""
    # Decrypt the message and hash
    decrypted_message = decrypt_message(encrypted_message, secret_key)
    decrypted_hash = decrypt_message(encrypted_hash, secret_key)

    # Recalculate the hash of the decrypted message with the quantum key
    recalculated_hash = quantum_inspired_hash(decrypted_message, quantum_key)

    # Check if the recalculated hash matches the decrypted hash
    if recalculated_hash == decrypted_hash:
        return f"Message integrity verified. Message: {decrypted_message}"
    else:
        return "Hash mismatch! Message might have been tampered with."


secret_key = os.urandom(16)

message = input("Enter your message: ")
encrypted_message, encrypted_hash, quantum_key = alice_send_message(message, secret_key)

print(f"Encrypted message: {encrypted_message}")
print(f"Encrypted hash: {encrypted_hash}")

# Bob receives the message and verifies it
verification_result = bob_receive_message(encrypted_message, encrypted_hash, quantum_key, secret_key)
print(verification_result)
