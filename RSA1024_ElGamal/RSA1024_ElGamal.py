import time
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from sympy import mod_inverse

# Define the key
KEY = "0424313011"  # Stored as a string for compatibility
KEY_INT = int(KEY)  # Convert to integer when needed


# Function to read file
def read_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()


# RSA Implementation
def rsa_setup():
    rsa_key = RSA.generate(1024)
    private_key = rsa_key.export_key()
    public_key = rsa_key.publickey().export_key()
    return private_key, public_key


def rsa_encrypt(data, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)

    # Calculate maximum block size
    max_block_size = rsa_key.size_in_bytes() - 2 * cipher._hashObj.digest_size - 2

    encrypted_data = b""
    for i in range(0, len(data), max_block_size):
        chunk = data[i:i + max_block_size]
        encrypted_data += cipher.encrypt(chunk)
    return encrypted_data


def rsa_decrypt(data, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)

    block_size = rsa_key.size_in_bytes()
    decrypted_data = b""
    for i in range(0, len(data), block_size):
        chunk = data[i:i + block_size]
        decrypted_data += cipher.decrypt(chunk)
    return decrypted_data


# ElGamal Implementation
def elgamal_setup():
    p = 29996224275833  # Large prime number
    g = 2  # Primitive root modulo p
    x = KEY_INT  # Private key
    h = pow(g, x, p)  # Public key component
    return (p, g, h), x


def elgamal_encrypt(data, public_key):
    p, g, h = public_key
    m = int.from_bytes(data, 'big')
    k = random.randint(1, p - 2)
    c1 = pow(g, k, p)
    c2 = (m * pow(h, k, p)) % p
    return c1, c2


def elgamal_decrypt(ciphertext, private_key, public_key):
    c1, c2 = ciphertext
    p, _, _ = public_key
    s = pow(c1, private_key, p)
    s_inv = mod_inverse(s, p)
    m = (c2 * s_inv) % p
    return m.to_bytes((m.bit_length() + 7) // 8, 'big')


# Benchmarking Function
def benchmark(file_paths):
    # Generate RSA keys
    rsa_private, rsa_public = rsa_setup()

    # Generate ElGamal keys
    elgamal_public, elgamal_private = elgamal_setup()

    # Test each file
    results = []
    for file_path in file_paths:
        print(f"\nTesting file: {file_path}")
        data = read_file(file_path)

        # RSA Benchmark
        print("\n--- RSA ---")
        start = time.time()
        rsa_encrypted = rsa_encrypt(data, rsa_public)
        rsa_encryption_time = time.time() - start
        print(f"RSA Encryption Time: {rsa_encryption_time:.6f} seconds")

        start = time.time()
        rsa_decrypted = rsa_decrypt(rsa_encrypted, rsa_private)
        rsa_decryption_time = time.time() - start
        print(f"RSA Decryption Time: {rsa_decryption_time:.6f} seconds")

        # ElGamal Benchmark
        print("\n--- ElGamal ---")
        start = time.time()
        elgamal_encrypted = elgamal_encrypt(data, elgamal_public)
        elgamal_encryption_time = time.time() - start
        print(f"ElGamal Encryption Time: {elgamal_encryption_time:.6f} seconds")

        start = time.time()
        elgamal_decrypted = elgamal_decrypt(elgamal_encrypted, elgamal_private, elgamal_public)
        elgamal_decryption_time = time.time() - start
        print(f"ElGamal Decryption Time: {elgamal_decryption_time:.6f} seconds")

        # Store results
        results.append({
            "file": file_path,
            "rsa_encryption_time": rsa_encryption_time,
            "rsa_decryption_time": rsa_decryption_time,
            "elgamal_encryption_time": elgamal_encryption_time,
            "elgamal_decryption_time": elgamal_decryption_time,
        })

    return results


# File paths for benchmarking
file_paths = ["1MB.txt", "100MB.txt", "1GB.txt"]

# Run the benchmark
results = benchmark(file_paths)

# Display final results
print("\n--- Comparative Analysis ---")
for result in results:
    print(f"\nFile: {result['file']}")
    print(f"RSA Encryption Time: {result['rsa_encryption_time']:.6f} seconds")
    print(f"RSA Decryption Time: {result['rsa_decryption_time']:.6f} seconds")
    print(f"ElGamal Encryption Time: {result['elgamal_encryption_time']:.6f} seconds")
    print(f"ElGamal Decryption Time: {result['elgamal_decryption_time']:.6f} seconds")
