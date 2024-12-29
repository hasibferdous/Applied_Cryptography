from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import pad, unpad
import os
import time


# Key definitions
key_3des = b"042431301100123456789012"  # Updated 24-byte key for 3DES

key_aes = b"0424313011000000"          # 16-byte key for AES
iv_3des = b"12345678"                  # 8-byte IV for 3DES
iv_aes = os.urandom(16)                # 16-byte IV for AES

# File sizes for testing
file_sizes = [1 * 1024 * 1024, 100 * 1024 * 1024, 1024 * 1024 * 1024]  # 1 MB, 100 MB, 1 GB
file_names = ["1MB.txt", "100MB.txt", "1GB.txt"]

# Generate test files
def generate_files():
    for size, name in zip(file_sizes, file_names):
        with open(name, "wb") as f:
            f.write(os.urandom(size))

# Encrypt a file and measure time
def encrypt_file(file_path, key, iv, cipher_type):
    with open(file_path, "rb") as f:
        data = f.read()

    if cipher_type == "3DES":
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
    elif cipher_type == "AES":
        cipher = AES.new(key, AES.MODE_CBC, iv)

    start_time = time.time()
    ciphertext = cipher.encrypt(pad(data, cipher.block_size))
    end_time = time.time()

    with open(file_path + f".{cipher_type.lower()}.enc", "wb") as f:
        f.write(ciphertext)

    return end_time - start_time

# Decrypt a file and measure time
def decrypt_file(file_path, key, iv, cipher_type):
    with open(file_path, "rb") as f:
        ciphertext = f.read()

    if cipher_type == "3DES":
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
    elif cipher_type == "AES":
        cipher = AES.new(key, AES.MODE_CBC, iv)

    start_time = time.time()
    data = unpad(cipher.decrypt(ciphertext), cipher.block_size)
    end_time = time.time()

    return end_time - start_time

# Test and measure performance
def test_algorithms():
    results = []

    for file_name in file_names:
        # 3DES Encryption and Decryption
        enc_time_3des = encrypt_file(file_name, key_3des, iv_3des, "3DES")
        dec_time_3des = decrypt_file(file_name + ".3des.enc", key_3des, iv_3des, "3DES")

        # AES-128 Encryption and Decryption
        enc_time_aes = encrypt_file(file_name, key_aes, iv_aes, "AES")
        dec_time_aes = decrypt_file(file_name + ".aes.enc", key_aes, iv_aes, "AES")

        results.append({
            "file": file_name,
            "3DES_enc_time": enc_time_3des,
            "3DES_dec_time": dec_time_3des,
            "AES_enc_time": enc_time_aes,
            "AES_dec_time": dec_time_aes,
        })

    return results

# Main execution
if __name__ == "__main__":
    generate_files()  # Generate files for testing
    performance_results = test_algorithms()

    # Print results
    for result in performance_results:
        print(f"File: {result['file']}")
        print(f"3DES - Encryption: {result['3DES_enc_time']:.4f}s, Decryption: {result['3DES_dec_time']:.4f}s")
        print(f"AES - Encryption: {result['AES_enc_time']:.4f}s, Decryption: {result['AES_dec_time']:.4f}s")
        print("-" * 50)

