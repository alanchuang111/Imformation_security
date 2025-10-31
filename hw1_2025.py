"""
AES-CBC and AES-OFB Implementation with Experimentation
Information Security and Management - Homework 1
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

def print_section(title):
    print("\n" + "="*70)
    print(f" {title}")


def print_hex(data, label):
    """Print data in hex format"""
    print(f"{label}: {data.hex()}")

# AES-CBC Mode Implementation

def aes_cbc_encrypt(plaintext, key, iv):
    """Encrypt using AES-CBC mode"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def aes_cbc_decrypt(ciphertext, key, iv):
    """Decrypt using AES-CBC mode"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    try:
        plaintext = unpad(padded_plaintext, AES.block_size)
        return plaintext
    except ValueError as e:
        return padded_plaintext  # Return without unpadding if it fails

# AES-OFB Mode Implementation

def aes_ofb_encrypt(plaintext, key, iv):
    """Encrypt using AES-OFB mode"""
    cipher = AES.new(key, AES.MODE_OFB, iv)
    ciphertext = cipher.encrypt(plaintext)  # OFB doesn't require padding
    return ciphertext

def aes_ofb_decrypt(ciphertext, key, iv):
    """Decrypt using AES-OFB mode"""
    cipher = AES.new(key, AES.MODE_OFB, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

# Experimentation Functions

def experiment_different_ivs():
    print_section("Experiment 1: Different IVs in Encryption")
    
    plaintext = b"This is a secret message for AES encryption testing!"
    key = get_random_bytes(16)  # AES-128
    
    # Test with different IVs
    iv1 = get_random_bytes(16)
    iv2 = get_random_bytes(16)
    iv3 = iv1  # Same as iv1
    
    print("\nPlaintext:", plaintext.decode())
    print_hex(key, "Key")
    
    print_hex(iv1, "IV1")
    print_hex(iv2, "IV2")
    print_hex(iv3, "IV3 (same as IV1)")

    # CBC with different IVs
    print("\n--- AES-CBC with Different IVs ---")
    ct1_cbc = aes_cbc_encrypt(plaintext, key, iv1)
    ct2_cbc = aes_cbc_encrypt(plaintext, key, iv2)
    ct3_cbc = aes_cbc_encrypt(plaintext, key, iv3)
    
    print_hex(ct1_cbc[:32], "Ciphertext1")
    print_hex(ct2_cbc[:32], "Ciphertext2")
    print_hex(ct3_cbc[:32], "Ciphertext3")
    
    # OFB with different IVs
    print("\n--- AES-OFB with Different IVs ---")
    ct1_ofb = aes_ofb_encrypt(plaintext, key, iv1)
    ct2_ofb = aes_ofb_encrypt(plaintext, key, iv2)
    ct3_ofb = aes_ofb_encrypt(plaintext, key, iv3)
    
    print_hex(ct1_ofb[:32], "Ciphertext1")
    print_hex(ct2_ofb[:32], "Ciphertext2")
    print_hex(ct3_ofb[:32], "Ciphertext3")


def experiment_modified_iv_decryption():
    print_section("Experiment 2: Modified IV in Decryption")
    
    plaintext = b"Block cipher modes are important for security!"
    key = get_random_bytes(16)
    iv_correct = get_random_bytes(16)
    iv_wrong = get_random_bytes(16)
    
    print("Original Plaintext:", plaintext.decode())
    
    # CBC Mode
    print("\n--- AES-CBC Mode ---")
    ciphertext_cbc = aes_cbc_encrypt(plaintext, key, iv_correct)
    print_hex(iv_correct, "Correct IV")
    print_hex(ciphertext_cbc, "Ciphertext")
    
    decrypted_correct = aes_cbc_decrypt(ciphertext_cbc, key, iv_correct)
    print("\nDecryption with CORRECT IV:", decrypted_correct.decode())
    
    decrypted_wrong = aes_cbc_decrypt(ciphertext_cbc, key, iv_wrong)
    print_hex(iv_wrong, "Wrong IV")
    print("Decryption with WRONG IV:", decrypted_wrong)
    
    
    # OFB Mode
    print("\n--- AES-OFB Mode ---")
    ciphertext_ofb = aes_ofb_encrypt(plaintext, key, iv_correct)
    
    decrypted_correct_ofb = aes_ofb_decrypt(ciphertext_ofb, key, iv_correct)
    print("Decryption with CORRECT IV:", decrypted_correct_ofb.decode())
    
    decrypted_wrong_ofb = aes_ofb_decrypt(ciphertext_ofb, key, iv_wrong)
    print("Decryption with WRONG IV:", decrypted_wrong_ofb)
    

def experiment_modified_ciphertext():

    print_section("Experiment 3: Modified Ciphertext")
    
    plaintext = b"Message authentication is crucial for data integrity!"
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    
    print("Original Plaintext:", plaintext.decode())
    
    # CBC Mode
    print("\n--- AES-CBC Mode ---")
    ciphertext_cbc = aes_cbc_encrypt(plaintext, key, iv)
    print_hex(ciphertext_cbc[:32], "Original Ciphertext")
    
    # Flip one bit in the second block
    modified_cbc = bytearray(ciphertext_cbc)
    modified_cbc[20] ^= 0x01  # Flip one bit
    modified_cbc = bytes(modified_cbc)
    
    decrypted_modified_cbc = aes_cbc_decrypt(modified_cbc, key, iv)
    print("\nDecryption with MODIFIED ciphertext:")
    print(decrypted_modified_cbc)
    
    # OFB Mode
    print("\n--- AES-OFB Mode ---")
    ciphertext_ofb = aes_ofb_encrypt(plaintext, key, iv)
    
    # Flip one bit
    modified_ofb = bytearray(ciphertext_ofb)
    modified_ofb[20] ^= 0x01
    modified_ofb = bytes(modified_ofb)
    
    decrypted_modified_ofb = aes_ofb_decrypt(modified_ofb, key, iv)
    print("Decryption with MODIFIED ciphertext:")
    print(decrypted_modified_ofb)
    
def experiment_wrong_key():
    """Experiment with wrong decryption key"""
    print_section("Experiment 4: Wrong Decryption Key")
    
    plaintext = b"The key is essential for decryption!"
    key_correct = get_random_bytes(16)
    key_wrong = get_random_bytes(16)
    iv = get_random_bytes(16)
    
    print("Original Plaintext:", plaintext.decode())
    
    # CBC Mode
    print("\n--- AES-CBC Mode ---")
    ciphertext_cbc = aes_cbc_encrypt(plaintext, key_correct, iv)
    
    decrypted_correct = aes_cbc_decrypt(ciphertext_cbc, key_correct, iv)
    print("Decryption with CORRECT key:", decrypted_correct.decode())
    
    decrypted_wrong = aes_cbc_decrypt(ciphertext_cbc, key_wrong, iv)
    print("Decryption with WRONG key:", decrypted_wrong)

    
    # OFB Mode
    print("\n--- AES-OFB Mode ---")
    ciphertext_ofb = aes_ofb_encrypt(plaintext, key_correct, iv)
    
    decrypted_wrong_ofb = aes_ofb_decrypt(ciphertext_ofb, key_wrong, iv)
    print("Decryption with WRONG key:", decrypted_wrong_ofb)



# Main
if __name__ == "__main__":

    
    # Run all experiments
    experiment_different_ivs()
    experiment_modified_iv_decryption()
    experiment_modified_ciphertext()
    experiment_wrong_key()
    
    print("\n" + "="*70)
    print(" SUMMARY OF KEY OBSERVATIONS")
    print("="*70)
    print("""
1. IV Requirements:
   - Both CBC and OFB require unique IVs for each encryption
   - Same IV with same key produces identical ciphertext (security risk)

2. IV Modification Impact:
   - CBC: Wrong IV only corrupts first block
   - OFB: Wrong IV corrupts entire plaintext

3. Ciphertext Modification:
   - CBC: Error propagates to current and next block
   - OFB: Error only affects corresponding bit (no propagation)

4. Wrong Key:
   - Both modes produce complete garbage with wrong key

5. Padding:
   - CBC: Requires padding to block size
   - OFB: Stream cipher mode, no padding needed

6. Security Considerations:
   - Never reuse IV with the same key
   - Use message authentication (MAC) to detect tampering
   - OFB is self-synchronizing for bit errors
   - CBC provides error propagation (tamper-evident)
    """)
    