"""
Basic RSA Usage Examples

This script demonstrates basic RSA operations including key generation,
encryption, decryption, and digital signatures.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.key_generation import generate_keypair
from src.rsa_core import encrypt, decrypt, sign, verify, encrypt_with_padding, decrypt_with_padding


def example_basic_encryption():
    """Demonstrate basic encryption and decryption."""
    print("\n" + "="*70)
    print("EXAMPLE 1: Basic Encryption and Decryption")
    print("="*70)
    
    # Generate key pair
    print("\nGenerating 1024-bit RSA key pair...")
    public_key, private_key = generate_keypair(1024)
    print(f"✓ Keys generated")
    print(f"  Public key: n={public_key.n}, e={public_key.exponent}")
    print(f"  Private key: n={private_key.n}, d={private_key.exponent}")
    
    # Encrypt message
    message = b"Hello, RSA!"
    print(f"\nOriginal message: {message}")
    
    ciphertext = encrypt(message, public_key)
    print(f"Ciphertext (as integer): {ciphertext}")
    
    # Decrypt message
    decrypted = decrypt(ciphertext, private_key)
    print(f"Decrypted message: {decrypted}")
    
    # Verify
    print(f"\nVerification: {message == decrypted}")


def example_digital_signature():
    """Demonstrate digital signatures."""
    print("\n" + "="*70)
    print("EXAMPLE 2: Digital Signatures")
    print("="*70)
    
    # Generate key pair
    print("\nGenerating 1024-bit RSA key pair...")
    public_key, private_key = generate_keypair(1024)
    print(f"✓ Keys generated")
    
    # Sign a message
    message = b"This is an authentic message"
    print(f"\nOriginal message: {message}")
    
    signature = sign(message, private_key)
    print(f"Digital signature: {signature}")
    
    # Verify signature
    is_valid = verify(message, signature, public_key)
    print(f"\nSignature verification: {is_valid}")
    
    # Try with tampered message
    tampered = b"This is a FAKE message"
    is_valid_tampered = verify(tampered, signature, public_key)
    print(f"Tampered message verification: {is_valid_tampered}")


def example_with_padding():
    """Demonstrate encryption with padding."""
    print("\n" + "="*70)
    print("EXAMPLE 3: Encryption with PKCS#1 v1.5 Padding")
    print("="*70)
    
    # Generate key pair
    print("\nGenerating 1024-bit RSA key pair...")
    public_key, private_key = generate_keypair(1024)
    print(f"✓ Keys generated")
    
    # Encrypt with padding
    message = b"Padded message for security"
    print(f"\nOriginal message: {message}")
    
    ciphertext = encrypt_with_padding(message, public_key)
    print(f"Ciphertext (with padding): {ciphertext}")
    
    # Decrypt with padding
    decrypted = decrypt_with_padding(ciphertext, private_key)
    print(f"Decrypted message: {decrypted}")
    
    # Verify
    print(f"\nVerification: {message == decrypted}")


def example_key_sizes():
    """Demonstrate different key sizes and their properties."""
    print("\n" + "="*70)
    print("EXAMPLE 4: Different Key Sizes")
    print("="*70)
    
    key_sizes = [512, 1024, 2048]
    
    for size in key_sizes:
        print(f"\nGenerating {size}-bit key pair...")
        public_key, private_key = generate_keypair(size)
        
        print(f"✓ {size}-bit keys generated")
        print(f"  Modulus n has {public_key.n.bit_length()} bits")
        print(f"  Public exponent e = {public_key.exponent}")
        print(f"  Private exponent d has {private_key.exponent.bit_length()} bits")


def main():
    """Run all examples."""
    print("\n" + "#"*70)
    print("# RSA BASIC USAGE EXAMPLES")
    print("#"*70)
    
    try:
        example_basic_encryption()
        example_digital_signature()
        example_with_padding()
        example_key_sizes()
        
        print("\n" + "="*70)
        print("✓ All examples completed successfully!")
        print("="*70)
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
