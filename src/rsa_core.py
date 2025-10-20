"""
RSA Core Implementation

This module provides the core RSA encryption/decryption functionality,
including key generation, encryption, decryption, and digital signatures.
"""

import random
from typing import Tuple
from .utils import mod_inverse, bytes_to_int, int_to_bytes


class RSAKey:
    """Represents an RSA key (public or private)"""
    
    def __init__(self, n: int, exponent: int, key_type: str = "public"):
        """
        Initialize an RSA key.
        
        Args:
            n: The modulus
            exponent: The exponent (e for public, d for private)
            key_type: Either "public" or "private"
        """
        self.n = n
        self.exponent = exponent
        self.key_type = key_type
        self.bit_length = n.bit_length()
    
    def __repr__(self):
        return f"RSAKey(type={self.key_type}, bits={self.bit_length}, n={hex(self.n)[:20]}..., exp={self.exponent})"


def encrypt(message: bytes, public_key: RSAKey) -> int:
    """
    Encrypt a message using RSA public key.
    
    Args:
        message: The plaintext message as bytes
        public_key: The RSA public key
    
    Returns:
        The ciphertext as an integer
    """
    # Convert message to integer
    m = bytes_to_int(message)
    
    # Check if message is too long
    if m >= public_key.n:
        raise ValueError("Message too long for key size")
    
    # Perform RSA encryption: c = m^e mod n
    c = pow(m, public_key.exponent, public_key.n)
    return c


def decrypt(ciphertext: int, private_key: RSAKey) -> bytes:
    """
    Decrypt a ciphertext using RSA private key.
    
    Args:
        ciphertext: The ciphertext as an integer
        private_key: The RSA private key
    
    Returns:
        The decrypted message as bytes
    """
    # Perform RSA decryption: m = c^d mod n
    m = pow(ciphertext, private_key.exponent, private_key.n)
    
    # Convert integer back to bytes
    message = int_to_bytes(m)
    return message


def sign(message: bytes, private_key: RSAKey) -> int:
    """
    Create a digital signature for a message.
    
    Args:
        message: The message to sign
        private_key: The RSA private key
    
    Returns:
        The signature as an integer
    """
    # Convert message to integer
    m = bytes_to_int(message)
    
    # Check if message is too long
    if m >= private_key.n:
        raise ValueError("Message too long for key size")
    
    # Sign: s = m^d mod n
    signature = pow(m, private_key.exponent, private_key.n)
    return signature


def verify(message: bytes, signature: int, public_key: RSAKey) -> bool:
    """
    Verify a digital signature.
    
    Args:
        message: The original message
        signature: The signature to verify
        public_key: The RSA public key
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Verify: m' = s^e mod n
        m_prime = pow(signature, public_key.exponent, public_key.n)
        
        # Convert message to integer
        m = bytes_to_int(message)
        
        # Compare
        return m == m_prime
    except Exception:
        return False


def encrypt_with_padding(message: bytes, public_key: RSAKey) -> int:
    """
    Encrypt a message with PKCS#1 v1.5 padding.
    
    Args:
        message: The plaintext message
        public_key: The RSA public key
    
    Returns:
        The ciphertext as an integer
    """
    # Calculate key size in bytes
    k = (public_key.bit_length + 7) // 8
    
    # Calculate required padding length
    mLen = len(message)
    if mLen > k - 11:
        raise ValueError("Message too long for key size with padding")
    
    # Create padding: 0x00 || 0x02 || PS || 0x00 || M
    # PS is random non-zero bytes, at least 8 bytes
    ps_len = k - mLen - 3
    ps = bytes([random.randint(1, 255) for _ in range(ps_len)])
    
    padded = b'\x00\x02' + ps + b'\x00' + message
    
    # Encrypt padded message
    return encrypt(padded, public_key)


def decrypt_with_padding(ciphertext: int, private_key: RSAKey) -> bytes:
    """
    Decrypt a message and remove PKCS#1 v1.5 padding.
    
    Args:
        ciphertext: The ciphertext as an integer
        private_key: The RSA private key
    
    Returns:
        The decrypted message without padding
    """
    # Decrypt
    padded = decrypt(ciphertext, private_key)
    
    # Check padding format
    if len(padded) < 11:
        raise ValueError("Decryption error: invalid padding")
    
    if padded[0:2] != b'\x00\x02':
        raise ValueError("Decryption error: invalid padding format")
    
    # Find the 0x00 separator
    separator_index = padded.find(b'\x00', 2)
    if separator_index == -1:
        raise ValueError("Decryption error: no separator found")
    
    # Extract message
    message = padded[separator_index + 1:]
    return message


if __name__ == "__main__":
    # Simple test
    from .key_generation import generate_keypair
    
    print("Testing RSA Core Implementation...")
    print("-" * 50)
    
    # Generate keys
    print("Generating 1024-bit key pair...")
    public_key, private_key = generate_keypair(1024)
    print(f"Public key: {public_key}")
    print(f"Private key: {private_key}")
    print()
    
    # Test encryption/decryption
    message = b"Hello, RSA!"
    print(f"Original message: {message}")
    
    ciphertext = encrypt(message, public_key)
    print(f"Ciphertext: {ciphertext}")
    
    decrypted = decrypt(ciphertext, private_key)
    print(f"Decrypted message: {decrypted}")
    print(f"Match: {message == decrypted}")
    print()
    
    # Test signature
    signature = sign(message, private_key)
    print(f"Signature: {signature}")
    
    valid = verify(message, signature, public_key)
    print(f"Signature valid: {valid}")
    
    invalid = verify(b"Wrong message", signature, public_key)
    print(f"Invalid signature: {not invalid}")
