"""
Unit Tests for RSA Core Functionality
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.key_generation import generate_keypair
from src.rsa_core import encrypt, decrypt, sign, verify, RSAKey


class TestRSACore(unittest.TestCase):
    """Test cases for RSA core functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.key_size = 512
        self.public_key, self.private_key = generate_keypair(self.key_size)
    
    def test_key_generation(self):
        """Test that key generation produces valid keys."""
        self.assertIsInstance(self.public_key, RSAKey)
        self.assertIsInstance(self.private_key, RSAKey)
        self.assertEqual(self.public_key.n, self.private_key.n)
        self.assertGreater(self.public_key.n, 0)
        self.assertGreater(self.public_key.exponent, 0)
        self.assertGreater(self.private_key.exponent, 0)
    
    def test_encryption_decryption(self):
        """Test basic encryption and decryption."""
        message = b"Test message"
        
        ciphertext = encrypt(message, self.public_key)
        self.assertIsInstance(ciphertext, int)
        self.assertGreater(ciphertext, 0)
        
        decrypted = decrypt(ciphertext, self.private_key)
        self.assertEqual(message, decrypted)
    
    def test_encryption_different_messages(self):
        """Test that different messages produce different ciphertexts."""
        message1 = b"Message 1"
        message2 = b"Message 2"
        
        ciphertext1 = encrypt(message1, self.public_key)
        ciphertext2 = encrypt(message2, self.public_key)
        
        self.assertNotEqual(ciphertext1, ciphertext2)
    
    def test_digital_signature(self):
        """Test digital signature creation and verification."""
        message = b"Important document"
        
        signature = sign(message, self.private_key)
        self.assertIsInstance(signature, int)
        
        # Valid signature
        self.assertTrue(verify(message, signature, self.public_key))
        
        # Invalid signature (wrong message)
        self.assertFalse(verify(b"Wrong message", signature, self.public_key))
    
    def test_signature_wrong_key(self):
        """Test that signature fails with wrong public key."""
        message = b"Signed message"
        signature = sign(message, self.private_key)
        
        # Generate different key pair
        other_public, _ = generate_keypair(512)
        
        # Should fail with wrong key
        self.assertFalse(verify(message, signature, other_public))
    
    def test_message_too_long(self):
        """Test that overly long messages raise an error."""
        # Create message longer than modulus
        long_message = b"x" * (self.key_size // 8 + 10)
        
        with self.assertRaises(ValueError):
            encrypt(long_message, self.public_key)
    
    def test_multiple_encryptions(self):
        """Test multiple encryption/decryption cycles."""
        messages = [b"Test 1", b"Test 2", b"Test 3"]
        
        for msg in messages:
            ct = encrypt(msg, self.public_key)
            decrypted = decrypt(ct, self.private_key)
            self.assertEqual(msg, decrypted)


class TestRSAKeyClass(unittest.TestCase):
    """Test cases for RSAKey class."""
    
    def test_key_creation(self):
        """Test RSAKey object creation."""
        n = 12345
        e = 65537
        key = RSAKey(n, e, "public")
        
        self.assertEqual(key.n, n)
        self.assertEqual(key.exponent, e)
        self.assertEqual(key.key_type, "public")
    
    def test_bit_length(self):
        """Test that bit_length property works."""
        n = 2**1023 + 1  # 1024-bit number
        key = RSAKey(n, 65537)
        
        self.assertEqual(key.bit_length, 1024)


if __name__ == "__main__":
    unittest.main()
