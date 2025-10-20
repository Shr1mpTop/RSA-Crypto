"""
Unit Tests for RSA Attacks
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.key_generation import (
    generate_weak_keypair_small_primes,
    generate_weak_keypair_close_primes,
    generate_weak_keypair_small_d,
    generate_keypair
)
from src.rsa_core import encrypt, decrypt, RSAKey
from src.attacks.small_prime import small_prime_attack
from src.attacks.fermat import fermat_attack
from src.attacks.common_modulus import common_modulus_attack
from src.utils import bytes_to_int, gcd


class TestSmallPrimeAttack(unittest.TestCase):
    """Test cases for small prime factorization attack."""
    
    def test_small_prime_attack(self):
        """Test that small prime attack works on weak keys."""
        # Generate weak key
        public_key, private_key = generate_weak_keypair_small_primes(256)
        
        # Encrypt a message
        message = b"Secret"
        ciphertext = encrypt(message, public_key)
        
        # Attack
        recovered_key = small_prime_attack(public_key)
        
        # Verify
        decrypted = decrypt(ciphertext, recovered_key)
        self.assertEqual(message, decrypted)


class TestFermatAttack(unittest.TestCase):
    """Test cases for Fermat's factorization attack."""
    
    def test_fermat_attack(self):
        """Test that Fermat's attack works on close primes."""
        # Generate weak key with close primes
        public_key, private_key = generate_weak_keypair_close_primes(256)
        
        # Encrypt a message
        message = b"Close!"
        ciphertext = encrypt(message, public_key)
        
        # Attack
        recovered_key = fermat_attack(public_key, max_iterations=10000)
        
        # Verify
        decrypted = decrypt(ciphertext, recovered_key)
        self.assertEqual(message, decrypted)


class TestCommonModulusAttack(unittest.TestCase):
    """Test cases for common modulus attack."""
    
    def test_common_modulus_attack(self):
        """Test that common modulus attack works."""
        from src.utils import mod_inverse
        
        # Generate a keypair
        pub1, priv1 = generate_keypair(512)
        n = pub1.n
        e1 = pub1.exponent
        
        # Create second key with same n but different e
        e2 = 3
        phi = (priv1.p - 1) * (priv1.q - 1)
        while gcd(e2, phi) != 1:
            e2 += 2
        
        # Encrypt same message with both keys
        message = b"Test"
        m = bytes_to_int(message)
        
        c1 = pow(m, e1, n)
        c2 = pow(m, e2, n)
        
        # Attack
        recovered_m = common_modulus_attack(c1, c2, e1, e2, n)
        
        # Verify
        self.assertEqual(m, recovered_m)


class TestAttackFailures(unittest.TestCase):
    """Test that attacks fail on secure parameters."""
    
    def test_small_prime_attack_fails_on_secure_key(self):
        """Test that small prime attack fails on secure keys."""
        # Generate secure key
        public_key, _ = generate_keypair(512)
        
        # Attack should fail
        with self.assertRaises(ValueError):
            small_prime_attack(public_key, max_prime=10000)
    
    def test_common_modulus_requires_coprime_exponents(self):
        """Test that common modulus attack requires coprime exponents."""
        n = 12345
        e1 = 6
        e2 = 9  # gcd(6, 9) = 3, not coprime
        c1 = 100
        c2 = 200
        
        with self.assertRaises(ValueError):
            common_modulus_attack(c1, c2, e1, e2, n)


if __name__ == "__main__":
    unittest.main()
