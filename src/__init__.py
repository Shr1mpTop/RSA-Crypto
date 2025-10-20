"""
RSA Crypto - RSA Implementation and Attack Demonstrations

This package provides a complete RSA implementation along with
demonstrations of various cryptographic attacks.
"""

from .rsa_core import RSAKey, encrypt, decrypt, sign, verify
from .key_generation import generate_keypair
from .utils import gcd, mod_inverse, is_prime

__version__ = "1.0.0"
__all__ = [
    "RSAKey",
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "generate_keypair",
    "gcd",
    "mod_inverse",
    "is_prime",
]
