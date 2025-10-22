"""
RSA Key Generation Module

This module provides secure RSA key generation using the Miller-Rabin
primality test and proper parameter selection.
"""

import random
from typing import Tuple
from .utils import is_prime, gcd, mod_inverse
from .rsa_core import RSAKey


def generate_prime(bits: int) -> int:
    """
    Generate a random prime number of specified bit length.
    
    Args:
        bits: The desired bit length of the prime
    
    Returns:
        A prime number of the specified bit length
    """
    while True:
        # Generate random odd number
        num = random.getrandbits(bits)
        # Ensure it's odd and has the right bit length
        num |= (1 << bits - 1) | 1
        
        if is_prime(num):
            return num


def generate_keypair(bits: int = 2048, e: int = 65537) -> Tuple[RSAKey, RSAKey]:
    """
    Generate an RSA key pair.
    
    Args:
        bits: The bit length of the modulus (default: 2048)
        e: The public exponent (default: 65537)
    
    Returns:
        A tuple of (public_key, private_key)
    """
    print(f"Generating {bits}-bit RSA key pair...")
    
    # Generate two distinct primes p and q
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    
    # Ensure p != q
    while p == q:
        q = generate_prime(bits // 2)
    
    # Calculate modulus
    n = p * q
    
    # Calculate Euler's totient function
    phi = (p - 1) * (q - 1)
    
    # Ensure e is coprime with phi
    if gcd(e, phi) != 1:
        raise ValueError(f"e={e} is not coprime with phi(n)")
    
    # Calculate private exponent d
    d = mod_inverse(e, phi)
    
    # Create key objects
    public_key = RSAKey(n, e, "public")
    private_key = RSAKey(n, d, "private")
    
    print(f"✓ Key generation complete")
    return public_key, private_key


def generate_weak_keypair_small_primes(bits: int = 2048, e: int = 65537) -> Tuple[RSAKey, RSAKey]:
    """
    Generate a weak RSA key pair with small primes (for demonstration).
    
    WARNING: This generates intentionally weak keys for educational purposes.
    NEVER use this in production!
    
    Args:
        bits: The bit length of the modulus
        e: The public exponent
    
    Returns:
        A tuple of (public_key, private_key) with weak parameters
    """
    print(f"⚠️ Generating WEAK {bits}-bit RSA key pair (small primes)...")
    
    # Generate small primes (24 bits each - small enough for fast trial division)
    # This results in n ≈ 48 bits, which can be factored quickly with trial division
    # Note: Message must be very short (1-5 bytes)
    p = generate_prime(24)
    q = generate_prime(24)
    
    # Ensure p != q
    while p == q:
        q = generate_prime(24)
    
    # Calculate modulus (will be ~48 bits, much smaller than requested bits)
    n = p * q
    
    # Note: n will be much smaller than the requested bit size,
    # but that's intentional for this weak key demonstration
    
    # Calculate phi
    phi = (p - 1) * (q - 1)
    
    # Calculate d
    d = mod_inverse(e, phi)
    
    public_key = RSAKey(n, e, "public")
    private_key = RSAKey(n, d, "private")
    
    # Store p and q for attack demonstration
    private_key.p = p
    private_key.q = q
    
    print(f"✓ Weak key generation complete (p={p}, q={q})")
    return public_key, private_key


def generate_weak_keypair_close_primes(bits: int = 2048, e: int = 65537) -> Tuple[RSAKey, RSAKey]:
    """
    Generate a weak RSA key pair with close primes (vulnerable to Fermat's attack).
    
    WARNING: This generates intentionally weak keys for educational purposes.
    
    Args:
        bits: The bit length of the modulus
        e: The public exponent
    
    Returns:
        A tuple of (public_key, private_key) with close primes
    """
    print(f"⚠️ Generating WEAK {bits}-bit RSA key pair (close primes)...")
    
    # Generate first prime
    p = generate_prime(bits // 2)
    
    # Generate q close to p
    diff = random.randint(1, 1000)
    q = p + diff
    
    # Ensure q is prime
    while not is_prime(q):
        q += 2
    
    n = p * q
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    
    public_key = RSAKey(n, e, "public")
    private_key = RSAKey(n, d, "private")
    
    # Store p and q for attack demonstration
    private_key.p = p
    private_key.q = q
    
    print(f"✓ Weak key generation complete (|p-q|={abs(p-q)})")
    return public_key, private_key


def generate_weak_keypair_small_d(bits: int = 2048) -> Tuple[RSAKey, RSAKey]:
    """
    Generate a weak RSA key pair with small private exponent d (vulnerable to Wiener's attack).
    
    WARNING: This generates intentionally weak keys for educational purposes.
    
    Args:
        bits: The bit length of the modulus
    
    Returns:
        A tuple of (public_key, private_key) with small d
    """
    print(f"⚠️ Generating WEAK {bits}-bit RSA key pair (small d)...")
    
    # Generate primes
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    
    while p == q:
        q = generate_prime(bits // 2)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Choose small d (vulnerable to Wiener's attack)
    # d must be < n^(1/4) for Wiener's attack to work
    max_d = int(n ** 0.25)
    
    # Keep trying until we find a valid small d
    attempts = 0
    while attempts < 10000:
        d = random.randint(max_d // 2, max_d)
        
        # Ensure d is coprime with phi
        if gcd(d, phi) == 1:
            break
        attempts += 1
    
    if attempts >= 10000:
        # Fallback: find a small d that works
        d = 3
        while gcd(d, phi) != 1 and d < max_d:
            d += 2
    
    # Calculate corresponding e
    e = mod_inverse(d, phi)
    
    public_key = RSAKey(n, e, "public")
    private_key = RSAKey(n, d, "private")
    
    # Store p and q for verification
    private_key.p = p
    private_key.q = q
    
    print(f"✓ Weak key generation complete (d={d})")
    return public_key, private_key


if __name__ == "__main__":
    print("Testing Key Generation...")
    print("-" * 50)
    
    # Test secure key generation
    print("\n1. Generating secure 1024-bit key pair:")
    pub, priv = generate_keypair(1024)
    print(f"   Public: {pub}")
    print(f"   Private: {priv}")
    
    # Test weak key generation
    print("\n2. Generating weak key pair (small primes):")
    weak_pub, weak_priv = generate_weak_keypair_small_primes(64)
    print(f"   Public: {weak_pub}")
    print(f"   Private: {weak_priv}")
    
    print("\n3. Generating weak key pair (close primes):")
    weak_pub2, weak_priv2 = generate_weak_keypair_close_primes(512)
    print(f"   Public: {weak_pub2}")
    print(f"   Private: {weak_priv2}")
    
    print("\n4. Generating weak key pair (small d):")
    weak_pub3, weak_priv3 = generate_weak_keypair_small_d(512)
    print(f"   Public: {weak_pub3}")
    print(f"   Private: {weak_priv3}")
