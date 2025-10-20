"""
Fermat's Factorization Attack

This attack exploits RSA keys where the two prime factors p and q
are close together. Fermat's method can quickly factor such numbers.
"""

import math
from ..rsa_core import RSAKey
from ..utils import mod_inverse, is_perfect_square


def fermat_factor(n: int, max_iterations: int = 100000) -> tuple:
    """
    Factor n using Fermat's factorization method.
    
    This method works well when the factors p and q are close together.
    
    The idea: If n = p*q where p and q are close, then:
        n = p*q = ((p+q)/2)^2 - ((p-q)/2)^2 = a^2 - b^2
    
    We search for a such that a^2 - n is a perfect square b^2.
    Then: p = a + b, q = a - b
    
    Args:
        n: The number to factor
        max_iterations: Maximum number of values to try
    
    Returns:
        Tuple (p, q) if successful
    
    Raises:
        ValueError: If factorization fails
    """
    print(f"Attempting Fermat's factorization...")
    print(f"Target n = {n}")
    
    # Start with a = ceil(sqrt(n))
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    
    print(f"Starting a = ceil(sqrt(n)) = {a}")
    
    for i in range(max_iterations):
        b_squared = a * a - n
        
        if b_squared < 0:
            a += 1
            continue
        
        # Check if b_squared is a perfect square
        if is_perfect_square(b_squared):
            b = math.isqrt(b_squared)
            p = a + b
            q = a - b
            
            print(f"\n✓ Found after {i+1} iterations!")
            print(f"  a = {a}")
            print(f"  b = {b}")
            print(f"  p = a + b = {p}")
            print(f"  q = a - b = {q}")
            print(f"  p × q = {p * q}")
            
            return (p, q) if p > q else (q, p)
        
        a += 1
        
        if (i + 1) % 10000 == 0:
            print(f"  Tried {i+1} values...")
    
    raise ValueError(f"Fermat factorization failed after {max_iterations} iterations")


def fermat_attack(public_key: RSAKey, max_iterations: int = 100000) -> RSAKey:
    """
    Attack RSA using Fermat's factorization method.
    
    This attack works when p and q are close together.
    
    Args:
        public_key: The RSA public key to attack
        max_iterations: Maximum iterations for factorization
    
    Returns:
        The recovered private key
    
    Raises:
        ValueError: If attack fails
    """
    print(f"\n{'='*60}")
    print("FERMAT'S FACTORIZATION ATTACK")
    print(f"{'='*60}")
    print(f"Target modulus n = {public_key.n}")
    print(f"Target bit length = {public_key.bit_length}")
    print(f"Public exponent e = {public_key.exponent}")
    print(f"\nThis attack works when |p - q| is small")
    print(f"(i.e., when p and q are close together)")
    
    n = public_key.n
    e = public_key.exponent
    
    # Attempt factorization
    try:
        p, q = fermat_factor(n, max_iterations)
        
        print(f"\n✓ Successfully factored n!")
        print(f"  p = {p}")
        print(f"  q = {q}")
        print(f"  |p - q| = {abs(p - q)}")
        
        # Calculate private key
        phi = (p - 1) * (q - 1)
        d = mod_inverse(e, phi)
        
        private_key = RSAKey(n, d, "private")
        private_key.p = p
        private_key.q = q
        
        print(f"\n✓ Recovered private exponent d = {d}")
        print(f"{'='*60}")
        
        return private_key
        
    except ValueError as ex:
        print(f"\n✗ Attack failed: {ex}")
        print(f"  p and q might not be close enough")
        print(f"{'='*60}")
        raise


def demonstrate_fermat_attack():
    """
    Demonstrate Fermat's factorization attack.
    """
    from ..key_generation import generate_weak_keypair_close_primes
    from ..rsa_core import encrypt, decrypt
    
    print("\n" + "="*70)
    print("DEMONSTRATION: Fermat's Factorization Attack")
    print("="*70)
    
    # Generate weak keypair with close primes
    print("\nStep 1: Generate weak RSA key with close primes")
    print("-" * 70)
    weak_public, weak_private = generate_weak_keypair_close_primes(512)
    print(f"Generated weak key pair:")
    print(f"  p = {weak_private.p}")
    print(f"  q = {weak_private.q}")
    print(f"  |p - q| = {abs(weak_private.p - weak_private.q)}")
    print(f"  n = {weak_public.n}")
    print(f"  e = {weak_public.exponent}")
    
    # Encrypt a message
    print("\nStep 2: Encrypt a secret message")
    print("-" * 70)
    message = b"Close primes!"
    print(f"Original message: {message}")
    ciphertext = encrypt(message, weak_public)
    print(f"Ciphertext: {ciphertext}")
    
    # Attack
    print("\nStep 3: Perform Fermat's factorization attack")
    print("-" * 70)
    recovered_private = fermat_attack(weak_public)
    
    # Verify
    print("\nStep 4: Decrypt with recovered private key")
    print("-" * 70)
    decrypted = decrypt(ciphertext, recovered_private)
    print(f"Decrypted message: {decrypted}")
    print(f"Match: {message == decrypted}")
    
    print("\n" + "="*70)
    print("✓ Fermat's attack successful!")
    print("LESSON: Ensure p and q have sufficient distance!")
    print("="*70)


if __name__ == "__main__":
    demonstrate_fermat_attack()
