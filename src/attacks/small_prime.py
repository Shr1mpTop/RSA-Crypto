"""
Small Prime Factorization Attack

This attack exploits RSA keys that use small prime numbers,
which can be quickly factorized using trial division.
"""

from ..rsa_core import RSAKey
from ..utils import gcd, mod_inverse, factor_trial_division


def small_prime_attack(public_key: RSAKey, max_prime: int = 1000000) -> RSAKey: 
    """
    Attempt to factor the modulus using trial division with small primes.
    
    This attack works when one or both of the prime factors p, q are small
    enough to be found by trial division.
    
    Args:
        public_key: The RSA public key to attack
        max_prime: Maximum prime to try in trial division
    
    Returns:
        The recovered private key if successful
    
    Raises:
        ValueError: If attack fails
    """
    print(f"Target modulus n = {public_key.n}")
    print(f"Target modulus bit length = {public_key.bit_length}")
    print(f"Public exponent e = {public_key.exponent}")
    print(f"\nAttempting factorization with primes up to {max_prime}...")
    
    n = public_key.n
    e = public_key.exponent
    
    # Try to factor using trial division
    factors = factor_trial_division(n, limit=max_prime)
    
    print(f"Found factors: {factors}")
    
    if len(factors) == 2 and factors[0] * factors[1] == n:
        p, q = factors
        print(f"\n✓ Successfully factored n!")
        print(f"  p = {p}")
        print(f"  q = {q}")
        print(f"  p × q = {n}")
        
        # Calculate private key
        phi = (p - 1) * (q - 1)
        d = mod_inverse(e, phi)
        
        private_key = RSAKey(n, d, "private")
        private_key.p = p
        private_key.q = q
        
        print(f"\n✓ Recovered private exponent d = {d}")
        
        return private_key
    else:
        print(f"\n✗ Attack failed: Could not factor n with small primes")
        raise ValueError("Small prime attack failed")


def demonstrate_small_prime_attack():
    """
    Demonstrate the small prime attack with a weak key.
    """
    from ..key_generation import generate_weak_keypair_small_primes
    from ..rsa_core import encrypt, decrypt
    
    # Generate weak keypair with small primes
    print("\nStep 1: Generate weak RSA key with small primes")
    print("-" * 70)
    weak_public, weak_private = generate_weak_keypair_small_primes(256)
    print(f"Generated weak key pair:")
    print(f"  p = {weak_private.p}")
    print(f"  q = {weak_private.q}")
    print(f"  n = {weak_public.n}")
    print(f"  e = {weak_public.exponent}")
    
    # Encrypt a message
    print("\nStep 2: Encrypt a secret message")
    print("-" * 70)
    message = b"Hi!"
    print(f"Original message: {message}")
    ciphertext = encrypt(message, weak_public)
    print(f"Ciphertext: {ciphertext}")
    
    # Attack
    print("\nStep 3: Perform small prime attack")
    print("-" * 70)
    # Use a higher limit to factor 24-bit primes (2^25 ≈ 33 million)
    recovered_private = small_prime_attack(weak_public, max_prime=2**25)
    
    # Decrypt with recovered key
    print("\nStep 4: Decrypt with recovered private key")
    print("-" * 70)
    decrypted = decrypt(ciphertext, recovered_private)
    print(f"Decrypted message: {decrypted}")
    print(f"Match: {message == decrypted}")
    
    print("\n" + "="*70)
    print("✓ Small prime factorization attack successful!")
    print("="*70)


if __name__ == "__main__":
    demonstrate_small_prime_attack()
