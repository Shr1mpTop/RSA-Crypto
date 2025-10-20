"""
Wiener's Attack

This attack exploits RSA keys with a small private exponent d.
When d < N^(1/4), the private key can be recovered using continued fractions.
"""

from ..rsa_core import RSAKey
from ..utils import convergents, gcd


def wiener_attack(public_key: RSAKey) -> RSAKey:
    """
    Wiener's attack on RSA with small private exponent.
    
    When d < N^(1/4), we can recover d using continued fractions.
    The attack is based on the fact that k/d is a convergent of e/n
    for some k < d.
    
    Args:
        public_key: The RSA public key to attack
    
    Returns:
        The recovered private key if successful
    
    Raises:
        ValueError: If attack fails
    """
    print(f"\n{'='*60}")
    print("WIENER'S ATTACK (Small d)")
    print(f"{'='*60}")
    print(f"Target modulus n = {public_key.n}")
    print(f"Target bit length = {public_key.bit_length}")
    print(f"Public exponent e = {public_key.exponent}")
    print(f"\nCondition: d < N^(1/4) ≈ {int(public_key.n ** 0.25)}")
    print(f"\nCalculating convergents of e/n...")
    
    n = public_key.n
    e = public_key.exponent
    
    # Get convergents of e/n
    conv = convergents(e, n, max_terms=1000)
    print(f"Testing {len(conv)} convergents...")
    
    for i, (k, d) in enumerate(conv):
        if k == 0:
            continue
        
        # Check if this d works
        # We need: e*d ≡ 1 (mod φ(n))
        # Which means: e*d - 1 = k*φ(n)
        # So: φ(n) = (e*d - 1) / k
        
        if (e * d - 1) % k != 0:
            continue
        
        phi = (e * d - 1) // k
        
        # Check if this phi leads to valid p and q
        # We know: φ(n) = (p-1)(q-1) = pq - p - q + 1 = n - p - q + 1
        # So: p + q = n - φ(n) + 1
        
        s = n - phi + 1
        
        # Now solve: p + q = s and p*q = n
        # This gives: p^2 - s*p + n = 0
        # Using quadratic formula: p = (s ± sqrt(s^2 - 4n)) / 2
        
        discriminant = s * s - 4 * n
        
        if discriminant < 0:
            continue
        
        # Check if discriminant is a perfect square
        sqrt_d = int(discriminant ** 0.5)
        if sqrt_d * sqrt_d != discriminant:
            continue
        
        p = (s + sqrt_d) // 2
        q = (s - sqrt_d) // 2
        
        if p * q == n:
            print(f"\n✓ Attack successful!")
            print(f"  Found after testing {i+1} convergents")
            print(f"  p = {p}")
            print(f"  q = {q}")
            print(f"  d = {d}")
            print(f"  k = {k}")
            
            # Verify
            print(f"\nVerification:")
            print(f"  p × q = {p * q}")
            print(f"  p × q == n: {p * q == n}")
            print(f"  e × d mod φ(n) = {(e * d) % phi}")
            
            private_key = RSAKey(n, d, "private")
            private_key.p = p
            private_key.q = q
            
            print(f"{'='*60}")
            return private_key
    
    print(f"\n✗ Attack failed: Could not find valid d")
    print(f"  d might be too large for Wiener's attack")
    print(f"{'='*60}")
    raise ValueError("Wiener's attack failed")


def demonstrate_wiener_attack():
    """
    Demonstrate Wiener's attack with a weak key.
    """
    from ..key_generation import generate_weak_keypair_small_d
    from ..rsa_core import encrypt, decrypt
    
    print("\n" + "="*70)
    print("DEMONSTRATION: Wiener's Attack on Small Private Exponent")
    print("="*70)
    
    # Generate weak keypair with small d
    print("\nStep 1: Generate weak RSA key with small d")
    print("-" * 70)
    weak_public, weak_private = generate_weak_keypair_small_d(512)
    print(f"Generated weak key pair:")
    print(f"  n = {weak_public.n}")
    print(f"  e = {weak_public.exponent}")
    print(f"  d = {weak_private.exponent} (small!)")
    print(f"  d < n^(1/4): {weak_private.exponent < int(weak_public.n ** 0.25)}")
    
    # Encrypt a message
    print("\nStep 2: Encrypt a secret message")
    print("-" * 70)
    message = b"Attack works!"
    print(f"Original message: {message}")
    ciphertext = encrypt(message, weak_public)
    print(f"Ciphertext: {ciphertext}")
    
    # Attack
    print("\nStep 3: Perform Wiener's attack")
    print("-" * 70)
    recovered_private = wiener_attack(weak_public)
    
    # Verify
    print("\nStep 4: Decrypt with recovered private key")
    print("-" * 70)
    decrypted = decrypt(ciphertext, recovered_private)
    print(f"Decrypted message: {decrypted}")
    print(f"Match: {message == decrypted}")
    print(f"Recovered d matches: {recovered_private.exponent == weak_private.exponent}")
    
    print("\n" + "="*70)
    print("✓ Wiener's attack successful! Private key recovered.")
    print("="*70)


if __name__ == "__main__":
    demonstrate_wiener_attack()
