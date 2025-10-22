"""
Common Modulus Attack

This attack exploits the scenario where the same message is encrypted
with the same modulus n but different public exponents e1 and e2.
"""

from ..rsa_core import RSAKey
from ..utils import extended_gcd, gcd


def common_modulus_attack(c1: int, c2: int, e1: int, e2: int, n: int) -> int:
    """
    Common modulus attack on RSA.
    
    When the same message m is encrypted with the same modulus n
    but different coprime exponents e1 and e2, we can recover m
    without knowing the private key.
    
    Given:
        c1 = m^e1 mod n
        c2 = m^e2 mod n
        gcd(e1, e2) = 1
    
    We can find s and t such that: s*e1 + t*e2 = 1
    Then: m = c1^s * c2^t mod n
    
    Args:
        c1: First ciphertext
        c2: Second ciphertext
        e1: First public exponent
        e2: Second public exponent
        n: Common modulus
    
    Returns:
        The recovered plaintext message
    
    Raises:
        ValueError: If e1 and e2 are not coprime
    """
    print(f"Common modulus n = {n}")
    print(f"First encryption: c1 = m^{e1} mod n")
    print(f"Second encryption: c2 = m^{e2} mod n")
    
    # Check if e1 and e2 are coprime
    g = gcd(e1, e2)
    print(f"\nChecking: gcd({e1}, {e2}) = {g}")
    
    if g != 1:
        print(f"✗ Attack failed: e1 and e2 are not coprime!")
        raise ValueError(f"e1 and e2 must be coprime (gcd = {g})")
    
    # Find s and t using extended Euclidean algorithm
    print(f"\nFinding s and t such that: s*{e1} + t*{e2} = 1")
    _, s, t = extended_gcd(e1, e2)
    
    print(f"Found: s = {s}, t = {t}")
    print(f"Verification: {s}*{e1} + {t}*{e2} = {s*e1 + t*e2}")
    
    # Handle negative exponents by computing modular inverse
    print(f"\nRecovering message: m = c1^s * c2^t mod n")
    
    if s < 0:
        # c1^s = (c1^(-1))^|s|
        c1 = pow(c1, -1, n)
        s = -s
        print(f"  (s was negative, using c1_inv^{s})")
    
    if t < 0:
        # c2^t = (c2^(-1))^|t|
        c2 = pow(c2, -1, n)
        t = -t
        print(f"  (t was negative, using c2_inv^{t})")
    
    # Compute m = c1^s * c2^t mod n
    m = (pow(c1, s, n) * pow(c2, t, n)) % n
    
    print(f"\n✓ Message recovered: m = {m}")
    
    return m


def demonstrate_common_modulus_attack():
    """
    Demonstrate the common modulus attack.
    """
    from ..key_generation import generate_keypair
    from ..rsa_core import encrypt, decrypt
    from ..utils import bytes_to_int, int_to_bytes
    
    # Setup: Two users share the same modulus (BAD PRACTICE!)
    print("\nStep 1: Generate two key pairs with SAME modulus (vulnerable!)")
    print("-" * 70)
    
    # Manually generate primes to have access to p and q
    from ..key_generation import generate_prime
    from ..utils import mod_inverse
    
    print("Generating primes...")
    p = generate_prime(512)
    q = generate_prime(512)
    while p == q:
        q = generate_prime(512)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # First user with e1 = 65537
    e1 = 65537
    d1 = mod_inverse(e1, phi)
    pub1 = RSAKey(n, e1, "public")
    priv1 = RSAKey(n, d1, "private")
    
    # Second user with different e2 (sharing same n - VULNERABILITY!)
    e2 = 3
    while gcd(e2, phi) != 1:
        e2 += 2
    
    d2 = mod_inverse(e2, phi)
    pub2 = RSAKey(n, e2, "public")
    priv2 = RSAKey(n, d2, "private")
    
    print(f"User 1: e1 = {e1}")
    print(f"User 2: e2 = {e2}")
    print(f"Shared modulus n = {n}")
    print(f"⚠️ WARNING: Sharing modulus is a critical vulnerability!")
    
    # Encrypt same message with both keys
    print("\nStep 2: Encrypt same message with both public keys")
    print("-" * 70)
    message = b"Secret!"
    print(f"Original message: {message}")
    
    m = bytes_to_int(message)
    c1 = pow(m, e1, n)
    c2 = pow(m, e2, n)
    
    print(f"Ciphertext 1 (with e1): {c1}")
    print(f"Ciphertext 2 (with e2): {c2}")
    
    # Attack
    print("\nStep 3: Perform common modulus attack")
    print("-" * 70)
    recovered_m = common_modulus_attack(c1, c2, e1, e2, n)
    
    # Verify
    print("\nStep 4: Verify recovered message")
    print("-" * 70)
    recovered_message = int_to_bytes(recovered_m)
    print(f"Recovered message: {recovered_message}")
    print(f"Match: {message == recovered_message}")
    
    print("\n" + "="*70)
    print("✓ Common modulus attack successful!")
    print("="*70)


if __name__ == "__main__":
    demonstrate_common_modulus_attack()
