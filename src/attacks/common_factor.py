"""
Common Factor Attack

This attack exploits scenarios where multiple RSA moduli share a common prime factor.
This can happen due to poor random number generation or weak key generation processes.
"""

from ..rsa_core import RSAKey
from ..utils import gcd, mod_inverse


def common_factor_attack(public_keys: list) -> dict:
    """
    Attack multiple RSA keys that share common factors.
    
    When multiple RSA moduli share a common prime factor,
    we can easily factor all of them using GCD.
    
    For example, if n1 = p*q1 and n2 = p*q2, then:
        gcd(n1, n2) = p
    
    Args:
        public_keys: List of RSA public keys to analyze
    
    Returns:
        Dictionary mapping public key indices to recovered private keys
    
    Raises:
        ValueError: If no common factors found
    """
    print(f"\n{'='*60}")
    print("COMMON FACTOR ATTACK")
    print(f"{'='*60}")
    print(f"Analyzing {len(public_keys)} RSA public keys...")
    print(f"Checking for shared prime factors...")
    
    num_keys = len(public_keys)
    factored_keys = {}
    
    # Check all pairs of moduli
    for i in range(num_keys):
        for j in range(i + 1, num_keys):
            n1 = public_keys[i].n
            n2 = public_keys[j].n
            
            # Compute GCD
            g = gcd(n1, n2)
            
            if g > 1 and g < n1:
                # Found common factor!
                print(f"\n✓ Found common factor between keys {i} and {j}!")
                print(f"  gcd(n{i}, n{j}) = {g}")
                
                # Factor both moduli
                p = g
                q1 = n1 // p
                q2 = n2 // p
                
                print(f"  Key {i}: n{i} = {p} × {q1}")
                print(f"  Key {j}: n{j} = {p} × {q2}")
                
                # Recover private keys
                if i not in factored_keys:
                    e1 = public_keys[i].exponent
                    phi1 = (p - 1) * (q1 - 1)
                    d1 = mod_inverse(e1, phi1)
                    
                    priv1 = RSAKey(n1, d1, "private")
                    priv1.p = p
                    priv1.q = q1
                    factored_keys[i] = priv1
                    
                    print(f"  ✓ Recovered private key for key {i}")
                
                if j not in factored_keys:
                    e2 = public_keys[j].exponent
                    phi2 = (p - 1) * (q2 - 1)
                    d2 = mod_inverse(e2, phi2)
                    
                    priv2 = RSAKey(n2, d2, "private")
                    priv2.p = p
                    priv2.q = q2
                    factored_keys[j] = priv2
                    
                    print(f"  ✓ Recovered private key for key {j}")
    
    if not factored_keys:
        print(f"\n✗ Attack failed: No common factors found")
        print(f"  All moduli appear to use distinct prime factors")
        print(f"{'='*60}")
        raise ValueError("No common factors found among the provided keys")
    
    print(f"\n✓ Successfully compromised {len(factored_keys)} out of {num_keys} keys!")
    print(f"{'='*60}")
    
    return factored_keys


def demonstrate_common_factor_attack():
    """
    Demonstrate the common factor attack.
    """
    from ..key_generation import generate_prime
    from ..utils import mod_inverse
    from ..rsa_core import encrypt, decrypt
    
    print("\n" + "="*70)
    print("DEMONSTRATION: Common Factor Attack")
    print("="*70)
    
    # Setup: Generate multiple keys with shared prime (VULNERABILITY!)
    print("\nStep 1: Generate RSA keys with shared prime factor (vulnerable!)")
    print("-" * 70)
    
    # Shared prime p
    p_shared = generate_prime(256)
    print(f"Shared prime: p = {p_shared}")
    print(f"⚠️ WARNING: Reusing primes is a critical vulnerability!")
    
    # Generate 3 keys sharing this prime
    num_keys = 3
    public_keys = []
    private_keys = []
    
    e = 65537
    
    for i in range(num_keys):
        # Generate unique q for each key
        q = generate_prime(256)
        while q == p_shared:
            q = generate_prime(256)
        
        n = p_shared * q
        phi = (p_shared - 1) * (q - 1)
        d = mod_inverse(e, phi)
        
        pub = RSAKey(n, e, "public")
        priv = RSAKey(n, d, "private")
        priv.p = p_shared
        priv.q = q
        
        public_keys.append(pub)
        private_keys.append(priv)
        
        print(f"\nKey {i}:")
        print(f"  p{i} = {p_shared} (shared!)")
        print(f"  q{i} = {q}")
        print(f"  n{i} = {n}")
    
    # Encrypt messages with different keys
    print("\nStep 2: Encrypt messages with the vulnerable keys")
    print("-" * 70)
    
    messages = [b"Secret 1", b"Secret 2", b"Secret 3"]
    ciphertexts = []
    
    for i, (msg, pub) in enumerate(zip(messages, public_keys)):
        ct = encrypt(msg, pub)
        ciphertexts.append(ct)
        print(f"Message {i}: {msg} -> Ciphertext: {ct}")
    
    # Attack
    print("\nStep 3: Perform common factor attack")
    print("-" * 70)
    recovered_keys = common_factor_attack(public_keys)
    
    # Verify
    print("\nStep 4: Decrypt messages with recovered keys")
    print("-" * 70)
    
    for i in recovered_keys:
        recovered_priv = recovered_keys[i]
        decrypted = decrypt(ciphertexts[i], recovered_priv)
        print(f"Key {i}:")
        print(f"  Original: {messages[i]}")
        print(f"  Decrypted: {decrypted}")
        print(f"  Match: {messages[i] == decrypted}")
    
    print("\n" + "="*70)
    print("✓ Common factor attack successful!")
    print("LESSON: Each RSA key must use completely unique prime factors!")
    print("="*70)


if __name__ == "__main__":
    demonstrate_common_factor_attack()
