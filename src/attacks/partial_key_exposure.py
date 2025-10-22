"""
Partial Key Exposure Attack

This attack exploits scenarios where partial information about prime factors is leaked.
Even leaking a fraction of bits can allow complete recovery of the key.

Theory: If approximately 1/4 to 1/3 of the bits of prime p are known,
an attacker can factor n in polynomial time using methods like Coppersmith's theorem.
"""

from ..rsa_core import RSAKey
from ..utils import mod_inverse
import math


def partial_p_attack_lsb(public_key: RSAKey, p_leaked_bits: int, leaked_value: int) -> RSAKey:
    """
    Attack RSA when least significant bits of prime p are leaked.
    
    Args:
        public_key: The RSA public key
        p_leaked_bits: Number of leaked least significant bits
        leaked_value: The leaked LSB value
    
    Returns:
        The recovered private key if successful
    
    Raises:
        ValueError: If attack fails
    """
    n = public_key.n
    e = public_key.exponent
    
    print(f"Factoring n using {p_leaked_bits} leaked LSBs of p...")
    
    # We know: p ≡ leaked_value (mod 2^p_leaked_bits)
    # So: p = leaked_value + k * 2^p_leaked_bits for some k
    
    mod_value = 2 ** p_leaked_bits
    sqrt_n = math.isqrt(n)
    max_k = (sqrt_n // mod_value) + 10000  # Add extra search space
    
    max_attempts = min(max_k, 10000000)  # Allow up to 10 million attempts
    print(f"Searching (this may take 10-30 seconds)...")
    
    for k in range(max_attempts):
        p_candidate = leaked_value + k * mod_value
        
        # Stop if p_candidate is way too large
        if p_candidate > n:
            break
        
        # Check if p_candidate divides n
        if n % p_candidate == 0:
            q = n // p_candidate
            
            if q > 1 and p_candidate * q == n and p_candidate <= sqrt_n * 2:
                # Success!
                phi = (p_candidate - 1) * (q - 1)
                d = mod_inverse(e, phi)
                
                private_key = RSAKey(n, d, "private")
                private_key.p = p_candidate
                private_key.q = q
                
                print(f"✓ Success! Found p after testing {k+1} candidates")
                return private_key
    
    raise ValueError("Partial p attack failed")


def demonstrate_partial_key_exposure_attack():
    """
    Demonstrate partial key exposure attack.
    """
    from ..key_generation import generate_prime
    from ..rsa_core import encrypt, decrypt
    from ..utils import mod_inverse
    
    
    # Retry logic - sometimes the search space is too large
    max_retries = 5
    for attempt in range(max_retries):
        try:
            print("\nStep 1: Generate RSA key")
            print("-" * 70)
            
            # Use 32-bit primes for fast, reliable demonstration
            # Smaller primes = faster search for educational demo
            print("Generating 32-bit primes...")
            p = generate_prime(32)
            q = generate_prime(32)
            while p == q:
                q = generate_prime(32)
            
            n = p * q
            e = 65537
            phi = (p - 1) * (q - 1)
            d = mod_inverse(e, phi)
            
            pub = RSAKey(n, e, "public")
            
            print(f"✓ Key generated:")
            print(f"  n has {n.bit_length()} bits")
            print(f"  p has {p.bit_length()} bits")
            print(f"  q has {q.bit_length()} bits")
            
            print("\nStep 2: Simulate information leak")
            print("-" * 70)
            
            # Leak n/4 bits as per the theoretical requirement
            # Since p is approximately n/2 bits, n/4 bits means leaking p/2 bits
            leaked_bits = n.bit_length() // 4
            leaked_mask = (1 << leaked_bits) - 1
            leaked_p_value = p & leaked_mask
            
            print(f"⚠️  LEAKED: {leaked_bits} least significant bits of p")
            print(f"  That's n/4 = {n.bit_length()}/4 = {leaked_bits} bits")
            print(f"  Leaked value: {leaked_p_value}")
            
            print("\nStep 3: Encrypt a message")
            print("-" * 70)
            message = b"Secret!"
            print(f"Message: {message}")
            ciphertext = encrypt(message, pub)
            print(f"Ciphertext: {ciphertext}")
            
            print("\nStep 4: Attack using leaked bits")
            print("-" * 70)
            recovered_key = partial_p_attack_lsb(pub, leaked_bits, leaked_p_value)
            
            print("\nStep 5: Verify attack success")
            print("-" * 70)
            print(f"  Recovered p: {recovered_key.p}")
            print(f"  Original p:  {p}")
            print(f"  Match: {recovered_key.p == p}")
            
            decrypted = decrypt(ciphertext, recovered_key)
            print(f"\n  Decrypted: {decrypted}")
            print(f"  Original:  {message}")
            print(f"  Match: {decrypted == message}")
            
            print("\n" + "="*70)
            print("✓ Partial key exposure attack successful!")
            print("="*70)
            break
            
        except ValueError as e:
            if attempt < max_retries - 1:
                print(f"\n⚠️  Attack failed (attempt {attempt + 1}/{max_retries}), retrying with new key...")
            else:
                print(f"\n✗ Attack failed after {max_retries} attempts")
                print("Note: Partial key exposure attack has probabilistic success")
                raise


if __name__ == "__main__":
    demonstrate_partial_key_exposure_attack()
