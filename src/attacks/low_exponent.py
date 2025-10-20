"""
Low Encryption Exponent Attack (Håstad's Broadcast Attack)

This attack exploits scenarios where:
1. A small public exponent e is used (like e=3)
2. The same message is sent to multiple recipients
3. No (or weak) padding is used
"""

from ..rsa_core import RSAKey
from ..utils import chinese_remainder_theorem, nth_root


def low_exponent_attack(ciphertexts: list, moduli: list, e: int) -> int:
    """
    Håstad's broadcast attack on RSA with low exponent.
    
    When the same message m is encrypted with the same small exponent e
    to at least e different recipients with different moduli, and m^e < n1*n2*...*ne,
    we can recover m using the Chinese Remainder Theorem.
    
    Given:
        c_i = m^e mod n_i for i = 1..k where k >= e
    
    We can compute:
        c = m^e mod (n1 * n2 * ... * nk)
    
    Then take the e-th root to recover m.
    
    Args:
        ciphertexts: List of ciphertexts
        moduli: List of moduli (must be pairwise coprime)
        e: The public exponent (should be small, like 3)
    
    Returns:
        The recovered plaintext message
    
    Raises:
        ValueError: If attack conditions are not met
    """
    print(f"\n{'='*60}")
    print(f"LOW EXPONENT ATTACK (Håstad's Broadcast Attack)")
    print(f"{'='*60}")
    print(f"Public exponent e = {e}")
    print(f"Number of ciphertexts = {len(ciphertexts)}")
    print(f"Number of moduli = {len(moduli)}")
    
    # Check if we have enough ciphertexts
    if len(ciphertexts) < e:
        print(f"✗ Attack failed: Need at least {e} ciphertexts, got {len(ciphertexts)}")
        raise ValueError(f"Need at least {e} ciphertexts for e={e}")
    
    # Use first e ciphertexts and moduli
    ciphertexts = ciphertexts[:e]
    moduli = moduli[:e]
    
    print(f"\nUsing first {e} encryptions:")
    for i, (c, n) in enumerate(zip(ciphertexts, moduli), 1):
        print(f"  c{i} = m^{e} mod n{i}")
        print(f"    c{i} = {c}")
        print(f"    n{i} = {n}")
    
    # Apply Chinese Remainder Theorem
    print(f"\nApplying Chinese Remainder Theorem...")
    print(f"Computing: c ≡ m^{e} mod (n1 × n2 × ... × n{e})")
    
    c = chinese_remainder_theorem(ciphertexts, moduli)
    
    print(f"Result: c = {c}")
    
    # Take e-th root
    print(f"\nTaking {e}-th root to recover m...")
    m = nth_root(c, e)
    
    # Verify
    print(f"\nVerification:")
    print(f"  m^{e} = {m**e}")
    print(f"  c = {c}")
    print(f"  Match: {m**e == c}")
    
    if m ** e != c:
        print(f"⚠️ Warning: Approximate root (message might be slightly off)")
        # Try m+1, m-1
        if (m+1) ** e == c:
            m = m + 1
            print(f"  Corrected to m+1")
        elif (m-1) ** e == c:
            m = m - 1
            print(f"  Corrected to m-1")
    
    print(f"\n✓ Message recovered: m = {m}")
    print(f"{'='*60}")
    
    return m


def demonstrate_low_exponent_attack():
    """
    Demonstrate the low exponent attack.
    """
    from ..key_generation import generate_keypair
    from ..utils import bytes_to_int, int_to_bytes, gcd, mod_inverse
    
    print("\n" + "="*70)
    print("DEMONSTRATION: Low Exponent Attack (Håstad's Broadcast)")
    print("="*70)
    
    # Setup: Multiple recipients with e=3
    print("\nStep 1: Setup - Same message encrypted to 3 recipients with e=3")
    print("-" * 70)
    
    e = 3
    num_recipients = 3
    
    # Original message
    message = b"Hi!"
    m = bytes_to_int(message)
    
    print(f"Original message: {message}")
    print(f"Message as integer: m = {m}")
    print(f"Public exponent: e = {e}")
    
    # Generate keys for multiple recipients
    keys = []
    ciphertexts = []
    moduli = []
    
    print(f"\nGenerating {num_recipients} recipient key pairs...")
    
    for i in range(num_recipients):
        # Generate keypair with e=3
        pub, priv = generate_keypair(512)
        
        # Generate a new keypair with e=3
        n = pub.n
        phi = (priv.p - 1) * (priv.q - 1)
        
        # Make sure gcd(e, phi) = 1
        if gcd(e, phi) != 1:
            print(f"  Recipient {i+1}: Regenerating (e not coprime with phi)...")
            continue
        
        d = mod_inverse(e, phi)
        
        pub_e3 = RSAKey(n, e, "public")
        keys.append(pub_e3)
        
        # Encrypt message
        c = pow(m, e, n)
        ciphertexts.append(c)
        moduli.append(n)
        
        print(f"  Recipient {i+1}:")
        print(f"    n{i+1} = {n}")
        print(f"    c{i+1} = {c}")
    
    # Attack
    print("\nStep 2: Perform low exponent attack")
    print("-" * 70)
    recovered_m = low_exponent_attack(ciphertexts, moduli, e)
    
    # Verify
    print("\nStep 3: Verify recovered message")
    print("-" * 70)
    recovered_message = int_to_bytes(recovered_m)
    print(f"Recovered message: {recovered_message}")
    print(f"Match: {message == recovered_message}")
    
    print("\n" + "="*70)
    print("✓ Low exponent attack successful!")
    print("LESSON: Use secure exponent (e=65537) and always use proper padding!")
    print("="*70)


if __name__ == "__main__":
    demonstrate_low_exponent_attack()
