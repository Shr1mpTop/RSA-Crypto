"""
Verification Script

This script verifies that the RSA implementation is working correctly.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))


def test_basic_rsa():
    """Test basic RSA functionality."""
    print("\n" + "="*70)
    print("TEST 1: Basic RSA Operations")
    print("="*70)
    
    from src.key_generation import generate_keypair
    from src.rsa_core import encrypt, decrypt, sign, verify
    
    try:
        # Generate keys
        print("  Generating 512-bit key pair...")
        public_key, private_key = generate_keypair(512)
        print("  ✓ Key generation successful")
        
        # Test encryption/decryption
        print("  Testing encryption and decryption...")
        message = b"Test message"
        ciphertext = encrypt(message, public_key)
        decrypted = decrypt(ciphertext, private_key)
        
        assert message == decrypted, "Decryption failed!"
        print("  ✓ Encryption/Decryption works")
        
        # Test signing/verification
        print("  Testing digital signatures...")
        signature = sign(message, private_key)
        valid = verify(message, signature, public_key)
        
        assert valid, "Signature verification failed!"
        print("  ✓ Digital signatures work")
        
        return True
    
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
        return False


def test_attacks():
    """Test that attack modules can be imported."""
    print("\n" + "="*70)
    print("TEST 2: Attack Module Imports")
    print("="*70)
    
    attacks = [
        "src.attacks.small_prime",
        "src.attacks.wiener",
        "src.attacks.common_modulus",
        "src.attacks.low_exponent",
        "src.attacks.fermat",
        "src.attacks.common_factor",
    ]
    
    all_passed = True
    
    for attack in attacks:
        try:
            __import__(attack)
            print(f"  ✓ {attack}")
        except Exception as e:
            print(f"  ✗ {attack}: {e}")
            all_passed = False
    
    return all_passed


def test_utilities():
    """Test utility functions."""
    print("\n" + "="*70)
    print("TEST 3: Utility Functions")
    print("="*70)
    
    from src.utils import gcd, mod_inverse, is_prime, extended_gcd
    
    try:
        # Test GCD
        assert gcd(48, 18) == 6, "GCD test failed"
        print("  ✓ GCD function works")
        
        # Test Extended GCD
        g, x, y = extended_gcd(35, 15)
        assert g == 5 and 35*x + 15*y == 5, "Extended GCD test failed"
        print("  ✓ Extended GCD function works")
        
        # Test Modular Inverse
        inv = mod_inverse(3, 11)
        assert (3 * inv) % 11 == 1, "Modular inverse test failed"
        print("  ✓ Modular inverse function works")
        
        # Test Primality
        assert is_prime(17) == True, "Primality test failed (17)"
        assert is_prime(18) == False, "Primality test failed (18)"
        print("  ✓ Primality test works")
        
        return True
    
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
        return False


def test_key_generation():
    """Test key generation variants."""
    print("\n" + "="*70)
    print("TEST 4: Key Generation Variants")
    print("="*70)
    
    from src.key_generation import (
        generate_keypair,
        generate_weak_keypair_small_primes,
        generate_weak_keypair_close_primes,
        generate_weak_keypair_small_d
    )
    
    try:
        # Test secure key generation
        print("  Testing secure key generation...")
        pub, priv = generate_keypair(512)
        assert pub.n == priv.n, "Key generation: moduli don't match"
        print("  ✓ Secure key generation works")
        
        # Test weak key generation
        print("  Testing weak key generation (small primes)...")
        weak_pub, weak_priv = generate_weak_keypair_small_primes(256)
        print("  ✓ Weak key generation (small primes) works")
        
        print("  Testing weak key generation (close primes)...")
        weak_pub2, weak_priv2 = generate_weak_keypair_close_primes(256)
        print("  ✓ Weak key generation (close primes) works")
        
        print("  Testing weak key generation (small d)...")
        weak_pub3, weak_priv3 = generate_weak_keypair_small_d(256)
        print("  ✓ Weak key generation (small d) works")
        
        return True
    
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all verification tests."""
    print("\n" + "#"*70)
    print("# RSA CRYPTO VERIFICATION")
    print("#"*70)
    print("\nRunning verification tests...")
    
    results = []
    
    results.append(("Basic RSA Operations", test_basic_rsa()))
    results.append(("Attack Module Imports", test_attacks()))
    results.append(("Utility Functions", test_utilities()))
    results.append(("Key Generation Variants", test_key_generation()))
    
    # Summary
    print("\n" + "="*70)
    print("VERIFICATION SUMMARY")
    print("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"  {status}: {name}")
    
    print("-" * 70)
    print(f"  Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✓ All verification tests passed!")
        print("  The RSA implementation is working correctly.")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed!")
        print("  Please check the error messages above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
