"""
Utility Functions for RSA Implementation

This module provides common mathematical and cryptographic utility functions.
"""

import random
from typing import Tuple


def gcd(a: int, b: int) -> int:
    """
    Calculate the greatest common divisor using Euclidean algorithm.
    
    Args:
        a, b: Two integers
    
    Returns:
        The GCD of a and b
    """
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean algorithm.
    
    Returns (gcd, x, y) such that a*x + b*y = gcd
    
    Args:
        a, b: Two integers
    
    Returns:
        Tuple of (gcd, x, y)
    """
    if a == 0:
        return b, 0, 1
    
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    
    return gcd_val, x, y


def mod_inverse(a: int, m: int) -> int:
    """
    Calculate the modular multiplicative inverse of a modulo m.
    
    Args:
        a: The number to find inverse of
        m: The modulus
    
    Returns:
        The modular inverse of a mod m
    
    Raises:
        ValueError: If inverse doesn't exist
    """
    gcd_val, x, _ = extended_gcd(a, m)
    
    if gcd_val != 1:
        raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
    
    return (x % m + m) % m


def is_prime(n: int, k: int = 40) -> bool:
    """
    Miller-Rabin primality test.
    
    Args:
        n: The number to test
        k: Number of rounds (higher = more accurate)
    
    Returns:
        True if n is probably prime, False if definitely composite
    """
    if n < 2:
        return False
    
    # Handle small primes
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    if n in small_primes:
        return True
    
    # Check if divisible by small primes
    for p in small_primes:
        if n % p == 0:
            return False
    
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


def bytes_to_int(data: bytes) -> int:
    """
    Convert bytes to integer.
    
    Args:
        data: Bytes to convert
    
    Returns:
        Integer representation
    """
    return int.from_bytes(data, byteorder='big')


def int_to_bytes(n: int) -> bytes:
    """
    Convert integer to bytes.
    
    Args:
        n: Integer to convert
    
    Returns:
        Bytes representation
    """
    # Calculate number of bytes needed
    byte_length = (n.bit_length() + 7) // 8
    return n.to_bytes(byte_length, byteorder='big')


def chinese_remainder_theorem(remainders: list, moduli: list) -> int:
    """
    Solve system of congruences using Chinese Remainder Theorem.
    
    x ≡ remainders[i] (mod moduli[i]) for all i
    
    Args:
        remainders: List of remainders
        moduli: List of moduli (must be pairwise coprime)
    
    Returns:
        The solution x
    """
    if len(remainders) != len(moduli):
        raise ValueError("Number of remainders must equal number of moduli")
    
    # Calculate product of all moduli
    N = 1
    for m in moduli:
        N *= m
    
    # Calculate result
    result = 0
    for r, m in zip(remainders, moduli):
        Ni = N // m
        Mi = mod_inverse(Ni, m)
        result += r * Ni * Mi
    
    return result % N


def nth_root(x: int, n: int) -> int:
    """
    Calculate the integer n-th root of x.
    
    Returns the largest integer r such that r^n <= x
    
    Args:
        x: The number
        n: The root degree
    
    Returns:
        The n-th root of x
    """
    if x == 0:
        return 0
    
    # Binary search for the root
    low = 0
    high = x
    
    while low <= high:
        mid = (low + high) // 2
        mid_nth = mid ** n
        
        if mid_nth == x:
            return mid
        elif mid_nth < x:
            low = mid + 1
        else:
            high = mid - 1
    
    return high


def is_perfect_square(n: int) -> bool:
    """
    Check if n is a perfect square.
    
    Args:
        n: The number to check
    
    Returns:
        True if n is a perfect square, False otherwise
    """
    if n < 0:
        return False
    
    root = int(n ** 0.5)
    return root * root == n


def factor_trial_division(n: int, limit: int = 1000000) -> list:
    """
    Factor n using trial division up to a limit.
    
    Args:
        n: The number to factor
        limit: Maximum value to try
    
    Returns:
        List of factors found (may be incomplete)
    """
    factors = []
    
    # Check small primes
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
        while n % p == 0:
            factors.append(p)
            n //= p
    
    # Check odd numbers up to limit
    i = 51
    while i <= limit and i * i <= n:
        while n % i == 0:
            factors.append(i)
            n //= i
        i += 2
    
    if n > 1:
        factors.append(n)
    
    return factors


def convergents(n: int, d: int, max_terms: int = 100) -> list:
    """
    Calculate convergents of the continued fraction representation of n/d.
    
    Args:
        n: Numerator
        d: Denominator
        max_terms: Maximum number of convergents to calculate
    
    Returns:
        List of (numerator, denominator) tuples representing convergents
    """
    # Calculate continued fraction representation
    cf = []
    while d != 0 and len(cf) < max_terms:
        q = n // d
        cf.append(q)
        n, d = d, n - q * d
    
    # Calculate convergents
    convergents_list = []
    h_prev2, h_prev1 = 0, 1
    k_prev2, k_prev1 = 1, 0
    
    for q in cf:
        h = q * h_prev1 + h_prev2
        k = q * k_prev1 + k_prev2
        convergents_list.append((h, k))
        h_prev2, h_prev1 = h_prev1, h
        k_prev2, k_prev1 = k_prev1, k
    
    return convergents_list


if __name__ == "__main__":
    print("Testing Utility Functions...")
    print("-" * 50)
    
    # Test GCD
    print("\n1. Testing GCD:")
    print(f"   gcd(48, 18) = {gcd(48, 18)}")
    print(f"   gcd(100, 35) = {gcd(100, 35)}")
    
    # Test Extended GCD
    print("\n2. Testing Extended GCD:")
    g, x, y = extended_gcd(35, 15)
    print(f"   35*{x} + 15*{y} = {g}")
    
    # Test Modular Inverse
    print("\n3. Testing Modular Inverse:")
    print(f"   inverse of 3 mod 11 = {mod_inverse(3, 11)}")
    print(f"   inverse of 7 mod 26 = {mod_inverse(7, 26)}")
    
    # Test Primality
    print("\n4. Testing Primality:")
    test_numbers = [17, 18, 97, 100, 1009]
    for num in test_numbers:
        print(f"   is_prime({num}) = {is_prime(num)}")
    
    # Test Chinese Remainder Theorem
    print("\n5. Testing Chinese Remainder Theorem:")
    remainders = [2, 3, 2]
    moduli = [3, 5, 7]
    result = chinese_remainder_theorem(remainders, moduli)
    print(f"   x ≡ 2 (mod 3), x ≡ 3 (mod 5), x ≡ 2 (mod 7)")
    print(f"   x = {result}")
    
    # Test nth root
    print("\n6. Testing nth root:")
    print(f"   3rd root of 27 = {nth_root(27, 3)}")
    print(f"   3rd root of 1000 = {nth_root(1000, 3)}")
    
    print("\n✓ All tests completed!")
