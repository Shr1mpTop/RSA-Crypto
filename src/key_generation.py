import random
from typing import Tuple
from .utils import is_prime, gcd, mod_inverse
from .rsa_core import RSAKey

def generate_prime(bits: int) -> int:
    while True:
        num = random.getrandbits(bits)
        # Ensure it's odd and has the right bit length
        num |= (1 << bits - 1) | 1        
        if is_prime(num):
            return num
        
def generate_keypair(bits: int = 2048, e: int = 65537) -> Tuple[RSAKey, RSAKey]:
    print(f"{bits}-bit")
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    
    # Ensure p != q
    while p == q:
        q = generate_prime(bits // 2)    

    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError(f"e={e} is not coprime with phi(n)")
    d = mod_inverse(e, phi)    
    # Create key objects with p and q for CRT optimization
    public_key = RSAKey(n, e, "public")
    private_key = RSAKey(n, d, "private", p=p, q=q)
    
    print(f"Key generation complete (CRT-enabled)")
    return public_key, private_key

def generate_weak_keypair_small_primes(bits: int = 2048, e: int = 65537) -> Tuple[RSAKey, RSAKey]:
    p = generate_prime(24)
    q = generate_prime(24)

    while p == q:
        q = generate_prime(24)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    
    public_key = RSAKey(n, e, "public")
    private_key = RSAKey(n, d, "private", p=p, q=q)
    
    print(f"p={p}\nq={q}")
    return public_key, private_key


def generate_weak_keypair_close_primes(bits: int = 2048, e: int = 65537) -> Tuple[RSAKey, RSAKey]:
    p = generate_prime(bits // 2)
    
    # Find a prime q close to p
    max_attempts = 10000
    attempts = 0
    while attempts < max_attempts:
        diff = random.randint(1, 1000)
        q = p + diff
        
        # Check if q is odd, if not make it odd
        if q % 2 == 0:
            q += 1
        
        # Search for next prime near p + diff
        search_limit = 10000
        for _ in range(search_limit):
            if is_prime(q):
                break
            q += 2
        
        if is_prime(q) and q != p:
            break
        
        attempts += 1
    
    if attempts >= max_attempts:
        raise ValueError("Failed to generate close primes after maximum attempts")
    
    n = p * q
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)    
    public_key = RSAKey(n, e, "public")
    private_key = RSAKey(n, d, "private", p=p, q=q)
    
    print(f"p={p}\nq={q}\n|p-q|={abs(p-q)}")
    return public_key, private_key


def generate_weak_keypair_small_d(bits: int = 2048) -> Tuple[RSAKey, RSAKey]:
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while p == q:
        q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    max_d = int(n ** 0.25)
    attempts = 0
    while attempts < 10000:
        d = random.randint(max_d // 2, max_d)
        if gcd(d, phi) == 1:
            break
        attempts += 1
    
    if attempts >= 10000:
        d = 3
        while gcd(d, phi) != 1 and d < max_d:
            d += 2

    e = mod_inverse(d, phi)
    
    public_key = RSAKey(n, e, "public")
    private_key = RSAKey(n, d, "private", p=p, q=q)
    
    print(f"✓ Weak key generation complete (d={d})")
    return public_key, private_key


if __name__ == "__main__":    
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
