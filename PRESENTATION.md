# RSA Encryption Algorithm Implementation and Attack Demonstration
## Presentation Materials

---

## Slide 1: Title

**RSA Encryption Algorithm Implementation and Attack Demonstration**

*A Comprehensive Cryptographic Security Project*

Team Members: [Your Names]
Date: [Presentation Date]

---

## Slide 2: Project Overview

### What is RSA?

- **RSA**: Rivest-Shamir-Adleman public-key cryptosystem
- Widely used for secure data transmission
- Based on mathematical difficulty of factoring large numbers

### Project Goals

1. ✅ Implement complete RSA algorithm from scratch
2. ✅ Demonstrate security vulnerabilities with weak parameters
3. ✅ Educate on cryptographic best practices

---

## Slide 3: RSA Algorithm Fundamentals

### Key Generation

```
1. Choose two large prime numbers: p, q
2. Calculate modulus: n = p × q
3. Calculate totient: φ(n) = (p-1)(q-1)
4. Choose public exponent: e (coprime with φ(n))
5. Calculate private exponent: d ≡ e⁻¹ (mod φ(n))
```

### Encryption & Decryption

- **Encryption**: c = m^e mod n
- **Decryption**: m = c^d mod n

---

## Slide 4: Implementation Highlights

### Core Features

✅ **Full RSA Implementation**
- 512, 1024, 2048, 4096-bit key support
- Miller-Rabin primality testing
- PKCS#1 v1.5 padding

✅ **Six Attack Methods**
- Small prime factorization
- Wiener's attack
- Common modulus attack
- Low exponent attack
- Fermat's factorization
- Common factor attack

---

## Slide 5: Attack 1 - Small Prime Factorization

### Vulnerability
- Using small prime numbers makes factorization trivial

### Attack Method
```python
def small_prime_attack(n):
    for p in small_primes:
        if n % p == 0:
            q = n // p
            return recover_private_key(p, q, e)
```

### Defense
- Use primes ≥ 512 bits
- Random prime generation

---

## Slide 6: Attack 2 - Wiener's Attack

### Vulnerability
- Small private exponent: d < N^(1/4)

### Attack Method
- Use continued fractions to find d
- Based on convergents of e/n

### Mathematical Foundation
```
k/d ≈ e/φ(n)
```

### Defense
- Ensure d is sufficiently large
- d > N^(1/4)

---

## Slide 7: Attack 3 - Common Modulus Attack

### Vulnerability
- Reusing modulus n with different exponents e₁, e₂

### Attack Scenario
```
c₁ = m^e₁ mod n
c₂ = m^e₂ mod n
```

### Solution
- Use Extended Euclidean Algorithm
- Find s, t such that: s·e₁ + t·e₂ = 1
- Recover: m = c₁^s · c₂^t mod n

---

## Slide 8: Attack 4 - Low Exponent Attack

### Vulnerability
- Small e (like e=3) with same message to multiple recipients

### Håstad's Broadcast Attack
- If same message sent to k recipients with e=k
- Use Chinese Remainder Theorem
- Compute: m^e mod (n₁ × n₂ × ... × nₖ)
- Take e-th root to recover m

### Defense
- Use random padding
- Standard e=65537

---

## Slide 9: Attack 5 - Fermat's Factorization

### Vulnerability
- p and q are close together

### Method
```python
def fermat_factor(n):
    a = ceil(sqrt(n))
    while not is_perfect_square(a² - n):
        a += 1
    b = sqrt(a² - n)
    return (a - b, a + b)
```

### Defense
- Ensure |p - q| is large

---

## Slide 10: Attack 6 - Common Factor Attack

### Vulnerability
- Multiple RSA moduli sharing common factors

### Attack Method
```python
def common_factor_attack(n1, n2):
    p = gcd(n1, n2)
    if p > 1:
        q1 = n1 // p
        q2 = n2 // p
        return p, q1, q2
```

### Real-World Impact
- 2012: Researchers found 0.2% of RSA keys share factors!

---

## Slide 11: Demo Architecture

```
RSA-Crypto/
├── src/
│   ├── rsa_core.py          # Core RSA implementation
│   ├── key_generation.py    # Secure key generation
│   ├── attacks/             # Attack implementations
│   │   ├── small_prime.py
│   │   ├── wiener.py
│   │   ├── common_modulus.py
│   │   ├── low_exponent.py
│   │   ├── fermat.py
│   │   └── common_factor.py
│   └── utils.py
├── examples/                # Usage examples
├── tests/                   # Unit tests
└── demo.py                  # Interactive demo
```

---

## Slide 12: Performance Benchmarks

| Key Size | Key Gen | Encrypt | Decrypt |
|----------|---------|---------|---------|
| 512-bit  | 0.1s    | <0.01s  | 0.01s   |
| 1024-bit | 0.5s    | <0.01s  | 0.05s   |
| 2048-bit | 2.0s    | <0.01s  | 0.2s    |
| 4096-bit | 15s     | <0.01s  | 1.5s    |

*Tested on: Intel i7, 16GB RAM*

---

## Slide 13: Security Best Practices

### ✅ Recommendations

1. **Key Size**: Use ≥ 2048 bits
2. **Exponent**: Use e = 65537
3. **Prime Gap**: Ensure |p - q| is large
4. **Uniqueness**: Never reuse keys
5. **Padding**: Always use OAEP or PKCS#1 v1.5
6. **Rotation**: Regularly update keys

### ❌ Avoid

- Small primes or key sizes
- Sharing modulus across encryptions
- Using e=3 without padding

---

## Slide 14: Live Demonstration

### Demo Flow

1. **Generate RSA Keys** (2048-bit)
2. **Encrypt Message**
3. **Decrypt Message**
4. **Generate Weak Keys**
5. **Run Attacks**
6. **Compare Results**

```bash
python demo.py
```

---

## Slide 15: Code Quality

### Development Practices

✅ **Clean Code**
- PEP 8 compliant
- Comprehensive docstrings
- Type hints throughout

✅ **Testing**
- Unit tests for all components
- Integration tests
- Attack verification tests

✅ **Documentation**
- Detailed README
- Inline comments
- Mathematical explanations

---

## Slide 16: Educational Value

### Learning Outcomes

Students will understand:

1. **RSA Mathematics**: Number theory fundamentals
2. **Cryptographic Attacks**: Real-world vulnerability analysis
3. **Security Engineering**: Best practices and pitfalls
4. **Practical Implementation**: Theory to working code

### Suitable For

- 🎓 Cryptography courses
- 🔒 Security training
- 🚩 CTF preparation
- 🔬 Research projects

---

## Slide 17: Real-World Relevance

### Historical Vulnerabilities

- **2012**: Mining P2P networks found weak RSA keys
- **2015**: FREAK attack exploited export-grade RSA
- **2017**: ROCA vulnerability in key generation
- **Ongoing**: Common modulus attacks in TLS misconfigurations

### Industry Impact

- SSL/TLS certificates
- SSH authentication
- Email encryption (PGP/GPG)
- Software signing

---

## Slide 18: Challenges & Solutions

### Challenge 1: Large Number Arithmetic
**Solution**: Used Python's arbitrary precision integers

### Challenge 2: Prime Generation Performance
**Solution**: Miller-Rabin with optimized parameters

### Challenge 3: Attack Complexity
**Solution**: Modular design with clear interfaces

### Challenge 4: Demonstration Clarity
**Solution**: Interactive CLI with detailed output

---

## Slide 19: Future Enhancements

### Potential Additions

- [ ] **Timing Attacks**: Side-channel demonstrations
- [ ] **GUI Interface**: User-friendly visualization
- [ ] **Additional Attacks**: Pollard's p-1, ECM
- [ ] **Performance**: C extensions for speed
- [ ] **Padding Schemes**: OAEP implementation
- [ ] **Key Formats**: PEM/DER import/export

---

## Slide 20: Conclusion

### Project Achievements

✅ Complete RSA implementation (2048-bit)
✅ Six practical attack demonstrations
✅ Educational and well-documented
✅ Production-quality code structure

### Key Takeaways

1. **RSA is secure** - when implemented correctly
2. **Parameter choice is critical** - weak params = broken crypto
3. **Understanding attacks** - builds better defenses

### Thank You!

Questions?

---

## Additional Resources

### References

- [RSA Cryptosystem (Wikipedia)](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [Twenty Years of Attacks on RSA](https://crypto.stanford.edu/~dabo/pubs/papers/RSA-survey.pdf)
- [Handbook of Applied Cryptography](http://cacr.uwaterloo.ca/hac/)

### Project Links

- **GitHub**: [github.com/Shr1mpTop/RSA-Crypto](https://github.com/Shr1mpTop/RSA-Crypto)
- **Documentation**: See README.md
- **Quick Start**: See QUICKSTART.md
