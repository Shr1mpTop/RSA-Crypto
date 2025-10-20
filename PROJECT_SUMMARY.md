# RSA Encryption Algorithm Implementation and Attack Demonstration - Project Summary

## Project Overview

This is a comprehensive educational project that implements the RSA encryption algorithm from scratch and demonstrates various cryptographic attacks against weak RSA implementations. The project is designed to help students and developers understand:

1. How RSA encryption works at a fundamental level
2. Common vulnerabilities in RSA implementations
3. Practical attack methods against weak parameters
4. Best practices for secure RSA usage

## Technical Implementation

### Core Components

#### 1. RSA Core Implementation (`src/rsa_core.py`)

- **Key Generation**: Implements secure prime generation using Miller-Rabin primality test
- **Encryption/Decryption**: Standard RSA operations with PKCS#1 v1.5 padding
- **Digital Signatures**: Sign and verify message signatures
- **Support for Multiple Key Sizes**: 512, 1024, 2048, and 4096 bits

#### 2. Attack Implementations (`src/attacks/`)

##### Small Prime Factorization Attack
- **Target**: RSA keys using small prime numbers
- **Method**: Trial division and efficient factorization
- **Complexity**: O(√n) for small primes

##### Wiener's Attack
- **Target**: RSA with small private exponent d < N^(1/4)
- **Method**: Continued fractions algorithm
- **Success Rate**: Very high when d is sufficiently small

##### Common Modulus Attack
- **Target**: Multiple encryptions of same message with same n but different e
- **Method**: Extended Euclidean algorithm
- **Requirement**: gcd(e₁, e₂) = 1

##### Low Encryption Exponent Attack (Håstad's Broadcast Attack)
- **Target**: Small public exponent e with multiple recipients
- **Method**: Chinese Remainder Theorem
- **Requirement**: Same message sent to ≥ e recipients

##### Fermat's Factorization Attack
- **Target**: RSA keys where p and q are close together
- **Method**: Fermat's factorization method
- **Complexity**: Fast when |p - q| is small

##### Common Factor Attack
- **Target**: Multiple RSA moduli sharing common factors
- **Method**: GCD computation
- **Application**: Mass surveillance of weak key generation

### Cryptographic Principles

#### RSA Mathematical Foundation

1. **Key Generation**:
   - Select two distinct large primes: p, q
   - Compute modulus: n = p × q
   - Compute totient: φ(n) = (p-1)(q-1)
   - Choose public exponent: e (commonly 65537)
   - Compute private exponent: d ≡ e⁻¹ (mod φ(n))

2. **Encryption**:
   - Convert message to integer: m < n
   - Compute ciphertext: c ≡ m^e (mod n)

3. **Decryption**:
   - Compute plaintext: m ≡ c^d (mod n)

#### Security Considerations

- **Prime Selection**: p and q must be sufficiently large and randomly chosen
- **Key Size**: Minimum 2048 bits recommended for current security standards
- **Exponent Choice**: e should be coprime with φ(n), commonly 65537
- **Padding**: Always use secure padding schemes (PKCS#1 v1.5 or OAEP)
- **Key Uniqueness**: Never reuse keys across different encryption contexts

## Educational Value

### Learning Objectives

1. **Understand RSA internals**: Students learn the mathematical foundations
2. **Security awareness**: Recognize common cryptographic vulnerabilities
3. **Practical application**: See theory applied in working code
4. **Attack mindset**: Think like an attacker to build better defenses

### Suitable For

- Cryptography courses
- Computer security education
- CTF (Capture The Flag) training
- Security research and analysis

## Project Highlights

### Technical Depth

- ✅ Real cryptographic implementations (not toy examples)
- ✅ 2048-bit and 4096-bit key support
- ✅ Multiple attack vectors implemented
- ✅ Comprehensive test coverage

### Code Quality

- ✅ Clear, well-documented code
- ✅ Modular architecture
- ✅ Type hints and docstrings
- ✅ PEP 8 compliant

### Educational Features

- ✅ Step-by-step attack demonstrations
- ✅ Detailed comments explaining math
- ✅ Interactive command-line interface
- ✅ Performance benchmarking

## Use Cases

### 1. Academic Learning
- Classroom demonstrations
- Homework assignments
- Research projects

### 2. Security Training
- Understanding RSA vulnerabilities
- Cryptanalysis techniques
- Security best practices

### 3. CTF Preparation
- Practice for RSA challenges
- Learn common attack patterns
- Develop problem-solving skills

## Ethical Considerations

⚠️ **Important**: This project is strictly for educational purposes. Users must:

- Only use on systems they own or have permission to test
- Never deploy weak key generation in production
- Understand legal implications of cryptographic attacks
- Use knowledge responsibly and ethically

## Future Enhancements

Potential additions to the project:

- [ ] Timing attack demonstrations
- [ ] Side-channel attack simulations
- [ ] More padding schemes (OAEP)
- [ ] GUI interface
- [ ] Performance optimizations with C extensions
- [ ] Additional attacks (Pollard's p-1, etc.)

## Conclusion

This project provides a comprehensive, hands-on approach to understanding RSA encryption and its vulnerabilities. By combining solid implementation with practical attack demonstrations, it serves as an excellent educational resource for anyone interested in cryptography and information security.
