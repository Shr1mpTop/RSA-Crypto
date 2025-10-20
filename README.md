# RSA Encryption Algorithm Implementation and Attack Demonstration

🔒 A comprehensive RSA encryption algorithm implementation and security analysis project

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Educational](https://img.shields.io/badge/purpose-educational-orange.svg)

## 📋 Project Overview

This project implements a complete RSA encryption algorithm and demonstrates various attack methods against RSA with weak parameters. This is an educational project designed to provide deep understanding of RSA's working principles and security vulnerabilities.

> ⚠️ **Warning**: This project is for educational purposes only. The weak key generation features are only for demonstrating attack principles and should NEVER be used in production environments.

## ✨ Key Features

### 1. Complete RSA Implementation

- ✅ Support for real-size RSA keys (512-bit, 1024-bit, 2048-bit, 4096-bit)
- ✅ Secure prime number generation (Miller-Rabin primality test)
- ✅ Standard encryption/decryption operations
- ✅ Digital signature functionality
- ✅ PKCS#1 v1.5 padding scheme

### 2. RSA Attack Demonstrations

- 🎯 Small Prime Factorization Attack - Against weak keys with small primes
- 🎯 Wiener's Attack - Against small private exponent d
- 🎯 Common Modulus Attack - Attack on same modulus n with different public exponents e
- 🎯 Low Encryption Exponent Attack - Against small public exponent e (Håstad's Broadcast Attack)
- 🎯 Fermat's Factorization Attack - When p and q are close together
- 🎯 Common Factor Attack - Multiple moduli sharing common factors

### 3. Visualization and Demonstration

- 📊 Interactive command-line interface
- 📊 Detailed attack process visualization
- 📊 Performance benchmarking
- 📊 Parameter security analysis

## 🚀 Quick Start

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run Demonstrations

```bash
# Full demonstration (includes all attack methods)
python demo.py

# Run basic RSA demonstration
python examples/basic_rsa.py

# Run specific attack demonstrations
python examples/attack_demo.py
```

## 📁 Project Structure

```
RSA-Crypto/
├── src/
│   ├── rsa_core.py          # RSA core implementation
│   ├── key_generation.py    # Key generation
│   ├── attacks/
│   │   ├── small_prime.py   # Small prime attack
│   │   ├── wiener.py        # Wiener's attack
│   │   ├── common_modulus.py # Common modulus attack
│   │   ├── low_exponent.py  # Low exponent attack
│   │   ├── fermat.py        # Fermat's factorization
│   │   └── common_factor.py # Common factor attack
│   └── utils.py             # Utility functions
├── examples/
│   ├── basic_rsa.py         # Basic usage examples
│   └── attack_demo.py       # Attack demonstrations
├── tests/
│   ├── test_rsa.py          # RSA tests
│   └── test_attacks.py      # Attack tests
├── demo.py                  # Main demonstration program
├── requirements.txt
└── README.md
```

## 🎓 Technical Details

### RSA Algorithm Principles

1. **Key Generation**: Select two large primes p and q, calculate n = p × q
2. **Public Key**: (e, n), where e is coprime with φ(n)
3. **Private Key**: (d, n), where d × e ≡ 1 (mod φ(n))
4. **Encryption**: c = m^e mod n
5. **Decryption**: m = c^d mod n

### Attack Methods Explained

#### 1. Small Prime Factorization Attack

- **Principle**: When p or q is small, n can be quickly factorized using trial division
- **Defense**: Use sufficiently large primes (at least 512 bits)

#### 2. Wiener's Attack

- **Principle**: When d < N^(1/4), d can be recovered using continued fractions algorithm
- **Defense**: Ensure d is sufficiently large

#### 3. Common Modulus Attack

- **Principle**: Same message encrypted with same n but different e can recover plaintext
- **Defense**: Use different n for each encryption

#### 4. Low Encryption Exponent Attack

- **Principle**: When e is small and same message is sent to multiple recipients, Chinese Remainder Theorem can recover plaintext
- **Defense**: Use safe e values (such as 65537) and add random padding

## 📊 Performance Benchmarks

| Key Size | Key Generation | Encryption | Decryption |
|----------|---------------|------------|------------|
| 512-bit  | ~0.1s        | <0.01s     | ~0.01s     |
| 1024-bit | ~0.5s        | <0.01s     | ~0.05s     |
| 2048-bit | ~2s          | <0.01s     | ~0.2s      |
| 4096-bit | ~15s         | <0.01s     | ~1.5s      |

## ⚠️ Security Recommendations

1. ✅ Use at least 2048-bit keys
2. ✅ Use standard public exponent e = 65537
3. ✅ Ensure p and q have sufficient gap
4. ✅ Each user should use independent key pairs
5. ✅ Use secure padding schemes (OAEP)
6. ✅ Regularly rotate keys

## 🎯 Demonstration Highlights

- Uses real-size RSA moduli (2048 bits)
- Complete implementation of various practical attack scenarios
- Detailed attack process visualization
- Clear code structure with comprehensive comments
- Includes complete test cases

## 👥 Team Collaboration

This project is suitable for 2-person group collaboration:

- **Member 1**: Responsible for RSA core implementation and basic attacks
- **Member 2**: Responsible for advanced attacks and demonstration interface

## 📚 References

- [RSA Algorithm Principles](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [Twenty Years of Attacks on the RSA Cryptosystem](https://crypto.stanford.edu/~dabo/pubs/papers/RSA-survey.pdf)
- [Applied Cryptography - Bruce Schneier](https://www.schneier.com/books/applied-cryptography/)

## 📄 License

This project is for educational purposes only. Do not use for illegal purposes.

---

⚡ **Key Points Covered**:

- ✅ Real-size RSA moduli (2048 bits)
- ✅ Multiple weak parameter attack demonstrations
- ✅ Sufficient technical depth
- ✅ Complete demonstrations and code
