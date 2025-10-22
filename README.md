# RSA Encryption Algorithm Implementation and Attack Demonstration
A comprehensive RSA encryption algorithm implementation and security analysis project

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Educational](https://img.shields.io/badge/purpose-educational-orange.svg)

## 📋 Project Overview
This project implements a complete RSA encryption algorithm and demonstrates various attack methods against RSA with weak parameters. This is an educational project designed to provide deep understanding of RSA's working principles and security vulnerabilities.


## Quick Start
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
## Technical Details
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

## 📚 References

- [RSA Algorithm Principles](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [Twenty Years of Attacks on the RSA Cryptosystem](https://crypto.stanford.edu/~dabo/pubs/papers/RSA-survey.pdf)
- [Applied Cryptography - Bruce Schneier](https://www.schneier.com/books/applied-cryptography/)
