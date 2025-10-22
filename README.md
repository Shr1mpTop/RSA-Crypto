# RSA Crypto - Implementation & Security Analysis

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Educational](https://img.shields.io/badge/purpose-educational-orange.svg)

Educational RSA implementation with cryptographic attack demonstrations.

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run demonstrations
python demo.py                    # Full demonstration
python examples/basic_rsa.py      # Basic RSA operations
python examples/attack_demo.py    # Attack demonstrations

# Run as module (recommended)
python -m src.rsa_core            # Test core functions
python -m src.key_generation      # Test key generation
```

## 📁 Project Structure

```
RSA-Crypto/
├── src/
│   ├── rsa_core.py              # Encryption, decryption, sign, verify
│   ├── key_generation.py        # Key generation (normal & weak)
│   ├── utils.py                 # Math utilities
│   └── attacks/
│       ├── small_prime.py       # Small prime factorization
│       ├── wiener.py            # Wiener's attack (small d)
│       ├── common_modulus.py    # Common modulus attack
│       ├── common_factor.py     # Common factor attack
│       └── partial_key_exposure.py
├── examples/
│   ├── basic_rsa.py             # Usage examples
│   └── attack_demo.py           # Attack demonstrations
├── tests/
│   ├── test_rsa.py              # Unit tests
│   └── test_attacks.py
└── demo.py                      # Main demo
```

## 🔐 Core Features

### RSA Operations
- **Key Generation**: Secure prime generation with customizable key sizes
- **Encryption/Decryption**: Standard RSA with optional PKCS#1 v1.5 padding
- **Digital Signature**: Sign/verify messages using private/public keys

### Attack Demonstrations
| Attack | Condition | Description |
|--------|-----------|-------------|
| **Small Prime** | p or q < 2^32 | Trial division factorization |
| **Wiener's Attack** | d < N^0.25 | Continued fractions to recover d |
| **Common Modulus** | Same n, different e | Recover plaintext without keys |
| **Common Factor** | gcd(n1, n2) > 1 | Factor multiple related moduli |

## 💡 Usage Example

```python
from src.key_generation import generate_keypair
from src.rsa_core import encrypt, decrypt, sign, verify

# Generate keys
public_key, private_key = generate_keypair(2048)

# Encrypt/Decrypt
message = b"Hello, RSA!"
ciphertext = encrypt(message, public_key)
plaintext = decrypt(ciphertext, private_key)

# Sign/Verify
signature = sign(message, private_key)
is_valid = verify(message, signature, public_key)
```

## ⚠️ Security Notes

This is an **educational implementation**. For production use:
- Use established libraries (e.g., `cryptography`, `PyCryptodome`)
- Always use proper padding (OAEP for encryption, PSS for signatures)
- Use key sizes ≥ 2048 bits
- Never reuse modulus n across different key pairs

## 📚 References

- [RSA (cryptosystem) - Wikipedia](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [Twenty Years of Attacks on RSA](https://crypto.stanford.edu/~dabo/pubs/papers/RSA-survey.pdf)
- [PKCS #1: RSA Cryptography Specifications](https://tools.ietf.org/html/rfc8017)
