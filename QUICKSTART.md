# Quick Start Guide

## Installation

1. **Clone the repository**:
```bash
git clone https://github.com/Shr1mpTop/RSA-Crypto.git
cd RSA-Crypto
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

## Basic Usage

### 1. Run Complete Demo

```bash
python demo.py
```

This will demonstrate:
- RSA key generation
- Encryption and decryption
- All attack methods

### 2. Basic RSA Operations

```bash
python examples/basic_rsa.py
```

Examples include:
- Key pair generation
- Message encryption
- Message decryption
- Digital signatures

### 3. Attack Demonstrations

```bash
python examples/attack_demo.py
```

Demonstrates various attack methods against weak RSA parameters.

## Code Examples

### Generate RSA Keys

```python
from src.key_generation import generate_keypair

# Generate 2048-bit RSA key pair
public_key, private_key = generate_keypair(2048)
print(f"Public key: {public_key}")
print(f"Private key: {private_key}")
```

### Encrypt and Decrypt

```python
from src.rsa_core import encrypt, decrypt

message = "Hello, RSA!"
ciphertext = encrypt(message, public_key)
plaintext = decrypt(ciphertext, private_key)
print(f"Decrypted: {plaintext}")
```

### Run an Attack

```python
from src.attacks.small_prime import small_prime_attack

# Attack weak RSA with small primes
private_key = small_prime_attack(public_key, ciphertext)
```

## Verification

Run the verification script to ensure everything is working:

```bash
python verify.py
```

This will test:
- ✅ Core RSA functionality
- ✅ All attack implementations
- ✅ System compatibility

## Next Steps

- Read [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) for detailed project overview
- Read [PRESENTATION.md](PRESENTATION.md) for presentation materials
- Explore the `examples/` directory for more code samples
- Check the `tests/` directory for unit tests
