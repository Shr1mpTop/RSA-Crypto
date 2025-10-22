import random
from typing import Tuple
from .utils import mod_inverse, bytes_to_int, int_to_bytes

class RSAKey:    
    def __init__(self, n: int, exponent: int, key_type: str = "public", p: int = None, q: int = None):
        self.n = n
        self.exponent = exponent
        self.key_type = key_type
        self.bit_length = n.bit_length()
        # Store p and q for CRT optimization (only for private keys)
        self.p = p
        self.q = q
        # Pre-compute CRT parameters if p and q are available
        if p and q and key_type == "private":
            self._precompute_crt_params()
        else:
            self.dp = None
            self.dq = None
            self.qinv = None
    
    def _precompute_crt_params(self):
        """Pre-compute CRT parameters for faster decryption"""
        self.dp = self.exponent % (self.p - 1)
        self.dq = self.exponent % (self.q - 1)
        self.qinv = mod_inverse(self.q, self.p)
    
    def __repr__(self):
        crt_status = " [CRT-enabled]" if self.dp is not None else ""
        return f"RSAKey(type={self.key_type}, bits={self.bit_length}, n={hex(self.n)[:20]}..., exp={self.exponent}{crt_status})"

def encrypt(message: bytes, public_key: RSAKey) -> int:
    m = bytes_to_int(message)    
    # Check if message is too long
    if m >= public_key.n:
        raise ValueError("Message too long for key size")    
    # Perform RSA encryption: c = m^e mod n
    c = pow(m, public_key.exponent, public_key.n)
    return c

def decrypt(ciphertext: int, private_key: RSAKey) -> bytes:
    """
    Decrypt using standard RSA or CRT if available.
    Automatically uses CRT if p and q are stored in the key.
    """
    if private_key.dp is not None:
        # Use CRT optimization
        return decrypt_with_crt(ciphertext, private_key)
    else:
        # Standard decryption
        m = pow(ciphertext, private_key.exponent, private_key.n)    
        message = int_to_bytes(m)
        return message


def decrypt_with_crt(ciphertext: int, private_key: RSAKey) -> bytes:
    """
    Decrypt using Chinese Remainder Theorem (CRT) optimization.
    This is approximately 4x faster than standard decryption.
    
    CRT Formula:
        m1 = c^dp mod p  (where dp = d mod (p-1))
        m2 = c^dq mod q  (where dq = d mod (q-1))
        h = qinv * (m1 - m2) mod p
        m = m2 + h * q
    
    Args:
        ciphertext: The encrypted message
        private_key: RSAKey with p, q, and CRT parameters
    
    Returns:
        Decrypted message as bytes
    """
    if private_key.p is None or private_key.q is None:
        raise ValueError("CRT decryption requires p and q to be stored in private key")
    
    # Use pre-computed parameters if available
    if private_key.dp is None:
        private_key._precompute_crt_params()
    
    # Compute m1 = c^dp mod p
    m1 = pow(ciphertext, private_key.dp, private_key.p)
    
    # Compute m2 = c^dq mod q
    m2 = pow(ciphertext, private_key.dq, private_key.q)
    
    # Compute h = qinv * (m1 - m2) mod p
    h = (private_key.qinv * (m1 - m2)) % private_key.p
    
    # Compute m = m2 + h * q
    m = m2 + h * private_key.q
    
    message = int_to_bytes(m)
    return message


def sign(message: bytes, private_key: RSAKey) -> int:
    """
    Sign a message using RSA private key.
    Automatically uses CRT if available for faster signing.
    """
    m = bytes_to_int(message)    
    # Check if message is too long
    if m >= private_key.n:
        raise ValueError("Message too long for key size")
    
    # Use CRT if available (same optimization as decryption)
    if private_key.dp is not None:
        return sign_with_crt(message, private_key)
    else:
        # Standard signing: s = m^d mod n
        signature = pow(m, private_key.exponent, private_key.n)
        return signature


def sign_with_crt(message: bytes, private_key: RSAKey) -> int:
    """
    Sign using Chinese Remainder Theorem (CRT) optimization.
    Approximately 4x faster than standard signing.
    
    Args:
        message: The message to sign
        private_key: RSAKey with p, q, and CRT parameters
    
    Returns:
        Signature as integer
    """
    if private_key.p is None or private_key.q is None:
        raise ValueError("CRT signing requires p and q to be stored in private key")
    
    m = bytes_to_int(message)
    
    # Use pre-computed parameters if available
    if private_key.dp is None:
        private_key._precompute_crt_params()
    
    # Compute s1 = m^dp mod p
    s1 = pow(m, private_key.dp, private_key.p)
    
    # Compute s2 = m^dq mod q
    s2 = pow(m, private_key.dq, private_key.q)
    
    # Compute h = qinv * (s1 - s2) mod p
    h = (private_key.qinv * (s1 - s2)) % private_key.p
    
    # Compute signature = s2 + h * q
    signature = s2 + h * private_key.q
    
    return signature


def verify(message: bytes, signature: int, public_key: RSAKey) -> bool:
    try:
        # Verify: m' = s^e mod n
        m_prime = pow(signature, public_key.exponent, public_key.n)
        m = bytes_to_int(message)
        return m == m_prime
    except Exception:
        return False


def encrypt_with_padding(message: bytes, public_key: RSAKey) -> int:
    k = (public_key.bit_length + 7) // 8
    # Calculate required padding length
    mLen = len(message)
    if mLen > k - 11:
        raise ValueError("Message too long for key size with padding")
    ps_len = k - mLen - 3
    ps = bytes([random.randint(1, 255) for _ in range(ps_len)])    
    padded = b'\x00\x02' + ps + b'\x00' + message
    return encrypt(padded, public_key)


def decrypt_with_padding(ciphertext: int, private_key: RSAKey) -> bytes:
    m = pow(ciphertext, private_key.exponent, private_key.n)
    k = (private_key.n.bit_length() + 7) // 8
    padded = m.to_bytes(k, byteorder='big')
    
    # Check padding format
    if len(padded) < 11:
        raise ValueError("Decryption error: invalid padding")    
    if padded[0:2] != b'\x00\x02':
        raise ValueError("Decryption error: invalid padding format")    
    # Find the 0x00 separator
    separator_index = padded.find(b'\x00', 2)
    if separator_index == -1:
        raise ValueError("Decryption error: no separator found")
    
    # Extract message
    message = padded[separator_index + 1:]
    return message


if __name__ == "__main__":
    # Simple test
    from .key_generation import generate_keypair
    
    print("Testing RSA Core Implementation...")
    print("-" * 50)
    
    # Generate keys
    print("Generating 1024-bit key pair...")
    public_key, private_key = generate_keypair(1024)
    print(f"Public key: {public_key}")
    print(f"Private key: {private_key}")
    print()
    
    # Test encryption/decryption
    message = b"Hello, RSA!"
    print(f"Original message: {message}")
    
    ciphertext = encrypt(message, public_key)
    print(f"Ciphertext: {ciphertext}")
    
    decrypted = decrypt(ciphertext, private_key)
    print(f"Decrypted message: {decrypted}")
    print(f"Match: {message == decrypted}")
    print()
    
    # Test signature
    signature = sign(message, private_key)
    print(f"Signature: {signature}")
    
    valid = verify(message, signature, public_key)
    print(f"Signature valid: {valid}")
    
    invalid = verify(b"Wrong message", signature, public_key)
    print(f"Invalid signature: {not invalid}")
