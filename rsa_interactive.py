import sys
from src.key_generation import generate_keypair, generate_prime
from src.rsa_core import RSAKey, encrypt, decrypt, sign, verify
from src.utils import gcd, mod_inverse

def get_user_input(prompt, input_type=str, validator=None):
    while True:
        try:
            user_input = input(prompt).strip()
            if user_input.lower() == 'q':
                print("Exiting program...")
                sys.exit(0)
            
            if input_type == int:
                value = int(user_input)
            elif input_type == bytes:
                value = user_input.encode('utf-8')
            else:
                value = user_input
            
            if validator and not validator(value):
                print("Invalid input, please try again")
                continue
            
            return value
        except ValueError:
            print("Invalid format, please try again")
        except KeyboardInterrupt:
            print("\nExiting program...")
            sys.exit(0)


def setup_keys():
    """Setup RSA keys"""
    print("RSA Key Setup")
    print("Choose key generation method:")
    print("1. Auto-generate (Recommended)")
    print("2. Manual parameters")
    
    choice = get_user_input("\nPlease select (1/2): ", str, lambda x: x in ['1', '2'])
    
    if choice == '1':
        # Auto-generate
        bits = get_user_input(
            "\nEnter key size in bits (suggested: 512/1024/2048) [default: 1024]: ",
            str,
            lambda x: x == '' or (x.isdigit() and int(x) >= 256)
        )
        bits = 1024 if bits == '' else int(bits)
        
        e = get_user_input(
            "Enter public exponent e [default: 65537]: ",
            str,
            lambda x: x == '' or (x.isdigit() and int(x) > 1)
        )
        e = 65537 if e == '' else int(e)
        
        print(f"\nGenerating {bits}-bit key pair...")
        
        # Generate primes
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        while p == q:
            q = generate_prime(bits // 2)
        
        n = p * q
        phi = (p - 1) * (q - 1)
        
        if gcd(e, phi) != 1:
            print("e is not coprime with φ(n), regenerating...")
            return setup_keys()
        
        d = mod_inverse(e, phi)
        
        public_key = RSAKey(n, e, "public")
        private_key = RSAKey(n, d, "private")
        
    else:
        # Manual setup
        print("\nEnter RSA parameters:")
        p = get_user_input("Prime p: ", int, lambda x: x > 1)
        q = get_user_input("Prime q: ", int, lambda x: x > 1 and x != p)
        e = get_user_input("Public exponent e [default: 65537]: ", str, lambda x: x == '' or (x.isdigit() and int(x) > 1))
        e = 65537 if e == '' else int(e)
        
        n = p * q
        phi = (p - 1) * (q - 1)
        
        if gcd(e, phi) != 1:
            print(f"Error: e={e} is not coprime with φ(n)={phi}")
            return setup_keys()
        
        d = mod_inverse(e, phi)
        
        # Create key objects
        public_key = RSAKey(n, e, "public")
        private_key = RSAKey(n, d, "private")
    
    # Display key information
    print("Key generation successful!")
    print(f"Key Parameters:")
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"n = p × q = {n}")
    print(f"φ(n) = {phi}")
    print(f"Bit length = {n.bit_length()} bits")
    print(f"Public Key:")
    print(f"e = {e}")
    print(f"n = {n}")
    print(f"Private Key:")
    print(f"d = {d}")
    print(f"n = {n}")
    
    return public_key, private_key, {'p': p, 'q': q, 'n': n, 'e': e, 'd': d, 'phi': phi}


def demonstrate_encryption(public_key, private_key):
    """Demonstrate encryption and decryption"""
    print("Encryption/Decryption Demo")
    
    # Calculate maximum message length
    max_bytes = (public_key.n.bit_length() - 1) // 8
    print(f"Current key can encrypt max {max_bytes} bytes (~{max_bytes} ASCII characters)")
    
    message = get_user_input(
        "Enter message to encrypt: ",
        bytes,
        lambda x: len(x) > 0
    )
    
    # Check message length
    message_int = int.from_bytes(message, 'big')
    if message_int >= public_key.n:
        print(f"\nMessage too long!")
        print(f"Message length: {len(message)} bytes")
        print(f"Message value: {message_int}")
        print(f"Maximum value: {public_key.n - 1}")
        print(f"\nSolutions:")
        print(f"1. Use shorter message (≤ {max_bytes} bytes)")
        print(f"2. Generate larger key (recommended ≥ 512 bits)")
        return
    
    print(f"\nPlaintext:")
    print(f"Text: {message.decode('utf-8')}")
    print(f"Bytes: {message.hex()}")
    print(f"Integer: {message_int}")
    
    # Encrypt
    try:
        ciphertext = encrypt(message, public_key)
        print(f"\nCiphertext:")
        print(f"c = m^e mod n")
        print(f"c = {ciphertext}")
        print(f"Hex: {hex(ciphertext)}")
        
        # Decrypt
        decrypted = decrypt(ciphertext, private_key)
        print(f"\nDecrypted:")
        print(f"m = c^d mod n")
        print(f"Text: {decrypted.decode('utf-8')}")
        print(f"Bytes: {decrypted.hex()}")
        
        # Verify
        if message == decrypted:
            print(f"\nVerification successful: Original == Decrypted")
        else:
            print(f"\nVerification failed: Messages don't match!")
            
    except ValueError as e:
        print(f"\nEncryption failed: {e}")
        print("Hint: Message too long, use larger key or shorter message")


def demonstrate_signature(public_key, private_key):
    """Demonstrate digital signature"""
    print("Digital Signature Demo")
    
    # Calculate maximum message length
    max_bytes = (public_key.n.bit_length() - 1) // 8
    print(f"Current key can sign max {max_bytes} bytes (~{max_bytes} ASCII characters)")
    
    message = get_user_input(
        "Enter message to sign: ",
        bytes,
        lambda x: len(x) > 0
    )
    
    # Check message length
    message_int = int.from_bytes(message, 'big')
    if message_int >= public_key.n:
        print(f"\nMessage too long!")
        print(f"Message length: {len(message)} bytes")
        print(f"Message value: {message_int}")
        print(f"Maximum value: {public_key.n - 1}")
        print(f"\nSolutions:")
        print(f"1. Use shorter message (≤ {max_bytes} bytes)")
        print(f"2. Generate larger key (recommended ≥ 512 bits)")
        return
    
    print(f"\nOriginal Message:")
    print(f"   {message.decode('utf-8')}")
    
    # Sign
    try:
        signature = sign(message, private_key)
        print(f"\nDigital Signature:")
        print(f"s = m^d mod n")
        print(f"s = {signature}")
        print(f"Hex: {hex(signature)}")
        
        # Verify signature
        is_valid = verify(message, signature, public_key)
        print(f"\nSignature Verification:")
        print(f"m' = s^e mod n")
        if is_valid:
            print(f"Signature valid! Message is authentic and from private key holder")
        else:
            print(f"Signature invalid!")
        
        # Test tampered message
        print(f"\nTesting Message Tampering:")
        tampered_message = b"Tampered message"
        is_valid_tampered = verify(tampered_message, signature, public_key)
        print(f"Verifying with tampered message: {'Invalid' if not is_valid_tampered else 'Valid'}")
        
    except ValueError as e:
        print(f"\nSigning failed: {e}")
        print("Hint: Message too long, use larger key or shorter message")


def main_menu(public_key, private_key, params):
    """Main menu"""
    while True:

        print("RSA Operations Menu")
        print("1. View key information")
        print("2. Encryption/Decryption demo")
        print("3. Digital signature demo")
        print("4. Regenerate keys")
        print("5. Exit")
        
        choice = get_user_input("\nSelect operation (1-5): ", str, lambda x: x in ['1', '2', '3', '4', '5'])
        
        if choice == '1':
            # View key information
    
            print("Current Key Information")
    
            print(f"p = {params['p']}")
            print(f"q = {params['q']}")
            print(f"n = {params['n']} ({params['n'].bit_length()} bits)")
            print(f"e = {params['e']}")
            print(f"d = {params['d']}")
            print(f"φ(n) = {params['phi']}")
            
        elif choice == '2':
            demonstrate_encryption(public_key, private_key)
            
        elif choice == '3':
            demonstrate_signature(public_key, private_key)
            
        elif choice == '4':
            return True  # Regenerate keys
            
        elif choice == '5':
    
            print("exiting...")
            sys.exit(0)


def main():
    """Main program"""
    print("  RSA Interactive Demonstration")
    print("  Educational Cryptography Tool")
    print("Hint: Type 'q' anytime to exit")
    print()
    
    while True:
        public_key, private_key, params = setup_keys()
        if not main_menu(public_key, private_key, params):
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram terminated")
        sys.exit(0)
