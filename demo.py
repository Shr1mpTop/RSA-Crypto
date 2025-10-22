import sys
import os

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from src.key_generation import generate_keypair, generate_prime
from src.rsa_core import encrypt, decrypt, RSAKey, sign, verify
from src.utils import gcd, mod_inverse

def print_header(title):
    """Print a formatted header."""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)


def get_user_input(prompt, input_type=str, validator=None):
    """Get validated user input."""
    while True:
        try:
            user_input = input(prompt).strip()
            if user_input.lower() == 'q':
                return None  # Signal to go back
            
            if input_type == int:
                value = int(user_input)
            elif input_type == bytes:
                value = user_input.encode('utf-8')
            else:
                value = user_input
            
            if validator and not validator(value):
                print("✗ Invalid input, please try again")
                continue
            
            return value
        except ValueError:
            print("✗ Invalid format, please try again")
        except KeyboardInterrupt:
            print("\n\nReturning to menu...")
            return None

def demonstrate_secure_rsa():
    """Demonstrate secure RSA usage."""
    print_header("DEMONSTRATION: Secure RSA Implementation")
    
    print("\n1. Generating secure 2048-bit RSA key pair...")
    public_key, private_key = generate_keypair(2048)
    print(f"  Keys generated successfully")
    print(f"  Modulus bit length: {public_key.bit_length} bits")
    print(f"  Public exponent: e = {public_key.exponent}")
    
    print("\n2. Encrypting a message...")
    message = b"This is a secure message encrypted with 2048-bit RSA!"
    print(f"Original message: {message}")
    
    ciphertext = encrypt(message, public_key)
    print(f"Ciphertext length: {len(str(ciphertext))} digits")
    
    print("\n3. Decrypting the message...")
    decrypted = decrypt(ciphertext, private_key)
    print(f"Decrypted message: {decrypted}")
    print(f"Decryption successful: {message == decrypted}")


def setup_keys_interactive():
    """Interactive RSA key setup with multiple options."""
    print_header("Interactive RSA Key Setup")
    print("Choose key generation method:")
    print("  1. Auto-generate (Recommended)")
    print("  2. Manual parameters (Advanced)")
    print("  0. Back to main menu")
    
    choice = get_user_input("\nSelect option (1/2/0): ", str, lambda x: x in ['1', '2', '0'])
    if choice is None or choice == '0':
        return None
    
    if choice == '1':
        # Auto-generate
        bits = get_user_input(
            "\nEnter key size in bits: ",
            str,
            lambda x: x == '' or (x.isdigit() and int(x) >= 256)
        )
        if bits is None:
            return None
        bits = 1024 if bits == '' else int(bits)
        
        e = get_user_input(
            "Enter public exponent e [default: 65537]: ",
            str,
            lambda x: x == '' or (x.isdigit() and int(x) > 1)
        )
        if e is None:
            return None
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
            print("✗ e is not coprime with φ(n), please try again...")
            return setup_keys_interactive()
        
        d = mod_inverse(e, phi)
        
        public_key = RSAKey(n, e, "public")
        private_key = RSAKey(n, d, "private")
        
    else:
        # Manual setup
        print("\nAdvanced Mode: Manual Parameter Entry")
        p = get_user_input("Enter prime p: ", int, lambda x: x > 1)
        if p is None:
            return None
        
        q = get_user_input("Enter prime q: ", int, lambda x: x > 1 and x != p)
        if q is None:
            return None
        
        e = get_user_input("Enter public exponent e [default: 65537]: ", str, 
                          lambda x: x == '' or (x.isdigit() and int(x) > 1))
        if e is None:
            return None
        e = 65537 if e == '' else int(e)
        
        n = p * q
        phi = (p - 1) * (q - 1)
        
        if gcd(e, phi) != 1:
            print(f"✗ Error: e={e} is not coprime with φ(n)={phi}")
            return setup_keys_interactive()
        
        d = mod_inverse(e, phi)
        
        public_key = RSAKey(n, e, "public")
        private_key = RSAKey(n, d, "private")
    
    # Display key information
    print("\n✓ Key generation successful!")
    print(f"\nKey Parameters:")
    print(f"  p = {p}")
    print(f"  q = {q}")
    print(f"  n = p × q = {n}")
    print(f"  φ(n) = {phi}")
    print(f"  Bit length = {n.bit_length()} bits")
    print(f"\nPublic Key:")
    print(f"  e = {e}")
    print(f"  n = {n}")
    print(f"\nPrivate Key:")
    print(f"  d = {d}")
    print(f"  n = {n}")
    
    return public_key, private_key, {'p': p, 'q': q, 'n': n, 'e': e, 'd': d, 'phi': phi}


def demonstrate_encryption_interactive(public_key, private_key):
    """Interactive encryption and decryption demonstration."""
    print_header("Encryption/Decryption Demo")
    
    # Calculate maximum message length
    max_bytes = (public_key.n.bit_length() - 1) // 8
    print(f"Current key can encrypt max {max_bytes} bytes (~{max_bytes} ASCII characters)")
    
    message = get_user_input(
        "\nEnter message to encrypt: ",
        bytes,
        lambda x: len(x) > 0
    )
    if message is None:
        return
    
    # Check message length
    message_int = int.from_bytes(message, 'big')
    if message_int >= public_key.n:
        print(f"\nMessage too long!")
        print(f"  Message length: {len(message)} bytes")
        print(f"  Message value: {message_int}")
        print(f"  Maximum value: {public_key.n - 1}")
        print(f"\nSolutions:")
        print(f"  1. Use shorter message (≤ {max_bytes} bytes)")
        print(f"  2. Generate larger key (recommended ≥ 512 bits)")
        return
    
    print(f"\nPlaintext:")
    print(f"  Text: {message.decode('utf-8')}")
    print(f"  Bytes: {message.hex()}")
    print(f"  Integer: {message_int}")
    
    # Encrypt
    try:
        ciphertext = encrypt(message, public_key)
        print(f"\nCiphertext:")
        print(f"  c = m^e mod n")
        print(f"  c = {ciphertext}")
        print(f"  Hex: {hex(ciphertext)}")
        
        # Decrypt
        decrypted = decrypt(ciphertext, private_key)
        print(f"\nDecrypted:")
        print(f"  m = c^d mod n")
        print(f"  Text: {decrypted.decode('utf-8')}")
        print(f"  Bytes: {decrypted.hex()}")
        
        # Verify
        if message == decrypted:
            print(f"\n✓ Verification successful: Original == Decrypted")
        else:
            print(f"\n✗ Verification failed: Messages don't match!")
            
    except ValueError as e:
        print(f"\n✗ Encryption failed: {e}")
        print("Hint: Message too long, use larger key or shorter message")


def demonstrate_signature_interactive(public_key, private_key):
    """Interactive digital signature demonstration."""
    print_header("Digital Signature Demo")
    
    # Calculate maximum message length
    max_bytes = (public_key.n.bit_length() - 1) // 8
    print(f"Current key can sign max {max_bytes} bytes (~{max_bytes} ASCII characters)")
    
    message = get_user_input(
        "\nEnter message to sign: ",
        bytes,
        lambda x: len(x) > 0
    )
    if message is None:
        return
    
    # Check message length
    message_int = int.from_bytes(message, 'big')
    if message_int >= public_key.n:
        print(f"\n✗ Message too long!")
        print(f"  Message length: {len(message)} bytes")
        print(f"  Message value: {message_int}")
        print(f"  Maximum value: {public_key.n - 1}")
        return
    
    print(f"\nOriginal Message:")
    print(f"  {message.decode('utf-8')}")
    
    # Sign
    try:
        signature = sign(message, private_key)
        print(f"\nDigital Signature:")
        print(f"  s = m^d mod n")
        print(f"  s = {signature}")
        print(f"  Hex: {hex(signature)}")
        
        # Verify signature
        is_valid = verify(message, signature, public_key)
        print(f"\nSignature Verification:")
        print(f"  m' = s^e mod n")
        if is_valid:
            print(f" Signature valid! Message is authentic and from private key holder")
        else:
            print(f" Signature invalid!")
        
        # Test tampered message
        print(f"\nTesting Message Tampering:")
        tampered_message = b"Tampered message"
        is_valid_tampered = verify(tampered_message, signature, public_key)
        print(f"  Verifying with tampered message: {'✗ Invalid' if not is_valid_tampered else '✓ Valid'}")
        
    except ValueError as e:
        print(f"\n✗ Signing failed: {e}")
        print("Hint: Message too long, use larger key or shorter message")


def interactive_rsa_menu():
    """Interactive RSA operations menu."""
    print_header("Interactive RSA Operations")
    print("Tip: Type 'q' at any prompt to return to this menu")
    
    # Setup keys first
    result = setup_keys_interactive()
    if result is None:
        return
    
    public_key, private_key, params = result
    
    while True:
        print("\n" + "-"*70)
        print("RSA Operations Menu:")
        print("  1. View key information")
        print("  2. Encrypt/Decrypt message")
        print("  3. Sign/Verify message")
        print("  4. Regenerate keys")
        print("  0. Back to main menu")
        
        choice = get_user_input("\nSelect operation (1-4/0): ", str, 
                               lambda x: x in ['1', '2', '3', '4', '0'])
        
        if choice is None or choice == '0':
            break
            
        if choice == '1':
            # View key information
            print_header("Current Key Information")
            print(f"Parameters:")
            print(f"  p = {params['p']}")
            print(f"  q = {params['q']}")
            print(f"  n = {params['n']} ({params['n'].bit_length()} bits)")
            print(f"  e = {params['e']}")
            print(f"  d = {params['d']}")
            print(f"  φ(n) = {params['phi']}")
            
        elif choice == '2':
            demonstrate_encryption_interactive(public_key, private_key)
            
        elif choice == '3':
            demonstrate_signature_interactive(public_key, private_key)
            
        elif choice == '4':
            result = setup_keys_interactive()
            if result is not None:
                public_key, private_key, params = result


def demonstrate_attacks():
    print_header("ATTACK DEMONSTRATIONS")
    
    print("\nWARNING: The following demonstrates attacks on WEAK RSA keys")
    print("    These are for EDUCATIONAL purposes only!")
    print("    NEVER use weak parameters in production!")
    
    attacks = [
        {
            "name": "Small Prime Factorization Attack",
            "description": "Attacking RSA with small prime factors",
            "module": "src.attacks.small_prime",
            "function": "demonstrate_small_prime_attack"
        },
        {
            "name": "Wiener's Attack",
            "description": "Attacking RSA with small private exponent d",
            "module": "src.attacks.wiener",
            "function": "demonstrate_wiener_attack"
        },
        {
            "name": "Common Modulus Attack",
            "description": "Attacking RSA when same modulus is reused",
            "module": "src.attacks.common_modulus",
            "function": "demonstrate_common_modulus_attack"
        },
        {
            "name": "Common Factor Attack",
            "description": "Attacking multiple RSA keys sharing factors",
            "module": "src.attacks.common_factor",
            "function": "demonstrate_common_factor_attack"
        },
        {
            "name": "Partial Key Exposure Attack",
            "description": "Attacking RSA when partial key bits are leaked",
            "module": "src.attacks.partial_key_exposure",
            "function": "demonstrate_partial_key_exposure_attack"
        }
    ]
    
    for i, attack in enumerate(attacks, 1):
        print(f"\n\n{'#'*70}")
        print(f"# ATTACK {i}/{len(attacks)}: {attack['name']}")
        print(f"# {attack['description']}")
        print(f"{'#'*70}")
        
        try:
            module = __import__(attack['module'], fromlist=[attack['function']])
            demo_func = getattr(module, attack['function'])
            demo_func()
        except Exception as e:
            print(f"\n✗ Error: {e}")
            import traceback
            traceback.print_exc()


def show_menu():
    """Display the main menu."""
    print("RSA System")
    print("Choose an option:")
    print("  1. RSA")
    print("  2. Secure RSA")
    print("  3. Attack")
    print("  4. Specific Attack")
    print("  5. Basic Examples")
    print("  0. Exit")

def show_attack_menu():
    """Display the attack selection menu."""
    print("\nSelect an attack to demonstrate:")
    print("  1. Small Prime Factorization Attack")
    print("  2. Wiener's Attack (Small d)")
    print("  3. Common Modulus Attack")
    print("  4. Common Factor Attack")
    print("  5. Partial Key Exposure Attack")
    print("  0. Back to main menu")


def run_specific_attack(choice):
    """Run a specific attack based on user choice."""
    attacks = {
        1: ("src.attacks.small_prime", "demonstrate_small_prime_attack", "Small Prime Attack"),
        2: ("src.attacks.wiener", "demonstrate_wiener_attack", "Wiener's Attack"),
        3: ("src.attacks.common_modulus", "demonstrate_common_modulus_attack", "Common Modulus Attack"),
        4: ("src.attacks.common_factor", "demonstrate_common_factor_attack", "Common Factor Attack"),
        5: ("src.attacks.partial_key_exposure", "demonstrate_partial_key_exposure_attack", "Partial Key Exposure Attack"),
    }
    
    if choice in attacks:
        module_name, func_name, attack_name = attacks[choice]
        print_header(f"Running: {attack_name}")
        try:
            module = __import__(module_name, fromlist=[func_name])
            demo_func = getattr(module, func_name)
            demo_func()
        except Exception as e:
            print(f"\n✗ Error: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("✗ Invalid choice")


def run_basic_examples():
    """Run basic RSA examples."""
    print_header("Running Basic RSA Examples")
    try:
        from examples.basic_rsa import main as basic_main
        basic_main()
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()


def main():
    """Main program entry point."""
    # Check for command-line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        if command == "interactive":
            interactive_rsa_menu()
        elif command == "secure":
            demonstrate_secure_rsa()
        elif command == "attacks":
            demonstrate_attacks()
        elif command == "examples":
            run_basic_examples()
        elif command == "all":
            demonstrate_secure_rsa()
            demonstrate_attacks()
        else:
            print(f"✗ Unknown command: {command}")
            print("Usage: python demo.py [interactive|secure|attacks|examples|all]")
        return
    
    while True:
        show_menu()
        try:
            choice = input("\nchoice: ").strip()
            
            if choice == "0":
                print("\nbye!")
                break
            elif choice == "1":
                interactive_rsa_menu()
            elif choice == "2":
                demonstrate_secure_rsa()
            elif choice == "3":
                demonstrate_attacks()
            elif choice == "4":
                show_attack_menu()
                attack_choice = input("\nchoice: ").strip()
                if attack_choice != "0":
                    try:
                        run_specific_attack(int(attack_choice))
                    except ValueError:
                        print("✗ Invalid choice.")
            elif choice == "5":
                run_basic_examples()
            else:
                print("✗ Invalid choice. Please select 0-5.")
        
        except KeyboardInterrupt:
            print("\n\n👋 Exiting... Stay secure!")
            break
        except Exception as e:
            print(f"\n✗ Error: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()
