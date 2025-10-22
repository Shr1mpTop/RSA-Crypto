import sys
import os

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from src.key_generation import generate_keypair
from src.rsa_core import encrypt, decrypt


def print_header(title):
    """Print a formatted header."""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)


def demonstrate_secure_rsa():
    """Demonstrate secure RSA usage."""
    print_header("DEMONSTRATION: Secure RSA Implementation")
    
    print("\n1. Generating secure 2048-bit RSA key pair...")
    print("-" * 70)
    public_key, private_key = generate_keypair(2048)
    print(f"✓ Keys generated successfully")
    print(f"  Modulus bit length: {public_key.bit_length} bits")
    print(f"  Public exponent: e = {public_key.exponent}")
    
    print("\n2. Encrypting a message...")
    print("-" * 70)
    message = b"This is a secure message encrypted with 2048-bit RSA!"
    print(f"Original message: {message}")
    
    ciphertext = encrypt(message, public_key)
    print(f"Ciphertext length: {len(str(ciphertext))} digits")
    
    print("\n3. Decrypting the message...")
    print("-" * 70)
    decrypted = decrypt(ciphertext, private_key)
    print(f"Decrypted message: {decrypted}")
    print(f"Decryption successful: {message == decrypted}")


def demonstrate_attacks():
    """Run all attack demonstrations."""
    print_header("ATTACK DEMONSTRATIONS")
    
    print("\n⚠️  WARNING: The following demonstrates attacks on WEAK RSA keys")
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
    print("\nChoose an option:")
    print("  1. Demonstrate Secure RSA (2048-bit)")
    print("  2. Demonstrate All Attacks")
    print("  3. Demonstrate Specific Attack")
    print("  4. Run Basic Examples")
    print("  0. Exit")
    print("-" * 70)


def show_attack_menu():
    """Display the attack selection menu."""
    print("\nSelect an attack to demonstrate:")
    print("  1. Small Prime Factorization Attack")
    print("  2. Wiener's Attack (Small d)")
    print("  3. Common Modulus Attack")
    print("  4. Common Factor Attack")
    print("  5. Partial Key Exposure Attack")
    print("  0. Back to main menu")
    print("-" * 70)


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
    """Main entry point."""
    print("\n" + "#"*70)
    print("# RSA ENCRYPTION ALGORITHM IMPLEMENTATION AND ATTACK DEMONSTRATION")
    print("# Educational Project - For Learning Purposes Only")
    print("#"*70)
    
    # Check for command-line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        if command == "secure":
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
            print("Usage: python demo.py [secure|attacks|examples|all]")
        return
    
    # Interactive mode
    while True:
        show_menu()
        try:
            choice = input("\nEnter your choice: ").strip()
            
            if choice == "0":
                print("\nThank you for using RSA Crypto Demo!")
                print("Remember: Always use secure parameters in production!")
                break
            elif choice == "1":
                demonstrate_secure_rsa()
            elif choice == "2":
                demonstrate_attacks()
            elif choice == "3":
                show_attack_menu()
                attack_choice = input("\nEnter your choice: ").strip()
                if attack_choice != "0":
                    run_specific_attack(int(attack_choice))
            elif choice == "4":
                run_basic_examples()
            else:
                print("✗ Invalid choice. Please try again.")
        
        except KeyboardInterrupt:
            print("\n\nExiting...")
            break
        except Exception as e:
            print(f"\n✗ Error: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()
