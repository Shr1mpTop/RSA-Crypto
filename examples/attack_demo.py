import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def run_all_attacks():    
    attacks = [
        ("Small Prime Factorization", "src.attacks.small_prime", "demonstrate_small_prime_attack"),
        ("Wiener's Attack", "src.attacks.wiener", "demonstrate_wiener_attack"),
        ("Common Modulus Attack", "src.attacks.common_modulus", "demonstrate_common_modulus_attack"),
        ("Low Exponent Attack", "src.attacks.low_exponent", "demonstrate_low_exponent_attack"),
        ("Fermat's Factorization", "src.attacks.fermat", "demonstrate_fermat_attack"),
        ("Common Factor Attack", "src.attacks.common_factor", "demonstrate_common_factor_attack"),
    ]
    
    for i, (name, module_name, func_name) in enumerate(attacks, 1):
        print(f"\n\n{'#'*70}")
        print(f"# ATTACK {i}/{len(attacks)}: {name}")
        print(f"{'#'*70}")
        
        try:
            # Import module and run demonstration
            module = __import__(module_name, fromlist=[func_name])
            demo_func = getattr(module, func_name)
            demo_func()
            
        except Exception as e:
            print(f"\n✗ Error running {name}: {e}")
            import traceback
            traceback.print_exc()
    
    print(f"\n\n{'#'*70}")
    print("# ALL ATTACK DEMONSTRATIONS COMPLETED")
    print(f"{'#'*70}")
    print("\n✓ All attack demonstrations finished!")
    print("\nKEY TAKEAWAYS:")
    print("  1. Always use sufficiently large primes (≥512 bits each)")
    print("  2. Ensure p and q are far apart")
    print("  3. Use standard public exponent e=65537")
    print("  4. Never reuse moduli or prime factors")
    print("  5. Always use proper padding (OAEP or PKCS#1 v1.5)")
    print("  6. Use at least 2048-bit keys for real applications")


def run_specific_attack(attack_name):
    """Run a specific attack demonstration."""
    attacks = {
        "small_prime": ("src.attacks.small_prime", "demonstrate_small_prime_attack"),
        "wiener": ("src.attacks.wiener", "demonstrate_wiener_attack"),
        "common_modulus": ("src.attacks.common_modulus", "demonstrate_common_modulus_attack"),
        "low_exponent": ("src.attacks.low_exponent", "demonstrate_low_exponent_attack"),
        "fermat": ("src.attacks.fermat", "demonstrate_fermat_attack"),
        "common_factor": ("src.attacks.common_factor", "demonstrate_common_factor_attack"),
    }
    
    if attack_name.lower() in attacks:
        module_name, func_name = attacks[attack_name.lower()]
        module = __import__(module_name, fromlist=[func_name])
        demo_func = getattr(module, func_name)
        demo_func()
    else:
        print(f"✗ Unknown attack: {attack_name}")
        print(f"Available attacks: {', '.join(attacks.keys())}")


def main():
    """Main entry point."""
    if len(sys.argv) > 1:
        # Run specific attack
        attack_name = sys.argv[1]
        run_specific_attack(attack_name)
    else:
        # Run all attacks
        run_all_attacks()


if __name__ == "__main__":
    main()
