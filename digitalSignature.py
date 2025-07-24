from cryptography.hazmat.primitives import hashes # Used for hashing messages (SHA256)
from cryptography.hazmat.primitives.asymmetric import rsa, padding # rsa for key generation and padding for signature schemes
from cryptography.hazmat.primitives import serialization # Used for converting keys to/from various formats (PEM)
from cryptography.exceptions import InvalidSignature # Exception raised if signature verification fails


def demonstrate_digital_signature():
    """
    This function demonstrates the core processes of a digital signature scheme using RSA (Rivest–Shamir–Adleman) algorithm 
    from the cryptography library. """
    # ANSI escape codes for text coloring in the terminal

    COLOR_GREEN = "\033[92m" # Green color for output
    COLOR_RESET = "\033[0m"  # Reset to default color after printing

    # Helper function to print all output in green color
    def cprint(text):
        print(f"{COLOR_GREEN}{text}{COLOR_RESET}")

    cprint("--- Digital Signature Demonstration (RSA) ---")

    # --- Part 3A.i.1: Generate a public-private key pair ---
    cprint("\n--- Key Generation ---")
    # Generate a new RSA private key. This is the secret key.
    # key_size: The length of the modulus in bits (2048 bits)- common and secure size for RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    # Derive the corresponding public key from the private key (this key can be shared)
    public_key = private_key.public_key()

    # --- Part 3A.ii: Clearly output the public key, private key (for illustrative purposes) ---
    # Outputting Private Key (for illustrative academic purposes ONLY - IRL WE SHOULD NEVER EXPOSE IN PRODUCTION!)
    # It is serialized to PEM format for easy display and understanding of its structure
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8, # PKCS#8 format is a common standard for private keys
        encryption_algorithm=serialization.NoEncryption() 
    )
    cprint("\nPrivate Key (PEM format - KEEP THIS SECRET IN REAL APPS!):")
    cprint(private_pem.decode('utf-8')) # Decode bytes to string for printing

    # Outputting Public Key (can be shared freely)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo # Standard format for public keys
    )
    cprint("\nPublic Key (PEM format - SHARE THIS FREELY):")
    cprint(public_pem.decode('utf-8')) # Decode bytes to string for printing

    # --- Part 3A.i.2: Takes a message string as input ---
    original_message = input("\nEnter a message string to sign: ")
    # Messages must be encoded into bytes before cryptographic operations (like hashing and signing)
    message_bytes = original_message.encode('utf-8')

    # --- Part 3A.i.3: Signs the message using the private key to create a digital signature. ---
    cprint("\n--- Signing Message ---")
    # The 'sign' method creates the digital signature.
    # It takes:
    # 1. The message bytes (which will be hashed internally by the specified algorithm).
    # 2. A padding scheme: PSS (Probabilistic Signature Scheme) is recommended for RSA signatures.
    #    - mgf (Mask Generation Function): MGF1 with SHA256 is commonly used.
    #    - salt_length: Using MAX_LENGTH provides stronger security.
    # 3. The hash algorithm used on the message *before* the signing operation (SHA256 in this case).
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), # Mask Generation Function 1 with SHA256
            salt_length=padding.PSS.MAX_LENGTH # Use maximum recommended salt length for PSS
        ),
        hashes.SHA256() # Specifies SHA256 as the hashing algorithm for the message
    )
    # --- Part 3A.ii: Clearly output the original message, the generated signature ---
    cprint(f"Original Message: '{original_message}'")
    cprint(f"Generated Signature (hexadecimal representation): {signature.hex()}") # Convert signature bytes to hex string for display

    # --- Part 3A.i.4: Verifies the signature against the original message using the public key. ---
    cprint("\n--- Verifying Signature ---")
    verification_result = False # Initialize verification result
    try:
        # The 'verify' method checks if the signature is valid for the given message and public key
        # It requires the same signature, message bytes, padding scheme, and hash algorithm used during signing
        # If verification fails (e.g., signature doesn't match, message tampered), it raises an InvalidSignature exception
        public_key.verify(
            signature, # The digital signature to verify
            message_bytes, # The original message bytes that were signed
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256() # The hash algorithm used for verification (must match signing)
        )
        verification_result = True # If no exception, verification was successful
    except InvalidSignature:
        verification_result = False # If InvalidSignature exception is caught, verification failed
    
    # --- Part 3A.ii: Clearly output the validation result ---
    cprint(f"Verification Result (Original Message, Original Signature): {verification_result}")

    # --- Demonstrate Tampering Effects ---
    # This part shows how digital signatures protect against message and signature tampering
    cprint("\n--- Demonstrating Tampering Effects ---")

    # Scenario 1: Tampering with the message after it has been signed
    tampered_message = "This is a tampered message."
    tampered_message_bytes = tampered_message.encode('utf-8')
    cprint(f"\nAttempting to verify with a TAMPERED MESSAGE: '{tampered_message}'")
    try:
        # Attempt to verify the original signature with the *altered* message.
        # This should fail due to integrity protection.
        public_key.verify(
            signature, # Still using the original, valid signature
            tampered_message_bytes, # Using the tampered message
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        tamper_message_result = True
    except InvalidSignature:
        tamper_message_result = False
    cprint(f"Verification Result (Tampered Message, Original Signature): {tamper_message_result} (Expected: False)")

    # Scenario 2: Tampering with the signature itself
    # A simple byte flip to simulate corruption or malicious alteration of the signature data
    if len(signature) > 1: # Ensure the signature has enough bytes to modify
        tampered_signature = bytearray(signature) # Convert to a mutable bytearray
        tampered_signature[-1] = (tampered_signature[-1] + 1) % 256 # Change the last byte's value
        tampered_signature = bytes(tampered_signature) # Convert back to immutable bytes
    else:
        # Fallback for very short signatures (unlikely with RSA 2048-bit signatures)
        tampered_signature = b'\x00' 

    cprint(f"\nAttempting to verify with a TAMPERED SIGNATURE: {tampered_signature.hex()}")
    try:
        # Attempt to verify the *altered* signature with the original message, this should also fail!!
        public_key.verify(
            tampered_signature, # Using the tampered signature
            message_bytes, # Using the original message
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        tamper_signature_result = True
    except InvalidSignature:
        tamper_signature_result = False
    cprint(f"Verification Result (Original Message, Tampered Signature): {tamper_signature_result} (Expected: False)")


# Run the demonstration when the script is executed
if __name__ == "__main__":
    demonstrate_digital_signature()
