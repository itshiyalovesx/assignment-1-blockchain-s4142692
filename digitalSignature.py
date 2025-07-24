from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def demonstrate_digital_signature():
   """
   This function demonstrates the core processes of a digital signature scheme
   using RSA (Rivest–Shamir–Adleman) algorithm from the cryptography library:
   1. Generating a public-private key pair.
   2. Signing a message using the private key.
   3. Verifying the signature using the public key.
   It also shows how tampering with the message or signature invalidates the verification.
   """
   print("--- Digital Signature Demonstration (RSA) ---")


   # --- 1. Generate a public-private key pair ---
   print("\n--- Key Generation ---")
   # Generate a new RSA private key.
   # public_exponent: A common and recommended value for the public exponent.
   # key_size: The length of the modulus in bits. 2048 bits is a common and secure size.
   private_key = rsa.generate_private_key(
       public_exponent=65537,
       key_size=2048
   )
   # Derive the corresponding public key from the private key.
   public_key = private_key.public_key()


   # --- Outputting Keys (for illustrative academic purposes ONLY) ---
   # In a real-world application, the private key MUST NEVER be exposed.
   # It is serialized to PEM format for easy display.
   private_pem = private_key.private_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PrivateFormat.PKCS8,
       encryption_algorithm=serialization.NoEncryption() # No encryption for demonstration clarity
   )
   print("\nPrivate Key (PEM format - KEEP THIS SECRET IN REAL APPS!):")
   print(private_pem.decode('utf-8'))


   public_pem = public_key.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.SubjectPublicKeyInfo
   )
   print("\nPublic Key (PEM format - SHARE THIS FREELY):")
   print(public_pem.decode('utf-8'))


   # --- 2. Take a message string as input ---
   original_message = input("\nEnter a message string to sign: ")
   # Messages must be encoded into bytes before cryptographic operations.
   message_bytes = original_message.encode('utf-8')


   # --- 3. Sign the message using the private key to create a digital signature ---
   print("\n--- Signing Message ---")
   # The 'sign' method creates a digital signature.
   # It takes the message bytes, a padding scheme, and a hash algorithm.
   # Standard practice is to hash the message first (SHA256 in this case) and then sign the hash.
   # PSS (Probabilistic Signature Scheme) padding is a recommended scheme for RSA signatures.
   signature = private_key.sign(
       message_bytes,
       padding.PSS(
           mgf=padding.MGF1(hashes.SHA256()), # Mask Generation Function
           salt_length=padding.PSS.MAX_LENGTH # Use maximum recommended salt length
       ),
       hashes.SHA256() # The hash algorithm used on the message before signing
   )
   print(f"Original Message: '{original_message}'")
   print(f"Generated Signature (hexadecimal representation): {signature.hex()}")


   # --- 4. Verify the signature against the original message using the public key ---
   print("\n--- Verifying Signature ---")
   verification_result = False
   try:
       # The 'verify' method checks if the signature is valid for the given message and public key.
       # It requires the same padding and hash algorithm used during signing.
       # If verification fails, it raises an InvalidSignature exception.
       public_key.verify(
           signature,
           message_bytes,
           padding.PSS(
               mgf=padding.MGF1(hashes.SHA256()),
               salt_length=padding.PSS.MAX_LENGTH
           ),
           hashes.SHA256()
       )
       verification_result = True
   except InvalidSignature:
       verification_result = False
  
   print(f"Verification Result (Original Message, Original Signature): {verification_result}")


   # --- Demonstrate Tampering ---
   print("\n--- Demonstrating Tampering Effects ---")


   # Scenario 1: Tampering with the message
   tampered_message = "This is a tampered message."
   tampered_message_bytes = tampered_message.encode('utf-8')
   print(f"\nAttempting to verify with a TAMPERED MESSAGE: '{tampered_message}'")
   try:
       public_key.verify(
           signature, # Using the original signature
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
   print(f"Verification Result (Tampered Message, Original Signature): {tamper_message_result} (Expected: False)")


   # Scenario 2: Tampering with the signature itself
   # A simple byte flip to simulate corruption or malicious alteration of the signature.
   if len(signature) > 1: # Ensure signature is long enough to tamper
       tampered_signature = bytearray(signature) # Convert to mutable bytearray
       tampered_signature[-1] = (tampered_signature[-1] + 1) % 256 # Change the last byte
       tampered_signature = bytes(tampered_signature) # Convert back to immutable bytes
   else:
       tampered_signature = b'\x00' # Fallback for very short signatures (unlikely with RSA)


   print(f"\nAttempting to verify with a TAMPERED SIGNATURE: {tampered_signature.hex()}")
   try:
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
   print(f"Verification Result (Original Message, Tampered Signature): {tamper_signature_result} (Expected: False)")




# Run the demonstration when the script is executed
if __name__ == "__main__":
   demonstrate_digital_signature()
