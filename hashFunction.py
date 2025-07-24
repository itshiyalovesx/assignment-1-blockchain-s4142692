
import hashlib
import binascii
import random
import string
import time


def hamming_distance(hash1_hex, hash2_hex):
   """
   Calculates the Hamming distance between two hexadecimal hash strings.
   This function converts the hex strings to integers, then performs a bitwise XOR
   to find the differing bits, and finally counts the set bits (1s) in the result.
   A higher Hamming distance indicates a greater difference at the bit level.
   """
   try:
       # Convert hexadecimal hash strings to integers
       int1 = int(hash1_hex, 16)
       int2 = int(hash2_hex, 16)
   except ValueError:
       print("Error: Invalid hexadecimal hash string provided for Hamming distance calculation.")
       return -1 # Indicate an error


   # Perform a bitwise XOR operation to find the differing bits
   # If a bit is different, the corresponding bit in 'diff' will be 1
   diff = int1 ^ int2


   # Count the number of set bits (1s) in the 'diff' result
   # This count represents the Hamming distance
   return bin(diff).count('1')


def demonstrate_hash_properties():
   """
   This function demonstrates two key properties of cryptographic hash functions:
   1. The Avalanche Effect: A tiny change in input results in a large change in output hash.
   2. Pre-image Resistance: It's computationally infeasible to find the original input
      given only its hash output.
   """
   print("--- Demonstrating Cryptographic Hash Function Properties (SHA-256) ---")


   # --- Part i: Demonstrating the Avalanche Effect ---
   print("\n--- Part i: Avalanche Effect ---")


   # 1. Take an arbitrary string as input from the user.
   original_input_string = input("Please enter an arbitrary string: ")


   # 2. Compute and display its hash (using SHA-256, a standard cryptographic hash function).
   # .encode('utf-8') converts the string to bytes, which is required by hash functions.
   # .hexdigest() returns the hash as a hexadecimal string.
   original_hash = hashlib.sha256(original_input_string.encode('utf-8')).hexdigest()
   print(f"\nOriginal Input String: '{original_input_string}'")
   print(f"SHA-256 Hash of Original: {original_hash}")


   # 3. Demonstrate the avalanche effect: Make a minimal change to the original input string.
   # This example changes the first character. If the string is empty, it adds a character.
   modified_input_string = list(original_input_string)
   if not modified_input_string:
       # If the original string was empty, add a character to demonstrate change.
       modified_input_string = ['a']
   else:
       # Change the first character. Toggle between 'a' and 'b' to ensure a change.
       if modified_input_string[0] == 'a':
           modified_input_string[0] = 'b'
       else:
           modified_input_string[0] = 'a'
   modified_input_string = "".join(modified_input_string)


   # Compute and display the hash of this modified string.
   modified_hash = hashlib.sha256(modified_input_string.encode('utf-8')).hexdigest()
   print(f"\nModified Input String (minimal change): '{modified_input_string}'")
   print(f"SHA-256 Hash of Modified: {modified_hash}")


   # Highlight or calculate the difference (Hamming distance).
   # The Hamming distance quantifies how many bits differ between the two hashes.
   distance = hamming_distance(original_hash, modified_hash)
   print(f"\nObservation: Notice how different the two hashes are, despite a tiny change in input.")
   print(f"Hamming Distance between hashes (number of differing bits): {distance} out of 256 bits.")
   print(f"This significant difference demonstrates the **Avalanche Effect**.")


   # --- Part ii: Demonstrating the Difficulty of Finding a Pre-image ---
   print("\n--- Part ii: Difficulty of Finding a Pre-image ---")


   # Define a target hash output. This is the hash of a known, short string.
   # In a real-world scenario, you would only have the target_hash, not the original string.
   target_preimage_source_string = "blockchain"
   target_hash = hashlib.sha256(target_preimage_source_string.encode('utf-8')).hexdigest()
   print(f"\nTarget Hash to find a pre-image for: {target_hash}")
   print(f"(The original string for this hash is '{target_preimage_source_string}' - kept secret for the demo!)")


   attempts_made = 0
   preimage_found = False
   # Set a limited number of iterations to prevent the program from running indefinitely.
   # Finding a pre-image for a secure hash like SHA-256 is computationally infeasible
   # within practical timeframes.
   max_attempts = 5 * 10**6 # 5 million attempts for demonstration purposes
   start_time = time.time()


   print(f"\nAttempting to find a pre-image by hashing random strings (up to {max_attempts} attempts)...")


   # Loop to iteratively hash random input strings and compare to the target hash.
   # We'll generate random strings of a fixed length to keep the search space manageable for the demo,
   # though even this small space is vast enough to make finding a pre-image highly unlikely.
   random_string_length = 8 # Length of random strings to generate
   characters = string.ascii_lowercase + string.digits # Characters to use in random strings


   while attempts_made < max_attempts:
       attempts_made += 1
       # Generate a random string
       random_input_string = ''.join(random.choices(characters, k=random_string_length))
      
       # Compute the hash of the random string
       current_hash = hashlib.sha256(random_input_string.encode('utf-8')).hexdigest()


       # Compare the computed hash with the target hash
       if current_hash == target_hash:
           print(f"\nSUCCESS! Pre-image found: '{random_input_string}'")
           print(f"Hash of found pre-image: {current_hash}")
           preimage_found = True
           break # Exit the loop if pre-image is found
      
       # Provide progress updates periodically
       if attempts_made % (max_attempts // 10) == 0:
           elapsed_time = time.time() - start_time
           print(f"Attempt {attempts_made} (after {elapsed_time:.2f} seconds)...")


   end_time = time.time()
   total_time = end_time - start_time


   if not preimage_found:
       print(f"\nPre-image **NOT** found after {attempts_made} attempts.")
       print(f"Total time elapsed: {total_time:.2f} seconds.")
       print("This clearly illustrates the immense difficulty and practical impossibility of finding a pre-image for a secure cryptographic hash function like SHA-256 within a reasonable timeframe.")
       print("The search space is astronomically large, making brute-force attacks infeasible.")


# Run the demonstration when the script is executed
if __name__ == "__main__":
   demonstrate_hash_properties()
