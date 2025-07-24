import hashlib # Used for cryptographic hash functions like SHA-256
import binascii # Not directly used for Hamming distance in this version, but it's useful for binary conversions
import random # Used for generating random strings in the pre-image demonstration
import string # Provides string constants like ascii_lowercase and digits
import time # Used to measure the duration of the pre-image search

# Part 1: Helper Function for Hamming Distance
def hamming_distance(hash1_hex, hash2_hex):
   
    """ Calculates the Hamming distance (number of differing bits) between two hexadecimal hash strings.
    This function is important for visually demonstrating the avalanche effect by quantifying
    how drastically the hash output changes with a small input modification. """
   
    try:
        # Convert hexadecimal hash strings to integers to allow bitwise operations
        int1 = int(hash1_hex, 16)
        int2 = int(hash2_hex, 16)
    except ValueError:
        # Error handling for invalid hex input
        print("Error: Invalid hexadecimal hash string provided for Hamming distance calculation.")
        return -1 # Return an error indicator

    # Perform a bitwise XOR operation (^) on the two integers
    diff = int1 ^ int2

    # Count the number of set bits (1s) in the 'diff' result.
    # The 'bin(diff)' converts the integer to its binary string representation (e.g., '0b10110').
    # '.count('1')' then counts the occurrences of '1' in that binary string. This count is the Hamming distance.
    return bin(diff).count('1')

# Main function to demonstrate hash properties as per Question 1 requirements
def demonstrate_hash_properties():
   
    """This function orchestrates the demonstration of cryptographic hash function properties,
    specifically the Avalanche Effect and Pre-image Resistance, using SHA-256 """
   
    # ANSI escape codes for text coloring in the terminal
    COLOR_GREEN = "\033[92m" # Green color
    COLOR_RESET = "\033[0m"  # Reset to default color

    apply_color = False

    # --- Part 1A.i: Demonstrating the Avalanche Effect ---
    print("--- Demonstrating Cryptographic Hash Function Properties (SHA-256) ---")

    #  1A.i.1: Takes an arbitrary string as input from the user.
    original_input_string = input("Please enter an arbitrary string: ")

    if original_input_string.lower() == "hiya":
        apply_color = True

    # Helper function to print with color if apply_color is True
    def cprint(text):
        if apply_color:
            print(f"{COLOR_GREEN}{text}{COLOR_RESET}")
        else:
            print(text)

    cprint("\n--- Part 1A.i: Demonstrating the Avalanche Effect ---")

    #  1A.i.2: Computes and displays its hash
    # hashlib.sha256: Initializes the SHA-256 hash algorithm
    # .encode('utf-8'): Converts the Python string into a sequence of bytes, as hash functions operate on byteS
    # .hexdigest(): Returns the computed hash as a string containing only hexadecimal digits. SHA-256 produces a 256-bit hash, which is represented as a 64-character hex string
    
    original_hash = hashlib.sha256(original_input_string.encode('utf-8')).hexdigest()
    cprint(f"\nOriginal Input String: '{original_input_string}'")
    cprint(f"SHA-256 Hash of Original: {original_hash}")

    #  1A.i.3: Demonstrates the avalanche effect. Make a minimal change to the original input string (e.g., flip one bit, change one character)
    # This example specifically changes the first character of the string.
    # FIX: Initialize modified_input_string_list here
    modified_input_string_list = list(original_input_string) 

    if not modified_input_string_list:
        # If the original string was empty, add a character to ensure a change can be made
        modified_input_string_list = ['a']
    else:
        # Change the first character. Toggling between 'a' and 'b' ensures a clear, minimal change
        if modified_input_string_list[0] == 'a':
            modified_input_string_list[0] = 'b'
        else:
            modified_input_string_list[0] = 'a'
    modified_input_string = "".join(modified_input_string_list) # Convert list back to string

    # Compute the hash of this modified string
    modified_hash = hashlib.sha256(modified_input_string.encode('utf-8')).hexdigest()
    cprint(f"\nModified Input String (minimal change): '{modified_input_string}'")
    cprint(f"SHA-256 Hash of Modified: {modified_hash}")

    # Highlight/calculate the difference (e.g., Hamming distance). The Hamming distance quantifies how many bits differ between the two hashes

    distance = hamming_distance(original_hash, modified_hash)
    cprint(f"\nObservation: Notice how drastically different the two hashes are, despite only a tiny change in the input string.")
    cprint(f"Hamming Distance between the two hashes (number of differing bits): {distance} out of 256 bits.")
    cprint(f"This significant difference (typically around 128 bits for SHA-256) clearly demonstrates the **Avalanche Effect**.")

    # --- Part 1A.ii: Demonstrating the Difficulty of Finding a Pre-image ---
    cprint("\n--- Part 1A.ii: Demonstrating the Difficulty of Finding a Pre-image ---")

    # Take a target hash output (this can be the hash of a known, short string you define in your code).
    # In a real-world scenario, an attacker would only have the target_hash and would not know the 'target_preimage_source_string'. We define it here to create a known target
   
    target_preimage_source_string = "blockchain"
    target_hash = hashlib.sha256(target_preimage_source_string.encode('utf-8')).hexdigest()
    cprint(f"\nTarget Hash to find a pre-image for: {target_hash}")
    cprint(f"(The original string for this hash is '{target_preimage_source_string}' - kept secret for the purpose of this demonstration!)")

    attempts_made = 0
    preimage_found = False
    # Your program should run for a limited number of iterations or a short period.
    # Finding a pre-image for a secure hash like SHA-256 is computationally infeasible within practical timeframes due to the astronomically large search space.
    
    max_attempts = 5 * 10**6 # Set a reasonable limit (e.g., 5 million attempts) for the demonstration
    start_time = time.time() # Record start time to measure duration

    cprint(f"\nAttempting to find a pre-image by hashing random strings (up to {max_attempts} attempts)...")

    # Write a loop that iteratively hashes random or sequential input strings and compares the output to your target hash.
    # We generate random strings of a fixed length to keep the search space consistent for the demo
  
    random_string_length = 8 # Length of random strings to generate (e.g., 8 characters)
    # Define the character set for random string generation (lowercase letters and digits).
    characters = string.ascii_lowercase + string.digits

    while attempts_made < max_attempts:
        attempts_made += 1 # Increment attempt counter
        
        # Generate a random string of the specified lengt
        random_input_string = ''.join(random.choices(characters, k=random_string_length))
        
        # Compute the SHA-256 hash of the generated random string.
        current_hash = hashlib.sha256(random_input_string.encode('utf-8')).hexdigest()

        # Compare the computed hash with the target hash.
        if current_hash == target_hash:
            # If a match is found (extremely rare for secure hashes), report success.
            cprint(f"\nSUCCESS! Pre-image found: '{random_input_string}'")
            cprint(f"Hash of found pre-image: {current_hash}")
            preimage_found = True
            break # Exit the loop as the pre-image has been found

        # Provide progress updates periodically to show the program is running.
        if attempts_made % (max_attempts // 10) == 0: # Update every 10% of max_attempts
            elapsed_time = time.time() - start_time
            cprint(f"Attempt {attempts_made} (after {elapsed_time:.2f} seconds)...")

    end_time = time.time() # Record end time
    total_time = end_time - start_time # Calculate total elapsed time

    # Report if the pre-image was found (it is highly unlikely for secure hashes) and the number of attempts made.
    if not preimage_found:
        cprint(f"\nPre-image **NOT** found after {attempts_made} attempts.")
        cprint(f"Total time elapsed: {total_time:.2f} seconds.")
        cprint("This clearly illustrates the immense difficulty and practical impossibility of finding a pre-image for a secure cryptographic hash function like SHA-256 within a reasonable timeframe.")
        cprint("The search space (e.g., 62^8 for 8 alphanumeric characters) is astronomically large, making brute-force attacks infeasible for secure hash functions.")

# Run the demonstration when the script is executed
if __name__ == "__main__":
    demonstrate_hash_properties()
