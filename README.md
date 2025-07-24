**BlockChain Technology Assignment 1 - Crypto Data- s4142692**

Blockchain Cryptography Demonstrations
 Hash Functions, Merkle Trees, and Digital Signatures
 *All output is printed in green*

To run these programs, you need:
Python 3.x installed on your system

The cryptography library for the Digital Signatures demonstration

Installation
1. Clone this repository:

git clone <repository_url>
cd <repository_name>

(Replace <repository_url> and <repository_name> with your actual GitHub repository details.)

2. Install the required Python library:

pip install cryptography

How to Run the Codes:
Navigate to the directory containing the Python scripts

**1. Hash Functions Demonstration (hash_properties_demo_q1.py)**
This script demonstrates the Avalanche Effect and the Pre-image Resistance of cryptographic hash functions (SHA-256)

To run:
python hash_properties_demo_q1.py

Interaction:
The program will:
1. Prompt you to "Enter an arbitrary string".
2. Display the hash of your input.
3. Show the hash of a minimally modified version of your input and calculate the Hamming distance, illustrating the avalanche effect.
4. Attempt to find a pre-image for a target hash by brute-forcing random strings (for a limited number of attempts), demonstrating pre-image resistance.

**2. Merkle Trees Demonstration (merkle_tree_implementation.py)**
This script demonstrates the construction of a Merkle Tree, the generation of a Merkle Proof, and the verification of that proof.

To run:
python merkle_tree_implementation.py

Interaction:
The program will:
1. Automatically run demonstrations with both an even and an odd number of sample data items (transactions).
2. Output the Merkle Root for each tree.
3. Generate and display a Merkle proof for a specific item within each tree.
4. Verify the generated proof against the Merkle Root, showing True for valid proofs and False for invalid/tampered ones.


**3. Digital Signatures Demonstration (digital_signature_demo.py)**
This script demonstrates Public Key Cryptography (PKC) by generating a public-private key pair, signing a message with the private key, and verifying the signature with the public key.
It also shows how tampering invalidates signatures.

To run:
python digital_signature_demo.py

Interaction:
The program will:
1. Generates and display a new RSA public-private key pair (note: private key is shown for academic context only, never share in real applications!).
2. Prompts you to "Enter a message string to sign"
3. Displays the original message and its generated digital signature.
4. Verifes the signature against the original message and output the validation result (True or False).
5. Demonstrate how verification fails if the message or the signature is tampered with.


