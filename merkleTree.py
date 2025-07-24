import hashlib
import math

class MerkleTree:
    def __init__(self, data_items):
        """
        Initializes the Merkle Tree with a list of data items.
        Each data item is first hashed to become a leaf node.
        The tree is then constructed level by level upwards to the root.
        Handles cases with an odd number of nodes at any level by duplicating the last node.
        """
        if not data_items:
            raise ValueError("Merkle Tree cannot be constructed from an empty list.")
        
        # Step 1: Hash each original data item to form the leaf nodes.
        # These are the bottom-most layer of the Merkle Tree.
        self.original_data_items = list(data_items) # Store original for proof generation context
        self.leaves = [hashlib.sha256(item.encode('utf-8')).hexdigest() for item in data_items]
        
        # Step 2: Build the tree levels from the leaves up to the root.
        # self.tree will store all levels, with the root at index 0.
        self.tree = self._build_tree(self.leaves)
        
        # The Merkle Root is the single hash at the top of the tree (first element of the first level).
        self.root = self.tree[0][0]

    def _build_tree(self, current_level_nodes):
        """
        Recursively (or iteratively) builds the Merkle Tree levels from a given set of nodes.
        It takes a list of hashes (nodes) for the current level and computes the next higher level.
        Handles odd number of nodes by duplicating the last one to ensure pairs.
        """
        tree_levels = [current_level_nodes] # Start with the current level (e.g., leaves)

        # Continue building levels as long as there's more than one node in the current level.
        while len(current_level_nodes) > 1:
            next_level = []
            
            # Handle odd number of nodes: Duplicate the last node to ensure all nodes have a pair.
            if len(current_level_nodes) % 2 != 0:
                current_level_nodes.append(current_level_nodes[-1])

            # Iterate through the current level, taking two nodes at a time.
            for i in range(0, len(current_level_nodes), 2):
                left_child_hash = current_level_nodes[i]
                right_child_hash = current_level_nodes[i+1]
                
                # Concatenate the two child hashes and then hash the combined string.
                # The order of concatenation (left + right) is crucial and must be consistent.
                combined_hash = hashlib.sha256((left_child_hash + right_child_hash).encode('utf-8')).hexdigest()
                next_level.append(combined_hash)
            
            # Add the newly computed level to our list of tree levels.
            tree_levels.append(next_level)
            # Move up to the next level for the next iteration.
            current_level_nodes = next_level
        
        # Reverse the list of levels so that the root is at index 0 and leaves are at the last index.
        return tree_levels[::-1]

    def get_merkle_root(self):
        """
        Returns the computed Merkle Root of the tree.
        """
        return self.root

    def generate_merkle_proof(self, target_data_item):
        """
        Generates a Merkle proof for a specific data item.
        A proof consists of a list of (sibling_hash, position) tuples, where 'position'
        indicates if the sibling hash is 'left' or 'right' relative to the path hash.
        """
        # First, hash the target data item to find its leaf hash.
        target_hash = hashlib.sha256(target_data_item.encode('utf-8')).hexdigest()
        
        # Find the index of the target hash in the original leaves (before any duplication for building).
        # This is important to get the correct starting point in the tree.
        try:
            initial_leaf_index = self.original_data_items.index(target_data_item)
            # Now, map this original index to the potentially padded leaves list
            # This 'current_index_in_level' will track our position as we move up the tree levels.
            current_index_in_level = initial_leaf_index 
        except ValueError:
            # If the target data item is not in the original list, a proof cannot be generated.
            return None, "Target data item not found in the original list used to build the tree."

        proof = []
        # Iterate through the tree levels from the leaves upwards towards the root.
        # self.tree[len(self.tree) - 1] is the leaf level. self.tree[0] is the root level.
        # We iterate from the leaf level (index `len(self.tree) - 1`) up to the level just before the root (index 1).
        for i in range(len(self.tree) - 1, 0, -1):
            current_level = self.tree[i] # The current level we are examining
            
            # Determine if the current hash (at current_index_in_level) is a left or right child.
            if current_index_in_level % 2 == 0: # Even index means it's a left child
                sibling_index = current_index_in_level + 1
                position = 'right' # The sibling is on the right
            else: # Odd index means it's a right child
                sibling_index = current_index_in_level - 1
                position = 'left' # The sibling is on the left
            
            # Add the sibling's hash and its position to the proof.
            # We need to ensure the sibling index is within the bounds of the current level.
            # This check is primarily for the last node in an odd-sized level, which was duplicated.
            if sibling_index < len(current_level):
                sibling_hash = current_level[sibling_index]
                proof.append((sibling_hash, position))
            else:
                # This case should ideally not be reached if the tree building (duplication)
                # and indexing logic is correct, ensuring every node has a sibling.
                # However, it's a good defensive check.
                pass 
            
            # Move up to the parent level: The parent's index is floor(current_index / 2).
            current_index_in_level = current_index_in_level // 2
        
        return proof, None # Return the generated proof and no error

def verify_merkle_proof(target_data_item, proof, merkel_root):
    """
    Verifies a Merkle proof for a given data item against a known Merkle Root.
    It reconstructs the hash path from the target item up to the root using the proof.
    """
    # Start with the hash of the target data item.
    current_hash = hashlib.sha256(target_data_item.encode('utf-8')).hexdigest()

    # Iterate through each (sibling_hash, position) pair in the proof.
    for sibling_hash, position in proof:
        # Concatenate the current hash with the sibling hash based on its position.
        # The order of concatenation is critical for correct hashing.
        if position == 'right':
            # If sibling is on the right, current_hash is on the left.
            combined_for_hashing = current_hash + sibling_hash
        elif position == 'left':
            # If sibling is on the left, current_hash is on the right.
            combined_for_hashing = sibling_hash + current_hash
        else:
            # Invalid position in proof, indicating a malformed or tampered proof.
            return False, "Invalid proof format: position must be 'left' or 'right'."
        
        # Hash the combined string to get the hash for the next level up.
        current_hash = hashlib.sha256(combined_for_hashing.encode('utf-8')).hexdigest()
    
    # After processing all proof elements, the final current_hash should match the Merkle Root.
    if current_hash == merkel_root:
        return True, None # Proof is valid
    else:
        return False, "Proof verification failed: Reconstructed root does not match provided Merkle Root."


# --- Demonstration ---
if __name__ == "__main__":
    print("--- Merkle Tree Construction and Proof Demonstration ---")

    # Example list of data items (e.g., transaction IDs in a blockchain block)
    data_items_even = [
        "tx_001_Alice_to_Bob",
        "tx_002_Bob_to_Charlie",
        "tx_003_Charlie_to_David",
        "tx_004_David_to_Eve"
    ]

    data_items_odd = [
        "tx_A_buy_coffee",
        "tx_B_sell_book",
        "tx_C_pay_rent",
        "tx_D_get_salary",
        "tx_E_send_gift"
    ]

    print("\n--- Demonstration with Even Number of Items ---")
    print(f"Original Data Items: {data_items_even}")
    merkle_tree_even = MerkleTree(data_items_even)
    merkle_root_even = merkle_tree_even.get_merkle_root()
    print(f"Merkle Root: {merkle_root_even}")
    print("\nMerkle Tree Levels (from root to leaves):")
    for i, level in enumerate(merkle_tree_even.tree):
        print(f"Level {i}: {level}")

    # Generate and Verify Proof for an item in the even list
    target_item_even = "tx_002_Bob_to_Charlie"
    proof_even, error_even = merkle_tree_even.generate_merkle_proof(target_item_even)
    if error_even:
        print(f"\nError generating proof for '{target_item_even}': {error_even}")
    else:
        print(f"\nMerkle Proof for '{target_item_even}':")
        for p_hash, p_pos in proof_even:
            print(f"  Hash: {p_hash}, Position: {p_pos}")
        
        is_valid_even, verify_error_even = verify_merkle_proof(target_item_even, proof_even, merkle_root_even)
        if verify_error_even:
            print(f"\nError verifying proof: {verify_error_even}")
        else:
            print(f"Verification Result for '{target_item_even}': {is_valid_even} (Expected True)")

    print("\n" + "="*80 + "\n")

    print("\n--- Demonstration with Odd Number of Items (and duplication handling) ---")
    print(f"Original Data Items: {data_items_odd}")
    merkle_tree_odd = MerkleTree(data_items_odd)
    merkle_root_odd = merkle_tree_odd.get_merkle_root()
    print(f"Merkle Root: {merkle_root_odd}")
    print("\nMerkle Tree Levels (from root to leaves):")
    for i, level in enumerate(merkle_tree_odd.tree):
        print(f"Level {i}: {level}")

    # Generate and Verify Proof for an item in the odd list
    target_item_odd = "tx_C_pay_rent"
    proof_odd, error_odd = merkle_tree_odd.generate_merkle_proof(target_item_odd)
    if error_odd:
        print(f"\nError generating proof for '{target_item_odd}': {error_odd}")
    else:
        print(f"\nMerkle Proof for '{target_item_odd}':")
        for p_hash, p_pos in proof_odd:
            print(f"  Hash: {p_hash}, Position: {p_pos}")
        
        is_valid_odd, verify_error_odd = verify_merkle_proof(target_item_odd, proof_odd, merkle_root_odd)
        if verify_error_odd:
            print(f"\nError verifying proof: {verify_error_odd}")
        else:
            print(f"Verification Result for '{target_item_odd}': {is_valid_odd} (Expected True)")

    # Test with an invalid item
    invalid_item = "tx_Z_not_in_list"
    proof_invalid, error_invalid = merkle_tree_odd.generate_merkle_proof(invalid_item)
    if error_invalid:
        print(f"\nError generating proof for '{invalid_item}': {error_invalid}")
    else:
        is_valid_invalid, verify_error_invalid = verify_merkle_proof(invalid_item, proof_invalid, merkle_root_odd)
        if verify_error_invalid:
            print(f"\nError verifying proof for '{invalid_item}': {verify_error_invalid}")
        else:
            print(f"Verification Result for '{invalid_item}' (expected False): {is_valid_invalid}")

    # Test with a tampered proof (e.g., change one hash in the proof)
    if proof_odd and len(proof_odd) > 0:
        tampered_proof = list(proof_odd) # Create a copy
        original_hash_in_proof = tampered_proof[0][0]
        # Tamper the first hash in the proof slightly
        tampered_hash = original_hash_in_proof[:-1] + ('f' if original_hash_in_proof[-1] != 'f' else 'e')
        tampered_proof[0] = (tampered_hash, tampered_proof[0][1])

        print(f"\nAttempting to verify with a tampered proof for '{target_item_odd}':")
        is_valid_tampered, verify_error_tampered = verify_merkle_proof(target_item_odd, tampered_proof, merkle_root_odd)
        if verify_error_tampered:
            print(f"\nError verifying tampered proof: {verify_error_tampered}")
        else:
            print(f"Verification Result with tampered proof (expected False): {is_valid_tampered}")
