import hashlib
import os
import json
from base64 import b64decode
from PIL import Image
from io import BytesIO
import ipfshttpclient
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from python_scripts.sharer import canonicalize, derive_adek # Import utility functions

# --- 1. Decryption Function ---

def decrypt_block(aek, nonce, tag, ciphertext):
    """Decrypts data using AES-256 GCM (Authenticated Encryption)."""
    try:
        cipher = AES.new(aek, AES.MODE_GCM, nonce=nonce)
        # Decrypts and verifies the authentication tag
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError as e:
        print(f"Decryption Error: {e}. Keys or data may be corrupt/tampered.")
        return None

# --- 2. Main Receiver Logic ---

def run_receiver_logic(metadata_path, output_image_path="reconstructed_image.png"):
    print("--- Receiver: Starting Decryption and Reconstruction ---")
    
    try:
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
    except FileNotFoundError:
        print(f"Error: Metadata file not found at {metadata_path}.")
        print("Please run 'python3 python_scripts/sharer.py' first.")
        return

    # Simulation: Receiver retrieves the raw salt S (which was securely encrypted/transferred)
    # In a real scenario, the receiver would decrypt the encryptedADEK/Salt_S with their private key here.
    try:
        RAW_SALT_S = b64decode(metadata['raw_salt_S_b64'])
        
        # Get block metadata for the private block
        block_meta = metadata['blocks'][0]
        block_id = block_meta['block_id']
        private_cid = block_meta['cid']
        attributes = block_meta['attrs']
        
        encrypt_meta = block_meta['encrypt_meta']
        tag_len = encrypt_meta['tag_len']
        nonce = b64decode(encrypt_meta['nonce_b64'])
        
        width, height = encrypt_meta['dimensions']
        
    except (KeyError, IndexError) as e:
        print(f"Error: Malformed metadata file. Missing key: {e}")
        return

    # 1. Re-Derive ADEK
    BLOCK_ID_BYTES = block_id.to_bytes(4, 'big')
    # The receiver uses the shared S, block ID, and known attributes to re-derive the key
    adek = derive_adek(attributes, RAW_SALT_S, BLOCK_ID_BYTES)
    print(f"Re-Derived ADEK (32 bytes): {b64encode(adek).decode('utf-8')[:10]}...")

    # 2. Fetch Blocks from IPFS
    try:
        client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001/http') 
        
        # Fetch public preview
        public_data = client.cat(metadata['preview_cid'])
        public_block_img = Image.open(BytesIO(public_data)).convert('RGB')
        
        # Fetch encrypted private block
        encrypted_data = client.cat(private_cid)
        print(f"✅ IPFS Fetched. Encrypted size: {len(encrypted_data)} bytes.")

    except Exception as e:
        print(f"❌ IPFS Connection/Fetch Error: {e}")
        return
    
    # 3. Separate Components and Decrypt
    # Encrypted data structure: [12-byte Nonce] [16-byte Tag] [Ciphertext]
    
    # Calculate sizes based on known lengths
    nonce_len = len(nonce)
    tag_start = nonce_len
    tag_end = nonce_len + tag_len
    
    # Split the incoming data
    retrieved_nonce = encrypted_data[:nonce_len]
    retrieved_tag = encrypted_data[tag_start:tag_end]
    retrieved_ciphertext = encrypted_data[tag_end:]

    if retrieved_nonce != nonce:
        print("ERROR: Nonce mismatch. Data corruption or wrong metadata.")
        return

    private_plaintext = decrypt_block(adek, retrieved_nonce, retrieved_tag, retrieved_ciphertext)
    
    if private_plaintext is None:
        print("Decryption failed. Cannot proceed.")
        return

    # 4. Reconstruct Image
    private_block_img = Image.open(BytesIO(private_plaintext)).convert('RGB')
    
    # Create a new, empty image canvas
    reconstructed_img = Image.new('RGB', (width, height))
    
    # Paste the public and private blocks back into the canvas
    # Public block coordinates: (0, 0, width//2, height)
    reconstructed_img.paste(public_block_img, (0, 0)) 
    
    # Private block coordinates are stored in metadata: [width//2, 0, width, height]
    # We use the original dimensions to reconstruct the image
    reconstructed_img.paste(private_block_img, (width // 2, 0))
    
    reconstructed_img.save(output_image_path)
    
    print(f"\n--- SUCCESS: Image Reconstructed ---")
    print(f"   Original image reassembled and saved as: {output_image_path}")
    print("   The receiver successfully used the securely transferred salt S to re-derive the key and decrypt the block.")


if __name__ == "__main__":
    # The path to the file simulating the securely transferred salt S
    metadata_file = "full_metadata_for_receiver.json"
    
    # Run the decryption and reconstruction process
    run_receiver_logic(metadata_file)
