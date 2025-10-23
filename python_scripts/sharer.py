import hashlib
import os
import json
from base64 import b64encode
from PIL import Image
from io import BytesIO
import ipfshttpclient
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
# Note: The Crypto.Util.Counter import is not strictly needed for AES-GCM
# but it's good practice to keep the standard cryptography imports.

# --- 1. Core ADEK Derivation Functions ---

def canonicalize(attrs: dict) -> bytes:
    """Creates a deterministic, sorted string from attributes for hashing."""
    items = sorted(attrs.items())
    s = ",".join(f"{k}:{v}" for k, v in items)
    return s.encode('utf-8')

def derive_adek(attrs: dict, salt: bytes, block_id: bytes) -> bytes:
    """Derives a 256-bit ADEK using HKDF-SHA256."""
    attr_bytes = canonicalize(attrs)
    
    # KDF Seed: Hash of (attributes + salt + block_id) ensures uniqueness per block and attribute set.
    seed = SHA256.new(attr_bytes + salt + block_id).digest()
    
    # HKDF to derive a strong 32-byte (256-bit) key from the seed
    adek = HKDF(
        master=seed,
        key_len=32,
        salt=None,
        hashmod=SHA256,
        num_keys=1,
        context=b"ADEK-v1" 
    )
    return adek

# --- 2. Encryption Function ---

def encrypt_block(aek, plaintext):
    """Encrypts data using AES-256 GCM (Authenticated Encryption)."""
    # GCM requires a 12-byte Nonce (Initialization Vector)
    nonce = os.urandom(12)
    # The cipher object handles the encryption
    cipher = AES.new(aek, AES.MODE_GCM, nonce=nonce)
    # encrypt_and_digest returns the ciphertext and the authentication tag
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ciphertext, tag

# --- 3. Main Sharer Logic ---

def run_sharer_logic(image_path, private_block_index=1):
    print("--- Sharer: Starting Image Processing and Encryption ---")
    
    # Unique IDs and Cryptographic Material
    IMAGE_ID = hashlib.sha256(os.urandom(16)).hexdigest()
    SALT_S = os.urandom(32) # CRITICAL: This MUST be kept private by the Sharer
    SALT_HASH = hashlib.sha256(SALT_S).hexdigest() # This goes on-chain (H(S))
    
    # 1. Image Partition (Simple vertical split)
    try:
        img = Image.open(image_path).convert('RGB')
    except FileNotFoundError:
        print(f"Error: Image not found at {image_path}. Please run the script once to generate it.")
        return None

    width, height = img.size
    
    # Split the image: left half is public, right half is private
    public_block = img.crop((0, 0, width//2, height))
    private_block = img.crop((width//2, 0, width, height))

    # Convert private block (PIL Image) to raw PNG bytes for encryption
    buffer = BytesIO()
    private_block.save(buffer, format="PNG")
    private_plaintext = buffer.getvalue()
    
    # 2. ADEK Generation
    ATTRIBUTES = {"role": "doctor", "org": "HospitalX"}
    BLOCK_ID_BYTES = private_block_index.to_bytes(4, 'big')
    
    adek = derive_adek(ATTRIBUTES, SALT_S, BLOCK_ID_BYTES)
    print(f"Derived ADEK (32 bytes): {b64encode(adek).decode('utf-8')[:10]}...")
    
    # 3. Encryption
    nonce, ciphertext, tag = encrypt_block(adek, private_plaintext)

    # 4. Upload to IPFS
    try:
        # Client connects to the IPFS daemon started in the terminal
        client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001/http') 
        
        # Upload Public Block (Preview)
        preview_buffer = BytesIO()
        public_block.save(preview_buffer, format="PNG")
        preview_res = client.add_bytes(preview_buffer.getvalue())
        PREVIEW_CID = preview_res['Hash']

        # Upload Encrypted Private Block (Concatenate nonce, tag, and ciphertext)
        encrypted_data = nonce + tag + ciphertext
        private_res = client.add_bytes(encrypted_data)
        PRIVATE_CID = private_res['Hash']
        
        print(f"\n✅ IPFS Uploaded.")
        print(f"   -> Preview CID: {PREVIEW_CID}")
        print(f"   -> Private CID: {PRIVATE_CID}")
        
    except Exception as e:
        print(f"\n❌ IPFS Connection Error: Is 'ipfs daemon &' running?")
        print(f"   Error details: {e}")
        return None
        
    # 5. Generate Metadata
    
    # The full metadata (Sharer's private record, includes raw SALT_S)
    full_metadata = {
        "image_id": IMAGE_ID,
        "preview_cid": PREVIEW_CID,
        "owner": "0xSharerAddress...",
        "raw_salt_S_b64": b64encode(SALT_S).decode('utf-8'), # Sharer must encrypt this for receiver
        "blocks": [
            {
                "block_id": private_block_index,
                "cid": PRIVATE_CID,
                "attrs": ATTRIBUTES,
                "attrs_hash": SHA256.new(canonicalize(ATTRIBUTES)).hexdigest(),
                "salt_hash": SALT_HASH,
                "encrypt_meta": {
                    "nonce_b64": b64encode(nonce).decode('utf-8'),
                    "tag_len": len(tag),
                    # The receiver needs to know the image dimensions to reconstruct it
                    "dimensions": [width, height], 
                    "private_block_coords": [width//2, 0, width, height]
                }
            }
        ]
    }
    
    # Save the on-chain ready data (excluding raw SALT_S)
    on_chain_data_file = f"on_chain_metadata_{IMAGE_ID}.json"
    on_chain_data = full_metadata.copy()
    del on_chain_data['raw_salt_S_b64'] 
    
    with open(on_chain_data_file, 'w') as f:
        json.dump(on_chain_data, f, indent=4)
        
    print(f"\n--- Metadata Generated ---")
    print(f"   On-chain data saved to: {on_chain_data_file}")
    print(f"   Image ID: {IMAGE_ID}")
    
    return full_metadata # Return the full metadata for the receiver script

# --- 6. Execution and Image Creation ---

if __name__ == "__main__":
    # Ensure this script is run from the 'adek-share' root folder
    # so 'python_scripts/sharer.py' can access 'test_image.png'
    
    test_image_path = 'test_image.png'
    
    # If the image doesn't exist, create a simple red/white placeholder image
    if not os.path.exists(test_image_path):
        print(f"Creating placeholder image: {test_image_path}")
        img = Image.new('RGB', (200, 100), color = 'red')
        # Draw a white square on the right side (private block simulation)
        for x in range(100, 200):
            for y in range(100):
                img.putpixel((x, y), (255, 255, 255))
        img.save(test_image_path)
        print("Placeholder image created successfully.")

    # Run the sharer logic and get the full metadata (including the private salt)
    result_metadata = run_sharer_logic(test_image_path)
    
    if result_metadata:
        # Save the full metadata to share with the receiver script 
        # (Simulating secure transfer/decryption of the salt S)
        with open("full_metadata_for_receiver.json", 'w') as f:
            json.dump(result_metadata, f, indent=4)
        print("\nSimulation Note: Full metadata (including the raw salt S) saved to 'full_metadata_for_receiver.json'.")
        print("This simulates the Sharer securely encrypting and sending S to the approved Receiver.")
