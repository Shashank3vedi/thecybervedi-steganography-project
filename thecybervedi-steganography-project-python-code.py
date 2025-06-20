import cv2
import numpy as np
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Core encryption/decryption functions
def derive_key(userkey):
    """Derive a 32-byte AES key using SHA-256."""
    print("\nDeriving key...")
    key = hashlib.sha256(userkey.encode()).digest()
    print("✓ Key derived.")
    return key

def ascii_xor_encrypt(data, xor_key):
    """Encrypt data with XOR using the provided key (byte-level)."""
    encrypted = []
    key_bytes = xor_key.encode()
    key_length = len(key_bytes)
    for i in range(len(data)):
        key_byte = key_bytes[i % key_length]
        encrypted_byte = (data[i] ^ key_byte) & 0xFF
        encrypted.append(encrypted_byte)
    return encrypted

def ascii_xor_decrypt(encrypted, xor_key):
    """Decrypt data with XOR using the provided key (byte-level)."""
    decrypted = []
    key_bytes = xor_key.encode()
    key_length = len(key_bytes)
    for i in range(len(encrypted)):
        key_byte = key_bytes[i % key_length]
        decrypted_byte = (encrypted[i] ^ key_byte) & 0xFF
        decrypted.append(decrypted_byte)
    return decrypted

def encrypt_message(message, userkey):
    """Encrypt message using AES in CBC mode."""
    print("\nEncrypting message...")
    key = derive_key(userkey)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(message.encode(), AES.block_size))
    encrypted = iv + ct
    print(f"✓ Message encrypted (length: {len(encrypted)} bytes).")
    return encrypted

def decrypt_message(cipher_bytes, userkey):
    """Decrypt message using AES in CBC mode."""
    try:
        print("\nDecrypting message...")
        print(f"Input length to decrypt: {len(cipher_bytes)} bytes")
        key = derive_key(userkey)
        iv = cipher_bytes[:16]
        ct = cipher_bytes[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ct), AES.block_size).decode()
        print("✓ Message decrypted.")
        return decrypted
    except ValueError as e:
        return f"Error: Invalid padding or ciphertext ({str(e)})"
    except Exception as e:
        return f"Error: Key mismatch or invalid ciphertext ({str(e)})"

# Embedding functions
def embed_message(image, message, aes_key, xor_key):
    """Embed message into image using LSB after AES and XOR."""
    print("\nEmbedding message into image...")
    
    # Encrypt with AES
    encrypted_message = encrypt_message(message, aes_key)
    
    # Perform ASCII XOR encryption
    xor_encrypted = ascii_xor_encrypt(encrypted_message, xor_key)
    
    # Debug: Print XOR-encrypted values
    print(f"XOR-encrypted values: {xor_encrypted[:10]}... (first 10)")
    
    # Convert to binary string with triple delimiter
    binary_message = ''.join(format(char, '08b') for char in xor_encrypted) + '111111111111111111111111'
    print(f"Binary message length: {len(binary_message)}")
    
    # Check if image can hold the message
    height, width, channels = image.shape
    max_bits = height * width * channels
    if len(binary_message) > max_bits:
        print(f"Error: Message too large for image (needs {len(binary_message)} bits, available {max_bits})")
        raise ValueError("Message too large for image")
    
    # Create a copy of the image
    stego_image = image.copy()
    
    # Embed message bits into LSB of pixels
    bit_index = 0
    for i in range(height):
        for j in range(width):
            for k in range(channels):
                if bit_index < len(binary_message):
                    pixel = int(stego_image[i, j, k])
                    new_pixel = (pixel & ~1) | int(binary_message[bit_index])
                    stego_image[i, j, k] = np.uint8(new_pixel)
                    bit_index += 1
                else:
                    print("✓ Message embedded successfully.")
                    return stego_image
    
    print("✓ Message embedded successfully.")
    return stego_image

# Extraction functions
def extract_message(stego_image, aes_key, xor_key):
    """Extract and decrypt message from stego-image."""
    print("\nExtracting message from stego-image...")
    
    # Extract bits from LSB
    height, width, channels = stego_image.shape
    binary_message = ''
    max_bits = height * width * channels
    for i in range(height):
        for j in range(width):
            for k in range(channels):
                if len(binary_message) < max_bits:
                    pixel = stego_image[i, j, k]
                    binary_message += str(pixel & 1)
                    # Check for triple delimiter
                    if len(binary_message) >= 24 and binary_message[-24:] == '111111111111111111111111':
                        binary_message = binary_message[:-24]
                        print(f"Extracted binary message length: {len(binary_message)} bits")
                        # Convert binary to bytes
                        if len(binary_message) % 8 != 0:
                            print(f"Error: Binary message length {len(binary_message)} not divisible by 8")
                            return "Error: Invalid binary message length"
                        encrypted_message = []
                        for idx in range(0, len(binary_message), 8):
                            byte = binary_message[idx:idx+8]
                            encrypted_message.append(int(byte, 2))
                        # Debug: Print extracted encrypted values and length
                        print(f"Extracted encrypted values: {encrypted_message[:10]}... (first 10)")
                        print(f"Extracted encrypted length: {len(encrypted_message)} bytes")
                        # Decrypt with ASCII XOR
                        decrypted_xor = ascii_xor_decrypt(encrypted_message, xor_key)
                        print(f"XOR-decrypted values: {decrypted_xor[:10]}... (first 10)")
                        # Convert to bytes and decrypt with AES
                        decrypted_message = decrypt_message(bytes(decrypted_xor), aes_key)
                        print("✓ Message extracted and decrypted.")
                        return decrypted_message
    print("Error: No message found or invalid delimiter.")
    return "Error: No message found"

# Main function to demonstrate encoding and decoding
def main():
    # Load custom image
    image = cv2.imread('thecybervedi.png')
    if image is None:
        print("Error: Could not load image. Check file name or path.")
        return
    
    # Define message and keys
    secret_message = "thecybervedi’s cipher by Shashank for IBM x EduNet!"
    aes_key = "thecybervedi-aes"
    xor_key = "thecybervedi-xor"
    
    # Save original image
    cv2.imwrite('original_image.png', image)
    
    # Embed message
    try:
        stego_image = embed_message(image, secret_message, aes_key, xor_key)
        cv2.imwrite('stego_image.png', stego_image)
        print("\nStego image saved as 'stego_image.png'")
    except Exception as e:
        print(f"Error embedding message: {e}")
        return
    
    # Extract message
    stego_image = cv2.imread('stego_image.png')
    extracted_message = extract_message(stego_image, aes_key, xor_key)
    print(f"\nExtracted message: {extracted_message}")

if __name__ == "__main__":
    main()