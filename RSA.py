from sympy import randprime
import math
import struct
import zlib

PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'


def generate_prime(min_bits, max_bits):
    """
    Generates a prime number with random bit length.
    """
    bit_length = 2 ** (min_bits - 1)
    upper_bound = 2 ** max_bits
    return randprime(bit_length, upper_bound)



def extended_gcd(a, b):
    """
    Extended Euclidean algorithm.
    Returns (gcd, x, y) such that: a*x + b*y = gcd
    """
    if a == 0:
        return b, 0, 1
    
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    
    return gcd, x, y


def mod_inverse(e, phi):
    """
    Computes the modular inverse: (e^-1) mod phi
    """
    gcd, x, _ = extended_gcd(e, phi)
    
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    
    return (x % phi + phi) % phi


def generate_keys(key_size=2048):
    """
    Generates an RSA key pair (public, private).
    
    Args:
        key_size: key size in bits
    
    Returns:
        ((n, e), (n, d)) - public and private key
    """
    # Determine size for each prime
    prime_bits = key_size // 2
    
    print(f"[*] Generating prime numbers ({prime_bits} bits each)...")
    
    p = generate_prime(prime_bits - 1, prime_bits)
    q = generate_prime(prime_bits - 1, prime_bits)
    
    while p == q:
        q = generate_prime(prime_bits - 1, prime_bits)
    
    print(f"[+] p = {p}")
    print(f"[+] q = {q}")
    
    # Compute modulus
    n = p * q
    print(f"[+] n = p * q = {n}")
    print(f"[+] Modulus size: {n.bit_length()} bits")
    
    # Compute Euler's totient function
    phi = (p - 1) * (q - 1)
    print(f"[+] φ(n) = {phi}")
    
    # Choose e (usually 65537, but may be smaller for small n)
    e = 65537
    
    # If e >= φ(n), reduce e
    if e >= phi:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
    
    print(f"[+] e = {e}")
    
    d = mod_inverse(e, phi)
    print(f"[+] d = {d}")
    
    return (n, e), (n, d)

def get_block_size(n):
    """
    Computes the maximum block size based on modulus n.
    Block must be smaller than n.
    
    Returns: number of bytes in a block
    """
    # Number of bytes = (number of bits - 1) / 8
    # Subtract 1 to ensure block < n
    bit_length = n.bit_length() - 1
    byte_length = bit_length // 8
    
    return max(1, byte_length)


def bytes_to_int(data):
    """Converts bytes to integer"""
    return int.from_bytes(data, byteorder='big')


def int_to_bytes(num, length):
    """Converts integer to bytes of specified length"""
    return num.to_bytes(length, byteorder='big')


def encrypt_block(plaintext_block, e, n):
    """
    Encrypts a single block.
    """

    m = bytes_to_int(plaintext_block)
    
    if m >= n:
        raise ValueError(f"Block too large: {m} >= {n}")
    
    # Encryption: c = m^e mod n
    c = pow(m, e, n)
    
    # Convert result to bytes (with variable size)
    cipher_bytes = int_to_bytes(c, (n.bit_length() + 7) // 8)
    
    return cipher_bytes


def decrypt_block(ciphertext_block, d, n):
    """
    Decrypts a single block.
    """
    c = bytes_to_int(ciphertext_block)
    
    # Decryption: m = c^d mod n
    m = pow(c, d, n)
    
    # Convert result to bytes
    block_size = get_block_size(n)
    plain_bytes = int_to_bytes(m, block_size)
    
    return plain_bytes


def encrypt_data(plaintext_bytes, e, n):
    """
    Encrypts data (file) in blocks.
    """
    block_size = get_block_size(n)
    ciphertext_blocks = []
    
    # Split data into blocks
    for i in range(0, len(plaintext_bytes), block_size):
        block = plaintext_bytes[i:i+block_size]
        
        # Padding: if last block is smaller, fill with zeros
        if len(block) < block_size:
            block = block + b'\x00' * (block_size - len(block))
        
        encrypted_block = encrypt_block(block, e, n)
        ciphertext_blocks.append(encrypted_block)
    
    # Combine all blocks into one byte string
    return b''.join(ciphertext_blocks)


def decrypt_data(ciphertext_bytes, d, n):
    """
    Decrypts data (file) in blocks.
    """
    cipher_block_size = (n.bit_length() + 7) // 8
    plaintext_blocks = []
    
    # Split data into blocks
    for i in range(0, len(ciphertext_bytes), cipher_block_size):
        block = ciphertext_bytes[i:i+cipher_block_size]
        
        decrypted_block = decrypt_block(block, d, n)
        plaintext_blocks.append(decrypted_block)
    
    # Combine blocks and remove padding
    plaintext = b''.join(plaintext_blocks).rstrip(b'\x00')
    
    return plaintext


# ---------------------------------------------------------------------------
# PNG-aware encryption: only IDAT (pixel) data is encrypted;
# the PNG signature, IHDR and all other metadata chunks remain untouched.
# ---------------------------------------------------------------------------

def _parse_png_chunks(data):
    """
    Parse a PNG byte string into a list of (chunk_type: bytes, chunk_data: bytes).
    Raises ValueError if the PNG signature is missing.
    """
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("Not a valid PNG file (bad signature)")

    chunks = []
    offset = len(PNG_SIGNATURE)

    while offset < len(data):
        if offset + 8 > len(data):
            break
        length = struct.unpack('>I', data[offset:offset + 4])[0]
        chunk_type = data[offset + 4:offset + 8]
        chunk_data = data[offset + 8:offset + 8 + length]
        chunks.append((chunk_type, chunk_data))
        offset += 12 + length

    return chunks


def _build_png_chunk(chunk_type, chunk_data):
    """Build a single PNG chunk with a freshly computed CRC."""
    length = struct.pack('>I', len(chunk_data))
    crc = struct.pack('>I', zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF)
    return length + chunk_type + chunk_data + crc


def _build_png(chunks):
    """Reassemble a PNG file from a list of (chunk_type, chunk_data) pairs."""
    return PNG_SIGNATURE + b''.join(
        _build_png_chunk(ct, cd) for ct, cd in chunks
    )


def encrypt_png_file(input_path, output_path, public_key):
    """
    Encrypts a PNG file while preserving its header and metadata.

    Only the concatenated IDAT chunk payload (compressed pixel data) is
    encrypted.  All other chunks (IHDR, tEXt, gAMA, IEND, …) are written
    back unchanged.  The original IDAT byte-length is prepended (4 bytes,
    big-endian) to the plaintext before encryption so that decryption can
    recover the exact original length without relying on zero-stripping.
    """
    n, e = public_key

    with open(input_path, 'rb') as f:
        data = f.read()

    print(f"[*] Encrypting PNG (payload only): {input_path}")
    print(f"[*] File size: {len(data)} bytes")

    chunks = _parse_png_chunks(data)

    idat_data = b''.join(cd for ct, cd in chunks if ct == b'IDAT')
    original_idat_len = len(idat_data)
    print(f"[*] IDAT payload size: {original_idat_len} bytes")

    # Prepend original length so decryption can recover exact bytes
    payload = struct.pack('>I', original_idat_len) + idat_data
    encrypted_idat = encrypt_data(payload, e, n)
    print(f"[+] Encrypted IDAT size: {len(encrypted_idat)} bytes")

    # Rebuild PNG: replace all IDAT chunks with a single encrypted one
    new_chunks = []
    idat_written = False
    for chunk_type, chunk_data in chunks:
        if chunk_type == b'IDAT':
            if not idat_written:
                new_chunks.append((b'IDAT', encrypted_idat))
                idat_written = True
        else:
            new_chunks.append((chunk_type, chunk_data))

    with open(output_path, 'wb') as f:
        f.write(_build_png(new_chunks))

    print(f"[+] Written to {output_path}")


def decrypt_png_file(input_path, output_path, private_key):
    """
    Decrypts a PNG file that was encrypted with encrypt_png_file.
    Restores the original IDAT data exactly (byte-for-byte).
    """
    n, d = private_key

    with open(input_path, 'rb') as f:
        data = f.read()

    print(f"[*] Decrypting PNG (payload only): {input_path}")
    print(f"[*] File size: {len(data)} bytes")

    chunks = _parse_png_chunks(data)
    encrypted_idat = b''.join(cd for ct, cd in chunks if ct == b'IDAT')

    # Decrypt block by block without zero-stripping — compressed IDAT data
    # can legitimately end with 0x00, so rstrip would corrupt it.
    # The original byte-length was stored as the first 4 bytes during encryption.
    cipher_block_size = (n.bit_length() + 7) // 8
    plaintext_blocks = []
    for i in range(0, len(encrypted_idat), cipher_block_size):
        block = encrypted_idat[i:i + cipher_block_size]
        plaintext_blocks.append(decrypt_block(block, d, n))
    full_payload = b''.join(plaintext_blocks)

    original_idat_len = struct.unpack('>I', full_payload[:4])[0]
    idat_data = full_payload[4:4 + original_idat_len]
    print(f"[+] Restored IDAT payload size: {len(idat_data)} bytes")

    new_chunks = []
    idat_written = False
    for chunk_type, chunk_data in chunks:
        if chunk_type == b'IDAT':
            if not idat_written:
                new_chunks.append((b'IDAT', idat_data))
                idat_written = True
        else:
            new_chunks.append((chunk_type, chunk_data))

    with open(output_path, 'wb') as f:
        f.write(_build_png(new_chunks))

    print(f"[+] Written to {output_path}")