from sympy import randprime
import math
import os
import struct
import zlib

PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'


def generate_prime(min_bits, max_bits):
    """
    Generates a prime number with random bit length.
    """
    lower_bound = 2 ** (min_bits - 1)
    upper_bound = 2 ** max_bits
    return randprime(lower_bound, upper_bound)



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
    
    # return (x % phi + phi) % phi
    return x % phi


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


def encrypt_data_ecb(plaintext_bytes, e, n):
    """
    ECB mode (Electronic CodeBook):
    Each block is encrypted independently.
    Identical plaintext blocks produce identical ciphertext blocks.
    """
    block_size = get_block_size(n)
    ciphertext_blocks = []
    
    for i in range(0, len(plaintext_bytes), block_size):
        block = plaintext_bytes[i:i+block_size]
        if len(block) < block_size:
            block = block + b'\x00' * (block_size - len(block))
        encrypted_block = encrypt_block(block, e, n)
        ciphertext_blocks.append(encrypted_block)
    
    return b''.join(ciphertext_blocks)


def decrypt_data_ecb(ciphertext_bytes, d, n):
    """
    ECB mode (Electronic CodeBook):
    Each block is decrypted independently.
    """
    cipher_block_size = (n.bit_length() + 7) // 8
    plaintext_blocks = []
    
    for i in range(0, len(ciphertext_bytes), cipher_block_size):
        block = ciphertext_bytes[i:i+cipher_block_size]
        decrypted_block = decrypt_block(block, d, n)
        plaintext_blocks.append(decrypted_block)
    
    return b''.join(plaintext_blocks).rstrip(b'\x00')


# Backward-compatible aliases
encrypt_data = encrypt_data_ecb
decrypt_data = decrypt_data_ecb


def encrypt_data_cbc(plaintext_bytes, e, n):
    """
    CBC mode (Cipher Block Chaining):
    Each plaintext block is XORed with the previous ciphertext block
    before encryption. Uses PKCS#7 padding and a random IV.
    """
    block_size = get_block_size(n)
    cipher_block_size = (n.bit_length() + 7) // 8

    pad_len = block_size - (len(plaintext_bytes) % block_size)
    plaintext_bytes = plaintext_bytes + bytes([pad_len] * pad_len)

    iv = os.urandom(cipher_block_size)
    ciphertext_blocks = [iv]
    prev = iv

    for i in range(0, len(plaintext_bytes), block_size):
        block = plaintext_bytes[i:i + block_size]
        mixed = bytes(a ^ b for a, b in zip(block, prev[:block_size]))
        encrypted = encrypt_block(mixed, e, n)
        ciphertext_blocks.append(encrypted)
        prev = encrypted

    return b''.join(ciphertext_blocks)


def decrypt_data_cbc(ciphertext_bytes, d, n):
    """
    CBC mode (Cipher Block Chaining):
    Decrypt each block, then XOR with the previous ciphertext block.
    """
    cipher_block_size = (n.bit_length() + 7) // 8
    block_size = get_block_size(n)

    iv = ciphertext_bytes[:cipher_block_size]
    prev = iv
    plaintext_blocks = []

    for i in range(cipher_block_size, len(ciphertext_bytes), cipher_block_size):
        ct_block = ciphertext_bytes[i:i + cipher_block_size]
        decrypted = decrypt_block(ct_block, d, n)
        mixed = bytes(a ^ b for a, b in zip(decrypted, prev[:block_size]))
        plaintext_blocks.append(mixed)
        prev = ct_block

    result = b''.join(plaintext_blocks)
    pad_len = result[-1]
    if pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding")
    return result[:-pad_len]


def encrypt_data_ctr(plaintext_bytes, e, n):
    """
    CTR mode (Counter):
    Encrypt counter values with RSA and XOR the keystream with plaintext.
    No padding needed. Uses a random nonce.
    The counter block is sized to block_size bytes so its integer value < n.
    """
    block_size = get_block_size(n)
    nonce_len = block_size // 2

    nonce = os.urandom(nonce_len)
    ciphertext_parts = [nonce]
    counter = 0

    for i in range(0, len(plaintext_bytes), block_size):
        chunk = plaintext_bytes[i:i + block_size]
        counter_bytes = nonce + counter.to_bytes(block_size - nonce_len, 'big')
        keystream = encrypt_block(counter_bytes, e, n)
        encrypted_chunk = bytes(a ^ b for a, b in zip(chunk, keystream[:len(chunk)]))
        ciphertext_parts.append(encrypted_chunk)
        counter += 1

    return b''.join(ciphertext_parts)


def decrypt_data_ctr(ciphertext_bytes, e, n):
    """
    CTR mode (Counter):
    Same as encryption — XOR keystream with ciphertext.
    Uses the RSA encryption function (e, n) for keystream generation.
    """
    block_size = get_block_size(n)
    nonce_len = block_size // 2

    nonce = ciphertext_bytes[:nonce_len]
    rest = ciphertext_bytes[nonce_len:]

    plaintext_parts = []
    counter = 0

    for i in range(0, len(rest), block_size):
        chunk = rest[i:i + block_size]
        counter_bytes = nonce + counter.to_bytes(block_size - nonce_len, 'big')
        keystream = encrypt_block(counter_bytes, e, n)
        decrypted_chunk = bytes(a ^ b for a, b in zip(chunk, keystream[:len(chunk)]))
        plaintext_parts.append(decrypted_chunk)
        counter += 1

    return b''.join(plaintext_parts)


def _parse_ihdr(ihdr_data):
    """Return (width, height, bit_depth, color_type) from a raw IHDR payload."""
    w, h = struct.unpack('>II', ihdr_data[:8])
    return w, h, ihdr_data[8], ihdr_data[9]


def _channels(color_type):
    return {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color_type, 3)


def _bytes_per_row(width, bit_depth, color_type):
    """Pixel bytes per scanline (no filter byte)."""
    return (width * _channels(color_type) * bit_depth + 7) // 8


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
    Encrypts a PNG file at the pixel level (raw RSA, ECB mode — blocks
    encrypted independently with zero-padding).

    Steps:
      1. Decompress IDAT → raw scanlines (filter_byte + pixel_bytes per row).
      2. Extract pixel bytes; keep filter bytes for recovery.
      3. Encrypt pixel bytes block-by-block (raw RSA, ECB — no padding).
      4. Pack ciphertext back as filter-0 scanlines and recompress → new IDAT.
      5. Store original height + filter bytes in a private 'rsFl' chunk so
         decryption can restore the file byte-for-byte.

    Because the ciphertext is slightly larger than the plaintext (256 output
    bytes per 255 input bytes for a 2048-bit key), the encrypted image may
    have a few extra rows compared to the original.
    """
    n, e = public_key

    with open(input_path, 'rb') as f:
        data = f.read()

    print(f"[*] Encrypting PNG (pixel-level, raw RSA): {input_path}")
    print(f"[*] File size: {len(data)} bytes")

    chunks = _parse_png_chunks(data)

    # cd - chunk data, ct - chunk type
    ihdr_data = next(cd for ct, cd in chunks if ct == b'IHDR')
    orig_w, orig_h, bit_depth, color_type = _parse_ihdr(ihdr_data)
    bpr = _bytes_per_row(orig_w, bit_depth, color_type)

    raw_idat = b''.join(cd for ct, cd in chunks if ct == b'IDAT')
    raw_scanlines = zlib.decompress(raw_idat)
    print(f"[*] Decompressed IDAT: {len(raw_scanlines)} bytes  ({orig_h} rows × {bpr} px-bytes)")

    stride = bpr + 1
    filter_bytes = bytes(raw_scanlines[i * stride] for i in range(orig_h))
    pixel_bytes  = b''.join(raw_scanlines[i * stride + 1:(i + 1) * stride] for i in range(orig_h))

    payload = struct.pack('>I', len(pixel_bytes)) + pixel_bytes
    encrypted = encrypt_data(payload, e, n)
    print(f"[+] Encrypted pixel data: {len(encrypted)} bytes")

    enc_rows = []
    for off in range(0, len(encrypted), bpr):
        row = encrypted[off:off + bpr]
        if len(row) < bpr:
            row = row + b'\x00' * (bpr - len(row))
        enc_rows.append(b'\x00' + row)

    new_h    = len(enc_rows)
    new_ihdr = struct.pack('>II', orig_w, new_h) + ihdr_data[8:]
    recovery = struct.pack('>II', orig_h, len(pixel_bytes)) + filter_bytes
    enc_idat = zlib.compress(b''.join(enc_rows))

    new_chunks = []
    idat_written = False
    for ct, cd in chunks:
        if ct == b'IHDR':
            new_chunks.append((b'IHDR', new_ihdr))
        elif ct == b'IDAT':
            if not idat_written:
                new_chunks.append((b'rsFl', recovery))
                new_chunks.append((b'IDAT', enc_idat))
                idat_written = True
        else:
            new_chunks.append((ct, cd))

    with open(output_path, 'wb') as f:
        f.write(_build_png(new_chunks))

    print(f"[+] Written to {output_path}")


def decrypt_png_file(input_path, output_path, private_key):
    """
    Decrypts a PNG file produced by encrypt_png_file (ECB mode).
    Restores the original file byte-for-byte (including original filter bytes).
    """
    n, d = private_key

    with open(input_path, 'rb') as f:
        data = f.read()

    print(f"[*] Decrypting PNG (pixel-level, raw RSA): {input_path}")

    chunks = _parse_png_chunks(data)

    recovery = next((cd for ct, cd in chunks if ct == b'rsFl'), None)
    if recovery is None:
        raise ValueError("Missing 'rsFl' recovery chunk — file was not encrypted by encrypt_png_file.")

    orig_h         = struct.unpack('>I', recovery[:4])[0]
    orig_pixel_len = struct.unpack('>I', recovery[4:8])[0]
    filter_bytes   = recovery[8:]

    ihdr_data = next(cd for ct, cd in chunks if ct == b'IHDR')
    enc_w, enc_h, bit_depth, color_type = _parse_ihdr(ihdr_data)
    bpr = _bytes_per_row(enc_w, bit_depth, color_type)

    raw_idat     = b''.join(cd for ct, cd in chunks if ct == b'IDAT')
    enc_scanlines = zlib.decompress(raw_idat)

    stride    = bpr + 1
    enc_bytes = b''.join(enc_scanlines[i * stride + 1:(i + 1) * stride] for i in range(enc_h))

    block_size       = get_block_size(n)
    cipher_block_size = (n.bit_length() + 7) // 8
    payload_len  = 4 + orig_pixel_len
    num_blocks   = (payload_len + block_size - 1) // block_size
    enc_bytes    = enc_bytes[:num_blocks * cipher_block_size]

    plaintext_blocks = []
    for i in range(0, len(enc_bytes), cipher_block_size):
        block = enc_bytes[i:i + cipher_block_size]
        if len(block) == cipher_block_size:
            plaintext_blocks.append(decrypt_block(block, d, n))
    full_payload = b''.join(plaintext_blocks)

    recovered_len = struct.unpack('>I', full_payload[:4])[0]
    pixel_bytes   = full_payload[4:4 + recovered_len]
    print(f"[+] Restored pixel data: {len(pixel_bytes)} bytes")

    raw_scanlines = bytearray()
    for i in range(orig_h):
        raw_scanlines.append(filter_bytes[i])
        raw_scanlines.extend(pixel_bytes[i * bpr:(i + 1) * bpr])

    orig_ihdr = ihdr_data[:4] + struct.pack('>I', orig_h) + ihdr_data[8:]

    new_chunks = []
    idat_written = False
    for ct, cd in chunks:
        if ct == b'IHDR':
            new_chunks.append((b'IHDR', orig_ihdr))
        elif ct == b'IDAT':
            if not idat_written:
                new_chunks.append((b'IDAT', zlib.compress(bytes(raw_scanlines))))
                idat_written = True
        elif ct == b'rsFl':
            pass
        else:
            new_chunks.append((ct, cd))

    with open(output_path, 'wb') as f:
        f.write(_build_png(new_chunks))

    print(f"[+] Written to {output_path}")
