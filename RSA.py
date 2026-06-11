from sympy import randprime
import math


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


def encrypt_file(input_path, output_path, public_key):
    """
    Encrypts a file using the public key.
    """
    n, e = public_key
    
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    
    print(f"[*] Encrypting {input_path}...")
    print(f"[*] File size: {len(plaintext)} bytes")
    

    ciphertext = encrypt_data(plaintext, e, n)
    print(f"[+] Encrypted: {len(ciphertext)} bytes")
    

    with open(output_path, 'wb') as f:
        f.write(ciphertext)
    
    print(f"[+] Written to {output_path}")


def decrypt_file(input_path, output_path, private_key):
    """
    Decrypts a file using the private key.
    """
    n, d = private_key
    
    with open(input_path, 'rb') as f:
        ciphertext = f.read()
    
    print(f"[*] Decrypting {input_path}...")
    print(f"[*] File size: {len(ciphertext)} bytes")
    
    # Decrypt data
    plaintext = decrypt_data(ciphertext, d, n)
    print(f"[+] Decrypted: {len(plaintext)} bytes")
    
    with open(output_path, 'wb') as f:
        f.write(plaintext)
    
    print(f"[+] Written to {output_path}")