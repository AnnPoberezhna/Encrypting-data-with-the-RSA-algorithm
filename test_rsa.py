import logging

from RSA import (
    mod_inverse,
    extended_gcd,
    generate_keys,
    encrypt_block,
    decrypt_block,
    get_block_size,
    encrypt_data_ecb,
    decrypt_data_ecb,
    encrypt_data_cbc,
    decrypt_data_cbc,
    encrypt_data_ctr,
    decrypt_data_ctr,
    encrypt_png_file,
    decrypt_png_file,
    PNG_SIGNATURE,
    _parse_png_chunks,
)

import time
import os


def test_extended_gcd():
    """Test extended Euclidean algorithm"""
    print("\n" + "="*70)
    print("TEST: Extended Euclidean Algorithm")
    print("="*70)
    
    gcd, x, y = extended_gcd(10, 6)
    print(f"extended_gcd(10, 6) = ({gcd}, {x}, {y})")
    print(f"Check: 10*{x} + 6*{y} = {10*x + 6*y} (should be {gcd})")
    
    assert gcd == 2
    assert 10*x + 6*y == gcd
    print("[✓] Test passed")


def test_mod_inverse():
    """Test modular inverse"""
    print("\n" + "="*70)
    print("TEST: Modular Inverse")
    print("="*70)
    
    e = 7
    phi = 12
    
    d = mod_inverse(e, phi)
    print(f"mod_inverse({e}, {phi}) = {d}")
    print(f"Check: ({e} * {d}) mod {phi} = {(e * d) % phi} (should be 1)")
    
    assert (e * d) % phi == 1
    print("[✓] Test passed")


def test_key_generation():
    """Test RSA key generation"""
    print("\n" + "="*70)
    print("TEST: RSA Key Generation")
    print("="*70)
    
    # Generate small keys for test speed
    start = time.time()
    public_key, private_key = generate_keys(key_size=512)
    elapsed = time.time() - start
    
    n, e = public_key
    n_priv, d = private_key
    
    print(f"\nGeneration time: {elapsed:.2f}s")
    print(f"Public key: (n={n}, e={e})")
    print(f"Private key: (n={n_priv}, d={d})")
    print(f"Block size: {get_block_size(n)} bytes")
    
    assert n == n_priv
    assert e > 1
    assert d > 1
    print("[✓] Test passed")


def test_block_encryption_decryption():
    """Test block encryption and decryption"""
    print("\n" + "="*70)
    print("TEST: Block Encryption and Decryption")
    print("="*70)
    
    # Generate keys
    public_key, private_key = generate_keys(key_size=512)
    n, e = public_key
    n_priv, d = private_key
    
    block_size = get_block_size(n)
    print(f"Block size: {block_size} bytes")
    
    # Test various data
    test_cases = [
        b"Hello",
        b"RSA",
        b"\x00\x01\x02\x03",
        bytes(range(min(256, block_size))),
    ]
    
    for plaintext in test_cases:
        # Padding
        block = plaintext + b'\x00' * (block_size - len(plaintext))
        
        # Encryption
        ciphertext = encrypt_block(block, e, n)
        
        # Decryption
        decrypted = decrypt_block(ciphertext, d, n)
        
        # Compare (omit padding)
        decrypted_clean = decrypted.rstrip(b'\x00')
        plaintext_clean = plaintext.rstrip(b'\x00')
        
        match = decrypted_clean == plaintext_clean
        status = "[✓]" if match else "[✗]"
        
        print(f"{status} {plaintext} -> {decrypted_clean}")
        assert match, f"Mismatch for {plaintext}"
    
    print("[✓] All tests passed")


def test_data_encryption_decryption_ecb():
    """Test ECB mode encryption and decryption of multi-block data"""
    print("\n" + "="*70)
    print("TEST: ECB Mode — Multi-block Data Encryption and Decryption")
    print("="*70)
    
    public_key, private_key = generate_keys(key_size=512)
    n, e = public_key
    n_priv, d = private_key
    
    test_data = [
        b"Hello World!",
        b"The quick brown fox jumps over the lazy dog" * 3,
        bytes(range(256)) * 2,
    ]
    
    for plaintext in test_data:
        print(f"\nData: {len(plaintext)} bytes")
        ciphertext = encrypt_data_ecb(plaintext, e, n)
        print(f"Encrypted: {len(ciphertext)} bytes")
        decrypted = decrypt_data_ecb(ciphertext, d, n)
        print(f"Decrypted: {len(decrypted)} bytes")
        match = decrypted == plaintext
        status = "[✓]" if match else "[✗]"
        print(f"{status} Data matches: {match}")
        assert match, f"ECB mismatch for data of size {len(plaintext)}"
    
    print("\n[✓] All ECB tests passed")


def test_data_encryption_decryption_cbc():
    """Test CBC mode encryption and decryption"""
    print("\n" + "="*70)
    print("TEST: CBC Mode — Multi-block Data Encryption and Decryption")
    print("="*70)
    
    public_key, private_key = generate_keys(key_size=512)
    n, e = public_key
    n_priv, d = private_key
    
    test_data = [
        b"Hello World!",
        b"Short",
        b"The quick brown fox jumps over the lazy dog" * 3,
        bytes(range(256)) * 2,
        b"A" * (get_block_size(n) * 3 + 1),
    ]
    
    for plaintext in test_data:
        print(f"\nData: {len(plaintext)} bytes")
        ciphertext = encrypt_data_cbc(plaintext, e, n)
        print(f"Encrypted: {len(ciphertext)} bytes")
        decrypted = decrypt_data_cbc(ciphertext, d, n)
        print(f"Decrypted: {len(decrypted)} bytes")
        match = decrypted == plaintext
        status = "[✓]" if match else "[✗]"
        print(f"{status} Data matches: {match}")
        assert match, f"CBC mismatch for data of size {len(plaintext)}"
    
    # Verify that identical plaintexts produce different ciphertexts (different IV)
    data = b"Same data same data same data"
    c1 = encrypt_data_cbc(data, e, n)
    c2 = encrypt_data_cbc(data, e, n)
    assert c1 != c2, "CBC ciphertexts should differ due to random IV"
    print("\n[✓] CBC is non-deterministic (different IV → different ciphertext)")
    
    print("\n[✓] All CBC tests passed")


def test_data_encryption_decryption_ctr():
    """Test CTR mode encryption and decryption"""
    print("\n" + "="*70)
    print("TEST: CTR Mode — Multi-block Data Encryption and Decryption")
    print("="*70)
    
    public_key, private_key = generate_keys(key_size=512)
    n, e = public_key
    n_priv, d = private_key
    
    test_data = [
        b"Hello World!",
        b"Short",
        b"The quick brown fox jumps over the lazy dog" * 3,
        bytes(range(256)) * 2,
        b"B" * (get_block_size(n) * 3 + 1),
    ]
    
    for plaintext in test_data:
        print(f"\nData: {len(plaintext)} bytes")
        ciphertext = encrypt_data_ctr(plaintext, e, n)
        print(f"Encrypted: {len(ciphertext)} bytes")
        decrypted = decrypt_data_ctr(ciphertext, e, n)
        print(f"Decrypted: {len(decrypted)} bytes")
        match = decrypted == plaintext
        status = "[✓]" if match else "[✗]"
        print(f"{status} Data matches: {match}")
        assert match, f"CTR mismatch for data of size {len(plaintext)}"
    
    # Verify non-determinism (different nonce → different ciphertext)
    data = b"Same data same"
    c1 = encrypt_data_ctr(data, e, n)
    c2 = encrypt_data_ctr(data, e, n)
    assert c1 != c2, "CTR ciphertexts should differ due to random nonce"
    print("\n[✓] CTR is non-deterministic (different nonce → different ciphertext)")
    
    # Verify no padding needed — size preservation for full blocks
    exact = b"A" * get_block_size(n)
    ct = encrypt_data_ctr(exact, e, n)
    nonce_len = get_block_size(n) // 2
    assert len(ct) == nonce_len + len(exact), "CTR should not add padding"
    print("[✓] CTR requires no padding (ciphertext ≈ plaintext + nonce)")
    
    print("\n[✓] All CTR tests passed")


def test_file_encryption_png():
    """
    Test PNG payload-only encryption:
    - PNG signature and IHDR must survive unchanged.
    - Encrypted IDAT data must differ from the original.
    - After decryption the file must be byte-for-byte identical to the original.
    """
    print("\n" + "="*70)
    print("TEST: PNG Payload-Only Encryption (header/metadata preserved)")
    print("="*70)

    test_png_path = "png-beer.png"
    encrypted_path = "png-beer_encrypted.png"
    decrypted_path = "png-beer_decrypted.png"

    if not os.path.exists(test_png_path):
        print(f"[!] File not found: {test_png_path}")
        print("[!] Skipping PNG encryption test")
        return

    print("\n[1] Generating keys...")
    public_key, private_key = generate_keys(key_size=512)

    print(f"\n[2] Using PNG file: {test_png_path}")
    with open(test_png_path, 'rb') as f:
        original = f.read()

    print("\n[3] Encrypting PNG (payload only)...")
    encrypt_png_file(test_png_path, encrypted_path, public_key)

    with open(encrypted_path, 'rb') as f:
        encrypted = f.read()

    print("\n[4] Verifying structure is preserved...")

    assert encrypted[:8] == PNG_SIGNATURE, "PNG signature must be preserved"
    print("[✓] PNG signature intact")

    orig_chunks = _parse_png_chunks(original)
    enc_chunks  = _parse_png_chunks(encrypted)

    orig_ihdr = next(cd for ct, cd in orig_chunks if ct == b'IHDR')
    enc_ihdr  = next(cd for ct, cd in enc_chunks  if ct == b'IHDR')
    # Width (bytes 0-3) and image attributes (bytes 8-12) must be unchanged.
    # Height (bytes 4-7) may grow slightly because ciphertext is larger than plaintext.
    assert orig_ihdr[:4]  == enc_ihdr[:4],  "Width must be preserved in IHDR"
    assert orig_ihdr[8:]  == enc_ihdr[8:],  "Bit-depth / color-type / interlace must be preserved"
    print("[✓] IHDR chunk preserved (width and image attributes unchanged)")

    orig_idat = b''.join(cd for ct, cd in orig_chunks if ct == b'IDAT')
    enc_idat  = b''.join(cd for ct, cd in enc_chunks  if ct == b'IDAT')
    assert orig_idat != enc_idat, "IDAT data must differ after encryption"
    print("[✓] IDAT data is encrypted (differs from original)")

    print("\n[5] Decrypting PNG...")
    decrypt_png_file(encrypted_path, decrypted_path, private_key)

    with open(decrypted_path, 'rb') as f:
        recovered = f.read()

    match = original == recovered
    status = "[✓]" if match else "[✗]"
    print(f"{status} Original and decrypted files match: {match}")
    print(f"  Original size:  {len(original)} bytes")
    print(f"  Encrypted size: {len(encrypted)} bytes")
    print(f"  Decrypted size: {len(recovered)} bytes")

    for path in [encrypted_path, decrypted_path]:
        try:
            os.remove(path)
        except FileNotFoundError as e:
            logging.warning(f"File not found during cleanup: {e}")
        except PermissionError:
            print(f"No permission to delete {path}.")

    assert match, "Decrypted file does not match the original"
    print("[✓] Test passed")


def main():
    """Run all tests"""
    print("\n" + "#"*70)
    print("# RSA - TEST SUITE")
    print("#"*70)
    
    test_extended_gcd()
    test_mod_inverse()
    test_key_generation()
    test_block_encryption_decryption()
    test_data_encryption_decryption_ecb()
    test_data_encryption_decryption_cbc()
    test_data_encryption_decryption_ctr()
    test_file_encryption_png()
    
    print("\n" + "#"*70)
    print("# ALL TESTS PASSED SUCCESSFULLY!")
    print("#"*70 + "\n")


if __name__ == "__main__":
    main()
