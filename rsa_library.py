"""
Library-based RSA encryption using the `cryptography` package (RSA-OAEP).
Used only for comparison with our own implementation in compare_rsa.py.
"""

import struct
import zlib
from cryptography.hazmat.primitives.asymmetric import rsa as _lib_rsa
from cryptography.hazmat.primitives.asymmetric import padding as _lib_padding
from cryptography.hazmat.primitives import hashes as _lib_hashes
from RSA import _parse_png_chunks, _build_png, _parse_ihdr, _bytes_per_row


def generate_keys_with_library(key_size=2048):
    """
    Generates an RSA key pair using the cryptography library.

    Returns:
        our_public_key  (n, e)   -- compatible with encrypt_png_file from RSA.py
        our_private_key (n, d)   -- compatible with decrypt_png_file from RSA.py
        lib_public_key           -- cryptography PublicKey object
        lib_private_key          -- cryptography PrivateKey object

    Both key pairs share the same n, e, d so results are directly comparable.
    """
    lib_priv = _lib_rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    lib_pub = lib_priv.public_key()

    pub_numbers  = lib_pub.public_numbers()
    priv_numbers = lib_priv.private_numbers()

    n = pub_numbers.n
    e = pub_numbers.e
    d = priv_numbers.d

    print(f"[+] n = {n}")
    print(f"[+] Modulus size: {n.bit_length()} bits")
    print(f"[+] e = {e}")
    print(f"[+] d = {d}")

    return (n, e), (n, d), lib_pub, lib_priv


def encrypt_png_file_library(input_path, output_path, lib_public_key):
    """
    Encrypts a PNG file at the pixel level using RSA-OAEP (cryptography library).

    Same pixel-level approach as encrypt_png_file (RSA.py) so the two outputs
    can be visually compared:
      - Our raw RSA (ECB, no padding)  → patterns from repeated pixel blocks may show.
      - Library RSA-OAEP (random seed) → completely random noise every run.
    """
    with open(input_path, 'rb') as f:
        data = f.read()

    print(f"[*] Encrypting PNG with library (OAEP): {input_path}")

    chunks    = _parse_png_chunks(data)
    ihdr_data = next(cd for ct, cd in chunks if ct == b'IHDR')
    orig_w, orig_h, bit_depth, color_type = _parse_ihdr(ihdr_data)
    bpr = _bytes_per_row(orig_w, bit_depth, color_type)

    raw_idat     = b''.join(cd for ct, cd in chunks if ct == b'IDAT')
    raw_scanlines = zlib.decompress(raw_idat)
    print(f"[*] Decompressed IDAT: {len(raw_scanlines)} bytes  ({orig_h} rows × {bpr} px-bytes)")

    stride       = bpr + 1
    filter_bytes = bytes(raw_scanlines[i * stride] for i in range(orig_h))
    pixel_bytes  = b''.join(raw_scanlines[i * stride + 1:(i + 1) * stride] for i in range(orig_h))

    key_bytes = lib_public_key.key_size // 8
    max_block = key_bytes - 2 * 32 - 2
    oaep = _lib_padding.OAEP(
        mgf=_lib_padding.MGF1(algorithm=_lib_hashes.SHA256()),
        algorithm=_lib_hashes.SHA256(),
        label=None,
    )

    payload = struct.pack('>I', len(pixel_bytes)) + pixel_bytes
    encrypted_blocks = []
    for i in range(0, len(payload), max_block):
        block = payload[i:i + max_block]
        encrypted_blocks.append(lib_public_key.encrypt(block, oaep))
    encrypted = b''.join(encrypted_blocks)
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


def decrypt_png_file_library(input_path, output_path, lib_private_key):
    """
    Decrypts a PNG file produced by encrypt_png_file_library.
    Restores the original file byte-for-byte (including original filter bytes).
    """
    with open(input_path, 'rb') as f:
        data = f.read()

    print(f"[*] Decrypting PNG with library (OAEP): {input_path}")

    chunks = _parse_png_chunks(data)

    recovery = next((cd for ct, cd in chunks if ct == b'rsFl'), None)
    if recovery is None:
        raise ValueError("Missing 'rsFl' recovery chunk — file was not encrypted by encrypt_png_file_library.")

    orig_h         = struct.unpack('>I', recovery[:4])[0]
    orig_pixel_len = struct.unpack('>I', recovery[4:8])[0]
    filter_bytes   = recovery[8:]

    ihdr_data = next(cd for ct, cd in chunks if ct == b'IHDR')
    enc_w, enc_h, bit_depth, color_type = _parse_ihdr(ihdr_data)
    bpr = _bytes_per_row(enc_w, bit_depth, color_type)

    raw_idat      = b''.join(cd for ct, cd in chunks if ct == b'IDAT')
    enc_scanlines = zlib.decompress(raw_idat)

    stride    = bpr + 1
    enc_bytes = b''.join(enc_scanlines[i * stride + 1:(i + 1) * stride] for i in range(enc_h))

    key_bytes = lib_private_key.key_size // 8
    max_block = key_bytes - 2 * 32 - 2
    payload_len = 4 + orig_pixel_len
    num_blocks  = (payload_len + max_block - 1) // max_block
    enc_bytes   = enc_bytes[:num_blocks * key_bytes]

    oaep = _lib_padding.OAEP(
        mgf=_lib_padding.MGF1(algorithm=_lib_hashes.SHA256()),
        algorithm=_lib_hashes.SHA256(),
        label=None,
    )

    decrypted_blocks = []
    for i in range(0, len(enc_bytes), key_bytes):
        block = enc_bytes[i:i + key_bytes]
        if len(block) == key_bytes:
            decrypted_blocks.append(lib_private_key.decrypt(block, oaep))
    full_payload = b''.join(decrypted_blocks)

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
