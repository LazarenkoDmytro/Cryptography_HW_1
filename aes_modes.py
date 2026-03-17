import secrets
from Crypto.Cipher import AES

BLOCK_SIZE = 16
VALID_KEY_SIZES = (16, 24, 32)


def xor_bytes(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


def _validate_key(key):
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("Key must be bytes.")
    if len(key) not in VALID_KEY_SIZES:
        raise ValueError(f"Invalid key size: {len(key)} bytes.")


def _validate_iv(iv):
    if not isinstance(iv, (bytes, bytearray)):
        raise TypeError("IV must be bytes.")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"IV must be {BLOCK_SIZE} bytes, got {len(iv)}.")


def generate_key(size=16):
    if size not in VALID_KEY_SIZES:
        raise ValueError(f"Key size must be one of {VALID_KEY_SIZES}.")
    return secrets.token_bytes(size)


def generate_iv():
    return secrets.token_bytes(BLOCK_SIZE)


def pkcs7_pad(data):
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data):
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Data length is not a multiple of the block size.")

    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError(f"Invalid padding value: {pad_len}.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Corrupt PKCS#7 padding.")

    return data[:-pad_len]


def aes_ecb_encrypt(key, plaintext, pad=True):
    _validate_key(key)
    cipher = AES.new(key, AES.MODE_ECB)

    if pad:
        plaintext = pkcs7_pad(plaintext)
    elif len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError("Plaintext must be block-aligned when pad=False.")

    result = bytearray()
    for i in range(0, len(plaintext), BLOCK_SIZE):
        result.extend(cipher.encrypt(plaintext[i : i + BLOCK_SIZE]))

    return bytes(result)


def aes_ecb_decrypt(key, ciphertext, unpad=True):
    _validate_key(key)
    cipher = AES.new(key, AES.MODE_ECB)

    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext must be block-aligned.")

    result = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        result.extend(cipher.decrypt(ciphertext[i : i + BLOCK_SIZE]))

    if unpad:
        return pkcs7_unpad(bytes(result))
    return bytes(result)


def aes_cbc_encrypt(key, plaintext, iv=None, pad=True):
    _validate_key(key)
    cipher = AES.new(key, AES.MODE_ECB)

    if iv is None:
        iv = generate_iv()
    _validate_iv(iv)

    if pad:
        plaintext = pkcs7_pad(plaintext)
    elif len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError("Plaintext must be block-aligned when pad=False.")

    result = bytearray()
    prev = iv
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i : i + BLOCK_SIZE]
        encrypted = cipher.encrypt(xor_bytes(block, prev))
        result.extend(encrypted)
        prev = encrypted

    return iv, bytes(result)


def aes_cbc_decrypt(key, ciphertext, iv, unpad=True):
    _validate_key(key)
    cipher = AES.new(key, AES.MODE_ECB)
    _validate_iv(iv)

    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext must be block-aligned.")

    result = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i : i + BLOCK_SIZE]
        decrypted = cipher.decrypt(block)
        result.extend(xor_bytes(decrypted, prev))
        prev = block

    if unpad:
        return pkcs7_unpad(bytes(result))
    return bytes(result)


def aes_cfb_encrypt(key, plaintext, iv=None):
    _validate_key(key)
    cipher = AES.new(key, AES.MODE_ECB)

    if iv is None:
        iv = generate_iv()
    _validate_iv(iv)

    result = bytearray()
    shift_register = bytearray(iv)

    for i in range(0, len(plaintext), BLOCK_SIZE):
        chunk = plaintext[i : i + BLOCK_SIZE]
        output = cipher.encrypt(bytes(shift_register))
        encrypted = xor_bytes(chunk, output[: len(chunk)])
        result.extend(encrypted)
        shift_register = bytearray(encrypted)

    return iv, bytes(result)


def aes_cfb_decrypt(key, ciphertext, iv):
    _validate_key(key)
    cipher = AES.new(key, AES.MODE_ECB)
    _validate_iv(iv)

    result = bytearray()
    shift_register = bytearray(iv)

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        chunk = ciphertext[i : i + BLOCK_SIZE]
        output = cipher.encrypt(bytes(shift_register))
        decrypted = xor_bytes(chunk, output[: len(chunk)])
        result.extend(decrypted)
        shift_register = bytearray(chunk)

    return bytes(result)
