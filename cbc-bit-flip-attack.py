from aes_modes import aes_cbc_encrypt, aes_cbc_decrypt, generate_key, generate_iv

BLOCK_SIZE = 16


def run_bit_flipping_attack():
    print("--- AES-CBC Bit-Flipping Attack ---")

    key = generate_key(16)
    iv = generate_iv()

    plaintext = b"userdata=alice; admin=false;"
    _, ciphertext = aes_cbc_encrypt(key, plaintext, iv)

    print(f"Original plaintext : {plaintext}")

    tampered = bytearray(ciphertext)
    base = 22 - BLOCK_SIZE

    tampered[base]     ^= ord('f') ^ ord('t')
    tampered[base + 1] ^= ord('a') ^ ord('r')
    tampered[base + 2] ^= ord('l') ^ ord('u')
    tampered[base + 3] ^= ord('s') ^ ord('e')
    tampered[base + 4] ^= ord('e') ^ ord('_')

    decrypted = aes_cbc_decrypt(key, bytes(tampered), iv)
    print(f"Decrypted after attack: {decrypted}")

    if b"admin=true_" in decrypted:
        print("Result: Success — privilege escalated.")
    else:
        print("Result: Failed.")


if __name__ == "__main__":
    run_bit_flipping_attack()
