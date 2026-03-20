from aes_modes import aes_cbc_encrypt, aes_cbc_decrypt, generate_key, generate_iv

BLOCK_SIZE = 16


def padding_oracle(key, iv, ciphertext):
    try:
        aes_cbc_decrypt(key, ciphertext, iv, unpad=True)
        return True
    except ValueError:
        return False


def attack_block(key, prev_block, target_block):
    intermediate = bytearray(BLOCK_SIZE)

    for byte_idx in range(BLOCK_SIZE - 1, -1, -1):
        pad_val = BLOCK_SIZE - byte_idx

        tampered = bytearray(BLOCK_SIZE)
        for k in range(byte_idx + 1, BLOCK_SIZE):
            tampered[k] = intermediate[k] ^ pad_val

        found = False
        for guess in range(256):
            tampered[byte_idx] = guess

            if not padding_oracle(key, bytes(tampered), target_block):
                continue

            if byte_idx == BLOCK_SIZE - 1:
                confirm = bytearray(tampered)
                confirm[byte_idx - 1] ^= 0x01
                if not padding_oracle(key, bytes(confirm), target_block):
                    continue

            intermediate[byte_idx] = guess ^ pad_val
            found = True
            break

        if not found:
            raise RuntimeError(f"Could not recover byte at index {byte_idx}")

    recovered = bytearray(BLOCK_SIZE)
    for i in range(BLOCK_SIZE):
        recovered[i] = intermediate[i] ^ prev_block[i]

    return bytes(recovered)


def run_padding_oracle_attack():
    print("--- AES-CBC Padding Oracle Attack ---")

    key = generate_key(16)
    iv = generate_iv()

    secret = b"Padding oracle attacks are dangerous!"
    _, ciphertext = aes_cbc_encrypt(key, secret, iv)

    num_blocks = len(ciphertext) // BLOCK_SIZE
    blocks = [ciphertext[i * BLOCK_SIZE : (i + 1) * BLOCK_SIZE]
              for i in range(num_blocks)]

    print(f"Ciphertext length : {len(ciphertext)} bytes ({num_blocks} blocks)")
    print("Recovering plaintext byte-by-byte ...\n")

    recovered = bytearray()
    for block_num in range(num_blocks):
        prev = iv if block_num == 0 else blocks[block_num - 1]
        plain_block = attack_block(key, prev, blocks[block_num])
        recovered.extend(plain_block)
        print(f"  Block {block_num + 1}/{num_blocks} recovered")

    pad_len = recovered[-1]
    plaintext = bytes(recovered[:-pad_len])

    print(f"\nRecovered plaintext: {plaintext}")
    print(f"Original  plaintext: {secret}")

    if plaintext == secret:
        print("Result: Success — full plaintext recovered via oracle.")
    else:
        print("Result: Failed.")


if __name__ == "__main__":
    run_padding_oracle_attack()
