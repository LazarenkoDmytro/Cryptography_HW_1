from aes_modes import aes_cbc_encrypt, aes_cbc_decrypt, generate_key, generate_iv


def padding_oracle(key, iv, ciphertext):
    try:
        aes_cbc_decrypt(key, ciphertext, iv, unpad=True)
        return True
    except ValueError:
        return False


def run_padding_oracle_attack():
    print("AES-CBC Padding Oracle Attack")

    key = generate_key(16)
    iv = generate_iv()

    secret = b"Secret!!"
    _, ciphertext = aes_cbc_encrypt(key, secret, iv)

    print("Guessing the last plaintext byte via oracle")

    found = None
    for guess in range(256):
        tampered_iv = bytearray(iv)
        tampered_iv[15] = iv[15] ^ guess ^ 0x01

        if padding_oracle(key, bytes(tampered_iv), ciphertext):
            found = guess
            label = chr(guess) if guess > 31 else "non-printable"
            print(f"Oracle OK for guess={guess} ('{label}')")
            break

    if found == 0x08:
        print("Result: Success — recovered the padding byte 0x08.")
    else:
        print("Result: Fail")


if __name__ == "__main__":
    run_padding_oracle_attack()
