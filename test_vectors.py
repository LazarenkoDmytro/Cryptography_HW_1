from aes_modes import (
    aes_ecb_encrypt,
    aes_ecb_decrypt,
    aes_cbc_encrypt,
    aes_cbc_decrypt,
    aes_cfb_encrypt,
    aes_cfb_decrypt,
)

PLAINTEXT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)

IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

KEYS = {
    128: bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
    192: bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
    256: bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
}

ECB_VECTORS = {
    "ECB-AES128": (128,
        "3ad77bb40d7a3660a89ecaf32466ef97"
        "f5d3d58503b9699de785895a96fdbaaf"
        "43b1cd7f598ece23881b00e3ed030688"
        "7b0c785e27e8ad3f8223207104725dd4"),
    "ECB-AES192": (192,
        "bd334f1d6e45f25ff712a214571fa5cc"
        "974104846d0ad3ad7734ecb3ecee4eef"
        "ef7afd2270e2e60adce0ba2face6444e"
        "9a4b41ba738d6c72fb16691603c18e0e"),
    "ECB-AES256": (256,
        "f3eed1bdb5d2a03c064b5a7e3db181f8"
        "591ccb10d410ed26dc5ba74a31362870"
        "b6ed21b99ca6f4f9f153e7b1beafed1d"
        "23304b7a39f9f3ff067d8d8f9e24ecc7"),
}

CBC_VECTORS = {
    "CBC-AES128": (128,
        "7649abac8119b246cee98e9b12e9197d"
        "5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e22229516"
        "3ff1caa1681fac09120eca307586e1a7"),
    "CBC-AES192": (192,
        "4f021db243bc633d7178183a9fa071e8"
        "b4d9ada9ad7dedf4e5e738763f69145a"
        "571b242012fb7ae07fa9baac3df102e0"
        "08b0e27988598881d920a9e64f5615cd"),
    "CBC-AES256": (256,
        "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
        "9cfc4e967edb808d679f777bc6702c7d"
        "39f23369a9d9bacfa530e26304231461"
        "b2eb05e2c39be9fcda6c19078c6a9d1b"),
}

CFB_VECTORS = {
    "CFB-AES128": (128,
        "3b3fd92eb72dad20333449f8e83cfb4a"
        "c8a64537a0b3a93fcde3cdad9f1ce58b"
        "26751f67a3cbb140b1808cf187a4f4df"
        "c04b05357c5d1c0eeac4c66f9ff7f2e6"),
    "CFB-AES192": (192,
        "cdc80d6fddf18cab34c25909c99a4174"
        "67ce7f7f81173621961a2b70171d3d7a"
        "2e1e8a1dd59b88b1c8e60fed1efac4c9"
        "c05f9f9ca9834fa042ae8fba584b09ff"),
    "CFB-AES256": (256,
        "dc7e84bfda79164b7ecd8486985d3860"
        "39ffed143b28b1c832113c6331e5407b"
        "df10132415e54b92a13ed0a8267ae2f9"
        "75a385741ab9cef82031623d55b1e471"),
}


def check(label, encrypted, expected, decrypted, original):
    ok = encrypted == expected and decrypted == original
    status = "PASS" if ok else "FAIL"
    print(f"  {status}: {label}")
    if encrypted != expected:
        print(f"    expected: {expected.hex()}")
        print(f"    got:      {encrypted.hex()}")
    return ok


def run_tests():
    passed = 0
    total = 0

    print("AES-ECB")
    for label, (key_bits, expected_hex) in ECB_VECTORS.items():
        key = KEYS[key_bits]
        expected = bytes.fromhex(expected_hex)
        encrypted = aes_ecb_encrypt(key, PLAINTEXT, pad=False)
        decrypted = aes_ecb_decrypt(key, encrypted, unpad=False)
        if check(label, encrypted, expected, decrypted, PLAINTEXT):
            passed += 1
        total += 1

    print("\nAES-CBC")
    for label, (key_bits, expected_hex) in CBC_VECTORS.items():
        key = KEYS[key_bits]
        expected = bytes.fromhex(expected_hex)
        _, encrypted = aes_cbc_encrypt(key, PLAINTEXT, IV, pad=False)
        decrypted = aes_cbc_decrypt(key, encrypted, IV, unpad=False)
        if check(label, encrypted, expected, decrypted, PLAINTEXT):
            passed += 1
        total += 1

    print("\nAES-CFB")
    for label, (key_bits, expected_hex) in CFB_VECTORS.items():
        key = KEYS[key_bits]
        expected = bytes.fromhex(expected_hex)
        _, encrypted = aes_cfb_encrypt(key, PLAINTEXT, IV)
        decrypted = aes_cfb_decrypt(key, encrypted, IV)
        if check(label, encrypted, expected, decrypted, PLAINTEXT):
            passed += 1
        total += 1

    print(f"\n{passed}/{total} passed")
    return passed == total


if __name__ == "__main__":
    import sys
    sys.exit(0 if run_tests() else 1)
