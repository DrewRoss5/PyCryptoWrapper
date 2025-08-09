from Crypto.Hash import SHA256

def sha256_hash(plaintext: bytes, rounds: int = 1):
    sha_hash = SHA256.new()
    for i in range(rounds):
        sha_hash.update(plaintext)
        plaintext = sha_hash.digest()
    return plaintext
