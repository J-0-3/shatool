def calculate_padding(data_length: int):
    padding = b'\x80'
    padding += b'\x00' * (55 - data_length % 64)
    padding += (data_length * 8).to_bytes(8)
    return padding

def choice(x: int, y: int, z: int) -> int:
    return ((x & y) ^ (~x & z))

def majority(x: int, y: int, z: int) -> int:
    return ((x & y) ^ (x & z) ^ (y & z))

def rotr(c: int, x: int) -> int:
    return (((x % 2**c) << 32 - c) | (x >> c))

def Σ0(x: int) -> int:
    return rotr(2, x) ^ rotr(13, x) ^ rotr(22, x)

def Σ1(x: int) -> int:
    return rotr(6, x) ^ rotr(11, x) ^ rotr(25, x)

def σ0(x: int) -> int:
    return rotr(7, x) ^ rotr(18, x) ^ (x >> 3)

def σ1(x: int) -> int:
    return rotr(17, x) ^ rotr(19, x) ^ (x >> 10)

def split_blocks(message: bytes) -> bytes:
    if len(message) % 64 != 0: raise ValueError("Message is not padded correctly")
    return [message[i:i+64] for i in range(0, len(message), 64)]

def message_schedule(block: bytes) -> bytes:
    words = []
    for t in range(0, 64, 4):
        words.append(int.from_bytes(block[t:t+4]))
    for t in range(16, 64):
        word = σ1(words[t - 2]) + words[t - 7] + σ0(words[t-15]) + words[t - 16]
        word %= 2**32
        words.append(word)
    return words

def calculate_hash_values(schedule: list[int], initial_values: list[int]):
    K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]

    a, b, c, d, e, f, g, h = initial_values
    for t in range(64):
        T1 = (h + Σ1(e) + choice(e, f, g) + K[t] + schedule[t]) % 2**32
        T2 = (Σ0(a) + majority(a, b, c)) % 2**32
        h = g
        g = f
        f = e
        e = (d + T1) % 2**32
        d = c
        c = b
        b = a
        a = (T1 + T2) % 2**32
    return list(map(lambda t: (t[0] + t[1]) % 2**32, zip(initial_values, (a, b, c, d, e, f, g, h))))

def combine_hash_values(hash_values: list[int]) -> bytes:
    digest = 0
    for v in hash_values:
        digest = (digest << 32) | v
    return digest.to_bytes(32)

def sha256(message: bytes) -> bytes:
    padding = calculate_padding(len(message))
    message += padding
    blocks = split_blocks(message)
    hash_values = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    for block in blocks:
        schedule = message_schedule(block)
        hash_values = calculate_hash_values(schedule, hash_values)
    return combine_hash_values(hash_values)
        
def split_hash_values(digest: bytes) -> list[int]:
    return [int.from_bytes(digest[i:i+4]) for i in range(0, 32, 4)]

def length_extend(digest: bytes, length: int, to_append: bytes) -> tuple[bytes, bytes]:
    starting_padding = calculate_padding(length)
    padding = calculate_padding(len(to_append))[:-8] + ((length + len(to_append) + len(starting_padding)) * 8).to_bytes(8)
    blocks = split_blocks(to_append + padding)
    hash_values = split_hash_values(digest)
    for block in blocks:
        schedule = message_schedule(block)
        hash_values = calculate_hash_values(schedule, hash_values)
    return starting_padding + to_append, combine_hash_values(hash_values)