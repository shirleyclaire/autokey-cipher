"""
hash_engine.py
--------------
Custom polynomial rolling hash with bit-rotation avalanche effect.

Design rationale:
  - Polynomial rolling hash: structurally sound, O(n), minimal collisions
  - Bit rotation (left): adds non-linearity so similar inputs diverge quickly
  - Position weighting: anagram-resistant (reordered chars → different hash)
  - Large prime modulus (2^61 - 1): maximises output space, reduces birthday collisions
  - XOR finalisation: breaks symmetry and mixes high/low bits

Output: 16-character uppercase hex string (64-bit digest).
"""

_MOD   = (1 << 61) - 1   # Mersenne prime – large, fast modulo arithmetic
_BASE  = 131              # Prime larger than ASCII range


def _rotate_left(value: int, shift: int, bits: int = 64) -> int:
    """Rotate `value` left by `shift` positions within a `bits`-wide integer."""
    shift %= bits
    mask = (1 << bits) - 1
    return ((value << shift) | (value >> (bits - shift))) & mask


def custom_hash(message: str) -> str:
    """
    Compute a 64-bit digest of `message` and return it as a 16-char hex string.

    Algorithm (per character at index i):
        accumulator = rotate_left(accumulator, 7) + ord(char) * BASE^(i+1)
        accumulator %= MOD
    Finalisation:
        digest = accumulator XOR (accumulator >> 32)
    """
    if not isinstance(message, str):
        raise TypeError(f"message must be str, got {type(message).__name__}")

    accumulator = 0
    power = _BASE

    for i, char in enumerate(message):
        rotated   = _rotate_left(accumulator, 7)
        weighted  = (ord(char) * power) % _MOD
        accumulator = (rotated + weighted) % _MOD
        power = (power * _BASE) % _MOD

    # Finalisation: fold upper and lower 32 bits together
    digest = accumulator ^ (accumulator >> 32)
    return format(digest & 0xFFFFFFFFFFFFFFFF, "016X")
