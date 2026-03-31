"""
autokey_cipher.py
-----------------
Autokey Cipher – encrypt and decrypt arbitrary uppercase hex strings.

The Autokey cipher avoids repeating-key vulnerabilities (like Vigenère) by
appending the plaintext itself to the keyword, producing a one-time-style
keystream that is as long as the message.

Alphabet used: A-Z  (26 symbols, indices 0-25)
Hex characters (0-9, A-F) map perfectly into A-Z (see _char_to_idx / _idx_to_char).

Character mapping
  A→0, B→1, …, Z→25
  Hex digits are ALL uppercase letters/digits – to keep them in [A-Z]
  we treat the plaintext as uppercase letters only.  Since our hash output
  is already hex (0-9, A-F), we re-encode it to all-alpha before encryption
  and reverse the re-encoding after decryption.

Design note: operating on A-Z (mod 26) is the canonical Autokey definition.
             The hex→alpha re-encoding is the clean way to respect that contract.
"""

_ALPHABET_SIZE = 26


# ── helpers ────────────────────────────────────────────────────────────────────

def _char_to_idx(ch: str) -> int:
    """Map an uppercase letter to its 0-based index in the alphabet."""
    return ord(ch) - ord('A')


def _idx_to_char(idx: int) -> str:
    """Map a 0-based alphabet index back to an uppercase letter."""
    return chr(idx + ord('A'))


def _hex_to_alpha(hex_str: str) -> str:
    """
    Re-encode a hex string (0-9, A-F) to a pure-alpha string (A-Z).
    Each hex character is mapped: '0'→'Q', '1'→'R', …, '9'→'Z', 'A'→'A', …, 'F'→'F'.
    This keeps A-F unchanged and shifts digits 0-9 to Q-Z (no collisions).
    """
    result = []
    for ch in hex_str.upper():
        if ch.isdigit():
            result.append(chr(ord('Q') + int(ch)))  # 0→Q, 1→R, …, 9→Z
        else:
            result.append(ch)                        # A-F unchanged
    return ''.join(result)


def _alpha_to_hex(alpha_str: str) -> str:
    """Reverse of _hex_to_alpha."""
    result = []
    for ch in alpha_str.upper():
        if 'Q' <= ch <= 'Z':
            result.append(str(ord(ch) - ord('Q')))  # Q→0, R→1, …, Z→9
        else:
            result.append(ch)                        # A-F unchanged
    return ''.join(result)


def _validate_key(key: str) -> str:
    """Return the key uppercased, raising ValueError if it contains non-alpha chars."""
    key = key.upper()
    if not key.isalpha():
        raise ValueError(f"Autokey keyword must contain only letters, got: {key!r}")
    return key


# ── core cipher ────────────────────────────────────────────────────────────────

def encrypt(plaintext_hex: str, keyword: str) -> str:
    """
    Encrypt a hex string with the Autokey cipher.

    Steps:
      1. Re-encode hex → alpha  (so every character is A-Z)
      2. Build keystream: keyword + alpha_plaintext  (trimmed to message length)
      3. Ciphertext[i] = (plain[i] + key[i]) mod 26
      4. Return ciphertext as uppercase letters.

    Parameters
    ----------
    plaintext_hex : str  – the hash digest to encrypt (uppercase hex, e.g. "3F7A…")
    keyword       : str  – secret key (letters only, any case)

    Returns
    -------
    str – uppercase-letter ciphertext of the same length as plaintext_hex
    """
    keyword = _validate_key(keyword)
    alpha   = _hex_to_alpha(plaintext_hex)
    keystream = (keyword + alpha)[:len(alpha)]   # Autokey: key || plaintext

    ciphertext = []
    for p_ch, k_ch in zip(alpha, keystream):
        p_idx  = _char_to_idx(p_ch)
        k_idx  = _char_to_idx(k_ch)
        c_idx  = (p_idx + k_idx) % _ALPHABET_SIZE
        ciphertext.append(_idx_to_char(c_idx))

    return ''.join(ciphertext)


def decrypt(ciphertext: str, keyword: str) -> str:
    """
    Decrypt an Autokey ciphertext back to the original hex string.

    Decryption is progressive: the keyword unlocks the first len(keyword)
    characters; each recovered plaintext letter then extends the keystream.

    Steps:
      1. Use keyword to recover the first len(keyword) alpha-plaintext chars.
      2. Use each newly recovered char as the next key character.
      3. Reverse the alpha→hex re-encoding to restore the original hex digest.

    Parameters
    ----------
    ciphertext : str  – the encrypted hash (uppercase letters)
    keyword    : str  – same secret key used during encryption

    Returns
    -------
    str – the recovered hash as an uppercase hex string
    """
    keyword = _validate_key(keyword)
    ciphertext = ciphertext.upper()

    recovered_alpha = []
    keystream       = list(keyword)          # starts with the known keyword

    for i, c_ch in enumerate(ciphertext):
        k_ch   = keystream[i]
        c_idx  = _char_to_idx(c_ch)
        k_idx  = _char_to_idx(k_ch)
        p_idx  = (c_idx - k_idx) % _ALPHABET_SIZE
        p_ch   = _idx_to_char(p_idx)
        recovered_alpha.append(p_ch)
        keystream.append(p_ch)               # Autokey: extend with recovered char

    return _alpha_to_hex(''.join(recovered_alpha))
