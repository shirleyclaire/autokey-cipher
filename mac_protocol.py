"""
mac_protocol.py
---------------
Message Authentication Code (MAC) protocol using:
  • Custom polynomial rolling hash  (hash_engine.py)
  • Autokey Cipher                  (autokey_cipher.py)

Transmission payload format
  <original_message>||<encrypted_hash>
  Delimiter: "||"

Sender flow
  1. Hash the message              → H
  2. Encrypt H with Autokey        → E(H)
  3. Transmit:  message || E(H)

Receiver flow
  1. Split payload into message and E(H)
  2. Decrypt E(H) with Autokey     → H'
  3. Hash the received message     → H
  4. Compare H' == H               → authentic / tampered
"""

from hash_engine    import custom_hash
from autokey_cipher import encrypt, decrypt

DELIMITER = "||"


# ── sender ─────────────────────────────────────────────────────────────────────

def create_payload(message: str, keyword: str) -> str:
    """
    Create an authenticated payload for transmission.

    Returns
    -------
    str – "<message>||<encrypted_hash>"
    """
    if DELIMITER in message:
        raise ValueError(
            f"Message must not contain the delimiter {DELIMITER!r}. "
            "Choose a different message or delimiter."
        )

    hash_digest     = custom_hash(message)
    encrypted_hash  = encrypt(hash_digest, keyword)
    return f"{message}{DELIMITER}{encrypted_hash}"


# ── receiver ───────────────────────────────────────────────────────────────────

def verify_payload(payload: str, keyword: str) -> dict:
    """
    Verify and decode a received payload.

    Returns
    -------
    dict with keys:
        message         : str   – the plaintext message
        received_hash   : str   – hash recovered by decrypting the payload's tag
        computed_hash   : str   – hash recomputed from the received message
        is_authentic    : bool  – True when the two hashes match
    """
    if DELIMITER not in payload:
        raise ValueError(
            f"Malformed payload: delimiter {DELIMITER!r} not found."
        )

    message, encrypted_hash = payload.rsplit(DELIMITER, 1)

    received_hash  = decrypt(encrypted_hash, keyword)
    computed_hash  = custom_hash(message)
    is_authentic   = received_hash == computed_hash

    return {
        "message":        message,
        "received_hash":  received_hash,
        "computed_hash":  computed_hash,
        "is_authentic":   is_authentic,
    }
