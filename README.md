# Message Authentication with Autokey Cipher

A from-scratch implementation of a **Message Authentication Code (MAC)** protocol that uses a custom hash function and the Autokey Cipher to detect message tampering in transit.

---

## What This Does

This is **authentication, not encryption**. The message travels in plaintext; the system guarantees the receiver can detect any modification. Think of it like a tamper-evident seal on a parcel — anyone can see the box, but they cannot open and reseal it without the owner noticing.

---

## Flow Diagram

```
SENDER
──────────────────────────────────────────────────────
  Message M
      │
      ▼
  custom_hash(M)  ──────────────────────────►  H
      │
      ▼
  autokey_encrypt(H, keyword)  ────────────►  E(H)
      │
      ▼
  Transmit:  M || E(H)

RECEIVER
──────────────────────────────────────────────────────
  Received payload:  M' || E(H)
      │
      ├──► autokey_decrypt(E(H), keyword)  ──►  H'   (from sender)
      │
      └──► custom_hash(M')  ─────────────────►  H    (recomputed)
                                                 │
                                           H' == H ?
                                           ✓ Authentic
                                           ✗ Tampered
```

---

## Module Structure

| File | Responsibility |
|------|----------------|
| `hash_engine.py` | Custom 64-bit polynomial rolling hash |
| `autokey_cipher.py` | Autokey Cipher encrypt / decrypt |
| `mac_protocol.py` | High-level create_payload / verify_payload API |
| `main.py` | Runnable demo covering 4 scenarios |

---

## Design Choices

### 1. Custom Hash Function (`hash_engine.py`)

A **64-bit polynomial rolling hash** with three deliberate hardening techniques:

| Technique | Why |
|-----------|-----|
| **Polynomial accumulation** | Structurally sound, O(n), well-studied collision behaviour |
| **Left bit-rotation (7 bits per step)** | Adds non-linearity so similar inputs diverge quickly (avalanche effect) |
| **Position weighting (`BASE^(i+1)`)** | Anagram-resistant — reordering characters changes the hash |
| **Mersenne prime modulus (2⁶¹ − 1)** | Maximises output space, fast modulo arithmetic, reduces birthday collisions |
| **XOR finalisation (`h ^ h>>32`)** | Folds high/low bits together to break symmetry |

**Output:** 16-character uppercase hex string (64-bit digest).

> *Why not SHA-256?* The task explicitly permits a custom hash. This design demonstrates the properties that matter for a MAC — collision resistance, avalanche effect, and position sensitivity — while keeping the algorithm transparent and examinable.

---

### 2. Autokey Cipher (`autokey_cipher.py`)

The Autokey cipher extends the short keyword with the plaintext itself, producing a keystream that never repeats within a single message. This avoids the **repeating-key vulnerability** of Vigenère.

**Encryption:**  `C[i] = (P[i] + K[i]) mod 26`  
**Decryption:**  `P[i] = (C[i] − K[i]) mod 26`  (progressive — each recovered `P[i]` extends `K`)

**Hex → Alpha re-encoding:**  
The hash output contains digits `0–9` and letters `A–F`. The cipher's alphabet is `A–Z` (mod 26). To honour this contract cleanly, digits are bijectively mapped to unused letters before encryption and reversed after decryption:

```
'0'→'Q', '1'→'R', …, '9'→'Z'   (digits 0-9 → letters Q-Z)
'A'→'A', 'B'→'B', …, 'F'→'F'   (hex letters unchanged)
```

No information is lost; the mapping is fully reversible.

---

### 3. MAC Protocol (`mac_protocol.py`)

**Payload format:**

```
<plaintext message> || <autokey-encrypted hash>
```

The `||` delimiter separates the two parts. The receiver splits on the last occurrence of `||`, so the message itself may contain `|` characters (just not `||`).

**Why encrypt the hash and not the message?**  
Encrypting the hash with a secret key ties the integrity tag to a shared secret. An attacker who does not know the keyword cannot forge a valid tag for a modified message — decrypting the tag with the wrong key yields garbage that will not match the recomputed hash.

---

## Scenarios Demonstrated (`main.py`)

| # | Scenario | Expected result |
|---|----------|-----------------|
| 1 | Message arrives intact | ✓ Authentic |
| 2 | Attacker swaps message body (keeps tag) | ✗ Rejected |
| 3 | Receiver uses the wrong keyword | ✗ Rejected |
| 4 | Hash sensitivity — single-character changes | Large hash differences (avalanche) |

---

## Running the Code

```bash
python main.py
```

No external dependencies — pure Python 3 standard library only.

---

## Limitations & Scope

- **No message confidentiality.** The message body is plaintext. This is a MAC, not encryption.
- **Autokey is not cryptographically secure** by modern standards (it is a classical cipher). In a real system, use HMAC-SHA256 or AES-GCM.
- **Keyword management** (distribution, rotation) is outside scope here.
- This implementation is designed for **educational purposes** to demonstrate authentication flow, hash design, and the Autokey cipher mechanism.